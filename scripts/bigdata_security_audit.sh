#!/bin/bash
# ════════════════════════════════════════════════════════════
#  bigdata_security_audit.sh — Big Data Platform Security Audit
#  Supported OS: Linux host (requires Hadoop/Spark installed or running via Docker)
#  Run as: root or corresponding service account
#  Mode: Read-only audit (no configuration modified)
#  Reference: Treydone/hadoop-sec-bench
#         cys3c/BigDataAudit
#         Apache Hadoop Security Documentation
#         Apache Spark Security Documentation
#  Project home: https://github.com/0x10debug/vps-security-enhancement-scripts
# ════════════════════════════════════════════════════════════
#
# Usage:
#   sudo ./scripts/bigdata_security_audit.sh                    # Audit all detected platforms
#   sudo ./scripts/bigdata_security_audit.sh --hadoop           # Audit Hadoop only
#   sudo ./scripts/bigdata_security_audit.sh --spark            # Audit Spark only
#   sudo ./scripts/bigdata_security_audit.sh --section auth     # Audit authentication section only
#   sudo ./scripts/bigdata_security_audit.sh --json             # JSON output
#
# Exit codes:
#   0 — Success
#   1 — No platform to detect / Parameter error
#   2 — Some features unavailable

set -euo pipefail
# shellcheck disable=SC2154
# Variables assigned inside bash -c strings are not seen by shellcheck

APP_NAME="bigdata_security_audit"
APP_VER="v3.0.0"
PLATFORM_FILTER=""
JSON_OUTPUT=false
REPORT_DIR="/var/log/bigdata-audit"
TIMESTAMP=$(date +%Y%m%d%H%M%S)

COUNT_PASS=0
COUNT_FAIL=0
COUNT_WARN=0
COUNT_SKIP=0
TOTAL_CHECKS=0
JSON_RESULTS="["
DETECTED_PLATFORMS=""

C_FAIL='\033[0;31m'
C_OK='\033[0;32m'
C_WARN='\033[0;33m'
C_INFO='\033[0;34m'
C_RST='\033[0m'

# ── Parameter parsing ─────────────────────────────────────────────────
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --hadoop) PLATFORM_FILTER="hadoop"; shift ;;
            --spark) PLATFORM_FILTER="spark"; shift ;;
            --json) JSON_OUTPUT=true; shift ;;
            -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
            *) echo "Unknown parameter: $1"; exit 1 ;;
        esac
    done
}

# ── Platform detection ─────────────────────────────────────────────────
detect_platforms() {
    DETECTED_PLATFORMS=""

    # Hadoop
    if command -v hdfs >/dev/null 2>&1 || command -v hadoop >/dev/null 2>&1; then
        DETECTED_PLATFORMS="$DETECTED_PLATFORMS hadoop"
    fi
    if [ -d /etc/hadoop/conf ] || [ -d /opt/hadoop ]; then
        DETECTED_PLATFORMS="$DETECTED_PLATFORMS hadoop"
    fi
    if command -v docker >/dev/null 2>&1; then
        docker ps --format '{{.Image}}' 2>/dev/null | grep -qi "hadoop" && DETECTED_PLATFORMS="$DETECTED_PLATFORMS hadoop"
    fi

    # Spark
    if command -v spark-submit >/dev/null 2>&1 || command -v spark-shell >/dev/null 2>&1; then
        DETECTED_PLATFORMS="$DETECTED_PLATFORMS spark"
    fi
    if [ -d /etc/spark/conf ] || [ -d /opt/spark ]; then
        DETECTED_PLATFORMS="$DETECTED_PLATFORMS spark"
    fi
    if command -v docker >/dev/null 2>&1; then
        docker ps --format '{{.Image}}' 2>/dev/null | grep -qi "spark" && DETECTED_PLATFORMS="$DETECTED_PLATFORMS spark"
    fi

    DETECTED_PLATFORMS=$(echo "$DETECTED_PLATFORMS" | xargs | tr ' ' '\n' | sort -u | tr '\n' ' ' | xargs)
}

# ── Report initialization ───────────────────────────────────────────────
init_report() {
    mkdir -p "$REPORT_DIR" 2>/dev/null || REPORT_DIR="/tmp/bigdata-audit"
    mkdir -p "$REPORT_DIR" 2>/dev/null || true
    REPORT_FILE="$REPORT_DIR/bigdata-audit-${TIMESTAMP}.txt"
    {
        echo "Big Data Security Audit Report"
        echo "================================"
        echo "Date: $(date)"
        echo "Host: $(hostname 2>/dev/null || echo 'N/A')"
        echo "Platforms: $DETECTED_PLATFORMS"
        echo "Script: $APP_NAME $APP_VER"
        echo ""
    } > "$REPORT_FILE"
}

# ── Check functions ─────────────────────────────────────────────────
run_check() {
    local id="$1" desc="$2"
    shift 2
    local result evidence rc

    evidence=$("$@" 2>&1) && rc=0 || rc=$?
    case $rc in
        0) result="PASS" ;;
        1) result="FAIL" ;;
        2) result="WARN" ;;
        *) result="SKIP" ;;
    esac

    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    case "$result" in
        PASS) COUNT_PASS=$((COUNT_PASS + 1)) ;;
        FAIL) COUNT_FAIL=$((COUNT_FAIL + 1)) ;;
        WARN) COUNT_WARN=$((COUNT_WARN + 1)) ;;
        SKIP) COUNT_SKIP=$((COUNT_SKIP + 1)) ;;
    esac

    local color
    case "$result" in
        PASS) color="$C_OK" ;;
        FAIL) color="$C_FAIL" ;;
        WARN) color="$C_WARN" ;;
        SKIP) color="$C_INFO" ;;
    esac
    printf "  ${color}%-4s${C_RST} %s  %s\n" "$result" "$id" "$desc"

    {
        echo ""
        echo "[$result] $id $desc"
        echo "  Evidence: $evidence"
    } >> "$REPORT_FILE"

    local json_entry
    json_entry=$(printf '{"id":"%s","description":"%s","result":"%s","evidence":"%s"}' \
        "$id" "${desc//\"/\\\"}" "$result" "${evidence//\"/\\\"}")
    if [ "$TOTAL_CHECKS" -gt 1 ]; then
        JSON_RESULTS="$JSON_RESULTS,$json_entry"
    else
        JSON_RESULTS="$JSON_RESULTS$json_entry"
    fi
}

# ── Hadoop security audit ──────────────────────────────────────────
audit_hadoop() {
    echo ""
    echo "━━━ Hadoop Security Audit ━━━"

    local conf_dir="/etc/hadoop/conf"
    [ -d "$conf_dir" ] || conf_dir="/opt/hadoop/etc/hadoop"

    echo -e "  ${C_INFO}── Authentication (Kerberos) ──${C_RST}"

    run_check "HADOOP-AUTH-1.1" "Kerberos authentication enabled" \
        bash -c "grep -q 'hadoop.security.authentication.*kerberos' $conf_dir/core-site.xml 2>/dev/null && echo 'Kerberos enabled' && return 0 || echo 'Kerberos not enabled' && return 2"

    run_check "HADOOP-AUTH-1.2" "Hadoop security authorization enabled" \
        bash -c "grep -q 'hadoop.security.authorization.*true' $conf_dir/core-site.xml 2>/dev/null && echo 'Authorization enabled' && return 0 || echo 'Authorization not enabled' && return 1"

    run_check "HADOOP-AUTH-1.3" "Kerberos NameNode keytab exists" \
        bash -c "grep -q 'dfs.namenode.keytab.file' $conf_dir/hdfs-site.xml 2>/dev/null && keytab=\$(grep 'dfs.namenode.keytab.file' $conf_dir/hdfs-site.xml 2>/dev/null | sed 's/.*<value>\(.*\)<\/value>.*/\1/' | head -1); [ -n \"\$keytab\" ] && [ -f \"\$keytab\" ] && echo \"keytab found: \$keytab\" && return 0 || echo 'keytab not found' && return 2"

    echo -e "  ${C_INFO}── Transport encryption (SSL/TLS) ──${C_RST}"

    run_check "HADOOP-SSL-2.1" "Hadoop SSL enabled" \
        bash -c "grep -q 'hadoop.ssl.enabled.*true' $conf_dir/core-site.xml 2>/dev/null && echo 'SSL enabled' && return 0 || echo 'SSL not enabled' && return 2"

    run_check "HADOOP-SSL-2.2" "Hadoop RPC encryption (privacy)" \
        bash -c "grep -q 'hadoop.rpc.protection.*privacy' $conf_dir/core-site.xml 2>/dev/null && echo 'RPC privacy enabled' && return 0 || echo 'RPC privacy not enabled' && return 2"

    run_check "HADOOP-SSL-2.3" "Hadoop DataNode transport encryption" \
        bash -c "grep -q 'dfs.encrypt.data.transfer.*true' $conf_dir/hdfs-site.xml 2>/dev/null && echo 'DataNode encryption enabled' && return 0 || echo 'DataNode encryption not enabled' && return 2"

    echo -e "  ${C_INFO}── Permissions and ACL ──${C_RST}"

    run_check "HADOOP-PERM-3.1" "HDFS permission check enabled" \
        bash -c "grep -q 'dfs.permissions.enabled.*true' $conf_dir/hdfs-site.xml 2>/dev/null && echo 'permissions enabled' && return 0 || echo 'permissions may be disabled' && return 2"

    run_check "HADOOP-PERM-3.2" "HDFS ACL enabled" \
        bash -c "grep -q 'dfs.namenode.acls.enabled.*true' $conf_dir/hdfs-site.xml 2>/dev/null && echo 'ACLs enabled' && return 0 || echo 'ACLs not enabled' && return 2"

    run_check "HADOOP-PERM-3.3" "YARN scheduler fair queue ACL" \
        bash -c "grep -q 'yarn.scheduler.fair.acl' $conf_dir/yarn-site.xml 2>/dev/null && echo 'YARN queue ACL configured' && return 0 || echo 'YARN queue ACL not configured' && return 2"

    echo -e "  ${C_INFO}── Audit log ──${C_RST}"

    run_check "HADOOP-AUDIT-4.1" "HDFS audit log enabled" \
        bash -c "grep -q 'dfs.namenode.audit.log.enabled.*true' $conf_dir/hdfs-site.xml 2>/dev/null && echo 'HDFS audit log enabled' && return 0 || echo 'HDFS audit log not enabled' && return 2"

    run_check "HADOOP-AUDIT-4.2" "YARN audit log enabled" \
        bash -c "grep -q 'yarn.resourcemanager.audit-log.enabled.*true' $conf_dir/yarn-site.xml 2>/dev/null && echo 'YARN audit log enabled' && return 0 || echo 'YARN audit log not enabled' && return 2"
}

# ── Spark security audit ───────────────────────────────────────────
audit_spark() {
    echo ""
    echo "━━━ Spark Security Audit ━━━"

    local conf_dir="/etc/spark/conf"
    [ -d "$conf_dir" ] || conf_dir="/opt/spark/conf"

    echo -e "  ${C_INFO}── Authentication (Kerberos) ──${C_RST}"

    run_check "SPARK-AUTH-1.1" "Spark Kerberos authentication enabled" \
        bash -c "grep -q 'spark.kerberos.access.enabled.*true' $conf_dir/spark-defaults.conf 2>/dev/null && echo 'Kerberos enabled' && return 0 || echo 'Kerberos not enabled' && return 2"

    run_check "SPARK-AUTH-1.2" "Spark authentication key configured" \
        bash -c "grep -q 'spark.auth.secret' $conf_dir/spark-defaults.conf 2>/dev/null && echo 'auth secret configured' && return 0 || echo 'auth secret not configured' && return 2"

    echo -e "  ${C_INFO}── Transport encryption (SSL/TLS) ──${C_RST}"

    run_check "SPARK-SSL-2.1" "Spark SSL enabled" \
        bash -c "grep -q 'spark.ssl.enabled.*true' $conf_dir/spark-defaults.conf 2>/dev/null && echo 'SSL enabled' && return 0 || echo 'SSL not enabled' && return 2"

    run_check "SPARK-SSL-2.2" "Spark RPC encryption enabled" \
        bash -c "grep -q 'spark.network.crypto.enabled.*true' $conf_dir/spark-defaults.conf 2>/dev/null && echo 'RPC encryption enabled' && return 0 || echo 'RPC encryption not enabled' && return 2"

    run_check "SPARK-SSL-2.3" "Spark UI SSL enabled" \
        bash -c "grep -q 'spark.ui.ssl.enabled.*true' $conf_dir/spark-defaults.conf 2>/dev/null && echo 'UI SSL enabled' && return 0 || echo 'UI SSL not enabled' && return 2"

    echo -e "  ${C_INFO}── Permissions and ACL ──${C_RST}"

    run_check "SPARK-PERM-3.1" "Spark UI ACL configured" \
        bash -c "grep -q 'spark.ui.acls.enabled.*true' $conf_dir/spark-defaults.conf 2>/dev/null && echo 'UI ACL enabled' && return 0 || echo 'UI ACL not enabled' && return 2"

    run_check "SPARK-PERM-3.2" "Spark View ACLs configured" \
        bash -c "grep -q 'spark.ui.view.acls' $conf_dir/spark-defaults.conf 2>/dev/null && echo 'view ACLs configured' && return 0 || echo 'view ACLs not configured' && return 2"

    run_check "SPARK-PERM-3.3" "Spark event log ACL" \
        bash -c "grep -q 'spark.eventLog.acls.enabled.*true' $conf_dir/spark-defaults.conf 2>/dev/null && echo 'event log ACL enabled' && return 0 || echo 'event log ACL not enabled' && return 2"

    echo -e "  ${C_INFO}── Audit log ──${C_RST}"

    run_check "SPARK-AUDIT-4.1" "Spark event log enabled" \
        bash -c "grep -q 'spark.eventLog.enabled.*true' $conf_dir/spark-defaults.conf 2>/dev/null && echo 'event log enabled' && return 0 || echo 'event log not enabled' && return 2"

    run_check "SPARK-AUDIT-4.2" "Spark event log directory configured" \
        bash -c "grep -q 'spark.eventLog.dir' $conf_dir/spark-defaults.conf 2>/dev/null && echo 'event log dir configured' && return 0 || echo 'event log dir not configured' && return 2"
}

# ── Audit main flow ───────────────────────────────────────────────
audit_all() {
    echo -e "${C_WARN}>>> Big data platform security audit <<<${C_RST}"
    echo -e "${C_INFO}Read-only mode, no configuration modified${C_RST}"
    echo ""

    detect_platforms
    init_report

    if [ -z "$DETECTED_PLATFORMS" ]; then
        echo -e "${C_WARN}No big data platform detected${C_RST}"
        echo -e "${C_INFO}Supported: Hadoop, Spark${C_RST}"
        return 0
    fi

    echo -e "${C_INFO}Detected: $DETECTED_PLATFORMS${C_RST}"
    echo ""

    local should_audit=false

    for platform in $DETECTED_PLATFORMS; do
        if [ -n "$PLATFORM_FILTER" ] && [ "$platform" != "$PLATFORM_FILTER" ]; then
            continue
        fi
        should_audit=true
        case "$platform" in
            hadoop) audit_hadoop ;;
            spark) audit_spark ;;
        esac
    done

    if [ "$should_audit" = false ]; then
        echo -e "${C_WARN}No matching platform detected: $PLATFORM_FILTER${C_RST}"
        return 0
    fi

    # JSON report
    if [ "$JSON_OUTPUT" = true ]; then
        echo "${JSON_RESULTS}]" > "$REPORT_DIR/bigdata-audit-${TIMESTAMP}.json"
    else
        echo "${JSON_RESULTS}]" > "$REPORT_DIR/bigdata-audit-${TIMESTAMP}.json"
    fi

    # Summary
    echo ""
    echo -e "${C_INFO}╔══════════════════════════════════════════╗${C_RST}"
    echo -e "${C_INFO}║  Big Data Security Audit Summary           ║${C_RST}"
    echo -e "${C_INFO}╚══════════════════════════════════════════╝${C_RST}"
    echo -e "${C_INFO}Platforms: $DETECTED_PLATFORMS${C_RST}"
    echo ""
    printf "  ${C_OK}PASS${C_RST}: %d\n" "$COUNT_PASS"
    printf "  ${C_FAIL}FAIL${C_RST}: %d\n" "$COUNT_FAIL"
    printf "  ${C_WARN}WARN${C_RST}: %d\n" "$COUNT_WARN"
    printf "  ${C_INFO}SKIP${C_RST}: %d\n" "$COUNT_SKIP"
    printf "  Total: %d\n" "$TOTAL_CHECKS"
    echo ""
    echo -e "Report: $REPORT_FILE"
    echo -e "JSON: $REPORT_DIR/bigdata-audit-${TIMESTAMP}.json"
}

# ── Main flow ───────────────────────────────────────────────────
main() {
    parse_args "$@"
    audit_all || true
    return 0
}

main "$@"
