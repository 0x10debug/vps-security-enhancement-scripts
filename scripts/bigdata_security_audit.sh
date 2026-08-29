#!/bin/bash
# ════════════════════════════════════════════════════════════
#  bigdata_security_audit.sh — Big Data Platform Security Audit
#  适用系统: Linux 主机 (需 Hadoop/Spark 已安装或通过 Docker 运行)
#  运行身份: root 或对应服务账号
#  模式: 只读审计 (不修改任何配置)
#  参考: Treydone/hadoop-sec-bench
#         cys3c/BigDataAudit
#         Apache Hadoop Security Documentation
#         Apache Spark Security Documentation
#  项目主页: https://github.com/0x10debug/vps-security-enhancement-scripts
# ════════════════════════════════════════════════════════════
#
# 用法:
#   sudo ./scripts/bigdata_security_audit.sh                    # 审计所有已检测平台
#   sudo ./scripts/bigdata_security_audit.sh --hadoop           # 只审计 Hadoop
#   sudo ./scripts/bigdata_security_audit.sh --spark            # 只审计 Spark
#   sudo ./scripts/bigdata_security_audit.sh --section auth     # 只审计认证章节
#   sudo ./scripts/bigdata_security_audit.sh --json             # JSON 输出
#
# 退出码:
#   0 — 成功
#   1 — 无平台可检测 / 参数错误
#   2 — 部分功能不可用

set -euo pipefail
# shellcheck disable=SC2154
# Variables assigned inside bash -c strings are not seen by shellcheck

APP_NAME="bigdata_security_audit"
APP_VER="v3.0.0"
PLATFORM_FILTER=""
SECTION_FILTER=""
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

# ── 参数解析 ─────────────────────────────────────────────────
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --hadoop) PLATFORM_FILTER="hadoop"; shift ;;
            --spark) PLATFORM_FILTER="spark"; shift ;;
            --section) SECTION_FILTER="$2"; shift 2 ;;
            --json) JSON_OUTPUT=true; shift ;;
            -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
            *) echo "未知参数: $1"; exit 1 ;;
        esac
    done
}

# ── 平台探测 ─────────────────────────────────────────────────
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

# ── 报告初始化 ───────────────────────────────────────────────
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

# ── 检查函数 ─────────────────────────────────────────────────
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

# ── Hadoop 安全审计 ──────────────────────────────────────────
audit_hadoop() {
    echo ""
    echo "━━━ Hadoop Security Audit ━━━"

    local conf_dir="/etc/hadoop/conf"
    [ -d "$conf_dir" ] || conf_dir="/opt/hadoop/etc/hadoop"

    echo -e "  ${C_INFO}── 认证 (Kerberos) ──${C_RST}"

    run_check "HADOOP-AUTH-1.1" "Kerberos 认证已启用" \
        bash -c "grep -q 'hadoop.security.authentication.*kerberos' $conf_dir/core-site.xml 2>/dev/null && echo 'Kerberos enabled' && return 0 || echo 'Kerberos not enabled' && return 2"

    run_check "HADOOP-AUTH-1.2" "Hadoop 安全授权已启用" \
        bash -c "grep -q 'hadoop.security.authorization.*true' $conf_dir/core-site.xml 2>/dev/null && echo 'Authorization enabled' && return 0 || echo 'Authorization not enabled' && return 1"

    run_check "HADOOP-AUTH-1.3" "Kerberos NameNode keytab 存在" \
        bash -c "grep -q 'dfs.namenode.keytab.file' $conf_dir/hdfs-site.xml 2>/dev/null && keytab=\$(grep 'dfs.namenode.keytab.file' $conf_dir/hdfs-site.xml 2>/dev/null | sed 's/.*<value>\(.*\)<\/value>.*/\1/' | head -1); [ -n \"\$keytab\" ] && [ -f \"\$keytab\" ] && echo \"keytab found: \$keytab\" && return 0 || echo 'keytab not found' && return 2"

    echo -e "  ${C_INFO}── 传输加密 (SSL/TLS) ──${C_RST}"

    run_check "HADOOP-SSL-2.1" "Hadoop SSL 已启用" \
        bash -c "grep -q 'hadoop.ssl.enabled.*true' $conf_dir/core-site.xml 2>/dev/null && echo 'SSL enabled' && return 0 || echo 'SSL not enabled' && return 2"

    run_check "HADOOP-SSL-2.2" "Hadoop RPC 加密 (privacy)" \
        bash -c "grep -q 'hadoop.rpc.protection.*privacy' $conf_dir/core-site.xml 2>/dev/null && echo 'RPC privacy enabled' && return 0 || echo 'RPC privacy not enabled' && return 2"

    run_check "HADOOP-SSL-2.3" "Hadoop DataNode 传输加密" \
        bash -c "grep -q 'dfs.encrypt.data.transfer.*true' $conf_dir/hdfs-site.xml 2>/dev/null && echo 'DataNode encryption enabled' && return 0 || echo 'DataNode encryption not enabled' && return 2"

    echo -e "  ${C_INFO}── 权限与 ACL ──${C_RST}"

    run_check "HADOOP-PERM-3.1" "HDFS 权限检查已启用" \
        bash -c "grep -q 'dfs.permissions.enabled.*true' $conf_dir/hdfs-site.xml 2>/dev/null && echo 'permissions enabled' && return 0 || echo 'permissions may be disabled' && return 2"

    run_check "HADOOP-PERM-3.2" "HDFS ACL 已启用" \
        bash -c "grep -q 'dfs.namenode.acls.enabled.*true' $conf_dir/hdfs-site.xml 2>/dev/null && echo 'ACLs enabled' && return 0 || echo 'ACLs not enabled' && return 2"

    run_check "HADOOP-PERM-3.3" "YARN 调度器公平队列 ACL" \
        bash -c "grep -q 'yarn.scheduler.fair.acl' $conf_dir/yarn-site.xml 2>/dev/null && echo 'YARN queue ACL configured' && return 0 || echo 'YARN queue ACL not configured' && return 2"

    echo -e "  ${C_INFO}── 审计日志 ──${C_RST}"

    run_check "HADOOP-AUDIT-4.1" "HDFS 审计日志已启用" \
        bash -c "grep -q 'dfs.namenode.audit.log.enabled.*true' $conf_dir/hdfs-site.xml 2>/dev/null && echo 'HDFS audit log enabled' && return 0 || echo 'HDFS audit log not enabled' && return 2"

    run_check "HADOOP-AUDIT-4.2" "YARN 审计日志已启用" \
        bash -c "grep -q 'yarn.resourcemanager.audit-log.enabled.*true' $conf_dir/yarn-site.xml 2>/dev/null && echo 'YARN audit log enabled' && return 0 || echo 'YARN audit log not enabled' && return 2"
}

# ── Spark 安全审计 ───────────────────────────────────────────
audit_spark() {
    echo ""
    echo "━━━ Spark Security Audit ━━━"

    local conf_dir="/etc/spark/conf"
    [ -d "$conf_dir" ] || conf_dir="/opt/spark/conf"

    echo -e "  ${C_INFO}── 认证 (Kerberos) ──${C_RST}"

    run_check "SPARK-AUTH-1.1" "Spark Kerberos 认证已启用" \
        bash -c "grep -q 'spark.kerberos.access.enabled.*true' $conf_dir/spark-defaults.conf 2>/dev/null && echo 'Kerberos enabled' && return 0 || echo 'Kerberos not enabled' && return 2"

    run_check "SPARK-AUTH-1.2" "Spark 认证密钥已配置" \
        bash -c "grep -q 'spark.auth.secret' $conf_dir/spark-defaults.conf 2>/dev/null && echo 'auth secret configured' && return 0 || echo 'auth secret not configured' && return 2"

    echo -e "  ${C_INFO}── 传输加密 (SSL/TLS) ──${C_RST}"

    run_check "SPARK-SSL-2.1" "Spark SSL 已启用" \
        bash -c "grep -q 'spark.ssl.enabled.*true' $conf_dir/spark-defaults.conf 2>/dev/null && echo 'SSL enabled' && return 0 || echo 'SSL not enabled' && return 2"

    run_check "SPARK-SSL-2.2" "Spark RPC 加密已启用" \
        bash -c "grep -q 'spark.network.crypto.enabled.*true' $conf_dir/spark-defaults.conf 2>/dev/null && echo 'RPC encryption enabled' && return 0 || echo 'RPC encryption not enabled' && return 2"

    run_check "SPARK-SSL-2.3" "Spark UI SSL 已启用" \
        bash -c "grep -q 'spark.ui.ssl.enabled.*true' $conf_dir/spark-defaults.conf 2>/dev/null && echo 'UI SSL enabled' && return 0 || echo 'UI SSL not enabled' && return 2"

    echo -e "  ${C_INFO}── 权限与 ACL ──${C_RST}"

    run_check "SPARK-PERM-3.1" "Spark UI ACL 已配置" \
        bash -c "grep -q 'spark.ui.acls.enabled.*true' $conf_dir/spark-defaults.conf 2>/dev/null && echo 'UI ACL enabled' && return 0 || echo 'UI ACL not enabled' && return 2"

    run_check "SPARK-PERM-3.2" "Spark View ACLs 已配置" \
        bash -c "grep -q 'spark.ui.view.acls' $conf_dir/spark-defaults.conf 2>/dev/null && echo 'view ACLs configured' && return 0 || echo 'view ACLs not configured' && return 2"

    run_check "SPARK-PERM-3.3" "Spark 事件日志 ACL" \
        bash -c "grep -q 'spark.eventLog.acls.enabled.*true' $conf_dir/spark-defaults.conf 2>/dev/null && echo 'event log ACL enabled' && return 0 || echo 'event log ACL not enabled' && return 2"

    echo -e "  ${C_INFO}── 审计日志 ──${C_RST}"

    run_check "SPARK-AUDIT-4.1" "Spark 事件日志已启用" \
        bash -c "grep -q 'spark.eventLog.enabled.*true' $conf_dir/spark-defaults.conf 2>/dev/null && echo 'event log enabled' && return 0 || echo 'event log not enabled' && return 2"

    run_check "SPARK-AUDIT-4.2" "Spark 事件日志目录已配置" \
        bash -c "grep -q 'spark.eventLog.dir' $conf_dir/spark-defaults.conf 2>/dev/null && echo 'event log dir configured' && return 0 || echo 'event log dir not configured' && return 2"
}

# ── 审计主流程 ───────────────────────────────────────────────
audit_all() {
    echo -e "${C_WARN}>>> 大数据平台安全审计 <<<${C_RST}"
    echo -e "${C_INFO}只读模式, 不修改任何配置${C_RST}"
    echo ""

    detect_platforms
    init_report

    if [ -z "$DETECTED_PLATFORMS" ]; then
        echo -e "${C_WARN}未检测到任何大数据平台${C_RST}"
        echo -e "${C_INFO}支持: Hadoop, Spark${C_RST}"
        return 0
    fi

    echo -e "${C_INFO}检测到: $DETECTED_PLATFORMS${C_RST}"
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
        echo -e "${C_WARN}未检测到匹配的平台: $PLATFORM_FILTER${C_RST}"
        return 0
    fi

    # JSON 报告
    if [ "$JSON_OUTPUT" = true ]; then
        echo "${JSON_RESULTS}]" > "$REPORT_DIR/bigdata-audit-${TIMESTAMP}.json"
    else
        echo "${JSON_RESULTS}]" > "$REPORT_DIR/bigdata-audit-${TIMESTAMP}.json"
    fi

    # 摘要
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
    echo -e "报告: $REPORT_FILE"
    echo -e "JSON: $REPORT_DIR/bigdata-audit-${TIMESTAMP}.json"
}

# ── 主流程 ───────────────────────────────────────────────────
main() {
    parse_args "$@"
    audit_all || true
    return 0
}

main "$@"
