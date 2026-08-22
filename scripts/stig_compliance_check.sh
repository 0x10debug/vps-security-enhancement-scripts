#!/bin/bash
# ════════════════════════════════════════════════════════════
#  stig_compliance_check.sh — DISA STIG Compliance Check
#  适用系统: Ubuntu / Debian / RHEL / CentOS / AlmaLinux / Rocky
#  运行身份: root (推荐) / 普通用户 (部分检查受限)
#  审计模式: 只读, 不修改任何系统配置
#  参考: DISA STIG for RHEL 8/9 V1R10+, Ubuntu 22.04 STIG V1R8+
#  项目主页: https://github.com/0x10debug/vps-security-enhancement-scripts
# ════════════════════════════════════════════════════════════
#
# 用法:
#   sudo ./scripts/stig_compliance_check.sh              # 交互式选择
#   sudo ./scripts/stig_compliance_check.sh --scanner     # 扫描器模式 (全部检查)
#   sudo ./scripts/stig_compliance_check.sh --enable SRG-OS-000001 --enable SRG-OS-000002
#   sudo ./scripts/stig_compliance_check.sh --disable SRG-OS-000099
#   sudo ./scripts/stig_compliance_check.sh --json        # 输出 JSON 报告路径
#   sudo ./scripts/stig_compliance_check.sh --quiet       # 只输出摘要
#
# 退出码:
#   0 — 审计完成 (不论是否合规)
#   1 — 参数错误
#   2 — 不支持的发行版

set -euo pipefail

APP_NAME="stig_compliance_check"
APP_VER="v2.1.0"
QUIET=0
JSON_ONLY=0
SCANNER_MODE=0
REPORT_DIR="/var/log/stig-audit"
REPORT_TXT=""
REPORT_JSON=""
TIMESTAMP=$(date +%Y%m%d%H%M%S)

# 启用/禁用的 SRG ID 列表
declare -a ENABLE_LIST=()
declare -a DISABLE_LIST=()

# 计数器
COUNT_PASS=0
COUNT_FAIL=0
COUNT_WARN=0
COUNT_SKIP=0
TOTAL_CHECKS=0

# JSON 结果
JSON_RESULTS="["

# 颜色
C_FAIL='\033[0;31m'
C_OK='\033[0;32m'
C_WARN='\033[0;33m'
C_INFO='\033[0;34m'
C_RST='\033[0m'

# ── 发行版探测 ───────────────────────────────────────────────
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO_ID="$ID"
        DISTRO_VERSION="$VERSION_ID"
        case "$ID" in
            ubuntu|debian) DISTRO_FAMILY="debian" ;;
            rhel|centos|almalinux|rocky|ol) DISTRO_FAMILY="rhel" ;;
            *) echo "不支持的发行版: $ID"; exit 2 ;;
        esac
    else
        echo "无法检测发行版 (缺少 /etc/os-release)"; exit 2
    fi
}

# ── 参数解析 ─────────────────────────────────────────────────
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --scanner) SCANNER_MODE=1; shift ;;
            --quiet) QUIET=1; shift ;;
            --json) JSON_ONLY=1; shift ;;
            --enable) ENABLE_LIST+=("$2"); shift 2 ;;
            --disable) DISABLE_LIST+=("$2"); shift 2 ;;
            -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
            *) echo "未知参数: $1"; exit 1 ;;
        esac
    done
}

# ── SRG 过滤 ─────────────────────────────────────────────────
srg_enabled() {
    local srg_id="$1"
    # 检查是否在 disable 列表
    for d in "${DISABLE_LIST[@]:-}"; do
        [ "$d" = "$srg_id" ] && return 1
    done
    # 如果 enable 列表非空，只检查 enable 列表中的
    if [ ${#ENABLE_LIST[@]} -gt 0 ]; then
        for e in "${ENABLE_LIST[@]}"; do
            [ "$e" = "$srg_id" ] && return 0
        done
        return 1
    fi
    return 0
}

# ── 报告初始化 ───────────────────────────────────────────────
init_report() {
    mkdir -p "$REPORT_DIR" 2>/dev/null || true
    REPORT_TXT="$REPORT_DIR/stig-audit-${TIMESTAMP}.txt"
    REPORT_JSON="$REPORT_DIR/stig-audit-${TIMESTAMP}.json"
    {
        echo "DISA STIG Compliance Audit Report"
        echo "=================================="
        echo "Date: $(date)"
        echo "Host: $(hostname)"
        echo "OS: ${PRETTY_NAME:-unknown}"
        echo "Distro: $DISTRO_ID $DISTRO_VERSION (family: $DISTRO_FAMILY)"
        echo "Mode: $([ "$SCANNER_MODE" = "1" ] && echo "scanner (all checks)" || echo "interactive")"
        echo "Script: $APP_NAME $APP_VER"
        echo ""
    } > "$REPORT_TXT"
}

# ── 检查函数 ─────────────────────────────────────────────────
run_check() {
    local srg_id="$1" severity="$2" desc="$3"
    shift 3
    local result evidence

    # SRG 过滤
    if ! srg_enabled "$srg_id"; then
        result="SKIP"
        evidence="SRG $srg_id disabled by user"
    else
        local rc
        evidence=$("$@" 2>&1) && rc=0 || rc=$?
        case $rc in
            0) result="PASS" ;;
            1) result="FAIL" ;;
            2) result="WARN" ;;
            *) result="SKIP" ;;
        esac
    fi

    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    case "$result" in
        PASS) COUNT_PASS=$((COUNT_PASS + 1)) ;;
        FAIL) COUNT_FAIL=$((COUNT_FAIL + 1)) ;;
        WARN) COUNT_WARN=$((COUNT_WARN + 1)) ;;
        SKIP) COUNT_SKIP=$((COUNT_SKIP + 1)) ;;
    esac

    if [ "$QUIET" -eq 0 ]; then
        local color sev_label
        case "$result" in
            PASS) color="$C_OK" ;;
            FAIL) color="$C_FAIL" ;;
            WARN) color="$C_WARN" ;;
            SKIP) color="$C_INFO" ;;
        esac
        case "$severity" in
            CAT1) sev_label="${C_FAIL}I${C_RST}" ;;
            CAT2) sev_label="${C_WARN}II${C_RST}" ;;
            CAT3) sev_label="${C_INFO}III${C_RST}" ;;
        esac
        printf "  ${color}%-4s${C_RST} [%s] %s  %s\n" "$result" "$sev_label" "$srg_id" "$desc"
    fi

    {
        echo ""
        echo "[$result] $srg_id (Cat $severity) $desc"
        echo "  Evidence: $evidence"
    } >> "$REPORT_TXT"

    local json_entry
    json_entry=$(printf '{"id":"%s","severity":"%s","description":"%s","result":"%s","evidence":"%s"}' \
        "$srg_id" "$severity" "${desc//\"/\\\"}" "$result" "${evidence//\"/\\\"}")
    if [ "$TOTAL_CHECKS" -gt 1 ]; then
        JSON_RESULTS="$JSON_RESULTS,$json_entry"
    else
        JSON_RESULTS="$JSON_RESULTS$json_entry"
    fi
}

# ── 辅助函数 ─────────────────────────────────────────────────
check_sysctl() {
    local key="$1" expected="$2"
    local actual
    actual=$(sysctl -n "$key" 2>/dev/null || echo "N/A")
    if [ "$actual" = "N/A" ]; then
        echo "$key 不存在"; return 2
    elif [ "$actual" = "$expected" ]; then
        echo "$key = $actual"; return 0
    else
        echo "$key = $actual (期望 $expected)"; return 1
    fi
}

check_file_perm() {
    local path="$1" expected_perm="$2"
    if [ ! -e "$path" ]; then
        echo "文件不存在: $path"; return 2
    fi
    local actual
    actual=$(stat -c '%a' "$path" 2>/dev/null || stat -f '%Lp' "$path" 2>/dev/null)
    if [ "$actual" = "$expected_perm" ]; then
        echo "权限 $actual"; return 0
    else
        echo "期望 $expected_perm, 实际 $actual"; return 1
    fi
}

check_pkg_installed() {
    local pkg="$1"
    if [ "$DISTRO_FAMILY" = "debian" ]; then
        dpkg -l "$pkg" 2>/dev/null | grep -q "^ii" && return 0 || return 1
    else
        rpm -q "$pkg" >/dev/null 2>&1 && return 0 || return 1
    fi
}

check_service_enabled() {
    local svc="$1" state="$2"
    local actual
    actual=$(systemctl is-enabled "$svc" 2>/dev/null || echo "not-found")
    if [ "$actual" = "$state" ]; then
        echo "$svc is $state"; return 0
    else
        echo "$svc is $actual (期望 $state)"; return 1
    fi
}

# ── STIG SRG-OS-0000xx: Access Control ───────────────────────
section_access_control() {
    echo ""
    echo "━━━ Access Control (SRG-OS-0000xx) ━━━"

    run_check "SRG-OS-000023" "CAT1" "Ensure SSH root login is disabled" \
        bash -c 'val=$(sshd -T 2>/dev/null | awk "/^permitrootlogin /{print \$2}"); [ "$val" = "no" ] && echo "PermitRootLogin=no" && return 0 || echo "PermitRootLogin=$val (期望 no)" && return 1'

    run_check "SRG-OS-000024" "CAT1" "Ensure SSH protocol is 2" \
        bash -c 'val=$(sshd -T 2>/dev/null | awk "/^protocol /{print \$2}"); [ "$val" = "2" ] || [ -z "$val" ] && echo "Protocol=2 (default)" && return 0 || echo "Protocol=$val" && return 1'

    run_check "SRG-OS-000025" "CAT1" "Ensure SSH PermitEmptyPasswords is disabled" \
        bash -c 'val=$(sshd -T 2>/dev/null | awk "/^permitemptypasswords /{print \$2}"); [ "$val" = "no" ] && echo "PermitEmptyPasswords=no" && return 0 || echo "PermitEmptyPasswords=$val" && return 1'

    run_check "SRG-OS-000026" "CAT1" "Ensure SSH MaxAuthTries is 4 or less" \
        bash -c 'val=$(sshd -T 2>/dev/null | awk "/^maxauthtries /{print \$2}"); [ -n "$val" ] && [ "$val" -le 4 ] 2>/dev/null && echo "MaxAuthTries=$val" && return 0 || echo "MaxAuthTries=$val (期望 <=4)" && return 1'

    run_check "SRG-OS-000027" "CAT2" "Ensure SSH ClientAliveInterval is set" \
        bash -c 'val=$(sshd -T 2>/dev/null | awk "/^clientaliveinterval /{print \$2}"); [ -n "$val" ] && [ "$val" -le 900 ] 2>/dev/null && echo "ClientAliveInterval=$val" && return 0 || echo "ClientAliveInterval=$val (期望 <=900)" && return 1'

    run_check "SRG-OS-000028" "CAT2" "Ensure SSH LoginGraceTime is set to 60 or less" \
        bash -c 'val=$(sshd -T 2>/dev/null | awk "/^logingracetime /{print \$2}"); [ -n "$val" ] && [ "$val" -le 60 ] 2>/dev/null && echo "LoginGraceTime=$val" && return 0 || echo "LoginGraceTime=$val (期望 <=60)" && return 1'

    run_check "SRG-OS-000029" "CAT2" "Ensure SSH access is restricted to required users/groups" \
        bash -c 'sshd -T 2>/dev/null | grep -q "^allowusers\|^allowgroups" && echo "access list configured" && return 0 || echo "no SSH access restriction" && return 2'

    run_check "SRG-OS-000030" "CAT2" "Ensure SSH IgnoreRhosts is enabled" \
        bash -c 'val=$(sshd -T 2>/dev/null | awk "/^ignorerhosts /{print \$2}"); [ "$val" = "yes" ] && echo "IgnoreRhosts=yes" && return 0 || echo "IgnoreRhosts=$val" && return 1'

    run_check "SRG-OS-000031" "CAT2" "Ensure SSH HostbasedAuthentication is disabled" \
        bash -c 'val=$(sshd -T 2>/dev/null | awk "/^hostbasedauthentication /{print \$2}"); [ "$val" = "no" ] && echo "HostbasedAuthentication=no" && return 0 || echo "HostbasedAuthentication=$val" && return 1'
}

# ── STIG SRG-OS-0000xx: Audit and Accountability ─────────────
section_audit() {
    echo ""
    echo "━━━ Audit and Accountability (SRG-OS-0000xx) ━━━"

    run_check "SRG-OS-000032" "CAT1" "Ensure auditd is installed" \
        bash -c 'check_pkg_installed auditd && echo "auditd installed" && return 0 || echo "auditd not installed" && return 1'

    run_check "SRG-OS-000033" "CAT1" "Ensure auditd service is enabled" \
        bash -c 'check_service_enabled auditd enabled'

    run_check "SRG-OS-000034" "CAT1" "Ensure auditing for processes that start prior to auditd" \
        bash -c 'grep -q "audit=1" /proc/cmdline 2>/dev/null && echo "audit=1 in cmdline" && return 0 || echo "audit=1 not in bootloader" && return 1'

    run_check "SRG-OS-000035" "CAT2" "Ensure audit log storage size is configured" \
        bash -c 'grep -q "max_log_file" /etc/audit/auditd.conf 2>/dev/null && echo "max_log_file set" && return 0 || echo "max_log_file not configured" && return 2'

    run_check "SRG-OS-000036" "CAT2" "Ensure audit logs are not automatically deleted" \
        bash -c 'grep "max_log_file_action" /etc/audit/auditd.conf 2>/dev/null | grep -q "keep_logs" && echo "keep_logs" && return 0 || echo "max_log_file_action not keep_logs" && return 1'

    run_check "SRG-OS-000037" "CAT2" "Ensure auditd log directory permissions are configured" \
        bash -c 'dir=$(grep "^log_file" /etc/audit/auditd.conf 2>/dev/null | awk "{print \$3}" | sed "s|/[^/]*$||"); [ -d "$dir" ] && check_file_perm "$dir" 750 || echo "audit log dir not found" && return 2'

    run_check "SRG-OS-000038" "CAT1" "Ensure auditd rules for login/logout events" \
        bash -c 'grep -q "logins" /etc/audit/rules.d/*.rules 2>/dev/null || auditctl -l 2>/dev/null | grep -q "logins" && echo "login/logout audit rules present" && return 0 || echo "no login/logout audit rules" && return 1'

    run_check "SRG-OS-000039" "CAT1" "Ensure auditd rules for session initiation" \
        bash -c 'auditctl -l 2>/dev/null | grep -q "session" && echo "session audit rules present" && return 0 || echo "no session audit rules" && return 1'

    run_check "SRG-OS-000040" "CAT1" "Ensure auditd rules for file deletion events" \
        bash -c 'auditctl -l 2>/dev/null | grep -q "delete\|unlink" && echo "deletion audit rules present" && return 0 || echo "no deletion audit rules" && return 1'

    run_check "SRG-OS-000041" "CAT1" "Ensure auditd rules for permission change events" \
        bash -c 'auditctl -l 2>/dev/null | grep -q "chmod\|chown\|fchmod\|fchown" && echo "permission change audit rules present" && return 0 || echo "no permission change audit rules" && return 1'

    run_check "SRG-OS-000042" "CAT2" "Ensure auditd rules for unsuccessful access attempts" \
        bash -c 'auditctl -l 2>/dev/null | grep -qE "EACCES|EPERM" && echo "unsuccessful access audit rules present" && return 0 || echo "no unsuccessful access audit rules" && return 1'
}

# ── STIG SRG-OS-0000xx: Identification and Authentication ────
section_identification() {
    echo ""
    echo "━━━ Identification and Authentication (SRG-OS-0000xx) ━━━"

    run_check "SRG-OS-000043" "CAT1" "Ensure no users have empty password fields" \
        bash -c 'n=$(awk -F: "(\$2 == \"\") { print \$1 }" /etc/shadow 2>/dev/null | wc -l); [ "$n" -eq 0 ] && echo "no empty passwords" && return 0 || echo "$n empty passwords" && return 1'

    run_check "SRG-OS-000044" "CAT1" "Ensure root is the only UID 0 account" \
        bash -c 'n=$(awk -F: "(\$3 == 0) { print \$1 }" /etc/passwd | wc -l); [ "$n" -eq 1 ] && echo "only root has UID 0" && return 0 || echo "$n accounts with UID 0" && return 1'

    run_check "SRG-OS-000045" "CAT2" "Ensure password minimum length is configured" \
        bash -c '[ "$DISTRO_FAMILY" = "debian" ] && { grep -q "minlen" /etc/pam.d/common-password 2>/dev/null && echo "minlen configured" && return 0 || echo "no minlen in PAM" && return 1; } || { grep -q "minlen" /etc/security/pwquality.conf 2>/dev/null && echo "minlen configured" && return 0 || echo "no minlen" && return 1; }'

    run_check "SRG-OS-000046" "CAT2" "Ensure password complexity is configured" \
        bash -c '[ "$DISTRO_FAMILY" = "debian" ] && { grep -q "pam_pwquality\|pam_cracklib" /etc/pam.d/common-password 2>/dev/null && echo "pwquality configured" && return 0 || echo "no pwquality" && return 1; } || { grep -q "pam_pwquality" /etc/pam.d/system-auth 2>/dev/null && return 0 || echo "no pwquality" && return 1; }'

    run_check "SRG-OS-000047" "CAT2" "Ensure password reuse is restricted" \
        bash -c 'grep -q "remember=" /etc/pam.d/common-password /etc/pam.d/system-auth 2>/dev/null && echo "password reuse restricted" && return 0 || echo "no password reuse restriction" && return 1'

    run_check "SRG-OS-000048" "CAT2" "Ensure lockout for failed password attempts is configured" \
        bash -c 'grep -q "pam_faillock\|pam_tally2" /etc/pam.d/common-auth /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null && echo "faillock configured" && return 0 || echo "no faillock" && return 1'

    run_check "SRG-OS-000049" "CAT2" "Ensure password hashing algorithm is up to date" \
        bash -c 'grep -q "yescrypt\|sha512" /etc/pam.d/common-password /etc/pam.d/system-auth 2>/dev/null && echo "strong hash configured" && return 0 || echo "hash algorithm not verified" && return 2'

    run_check "SRG-OS-000050" "CAT2" "Ensure no duplicate UIDs exist" \
        bash -c 'dups=$(awk -F: "{print \$3}" /etc/passwd | sort | uniq -d); [ -z "$dups" ] && echo "no duplicate UIDs" && return 0 || echo "duplicate UIDs: $dups" && return 1'

    run_check "SRG-OS-000051" "CAT2" "Ensure no duplicate user names exist" \
        bash -c 'dups=$(awk -F: "{print \$1}" /etc/passwd | sort | uniq -d); [ -z "$dups" ] && echo "no duplicate users" && return 0 || echo "duplicate users: $dups" && return 1'
}

# ── STIG SRG-OS-0000xx: System and Information Integrity ─────
section_integrity() {
    echo ""
    echo "━━━ System and Information Integrity (SRG-OS-0000xx) ━━━"

    run_check "SRG-OS-000052" "CAT1" "Ensure ASLR is enabled" \
        bash -c 'check_sysctl kernel.randomize_va_space 2'

    run_check "SRG-OS-000053" "CAT1" "Ensure core dumps are restricted" \
        bash -c 'check_sysctl fs.suid_dumpable 0'

    run_check "SRG-OS-000054" "CAT2" "Ensure kernel.kptr_restrict is set" \
        bash -c 'check_sysctl kernel.kptr_restrict 2'

    run_check "SRG-OS-000055" "CAT2" "Ensure kernel.dmesg_restrict is set" \
        bash -c 'check_sysctl kernel.dmesg_restrict 1'

    run_check "SRG-OS-000056" "CAT2" "Ensure kernel.perf_event_paranoid is set" \
        bash -c 'check_sysctl kernel.perf_event_paranoid 2'

    run_check "SRG-OS-000057" "CAT2" "Ensure kernel.yama.ptrace_scope is set" \
        bash -c 'check_sysctl kernel.yama.ptrace_scope 1'

    run_check "SRG-OS-000058" "CAT1" "Ensure AIDE is installed" \
        bash -c 'check_pkg_installed aide && echo "AIDE installed" && return 0 || echo "AIDE not installed" && return 1'

    run_check "SRG-OS-000059" "CAT2" "Ensure AIDE database is initialized" \
        bash -c '[ -f /var/lib/aide/aide.db.gz ] || [ -f /var/lib/aide/aide.db ] && echo "AIDE database exists" && return 0 || echo "AIDE database not initialized" && return 1'

    run_check "SRG-OS-000060" "CAT2" "Ensure file integrity tool is run regularly" \
        bash -c 'crontab -l 2>/dev/null | grep -q aide || ls /etc/cron.d/ 2>/dev/null | grep -q aide && echo "AIDE cron configured" && return 0 || echo "no AIDE cron" && return 1'

    run_check "SRG-OS-000061" "CAT2" "Ensure rsyslog is installed and enabled" \
        bash -c 'check_pkg_installed rsyslog && check_service_enabled rsyslog enabled'
}

# ── STIG SRG-OS-0000xx: Configuration Management ─────────────
section_config_management() {
    echo ""
    echo "━━━ Configuration Management (SRG-OS-0000xx) ━━━"

    run_check "SRG-OS-000062" "CAT2" "Ensure permissions on /etc/passwd are 644" \
        bash -c 'check_file_perm /etc/passwd 644'

    run_check "SRG-OS-000063" "CAT2" "Ensure permissions on /etc/shadow are 640 or more restrictive" \
        bash -c 'check_file_perm /etc/shadow 640'

    run_check "SRG-OS-000064" "CAT2" "Ensure permissions on /etc/group are 644" \
        bash -c 'check_file_perm /etc/group 644'

    run_check "SRG-OS-000065" "CAT2" "Ensure permissions on /etc/gshadow are 640 or more restrictive" \
        bash -c 'check_file_perm /etc/gshadow 640'

    run_check "SRG-OS-000066" "CAT2" "Ensure permissions on /etc/crontab are configured" \
        bash -c 'check_file_perm /etc/crontab 600'

    run_check "SRG-OS-000067" "CAT2" "Ensure permissions on /etc/cron.hourly are configured" \
        bash -c 'check_file_perm /etc/cron.hourly 700'

    run_check "SRG-OS-000068" "CAT2" "Ensure permissions on /etc/cron.daily are configured" \
        bash -c 'check_file_perm /etc/cron.daily 700'

    run_check "SRG-OS-000069" "CAT2" "Ensure permissions on /etc/cron.weekly are configured" \
        bash -c 'check_file_perm /etc/cron.weekly 700'

    run_check "SRG-OS-000070" "CAT2" "Ensure permissions on /etc/cron.monthly are configured" \
        bash -c 'check_file_perm /etc/cron.monthly 700'

    run_check "SRG-OS-000071" "CAT2" "Ensure permissions on /etc/cron.d are configured" \
        bash -c 'check_file_perm /etc/cron.d 700'

    run_check "SRG-OS-000072" "CAT1" "Ensure no world writable files exist" \
        bash -c 'n=$(df --local -P 2>/dev/null | awk "{if (NR!=1) print \$6}" | xargs -I "{}" find "{}" -xdev -type f -perm -0002 2>/dev/null | wc -l); [ "$n" -eq 0 ] && echo "no world writable files" && return 0 || echo "$n world writable files" && return 1'

    run_check "SRG-OS-000073" "CAT2" "Ensure no unowned files or directories exist" \
        bash -c 'n=$(df --local -P 2>/dev/null | awk "{if (NR!=1) print \$6}" | xargs -I "{}" find "{}" -xdev -nouser 2>/dev/null | wc -l); [ "$n" -eq 0 ] && echo "no unowned files" && return 0 || echo "$n unowned files" && return 1'

    run_check "SRG-OS-000074" "CAT2" "Ensure no ungrouped files or directories exist" \
        bash -c 'n=$(df --local -P 2>/dev/null | awk "{if (NR!=1) print \$6}" | xargs -I "{}" find "{}" -xdev -nogroup 2>/dev/null | wc -l); [ "$n" -eq 0 ] && echo "no ungrouped files" && return 0 || echo "$n ungrouped files" && return 1'
}

# ── STIG SRG-OS-0000xx: Network Security ─────────────────────
section_network_security() {
    echo ""
    echo "━━━ Network Security (SRG-OS-0000xx) ━━━"

    run_check "SRG-OS-000075" "CAT1" "Ensure IP forwarding is disabled" \
        bash -c 'check_sysctl net.ipv4.ip_forward 0; check_sysctl net.ipv6.conf.all.forwarding 0'

    run_check "SRG-OS-000076" "CAT1" "Ensure packet redirect sending is disabled" \
        bash -c 'check_sysctl net.ipv4.conf.all.send_redirects 0; check_sysctl net.ipv4.conf.default.send_redirects 0'

    run_check "SRG-OS-000077" "CAT1" "Ensure source routed packets are not accepted" \
        bash -c 'check_sysctl net.ipv4.conf.all.accept_source_route 0; check_sysctl net.ipv6.conf.all.accept_source_route 0'

    run_check "SRG-OS-000078" "CAT1" "Ensure ICMP redirects are not accepted" \
        bash -c 'check_sysctl net.ipv4.conf.all.accept_redirects 0; check_sysctl net.ipv6.conf.all.accept_redirects 0'

    run_check "SRG-OS-000079" "CAT2" "Ensure secure ICMP redirects are not accepted" \
        bash -c 'check_sysctl net.ipv4.conf.all.secure_redirects 0'

    run_check "SRG-OS-000080" "CAT2" "Ensure suspicious packets are logged" \
        bash -c 'check_sysctl net.ipv4.conf.all.log_martians 1'

    run_check "SRG-OS-000081" "CAT1" "Ensure TCP SYN cookies is enabled" \
        bash -c 'check_sysctl net.ipv4.tcp_syncookies 1'

    run_check "SRG-OS-000082" "CAT2" "Ensure IPv6 router advertisements are not accepted" \
        bash -c 'check_sysctl net.ipv6.conf.all.accept_ra 0'

    run_check "SRG-OS-000083" "CAT1" "Ensure firewall is installed" \
        bash -c '{ check_pkg_installed ufw || check_pkg_installed firewalld || check_pkg_installed nftables; } && echo "firewall installed" && return 0 || echo "no firewall package" && return 1'

    run_check "SRG-OS-000084" "CAT1" "Ensure firewall is active" \
        bash -c 'ufw status 2>/dev/null | grep -q "active" && return 0 || firewall-cmd --state 2>/dev/null | grep -q "running" && return 0 || systemctl is-active nftables 2>/dev/null | grep -q active && return 0 || echo "no firewall active" && return 1'
}

# ── STIG SRG-OS-0000xx: Operating System Hardening ───────────
section_os_hardening() {
    echo ""
    echo "━━━ Operating System Hardening (SRG-OS-0000xx) ━━━"

    run_check "SRG-OS-000085" "CAT1" "Ensure SELinux or AppArmor is enabled" \
        bash -c '[ "$DISTRO_FAMILY" = "debian" ] && { apparmor_status 2>/dev/null | grep -q "profiles are loaded" && echo "AppArmor active" && return 0 || echo "AppArmor not active" && return 1; } || { sestatus 2>/dev/null | grep -q "enforcing" && echo "SELinux enforcing" && return 0 || echo "SELinux not enforcing" && return 1; }'

    run_check "SRG-OS-000086" "CAT2" "Ensure bootloader password is set" \
        bash -c 'grep -q "password" /boot/grub/grub.cfg 2>/dev/null && echo "password set" && return 0 || grep -q "password_pbkdf2" /boot/grub/grub.cfg 2>/dev/null && return 0 || echo "no bootloader password" && return 1'

    run_check "SRG-OS-000087" "CAT2" "Ensure permissions on bootloader config are configured" \
        bash -c '[ -f /boot/grub/grub.cfg ] && check_file_perm /boot/grub/grub.cfg 400 || echo "grub.cfg not at standard path" && return 2'

    run_check "SRG-OS-000088" "CAT2" "Ensure warning banners are configured" \
        bash -c '[ -f /etc/issue ] && grep -qiE "authorized|security|restricted" /etc/issue && echo "issue has warning" && return 0 || echo "issue lacks warning" && return 1'

    run_check "SRG-OS-000089" "CAT2" "Ensure GDM login banner is configured (if GUI)" \
        bash -c 'check_pkg_installed gdm3 2>/dev/null || check_pkg_installed gdm 2>/dev/null && { grep -q "banner-message-enable" /etc/gdm3/greeter.dconf-defaults 2>/dev/null && return 0 || echo "GDM banner not configured" && return 1; } || echo "no GDM (headless)" && return 3'

    run_check "SRG-OS-000090" "CAT2" "Ensure time synchronization is in use" \
        bash -c '{ check_pkg_installed chrony || check_pkg_installed systemd-timesyncd || check_pkg_installed ntp; } && echo "time sync installed" && return 0 || echo "no time sync" && return 1'

    run_check "SRG-OS-000091" "CAT2" "Ensure X Window System is not installed" \
        bash -c '! check_pkg_installed xserver-xorg 2>/dev/null && ! rpm -q xorg-x11-server-Xorg >/dev/null 2>&1 && echo "X not installed" && return 0 || echo "X installed on server" && return 1'

    run_check "SRG-OS-000092" "CAT2" "Ensure unnecessary services are not installed (Avahi/CUPS/DHCP)" \
        bash -c '! check_pkg_installed avahi-daemon 2>/dev/null && ! check_pkg_installed cups 2>/dev/null && ! check_pkg_installed dhcp-server 2>/dev/null && echo "unnecessary services not installed" && return 0 || echo "unnecessary service found" && return 1'

    run_check "SRG-OS-000093" "CAT2" "Ensure mail server is not installed (unless required)" \
        bash -c '! check_pkg_installed postfix 2>/dev/null && ! check_pkg_installed sendmail 2>/dev/null && echo "no mail server" && return 0 || echo "mail server installed" && return 2'
}

# ── 摘要输出 ─────────────────────────────────────────────────
print_summary() {
    local total=$TOTAL_CHECKS
    local pass_pct=0
    [ "$total" -gt 0 ] && pass_pct=$((COUNT_PASS * 100 / total))

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  DISA STIG Compliance Audit Summary"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    printf "  Total checks:  %d\n" "$total"
    printf "  ${C_OK}PASS${C_RST}:           %d\n" "$COUNT_PASS"
    printf "  ${C_FAIL}FAIL${C_RST}:           %d\n" "$COUNT_FAIL"
    printf "  ${C_WARN}WARN${C_RST}:           %d\n" "$COUNT_WARN"
    printf "  ${C_INFO}SKIP${C_RST}:           %d\n" "$COUNT_SKIP"
    printf "  Compliance:     %d%%\n" "$pass_pct"
    echo ""
    echo "  Severity breakdown:"
    printf "    CAT I (high):   %d FAIL\n" "$(grep -c "Cat I.*FAIL" "$REPORT_TXT" 2>/dev/null || echo 0)"
    printf "    CAT II (medium): %d FAIL\n" "$(grep -c "CAT2.*FAIL" "$REPORT_TXT" 2>/dev/null || echo 0)"
    echo ""
    echo "  Reports:"
    echo "    TXT:  $REPORT_TXT"
    echo "    JSON: $REPORT_JSON"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# ── JSON 报告 ────────────────────────────────────────────────
write_json_report() {
    JSON_RESULTS="$JSON_RESULTS]"
    cat > "$REPORT_JSON" <<EOF
{
  "audit": {
    "tool": "$APP_NAME",
    "version": "$APP_VER",
    "timestamp": "$(date -Iseconds 2>/dev/null || date)",
    "host": "$(hostname)",
    "os": "${PRETTY_NAME:-unknown}",
    "distro": "$DISTRO_ID",
    "distro_version": "$DISTRO_VERSION",
    "distro_family": "$DISTRO_FAMILY",
    "scanner_mode": $SCANNER_MODE
  },
  "summary": {
    "total": $TOTAL_CHECKS,
    "pass": $COUNT_PASS,
    "fail": $COUNT_FAIL,
    "warn": $COUNT_WARN,
    "skip": $COUNT_SKIP,
    "compliance_pct": $([ "$TOTAL_CHECKS" -gt 0 ] && echo $((COUNT_PASS * 100 / TOTAL_CHECKS)) || echo 0)
  },
  "results": $JSON_RESULTS
}
EOF
}

# ── 主流程 ───────────────────────────────────────────────────
main() {
    parse_args "$@"
    detect_distro
    init_report

    if [ "$QUIET" -eq 0 ]; then
        echo ""
        echo -e "${C_INFO}╔══════════════════════════════════════════╗${C_RST}"
        echo -e "${C_INFO}║  DISA STIG Compliance Check               ║${C_RST}"
        echo -e "${C_INFO}║  $APP_NAME $APP_VER                       ║${C_RST}"
        echo -e "${C_INFO}╚══════════════════════════════════════════╝${C_RST}"
        echo -e "${C_INFO}Host: ${PRETTY_NAME:-unknown}${C_RST}"
        echo -e "${C_INFO}Mode: $([ "$SCANNER_MODE" = "1" ] && echo "scanner (all checks)" || echo "interactive")${C_RST}"
        echo -e "${C_INFO}Severity: CAT I (high) / CAT II (medium) / CAT III (low)${C_RST}"
        echo -e "${C_INFO}Read-only: no system changes${C_RST}"
        echo ""
    fi

    section_access_control
    section_audit
    section_identification
    section_integrity
    section_config_management
    section_network_security
    section_os_hardening

    write_json_report
    print_summary

    [ "$JSON_ONLY" -eq 1 ] && echo "$REPORT_JSON"
    return 0
}

main "$@"
