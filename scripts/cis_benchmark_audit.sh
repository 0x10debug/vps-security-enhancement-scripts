#!/bin/bash
# ════════════════════════════════════════════════════════════
#  cis_benchmark_audit.sh — CIS Benchmark Compliance Audit
#  适用系统: Ubuntu / Debian / RHEL / CentOS / AlmaLinux / Rocky
#  运行身份: root (推荐) / 普通用户 (部分检查受限)
#  审计模式: 只读, 不修改任何系统配置
#  参考: CIS Benchmarks v2.0.0 (Ubuntu 22.04/24.04, RHEL 8/9)
#  项目主页: https://github.com/0x10debug/vps-security-enhancement-scripts
# ════════════════════════════════════════════════════════════
#
# 用法:
#   sudo ./cis_benchmark_audit.sh              # 交互式选择级别
#   sudo ./cis_benchmark_audit.sh --level 1    # Level 1 (基础)
#   sudo ./cis_benchmark_audit.sh --level 2    # Level 2 (深度)
#   sudo ./cis_benchmark_audit.sh --json       # 输出 JSON 报告路径
#   sudo ./cis_benchmark_audit.sh --quiet      # 只输出摘要
#
# 退出码:
#   0 — 审计完成 (不论是否合规)
#   1 — 参数错误
#   2 — 不支持的发行版

set -euo pipefail

# ── 全局变量 ─────────────────────────────────────────────────
APP_NAME="cis_benchmark_audit"
APP_VER="v2.1.0"
CIS_LEVEL=1
QUIET=0
JSON_ONLY=0
REPORT_DIR="/var/log/cis-audit"
REPORT_TXT=""
REPORT_JSON=""
TIMESTAMP=$(date +%Y%m%d%H%M%S)

# 计数器
COUNT_PASS=0
COUNT_FAIL=0
COUNT_WARN=0
COUNT_SKIP=0
TOTAL_CHECKS=0

# JSON 结果数组
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
        DISTRO_FAMILY=""
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
            --level) CIS_LEVEL="$2"; shift 2 ;;
            --quiet) QUIET=1; shift ;;
            --json) JSON_ONLY=1; shift ;;
            -h|--help)
                sed -n '2,20p' "$0"
                exit 0
                ;;
            *) echo "未知参数: $1"; exit 1 ;;
        esac
    done
    if [ "$CIS_LEVEL" != "1" ] && [ "$CIS_LEVEL" != "2" ]; then
        echo "级别必须是 1 或 2"; exit 1
    fi
}

# ── 报告初始化 ───────────────────────────────────────────────
init_report() {
    mkdir -p "$REPORT_DIR" 2>/dev/null || true
    REPORT_TXT="$REPORT_DIR/cis-audit-${TIMESTAMP}.txt"
    REPORT_JSON="$REPORT_DIR/cis-audit-${TIMESTAMP}.json"
    {
        echo "CIS Benchmark Compliance Audit Report"
        echo "======================================"
        echo "Date: $(date)"
        echo "Host: $(hostname)"
        echo "OS: ${PRETTY_NAME:-unknown}"
        echo "Distro: $DISTRO_ID $DISTRO_VERSION (family: $DISTRO_FAMILY)"
        echo "Level: $CIS_LEVEL"
        echo "Script: $APP_NAME $APP_VER"
        echo ""
    } > "$REPORT_TXT"
}

# ── 检查函数 ─────────────────────────────────────────────────
# 用法: run_check <cis_id> <description> <level> <check_cmd...>
# check_cmd 返回 0=PASS, 1=FAIL, 2=WARN, 3=SKIP
run_check() {
    local cis_id="$1" desc="$2" level="$3"
    shift 3
    local result evidence

    # 级别过滤: Level 2 检查在 Level 1 模式下跳过
    if [ "$level" -gt "$CIS_LEVEL" ]; then
        result="SKIP"
        evidence="Level $level check, skipped in Level $CIS_LEVEL mode"
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

    # 控制台输出
    if [ "$QUIET" -eq 0 ]; then
        local color
        case "$result" in
            PASS) color="$C_OK" ;;
            FAIL) color="$C_FAIL" ;;
            WARN) color="$C_WARN" ;;
            SKIP) color="$C_INFO" ;;
        esac
        printf "  ${color}%-4s${C_RST} %s  %s\n" "$result" "$cis_id" "$desc"
    fi

    # 文本报告
    {
        echo ""
        echo "[$result] $cis_id ($level) $desc"
        echo "  Evidence: $evidence"
    } >> "$REPORT_TXT"

    # JSON 累积
    local json_entry
    json_entry=$(printf '{"id":"%s","description":"%s","level":%d,"result":"%s","evidence":"%s"}' \
        "$cis_id" "${desc//\"/\\\"}" "$level" "$result" "${evidence//\"/\\\"}")
    if [ "$TOTAL_CHECKS" -gt 1 ]; then
        JSON_RESULTS="$JSON_RESULTS,$json_entry"
    else
        JSON_RESULTS="$JSON_RESULTS$json_entry"
    fi
}

# ── 辅助检查函数 (返回 0=PASS, 1=FAIL, 2=WARN) ──────────────

# 检查文件是否存在且权限正确
check_file_perm() {
    local path="$1" expected_perm="$2"
    if [ ! -e "$path" ]; then
        echo "文件不存在: $path"
        return 2
    fi
    local actual
    actual=$(stat -c '%a' "$path" 2>/dev/null || stat -f '%Lp' "$path" 2>/dev/null)
    if [ "$actual" = "$expected_perm" ]; then
        echo "权限 $actual"
        return 0
    else
        echo "期望 $expected_perm, 实际 $actual"
        return 1
    fi
}

# 检查 sysctl 值
check_sysctl() {
    local key="$1" expected="$2"
    local actual
    actual=$(sysctl -n "$key" 2>/dev/null || echo "N/A")
    if [ "$actual" = "N/A" ]; then
        echo "$key 不存在"
        return 2
    elif [ "$actual" = "$expected" ]; then
        echo "$key = $actual"
        return 0
    else
        echo "$key = $actual (期望 $expected)"
        return 1
    fi
}

# 检查某包是否安装
check_pkg_installed() {
    local pkg="$1"
    if [ "$DISTRO_FAMILY" = "debian" ]; then
        dpkg -l "$pkg" 2>/dev/null | grep -q "^ii" && return 0 || return 1
    else
        rpm -q "$pkg" >/dev/null 2>&1 && return 0 || return 1
    fi
}

# 检查服务状态
check_service_enabled() {
    local svc="$1" state="$2"  # state: enabled/disabled/masked
    local actual
    actual=$(systemctl is-enabled "$svc" 2>/dev/null || echo "not-found")
    if [ "$actual" = "$state" ]; then
        echo "$svc is $state"
        return 0
    else
        echo "$svc is $actual (期望 $state)"
        return 1
    fi
}

check_service_active() {
    local svc="$1" state="$2"  # state: active/inactive
    local actual
    actual=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
    if [ "$actual" = "$state" ]; then
        echo "$svc is $state"
        return 0
    else
        echo "$svc is $actual (期望 $state)"
        return 1
    fi
}

# ── CIS 1.x: Initial Setup ───────────────────────────────────
section_1_initial_setup() {
    echo ""
    echo "━━━ 1.x Initial Setup ━━━"

    # 1.1 Filesystem
    run_check "1.1.1.1" "Ensure mounting of cramfs filesystems is disabled" 1 \
        bash -c 'modprobe -n -v cramfs 2>/dev/null | grep -q "install /bin/true" && echo "cramfs disabled" && return 0 || { lsmod | grep -q cramfs && echo "cramfs loaded" && return 1; } || echo "cramfs not loaded (ok)" && return 0'

    run_check "1.1.2" "Ensure /tmp is configured" 1 \
        bash -c 'mount | grep -q "on /tmp " && echo "/tmp mounted" && return 0 || echo "/tmp not separate mount" && return 2'

    run_check "1.1.3" "Ensure nodev option set on /tmp partition" 1 \
        bash -c 'mount | grep "on /tmp " | grep -q nodev && return 0 || echo "nodev not set on /tmp" && return 1'

    run_check "1.1.4" "Ensure nosuid option set on /tmp partition" 1 \
        bash -c 'mount | grep "on /tmp " | grep -q nosuid && return 0 || echo "nosuid not set on /tmp" && return 1'

    run_check "1.1.5" "Ensure noexec option set on /tmp partition" 1 \
        bash -c 'mount | grep "on /tmp " | grep -q noexec && return 0 || echo "noexec not set on /tmp" && return 1'

    # 1.2 Software updates
    run_check "1.2.1" "Ensure GPG keys are configured (RHEL) / package manager configured" 1 \
        bash -c '[ "$DISTRO_FAMILY" = "rhel" ] && { rpm -q gpg-pubkey >/dev/null 2>&1 && echo "GPG keys installed" && return 0; } || echo "Debian family: apt uses signed repos" && return 0'

    run_check "1.2.2" "Ensure package manager repositories are configured" 1 \
        bash -c '[ "$DISTRO_FAMILY" = "debian" ] && apt-cache policy 2>/dev/null | grep -q "http" && return 0 || { [ "$DISTRO_FAMILY" = "rhel" ] && yum repolist 2>/dev/null | grep -q "repolist" && return 0; } || echo "无法确认仓库配置" && return 2'

    run_check "1.2.3" "Ensure gpgcheck is globally activated (RHEL)" 1 \
        bash -c '[ "$DISTRO_FAMILY" = "rhel" ] && { grep -q "gpgcheck=1" /etc/yum.conf 2>/dev/null && echo "gpgcheck=1" && return 0 || echo "gpgcheck not set" && return 1; } || echo "Debian: apt uses signed repos by default" && return 0'

    # 1.3 Mandatory access control
    if [ "$DISTRO_FAMILY" = "debian" ]; then
        run_check "1.3.1" "Ensure AppArmor is installed" 1 \
            bash -c 'check_pkg_installed apparmor && echo "apparmor installed" && return 0 || echo "apparmor not installed" && return 1'
        run_check "1.3.2" "Ensure AppArmor is enabled in kernel" 1 \
            bash -c 'grep -q "apparmor=1" /proc/cmdline 2>/dev/null && echo "apparmor=1 in cmdline" && return 0 || echo "apparmor not in cmdline" && return 2'
        run_check "1.3.3" "Ensure AppArmor is active" 1 \
            bash -c 'apparmor_status 2>/dev/null | grep -q "profiles are loaded" && return 0 || echo "apparmor not active" && return 1'
    else
        run_check "1.3.1" "Ensure SELinux is installed" 1 \
            bash -c 'check_pkg_installed libselinux && echo "libselinux installed" && return 0 || echo "libselinux not installed" && return 1'
        run_check "1.3.2" "Ensure SELinux is not disabled in bootloader" 1 \
            bash -c 'grep -q "selinux=0" /proc/cmdline 2>/dev/null && echo "selinux=0 found (bad)" && return 1 || echo "selinux not disabled in bootloader" && return 0'
        run_check "1.3.3" "Ensure SELinux policy is configured" 1 \
            bash -c 'sestatus 2>/dev/null | grep -q "Loaded policy name" && return 0 || echo "SELinux policy not loaded" && return 1'
    fi

    # 1.4 Bootloader
    run_check "1.4.1" "Ensure permissions on bootloader config are configured" 1 \
        bash -c '[ -f /boot/grub/grub.cfg ] && check_file_perm /boot/grub/grub.cfg 400 || echo "grub.cfg not at standard path" && return 2'

    run_check "1.4.2" "Ensure bootloader password is set" 2 \
        bash -c 'grep -q "password" /boot/grub/grub.cfg 2>/dev/null && echo "password set" && return 0 || grep -q "password_pbkdf2" /boot/grub/grub.cfg 2>/dev/null && return 0 || echo "no bootloader password" && return 1'

    # 1.5 Kernel hardening
    run_check "1.5.1" "Ensure address space layout randomization (ASLR) is enabled" 1 \
        bash -c 'check_sysctl kernel.randomize_va_space 2'

    run_check "1.5.2" "Ensure core dumps are restricted" 1 \
        bash -c 'check_sysctl fs.suid_dumpable 0'

    run_check "1.5.3" "Ensure kernel.kptr_restrict is set" 1 \
        bash -c 'check_sysctl kernel.kptr_restrict 2'

    run_check "1.5.4" "Ensure kernel.dmesg_restrict is set" 1 \
        bash -c 'check_sysctl kernel.dmesg_restrict 1'

    run_check "1.5.5" "Ensure kernel.kexec_load_disabled is set" 2 \
        bash -c 'check_sysctl kernel.kexec_load_disabled 1'

    # 1.6 Hardening (Debian: 1.6.x = various, RHEL: 1.6 = SELinux already above)
    # 1.7 Warning banners
    run_check "1.7.1" "Ensure message of the day is configured properly" 1 \
        bash -c '[ -f /etc/motd ] && head -1 /etc/motd | grep -qiE "authorized|security|monitor" && echo "motd has warning" && return 0 || echo "motd lacks warning" && return 1'

    run_check "1.7.2" "Ensure local login warning banner is configured" 1 \
        bash -c '[ -f /etc/issue ] && grep -qiE "authorized|security|restricted" /etc/issue && echo "issue has warning" && return 0 || echo "issue lacks warning" && return 1'

    run_check "1.7.3" "Ensure remote login warning banner is configured" 1 \
        bash -c '[ -f /etc/issue.net ] && grep -qiE "authorized|security|restricted" /etc/issue.net && echo "issue.net has warning" && return 0 || echo "issue.net lacks warning" && return 1'
}

# ── CIS 2.x: Services ────────────────────────────────────────
section_2_services() {
    echo ""
    echo "━━━ 2.x Services ━━━"

    # 2.1 Time sync
    run_check "2.1.1.1" "Ensure time synchronization is in use" 1 \
        bash -c '{ check_pkg_installed chrony || check_pkg_installed systemd-timesyncd || check_pkg_installed ntp; } && echo "time sync installed" && return 0 || echo "no time sync package" && return 1'

    run_check "2.1.2" "Ensure systemd-timesyncd configured or chrony active" 1 \
        bash -c 'systemctl is-active systemd-timesyncd 2>/dev/null | grep -q active && return 0 || systemctl is-active chronyd 2>/dev/null | grep -q active && return 0 || systemctl is-active ntpd 2>/dev/null | grep -q active && return 0 || echo "no time sync service active" && return 1'

    # 2.2 X Window System
    run_check "2.2.1" "Ensure X Window System is not installed" 1 \
        bash -c '! check_pkg_installed xserver-xorg* 2>/dev/null && ! rpm -q xorg-x11-server-Xorg >/dev/null 2>&1 && echo "X not installed" && return 0 || echo "X installed on server" && return 1'

    # 2.3 Avahi / CUPS / DHCP / LDAP / NFS / DNS / FTP
    for svc_pkg in "avahi-daemon:Avahi" "cups:CUPS" "dhcp-server:DHCP server" "slapd:LDAP" "nfs-kernel-server:NFS server" "bind9:DNS server" "vsftpd:FTP server"; do
        local pkg="${svc_pkg%%:*}" name="${svc_pkg##*:}"
        run_check "2.x" "Ensure $name is not installed (server)" 1 \
            bash -c "! check_pkg_installed $pkg 2>/dev/null && echo '$pkg not installed' && return 0 || echo '$pkg installed' && return 1"
    done

    # 2.4 Mail server
    run_check "2.4" "Ensure mail server is not installed (unless required)" 1 \
        bash -c '! check_pkg_installed postfix 2>/dev/null && ! check_pkg_installed sendmail 2>/dev/null && echo "no mail server" && return 0 || echo "mail server installed" && return 2'
}

# ── CIS 3.x: Network Configuration ───────────────────────────
section_3_network() {
    echo ""
    echo "━━━ 3.x Network Configuration ━━━"

    # 3.1 Network parameters (host)
    run_check "3.1.1" "Ensure IPv6 is disabled if not in use" 2 \
        bash -c 'check_sysctl net.ipv6.conf.all.disable_ipv6 1; check_sysctl net.ipv6.conf.default.disable_ipv6 1'

    run_check "3.1.2" "Ensure packet redirect sending is disabled" 1 \
        bash -c 'check_sysctl net.ipv4.conf.all.send_redirects 0; check_sysctl net.ipv4.conf.default.send_redirects 0'

    run_check "3.1.3" "Ensure IP forwarding is disabled" 1 \
        bash -c 'check_sysctl net.ipv4.ip_forward 0; check_sysctl net.ipv6.conf.all.forwarding 0'

    # 3.2 Network parameters (routing)
    run_check "3.2.1" "Ensure source routed packets are not accepted" 1 \
        bash -c 'check_sysctl net.ipv4.conf.all.accept_source_route 0; check_sysctl net.ipv6.conf.all.accept_source_route 0'

    run_check "3.2.2" "Ensure ICMP redirects are not accepted" 1 \
        bash -c 'check_sysctl net.ipv4.conf.all.accept_redirects 0; check_sysctl net.ipv6.conf.all.accept_redirects 0'

    # 3.3 Secure ICMP
    run_check "3.3.1" "Ensure secure ICMP redirects are not accepted" 1 \
        bash -c 'check_sysctl net.ipv4.conf.all.secure_redirects 0'

    run_check "3.3.2" "Ensure suspicious packets are logged" 2 \
        bash -c 'check_sysctl net.ipv4.conf.all.log_martians 1'

    # 3.4 TCP/IP hardening
    run_check "3.4.1" "Ensure TCP SYN cookies is enabled" 1 \
        bash -c 'check_sysctl net.ipv4.tcp_syncookies 1'

    run_check "3.4.2" "Ensure IPv6 router advertisements are not accepted" 1 \
        bash -c 'check_sysctl net.ipv6.conf.all.accept_ra 0'

    # 3.5 Firewall
    run_check "3.5.1.1" "Ensure firewall is installed (ufw/firewalld/nftables)" 1 \
        bash -c '{ check_pkg_installed ufw || check_pkg_installed firewalld || check_pkg_installed nftables; } && echo "firewall installed" && return 0 || echo "no firewall package" && return 1'

    run_check "3.5.1.2" "Ensure firewall is active" 1 \
        bash -c 'ufw status 2>/dev/null | grep -q "active" && return 0 || firewall-cmd --state 2>/dev/null | grep -q "running" && return 0 || systemctl is-active nftables 2>/dev/null | grep -q active && return 0 || echo "no firewall active" && return 1'
}

# ── CIS 4.x: Logging and Auditing ────────────────────────────
section_4_logging() {
    echo ""
    echo "━━━ 4.x Logging and Auditing ━━━"

    # 4.1 rsyslog
    run_check "4.1.1.1" "Ensure rsyslog is installed" 1 \
        bash -c 'check_pkg_installed rsyslog && echo "rsyslog installed" && return 0 || echo "rsyslog not installed" && return 1'

    run_check "4.1.1.2" "Ensure rsyslog service is enabled" 1 \
        bash -c 'check_service_enabled rsyslog enabled'

    run_check "4.1.1.3" "Ensure rsyslog default file permissions configured" 1 \
        bash -c 'grep -q "\$FileCreateMode" /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null && echo "FileCreateMode set" && return 0 || echo "FileCreateMode not set (default 0644 ok)" && return 2'

    # 4.2 journald
    run_check "4.2.1.1" "Ensure journald is configured to send logs to rsyslog" 1 \
        bash -c 'grep -q "ForwardToSyslog=yes" /etc/systemd/journald.conf 2>/dev/null && echo "ForwardToSyslog=yes" && return 0 || echo "ForwardToSyslog not set (default varies)" && return 2'

    run_check "4.2.1.2" "Ensure journald log file rotation is configured" 1 \
        bash -c 'grep -q "MaxRetentionSec" /etc/systemd/journald.conf 2>/dev/null && grep -v "^#" /etc/systemd/journald.conf | grep -q "MaxRetentionSec" && return 0 || echo "MaxRetentionSec not configured" && return 2'

    # 4.3 logrotate
    run_check "4.3" "Ensure logrotate is configured" 1 \
        bash -c 'check_pkg_installed logrotate && echo "logrotate installed" && return 0 || echo "logrotate not installed" && return 1'

    # 4.4 auditd
    run_check "4.4.1.1" "Ensure auditd is installed" 1 \
        bash -c 'check_pkg_installed auditd && echo "auditd installed" && return 0 || echo "auditd not installed" && return 1'

    run_check "4.4.1.2" "Ensure auditd service is enabled" 1 \
        bash -c 'check_service_enabled auditd enabled'

    run_check "4.4.1.3" "Ensure auditing for processes that start prior to auditd" 1 \
        bash -c 'grep -q "audit=1" /proc/cmdline 2>/dev/null && echo "audit=1 in cmdline" && return 0 || echo "audit=1 not in bootloader config" && return 1'

    run_check "4.4.2.1" "Ensure audit log storage size is configured" 1 \
        bash -c 'grep -q "max_log_file" /etc/audit/auditd.conf 2>/dev/null && echo "max_log_file set" && return 0 || echo "max_log_file not configured" && return 2'

    run_check "4.4.2.2" "Ensure audit log retention is configured" 2 \
        bash -c 'grep -q "num_logs" /etc/audit/auditd.conf 2>/dev/null && echo "num_logs set" && return 0 || echo "num_logs not configured" && return 2'

    run_check "4.4.3" "Ensure audit logs are not automatically deleted" 1 \
        bash -c 'grep -q "max_log_file_action" /etc/audit/auditd.conf 2>/dev/null && grep "max_log_file_action" /etc/audit/auditd.conf | grep -q "keep_logs" && echo "keep_logs" && return 0 || echo "max_log_file_action not keep_logs" && return 1'
}

# ── CIS 5.x: Access, Authentication, Authorization ───────────
section_5_access() {
    echo ""
    echo "━━━ 5.x Access, Authentication, Authorization ━━━"

    # 5.1 Cron
    run_check "5.1.1" "Ensure cron daemon is enabled" 1 \
        bash -c 'check_service_enabled cron enabled || check_service_enabled crond enabled'

    run_check "5.1.2" "Ensure permissions on /etc/crontab are configured" 1 \
        bash -c 'check_file_perm /etc/crontab 600'

    run_check "5.1.3" "Ensure permissions on /etc/cron.hourly are configured" 1 \
        bash -c 'check_file_perm /etc/cron.hourly 700'

    run_check "5.1.4" "Ensure permissions on /etc/cron.daily are configured" 1 \
        bash -c 'check_file_perm /etc/cron.daily 700'

    run_check "5.1.5" "Ensure permissions on /etc/cron.weekly are configured" 1 \
        bash -c 'check_file_perm /etc/cron.weekly 700'

    run_check "5.1.6" "Ensure permissions on /etc/cron.monthly are configured" 1 \
        bash -c 'check_file_perm /etc/cron.monthly 700'

    run_check "5.1.7" "Ensure permissions on /etc/cron.d are configured" 1 \
        bash -c 'check_file_perm /etc/cron.d 700'

    # 5.2 SSH
    run_check "5.2.1" "Ensure permissions on /etc/ssh/sshd_config are configured" 1 \
        bash -c 'check_file_perm /etc/ssh/sshd_config 600'

    run_check "5.2.2" "Ensure SSH access is limited" 1 \
        bash -c 'sshd -T 2>/dev/null | grep -q "^allowusers\|^allowgroups\|^denyusers\|^denygroups" && echo "access list configured" && return 0 || echo "no SSH access restriction" && return 2'

    run_check "5.2.3" "Ensure permissions on SSH host private keys are configured" 1 \
        bash -c 'for f in /etc/ssh/ssh_host_*_key; do [ -f "$f" ] && { local p=$(stat -c "%a" "$f" 2>/dev/null || stat -f "%Lp" "$f"); [ "$p" -le 600 ] || echo "$f: $p" && return 1; }; done; echo "all host keys <= 600" && return 0'

    run_check "5.2.4" "Ensure SSH LogLevel is appropriate" 1 \
        bash -c 'val=$(sshd -T 2>/dev/null | awk "/^loglevel /{print \$2}"); [ "$val" = "VERBOSE" ] || [ "$val" = "INFO" ] && echo "LogLevel=$val" && return 0 || echo "LogLevel=$val (期望 VERBOSE/INFO)" && return 1'

    run_check "5.2.5" "Ensure SSH X11 forwarding is disabled" 1 \
        bash -c 'val=$(sshd -T 2>/dev/null | awk "/^x11forwarding /{print \$2}"); [ "$val" = "no" ] && echo "X11Forwarding=no" && return 0 || echo "X11Forwarding=$val" && return 1'

    run_check "5.2.6" "Ensure SSH MaxAuthTries is set to 4 or less" 1 \
        bash -c 'val=$(sshd -T 2>/dev/null | awk "/^maxauthtries /{print \$2}"); [ "$val" -le 4 ] 2>/dev/null && echo "MaxAuthTries=$val" && return 0 || echo "MaxAuthTries=$val (期望 <=4)" && return 1'

    run_check "5.2.7" "Ensure SSH IgnoreRhosts is enabled" 1 \
        bash -c 'val=$(sshd -T 2>/dev/null | awk "/^ignorerhosts /{print \$2}"); [ "$val" = "yes" ] && echo "IgnoreRhosts=yes" && return 0 || echo "IgnoreRhosts=$val" && return 1'

    run_check "5.2.8" "Ensure SSH HostbasedAuthentication is disabled" 1 \
        bash -c 'val=$(sshd -T 2>/dev/null | awk "/^hostbasedauthentication /{print \$2}"); [ "$val" = "no" ] && echo "HostbasedAuthentication=no" && return 0 || echo "HostbasedAuthentication=$val" && return 1'

    run_check "5.2.9" "Ensure SSH PermitRootLogin is disabled" 1 \
        bash -c 'val=$(sshd -T 2>/dev/null | awk "/^permitrootlogin /{print \$2}"); [ "$val" = "no" ] && echo "PermitRootLogin=no" && return 0 || echo "PermitRootLogin=$val (期望 no)" && return 1'

    run_check "5.2.10" "Ensure SSH PermitEmptyPasswords is disabled" 1 \
        bash -c 'val=$(sshd -T 2>/dev/null | awk "/^permitemptypasswords /{print \$2}"); [ "$val" = "no" ] && echo "PermitEmptyPasswords=no" && return 0 || echo "PermitEmptyPasswords=$val" && return 1'

    run_check "5.2.11" "Ensure SSH PermitUserEnvironment is disabled" 1 \
        bash -c 'val=$(sshd -T 2>/dev/null | awk "/^permituserenvironment /{print \$2}"); [ "$val" = "no" ] && echo "PermitUserEnvironment=no" && return 0 || echo "PermitUserEnvironment=$val" && return 1'

    run_check "5.2.12" "Ensure only strong Ciphers are used" 1 \
        bash -c 'val=$(sshd -T 2>/dev/null | awk "/^ciphers /{print \$2}"); echo "$val" | grep -qi "cbc" && echo "weak cipher (cbc) present" && return 1 || echo "ciphers ok" && return 0'

    run_check "5.2.13" "Ensure only strong MAC algorithms are used" 1 \
        bash -c 'val=$(sshd -T 2>/dev/null | awk "/^macs /{print \$2}"); echo "$val" | grep -qiE "md5|sha1|96" && echo "weak MAC present" && return 1 || echo "MACs ok" && return 0'

    run_check "5.2.14" "Ensure only strong KEX algorithms are used" 2 \
        bash -c 'val=$(sshd -T 2>/dev/null | awk "/^kexalgorithms /{print \$2}"); echo "$val" | grep -qi "diffie-hellman-group1-sha1" && echo "weak KEX present" && return 1 || echo "KEX ok" && return 0'

    run_check "5.2.15" "Ensure SSH ClientAliveInterval and ClientAliveCountMax are configured" 1 \
        bash -c 'i=$(sshd -T 2>/dev/null | awk "/^clientaliveinterval /{print \$2}"); c=$(sshd -T 2>/dev/null | awk "/^clientalivecountmax /{print \$2}"); [ -n "$i" ] && [ "$i" -le 300 ] 2>/dev/null && [ "$c" -le 3 ] 2>/dev/null && echo "Interval=$i CountMax=$c" && return 0 || echo "Interval=$i CountMax=$c (期望 <=300, <=3)" && return 1'

    run_check "5.2.16" "Ensure SSH LoginGraceTime is set to one minute or less" 1 \
        bash -c 'val=$(sshd -T 2>/dev/null | awk "/^logingracetime /{print \$2}"); [ -n "$val" ] && [ "$val" -le 60 ] 2>/dev/null && echo "LoginGraceTime=$val" && return 0 || echo "LoginGraceTime=$val (期望 <=60)" && return 1'

    # 5.3 sudo
    run_check "5.3.1" "Ensure sudo is installed" 1 \
        bash -c 'check_pkg_installed sudo && echo "sudo installed" && return 0 || echo "sudo not installed" && return 1'

    run_check "5.3.2" "Ensure sudo log file exists" 1 \
        bash -c 'grep -q "logfile" /etc/sudoers /etc/sudoers.d/* 2>/dev/null && echo "sudo log file configured" && return 0 || echo "no sudo log file" && return 2'

    # 5.4 Password policies
    run_check "5.4.1.1" "Ensure password creation requirements are configured" 1 \
        bash -c '[ "$DISTRO_FAMILY" = "debian" ] && { grep -q "pam_pwquality\|pam_cracklib" /etc/pam.d/common-password 2>/dev/null && echo "pwquality configured" && return 0 || echo "no pwquality in PAM" && return 1; } || { grep -q "pam_pwquality" /etc/pam.d/system-auth 2>/dev/null && return 0 || echo "no pwquality" && return 1; }'

    run_check "5.4.1.2" "Ensure lockout for failed password attempts is configured" 1 \
        bash -c 'grep -q "pam_faillock\|pam_tally2" /etc/pam.d/common-auth /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null && echo "faillock configured" && return 0 || echo "no faillock" && return 1'

    run_check "5.4.1.3" "Ensure password reuse is restricted" 1 \
        bash -c 'grep -q "remember=" /etc/pam.d/common-password /etc/pam.d/system-auth 2>/dev/null && echo "password reuse restricted" && return 0 || echo "no password reuse restriction" && return 1'

    run_check "5.4.1.4" "Ensure password hashing algorithm is up to date" 1 \
        bash -c 'grep -q "yescrypt\|sha512" /etc/pam.d/common-password /etc/pam.d/system-auth 2>/dev/null && echo "strong hash configured" && return 0 || echo "hash algorithm not verified" && return 2'

    # 5.5 User accounts
    run_check "5.5.1" "Ensure no users have empty password fields" 1 \
        bash -c 'awk -F: "(\$2 == \"\") { print \$1 }" /etc/shadow 2>/dev/null | head -1 | grep -q "." && echo "user with empty password found" && return 1 || echo "no empty passwords" && return 0'

    run_check "5.5.2" "Ensure all groups in /etc/passwd exist in /etc/group" 1 \
        bash -c 'for gid in $(awk -F: "{print \$3}" /etc/group); do echo "$gid"; done | sort -n | uniq > /tmp/gids.$$; for gid in $(awk -F: "{print \$4}" /etc/passwd); do grep -qx "$gid" /tmp/gids.$$ || echo "missing GID: $gid"; done; rm /tmp/gids.$$; return 0'

    run_check "5.5.3" "Ensure no duplicate UIDs exist" 1 \
        bash -c 'dups=$(awk -F: "{print \$3}" /etc/passwd | sort | uniq -d); [ -z "$dups" ] && echo "no duplicate UIDs" && return 0 || echo "duplicate UIDs: $dups" && return 1'

    run_check "5.5.4" "Ensure no duplicate GIDs exist" 1 \
        bash -c 'dups=$(awk -F: "{print \$3}" /etc/group | sort | uniq -d); [ -z "$dups" ] && echo "no duplicate GIDs" && return 0 || echo "duplicate GIDs: $dups" && return 1'

    run_check "5.5.5" "Ensure no duplicate user names exist" 1 \
        bash -c 'dups=$(awk -F: "{print \$1}" /etc/passwd | sort | uniq -d); [ -z "$dups" ] && echo "no duplicate users" && return 0 || echo "duplicate users: $dups" && return 1'

    run_check "5.5.6" "Ensure no duplicate group names exist" 1 \
        bash -c 'dups=$(awk -F: "{print \$1}" /etc/group | sort | uniq -d); [ -z "$dups" ] && echo "no duplicate groups" && return 0 || echo "duplicate groups: $dups" && return 1'

    run_check "5.5.7" "Ensure root PATH Integrity" 1 \
        bash -c 'echo "$PATH" | grep -q "::" && echo "double colon in PATH" && return 1 || echo "$PATH" | grep -q ":$" && echo "trailing colon in PATH" && return 1 || for d in $(echo "$PATH" | tr ":" "\n"); do [ -d "$d" ] || echo "non-existent dir: $d" && return 1; done; echo "PATH ok" && return 0'

    run_check "5.5.8" "Ensure root is the only UID 0 account" 1 \
        bash -c 'n=$(awk -F: "(\$3 == 0) { print \$1 }" /etc/passwd | wc -l); [ "$n" -eq 1 ] && echo "only root has UID 0" && return 0 || echo "$n accounts with UID 0" && return 1'

    # 5.6 Root login restriction
    run_check "5.6" "Ensure root login via console is restricted (system default)" 2 \
        bash -c 'grep -q "^root:" /etc/securetty 2>/dev/null && wc -l /etc/securetty | awk "{print \$1}" | grep -q "^0$" && echo "no securetty entries" && return 0 || [ ! -f /etc/securetty ] && echo "no securetty file" && return 0 || echo "securetty has entries" && return 2'

    # 5.7 su access restriction
    run_check "5.7" "Ensure access to the su command is restricted" 1 \
        bash -c 'grep -q "required.*pam_wheel.so" /etc/pam.d/su 2>/dev/null && echo "pam_wheel configured" && return 0 || echo "no pam_wheel restriction on su" && return 2'
}

# ── CIS 6.x: System Maintenance ──────────────────────────────
section_6_maintenance() {
    echo ""
    echo "━━━ 6.x System Maintenance ━━━"

    # 6.1 File permissions
    run_check "6.1.1" "Ensure permissions on /etc/passwd are configured" 1 \
        bash -c 'check_file_perm /etc/passwd 644'

    run_check "6.1.2" "Ensure permissions on /etc/shadow are configured" 1 \
        bash -c 'check_file_perm /etc/shadow 640'

    run_check "6.1.3" "Ensure permissions on /etc/group are configured" 1 \
        bash -c 'check_file_perm /etc/group 644'

    run_check "6.1.4" "Ensure permissions on /etc/gshadow are configured" 1 \
        bash -c 'check_file_perm /etc/gshadow 640'

    run_check "6.1.5" "Ensure permissions on /etc/passwd- are configured" 1 \
        bash -c 'check_file_perm /etc/passwd- 644'

    run_check "6.1.6" "Ensure permissions on /etc/shadow- are configured" 1 \
        bash -c 'check_file_perm /etc/shadow- 640'

    run_check "6.1.7" "Ensure permissions on /etc/group- are configured" 1 \
        bash -c 'check_file_perm /etc/group- 644'

    run_check "6.1.8" "Ensure permissions on /etc/gshadow- are configured" 1 \
        bash -c 'check_file_perm /etc/gshadow- 640'

    run_check "6.1.9" "Ensure no world writable files exist" 1 \
        bash -c 'n=$(df --local -P 2>/dev/null | awk "{if (NR!=1) print \$6}" | xargs -I '{}' find '{}' -xdev -type f -perm -0002 2>/dev/null | wc -l); [ "$n" -eq 0 ] && echo "no world writable files" && return 0 || echo "$n world writable files" && return 1'

    run_check "6.1.10" "Ensure no unowned files or directories exist" 1 \
        bash -c 'n=$(df --local -P 2>/dev/null | awk "{if (NR!=1) print \$6}" | xargs -I '{}' find '{}' -xdev -nouser 2>/dev/null | wc -l); [ "$n" -eq 0 ] && echo "no unowned files" && return 0 || echo "$n unowned files" && return 1'

    run_check "6.1.11" "Ensure no ungrouped files or directories exist" 1 \
        bash -c 'n=$(df --local -P 2>/dev/null | awk "{if (NR!=1) print \$6}" | xargs -I '{}' find '{}' -xdev -nogroup 2>/dev/null | wc -l); [ "$n" -eq 0 ] && echo "no ungrouped files" && return 0 || echo "$n ungrouped files" && return 1'

    run_check "6.1.12" "Ensure no SUID files exist that are not expected" 2 \
        bash -c 'n=$(df --local -P 2>/dev/null | awk "{if (NR!=1) print \$6}" | xargs -I '{}' find '{}' -xdev -type f -perm -4000 2>/dev/null | wc -l); echo "$n SUID files found" && return 2'

    run_check "6.1.13" "Ensure no SGID files exist that are not expected" 2 \
        bash -c 'n=$(df --local -P 2>/dev/null | awk "{if (NR!=1) print \$6}" | xargs -I '{}' find '{}' -xdev -type f -perm -2000 2>/dev/null | wc -l); echo "$n SGID files found" && return 2'

    # 6.2 User and group settings
    run_check "6.2.1" "Ensure accounts in /etc/passwd use shadowed passwords" 1 \
        bash -c 'n=$(awk -F: "(\$2 != \"x\") { print \$1 }" /etc/passwd | wc -l); [ "$n" -eq 0 ] && echo "all accounts use shadow" && return 0 || echo "$n accounts not using shadow" && return 1'

    run_check "6.2.2" "Ensure /etc/shadow password fields are not empty" 1 \
        bash -c 'n=$(awk -F: "(\$2 == \"\") { print \$1 }" /etc/shadow | wc -l); [ "$n" -eq 0 ] && echo "no empty shadow passwords" && return 0 || echo "$n empty passwords" && return 1'

    run_check "6.2.3" "Ensure all groups in /etc/passwd exist in /etc/group" 1 \
        bash -c 'echo "covered by 5.5.2" && return 3'

    run_check "6.2.4" "Ensure user home directories exist" 1 \
        bash -c 'n=0; for user in $(awk -F: "(\$3 >= 1000 && \$3 != 65534) { print \$1, \$6 }" /etc/passwd); do home=$(awk -F: -v u="$user" "(\$1==u) {print \$6}" /etc/passwd); [ -d "$home" ] || n=$((n+1)); done; [ "$n" -eq 0 ] && echo "all home dirs exist" && return 0 || echo "$n missing home dirs" && return 1'

    run_check "6.2.5" "Ensure users' home directories permissions are 750 or more restrictive" 1 \
        bash -c 'bad=0; for home in $(awk -F: "(\$3 >= 1000 && \$3 != 65534) { print \$6 }" /etc/passwd); do [ -d "$home" ] && { p=$(stat -c "%a" "$home" 2>/dev/null || stat -f "%Lp" "$home"); [ "$p" -gt 750 ] 2>/dev/null && bad=$((bad+1)); }; done; [ "$bad" -eq 0 ] && echo "all home dirs ok" && return 0 || echo "$bad home dirs too permissive" && return 1'

    run_check "6.2.6" "Ensure users' dot files are not group or world writable" 1 \
        bash -c 'bad=0; for home in $(awk -F: "(\$3 >= 1000 && \$3 != 65534) { print \$6 }" /etc/passwd); do [ -d "$home" ] && find "$home" -maxdepth 1 -name ".*" -type f -perm /022 2>/dev/null | grep -q . && bad=$((bad+1)); done; [ "$bad" -eq 0 ] && echo "no writable dot files" && return 0 || echo "$bad users with writable dot files" && return 1'

    run_check "6.2.7" "Ensure no users have .forward files" 1 \
        bash -c 'n=$(awk -F: "(\$3 >= 1000 && \$3 != 65534) { print \$6 }" /etc/passwd | xargs -I '{}' find '{}' -maxdepth 1 -name ".forward" 2>/dev/null | wc -l); [ "$n" -eq 0 ] && echo "no .forward files" && return 0 || echo "$n .forward files" && return 1'

    run_check "6.2.8" "Ensure no users have .netrc files" 1 \
        bash -c 'n=$(awk -F: "(\$3 >= 1000 && \$3 != 65534) { print \$6 }" /etc/passwd | xargs -I '{}' find '{}' -maxdepth 1 -name ".netrc" 2>/dev/null | wc -l); [ "$n" -eq 0 ] && echo "no .netrc files" && return 0 || echo "$n .netrc files" && return 1'

    run_check "6.2.9" "Ensure no users have .rhosts files" 1 \
        bash -c 'n=$(awk -F: "(\$3 >= 1000 && \$3 != 65534) { print \$6 }" /etc/passwd | xargs -I '{}' find '{}' -maxdepth 1 -name ".rhosts" 2>/dev/null | wc -l); [ "$n" -eq 0 ] && echo "no .rhosts files" && return 0 || echo "$n .rhosts files" && return 1'

    run_check "6.2.10" "Ensure no users have .bashrc or .bash_profile that reference .rhosts" 1 \
        bash -c 'n=$(awk -F: "(\$3 >= 1000 && \$3 != 65534) { print \$6 }" /etc/passwd | xargs -I '{}' find '{}' -maxdepth 1 -name ".bash*" -exec grep -l "rhosts" {} \; 2>/dev/null | wc -l); [ "$n" -eq 0 ] && echo "no .bashrc .rhosts refs" && return 0 || echo "$n .bashrc with .rhosts refs" && return 1'
}

# ── 摘要输出 ─────────────────────────────────────────────────
print_summary() {
    local total=$TOTAL_CHECKS
    local pass_pct=0
    [ "$total" -gt 0 ] && pass_pct=$((COUNT_PASS * 100 / total))

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  CIS Benchmark Audit Summary"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    printf "  Total checks:  %d\n" "$total"
    printf "  ${C_OK}PASS${C_RST}:           %d\n" "$COUNT_PASS"
    printf "  ${C_FAIL}FAIL${C_RST}:           %d\n" "$COUNT_FAIL"
    printf "  ${C_WARN}WARN${C_RST}:           %d\n" "$COUNT_WARN"
    printf "  ${C_INFO}SKIP${C_RST}:           %d\n" "$COUNT_SKIP"
    printf "  Compliance:     %d%%\n" "$pass_pct"
    echo ""
    echo "  Reports:"
    echo "    TXT:  $REPORT_TXT"
    echo "    JSON: $REPORT_JSON"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# ── JSON 报告写入 ────────────────────────────────────────────
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
    "cis_level": $CIS_LEVEL
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
        echo -e "${C_INFO}║  CIS Benchmark Compliance Audit           ║${C_RST}"
        echo -e "${C_INFO}║  $APP_NAME $APP_VER                       ║${C_RST}"
        echo -e "${C_INFO}╚══════════════════════════════════════════╝${C_RST}"
        echo -e "${C_INFO}Host: ${PRETTY_NAME:-unknown}${C_RST}"
        echo -e "${C_INFO}Level: $CIS_LEVEL${C_RST}"
        echo -e "${C_INFO}Mode: READ-ONLY (no system changes)${C_RST}"
        echo ""
    fi

    section_1_initial_setup
    section_2_services
    section_3_network
    section_4_logging
    section_5_access
    section_6_maintenance

    write_json_report
    print_summary

    if [ "$JSON_ONLY" -eq 1 ]; then
        echo "$REPORT_JSON"
    fi

    return 0
}

main "$@"
