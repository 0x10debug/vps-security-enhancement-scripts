#!/bin/bash
# ════════════════════════════════════════════════════════════
#  incident_triage.sh — Incident Response & Forensic Triage Collector
#  Supported OS: Linux host
#  Run as: root
#  Mode: Read-only forensic collection (does not modify system, does not kill processes, does not delete files)
#  Reference: NIST SP 800-61 (Incident Response)
#         SANS Forensic Triage
#         order-of-volatility (RFC 3227)
#  Project home: https://github.com/0x10debug/vps-security-enhancement-scripts
# ════════════════════════════════════════════════════════════
#
# Usage:
#   sudo ./scripts/incident_triage.sh                    # Interactive wizard
#   sudo ./scripts/incident_triage.sh collect            # Full forensic collection (complete)
#   sudo ./scripts/incident_triage.sh quick              # Quick overview (~30s)
#   sudo ./scripts/incident_triage.sh analyze <archive>  # Analyze collected data
#   sudo ./scripts/incident_triage.sh report <archive>   # Generate summary report
#   sudo ./scripts/incident_triage.sh audit              # Read-only audit (15+ checks)
#   sudo ./scripts/incident_triage.sh --output ./triage-out
#
# Exit codes:
#   0 — Success
#   1 — Parameter error / missing dependency
#   2 — Some features unavailable

set -euo pipefail

APP_NAME="incident_triage"
APP_VER="v1.0.0"
MODE=""
OUTPUT_DIR="${OUTPUT_DIR:-./triage-out}"
ARCHIVE_PATH=""
REPORT_DIR="/var/log/incident-triage"
TIMESTAMP=$(date +%Y%m%d%H%M%S)
COLLECTOR="${USER:-unknown}@$(hostname 2>/dev/null || echo 'unknown')"

COUNT_PASS=0
COUNT_FAIL=0
COUNT_WARN=0
COUNT_SKIP=0
TOTAL_CHECKS=0

C_FAIL='\033[0;31m'
C_OK='\033[0;32m'
C_WARN='\033[0;33m'
C_INFO='\033[0;34m'
C_RST='\033[0m'

# ── Parameter parsing ─────────────────────────────────────────────────
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            collect) MODE="collect"; shift ;;
            quick) MODE="quick"; shift ;;
            analyze) MODE="analyze"; shift; [ $# -gt 0 ] && ARCHIVE_PATH="$1" && shift ;;
            report) MODE="report"; shift; [ $# -gt 0 ] && ARCHIVE_PATH="$1" && shift ;;
            audit) MODE="audit"; shift ;;
            --output) OUTPUT_DIR="$2"; shift 2 ;;
            -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
            *) echo "Unknown parameter: $1"; exit 1 ;;
        esac
    done
    if [ -z "$MODE" ]; then
        MODE="interactive"
    fi
}

# ── Report initialization ───────────────────────────────────────────────
init_report() {
    mkdir -p "$REPORT_DIR" 2>/dev/null || REPORT_DIR="/tmp/incident-triage"
    mkdir -p "$REPORT_DIR" 2>/dev/null || true
    REPORT_FILE="$REPORT_DIR/incident-triage-${TIMESTAMP}.txt"
    {
        echo "Incident Triage Audit Report"
        echo "============================="
        echo "Date: $(date)"
        echo "Host: $(hostname 2>/dev/null || echo 'N/A')"
        echo "Collector: $COLLECTOR"
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
}

# ── Utility functions ─────────────────────────────────────────────────
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${C_FAIL}Please run as root (forensic collection requires reading system logs/process memory maps)${C_RST}"
        exit 1
    fi
}

check_cmd() {
    command -v "$1" >/dev/null 2>&1
}

print_summary() {
    echo ""
    echo -e "${C_OK}══════════════════════════════${C_RST}"
    echo -e "${C_OK}  Audit summary${C_RST}"
    echo -e "${C_OK}══════════════════════════════${C_RST}"
    printf "  ${C_OK}PASS${C_RST}: %d  ${C_FAIL}FAIL${C_RST}: %d  ${C_WARN}WARN${C_RST}: %d  ${C_INFO}SKIP${C_RST}: %d  Total: %d\n" \
        "$COUNT_PASS" "$COUNT_FAIL" "$COUNT_WARN" "$COUNT_SKIP" "$TOTAL_CHECKS"
    echo -e "  Report: ${C_INFO}${REPORT_FILE}${C_RST}"
}

wait_key() {
    echo ""
    read -r -p "Press Enter to continue..." _
}

# ── Collection work directory ─────────────────────────────────────────────
setup_workdir() {
    local base="$1"
    local workdir="${base}/incident-${TIMESTAMP}"
    mkdir -p "$workdir"
    echo "$workdir"
}

# Capture single file: save_cmd <outfile> <command...>
# Capture command output to file, write error placeholder on failure
save_cmd() {
    local outfile="$1"
    shift
    {
        echo "# Command: $*"
        echo "# Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "# Host: $(hostname 2>/dev/null || echo 'N/A')"
        echo "---"
        "$@" 2>&1 || echo "[ERROR] command failed with exit $?"
    } > "$outfile"
}

# Capture file content: save_file <outfile> <source>
save_file() {
    local outfile="$1"
    local src="$2"
    {
        echo "# Source: $src"
        echo "# Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "---"
        if [ -f "$src" ]; then
            cat "$src" 2>&1 || echo "[ERROR] read failed"
        else
            echo "[SKIP] file not found"
        fi
    } > "$outfile"
}

# Capture file tail: save_tail <outfile> <source> <lines>
save_tail() {
    local outfile="$1"
    local src="$2"
    local lines="${3:-200}"
    {
        echo "# Source: $src (last $lines lines)"
        echo "# Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "---"
        if [ -f "$src" ]; then
            tail -n "$lines" "$src" 2>&1 || echo "[ERROR] read failed"
        else
            echo "[SKIP] file not found"
        fi
    } > "$outfile"
}

# List numeric PIDs in /proc (avoid ls | grep, shellcheck compatible)
proc_numeric_pids() {
    local p
    for p in /proc/[0-9]*; do
        [ -d "$p" ] || continue
        basename "$p"
    done
}

# ── System info collection ─────────────────────────────────────────────
collect_system_info() {
    local d="$1"
    echo -e "${C_INFO}── System info ──${C_RST}"
    save_cmd "$d/01-hostname.txt" hostname
    save_cmd "$d/01-hostnamectl.txt" hostnamectl
    save_cmd "$d/01-uptime.txt" uptime
    save_cmd "$d/01-uname.txt" uname -a
    save_cmd "$d/01-os-release.txt" cat /etc/os-release
    save_cmd "$d/01-who.txt" who
    save_cmd "$d/01-w.txt" w
    save_cmd "$d/01-last.txt" last -50
    save_cmd "$d/01-lastb.txt" lastb -50
    save_cmd "$d/01-date.txt" date
    save_cmd "$d/01-timedatectl.txt" timedatectl
    save_cmd "$d/01-dmesg-tail.txt" dmesg 2>/dev/null || true
}

# ── Process analysis ─────────────────────────────────────────────────
collect_processes() {
    local d="$1"
    echo -e "${C_INFO}── Process analysis ──${C_RST}"
    save_cmd "$d/02-ps-aux.txt" ps auxww
    save_cmd "$d/02-ps-ef.txt" ps -ef
    save_cmd "$d/02-ps-tree.txt" ps -eo pid,ppid,user,cmd --forest
    save_cmd "$d/02-top.txt" top -b -n 1
    # Suspicious processes: top 20 by CPU/memory
    save_cmd "$d/02-ps-cpu-top.txt" ps aux --sort=-%cpu | head -20
    save_cmd "$d/02-ps-mem-top.txt" ps aux --sort=-%mem | head -20
    # Hidden process detection: exists in /proc but not shown by ps
    {
        echo "# Hidden process detection (proc vs ps)"
        echo "# Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "---"
        local ps_pids proc_pids hidden
        ps_pids=$(ps -e -o pid= | tr -d ' ' | sort -n | uniq)
        proc_pids=$(proc_numeric_pids | sort -n | uniq)
        hidden=$(comm -23 <(echo "$proc_pids") <(echo "$ps_pids"))
        if [ -n "$hidden" ]; then
            echo "[WARN] PIDs in /proc but not in ps (possible rootkit/hide):"
            echo "$hidden"
        else
            echo "[OK] no hidden PIDs detected"
        fi
    } > "$d/02-hidden-pids.txt"
    # Process memory maps (do not export full memory, too large)
    {
        echo "# Process memory maps (top 10 by CPU)"
        echo "# Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "---"
        local pids
        pids=$(ps -eo pid= --sort=-%cpu | head -10 | tr -d ' ')
        for pid in $pids; do
            echo "=== PID $pid ==="
            cat "/proc/$pid/maps" 2>/dev/null || echo "[SKIP] cannot read maps for $pid"
            echo ""
        done
    } > "$d/02-memory-maps.txt"
    # Process executable paths and deleted executables
    {
        echo "# Process exe paths (deleted exe = suspicious)"
        echo "# Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "---"
        for pid in $(proc_numeric_pids); do
            local exe
            exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || continue
            case "$exe" in
                *deleted*) echo "[SUSPECT] PID $pid exe=$exe" ;;
                *) echo "PID $pid exe=$exe" ;;
            esac
        done
    } > "$d/02-exe-paths.txt"
}

# ── Network analysis ─────────────────────────────────────────────────
collect_network() {
    local d="$1"
    echo -e "${C_INFO}── Network analysis ──${C_RST}"
    if check_cmd ss; then
        save_cmd "$d/03-ss-all.txt" ss -tulnpa
        save_cmd "$d/03-ss-listen.txt" ss -tlnp
    else
        save_cmd "$d/03-netstat-all.txt" netstat -tulnpa 2>/dev/null || true
        save_cmd "$d/03-netstat-listen.txt" netstat -tlnp 2>/dev/null || true
    fi
    save_cmd "$d/03-route.txt" ip route 2>/dev/null || route -n 2>/dev/null || true
    save_cmd "$d/03-arp.txt" ip neigh 2>/dev/null || arp -a 2>/dev/null || true
    save_cmd "$d/03-dns-resolv.txt" cat /etc/resolv.conf
    save_cmd "$d/03-dns-hosts.txt" cat /etc/hosts
    save_cmd "$d/03-iptables.txt" iptables -L -n -v 2>/dev/null || true
    save_cmd "$d/03-nft.txt" nft list ruleset 2>/dev/null || true
    save_cmd "$d/03-ufw.txt" ufw status verbose 2>/dev/null || true
    save_cmd "$d/03-firewalld.txt" firewall-cmd --list-all 2>/dev/null || true
    save_cmd "$d/03-conntrack.txt" conntrack -L 2>/dev/null || true
    # Established outbound connections (non-local/non-listening)
    {
        echo "# Established outbound connections"
        echo "# Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "---"
        if check_cmd ss; then
            ss -tunpa state established 2>/dev/null || ss -tunpa 2>/dev/null || true
        else
            netstat -tunpa 2>/dev/null | grep ESTABLISHED || true
        fi
    } > "$d/03-established.txt"
}

# ── Persistence mechanisms ───────────────────────────────────────────────
collect_persistence() {
    local d="$1"
    echo -e "${C_INFO}── Persistence mechanisms ──${C_RST}"
    # cron
    save_cmd "$d/04-crontab-root.txt" crontab -l 2>/dev/null || echo "[SKIP] no root crontab"
    save_cmd "$d/04-crontab-etc.txt" cat /etc/crontab
    {
        echo "# /etc/cron.d/ listing + contents"
        echo "# Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "---"
        ls -la /etc/cron.d/ 2>/dev/null || echo "[SKIP] no /etc/cron.d"
        for f in /etc/cron.d/*; do
            [ -f "$f" ] || continue
            echo "=== $f ==="
            cat "$f" 2>/dev/null || true
        done
    } > "$d/04-cron-d.txt"
    {
        echo "# All user crontabs"
        echo "# Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "---"
        cut -d: -f1 /etc/passwd 2>/dev/null | while IFS= read -r user; do
            [ -n "$user" ] || continue
            local cron
            cron=$(crontab -u "$user" -l 2>/dev/null) || continue
            [ -n "$cron" ] && echo "=== $user ===" && echo "$cron"
        done
    } > "$d/04-crontab-all-users.txt"
    # systemd
    save_cmd "$d/04-systemd-services.txt" systemctl list-units --type=service --all
    save_cmd "$d/04-systemd-timers.txt" systemctl list-timers --all
    save_cmd "$d/04-systemd-enabled.txt" systemctl list-unit-files --state=enabled
    # Startup scripts
    save_cmd "$d/04-rc-local.txt" cat /etc/rc.local 2>/dev/null || echo "[SKIP] no rc.local"
    {
        echo "# /etc/init.d/ listing"
        echo "---"
        ls -la /etc/init.d/ 2>/dev/null || echo "[SKIP]"
    } > "$d/04-init-d.txt"
    {
        echo "# /etc/profile.d/ listing + contents"
        echo "---"
        ls -la /etc/profile.d/ 2>/dev/null || echo "[SKIP]"
        for f in /etc/profile.d/*.sh; do
            [ -f "$f" ] || continue
            echo "=== $f ==="
            cat "$f" 2>/dev/null || true
        done
    } > "$d/04-profile-d.txt"
    # SSH authorized_keys
    {
        echo "# SSH authorized_keys for all users"
        echo "# Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "---"
        for home in /root /home/*; do
            local ak="$home/.ssh/authorized_keys"
            if [ -f "$ak" ]; then
                echo "=== $ak ==="
                cat "$ak" 2>/dev/null || true
            fi
        done
    } > "$d/04-authorized-keys.txt"
    # bashrc / profile modifications
    save_file "$d/04-root-bashrc.txt" /root/.bashrc
    save_file "$d/04-root-profile.txt" /root/.profile
    {
        echo "# User shell rc files"
        echo "---"
        for home in /home/*; do
            for rc in "$home/.bashrc" "$home/.profile" "$home/.bash_profile"; do
                [ -f "$rc" ] || continue
                echo "=== $rc ==="
                cat "$rc" 2>/dev/null || true
            done
        done
    } > "$d/04-user-shell-rc.txt"
    # LD_PRELOAD / /etc/ld.so.preload (rootkit indicator)
    save_file "$d/04-ld-so-preload.txt" /etc/ld.so.preload
}

# ── Log analysis ─────────────────────────────────────────────────
collect_logs() {
    local d="$1"
    echo -e "${C_INFO}── Log analysis ──${C_RST}"
    local lines=500
    # auth log
    save_tail "$d/05-auth-log.txt" /var/log/auth.log "$lines"
    save_tail "$d/05-secure.txt" /var/log/secure "$lines"
    save_tail "$d/05-syslog.txt" /var/log/syslog "$lines"
    save_tail "$d/05-messages.txt" /var/log/messages "$lines"
    save_tail "$d/05-kern-log.txt" /var/log/kern.log "$lines"
    save_tail "$d/05-dmesg.txt" /var/log/dmesg "$lines"
    # audit
    save_cmd "$d/05-auditd.txt" ausearch -m all --start today 2>/dev/null || true
    save_cmd "$d/05-aureport.txt" aureport --summary 2>/dev/null || true
    # journalctl
    save_cmd "$d/05-journal-tail.txt" journalctl -n "$lines" --no-pager 2>/dev/null || true
    save_cmd "$d/05-journal-boot.txt" journalctl -b --no-pager 2>/dev/null | tail -n "$lines" || true
    # web server logs
    save_tail "$d/05-nginx-access.txt" /var/log/nginx/access.log "$lines"
    save_tail "$d/05-nginx-error.txt" /var/log/nginx/error.log "$lines"
    save_tail "$d/05-apache-access.txt" /var/log/apache2/access.log "$lines"
    save_tail "$d/05-apache-error.txt" /var/log/apache2/error.log "$lines"
    save_tail "$d/05-httpd-access.txt" /var/log/httpd/access_log "$lines"
    save_tail "$d/05-httpd-error.txt" /var/log/httpd/error_log "$lines"
    # Suspicious entries: failed sudo / failed ssh / root login
    {
        echo "# Suspicious log entries (failed sudo/ssh, root login)"
        echo "# Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "---"
        for lg in /var/log/auth.log /var/log/secure; do
            [ -f "$lg" ] || continue
            echo "=== $lg: failed/sudo/root ==="
            grep -iE 'failed|invalid user|authentication failure|sudo|root|accepted' "$lg" 2>/dev/null | tail -n "$lines" || true
        done
    } > "$d/05-suspicious.txt"
}

# ── Filesystem ─────────────────────────────────────────────────
collect_filesystem() {
    local d="$1"
    echo -e "${C_INFO}── Filesystem ──${C_RST}"
    # Recently modified files (last 24h, excluding /proc /sys /dev /run)
    {
        echo "# Files modified in last 24h (excluding pseudo-fs)"
        echo "# Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "---"
        find / -xdev -type f -mtime -1 2>/dev/null | head -200 || true
    } > "$d/06-recent-modified.txt"
    # SUID/SGID
    {
        echo "# SUID/SGID files"
        echo "---"
        find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | head -200 || true
    } > "$d/06-suid-sgid.txt"
    # world-writable (excluding /tmp /var/tmp)
    {
        echo "# World-writable files (excluding /tmp /var/tmp)"
        echo "---"
        find / -xdev -type f -perm -0002 ! -path "/tmp/*" ! -path "/var/tmp/*" 2>/dev/null | head -200 || true
    } > "$d/06-world-writable.txt"
    # Suspicious files in /tmp
    {
        echo "# /tmp and /var/tmp contents"
        echo "---"
        ls -la /tmp/ 2>/dev/null || true
        echo "--- /dev/shm ---"
        ls -la /dev/shm/ 2>/dev/null || true
        echo "--- /var/tmp ---"
        ls -la /var/tmp/ 2>/dev/null || true
    } > "$d/06-tmp-contents.txt"
    # Suspicious hidden files
    {
        echo "# Hidden files in common dirs"
        echo "---"
        find /root /home /tmp /var/tmp /dev/shm -name ".*" -type f 2>/dev/null | head -100 || true
    } > "$d/06-hidden-files.txt"
    # Mount points
    save_cmd "$d/06-mount.txt" mount
    save_cmd "$d/06-df.txt" df -h
    save_cmd "$d/06-fstab.txt" cat /etc/fstab
}

# ── User accounts ─────────────────────────────────────────────────
collect_users() {
    local d="$1"
    echo -e "${C_INFO}── User accounts ──${C_RST}"
    save_cmd "$d/07-passwd.txt" cat /etc/passwd
    save_cmd "$d/07-shadow.txt" cat /etc/shadow
    save_cmd "$d/07-group.txt" cat /etc/group
    {
        echo "# UID 0 accounts (should be only root)"
        echo "---"
        awk -F: '$3 == 0 {print}' /etc/passwd 2>/dev/null || true
    } > "$d/07-uid0.txt"
    {
        echo "# Users with login shell"
        echo "---"
        grep -vE '/(nologin|false|sync)$' /etc/passwd 2>/dev/null || true
    } > "$d/07-login-shells.txt"
    save_file "$d/07-sudoers.txt" /etc/sudoers
    {
        echo "# /etc/sudoers.d/ listing + contents"
        echo "---"
        ls -la /etc/sudoers.d/ 2>/dev/null || echo "[SKIP]"
        for f in /etc/sudoers.d/*; do
            [ -f "$f" ] || continue
            echo "=== $f ==="
            cat "$f" 2>/dev/null || true
        done
    } > "$d/07-sudoers-d.txt"
    save_cmd "$d/07-last-logins.txt" last -50
    save_cmd "$d/07-lastb.txt" lastb -50
}

# ── Evidence chain / manifest ────────────────────────────────────────────
build_manifest() {
    local workdir="$1"
    local manifest="$workdir/manifest.json"
    local file_list
    file_list=$(find "$workdir" -type f ! -name "manifest.json" ! -name "sha256sums.txt" 2>/dev/null | sort)
    {
        echo "{"
        echo "  \"schema\": \"incident-triage/1.0\","
        echo "  \"collected_at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
        echo "  \"host\": \"$(hostname 2>/dev/null || echo 'N/A')\","
        echo "  \"collector\": \"$COLLECTOR\","
        echo "  \"script\": \"$APP_NAME\","
        echo "  \"version\": \"$APP_VER\","
        echo "  \"timestamp\": \"$TIMESTAMP\","
        echo "  \"artifacts\": ["
        local first=1
        for f in $file_list; do
            local rel hash size
            rel=${f#"$workdir/"}
            hash=$(sha256sum "$f" 2>/dev/null | awk '{print $1}')
            size=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null || echo 0)
            [ "$first" -eq 1 ] || echo ","
            printf '    {"file": "%s", "sha256": "%s", "bytes": %s}' "$rel" "$hash" "$size"
            first=0
        done
        echo ""
        echo "  ]"
        echo "}"
    } > "$manifest"
    # Standalone sha256 manifest
    {
        echo "# SHA-256 checksums for all artifacts"
        echo "# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "# Host: $(hostname 2>/dev/null || echo 'N/A')"
        echo ""
        for f in $file_list; do
            sha256sum "$f" 2>/dev/null || true
        done
        sha256sum "$manifest" 2>/dev/null || true
    } > "$workdir/sha256sums.txt"
    echo "$manifest"
}

# ── Package archive ─────────────────────────────────────────────────
build_archive() {
    local workdir="$1"
    local base="$2"
    local archive="${base}/incident-triage-${TIMESTAMP}.tar.gz"
    tar -czf "$archive" -C "$base" "$(basename "$workdir")" 2>/dev/null
    local arc_hash
    arc_hash=$(sha256sum "$archive" 2>/dev/null | awk '{print $1}')
    echo -e "${C_OK}Archive: ${C_INFO}$archive${C_RST}"
    echo -e "${C_OK}SHA-256: ${C_INFO}$arc_hash${C_RST}"
    echo "$archive"
}

# ── Full collection ─────────────────────────────────────────────────
do_collect() {
    echo -e "${C_WARN}>>> Full forensic collection (read-only, no system modification) <<<${C_RST}"
    echo -e "${C_INFO}Output directory: $OUTPUT_DIR${C_RST}"
    echo ""
    mkdir -p "$OUTPUT_DIR"
    local workdir
    workdir=$(setup_workdir "$OUTPUT_DIR")
    echo -e "${C_INFO}Working directory: $workdir${C_RST}"
    echo ""

    collect_system_info "$workdir"
    collect_processes "$workdir"
    collect_network "$workdir"
    collect_persistence "$workdir"
    collect_logs "$workdir"
    collect_filesystem "$workdir"
    collect_users "$workdir"

    echo ""
    echo -e "${C_INFO}── Build evidence chain ──${C_RST}"
    local manifest
    manifest=$(build_manifest "$workdir")
    echo -e "${C_OK}Manifest: $manifest${C_RST}"

    echo ""
    echo -e "${C_INFO}── Package archive ──${C_RST}"
    local archive
    archive=$(build_archive "$workdir" "$OUTPUT_DIR")

    echo ""
    echo -e "${C_OK}══════════════════════════════${C_RST}"
    echo -e "${C_OK}  Collection complete${C_RST}"
    echo -e "${C_OK}══════════════════════════════${C_RST}"
    echo -e "  Archive: ${C_INFO}$archive${C_RST}"
    echo -e "  Manifest: ${C_INFO}$manifest${C_RST}"
    echo -e "  Verify: ${C_INFO}$OUTPUT_DIR/sha256sums.txt${C_RST}"
    echo -e "${C_WARN}Copy archive to offline/trusted storage before analysis.${C_RST}"
}

# ── Quick overview ─────────────────────────────────────────────────
do_quick() {
    echo -e "${C_WARN}>>> Quick overview (~30s, read-only) <<<${C_RST}"
    echo ""
    echo -e "${C_INFO}── System ──${C_RST}"
    echo "Host: $(hostname 2>/dev/null || echo 'N/A')"
    echo "Uptime: $(uptime 2>/dev/null || echo 'N/A')"
    echo "Kernel: $(uname -r 2>/dev/null)"
    echo "Date: $(date)"
    echo ""
    echo -e "${C_INFO}── Current logins ──${C_RST}"
    who 2>/dev/null || true
    echo ""
    echo -e "${C_INFO}── Top 10 processes (CPU) ──${C_RST}"
    ps aux --sort=-%cpu 2>/dev/null | head -11 || true
    echo ""
    echo -e "${C_INFO}── Listening ports ──${C_RST}"
    if check_cmd ss; then
        ss -tlnp 2>/dev/null || true
    else
        netstat -tlnp 2>/dev/null || true
    fi
    echo ""
    echo -e "${C_INFO}── Established connections ──${C_RST}"
    if check_cmd ss; then
        ss -tunpa state established 2>/dev/null || ss -tunpa 2>/dev/null || true
    else
        netstat -tunpa 2>/dev/null | grep ESTABLISHED || true
    fi
    echo ""
    echo -e "${C_INFO}── UID 0 accounts ──${C_RST}"
    awk -F: '$3 == 0 {print}' /etc/passwd 2>/dev/null || true
    echo ""
    echo -e "${C_INFO}── root crontab ──${C_RST}"
    crontab -l 2>/dev/null || echo "[No root crontab]"
    echo ""
    echo -e "${C_INFO}── Recent logins ──${C_RST}"
    last -10 2>/dev/null || true
    echo ""
    echo -e "${C_INFO}── Recently modified files (last 24h, top 30) ──${C_RST}"
    find / -xdev -type f -mtime -1 2>/dev/null | head -30 || true
    echo ""
    echo -e "${C_WARN}Quick overview complete. For full collection use: $0 collect${C_RST}"
}

# ── Read-only audit (15+ checks) ────────────────────────────────────
chk_uid0() {
    local n
    n=$(awk -F: '$3 == 0 {print $1}' /etc/passwd 2>/dev/null | wc -l | tr -d ' ')
    if [ "$n" -eq 1 ]; then
        echo "only root has UID 0"
        return 0
    else
        awk -F: '$3 == 0 {print $1}' /etc/passwd 2>/dev/null
        return 1
    fi
}

chk_empty_root_pw() {
    local entry
    entry=$(getent shadow root 2>/dev/null | cut -d: -f2)
    if [ -z "$entry" ]; then
        echo "root password is EMPTY"
        return 1
    fi
    echo "root password set"
    return 0
}

chk_world_writable_etc() {
    local n
    n=$(find /etc -type f -perm -0002 2>/dev/null | wc -l | tr -d ' ')
    if [ "$n" -eq 0 ]; then
        echo "no world-writable files in /etc"
        return 0
    fi
    find /etc -type f -perm -0002 2>/dev/null | head -10
    return 1
}

chk_suid_unusual() {
    # Common legitimate SUID binaries
    local known="su sudo mount umount passwd chsh chfn newgrp gpasswd pkexec dbus-daemon-launch-helper polkit-agent-helper"
    local found=0
    while IFS= read -r f; do
        local base
        base=$(basename "$f")
        case " $known " in
            *" $base "*) ;;
            *) echo "unusual SUID: $f"; found=1 ;;
        esac
    done < <(find / -xdev -perm -4000 -type f 2>/dev/null)
    [ "$found" -eq 0 ] && echo "no unusual SUID binaries" && return 0
    return 1
}

chk_ld_preload() {
    if [ -f /etc/ld.so.preload ]; then
        local content
        content=$(cat /etc/ld.so.preload 2>/dev/null)
        if [ -n "$content" ]; then
            echo "/etc/ld.so.preload non-empty: $content"
            return 1
        fi
    fi
    echo "no ld.so.preload"
    return 0
}

chk_deleted_exe() {
    local found=0
    for pid in $(proc_numeric_pids); do
        local exe
        exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || continue
        case "$exe" in
            *deleted*) echo "PID $pid running deleted binary: $exe"; found=1 ;;
        esac
    done
    [ "$found" -eq 0 ] && echo "no processes running deleted binaries" && return 0
    return 1
}

chk_hidden_pids() {
    local ps_pids proc_pids hidden
    ps_pids=$(ps -e -o pid= | tr -d ' ' | sort -n | uniq)
    proc_pids=$(proc_numeric_pids | sort -n | uniq)
    hidden=$(comm -23 <(echo "$proc_pids") <(echo "$ps_pids"))
    if [ -n "$hidden" ]; then
        echo "hidden PIDs: $hidden"
        return 1
    fi
    echo "no hidden PIDs"
    return 0
}

chk_authorized_keys() {
    local found=0
    for home in /root /home/*; do
        local ak="$home/.ssh/authorized_keys"
        if [ -f "$ak" ]; then
            local n
            n=$(grep -cv '^#' "$ak" 2>/dev/null | tr -d ' ')
            [ "$n" -gt 0 ] && echo "$ak: $n keys" && found=1
        fi
    done
    [ "$found" -eq 0 ] && echo "no authorized_keys found" && return 0
    return 2
}

chk_cron_suspicious() {
    local found=0
    for f in /etc/crontab /etc/cron.d/*; do
        [ -f "$f" ] || continue
        if grep -qiE 'wget|curl|nc |ncat|bash -i|/dev/tcp|python -c|perl -e' "$f" 2>/dev/null; then
            echo "suspicious entry in $f"
            found=1
        fi
    done
    local root_cron
    root_cron=$(crontab -l 2>/dev/null) || true
    if echo "$root_cron" | grep -qiE 'wget|curl|nc |ncat|bash -i|/dev/tcp|python -c|perl -e'; then
        echo "suspicious entry in root crontab"
        found=1
    fi
    [ "$found" -eq 0 ] && echo "no suspicious cron entries" && return 0
    return 1
}

chk_tmp_exec() {
    local found=0
    while IFS= read -r f; do
        [ -x "$f" ] && echo "executable in /tmp: $f" && found=1
    done < <(find /tmp /var/tmp /dev/shm -type f 2>/dev/null)
    [ "$found" -eq 0 ] && echo "no executables in /tmp" && return 0
    return 2
}

chk_failed_ssh() {
    local n=0
    for lg in /var/log/auth.log /var/log/secure; do
        [ -f "$lg" ] || continue
        n=$((n + $(grep -c 'Failed password' "$lg" 2>/dev/null || echo 0)))
    done
    if [ "$n" -gt 50 ]; then
        echo "$n failed SSH attempts (>50)"
        return 2
    fi
    echo "$n failed SSH attempts"
    return 0
}

chk_root_login_recent() {
    local n=0
    for lg in /var/log/auth.log /var/log/secure; do
        [ -f "$lg" ] || continue
        n=$((n + $(grep -c 'session opened for user root' "$lg" 2>/dev/null || echo 0)))
    done
    if [ "$n" -gt 0 ]; then
        echo "$n root logins in current auth log"
        return 2
    fi
    echo "no root logins in current auth log"
    return 0
}

chk_new_users() {
    local new
    new=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1":"$3}' /etc/passwd 2>/dev/null)
    if [ -n "$new" ]; then
        echo "$new"
        return 2
    fi
    echo "no non-system users"
    return 0
}

chk_sudoers_unusual() {
    local found=0
    for f in /etc/sudoers /etc/sudoers.d/*; do
        [ -f "$f" ] || continue
        if grep -qE 'NOPASSWD.*ALL' "$f" 2>/dev/null; then
            echo "NOPASSWD:ALL in $f"
            found=1
        fi
    done
    [ "$found" -eq 0 ] && echo "no NOPASSWD:ALL sudoers" && return 0
    return 1
}

chk_established_outbound() {
    local n=0
    if check_cmd ss; then
        n=$(ss -tunpa state established 2>/dev/null | grep -cvE '127\.0\.0\.|::1|\[::1\]' || true)
    elif check_cmd netstat; then
        n=$(netstat -tunpa 2>/dev/null | grep ESTABLISHED | grep -cvE '127\.0\.0\.|::1' || true)
    fi
    if [ "$n" -gt 20 ]; then
        echo "$n established outbound (>20)"
        return 2
    fi
    echo "$n established outbound"
    return 0
}

chk_recent_modified_bin() {
    local n
    n=$(find /usr/bin /usr/sbin /usr/local/bin /bin /sbin -type f -mtime -7 2>/dev/null | wc -l | tr -d ' ')
    if [ "$n" -gt 0 ]; then
        find /usr/bin /usr/sbin /usr/local/bin /bin /sbin -type f -mtime -7 2>/dev/null
        return 2
    fi
    echo "no recently modified binaries"
    return 0
}

do_audit() {
    echo -e "${C_WARN}>>> Read-only audit (15+ event indicator checks) <<<${C_RST}"
    echo ""
    init_report
    run_check "IR-01" "UID 0 accounts: only root" chk_uid0
    run_check "IR-02" "Root password is not empty" chk_empty_root_pw
    run_check "IR-03" "No world-writable files in /etc" chk_world_writable_etc
    run_check "IR-04" "No atypical SUID binaries" chk_suid_unusual
    run_check "IR-05" "/etc/ld.so.preload is empty" chk_ld_preload
    run_check "IR-06" "No process running deleted binary" chk_deleted_exe
    run_check "IR-07" "No hidden PIDs (rootkit indicator)" chk_hidden_pids
    run_check "IR-08" "SSH authorized_keys manifest" chk_authorized_keys
    run_check "IR-09" "No suspicious cron entries" chk_cron_suspicious
    run_check "IR-10" "No executable files in /tmp" chk_tmp_exec
    run_check "IR-11" "SSH failed attempts count" chk_failed_ssh
    run_check "IR-12" "Recent root logins" chk_root_login_recent
    run_check "IR-13" "Non-system user list" chk_new_users
    run_check "IR-14" "No NOPASSWD:ALL in sudoers" chk_sudoers_unusual
    run_check "IR-15" "Established outbound connections count" chk_established_outbound
    run_check "IR-16" "System binaries modified in last 7 days" chk_recent_modified_bin
    print_summary
}

# ── Analyze collected data ───────────────────────────────────────────
do_analyze() {
    if [ -z "$ARCHIVE_PATH" ]; then
        echo -e "${C_FAIL}Please specify archive path: $0 analyze <archive.tar.gz>${C_RST}"
        exit 1
    fi
    if [ ! -f "$ARCHIVE_PATH" ]; then
        echo -e "${C_FAIL}Archive does not exist: $ARCHIVE_PATH${C_RST}"
        exit 1
    fi
    echo -e "${C_WARN}>>> Analyze collected data: $ARCHIVE_PATH <<<${C_RST}"
    echo ""
    # Verify archive integrity
    echo -e "${C_INFO}── Archive verification ──${C_RST}"
    local arc_hash
    arc_hash=$(sha256sum "$ARCHIVE_PATH" 2>/dev/null | awk '{print $1}')
    echo "SHA-256: $arc_hash"
    echo ""
    # Extract to temp directory
    local tmpdir
    tmpdir=$(mktemp -d)
    tar -xzf "$ARCHIVE_PATH" -C "$tmpdir" 2>/dev/null || {
        echo -e "${C_FAIL}Extraction failed${C_RST}"
        rm -rf "$tmpdir"
        exit 1
    }
    local workdir
    workdir=$(find "$tmpdir" -maxdepth 1 -type d -name "incident-*" | head -1)
    [ -z "$workdir" ] && workdir="$tmpdir"
    echo -e "${C_INFO}Extracted directory: $workdir${C_RST}"
    echo ""
    # Verify manifest
    if [ -f "$workdir/manifest.json" ]; then
        echo -e "${C_INFO}── Manifest verification ──${C_RST}"
        local mismatches=0
        while IFS= read -r f; do
            local rel hash stored
            rel=${f#"$workdir/"}
            hash=$(sha256sum "$f" 2>/dev/null | awk '{print $1}')
            stored=$(grep -A1 "\"file\": \"$rel\"" "$workdir/manifest.json" 2>/dev/null | grep sha256 | head -1 | sed -E 's/.*"sha256": "([^"]+)".*/\1/')
            if [ -n "$stored" ] && [ "$hash" != "$stored" ]; then
                echo -e "${C_FAIL}MISMATCH: $rel${C_RST}"
                mismatches=$((mismatches + 1))
            fi
        done < <(find "$workdir" -type f ! -name "manifest.json" ! -name "sha256sums.txt" 2>/dev/null)
        if [ "$mismatches" -eq 0 ]; then
            echo -e "${C_OK}All artifact hashes match${C_RST}"
        else
            echo -e "${C_FAIL}$mismatches artifact hashes mismatch${C_RST}"
        fi
    fi
    echo ""
    # Highlight suspicious items
    echo -e "${C_INFO}── Suspicious indicator scan ──${C_RST}"
    local suspects=0
    if [ -f "$workdir/02-hidden-pids.txt" ] && grep -q WARN "$workdir/02-hidden-pids.txt" 2>/dev/null; then
        echo -e "${C_FAIL}[!] Hidden PID detected${C_RST}"; suspects=$((suspects + 1))
    fi
    if [ -f "$workdir/02-exe-paths.txt" ] && grep -q SUSPECT "$workdir/02-exe-paths.txt" 2>/dev/null; then
        echo -e "${C_FAIL}[!] Process running deleted binary${C_RST}"; suspects=$((suspects + 1))
    fi
    if [ -f "$workdir/04-ld-so-preload.txt" ] && ! grep -q '\[SKIP\]' "$workdir/04-ld-so-preload.txt" 2>/dev/null; then
        if [ -s "$workdir/04-ld-so-preload.txt" ]; then
            echo -e "${C_FAIL}[!] /etc/ld.so.preload is non-empty (rootkit indicator)${C_RST}"; suspects=$((suspects + 1))
        fi
    fi
    if [ -f "$workdir/07-uid0.txt" ] && [ "$(wc -l < "$workdir/07-uid0.txt" | tr -d ' ')" -gt 1 ]; then
        echo -e "${C_FAIL}[!] Multiple UID 0 accounts${C_RST}"; suspects=$((suspects + 1))
    fi
    if [ -f "$workdir/05-suspicious.txt" ] && [ -s "$workdir/05-suspicious.txt" ]; then
        echo -e "${C_WARN}[?] Suspicious entries found in logs (see 05-suspicious.txt)${C_RST}"; suspects=$((suspects + 1))
    fi
    if [ "$suspects" -eq 0 ]; then
        echo -e "${C_OK}No obvious suspicious indicators found${C_RST}"
    else
        echo ""
        echo -e "${C_WARN}Total $suspects suspicious indicators, please manually review related files.${C_RST}"
    fi
    echo ""
    echo -e "${C_INFO}Artifact directory: $workdir${C_RST}"
    echo -e "${C_WARN}After analysis, please clean up temp directory: rm -rf $tmpdir${C_RST}"
}

# ── Generate summary report ─────────────────────────────────────────────
do_report() {
    if [ -z "$ARCHIVE_PATH" ]; then
        echo -e "${C_FAIL}Please specify archive path: $0 report <archive.tar.gz>${C_RST}"
        exit 1
    fi
    if [ ! -f "$ARCHIVE_PATH" ]; then
        echo -e "${C_FAIL}Archive does not exist: $ARCHIVE_PATH${C_RST}"
        exit 1
    fi
    echo -e "${C_WARN}>>> Generate summary report: $ARCHIVE_PATH <<<${C_RST}"
    echo ""
    local tmpdir
    tmpdir=$(mktemp -d)
    tar -xzf "$ARCHIVE_PATH" -C "$tmpdir" 2>/dev/null || {
        echo -e "${C_FAIL}Extraction failed${C_RST}"
        rm -rf "$tmpdir"
        exit 1
    }
    local workdir
    workdir=$(find "$tmpdir" -maxdepth 1 -type d -name "incident-*" | head -1)
    [ -z "$workdir" ] && workdir="$tmpdir"
    local report="${ARCHIVE_PATH%.tar.gz}-report.txt"
    {
        echo "Incident Triage Summary Report"
        echo "==============================="
        echo "Archive: $ARCHIVE_PATH"
        echo "Generated: $(date)"
        echo "Analyst: $COLLECTOR"
        echo ""
        echo "## System"
        if [ -f "$workdir/01-hostname.txt" ]; then grep -A1 '^---' "$workdir/01-hostname.txt" 2>/dev/null | tail -1; fi
        if [ -f "$workdir/01-uname.txt" ]; then grep -A1 '^---' "$workdir/01-uname.txt" 2>/dev/null | tail -1; fi
        if [ -f "$workdir/01-uptime.txt" ]; then grep -A1 '^---' "$workdir/01-uptime.txt" 2>/dev/null | tail -1; fi
        echo ""
        echo "## Users logged in"
        if [ -f "$workdir/01-who.txt" ]; then grep -A1 '^---' "$workdir/01-who.txt" 2>/dev/null | tail -n +2; fi
        echo ""
        echo "## UID 0 accounts"
        if [ -f "$workdir/07-uid0.txt" ]; then grep -A1 '^---' "$workdir/07-uid0.txt" 2>/dev/null | tail -n +2; fi
        echo ""
        echo "## Listening ports"
        if [ -f "$workdir/03-ss-listen.txt" ]; then grep -A1 '^---' "$workdir/03-ss-listen.txt" 2>/dev/null | tail -n +2; fi
        if [ -f "$workdir/03-netstat-listen.txt" ]; then grep -A1 '^---' "$workdir/03-netstat-listen.txt" 2>/dev/null | tail -n +2; fi
        echo ""
        echo "## Established connections"
        if [ -f "$workdir/03-established.txt" ]; then grep -A1 '^---' "$workdir/03-established.txt" 2>/dev/null | tail -n +2; fi
        echo ""
        echo "## Top 10 processes by CPU"
        if [ -f "$workdir/02-ps-cpu-top.txt" ]; then grep -A1 '^---' "$workdir/02-ps-cpu-top.txt" 2>/dev/null | tail -n +2; fi
        echo ""
        echo "## Hidden PIDs"
        if [ -f "$workdir/02-hidden-pids.txt" ]; then grep -A1 '^---' "$workdir/02-hidden-pids.txt" 2>/dev/null | tail -n +2; fi
        echo ""
        echo "## Deleted-binary processes"
        if [ -f "$workdir/02-exe-paths.txt" ]; then grep SUSPECT "$workdir/02-exe-paths.txt" 2>/dev/null || echo "none"; fi
        echo ""
        echo "## SSH authorized_keys"
        if [ -f "$workdir/04-authorized-keys.txt" ]; then wc -l "$workdir/04-authorized-keys.txt" 2>/dev/null; fi
        echo ""
        echo "## Suspicious log entries"
        if [ -f "$workdir/05-suspicious.txt" ]; then wc -l "$workdir/05-suspicious.txt" 2>/dev/null; fi
        echo ""
        echo "## Recently modified files (24h)"
        if [ -f "$workdir/06-recent-modified.txt" ]; then wc -l "$workdir/06-recent-modified.txt" 2>/dev/null; fi
        echo ""
        echo "## SUID/SGID files"
        if [ -f "$workdir/06-suid-sgid.txt" ]; then wc -l "$workdir/06-suid-sgid.txt" 2>/dev/null; fi
        echo ""
        echo "## Manifest"
        if [ -f "$workdir/manifest.json" ]; then head -10 "$workdir/manifest.json" 2>/dev/null; fi
        echo ""
        echo "## Recommendation"
        echo "1. Review all [SUSPECT]/[WARN]/[!] items above"
        echo "2. Cross-reference established connections with expected services"
        echo "3. Verify all authorized_keys belong to known administrators"
        echo "4. If compromise confirmed: isolate, preserve evidence, then eradicate"
        echo "5. See handbook/21-incident-response-forensics.md for full procedure"
    } > "$report"
    echo -e "${C_OK}Report: ${C_INFO}$report${C_RST}"
    echo ""
    cat "$report"
    rm -rf "$tmpdir"
}

# ── Interactive wizard ───────────────────────────────────────────────
interactive_wizard() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}  Emergency forensic collection      ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 📦 Full collection (collect)"
        echo -e "  ${C_WARN}2.${C_RST} ⚡ Quick overview (quick)"
        echo -e "  ${C_WARN}3.${C_RST} 🛡️ Read-only audit (audit, 15+ checks)"
        echo -e "  ${C_WARN}4.${C_RST} 🔍 Analyze archive (analyze)"
        echo -e "  ${C_WARN}5.${C_RST} 📋 Generate report (report)"
        echo -e "  ${C_WARN}0.${C_RST} Back"
        echo
        local pick
        read -r -p "Select [0-5]: " pick
        case $pick in
            1) do_collect; wait_key ;;
            2) do_quick; wait_key ;;
            3) do_audit; wait_key ;;
            4)
                read -r -p "Archive path: " ARCHIVE_PATH
                do_analyze; wait_key
                ;;
            5)
                read -r -p "Archive path: " ARCHIVE_PATH
                do_report; wait_key
                ;;
            0) break ;;
            *) echo -e "${C_FAIL}Invalid input${C_RST}"; sleep 1 ;;
        esac
    done
}

# ── Main flow ───────────────────────────────────────────────────
main() {
    parse_args "$@"
    case "$MODE" in
        collect) check_root; do_collect ;;
        quick) check_root; do_quick ;;
        audit) check_root; do_audit ;;
        analyze) do_analyze ;;
        report) do_report ;;
        interactive) check_root; interactive_wizard ;;
        *) echo "Unknown mode: $MODE"; exit 1 ;;
    esac
}

main "$@"
