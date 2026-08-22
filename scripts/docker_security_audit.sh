#!/bin/bash
# ════════════════════════════════════════════════════════════
#  docker_security_audit.sh — CIS Docker Benchmark Compliance Audit
#  适用系统: 任何安装了 Docker 的 Linux 主机
#  运行身份: root (推荐) 或 docker 组成员
#  审计模式: 只读, 不修改任何 Docker 配置或容器
#  参考: CIS Docker Benchmark v1.6.0
#  项目主页: https://github.com/0x10debug/vps-security-enhancement-scripts
# ════════════════════════════════════════════════════════════
#
# 用法:
#   sudo ./scripts/docker_security_audit.sh              # 完整审计
#   sudo ./scripts/docker_security_audit.sh --json       # 输出 JSON 报告路径
#   sudo ./scripts/docker_security_audit.sh --quiet      # 只输出摘要
#   sudo ./scripts/docker_security_audit.sh --container <name>  # 审计特定容器
#
# 退出码:
#   0 — 审计完成
#   1 — 参数错误 / Docker 未安装

set -euo pipefail

APP_NAME="docker_security_audit"
APP_VER="v2.2.0"
QUIET=0
JSON_ONLY=0
TARGET_CONTAINER=""
REPORT_DIR="/var/log/docker-audit"
REPORT_TXT=""
REPORT_JSON=""
TIMESTAMP=$(date +%Y%m%d%H%M%S)

COUNT_PASS=0
COUNT_FAIL=0
COUNT_WARN=0
COUNT_SKIP=0
TOTAL_CHECKS=0
JSON_RESULTS="["

C_FAIL='\033[0;31m'
C_OK='\033[0;32m'
C_WARN='\033[0;33m'
C_INFO='\033[0;34m'
C_RST='\033[0m'

# ── 参数解析 ─────────────────────────────────────────────────
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --quiet) QUIET=1; shift ;;
            --json) JSON_ONLY=1; shift ;;
            --container) TARGET_CONTAINER="$2"; shift 2 ;;
            -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
            *) echo "未知参数: $1"; exit 1 ;;
        esac
    done
}

# ── Docker 检查 ──────────────────────────────────────────────
check_docker_installed() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker 未安装"
        exit 1
    fi
}

# ── 报告初始化 ───────────────────────────────────────────────
init_report() {
    mkdir -p "$REPORT_DIR" 2>/dev/null || true
    REPORT_TXT="$REPORT_DIR/docker-audit-${TIMESTAMP}.txt"
    REPORT_JSON="$REPORT_DIR/docker-audit-${TIMESTAMP}.json"
    {
        echo "CIS Docker Benchmark Compliance Audit Report"
        echo "============================================="
        echo "Date: $(date)"
        echo "Host: $(hostname)"
        echo "Docker: $(docker --version 2>/dev/null || echo 'N/A')"
        echo "Script: $APP_NAME $APP_VER"
        echo ""
    } > "$REPORT_TXT"
}

# ── 检查函数 ─────────────────────────────────────────────────
run_check() {
    local cis_id="$1" desc="$2"
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

    {
        echo ""
        echo "[$result] $cis_id $desc"
        echo "  Evidence: $evidence"
    } >> "$REPORT_TXT"

    local json_entry
    json_entry=$(printf '{"id":"%s","description":"%s","result":"%s","evidence":"%s"}' \
        "$cis_id" "${desc//\"/\\\"}" "$result" "${evidence//\"/\\\"}")
    if [ "$TOTAL_CHECKS" -gt 1 ]; then
        JSON_RESULTS="$JSON_RESULTS,$json_entry"
    else
        JSON_RESULTS="$JSON_RESULTS$json_entry"
    fi
}

# ── 辅助 ─────────────────────────────────────────────────────
get_docker_info() {
    docker info 2>/dev/null
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

# ── 1.x Docker Daemon Configuration ──────────────────────────
section_daemon_config() {
    echo ""
    echo "━━━ 1.x Docker Daemon Configuration ━━━"

    run_check "1.1" "Ensure Docker daemon is running" \
        bash -c 'docker info >/dev/null 2>&1 && echo "daemon running" && return 0 || echo "daemon not running" && return 1'

    run_check "1.2" "Ensure Docker daemon is managed by systemd" \
        bash -c 'systemctl is-enabled docker 2>/dev/null | grep -q "enabled" && echo "docker managed by systemd" && return 0 || echo "docker not managed by systemd" && return 1'

    run_check "1.3" "Ensure auditing is configured for the Docker daemon" \
        bash -c 'auditctl -l 2>/dev/null | grep -q "/usr/bin/docker" && echo "docker daemon audited" && return 0 || echo "no auditd rule for docker daemon" && return 1'

    run_check "1.4" "Ensure auditing is configured for Docker files and directories" \
        bash -c 'auditctl -l 2>/dev/null | grep -q "/var/lib/docker" && echo "docker dirs audited" && return 0 || echo "no auditd rule for docker dirs" && return 1'

    run_check "1.5" "Ensure auditing is configured for Docker socket" \
        bash -c 'auditctl -l 2>/dev/null | grep -q "/var/run/docker.sock" && echo "docker socket audited" && return 0 || echo "no auditd rule for docker socket" && return 1'

    # 1.x daemon.json checks
    run_check "1.6" "Ensure /etc/docker/daemon.json is configured" \
        bash -c '[ -f /etc/docker/daemon.json ] && echo "daemon.json exists" && return 0 || echo "daemon.json not found" && return 2'

    run_check "1.7" "Ensure containerd is configured (if used)" \
        bash -c '[ -f /etc/containerd/config.toml ] && echo "containerd config exists" && return 0 || echo "no containerd config (may not be in use)" && return 3'

    # Security options in daemon.json
    run_check "1.8" "Ensure user namespace remapping is configured" \
        bash -c 'get_docker_info | grep -q "userns-remap" && echo "userns-remap enabled" && return 0 || echo "userns-remap not configured" && return 1'

    run_check "1.9" "Ensure live restore is enabled" \
        bash -c 'get_docker_info | grep -q "Live Restore Enabled: true" && echo "live restore enabled" && return 0 || echo "live restore not enabled" && return 1'

    run_check "1.10" "Ensure Content trust for Docker is enabled" \
        bash -c 'get_docker_info 2>/dev/null | grep -qi "content trust" && return 0 || { [ -n "${DOCKER_CONTENT_TRUST:-}" ] && [ "$DOCKER_CONTENT_TRUST" = "1" ] && echo "DOCKER_CONTENT_TRUST=1" && return 0; } || echo "content trust not enabled" && return 1'

    run_check "1.11" "Ensure containerd runtime is configured" \
        bash -c 'get_docker_info 2>/dev/null | grep -q "default runtime: runc\|default runtime: containerd" && echo "runtime configured" && return 0 || echo "runtime check inconclusive" && return 2'

    run_check "1.12" "Ensure default ulimit is configured" \
        bash -c 'get_docker_info 2>/dev/null | grep -q "default ulimit" && echo "default ulimit set" && return 0 || echo "no default ulimit" && return 2'
}

# ── 2.x Docker Daemon Files ──────────────────────────────────
section_daemon_files() {
    echo ""
    echo "━━━ 2.x Docker Daemon Files ━━━"

    run_check "2.1" "Ensure permissions on /etc/docker/daemon.json are 644 or more restrictive" \
        bash -c '[ -f /etc/docker/daemon.json ] && check_file_perm /etc/docker/daemon.json 644 || echo "daemon.json not found" && return 2'

    run_check "2.2" "Ensure permissions on /etc/docker/ directory are 755 or more restrictive" \
        bash -c 'check_file_perm /etc/docker 755'

    run_check "2.3" "Ensure permissions on docker.socket are configured" \
        bash -c 'f=$(systemctl show docker.socket -p FragmentPath 2>/dev/null | cut -d= -f2); [ -n "$f" ] && [ -f "$f" ] && check_file_perm "$f" 644 || echo "docker.socket not found via systemd" && return 2'

    run_check "2.4" "Ensure permissions on docker.service are configured" \
        bash -c 'f=$(systemctl show docker.service -p FragmentPath 2>/dev/null | cut -d= -f2); [ -n "$f" ] && [ -f "$f" ] && check_file_perm "$f" 644 || echo "docker.service not found via systemd" && return 2'

    run_check "2.5" "Ensure permissions on /var/lib/docker/ are configured" \
        bash -c 'check_file_perm /var/lib/docker 711'

    run_check "2.6" "Ensure permissions on /var/run/docker.sock are configured" \
        bash -c '[ -S /var/run/docker.sock ] && check_file_perm /var/run/docker.sock 660 || echo "docker.sock not found" && return 2'
}

# ── 3.x Container Images ─────────────────────────────────────
section_container_images() {
    echo ""
    echo "━━━ 3.x Container Images ━━━"

    run_check "3.1" "Ensure no :latest tag images are in use" \
        bash -c 'n=$(docker ps --format "{{.Image}}" 2>/dev/null | grep -c ":latest" || true); [ "$n" -eq 0 ] && echo "no :latest tags in running containers" && return 0 || echo "$n containers using :latest" && return 1'

    run_check "3.2" "Ensure specific image tags are used (not floating)" \
        bash -c 'n=$(docker ps --format "{{.Image}}" 2>/dev/null | grep -vE ":[a-zA-Z0-9._-]+$" | grep -vE ":[0-9]+\.[0-9]+\.[0-9]+" | wc -l || true); [ "$n" -eq 0 ] && echo "all images have specific tags" && return 0 || echo "$n images may have floating tags" && return 2'

    run_check "3.3" "Ensure Docker image vulnerability scanning is configured" \
        bash -c 'docker scout version 2>/dev/null >/dev/null && echo "docker scout available" && return 0 || { command -v trivy >/dev/null 2>&1 && echo "trivy available" && return 0; } || echo "no image scanner found (docker scout or trivy)" && return 1'

    run_check "3.4" "Ensure rootless Docker mode is used (if possible)" \
        bash -c 'get_docker_info 2>/dev/null | grep -q "rootless" && echo "rootless mode" && return 0 || echo "not rootless mode" && return 2'

    run_check "3.5" "Ensure only trusted base images are used" \
        bash -c 'echo "manual review required — check Dockerfile FROM lines" && return 2'
}

# ── 4.x Container Runtime ────────────────────────────────────
section_container_runtime() {
    echo ""
    echo "━━━ 4.x Container Runtime ━━━"

    local container_filter=""
    [ -n "$TARGET_CONTAINER" ] && container_filter="--filter name=$TARGET_CONTAINER"

    # Get running containers (used implicitly via docker ps in checks below)

    run_check "4.1" "Ensure --privileged mode is not used" \
        bash -c 'n=$(docker inspect --format "{{.HostConfig.Privileged}}" $(docker ps -q '"$container_filter"' 2>/dev/null) 2>/dev/null | grep -c "true" || true); [ "$n" -eq 0 ] && echo "no privileged containers" && return 0 || echo "$n privileged containers" && return 1'

    run_check "4.2" "Ensure --cap-add is not used to add dangerous capabilities" \
        bash -c 'n=0; for c in $(docker ps -q '"$container_filter"' 2>/dev/null); do caps=$(docker inspect --format "{{.HostConfig.CapAdd}}" "$c" 2>/dev/null); echo "$caps" | grep -qiE "SYS_ADMIN|SYS_MODULE|SYS_PTRACE|NET_ADMIN|DAC_READ_SEARCH" && n=$((n+1)); done; [ "$n" -eq 0 ] && echo "no dangerous caps added" && return 0 || echo "$n containers with dangerous caps" && return 1'

    run_check "4.3" "Ensure containers do not share host PID namespace" \
        bash -c 'n=$(docker inspect --format "{{.HostConfig.PidMode}}" $(docker ps -q '"$container_filter"' 2>/dev/null) 2>/dev/null | grep -c "host" || true); [ "$n" -eq 0 ] && echo "no host PID namespace sharing" && return 0 || echo "$n containers sharing host PID" && return 1'

    run_check "4.4" "Ensure containers do not share host IPC namespace" \
        bash -c 'n=$(docker inspect --format "{{.HostConfig.IpcMode}}" $(docker ps -q '"$container_filter"' 2>/dev/null) 2>/dev/null | grep -c "host" || true); [ "$n" -eq 0 ] && echo "no host IPC namespace sharing" && return 0 || echo "$n containers sharing host IPC" && return 1'

    run_check "4.5" "Ensure containers do not share host UTS namespace" \
        bash -c 'n=$(docker inspect --format "{{.HostConfig.UTSMode}}" $(docker ps -q '"$container_filter"' 2>/dev/null) 2>/dev/null | grep -c "host" || true); [ "$n" -eq 0 ] && echo "no host UTS namespace sharing" && return 0 || echo "$n containers sharing host UTS" && return 1'

    run_check "4.6" "Ensure containers do not share host network namespace" \
        bash -c 'n=$(docker inspect --format "{{.HostConfig.NetworkMode}}" $(docker ps -q '"$container_filter"' 2>/dev/null) 2>/dev/null | grep -c "host" || true); [ "$n" -eq 0 ] && echo "no host network namespace sharing" && return 0 || echo "$n containers sharing host network" && return 1'

    run_check "4.7" "Ensure containers do not share host user namespace" \
        bash -c 'n=$(docker inspect --format "{{.HostConfig.UsernsMode}}" $(docker ps -q '"$container_filter"' 2>/dev/null) 2>/dev/null | grep -c "host" || true); [ "$n" -eq 0 ] && echo "no host user namespace sharing" && return 0 || echo "$n containers sharing host userns" && return 1'

    run_check "4.8" "Ensure containers do not run as root user" \
        bash -c 'n=0; for c in $(docker ps -q '"$container_filter"' 2>/dev/null); do user=$(docker inspect --format "{{.Config.User}}" "$c" 2>/dev/null); [ -z "$user" ] || [ "$user" = "root" ] || [ "$user" = "0" ] && n=$((n+1)); done; [ "$n" -eq 0 ] && echo "no root-running containers" && return 0 || echo "$n containers running as root" && return 1'

    run_check "4.9" "Ensure containers do not mount Docker socket" \
        bash -c 'n=0; for c in $(docker ps -q '"$container_filter"' 2>/dev/null); do docker inspect --format "{{range .Mounts}}{{.Source}}{{end}}" "$c" 2>/dev/null | grep -q "docker.sock" && n=$((n+1)); done; [ "$n" -eq 0 ] && echo "no docker.sock mounts" && return 0 || echo "$n containers mounting docker.sock" && return 1'

    run_check "4.10" "Ensure containers do not mount sensitive host directories" \
        bash -c 'n=0; for c in $(docker ps -q '"$container_filter"' 2>/dev/null); do docker inspect --format "{{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}" "$c" 2>/dev/null | grep -qE "/etc | /root | /var/lib/docker | /proc | /sys " && n=$((n+1)); done; [ "$n" -eq 0 ] && echo "no sensitive host mounts" && return 0 || echo "$n containers with sensitive mounts" && return 1'

    run_check "4.11" "Ensure container memory limit is set" \
        bash -c 'n=0; for c in $(docker ps -q '"$container_filter"' 2>/dev/null); do mem=$(docker inspect --format "{{.HostConfig.Memory}}" "$c" 2>/dev/null); [ "$mem" = "0" ] || [ -z "$mem" ] && n=$((n+1)); done; [ "$n" -eq 0 ] && echo "all containers have memory limits" && return 0 || echo "$n containers without memory limits" && return 1'

    run_check "4.12" "Ensure container CPU priority is set" \
        bash -c 'n=0; for c in $(docker ps -q '"$container_filter"' 2>/dev/null); do cpu=$(docker inspect --format "{{.HostConfig.CpuShares}}" "$c" 2>/dev/null); [ "$cpu" = "0" ] || [ -z "$cpu" ] && n=$((n+1)); done; [ "$n" -eq 0 ] && echo "all containers have CPU shares" && return 0 || echo "$n containers without CPU shares" && return 2'

    run_check "4.13" "Ensure container read-only root filesystem is used" \
        bash -c 'n=0; for c in $(docker ps -q '"$container_filter"' 2>/dev/null); do ro=$(docker inspect --format "{{.HostConfig.ReadonlyRootfs}}" "$c" 2>/dev/null); [ "$ro" = "false" ] || [ -z "$ro" ] && n=$((n+1)); done; [ "$n" -eq 0 ] && echo "all containers have read-only rootfs" && return 0 || echo "$n containers without read-only rootfs" && return 2'

    run_check "4.14" "Ensure container restart policy is not always" \
        bash -c 'n=$(docker inspect --format "{{.HostConfig.RestartPolicy.Name}}" $(docker ps -q '"$container_filter"' 2>/dev/null) 2>/dev/null | grep -c "always" || true); [ "$n" -eq 0 ] && echo "no always restart policy" && return 0 || echo "$n containers with always restart" && return 2'

    run_check "4.15" "Ensure HEALTHCHECK is configured for containers" \
        bash -c 'n=0; for c in $(docker ps -q '"$container_filter"' 2>/dev/null); do hc=$(docker inspect --format "{{.Config.Healthcheck.Test}}" "$c" 2>/dev/null); [ -z "$hc" ] || [ "$hc" = "<nil>" ] && n=$((n+1)); done; [ "$n" -eq 0 ] && echo "all containers have healthcheck" && return 0 || echo "$n containers without healthcheck" && return 1'
}

# ── 5.x Docker Security Operations ───────────────────────────
section_security_ops() {
    echo ""
    echo "━━━ 5.x Docker Security Operations ━━━"

    run_check "5.1" "Ensure AppArmor or SELinux profile is applied to containers" \
        bash -c 'n=0; for c in $(docker ps -q 2>/dev/null); do aa=$(docker inspect --format "{{.AppArmorProfile}}" "$c" 2>/dev/null); [ -z "$aa" ] || [ "$aa" = "<no value>" ] && n=$((n+1)); done; [ "$n" -eq 0 ] && echo "all containers have AppArmor/SELinux" && return 0 || echo "$n containers without MAC profile" && return 1'

    run_check "5.2" "Ensure seccomp profile is applied to containers" \
        bash -c 'n=$(docker inspect --format "{{.HostConfig.SecurityOpt}}" $(docker ps -q 2>/dev/null) 2>/dev/null | grep -c "seccomp:unconfined" || true); [ "$n" -eq 0 ] && echo "no unconfined seccomp" && return 0 || echo "$n containers with unconfined seccomp" && return 1'

    run_check "5.3" "Ensure cgroup usage is restricted" \
        bash -c 'n=0; for c in $(docker ps -q 2>/dev/null); do cg=$(docker inspect --format "{{.HostConfig.CgroupParent}}" "$c" 2>/dev/null); [ -n "$cg" ] && [ "$cg" != "" ] && n=$((n+1)); done; echo "$n containers with custom cgroup parent" && return 2'

    run_check "5.4" "Ensure container PID cgroup is limited" \
        bash -c 'n=0; for c in $(docker ps -q 2>/dev/null); do pids=$(docker inspect --format "{{.HostConfig.PidsLimit}}" "$c" 2>/dev/null); [ "$pids" = "0" ] || [ -z "$pids" ] && n=$((n+1)); done; [ "$n" -eq 0 ] && echo "all containers have PID limits" && return 0 || echo "$n containers without PID limits" && return 2'

    run_check "5.5" "Ensure Docker's secret management is used" \
        bash -c 'docker secret ls 2>/dev/null | grep -q . && echo "secrets in use" && return 0 || echo "no Docker secrets (may use other secret mgmt)" && return 2'

    run_check "5.6" "Ensure docker-compose network exposure is minimal" \
        bash -c 'n=$(docker network ls --filter driver=bridge -q 2>/dev/null | wc -l); echo "$n bridge networks" && return 2'

    run_check "5.7" "Ensure Docker API is not exposed via TCP without TLS" \
        bash -c 'get_docker_info 2>/dev/null | grep -q "tcp://" && { get_docker_info | grep -q "tls" && echo "TCP with TLS" && return 0 || echo "TCP without TLS (insecure)" && return 1; } || echo "no TCP API (unix socket only)" && return 0'
}

# ── 6.x Docker Network Configuration ─────────────────────────
section_network() {
    echo ""
    echo "━━━ 6.x Docker Network Configuration ━━━"

    run_check "6.1" "Ensure default bridge network is not used for containers" \
        bash -c 'n=$(docker ps --format "{{.Networks}}" 2>/dev/null | grep -c "bridge" || true); echo "$n containers on default bridge" && return 2'

    run_check "6.2" "Ensure Docker bridge network is properly restricted" \
        bash -c 'iptables -L DOCKER-USER -n 2>/dev/null | grep -q . && echo "DOCKER-USER chain exists" && return 0 || echo "no DOCKER-USER chain" && return 2'

    run_check "6.3" "Ensure Docker daemon port is not exposed externally" \
        bash -c 'ss -tlnp 2>/dev/null | grep -q "2375\|2376" && echo "Docker port exposed (check if protected)" && return 1 || echo "Docker port not exposed" && return 0'
}

# ── 7.x Docker Logging ───────────────────────────────────────
section_logging() {
    echo ""
    echo "━━━ 7.x Docker Logging ━━━"

    run_check "7.1" "Ensure Docker log rotation is configured" \
        bash -c 'get_docker_info 2>/dev/null | grep -q "log-opts" || [ -f /etc/docker/daemon.json ] && grep -q "max-size" /etc/docker/daemon.json 2>/dev/null && echo "log rotation configured" && return 0 || echo "no log rotation" && return 1'

    run_check "7.2" "Ensure Docker logs are forwarded to a central log server" \
        bash -c 'get_docker_info 2>/dev/null | grep -q "syslog\|fluentd\|gelf\|journald" && echo "central logging configured" && return 0 || echo "no central logging (default json-file)" && return 2'
}

# ── 摘要 ─────────────────────────────────────────────────────
print_summary() {
    local total=$TOTAL_CHECKS
    local pass_pct=0
    [ "$total" -gt 0 ] && pass_pct=$((COUNT_PASS * 100 / total))

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  CIS Docker Benchmark Audit Summary"
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

write_json_report() {
    JSON_RESULTS="$JSON_RESULTS]"
    cat > "$REPORT_JSON" <<EOF
{
  "audit": {
    "tool": "$APP_NAME",
    "version": "$APP_VER",
    "timestamp": "$(date -Iseconds 2>/dev/null || date)",
    "host": "$(hostname)",
    "docker_version": "$(docker --version 2>/dev/null || echo 'N/A')",
    "target_container": "${TARGET_CONTAINER:-all}"
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
    check_docker_installed
    init_report

    if [ "$QUIET" -eq 0 ]; then
        echo ""
        echo -e "${C_INFO}╔══════════════════════════════════════════╗${C_RST}"
        echo -e "${C_INFO}║  CIS Docker Benchmark Audit               ║${C_RST}"
        echo -e "${C_INFO}║  $APP_NAME $APP_VER                       ║${C_RST}"
        echo -e "${C_INFO}╚══════════════════════════════════════════╝${C_RST}"
        echo -e "${C_INFO}Docker: $(docker --version 2>/dev/null || echo 'N/A')${C_RST}"
        [ -n "$TARGET_CONTAINER" ] && echo -e "${C_INFO}Target: $TARGET_CONTAINER${C_RST}"
        echo -e "${C_INFO}Mode: READ-ONLY (no changes)${C_RST}"
        echo ""
    fi

    section_daemon_config
    section_daemon_files
    section_container_images
    section_container_runtime
    section_security_ops
    section_network
    section_logging

    write_json_report
    print_summary

    [ "$JSON_ONLY" -eq 1 ] && echo "$REPORT_JSON"
    return 0
}

main "$@"
