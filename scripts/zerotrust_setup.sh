#!/bin/bash
# ════════════════════════════════════════════════════════════
#  zerotrust_setup.sh — Zero Trust Network Setup (WireGuard + Headscale)
#  适用系统: Linux 主机
#  运行身份: root
#  模式: 部署 + 配置生成 + 审计 (不直接修改运行中的 Headscale)
#  参考: juanfont/headscale
#         OLife97/headscale-stack-crowdsec
#         WireGuard 官方文档
#  项目主页: https://github.com/0x10debug/vps-security-enhancement-scripts
# ════════════════════════════════════════════════════════════
#
# 用法:
#   sudo ./scripts/zerotrust_setup.sh                    # 交互式向导
#   sudo ./scripts/zerotrust_setup.sh --install-wireguard # 安装 WireGuard
#   sudo ./scripts/zerotrust_setup.sh --install-headscale # 安装 Headscale
#   sudo ./scripts/zerotrust_setup.sh --acl               # 生成 ACL 配置
#   sudo ./scripts/zerotrust_setup.sh --crowdsec          # 生成 CrowdSec 集成配置
#   sudo ./scripts/zerotrust_setup.sh --geoip             # 生成 GeoIP 过滤配置
#   sudo ./scripts/zerotrust_setup.sh --audit             # 只读审计零信任配置
#   sudo ./scripts/zerotrust_setup.sh --output ./zt-configs
#   sudo ./scripts/zerotrust_setup.sh --domain zt.example.com
#
# 退出码:
#   0 — 成功
#   1 — 参数错误 / 依赖缺失
#   2 — 部分功能不可用

set -euo pipefail

APP_NAME="zerotrust_setup"
APP_VER="v3.0.0"
MODE=""
OUTPUT_DIR=""
DOMAIN=""
REPORT_DIR="/var/log/zerotrust-audit"
TIMESTAMP=$(date +%Y%m%d%H%M%S)

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

# ── 参数解析 ─────────────────────────────────────────────────
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --install-wireguard) MODE="install-wg"; shift ;;
            --install-headscale) MODE="install-hs"; shift ;;
            --acl) MODE="acl"; shift ;;
            --crowdsec) MODE="crowdsec"; shift ;;
            --geoip) MODE="geoip"; shift ;;
            --audit) MODE="audit"; shift ;;
            --output) OUTPUT_DIR="$2"; shift 2 ;;
            --domain) DOMAIN="$2"; shift 2 ;;
            -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
            *) echo "未知参数: $1"; exit 1 ;;
        esac
    done
    if [ -z "$MODE" ]; then
        MODE="interactive"
    fi
    if [ -z "$OUTPUT_DIR" ]; then
        OUTPUT_DIR="./zerotrust-configs"
    fi
    if [ -z "$DOMAIN" ]; then
        DOMAIN="zt.vps.local"
    fi
}

# ── 报告初始化 ───────────────────────────────────────────────
init_report() {
    mkdir -p "$REPORT_DIR" 2>/dev/null || REPORT_DIR="/tmp/zerotrust-audit"
    mkdir -p "$REPORT_DIR" 2>/dev/null || true
    REPORT_FILE="$REPORT_DIR/zt-audit-${TIMESTAMP}.txt"
    {
        echo "Zero Trust Network Audit Report"
        echo "================================"
        echo "Date: $(date)"
        echo "Host: $(hostname 2>/dev/null || echo 'N/A')"
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
}

# ── WireGuard 安装 ───────────────────────────────────────────
install_wireguard() {
    echo -e "${C_WARN}>>> 安装 WireGuard <<<${C_RST}"

    if command -v wg >/dev/null 2>&1; then
        echo -e "${C_OK}WireGuard 已安装: $(wg --version)${C_RST}"
        return 0
    fi

    if command -v apt >/dev/null 2>&1; then
        apt update && apt install -y wireguard wireguard-tools
    elif command -v yum >/dev/null 2>&1; then
        yum install -y epel-release && yum install -y wireguard-tools
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache wireguard-tools
    else
        echo -e "${C_FAIL}不支持的包管理器${C_RST}"
        return 1
    fi

    # 启用 IP 转发
    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.ipv6.conf.all.forwarding=1
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.d/99-wireguard.conf
    echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-wireguard.conf

    echo -e "${C_OK}WireGuard 安装完成${C_RST}"
    echo -e "${C_INFO}使用 wg-quick up <config> 启动隧道${C_RST}"
}

# ── Headscale 安装 ───────────────────────────────────────────
install_headscale() {
    echo -e "${C_WARN}>>> 安装 Headscale (Tailscale 控制服务器) <<<${C_RST}"

    if command -v headscale >/dev/null 2>&1; then
        echo -e "${C_OK}Headscale 已安装: $(headscale version 2>/dev/null || echo 'unknown')${C_RST}"
        return 0
    fi

    # 下载最新 release binary
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64) arch="amd64" ;;
        aarch64) arch="arm64" ;;
        *) echo -e "${C_FAIL}不支持的架构: $arch${C_RST}"; return 1 ;;
    esac

    echo -e "${C_INFO}下载 Headscale...${C_RST}"
    local hs_version
    hs_version=$(curl -sL https://api.github.com/repos/juanfont/headscale/releases/latest \
        | grep '"tag_name"' | sed 's/.*"v\(.*\)".*/\1/' | head -1)
    [ -z "$hs_version" ] && hs_version="0.23.0"

    curl -sL "https://github.com/juanfont/headscale/releases/download/v${hs_version}/headscale_${hs_version}_linux_${arch}" \
        -o /usr/local/bin/headscale
    chmod +x /usr/local/bin/headscale

    # 创建配置目录
    mkdir -p /etc/headscale
    mkdir -p /var/lib/headscale

    # 生成默认配置
    headscale config generate > /etc/headscale/config.yaml 2>/dev/null || true

    # 创建 systemd 服务
    cat > /etc/systemd/system/headscale.service <<'EOF'
[Unit]
Description=Headscale - Tailscale Control Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/headscale serve
Restart=always
RestartSec=5
Environment=HEADSCALE_CONFIG=/etc/headscale/config.yaml

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable headscale
    systemctl start headscale

    echo -e "${C_OK}Headscale 安装完成 (v${hs_version})${C_RST}"
    echo -e "${C_INFO}配置文件: /etc/headscale/config.yaml${C_RST}"
    echo -e "${C_INFO}服务: systemctl status headscale${C_RST}"
}

# ── ACL 配置生成 ─────────────────────────────────────────────
generate_acl_config() {
    echo -e "${C_WARN}>>> 生成 Headscale ACL 配置 <<<${C_RST}"
    mkdir -p "$OUTPUT_DIR"

    cat > "$OUTPUT_DIR/headscale-acl.huac" <<'EOF'
// Headscale ACL (Huac format)
// Zero Trust Network Access Control
// Generated by zerotrust_setup.sh

// ── 用户组 ──
group:admin    = ["admin@zt.vps.local"];
group:developer = ["dev@zt.vps.local"];
group:viewer   = ["viewer@zt.vps.local"];

// ── 设备标签 ──
tag:server     = ["admin@zt.vps.local"];
tag:workstation = ["admin@zt.vps.local", "dev@zt.vps.local"];
tag:monitoring = ["admin@zt.vps.local"];

// ── ACL 规则 ──
acl = [
    // admin: 全部访问
    { action = "accept", src = ["group:admin"], dst = ["*:*"] },

    // developer: 访问开发服务器 + Web 服务
    { action = "accept", src = ["group:developer"], dst = ["tag:server:80,443,22", "tag:workstation:*"] },

    // viewer: 只读访问 Web 服务
    { action = "accept", src = ["group:viewer"], dst = ["tag:server:80,443"] },

    // monitoring: 访问监控端口
    { action = "accept", src = ["tag:monitoring"], dst = ["tag:server:9090,9093,3000,9100"] },

    // 默认拒绝
    { action = "deny", src = ["*"], dst = ["*:*"] },
];

// ── SSH 规则 ──
ssh = [
    // admin 可 SSH 到所有服务器
    { action = "accept", src = ["group:admin"], dst = ["tag:server"] },
    // developer 可 SSH 到开发服务器
    { action = "accept", src = ["group:developer"], dst = ["tag:server"] },
];

// ── 测试规则 ──
tests = [
    { src = "admin@zt.vps.local", accept = ["tag:server:22", "tag:server:443"] },
    { src = "dev@zt.vps.local", accept = ["tag:server:443"], deny = ["tag:server:22"] },
    { src = "viewer@zt.vps.local", accept = ["tag:server:443"], deny = ["tag:server:22"] },
];
EOF

    cat > "$OUTPUT_DIR/acl-README.md" <<'EOF'
# Headscale ACL Configuration

## Overview
This ACL defines zero trust access rules for the Headscale mesh network.

## Groups
- **admin**: Full access to all resources
- **developer**: Access to dev servers (SSH + Web) and workstations
- **viewer**: Read-only web access

## Tags
- **server**: Production servers (assigned by admin)
- **workstation**: Developer workstations
- **monitoring**: Monitoring nodes

## Deployment
1. Copy headscale-acl.huac to /etc/headscale/acl.huac
2. Update config.yaml: `acl_path: /etc/headscale/acl.huac`
3. Restart Headscale: `systemctl restart headscale`
4. Verify: `headscale policy check`

## Testing
The `tests` section includes automated test cases to verify ACL correctness.
EOF

    echo -e "${C_OK}ACL 配置已生成到: $OUTPUT_DIR/headscale-acl.huac${C_RST}"
}

# ── CrowdSec 集成配置 ────────────────────────────────────────
generate_crowdsec_config() {
    echo -e "${C_WARN}>>> 生成 CrowdSec 集成配置 <<<${C_RST}"
    mkdir -p "$OUTPUT_DIR/crowdsec"

    # CrowdSec acquisition for Headscale logs
    cat > "$OUTPUT_DIR/crowdsec/acquis.yaml" <<'EOF'
# CrowdSec acquisition for Headscale / WireGuard logs
# Place in /etc/crowdsec/acquis.yaml (append)

filenames:
  - /var/log/headscale.log
  - /var/log/syslog
labels:
  type: headscale
---
filenames:
  - /var/log/auth.log
  - /var/log/syslog
labels:
  type: wireguard
---
journalctl_filter:
  - _SYSTEMD_UNIT=headscale.service
labels:
  type: headscale
---
journalctl_filter:
  - _SYSTEMD_UNIT=wg-quick@*.service
labels:
  type: wireguard
EOF

    # CrowdSec scenario for Headscale auth failures
    cat > "$OUTPUT_DIR/crowdsec/headscale-auth-bf.yaml" <<'EOF'
# CrowdSec scenario: Headscale authentication brute force
type: trigger
name: headscale/headscale-auth-bf
description: "Detect brute force on Headscale API"
filter: 'evt.Meta.log_type == "headscale" && evt.Meta.sub_log_type == "auth_failure"'
groupby: 'evt.Meta.source_ip'
distinct: 'evt.Meta.username'
reprocess: false
alerts:
  - meta:
      machine: headscale
      scenario: headscale-auth-bf
      source_ip: evt.Meta.source_ip
    expr: 'len(queue.Queue) >= 5'
blackhole: 2m
labels:
  type: scan
  severity: medium
  confidence: 3
  behavior: "http:bruteforce"
EOF

    # CrowdSec bouncer for WireGuard
    cat > "$OUTPUT_DIR/crowdsec/wg-bouncer.sh" <<'BASHEOF'
#!/bin/bash
# CrowdSec bouncer for WireGuard
# Blocks IPs that trigger CrowdSec decisions by removing them from WireGuard peers

CSCLI="/usr/bin/cscli"
WG="/usr/bin/wg"

# Get active decisions from CrowdSec
decisions=$($CSCLI decisions list -o json 2>/dev/null)

# Parse and block IPs
echo "$decisions" | jq -r '.[].decisions[].ip // empty' | while read -r ip; do
    if [ -n "$ip" ]; then
        # Remove from WireGuard peers if present
        $WG show all peers | grep -q "$ip" && {
            $WG set wg0 peer "$($WG show wg0 peers | grep -B1 "$ip" | head -1)" remove
            echo "Blocked $ip on WireGuard"
        }
    fi
done
BASHEOF
    chmod +x "$OUTPUT_DIR/crowdsec/wg-bouncer.sh"

    cat > "$OUTPUT_DIR/crowdsec/README.md" <<'EOF'
# CrowdSec Integration for Zero Trust Network

## Overview
Integrates CrowdSec threat detection with Headscale/WireGuard for automated blocking.

## Components
1. **acquis.yaml** — Log acquisition for Headscale and WireGuard logs
2. **headscale-auth-bf.yaml** — Brute force detection scenario
3. **wg-bouncer.sh** — WireGuard bouncer (removes blocked IPs from peers)

## Deployment
1. Copy acquis.yaml content to /etc/crowdsec/acquis.yaml (append)
2. Copy headscale-auth-bf.yaml to /etc/crowdsec/scenarios/
3. Copy wg-bouncer.sh to /usr/local/bin/ and add to cron:
   ```
   * * * * * /usr/local/bin/wg-bouncer.sh
   ```
4. Restart CrowdSec: `systemctl restart crowdsec`
EOF

    echo -e "${C_OK}CrowdSec 集成配置已生成到: $OUTPUT_DIR/crowdsec/${C_RST}"
}

# ── GeoIP 过滤配置 ───────────────────────────────────────────
generate_geoip_config() {
    echo -e "${C_WARN}>>> 生成 GeoIP 过滤配置 <<<${C_RST}"
    mkdir -p "$OUTPUT_DIR/geoip"

    # GeoIP-based ACL extension
    cat > "$OUTPUT_DIR/geoip/geoip-filter.sh" <<'BASHEOF'
#!/bin/bash
# GeoIP filter for WireGuard / Headscale
# Only allows connections from specified countries

ALLOWED_COUNTRIES="US,CA,GB,DE,JP"
MAXMIND_DB="/etc/geoip/GeoLite2-Country.mmdb"
WG="/usr/bin/wg"

# Check if mmdblookup is available
if ! command -v mmdblookup >/dev/null 2>&1; then
    echo "mmdblookup not found. Install: apt install mmdb-bin"
    exit 1
fi

# Check each peer's endpoint IP
$WG show all endpoints | while read -r peer ip; do
    ip_only=$(echo "$ip" | cut -d: -f1)
    country=$(mmdblookup --file "$MAXMIND_DB" --ip "$ip_only" country iso_code 2>/dev/null | tr -d ' "')

    if [ -n "$country" ]; then
        if echo ",$ALLOWED_COUNTRIES," | grep -q ",$country,"; then
            echo "ALLOW $ip_only ($country) — peer $peer"
        else
            echo "DENY $ip_only ($country) — peer $peer"
            # Optionally remove peer: $WG set wg0 peer "$peer" remove
        fi
    fi
done
BASHEOF
    chmod +x "$OUTPUT_DIR/geoip/geoip-filter.sh"

    cat > "$OUTPUT_DIR/geoip/README.md" <<'EOF'
# GeoIP Filtering for Zero Trust Network

## Overview
Adds country-level IP filtering to the WireGuard/Headscale mesh network.

## Prerequisites
- MaxMind GeoLite2 Country database (free)
- `mmdb-bin` package (mmdblookup)

## Setup
1. Get GeoLite2 database:
   ```
   # Sign up at https://www.maxmind.com (free account)
   # Download GeoLite2-Country.mmdb
   sudo mkdir -p /etc/geoip
   sudo cp GeoLite2-Country.mmdb /etc/geoip/
   ```
2. Install mmdblookup:
   ```
   sudo apt install mmdb-bin  # Debian/Ubuntu
   sudo yum install mmdb-bin  # RHEL/CentOS
   ```
3. Edit ALLOWED_COUNTRIES in geoip-filter.sh
4. Add to cron:
   ```
   */5 * * * * /usr/local/bin/geoip-filter.sh >> /var/log/geoip-filter.log
   ```

## Notes
- GeoIP filtering is a defense-in-depth measure, not a complete solution
- VPN/proxy users can bypass country restrictions
- Combine with CrowdSec for behavioral detection
EOF

    echo -e "${C_OK}GeoIP 过滤配置已生成到: $OUTPUT_DIR/geoip/${C_RST}"
}

# ── 审计模式 ─────────────────────────────────────────────────
audit_zerotrust() {
    echo -e "${C_WARN}>>> 零信任网络审计 <<<${C_RST}"
    echo -e "${C_INFO}只读模式, 不修改任何配置${C_RST}"
    echo ""

    init_report

    echo -e "${C_INFO}── WireGuard 检查 ──${C_RST}"

    run_check "WG-1.1" "WireGuard 已安装" \
        command -v wg

    run_check "WG-1.2" "WireGuard 内核模块已加载" \
        bash -c "lsmod | grep -q wireguard && echo 'module loaded' && return 0 || modprobe wireguard 2>/dev/null && echo 'module loaded after modprobe' && return 0 || echo 'module not loaded' && return 2"

    run_check "WG-1.3" "WireGuard 接口已启动" \
        bash -c "ip link show wg0 2>/dev/null | grep -q 'UP' && echo 'wg0 is UP' && return 0 || echo 'wg0 not found or down' && return 2"

    run_check "WG-1.4" "IP 转发已启用" \
        bash -c "sysctl net.ipv4.ip_forward 2>/dev/null | grep -q '=1' && echo 'ip_forward enabled' && return 0 || echo 'ip_forward disabled' && return 1"

    run_check "WG-1.5" "WireGuard 配置文件权限" \
        bash -c "find /etc/wireguard -name '*.conf' -perm 600 2>/dev/null | head -1 | grep -q . && echo 'config files are 600' && return 0 || echo 'no 600 config found' && return 2"

    echo ""
    echo -e "${C_INFO}── Headscale 检查 ──${C_RST}"

    run_check "HS-2.1" "Headscale 已安装" \
        command -v headscale

    run_check "HS-2.2" "Headscale 服务运行中" \
        bash -c "systemctl is-active headscale 2>/dev/null | grep -q active && echo 'service active' && return 0 || echo 'service not active' && return 2"

    run_check "HS-2.3" "Headscale 配置文件存在" \
        bash -c "[ -f /etc/headscale/config.yaml ] && echo 'config exists' && return 0 || echo 'config not found' && return 2"

    run_check "HS-2.4" "Headscale ACL 已配置" \
        bash -c "grep -q 'acl_path' /etc/headscale/config.yaml 2>/dev/null && echo 'ACL configured' && return 0 || echo 'ACL not configured' && return 2"

    run_check "HS-2.5" "Headscale 监听 127.0.0.1" \
        bash -c "grep -q '127.0.0.1' /etc/headscale/config.yaml 2>/dev/null && echo 'listening on localhost' && return 0 || echo 'may be listening on all interfaces' && return 2"

    echo ""
    echo -e "${C_INFO}── CrowdSec 集成检查 ──${C_RST}"

    run_check "CS-3.1" "CrowdSec 已安装" \
        command -v cscli

    run_check "CS-3.2" "Headscale 日志采集已配置" \
        bash -c "grep -q 'headscale' /etc/crowdsec/acquis.yaml 2>/dev/null && echo 'headscale acquisition configured' && return 0 || echo 'headscale acquisition not configured' && return 2"

    run_check "CS-3.3" "WireGuard 日志采集已配置" \
        bash -c "grep -q 'wireguard' /etc/crowdsec/acquis.yaml 2>/dev/null && echo 'wireguard acquisition configured' && return 0 || echo 'wireguard acquisition not configured' && return 2"

    echo ""
    echo -e "${C_INFO}── 网络安全检查 ──${C_RST}"

    run_check "NET-4.1" "WireGuard 使用非默认端口" \
        bash -c "port=\$(grep -oP 'ListenPort\s*=\s*\K\d+' /etc/wireguard/wg0.conf 2>/dev/null || echo '51820'); [ \"\$port\" != '51820' ] && echo \"port: \$port\" && return 0 || echo 'using default port 51820' && return 2"

    run_check "NET-4.2" "WireGuard 私钥权限正确" \
        bash -c "find /etc/wireguard -name '*.conf' -perm 600 2>/dev/null | head -1 | grep -q . && echo 'private key files are 600' && return 0 || echo 'private key files may be world-readable' && return 1"

    run_check "NET-4.3" "Headscale 使用 TLS" \
        bash -c "grep -q 'tls_letsencrypt' /etc/headscale/config.yaml 2>/dev/null && echo 'TLS configured' && return 0 || echo 'TLS not configured' && return 2"

    # 摘要
    echo ""
    echo -e "${C_INFO}╔══════════════════════════════════════════╗${C_RST}"
    echo -e "${C_INFO}║  Zero Trust Audit Summary                  ║${C_RST}"
    echo -e "${C_INFO}╚══════════════════════════════════════════╝${C_RST}"
    echo ""
    printf "  ${C_OK}PASS${C_RST}: %d\n" "$COUNT_PASS"
    printf "  ${C_FAIL}FAIL${C_RST}: %d\n" "$COUNT_FAIL"
    printf "  ${C_WARN}WARN${C_RST}: %d\n" "$COUNT_WARN"
    printf "  ${C_INFO}SKIP${C_RST}: %d\n" "$COUNT_SKIP"
    printf "  Total: %d\n" "$TOTAL_CHECKS"
    echo ""
    echo -e "报告: $REPORT_FILE"
}

# ── 交互式模式 ───────────────────────────────────────────────
interactive_mode() {
    echo -e "${C_INFO}╔══════════════════════════════════════════╗${C_RST}"
    echo -e "${C_INFO}║  Zero Trust Network Setup Wizard           ║${C_RST}"
    echo -e "${C_INFO}║  $APP_NAME $APP_VER                          ║${C_RST}"
    echo -e "${C_INFO}╚══════════════════════════════════════════╝${C_RST}"
    echo ""

    echo -e "${C_INFO}选择操作:${C_RST}"
    echo -e "  ${C_WARN}1.${C_RST} 安装 WireGuard"
    echo -e "  ${C_WARN}2.${C_RST} 安装 Headscale"
    echo -e "  ${C_WARN}3.${C_RST} 生成 ACL 配置"
    echo -e "  ${C_WARN}4.${C_RST} 生成 CrowdSec 集成配置"
    echo -e "  ${C_WARN}5.${C_RST} 生成 GeoIP 过滤配置"
    echo -e "  ${C_WARN}6.${C_RST} 审计现有零信任配置 (只读)"
    echo -e "  ${C_WARN}0.${C_RST} 退出"
    echo ""
    local pick
    read -r -p "❯ 选择 [0-6]: " pick
    case $pick in
        1) install_wireguard ;;
        2) install_headscale ;;
        3) generate_acl_config ;;
        4) generate_crowdsec_config ;;
        5) generate_geoip_config ;;
        6) audit_zerotrust || true ;;
        0) echo "退出"; exit 0 ;;
        *) echo -e "${C_FAIL}无效输入${C_RST}"; exit 1 ;;
    esac
}

# ── 主流程 ───────────────────────────────────────────────────
main() {
    parse_args "$@"

    case "$MODE" in
        install-wg) install_wireguard ;;
        install-hs) install_headscale ;;
        acl) generate_acl_config ;;
        crowdsec) generate_crowdsec_config ;;
        geoip) generate_geoip_config ;;
        audit) audit_zerotrust || true ;;
        interactive) interactive_mode || true ;;
        *) echo "未知模式: $MODE"; exit 1 ;;
    esac
    return 0
}

main "$@"
