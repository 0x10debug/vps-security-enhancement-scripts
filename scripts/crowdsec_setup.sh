#!/bin/bash
# ════════════════════════════════════════════════════════════
#  crowdsec_setup.sh — CrowdSec Deployment & Intrusion Prevention
#  Supported OS: Linux host (Ubuntu/Debian/CentOS/AlmaLinux/Rocky)
#  Run as: root
#  Mode: Install + scenario config + Bouncer deployment + alerts + audit (read-only)
#  Reference: crowdsecurity/crowdsec
#         crowdsecurity/cs-nginx-bouncer
#         crowdsecurity/cs-cloudflare-bouncer
#  Project home: https://github.com/0x10debug/vps-security-enhancement-scripts
# ════════════════════════════════════════════════════════════
#
# Usage:
#   sudo ./scripts/crowdsec_setup.sh                    # Interactive wizard
#   sudo ./scripts/crowdsec_setup.sh --install          # Install CrowdSec
#   sudo ./scripts/crowdsec_setup.sh --scenarios        # Configure detection scenarios
#   sudo ./scripts/crowdsec_setup.sh --bouncer          # Deploy bouncer (requires --bouncer-type)
#   sudo ./scripts/crowdsec_setup.sh --alerts           # Configure alerts (requires --alert-type)
#   sudo ./scripts/crowdsec_setup.sh --hub              # Update hub + manage collections
#   sudo ./scripts/crowdsec_setup.sh --status           # View running status
#   sudo ./scripts/crowdsec_setup.sh --logs             # View logs
#   sudo ./scripts/crowdsec_setup.sh --uninstall        # Uninstall CrowdSec
#   sudo ./scripts/crowdsec_setup.sh --audit            # Read-only audit CrowdSec config
#   sudo ./scripts/crowdsec_setup.sh --bouncer-type iptables|nginx|cloudflare
#   sudo ./scripts/crowdsec_setup.sh --alert-type email|webhook|slack|discord
#   sudo ./scripts/crowdsec_setup.sh --output ./crowdsec-configs
#
# Exit codes:
#   0 — Success
#   1 — Parameter error / missing dependency
#   2 — Some features unavailable

set -euo pipefail

APP_NAME="crowdsec_setup"
APP_VER="v3.2.0"
MODE=""
OUTPUT_DIR=""
BOUNCER_TYPE=""
ALERT_TYPE=""
REPORT_DIR="/var/log/crowdsec-audit"
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

# ── Parameter parsing ─────────────────────────────────────────────────
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --install) MODE="install"; shift ;;
            --scenarios) MODE="scenarios"; shift ;;
            --bouncer) MODE="bouncer"; shift ;;
            --alerts) MODE="alerts"; shift ;;
            --hub) MODE="hub"; shift ;;
            --status) MODE="status"; shift ;;
            --logs) MODE="logs"; shift ;;
            --uninstall) MODE="uninstall"; shift ;;
            --audit) MODE="audit"; shift ;;
            --bouncer-type) BOUNCER_TYPE="$2"; shift 2 ;;
            --alert-type) ALERT_TYPE="$2"; shift 2 ;;
            --output) OUTPUT_DIR="$2"; shift 2 ;;
            -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
            *) echo "Unknown parameter: $1"; exit 1 ;;
        esac
    done
    if [ -z "$MODE" ]; then
        MODE="interactive"
    fi
    if [ -z "$OUTPUT_DIR" ]; then
        OUTPUT_DIR="./crowdsec-configs"
    fi
}

# ── Report initialization ───────────────────────────────────────────────
init_report() {
    mkdir -p "$REPORT_DIR" 2>/dev/null || REPORT_DIR="/tmp/crowdsec-audit"
    mkdir -p "$REPORT_DIR" 2>/dev/null || true
    REPORT_FILE="$REPORT_DIR/crowdsec-audit-${TIMESTAMP}.txt"
    {
        echo "CrowdSec Deployment Audit Report"
        echo "================================="
        echo "Date: $(date)"
        echo "Host: $(hostname 2>/dev/null || echo 'N/A')"
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
        echo -e "${C_FAIL}Please run as root${C_RST}"
        exit 1
    fi
}

check_cmd() {
    command -v "$1" >/dev/null 2>&1
}

check_cscli() {
    check_cmd cscli
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

ask_yes() {
    local prompt="$1"
    local reply
    read -r -p "$prompt [y/N]: " reply
    case "$reply" in
        y|Y|yes|YES) return 0 ;;
        *) return 1 ;;
    esac
}

detect_distro() {
    if [ -f /etc/os-release ]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        echo "$ID"
    else
        echo "unknown"
    fi
}

# ── CrowdSec installation ─────────────────────────────────────────────
install_crowdsec() {
    echo -e "${C_WARN}>>> Install CrowdSec <<<${C_RST}"

    if check_cscli; then
        echo -e "${C_INFO}CrowdSec Installed, Attempting upgrade...${C_RST}"
        cscli hub update 2>/dev/null || true
        cscli hub upgrade 2>/dev/null || true
        echo -e "${C_OK}CrowdSec is up to date${C_RST}"
        return 0
    fi

    local distro
    distro=$(detect_distro)
    echo -e "${C_INFO}Detected distribution: $distro${C_RST}"

    echo -e "${C_INFO}[1/2] Try official install script...${C_RST}"
    local install_script="/tmp/crowdsec-install.sh"
    if curl -fsSL https://raw.githubusercontent.com/crowdsecurity/crowdsec/master/scripts/install.sh \
        -o "$install_script" 2>/dev/null; then
        bash "$install_script" 2>&1 | tail -20
        rm -f "$install_script"
        if check_cscli; then
            echo -e "${C_OK}CrowdSec installed successfully (official script)${C_RST}"
            post_install_info
            return 0
        fi
        echo -e "${C_WARN}Official script failed, trying manual package manager install...${C_RST}"
    else
        echo -e "${C_WARN}Cannot download official script, trying manual package manager install...${C_RST}"
    fi

    echo -e "${C_INFO}[2/2] Manual package manager install...${C_RST}"
    case "$distro" in
        ubuntu|debian)
            install_debian
            ;;
        centos|rhel|almalinux|rocky|fedora)
            install_rhel
            ;;
        *)
            echo -e "${C_FAIL}Unsupported distribution: $distro${C_RST}"
            echo -e "${C_INFO}Please refer manually: https://docs.crowdsec.net/docs/getting_started/installation/${C_RST}"
            return 1
            ;;
    esac

    if check_cscli; then
        echo -e "${C_OK}CrowdSec installed successfully (package manager)${C_RST}"
        post_install_info
    else
        echo -e "${C_FAIL}CrowdSec installation failed, please troubleshoot manually${C_RST}"
        echo -e "${C_INFO}Documentation: https://docs.crowdsec.net/docs/getting_started/installation/${C_RST}"
        return 1
    fi
}

install_debian() {
    curl -fsSL https://packagecloud.io/crowdsec/crowdsec/gpgkey \
        -o /tmp/crowdsec-gpgkey 2>/dev/null || true
    apt-get update -qq
    apt-get install -y -qq crowdsec 2>&1 | tail -10 || {
        echo -e "${C_INFO}Trying to add CrowdSec repository...${C_RST}"
        apt-get install -y -qq gnupg 2>/dev/null || true
        curl -fsSL https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh \
            -o /tmp/crowdsec-repo.sh 2>/dev/null
        bash /tmp/crowdsec-repo.sh 2>&1 | tail -5
        rm -f /tmp/crowdsec-repo.sh
        apt-get update -qq
        apt-get install -y -qq crowdsec 2>&1 | tail -10
    }
}

install_rhel() {
    yum install -y -q crowdsec 2>&1 | tail -10 || {
        echo -e "${C_INFO}Trying to add CrowdSec repository...${C_RST}"
        curl -fsSL https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.rpm.sh \
            -o /tmp/crowdsec-repo.sh 2>/dev/null
        bash /tmp/crowdsec-repo.sh 2>&1 | tail -5
        rm -f /tmp/crowdsec-repo.sh
        yum install -y -q crowdsec 2>&1 | tail -10
    }
}

post_install_info() {
    echo ""
    echo -e "${C_INFO}── Installation info ──${C_RST}"
    systemctl enable crowdsec 2>/dev/null || true
    systemctl start crowdsec 2>/dev/null || true
    echo -e "${C_INFO}Version: $(cscli version 2>/dev/null || echo 'unknown')${C_RST}"
    echo -e "${C_INFO}Common commands:${C_RST}"
    echo -e "  ${C_WARN}cscli metrics${C_RST}        — View detection metrics"
    echo -e "  ${C_WARN}cscli decisions list${C_RST}  — View block list"
    echo -e "  ${C_WARN}cscli alerts list${C_RST}     — View alerts"
    echo -e "  ${C_WARN}cscli bouncers list${C_RST}   — View bouncers"
    echo -e "${C_INFO}Suggested next steps:${C_RST}"
    echo -e "  ${C_WARN}--scenarios${C_RST}  Configure detection scenarios"
    echo -e "  ${C_WARN}--bouncer${C_RST}    Deploy block bouncer"
    echo -e "  ${C_WARN}--alerts${C_RST}     Configure alert notifications"
}

# ── Scenario config ──────────────────────────────────────────────────
configure_scenarios() {
    echo -e "${C_WARN}>>> Configure detection scenarios <<<${C_RST}"

    if ! check_cscli; then
        echo -e "${C_FAIL}CrowdSec not installed, please run first --install${C_RST}"
        return 1
    fi

    echo -e "${C_INFO}Updating CrowdSec Hub...${C_RST}"
    cscli hub update 2>&1 | tail -5 || true
    cscli hub upgrade 2>&1 | tail -5 || true

    echo ""
    echo -e "${C_INFO}── Recommended scenario collections ──${C_RST}"

    local collections=(
        "crowdsecurity/sshd"
        "crowdsecurity/ssh-slow-bf"
        "crowdsecurity/http-cve"
        "crowdsecurity/http-probing"
        "crowdsecurity/http-bad-user-agent"
        "crowdsecurity/http-sensitive-files"
        "crowdsecurity/whitelist-good-actors"
        "crowdsecurity/nfx"
        "crowdsecurity/iptables-logs"
        "crowdsecurity/linux"
    )

    echo "  1) SSH brute-force          crowdsecurity/sshd"
    echo "  2) SSH slow brute-force          crowdsecurity/ssh-slow-bf"
    echo "  3) Web CVE exploitation      crowdsecurity/http-cve"
    echo "  4) Web probing scan          crowdsecurity/http-probing"
    echo "  5) Malicious User-Agent       crowdsecurity/http-bad-user-agent"
    echo "  6) Sensitive file access          crowdsecurity/http-sensitive-files"
    echo "  7) Whitelist good actors          crowdsecurity/whitelist-good-actors"
    echo "  8) Network firewall logs        crowdsecurity/nfx"
    echo "  9) iptables logs         crowdsecurity/iptables-logs"
    echo " 10) Linux system scenarios        crowdsecurity/linux"
    echo ""
    echo -e "${C_INFO}Will install all recommended scenarios above (already installed will be skipped)${C_RST}"
    if ! ask_yes "Continue installation?"; then
        return 0
    fi

    local installed=0 skipped=0 failed=0
    for col in "${collections[@]}"; do
        if cscli collections list -o raw 2>/dev/null | grep -q "^${col}$"; then
            echo -e "  ${C_INFO}SKIP${C_RST} $col (Installed)"
            skipped=$((skipped + 1))
        elif cscli collections install "$col" >/dev/null 2>&1; then
            echo -e "  ${C_OK}OK${C_RST}   $col"
            installed=$((installed + 1))
        else
            echo -e "  ${C_FAIL}FAIL${C_RST} $col"
            failed=$((failed + 1))
        fi
    done

    echo ""
    echo -e "${C_OK}Installed: $installed  Skipped: $skipped  Failed: $failed${C_RST}"

    echo ""
    echo -e "${C_INFO}── Currently installed scenario collections ──${C_RST}"
    cscli collections list 2>/dev/null || true

    echo ""
    echo -e "${C_INFO}Restarting CrowdSec to load new scenarios...${C_RST}"
    systemctl restart crowdsec 2>/dev/null || true
    echo -e "${C_OK}Scenario configuration complete${C_RST}"
}

# ── Bouncer deployment ──────────────────────────────────────────────
deploy_bouncer() {
    echo -e "${C_WARN}>>> Deploy Bouncer <<<${C_RST}"

    if ! check_cscli; then
        echo -e "${C_FAIL}CrowdSec not installed, please run first --install${C_RST}"
        return 1
    fi

    if [ -z "$BOUNCER_TYPE" ]; then
        echo "Bouncer type:"
        echo "  1) iptables    — System firewall block (recommended, universal)"
        echo "  2) nginx       — Nginx reverse proxy layer block"
        echo "  3) cloudflare  — Cloudflare API layer block (requires API token)"
        echo ""
        read -r -p "Select [1-3]: " bt
        case $bt in
            1) BOUNCER_TYPE="iptables" ;;
            2) BOUNCER_TYPE="nginx" ;;
            3) BOUNCER_TYPE="cloudflare" ;;
            *) echo -e "${C_FAIL}Invalid choice${C_RST}"; return 1 ;;
        esac
    fi

    case "$BOUNCER_TYPE" in
        iptables) deploy_iptables_bouncer ;;
        nginx) deploy_nginx_bouncer ;;
        cloudflare) deploy_cloudflare_bouncer ;;
        *)
            echo -e "${C_FAIL}Unknown bouncer type: $BOUNCER_TYPE${C_RST}"
            echo -e "${C_INFO}Optional: iptables | nginx | cloudflare${C_RST}"
            return 1
            ;;
    esac
}

deploy_iptables_bouncer() {
    echo -e "${C_INFO}── iptables Bouncer ──${C_RST}"
    echo -e "${C_INFO}Block malicious IPs at system firewall layer, universal and no reverse proxy needed${C_RST}"

    if cscli bouncers list -o raw 2>/dev/null | grep -q "iptables-bouncer"; then
        echo -e "${C_INFO}iptables bouncer Installed${C_RST}"
        if ask_yes "Reinstall/upgrade?"; then
            cscli bouncers delete iptables-bouncer 2>/dev/null || true
        else
            return 0
        fi
    fi

    if check_cmd apt-get; then
        apt-get install -y -qq crowdsec-firewall-bouncer-iptables 2>&1 | tail -10
    elif check_cmd yum; then
        yum install -y -q crowdsec-firewall-bouncer-iptables 2>&1 | tail -10
    else
        echo -e "${C_FAIL}Cannot find package manager (apt/yum)${C_RST}"
        return 1
    fi

    systemctl enable crowdsec-firewall-bouncer 2>/dev/null || true
    systemctl restart crowdsec-firewall-bouncer 2>/dev/null || true

    if systemctl is-active crowdsec-firewall-bouncer >/dev/null 2>&1; then
        echo -e "${C_OK}iptables bouncer deployed successfully${C_RST}"
    else
        echo -e "${C_WARN}bouncer service may not have started properly, please check:${C_RST}"
        echo -e "  systemctl status crowdsec-firewall-bouncer"
    fi
}

deploy_nginx_bouncer() {
    echo -e "${C_INFO}── Nginx Bouncer ──${C_RST}"
    echo -e "${C_INFO}Block at Nginx reverse proxy layer, suitable for environments with existing Nginx${C_RST}"

    if ! check_cmd nginx; then
        echo -e "${C_WARN}nginx not detected, please install Nginx first${C_RST}"
        if ! ask_yes "Continue installing bouncer (configure Nginx manually later)?"; then
            return 0
        fi
    fi

    if cscli bouncers list -o raw 2>/dev/null | grep -q "nginx-bouncer"; then
        echo -e "${C_INFO}nginx bouncer Installed${C_RST}"
        if ask_yes "Reinstall/upgrade?"; then
            cscli bouncers delete nginx-bouncer 2>/dev/null || true
        else
            return 0
        fi
    fi

    if check_cmd apt-get; then
        apt-get install -y -qq crowdsec-nginx-bouncer 2>&1 | tail -10
    elif check_cmd yum; then
        yum install -y -q crowdsec-nginx-bouncer 2>&1 | tail -10
    else
        echo -e "${C_FAIL}Cannot find package manager (apt/yum)${C_RST}"
        return 1
    fi

    systemctl enable crowdsec-nginx-bouncer 2>/dev/null || true
    systemctl restart crowdsec-nginx-bouncer 2>/dev/null || true

    echo -e "${C_OK}nginx bouncer deployment complete${C_RST}"
    echo -e "${C_INFO}Ensure bouncer module is loaded in Nginx config:${C_RST}"
    echo -e "  ${C_WARN}load_module modules/ngx_http_crowdsec_module.so;${C_RST}"
    echo -e "${C_INFO}And enable in server block:${C_RST}"
    echo -e "  ${C_WARN}crowdsec on;${C_RST}"
    echo -e "  ${C_WARN}crowdsec_sanitize_urls on;${C_RST}"
}

deploy_cloudflare_bouncer() {
    echo -e "${C_INFO}── Cloudflare Bouncer ──${C_RST}"
    echo -e "${C_INFO}Block at edge layer via Cloudflare API, no local bandwidth consumed${C_RST}"

    if cscli bouncers list -o raw 2>/dev/null | grep -q "cloudflare-bouncer"; then
        echo -e "${C_INFO}cloudflare bouncer Installed${C_RST}"
        if ask_yes "Reinstall/upgrade?"; then
            cscli bouncers delete cloudflare-bouncer 2>/dev/null || true
        else
            return 0
        fi
    fi

    echo ""
    echo -e "${C_INFO}Requires Cloudflare API Token (permissions: Zone.Firewall Rules + Account)${C_RST}"
    echo -e "${C_INFO}Get: https://dash.cloudflare.com/profile/api-tokens${C_RST}"
    echo ""

    local cf_token cf_zone_id
    read -r -p "Cloudflare API Token: " cf_token
    if [ -z "$cf_token" ]; then
        echo -e "${C_FAIL}API Token cannot be empty${C_RST}"
        return 1
    fi
    read -r -p "Cloudflare Zone ID (optional, leave empty for auto-detection): " cf_zone_id

    mkdir -p "$OUTPUT_DIR"

    cat > "$OUTPUT_DIR/cloudflare-bouncer.yaml" <<EOF
# Cloudflare Bouncer config
# Generated by crowdsec_setup.sh
# Documentation: https://docs.crowdsec.net/docs/bouncers/cloudflare/

mode: live

cloudflare_config:
  api_token: "$cf_token"
  zone_id: "$cf_zone_id"
  # Action: challenge (CAPTCHA) or block (direct block)
  default_action: challenge
  # Polling interval (seconds)
  update_frequency: 10s

# Block duration
ban_action: challenge
EOF

    echo -e "${C_INFO}Config generated: $OUTPUT_DIR/cloudflare-bouncer.yaml${C_RST}"

    if check_cmd apt-get; then
        apt-get install -y -qq crowdsec-cloudflare-bouncer 2>&1 | tail -10 || true
    elif check_cmd yum; then
        yum install -y -q crowdsec-cloudflare-bouncer 2>&1 | tail -10 || true
    fi

    local cfg_path="/etc/crowdsec/bouncers/cloudflare.yaml"
    if [ -d /etc/crowdsec/bouncers ]; then
        cp "$OUTPUT_DIR/cloudflare-bouncer.yaml" "$cfg_path" 2>/dev/null || true
    fi

    echo -e "${C_OK}cloudflare bouncer config complete${C_RST}"
    echo -e "${C_WARN}Please check config: $cfg_path${C_RST}"
    echo -e "${C_INFO}Start: systemctl enable --now crowdsec-cloudflare-bouncer${C_RST}"
}

# ── Alert config ──────────────────────────────────────────────────
configure_alerts() {
    echo -e "${C_WARN}>>> Configure alert notifications <<<${C_RST}"

    if ! check_cscli; then
        echo -e "${C_FAIL}CrowdSec not installed, please run first --install${C_RST}"
        return 1
    fi

    if [ -z "$ALERT_TYPE" ]; then
        echo "Alert type:"
        echo "  1) email     — Email notification (requires SMTP)"
        echo "  2) webhook   — Generic Webhook (HTTP POST)"
        echo "  3) slack     — Slack notification"
        echo "  4) discord   — Discord notification"
        echo ""
        read -r -p "Select [1-4]: " at
        case $at in
            1) ALERT_TYPE="email" ;;
            2) ALERT_TYPE="webhook" ;;
            3) ALERT_TYPE="slack" ;;
            4) ALERT_TYPE="discord" ;;
            *) echo -e "${C_FAIL}Invalid choice${C_RST}"; return 1 ;;
        esac
    fi

    case "$ALERT_TYPE" in
        email) config_email_alert ;;
        webhook) config_webhook_alert ;;
        slack) config_slack_alert ;;
        discord) config_discord_alert ;;
        *)
            echo -e "${C_FAIL}Unknown alert type: $ALERT_TYPE${C_RST}"
            return 1
            ;;
    esac
}

config_email_alert() {
    echo -e "${C_INFO}── Email alert ──${C_RST}"

    local smtp_host smtp_port smtp_user smtp_pass mail_from mail_to
    read -r -p "SMTP server (e.g. smtp.gmail.com): " smtp_host
    read -r -p "SMTP port (e.g. 587): " smtp_port
    read -r -p "SMTP username: " smtp_user
    read -r -s -p "SMTP password: " smtp_pass
    echo ""
    read -r -p "From address: " mail_from
    read -r -p "To address: " mail_to

    mkdir -p "$OUTPUT_DIR"
    cat > "$OUTPUT_DIR/email-alert.yaml" <<EOF
# CrowdSec Email alert config
# Generated by crowdsec_setup.sh
# Documentation: https://docs.crowdsec.net/docs/notifications/email/

type: email
name: email_default
debug: false

smtp_host: "$smtp_host"
smtp_port: $smtp_port
smtp_username: "$smtp_user"
smtp_password: "$smtp_pass"
from: "$mail_from"
to: "$mail_to"
# Email subject template
subject: "CrowdSec alert: {{ .AlertsCount }} new alerts"
# Email body template
body: |
  CrowdSec detected {{ .AlertsCount }} new alerts:
  {{ range .Alerts }}
  - Scenario: {{ .Scenario }}
    IP: {{ .Source.IP }}
    Decisions: {{ range .Decisions }}{{ .Type }} {{ end }}
  {{ end }}
EOF

    echo -e "${C_OK}Email alertConfig generated: $OUTPUT_DIR/email-alert.yaml${C_RST}"
    install_alert_profile "$OUTPUT_DIR/email-alert.yaml" "email_default"
}

config_webhook_alert() {
    echo -e "${C_INFO}── Webhook alert ──${C_RST}"

    local hook_url
    read -r -p "Webhook URL: " hook_url
    if [ -z "$hook_url" ]; then
        echo -e "${C_FAIL}Webhook URL cannot be empty${C_RST}"
        return 1
    fi

    mkdir -p "$OUTPUT_DIR"
    # shellcheck disable=SC2154
    cat > "$OUTPUT_DIR/webhook-alert.yaml" <<'CROWDSEC_EOF'
# CrowdSec Webhook alert config
# Generated by crowdsec_setup.sh
# Documentation: https://docs.crowdsec.net/docs/notifications/webhook/

type: webhook
name: webhook_default
debug: false

url: "__HOOK_URL__"
method: POST
# Optional custom header
headers:
  Content-Type: application/json
# Request body template (JSON)
body: |
  {
    "text": "CrowdSec alert: {{ .AlertsCount }} new alerts",
    "alerts": [
      {{ range $i, $a := .Alerts }}{{ if $i }},{{ end }}
      {"scenario": "{{ $a.Scenario }}", "ip": "{{ $a.Source.IP }}"}
      {{ end }}
    ]
  }
CROWDSEC_EOF
    sed -i "s|__HOOK_URL__|$hook_url|g" "$OUTPUT_DIR/webhook-alert.yaml"

    echo -e "${C_OK}Webhook alertConfig generated: $OUTPUT_DIR/webhook-alert.yaml${C_RST}"
    install_alert_profile "$OUTPUT_DIR/webhook-alert.yaml" "webhook_default"
}

config_slack_alert() {
    echo -e "${C_INFO}── Slack alert ──${C_RST}"

    local slack_hook
    read -r -p "Slack Webhook URL (https://hooks.slack.com/services/...): " slack_hook
    if [ -z "$slack_hook" ]; then
        echo -e "${C_FAIL}Slack Webhook URL cannot be empty${C_RST}"
        return 1
    fi

    mkdir -p "$OUTPUT_DIR"
    cat > "$OUTPUT_DIR/slack-alert.yaml" <<EOF
# CrowdSec Slack alert config
# Generated by crowdsec_setup.sh
# Documentation: https://docs.crowdsec.net/docs/notifications/slack/

type: slack
name: slack_default
debug: false

webhook_url: "$slack_hook"
# Message template
message: |
  CrowdSec alert: {{ .AlertsCount }} new alerts
  {{ range .Alerts }}
  • Scenario: {{ .Scenario }} | IP: {{ .Source.IP }}
  {{ end }}
EOF

    echo -e "${C_OK}Slack alertConfig generated: $OUTPUT_DIR/slack-alert.yaml${C_RST}"
    install_alert_profile "$OUTPUT_DIR/slack-alert.yaml" "slack_default"
}

config_discord_alert() {
    echo -e "${C_INFO}── Discord alert ──${C_RST}"

    local discord_hook
    read -r -p "Discord Webhook URL (https://discord.com/api/webhooks/...): " discord_hook
    if [ -z "$discord_hook" ]; then
        echo -e "${C_FAIL}Discord Webhook URL cannot be empty${C_RST}"
        return 1
    fi

    mkdir -p "$OUTPUT_DIR"
    cat > "$OUTPUT_DIR/discord-alert.yaml" <<EOF
# CrowdSec Discord alert config
# Generated by crowdsec_setup.sh
# Documentation: https://docs.crowdsec.net/docs/notifications/discord/

type: discord
name: discord_default
debug: false

webhook_url: "$discord_hook"
# Message template
message: |
  CrowdSec alert: {{ .AlertsCount }} new alerts
  {{ range .Alerts }}
  • Scenario: {{ .Scenario }} | IP: {{ .Source.IP }}
  {{ end }}
EOF

    echo -e "${C_OK}Discord alertConfig generated: $OUTPUT_DIR/discord-alert.yaml${C_RST}"
    install_alert_profile "$OUTPUT_DIR/discord-alert.yaml" "discord_default"
}

install_alert_profile() {
    local cfg_file="$1" profile_name="$2"
    local dest_dir="/etc/crowdsec/notifications"
    if [ -d "$dest_dir" ]; then
        cp "$cfg_file" "$dest_dir/${profile_name}.yaml" 2>/dev/null || true
        cscli notifications reload 2>/dev/null || true
        echo -e "${C_INFO}Installed to $dest_dir/${profile_name}.yaml and reloaded${C_RST}"
    else
        echo -e "${C_WARN}Directory $dest_dir does not exist, config generated but not installed${C_RST}"
        echo -e "${C_INFO}Manually copy to $dest_dir/ then run: cscli notifications reload${C_RST}"
    fi
}

# ── Hub update and collection management ────────────────────────────────────────
manage_hub() {
    echo -e "${C_WARN}>>> Hub update and collection management <<<${C_RST}"

    if ! check_cscli; then
        echo -e "${C_FAIL}CrowdSec not installed, please run first --install${C_RST}"
        return 1
    fi

    echo -e "${C_INFO}[1/3] Updating Hub index...${C_RST}"
    cscli hub update 2>&1 | tail -5 || true

    echo ""
    echo -e "${C_INFO}[2/3] Upgrading installed collections...${C_RST}"
    cscli hub upgrade 2>&1 | tail -10 || true

    echo ""
    echo -e "${C_INFO}[3/3] Currently installed collections:${C_RST}"
    cscli collections list 2>/dev/null || true

    echo ""
    echo -e "${C_INFO}── Available collections (first 30) ──${C_RST}"
    cscli collections list -a 2>/dev/null | head -30 || true

    echo ""
    echo -e "${C_INFO}Management options:${C_RST}"
    echo "  1) Install specified collection"
    echo "  2) Delete specified collection"
    echo "  3) List all parsers"
    echo "  4) List all scenarios"
    echo "  0) Back"
    read -r -p "Select [0-4]: " hp
    case $hp in
        1)
            read -r -p "Collection name (e.g. crowdsecurity/sshd): " col_name
            cscli collections install "$col_name" 2>&1 || true
            systemctl restart crowdsec 2>/dev/null || true
            echo -e "${C_OK}Installed $col_name${C_RST}"
            ;;
        2)
            read -r -p "Collection name: " col_name
            cscli collections delete "$col_name" 2>&1 || true
            systemctl restart crowdsec 2>/dev/null || true
            echo -e "${C_OK}Deleted $col_name${C_RST}"
            ;;
        3) cscli parsers list 2>/dev/null || true ;;
        4) cscli scenarios list 2>/dev/null || true ;;
        0) return 0 ;;
        *) echo -e "${C_FAIL}Invalid choice${C_RST}" ;;
    esac
}

# ── Status view ──────────────────────────────────────────────────
show_status() {
    echo -e "${C_WARN}>>> CrowdSec status <<<${C_RST}"

    if ! check_cscli; then
        echo -e "${C_FAIL}CrowdSec Not installed${C_RST}"
        return 1
    fi

    echo -e "${C_INFO}── Service status ──${C_RST}"
    if systemctl is-active crowdsec >/dev/null 2>&1; then
        echo -e "${C_OK}crowdsec is running${C_RST}"
    else
        echo -e "${C_FAIL}crowdsec is not running${C_RST}"
    fi
    echo ""

    echo -e "${C_INFO}── Version ──${C_RST}"
    cscli version 2>/dev/null || echo -e "${C_WARN}Cannot get version${C_RST}"
    echo ""

    echo -e "${C_INFO}── Detection metrics ──${C_RST}"
    cscli metrics 2>/dev/null || echo -e "${C_WARN}Cannot get metrics${C_RST}"
    echo ""

    echo -e "${C_INFO}── Block decisions ──${C_RST}"
    cscli decisions list 2>/dev/null || echo -e "${C_WARN}No block decisions${C_RST}"
    echo ""

    echo -e "${C_INFO}── Alerts ──${C_RST}"
    cscli alerts list 2>/dev/null || echo -e "${C_WARN}No alerts${C_RST}"
    echo ""

    echo -e "${C_INFO}── Bouncer ──${C_RST}"
    cscli bouncers list 2>/dev/null || echo -e "${C_WARN}No bouncers${C_RST}"
    echo ""

    echo -e "${C_INFO}── Collections ──${C_RST}"
    cscli collections list 2>/dev/null || echo -e "${C_WARN}No collections${C_RST}"
    echo ""

    echo -e "${C_INFO}── Notifications ──${C_RST}"
    cscli notifications list 2>/dev/null || echo -e "${C_WARN}No notification config${C_RST}"
}

# ── Log view ──────────────────────────────────────────────────
show_logs() {
    echo -e "${C_WARN}>>> CrowdSec logs <<<${C_RST}"

    if ! check_cscli; then
        echo -e "${C_FAIL}CrowdSec Not installed${C_RST}"
        return 1
    fi

    echo "Log source:"
    echo "  1) crowdsec service log (journalctl)"
    echo "  2) crowdsec application log (/var/log/crowdsec.log)"
    echo "  3) bouncer log"
    echo "  4) Recent alert details"
    echo "  0) Back"
    read -r -p "Select [0-4]: " lp
    case $lp in
        1) journalctl -u crowdsec --no-pager -n 100 ;;
        2) tail -n 100 /var/log/crowdsec.log 2>/dev/null || echo -e "${C_WARN}Log file does not exist${C_RST}" ;;
        3)
            echo "Bouncer log:"
            for svc in crowdsec-firewall-bouncer crowdsec-nginx-bouncer crowdsec-cloudflare-bouncer; do
                if systemctl list-unit-files 2>/dev/null | grep -q "$svc"; then
                    echo -e "${C_INFO}── $svc ──${C_RST}"
                    journalctl -u "$svc" --no-pager -n 50 2>/dev/null || true
                fi
            done
            ;;
        4) cscli alerts list -o human 2>/dev/null | head -20 ;;
        0) return 0 ;;
        *) echo -e "${C_FAIL}Invalid choice${C_RST}" ;;
    esac
}

# ── Uninstall ──────────────────────────────────────────────────────
uninstall_crowdsec() {
    echo -e "${C_WARN}>>> Uninstall CrowdSec <<<${C_RST}"

    if ! check_cscli; then
        echo -e "${C_INFO}CrowdSec not installed, no need to uninstall${C_RST}"
        return 0
    fi

    echo -e "${C_FAIL}Warning: This will remove CrowdSec and all block decisions and config${C_RST}"
    if ! ask_yes "Confirm uninstall?"; then
        return 0
    fi
    if ! ask_yes "Confirm again? This operation is irreversible"; then
        return 0
    fi

    echo -e "${C_INFO}Stopping service...${C_RST}"
    systemctl stop crowdsec 2>/dev/null || true
    for svc in crowdsec-firewall-bouncer crowdsec-nginx-bouncer crowdsec-cloudflare-bouncer; do
        systemctl stop "$svc" 2>/dev/null || true
        systemctl disable "$svc" 2>/dev/null || true
    done

    echo -e "${C_INFO}Removing decisions (releasing blocked IPs)...${C_RST}"
    cscli decisions delete --all 2>/dev/null || true

    echo -e "${C_INFO}Uninstalling packages...${C_RST}"
    if check_cmd apt-get; then
        apt-get purge -y -qq crowdsec crowdsec-firewall-bouncer-iptables crowdsec-nginx-bouncer \
            crowdsec-cloudflare-bouncer 2>&1 | tail -10 || true
        apt-get autoremove -y -qq 2>&1 | tail -5 || true
    elif check_cmd yum; then
        yum remove -y -q crowdsec crowdsec-firewall-bouncer-iptables crowdsec-nginx-bouncer \
            crowdsec-cloudflare-bouncer 2>&1 | tail -10 || true
    fi

    echo -e "${C_INFO}Cleaning config directory...${C_RST}"
    rm -rf /etc/crowdsec /var/lib/crowdsec /var/log/crowdsec* 2>/dev/null || true

    echo -e "${C_OK}CrowdSec uninstalled${C_RST}"
}

# ── Read-only audit ──────────────────────────────────────────────────
audit_crowdsec() {
    echo -e "${C_WARN}>>> CrowdSec read-only audit <<<${C_RST}"
    echo -e "${C_INFO}Audit mode does not modify any config, only checks and generates report${C_RST}"
    echo ""

    init_report

    # CS-001: CrowdSec Installed
    run_check "CS-001" "CrowdSec installed (cscli available)" check_cscli

    # CS-002: crowdsec service is running
    run_check "CS-002" "crowdsec service is running" \
        bash -c 'systemctl is-active crowdsec >/dev/null 2>&1'

    # CS-003: crowdsec service auto-start enabled
    run_check "CS-003" "crowdsec service auto-start enabled" \
        bash -c 'systemctl is-enabled crowdsec >/dev/null 2>&1'

    # CS-004: Hub version is up to date
    if check_cscli; then
        run_check "CS-004" "CrowdSec Hub is up to date" \
            bash -c 'cscli hub list >/dev/null 2>&1'
    else
        run_check "CS-004" "CrowdSec Hub is up to date" bash -c 'exit 3'
    fi

    # CS-005: Installed scenario collection count
    if check_cscli; then
        local col_count
        col_count=$(cscli collections list -o raw 2>/dev/null | grep -c . || echo 0)
        if [ "$col_count" -gt 0 ]; then
            run_check "CS-005" "Installed $col_count scenario collections" true
        else
            run_check "CS-005" "No scenario collections installed" bash -c 'exit 1'
        fi
    else
        run_check "CS-005" "Scenario collection check" bash -c 'exit 3'
    fi

    # CS-006: SSH brute-force scenarioInstalled
    if check_cscli; then
        run_check "CS-006" "SSH brute-force scenario (crowdsecurity/sshd)" \
            bash -c 'cscli collections list -o raw 2>/dev/null | grep -q "^crowdsecurity/sshd$"'
    else
        run_check "CS-006" "SSH brute-force scenario" bash -c 'exit 3'
    fi

    # CS-007: At least one bouncer deployed
    if check_cscli; then
        local bouncer_count
        bouncer_count=$(cscli bouncers list -o raw 2>/dev/null | grep -c . || echo 0)
        if [ "$bouncer_count" -gt 0 ]; then
            run_check "CS-007" "$bouncer_count bouncers deployed" true
        else
            run_check "CS-007" "No bouncer deployed (blocking not effective)" bash -c 'exit 1'
        fi
    else
        run_check "CS-007" "Bouncer deployment check" bash -c 'exit 3'
    fi

    # CS-008: firewall bouncer is running
    run_check "CS-008" "firewall bouncer service is running" \
        bash -c 'systemctl is-active crowdsec-firewall-bouncer >/dev/null 2>&1 || systemctl is-active crowdsec-nginx-bouncer >/dev/null 2>&1 || systemctl is-active crowdsec-cloudflare-bouncer >/dev/null 2>&1'

    # CS-009: Current block decision count
    if check_cscli; then
        local dec_count
        dec_count=$(cscli decisions list -o raw 2>/dev/null | grep -c . || echo 0)
        if [ "$dec_count" -ge 0 ]; then
            run_check "CS-009" "Currently $dec_count block decisions" true
        fi
    else
        run_check "CS-009" "Block decision check" bash -c 'exit 3'
    fi

    # CS-010: Alert notifications configured
    if check_cscli; then
        local notif_count
        notif_count=$(cscli notifications list -o raw 2>/dev/null | grep -c . || echo 0)
        if [ "$notif_count" -gt 0 ]; then
            run_check "CS-010" "$notif_count alert notifications configured" true
        else
            run_check "CS-010" "No alert notifications configured (no real-time alerts)" bash -c 'exit 2'
        fi
    else
        run_check "CS-010" "Alert notification check" bash -c 'exit 3'
    fi

    # CS-011: Config file exists and is readable
    run_check "CS-011" "Config file /etc/crowdsec/config.yaml exists" \
        test -f /etc/crowdsec/config.yaml

    # CS-012: CrowdSec API port listening
    run_check "CS-012" "CrowdSec API port (8080) listening" \
        bash -c 'ss -tlnp 2>/dev/null | grep -q ":8080" || netstat -tlnp 2>/dev/null | grep -q ":8080"'

    # CS-013: LAPI port listening
    run_check "CS-013" "Local API port (8081) listening" \
        bash -c 'ss -tlnp 2>/dev/null | grep -q ":8081" || netstat -tlnp 2>/dev/null | grep -q ":8081"'

    # CS-014: Database file exists
    run_check "CS-014" "CrowdSec Database file exists" \
        test -f /var/lib/crowdsec/data/crowdsec.db

    # CS-015: Log file exists and is non-empty
    if [ -f /var/log/crowdsec.log ]; then
        run_check "CS-015" "CrowdSec log file exists" true
    else
        run_check "CS-015" "CrowdSec Log file does not exist" bash -c 'exit 2'
    fi

    print_summary
}

# ── Interactive wizard ────────────────────────────────────────────────
interactive_wizard() {
    while true; do
        clear
        echo -e "${C_OK}══════════════════════════════${C_RST}"
        echo -e "${C_OK}   CrowdSec deployment and intrusion blocking    ${C_RST}"
        echo -e "${C_OK}══════════════════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 📦 Install CrowdSec"
        echo -e "  ${C_WARN}2.${C_RST} 🎯 Configure detection scenarios"
        echo -e "  ${C_WARN}3.${C_RST} 🛡️ Deploy Bouncer (blocking)"
        echo -e "  ${C_WARN}4.${C_RST} 🔔 Configure alert notifications"
        echo -e "  ${C_WARN}5.${C_RST} 🔄 Hub update and collection management"
        echo -e "  ${C_WARN}6.${C_RST} 📊 View running status"
        echo -e "  ${C_WARN}7.${C_RST} 📜 View logs"
        echo -e "  ${C_WARN}8.${C_RST} 🛡️ Audit CrowdSec config (read-only)"
        echo -e "  ${C_WARN}9.${C_RST} ❌ Uninstall CrowdSec"
        echo -e "  ${C_WARN}0.${C_RST} Back"
        echo
        local pick
        read -r -p "Select [0-9]: " pick
        case $pick in
            1) install_crowdsec; wait_key ;;
            2) configure_scenarios; wait_key ;;
            3) deploy_bouncer; wait_key ;;
            4) configure_alerts; wait_key ;;
            5) manage_hub; wait_key ;;
            6) show_status; wait_key ;;
            7) show_logs; wait_key ;;
            8) audit_crowdsec; wait_key ;;
            9) uninstall_crowdsec; wait_key ;;
            0) break ;;
            *) echo -e "${C_FAIL}Invalid input${C_RST}"; sleep 1 ;;
        esac
    done
}

# ── Main entry ────────────────────────────────────────────────────
main() {
    parse_args "$@"

    case "$MODE" in
        install) check_root; install_crowdsec ;;
        scenarios) check_root; configure_scenarios ;;
        bouncer) check_root; deploy_bouncer ;;
        alerts) check_root; configure_alerts ;;
        hub) check_root; manage_hub ;;
        status) show_status ;;
        logs) show_logs ;;
        uninstall) check_root; uninstall_crowdsec ;;
        audit) audit_crowdsec ;;
        interactive) interactive_wizard ;;
        *) echo "Unknown mode: $MODE"; exit 1 ;;
    esac
}

main "$@"
