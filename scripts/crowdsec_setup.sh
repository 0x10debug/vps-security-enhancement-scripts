#!/bin/bash
# ════════════════════════════════════════════════════════════
#  crowdsec_setup.sh — CrowdSec Deployment & Intrusion Prevention
#  适用系统: Linux 主机 (Ubuntu/Debian/CentOS/AlmaLinux/Rocky)
#  运行身份: root
#  模式: 安装 + 场景配置 + Bouncer 部署 + 告警 + 审计 (只读)
#  参考: crowdsecurity/crowdsec
#         crowdsecurity/cs-nginx-bouncer
#         crowdsecurity/cs-cloudflare-bouncer
#  项目主页: https://github.com/0x10debug/vps-security-enhancement-scripts
# ════════════════════════════════════════════════════════════
#
# 用法:
#   sudo ./scripts/crowdsec_setup.sh                    # 交互式向导
#   sudo ./scripts/crowdsec_setup.sh --install          # 安装 CrowdSec
#   sudo ./scripts/crowdsec_setup.sh --scenarios        # 配置检测场景
#   sudo ./scripts/crowdsec_setup.sh --bouncer          # 部署 bouncer (需 --bouncer-type)
#   sudo ./scripts/crowdsec_setup.sh --alerts           # 配置告警 (需 --alert-type)
#   sudo ./scripts/crowdsec_setup.sh --hub              # 更新 hub + 管理集合
#   sudo ./scripts/crowdsec_setup.sh --status           # 查看运行状态
#   sudo ./scripts/crowdsec_setup.sh --logs             # 查看日志
#   sudo ./scripts/crowdsec_setup.sh --uninstall        # 卸载 CrowdSec
#   sudo ./scripts/crowdsec_setup.sh --audit            # 只读审计 CrowdSec 配置
#   sudo ./scripts/crowdsec_setup.sh --bouncer-type iptables|nginx|cloudflare
#   sudo ./scripts/crowdsec_setup.sh --alert-type email|webhook|slack|discord
#   sudo ./scripts/crowdsec_setup.sh --output ./crowdsec-configs
#
# 退出码:
#   0 — 成功
#   1 — 参数错误 / 依赖缺失
#   2 — 部分功能不可用

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

# ── 参数解析 ─────────────────────────────────────────────────
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
            *) echo "未知参数: $1"; exit 1 ;;
        esac
    done
    if [ -z "$MODE" ]; then
        MODE="interactive"
    fi
    if [ -z "$OUTPUT_DIR" ]; then
        OUTPUT_DIR="./crowdsec-configs"
    fi
}

# ── 报告初始化 ───────────────────────────────────────────────
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

# ── 工具函数 ─────────────────────────────────────────────────
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${C_FAIL}请以 root 身份运行${C_RST}"
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
    echo -e "${C_OK}  审计总结${C_RST}"
    echo -e "${C_OK}══════════════════════════════${C_RST}"
    printf "  ${C_OK}PASS${C_RST}: %d  ${C_FAIL}FAIL${C_RST}: %d  ${C_WARN}WARN${C_RST}: %d  ${C_INFO}SKIP${C_RST}: %d  Total: %d\n" \
        "$COUNT_PASS" "$COUNT_FAIL" "$COUNT_WARN" "$COUNT_SKIP" "$TOTAL_CHECKS"
    echo -e "  报告: ${C_INFO}${REPORT_FILE}${C_RST}"
}

wait_key() {
    echo ""
    read -r -p "按回车继续..." _
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

# ── CrowdSec 安装 ─────────────────────────────────────────────
install_crowdsec() {
    echo -e "${C_WARN}>>> 安装 CrowdSec <<<${C_RST}"

    if check_cscli; then
        echo -e "${C_INFO}CrowdSec 已安装, 尝试升级...${C_RST}"
        cscli hub update 2>/dev/null || true
        cscli hub upgrade 2>/dev/null || true
        echo -e "${C_OK}CrowdSec 已是最新${C_RST}"
        return 0
    fi

    local distro
    distro=$(detect_distro)
    echo -e "${C_INFO}检测到发行版: $distro${C_RST}"

    echo -e "${C_INFO}[1/2] 尝试官方安装脚本...${C_RST}"
    local install_script="/tmp/crowdsec-install.sh"
    if curl -fsSL https://raw.githubusercontent.com/crowdsecurity/crowdsec/master/scripts/install.sh \
        -o "$install_script" 2>/dev/null; then
        bash "$install_script" 2>&1 | tail -20
        rm -f "$install_script"
        if check_cscli; then
            echo -e "${C_OK}CrowdSec 安装成功 (官方脚本)${C_RST}"
            post_install_info
            return 0
        fi
        echo -e "${C_WARN}官方脚本未成功, 尝试包管理器手动安装...${C_RST}"
    else
        echo -e "${C_WARN}无法下载官方脚本, 尝试包管理器手动安装...${C_RST}"
    fi

    echo -e "${C_INFO}[2/2] 包管理器手动安装...${C_RST}"
    case "$distro" in
        ubuntu|debian)
            install_debian
            ;;
        centos|rhel|almalinux|rocky|fedora)
            install_rhel
            ;;
        *)
            echo -e "${C_FAIL}不支持的发行版: $distro${C_RST}"
            echo -e "${C_INFO}请手动参考: https://docs.crowdsec.net/docs/getting_started/installation/${C_RST}"
            return 1
            ;;
    esac

    if check_cscli; then
        echo -e "${C_OK}CrowdSec 安装成功 (包管理器)${C_RST}"
        post_install_info
    else
        echo -e "${C_FAIL}CrowdSec 安装失败, 请手动排查${C_RST}"
        echo -e "${C_INFO}文档: https://docs.crowdsec.net/docs/getting_started/installation/${C_RST}"
        return 1
    fi
}

install_debian() {
    curl -fsSL https://packagecloud.io/crowdsec/crowdsec/gpgkey \
        -o /tmp/crowdsec-gpgkey 2>/dev/null || true
    apt-get update -qq
    apt-get install -y -qq crowdsec 2>&1 | tail -10 || {
        echo -e "${C_INFO}尝试添加 CrowdSec 源...${C_RST}"
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
        echo -e "${C_INFO}尝试添加 CrowdSec 源...${C_RST}"
        curl -fsSL https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.rpm.sh \
            -o /tmp/crowdsec-repo.sh 2>/dev/null
        bash /tmp/crowdsec-repo.sh 2>&1 | tail -5
        rm -f /tmp/crowdsec-repo.sh
        yum install -y -q crowdsec 2>&1 | tail -10
    }
}

post_install_info() {
    echo ""
    echo -e "${C_INFO}── 安装信息 ──${C_RST}"
    systemctl enable crowdsec 2>/dev/null || true
    systemctl start crowdsec 2>/dev/null || true
    echo -e "${C_INFO}版本: $(cscli version 2>/dev/null || echo '未知')${C_RST}"
    echo -e "${C_INFO}常用命令:${C_RST}"
    echo -e "  ${C_WARN}cscli metrics${C_RST}        — 查看检测指标"
    echo -e "  ${C_WARN}cscli decisions list${C_RST}  — 查看封禁列表"
    echo -e "  ${C_WARN}cscli alerts list${C_RST}     — 查看告警"
    echo -e "  ${C_WARN}cscli bouncers list${C_RST}   — 查看 bouncer"
    echo -e "${C_INFO}建议下一步:${C_RST}"
    echo -e "  ${C_WARN}--scenarios${C_RST}  配置检测场景"
    echo -e "  ${C_WARN}--bouncer${C_RST}    部署封禁 bouncer"
    echo -e "  ${C_WARN}--alerts${C_RST}     配置告警通知"
}

# ── 场景配置 ──────────────────────────────────────────────────
configure_scenarios() {
    echo -e "${C_WARN}>>> 配置检测场景 <<<${C_RST}"

    if ! check_cscli; then
        echo -e "${C_FAIL}CrowdSec 未安装, 请先运行 --install${C_RST}"
        return 1
    fi

    echo -e "${C_INFO}更新 CrowdSec Hub...${C_RST}"
    cscli hub update 2>&1 | tail -5 || true
    cscli hub upgrade 2>&1 | tail -5 || true

    echo ""
    echo -e "${C_INFO}── 推荐场景集合 ──${C_RST}"

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

    echo "  1) SSH 暴力破解          crowdsecurity/sshd"
    echo "  2) SSH 慢速暴力          crowdsecurity/ssh-slow-bf"
    echo "  3) Web CVE 漏洞利用      crowdsecurity/http-cve"
    echo "  4) Web 探测扫描          crowdsecurity/http-probing"
    echo "  5) 恶意 User-Agent       crowdsecurity/http-bad-user-agent"
    echo "  6) 敏感文件访问          crowdsecurity/http-sensitive-files"
    echo "  7) 白名单好演员          crowdsecurity/whitelist-good-actors"
    echo "  8) 网络防火墙日志        crowdsecurity/nfx"
    echo "  9) iptables 日志         crowdsecurity/iptables-logs"
    echo " 10) Linux 系统场景        crowdsecurity/linux"
    echo ""
    echo -e "${C_INFO}将安装以上全部推荐场景 (已安装的会跳过)${C_RST}"
    if ! ask_yes "继续安装？"; then
        return 0
    fi

    local installed=0 skipped=0 failed=0
    for col in "${collections[@]}"; do
        if cscli collections list -o raw 2>/dev/null | grep -q "^${col}$"; then
            echo -e "  ${C_INFO}SKIP${C_RST} $col (已安装)"
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
    echo -e "${C_OK}已安装: $installed  跳过: $skipped  失败: $failed${C_RST}"

    echo ""
    echo -e "${C_INFO}── 当前已安装场景集合 ──${C_RST}"
    cscli collections list 2>/dev/null || true

    echo ""
    echo -e "${C_INFO}重启 CrowdSec 以加载新场景...${C_RST}"
    systemctl restart crowdsec 2>/dev/null || true
    echo -e "${C_OK}场景配置完成${C_RST}"
}

# ── Bouncer 部署 ──────────────────────────────────────────────
deploy_bouncer() {
    echo -e "${C_WARN}>>> 部署 Bouncer <<<${C_RST}"

    if ! check_cscli; then
        echo -e "${C_FAIL}CrowdSec 未安装, 请先运行 --install${C_RST}"
        return 1
    fi

    if [ -z "$BOUNCER_TYPE" ]; then
        echo "Bouncer 类型:"
        echo "  1) iptables    — 系统防火墙封禁 (推荐, 通用)"
        echo "  2) nginx       — Nginx 反代层封禁"
        echo "  3) cloudflare  — Cloudflare API 层封禁 (需 API token)"
        echo ""
        read -r -p "选择 [1-3]: " bt
        case $bt in
            1) BOUNCER_TYPE="iptables" ;;
            2) BOUNCER_TYPE="nginx" ;;
            3) BOUNCER_TYPE="cloudflare" ;;
            *) echo -e "${C_FAIL}无效选择${C_RST}"; return 1 ;;
        esac
    fi

    case "$BOUNCER_TYPE" in
        iptables) deploy_iptables_bouncer ;;
        nginx) deploy_nginx_bouncer ;;
        cloudflare) deploy_cloudflare_bouncer ;;
        *)
            echo -e "${C_FAIL}未知 bouncer 类型: $BOUNCER_TYPE${C_RST}"
            echo -e "${C_INFO}可选: iptables | nginx | cloudflare${C_RST}"
            return 1
            ;;
    esac
}

deploy_iptables_bouncer() {
    echo -e "${C_INFO}── iptables Bouncer ──${C_RST}"
    echo -e "${C_INFO}在系统防火墙层封禁恶意 IP, 通用且无需反代${C_RST}"

    if cscli bouncers list -o raw 2>/dev/null | grep -q "iptables-bouncer"; then
        echo -e "${C_INFO}iptables bouncer 已安装${C_RST}"
        if ask_yes "重新安装/升级？"; then
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
        echo -e "${C_FAIL}找不到包管理器 (apt/yum)${C_RST}"
        return 1
    fi

    systemctl enable crowdsec-firewall-bouncer 2>/dev/null || true
    systemctl restart crowdsec-firewall-bouncer 2>/dev/null || true

    if systemctl is-active crowdsec-firewall-bouncer >/dev/null 2>&1; then
        echo -e "${C_OK}iptables bouncer 部署成功${C_RST}"
    else
        echo -e "${C_WARN}bouncer 服务可能未正常启动, 请检查:${C_RST}"
        echo -e "  systemctl status crowdsec-firewall-bouncer"
    fi
}

deploy_nginx_bouncer() {
    echo -e "${C_INFO}── Nginx Bouncer ──${C_RST}"
    echo -e "${C_INFO}在 Nginx 反代层封禁, 适合已有 Nginx 的环境${C_RST}"

    if ! check_cmd nginx; then
        echo -e "${C_WARN}未检测到 nginx, 请先安装 Nginx${C_RST}"
        if ! ask_yes "继续安装 bouncer (稍后手动配置 Nginx)？"; then
            return 0
        fi
    fi

    if cscli bouncers list -o raw 2>/dev/null | grep -q "nginx-bouncer"; then
        echo -e "${C_INFO}nginx bouncer 已安装${C_RST}"
        if ask_yes "重新安装/升级？"; then
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
        echo -e "${C_FAIL}找不到包管理器 (apt/yum)${C_RST}"
        return 1
    fi

    systemctl enable crowdsec-nginx-bouncer 2>/dev/null || true
    systemctl restart crowdsec-nginx-bouncer 2>/dev/null || true

    echo -e "${C_OK}nginx bouncer 部署完成${C_RST}"
    echo -e "${C_INFO}确保 Nginx 配置中已加载 bouncer 模块:${C_RST}"
    echo -e "  ${C_WARN}load_module modules/ngx_http_crowdsec_module.so;${C_RST}"
    echo -e "${C_INFO}并在 server 块中启用:${C_RST}"
    echo -e "  ${C_WARN}crowdsec on;${C_RST}"
    echo -e "  ${C_WARN}crowdsec_sanitize_urls on;${C_RST}"
}

deploy_cloudflare_bouncer() {
    echo -e "${C_INFO}── Cloudflare Bouncer ──${C_RST}"
    echo -e "${C_INFO}通过 Cloudflare API 在边缘层封禁, 不消耗本地带宽${C_RST}"

    if cscli bouncers list -o raw 2>/dev/null | grep -q "cloudflare-bouncer"; then
        echo -e "${C_INFO}cloudflare bouncer 已安装${C_RST}"
        if ask_yes "重新安装/升级？"; then
            cscli bouncers delete cloudflare-bouncer 2>/dev/null || true
        else
            return 0
        fi
    fi

    echo ""
    echo -e "${C_INFO}需要 Cloudflare API Token (权限: Zone.Firewall Rules + Account)${C_RST}"
    echo -e "${C_INFO}获取: https://dash.cloudflare.com/profile/api-tokens${C_RST}"
    echo ""

    local cf_token cf_zone_id
    read -r -p "Cloudflare API Token: " cf_token
    if [ -z "$cf_token" ]; then
        echo -e "${C_FAIL}API Token 不能为空${C_RST}"
        return 1
    fi
    read -r -p "Cloudflare Zone ID (可选, 留空则自动检测): " cf_zone_id

    mkdir -p "$OUTPUT_DIR"

    cat > "$OUTPUT_DIR/cloudflare-bouncer.yaml" <<EOF
# Cloudflare Bouncer 配置
# Generated by crowdsec_setup.sh
# 文档: https://docs.crowdsec.net/docs/bouncers/cloudflare/

mode: live

cloudflare_config:
  api_token: "$cf_token"
  zone_id: "$cf_zone_id"
  # 动作: challenge (验证码) 或 block (直接封禁)
  default_action: challenge
  # 轮询间隔 (秒)
  update_frequency: 10s

# 封禁持续时间
ban_action: challenge
EOF

    echo -e "${C_INFO}配置已生成: $OUTPUT_DIR/cloudflare-bouncer.yaml${C_RST}"

    if check_cmd apt-get; then
        apt-get install -y -qq crowdsec-cloudflare-bouncer 2>&1 | tail -10 || true
    elif check_cmd yum; then
        yum install -y -q crowdsec-cloudflare-bouncer 2>&1 | tail -10 || true
    fi

    local cfg_path="/etc/crowdsec/bouncers/cloudflare.yaml"
    if [ -d /etc/crowdsec/bouncers ]; then
        cp "$OUTPUT_DIR/cloudflare-bouncer.yaml" "$cfg_path" 2>/dev/null || true
    fi

    echo -e "${C_OK}cloudflare bouncer 配置完成${C_RST}"
    echo -e "${C_WARN}请检查配置: $cfg_path${C_RST}"
    echo -e "${C_INFO}启动: systemctl enable --now crowdsec-cloudflare-bouncer${C_RST}"
}

# ── 告警配置 ──────────────────────────────────────────────────
configure_alerts() {
    echo -e "${C_WARN}>>> 配置告警通知 <<<${C_RST}"

    if ! check_cscli; then
        echo -e "${C_FAIL}CrowdSec 未安装, 请先运行 --install${C_RST}"
        return 1
    fi

    if [ -z "$ALERT_TYPE" ]; then
        echo "告警类型:"
        echo "  1) email     — 邮件通知 (需 SMTP)"
        echo "  2) webhook   — 通用 Webhook (HTTP POST)"
        echo "  3) slack     — Slack 通知"
        echo "  4) discord   — Discord 通知"
        echo ""
        read -r -p "选择 [1-4]: " at
        case $at in
            1) ALERT_TYPE="email" ;;
            2) ALERT_TYPE="webhook" ;;
            3) ALERT_TYPE="slack" ;;
            4) ALERT_TYPE="discord" ;;
            *) echo -e "${C_FAIL}无效选择${C_RST}"; return 1 ;;
        esac
    fi

    case "$ALERT_TYPE" in
        email) config_email_alert ;;
        webhook) config_webhook_alert ;;
        slack) config_slack_alert ;;
        discord) config_discord_alert ;;
        *)
            echo -e "${C_FAIL}未知告警类型: $ALERT_TYPE${C_RST}"
            return 1
            ;;
    esac
}

config_email_alert() {
    echo -e "${C_INFO}── 邮件告警 ──${C_RST}"

    local smtp_host smtp_port smtp_user smtp_pass mail_from mail_to
    read -r -p "SMTP 服务器 (如 smtp.gmail.com): " smtp_host
    read -r -p "SMTP 端口 (如 587): " smtp_port
    read -r -p "SMTP 用户名: " smtp_user
    read -r -s -p "SMTP 密码: " smtp_pass
    echo ""
    read -r -p "发件地址: " mail_from
    read -r -p "收件地址: " mail_to

    mkdir -p "$OUTPUT_DIR"
    cat > "$OUTPUT_DIR/email-alert.yaml" <<EOF
# CrowdSec 邮件告警配置
# Generated by crowdsec_setup.sh
# 文档: https://docs.crowdsec.net/docs/notifications/email/

type: email
name: email_default
debug: false

smtp_host: "$smtp_host"
smtp_port: $smtp_port
smtp_username: "$smtp_user"
smtp_password: "$smtp_pass"
from: "$mail_from"
to: "$mail_to"
# 邮件主题模板
subject: "CrowdSec 告警: {{ .AlertsCount }} 个新告警"
# 邮件正文模板
body: |
  CrowdSec 检测到 {{ .AlertsCount }} 个新告警:
  {{ range .Alerts }}
  - 场景: {{ .Scenario }}
    IP: {{ .Source.IP }}
    决策: {{ range .Decisions }}{{ .Type }} {{ end }}
  {{ end }}
EOF

    echo -e "${C_OK}邮件告警配置已生成: $OUTPUT_DIR/email-alert.yaml${C_RST}"
    install_alert_profile "$OUTPUT_DIR/email-alert.yaml" "email_default"
}

config_webhook_alert() {
    echo -e "${C_INFO}── Webhook 告警 ──${C_RST}"

    local hook_url
    read -r -p "Webhook URL: " hook_url
    if [ -z "$hook_url" ]; then
        echo -e "${C_FAIL}Webhook URL 不能为空${C_RST}"
        return 1
    fi

    mkdir -p "$OUTPUT_DIR"
    # shellcheck disable=SC2154
    cat > "$OUTPUT_DIR/webhook-alert.yaml" <<'CROWDSEC_EOF'
# CrowdSec Webhook 告警配置
# Generated by crowdsec_setup.sh
# 文档: https://docs.crowdsec.net/docs/notifications/webhook/

type: webhook
name: webhook_default
debug: false

url: "__HOOK_URL__"
method: POST
# 可选自定义 header
headers:
  Content-Type: application/json
# 请求体模板 (JSON)
body: |
  {
    "text": "CrowdSec 告警: {{ .AlertsCount }} 个新告警",
    "alerts": [
      {{ range $i, $a := .Alerts }}{{ if $i }},{{ end }}
      {"scenario": "{{ $a.Scenario }}", "ip": "{{ $a.Source.IP }}"}
      {{ end }}
    ]
  }
CROWDSEC_EOF
    sed -i "s|__HOOK_URL__|$hook_url|g" "$OUTPUT_DIR/webhook-alert.yaml"

    echo -e "${C_OK}Webhook 告警配置已生成: $OUTPUT_DIR/webhook-alert.yaml${C_RST}"
    install_alert_profile "$OUTPUT_DIR/webhook-alert.yaml" "webhook_default"
}

config_slack_alert() {
    echo -e "${C_INFO}── Slack 告警 ──${C_RST}"

    local slack_hook
    read -r -p "Slack Webhook URL (https://hooks.slack.com/services/...): " slack_hook
    if [ -z "$slack_hook" ]; then
        echo -e "${C_FAIL}Slack Webhook URL 不能为空${C_RST}"
        return 1
    fi

    mkdir -p "$OUTPUT_DIR"
    cat > "$OUTPUT_DIR/slack-alert.yaml" <<EOF
# CrowdSec Slack 告警配置
# Generated by crowdsec_setup.sh
# 文档: https://docs.crowdsec.net/docs/notifications/slack/

type: slack
name: slack_default
debug: false

webhook_url: "$slack_hook"
# 消息模板
message: |
  CrowdSec 告警: {{ .AlertsCount }} 个新告警
  {{ range .Alerts }}
  • 场景: {{ .Scenario }} | IP: {{ .Source.IP }}
  {{ end }}
EOF

    echo -e "${C_OK}Slack 告警配置已生成: $OUTPUT_DIR/slack-alert.yaml${C_RST}"
    install_alert_profile "$OUTPUT_DIR/slack-alert.yaml" "slack_default"
}

config_discord_alert() {
    echo -e "${C_INFO}── Discord 告警 ──${C_RST}"

    local discord_hook
    read -r -p "Discord Webhook URL (https://discord.com/api/webhooks/...): " discord_hook
    if [ -z "$discord_hook" ]; then
        echo -e "${C_FAIL}Discord Webhook URL 不能为空${C_RST}"
        return 1
    fi

    mkdir -p "$OUTPUT_DIR"
    cat > "$OUTPUT_DIR/discord-alert.yaml" <<EOF
# CrowdSec Discord 告警配置
# Generated by crowdsec_setup.sh
# 文档: https://docs.crowdsec.net/docs/notifications/discord/

type: discord
name: discord_default
debug: false

webhook_url: "$discord_hook"
# 消息模板
message: |
  CrowdSec 告警: {{ .AlertsCount }} 个新告警
  {{ range .Alerts }}
  • 场景: {{ .Scenario }} | IP: {{ .Source.IP }}
  {{ end }}
EOF

    echo -e "${C_OK}Discord 告警配置已生成: $OUTPUT_DIR/discord-alert.yaml${C_RST}"
    install_alert_profile "$OUTPUT_DIR/discord-alert.yaml" "discord_default"
}

install_alert_profile() {
    local cfg_file="$1" profile_name="$2"
    local dest_dir="/etc/crowdsec/notifications"
    if [ -d "$dest_dir" ]; then
        cp "$cfg_file" "$dest_dir/${profile_name}.yaml" 2>/dev/null || true
        cscli notifications reload 2>/dev/null || true
        echo -e "${C_INFO}已安装到 $dest_dir/${profile_name}.yaml 并重载${C_RST}"
    else
        echo -e "${C_WARN}目录 $dest_dir 不存在, 配置仅生成未安装${C_RST}"
        echo -e "${C_INFO}手动复制到 $dest_dir/ 后运行: cscli notifications reload${C_RST}"
    fi
}

# ── Hub 更新与集合管理 ────────────────────────────────────────
manage_hub() {
    echo -e "${C_WARN}>>> Hub 更新与集合管理 <<<${C_RST}"

    if ! check_cscli; then
        echo -e "${C_FAIL}CrowdSec 未安装, 请先运行 --install${C_RST}"
        return 1
    fi

    echo -e "${C_INFO}[1/3] 更新 Hub 索引...${C_RST}"
    cscli hub update 2>&1 | tail -5 || true

    echo ""
    echo -e "${C_INFO}[2/3] 升级已安装集合...${C_RST}"
    cscli hub upgrade 2>&1 | tail -10 || true

    echo ""
    echo -e "${C_INFO}[3/3] 当前已安装集合:${C_RST}"
    cscli collections list 2>/dev/null || true

    echo ""
    echo -e "${C_INFO}── 可用集合 (前 30 个) ──${C_RST}"
    cscli collections list -a 2>/dev/null | head -30 || true

    echo ""
    echo -e "${C_INFO}管理选项:${C_RST}"
    echo "  1) 安装指定集合"
    echo "  2) 删除指定集合"
    echo "  3) 列出所有解析器"
    echo "  4) 列出所有场景"
    echo "  0) 返回"
    read -r -p "选择 [0-4]: " hp
    case $hp in
        1)
            read -r -p "集合名称 (如 crowdsecurity/sshd): " col_name
            cscli collections install "$col_name" 2>&1 || true
            systemctl restart crowdsec 2>/dev/null || true
            echo -e "${C_OK}已安装 $col_name${C_RST}"
            ;;
        2)
            read -r -p "集合名称: " col_name
            cscli collections delete "$col_name" 2>&1 || true
            systemctl restart crowdsec 2>/dev/null || true
            echo -e "${C_OK}已删除 $col_name${C_RST}"
            ;;
        3) cscli parsers list 2>/dev/null || true ;;
        4) cscli scenarios list 2>/dev/null || true ;;
        0) return 0 ;;
        *) echo -e "${C_FAIL}无效选择${C_RST}" ;;
    esac
}

# ── 状态查看 ──────────────────────────────────────────────────
show_status() {
    echo -e "${C_WARN}>>> CrowdSec 状态 <<<${C_RST}"

    if ! check_cscli; then
        echo -e "${C_FAIL}CrowdSec 未安装${C_RST}"
        return 1
    fi

    echo -e "${C_INFO}── 服务状态 ──${C_RST}"
    if systemctl is-active crowdsec >/dev/null 2>&1; then
        echo -e "${C_OK}crowdsec 运行中${C_RST}"
    else
        echo -e "${C_FAIL}crowdsec 未运行${C_RST}"
    fi
    echo ""

    echo -e "${C_INFO}── 版本 ──${C_RST}"
    cscli version 2>/dev/null || echo -e "${C_WARN}无法获取版本${C_RST}"
    echo ""

    echo -e "${C_INFO}── 检测指标 ──${C_RST}"
    cscli metrics 2>/dev/null || echo -e "${C_WARN}无法获取指标${C_RST}"
    echo ""

    echo -e "${C_INFO}── 封禁决策 ──${C_RST}"
    cscli decisions list 2>/dev/null || echo -e "${C_WARN}无封禁决策${C_RST}"
    echo ""

    echo -e "${C_INFO}── 告警 ──${C_RST}"
    cscli alerts list 2>/dev/null || echo -e "${C_WARN}无告警${C_RST}"
    echo ""

    echo -e "${C_INFO}── Bouncer ──${C_RST}"
    cscli bouncers list 2>/dev/null || echo -e "${C_WARN}无 bouncer${C_RST}"
    echo ""

    echo -e "${C_INFO}── 集合 ──${C_RST}"
    cscli collections list 2>/dev/null || echo -e "${C_WARN}无集合${C_RST}"
    echo ""

    echo -e "${C_INFO}── 通知 ──${C_RST}"
    cscli notifications list 2>/dev/null || echo -e "${C_WARN}无通知配置${C_RST}"
}

# ── 日志查看 ──────────────────────────────────────────────────
show_logs() {
    echo -e "${C_WARN}>>> CrowdSec 日志 <<<${C_RST}"

    if ! check_cscli; then
        echo -e "${C_FAIL}CrowdSec 未安装${C_RST}"
        return 1
    fi

    echo "日志来源:"
    echo "  1) crowdsec 服务日志 (journalctl)"
    echo "  2) crowdsec 应用日志 (/var/log/crowdsec.log)"
    echo "  3) bouncer 日志"
    echo "  4) 最近告警详情"
    echo "  0) 返回"
    read -r -p "选择 [0-4]: " lp
    case $lp in
        1) journalctl -u crowdsec --no-pager -n 100 ;;
        2) tail -n 100 /var/log/crowdsec.log 2>/dev/null || echo -e "${C_WARN}日志文件不存在${C_RST}" ;;
        3)
            echo "Bouncer 日志:"
            for svc in crowdsec-firewall-bouncer crowdsec-nginx-bouncer crowdsec-cloudflare-bouncer; do
                if systemctl list-unit-files 2>/dev/null | grep -q "$svc"; then
                    echo -e "${C_INFO}── $svc ──${C_RST}"
                    journalctl -u "$svc" --no-pager -n 50 2>/dev/null || true
                fi
            done
            ;;
        4) cscli alerts list -o human 2>/dev/null | head -20 ;;
        0) return 0 ;;
        *) echo -e "${C_FAIL}无效选择${C_RST}" ;;
    esac
}

# ── 卸载 ──────────────────────────────────────────────────────
uninstall_crowdsec() {
    echo -e "${C_WARN}>>> 卸载 CrowdSec <<<${C_RST}"

    if ! check_cscli; then
        echo -e "${C_INFO}CrowdSec 未安装, 无需卸载${C_RST}"
        return 0
    fi

    echo -e "${C_FAIL}警告: 这将移除 CrowdSec 及所有封禁决策和配置${C_RST}"
    if ! ask_yes "确认卸载？"; then
        return 0
    fi
    if ! ask_yes "再次确认？此操作不可逆"; then
        return 0
    fi

    echo -e "${C_INFO}停止服务...${C_RST}"
    systemctl stop crowdsec 2>/dev/null || true
    for svc in crowdsec-firewall-bouncer crowdsec-nginx-bouncer crowdsec-cloudflare-bouncer; do
        systemctl stop "$svc" 2>/dev/null || true
        systemctl disable "$svc" 2>/dev/null || true
    done

    echo -e "${C_INFO}移除决策 (释放被封 IP)...${C_RST}"
    cscli decisions delete --all 2>/dev/null || true

    echo -e "${C_INFO}卸载软件包...${C_RST}"
    if check_cmd apt-get; then
        apt-get purge -y -qq crowdsec crowdsec-firewall-bouncer-iptables crowdsec-nginx-bouncer \
            crowdsec-cloudflare-bouncer 2>&1 | tail -10 || true
        apt-get autoremove -y -qq 2>&1 | tail -5 || true
    elif check_cmd yum; then
        yum remove -y -q crowdsec crowdsec-firewall-bouncer-iptables crowdsec-nginx-bouncer \
            crowdsec-cloudflare-bouncer 2>&1 | tail -10 || true
    fi

    echo -e "${C_INFO}清理配置目录...${C_RST}"
    rm -rf /etc/crowdsec /var/lib/crowdsec /var/log/crowdsec* 2>/dev/null || true

    echo -e "${C_OK}CrowdSec 已卸载${C_RST}"
}

# ── 只读审计 ──────────────────────────────────────────────────
audit_crowdsec() {
    echo -e "${C_WARN}>>> CrowdSec 只读审计 <<<${C_RST}"
    echo -e "${C_INFO}审计模式不修改任何配置, 仅检查并生成报告${C_RST}"
    echo ""

    init_report

    # CS-001: CrowdSec 已安装
    run_check "CS-001" "CrowdSec 已安装 (cscli 可用)" check_cscli

    # CS-002: crowdsec 服务运行中
    run_check "CS-002" "crowdsec 服务运行中" \
        bash -c 'systemctl is-active crowdsec >/dev/null 2>&1'

    # CS-003: crowdsec 服务已启用开机自启
    run_check "CS-003" "crowdsec 服务已启用开机自启" \
        bash -c 'systemctl is-enabled crowdsec >/dev/null 2>&1'

    # CS-004: Hub 版本已更新
    if check_cscli; then
        run_check "CS-004" "CrowdSec Hub 已更新" \
            bash -c 'cscli hub list >/dev/null 2>&1'
    else
        run_check "CS-004" "CrowdSec Hub 已更新" bash -c 'exit 3'
    fi

    # CS-005: 已安装场景集合数量
    if check_cscli; then
        local col_count
        col_count=$(cscli collections list -o raw 2>/dev/null | grep -c . || echo 0)
        if [ "$col_count" -gt 0 ]; then
            run_check "CS-005" "已安装 $col_count 个场景集合" true
        else
            run_check "CS-005" "未安装任何场景集合" bash -c 'exit 1'
        fi
    else
        run_check "CS-005" "场景集合检查" bash -c 'exit 3'
    fi

    # CS-006: SSH 暴力破解场景已安装
    if check_cscli; then
        run_check "CS-006" "SSH 暴力破解场景 (crowdsecurity/sshd)" \
            bash -c 'cscli collections list -o raw 2>/dev/null | grep -q "^crowdsecurity/sshd$"'
    else
        run_check "CS-006" "SSH 暴力破解场景" bash -c 'exit 3'
    fi

    # CS-007: 已部署至少一个 bouncer
    if check_cscli; then
        local bouncer_count
        bouncer_count=$(cscli bouncers list -o raw 2>/dev/null | grep -c . || echo 0)
        if [ "$bouncer_count" -gt 0 ]; then
            run_check "CS-007" "已部署 $bouncer_count 个 bouncer" true
        else
            run_check "CS-007" "未部署任何 bouncer (封禁不生效)" bash -c 'exit 1'
        fi
    else
        run_check "CS-007" "Bouncer 部署检查" bash -c 'exit 3'
    fi

    # CS-008: firewall bouncer 运行中
    run_check "CS-008" "firewall bouncer 服务运行中" \
        bash -c 'systemctl is-active crowdsec-firewall-bouncer >/dev/null 2>&1 || systemctl is-active crowdsec-nginx-bouncer >/dev/null 2>&1 || systemctl is-active crowdsec-cloudflare-bouncer >/dev/null 2>&1'

    # CS-009: 当前封禁决策数量
    if check_cscli; then
        local dec_count
        dec_count=$(cscli decisions list -o raw 2>/dev/null | grep -c . || echo 0)
        if [ "$dec_count" -ge 0 ]; then
            run_check "CS-009" "当前 $dec_count 条封禁决策" true
        fi
    else
        run_check "CS-009" "封禁决策检查" bash -c 'exit 3'
    fi

    # CS-010: 告警通知已配置
    if check_cscli; then
        local notif_count
        notif_count=$(cscli notifications list -o raw 2>/dev/null | grep -c . || echo 0)
        if [ "$notif_count" -gt 0 ]; then
            run_check "CS-010" "已配置 $notif_count 个告警通知" true
        else
            run_check "CS-010" "未配置告警通知 (无实时告警)" bash -c 'exit 2'
        fi
    else
        run_check "CS-010" "告警通知检查" bash -c 'exit 3'
    fi

    # CS-011: 配置文件存在且可读
    run_check "CS-011" "配置文件 /etc/crowdsec/config.yaml 存在" \
        test -f /etc/crowdsec/config.yaml

    # CS-012: CrowdSec API 端口监听
    run_check "CS-012" "CrowdSec API 端口 (8080) 监听中" \
        bash -c 'ss -tlnp 2>/dev/null | grep -q ":8080" || netstat -tlnp 2>/dev/null | grep -q ":8080"'

    # CS-013: LAPI 端口监听
    run_check "CS-013" "Local API 端口 (8081) 监听中" \
        bash -c 'ss -tlnp 2>/dev/null | grep -q ":8081" || netstat -tlnp 2>/dev/null | grep -q ":8081"'

    # CS-014: 数据库文件存在
    run_check "CS-014" "CrowdSec 数据库文件存在" \
        test -f /var/lib/crowdsec/data/crowdsec.db

    # CS-015: 日志文件存在且非空
    if [ -f /var/log/crowdsec.log ]; then
        run_check "CS-015" "CrowdSec 日志文件存在" true
    else
        run_check "CS-015" "CrowdSec 日志文件不存在" bash -c 'exit 2'
    fi

    print_summary
}

# ── 交互式向导 ────────────────────────────────────────────────
interactive_wizard() {
    while true; do
        clear
        echo -e "${C_OK}══════════════════════════════${C_RST}"
        echo -e "${C_OK}   CrowdSec 部署与入侵封禁    ${C_RST}"
        echo -e "${C_OK}══════════════════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 📦 安装 CrowdSec"
        echo -e "  ${C_WARN}2.${C_RST} 🎯 配置检测场景"
        echo -e "  ${C_WARN}3.${C_RST} 🛡️ 部署 Bouncer (封禁)"
        echo -e "  ${C_WARN}4.${C_RST} 🔔 配置告警通知"
        echo -e "  ${C_WARN}5.${C_RST} 🔄 Hub 更新与集合管理"
        echo -e "  ${C_WARN}6.${C_RST} 📊 查看运行状态"
        echo -e "  ${C_WARN}7.${C_RST} 📜 查看日志"
        echo -e "  ${C_WARN}8.${C_RST} 🛡️ 审计 CrowdSec 配置 (只读)"
        echo -e "  ${C_WARN}9.${C_RST} ❌ 卸载 CrowdSec"
        echo -e "  ${C_WARN}0.${C_RST} 返回"
        echo
        local pick
        read -r -p "❯ 选择 [0-9]: " pick
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
            *) echo -e "${C_FAIL}无效输入${C_RST}"; sleep 1 ;;
        esac
    done
}

# ── 主入口 ────────────────────────────────────────────────────
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
        *) echo "未知模式: $MODE"; exit 1 ;;
    esac
}

main "$@"
