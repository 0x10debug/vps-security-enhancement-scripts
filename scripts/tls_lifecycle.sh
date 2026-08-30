#!/bin/bash
# ════════════════════════════════════════════════════════════
#  tls_lifecycle.sh — TLS Certificate Lifecycle Management
#  适用系统: Linux 主机
#  运行身份: root
#  模式: 签发 + 续期 + 部署 + 监控 + 审计 (不直接修改运行中的反代)
#  参考: acmesh-official/acme.sh
#         certbot/certbot
#         fabriziosalmi/certmate
#  项目主页: https://github.com/0x10debug/vps-security-enhancement-scripts
# ════════════════════════════════════════════════════════════
#
# 用法:
#   sudo ./scripts/tls_lifecycle.sh                    # 交互式向导
#   sudo ./scripts/tls_lifecycle.sh --install          # 安装 acme.sh
#   sudo ./scripts/tls_lifecycle.sh --issue            # 签发证书 (需 --domain --dns 或 --standalone)
#   sudo ./scripts/tls_lifecycle.sh --renew            # 续期所有证书
#   sudo ./scripts/tls_lifecycle.sh --deploy           # 部署证书到反代 (需 --domain --proxy)
#   sudo ./scripts/tls_lifecycle.sh --revoke           # 撤销证书 (需 --domain)
#   sudo ./scripts/tls_lifecycle.sh --monitor          # 监控证书过期状态
#   sudo ./scripts/tls_lifecycle.sh --audit            # 只读审计 TLS 配置
#   sudo ./scripts/tls_lifecycle.sh --output ./tls-configs
#   sudo ./scripts/tls_lifecycle.sh --domain example.com --dns cloudflare
#   sudo ./scripts/tls_lifecycle.sh --domain example.com --standalone
#   sudo ./scripts/tls_lifecycle.sh --domain example.com --proxy nginx
#
# 退出码:
#   0 — 成功
#   1 — 参数错误 / 依赖缺失
#   2 — 部分功能不可用

set -euo pipefail

APP_NAME="tls_lifecycle"
APP_VER="v3.2.0"
MODE=""
OUTPUT_DIR=""
DOMAIN=""
DNS_PROVIDER=""
AUTH_MODE=""
PROXY_TYPE=""
KEY_TYPE="ec256"
ACME_HOME="${ACME_HOME:-/root/.acme.sh}"
ACME_EMAIL="${ACME_EMAIL:-admin@$(hostname -f 2>/dev/null || echo localhost)}"
REPORT_DIR="/var/log/tls-audit"
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
            --issue) MODE="issue"; shift ;;
            --renew) MODE="renew"; shift ;;
            --deploy) MODE="deploy"; shift ;;
            --revoke) MODE="revoke"; shift ;;
            --monitor) MODE="monitor"; shift ;;
            --audit) MODE="audit"; shift ;;
            --output) OUTPUT_DIR="$2"; shift 2 ;;
            --domain) DOMAIN="$2"; shift 2 ;;
            --dns) DNS_PROVIDER="$2"; AUTH_MODE="dns"; shift 2 ;;
            --standalone) AUTH_MODE="standalone"; shift ;;
            --proxy) PROXY_TYPE="$2"; shift 2 ;;
            --keytype) KEY_TYPE="$2"; shift 2 ;;
            --email) ACME_EMAIL="$2"; shift 2 ;;
            -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
            *) echo "未知参数: $1"; exit 1 ;;
        esac
    done
    if [ -z "$MODE" ]; then
        MODE="interactive"
    fi
    if [ -z "$OUTPUT_DIR" ]; then
        OUTPUT_DIR="./tls-configs"
    fi
}

# ── 报告初始化 ───────────────────────────────────────────────
init_report() {
    mkdir -p "$REPORT_DIR" 2>/dev/null || REPORT_DIR="/tmp/tls-audit"
    mkdir -p "$REPORT_DIR" 2>/dev/null || true
    REPORT_FILE="$REPORT_DIR/tls-audit-${TIMESTAMP}.txt"
    {
        echo "TLS Lifecycle Audit Report"
        echo "==========================="
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

# ── DNS 提供商列表 ────────────────────────────────────────────
show_dns_providers() {
    cat <<'EOF'
支持的 DNS API 提供商 (acme.sh):
  cloudflare     — Cloudflare DNS API
  dpdns          — DNSPod
  aliyun         — 阿里云 DNS
  tencent        — 腾讯云 DNS
  aws            — AWS Route 53
  gcloud         — Google Cloud DNS
  azure          — Azure DNS
  godaddy        — GoDaddy
  namecheap      — Namecheap
  dynu           — Dynu
  freedns        — FreeDNS
  linode         — Linode DNS
  digitalocean   — DigitalOcean DNS
  hetzner        — Hetzner DNS
  vultr          — Vultr DNS
  ovh            — OVH DNS
  pdns           — PowerDNS
  rackspace      — Rackspace DNS
  vercel         — Vercel DNS
  netlify        — Netlify DNS
  conoha         — ConoHa DNS
  nocmd          — No-IP
  simply         — Simply.com
  transip        — TransIP
  inwx           — INWX
  zoneedit       — ZoneEdit
  regru          — Reg.ru
  netcup         — Netcup
  hexonet        — Hexonet
  leaseweb       — LeaseWeb

设置环境变量以提供 API 凭据, 例如:
  export CF_Token="your_cloudflare_api_token"
  export CF_Zone_ID="your_zone_id"
  export Ali_Key="your_aliyun_key"
  export Ali_Secret="your_aliyun_secret"

完整列表见: https://github.com/acmesh-official/acme.sh/wiki/dnsapi
EOF
}

# ── acme.sh 安装 ──────────────────────────────────────────────
install_acme() {
    echo -e "${C_WARN}>>> 安装 acme.sh <<<${C_RST}"

    if [ -f "$ACME_HOME/acme.sh" ]; then
        echo -e "${C_INFO}acme.sh 已安装于 $ACME_HOME, 將尝试升级...${C_RST}"
        bash "$ACME_HOME/acme.sh" --upgrade 2>/dev/null || true
        echo -e "${C_OK}acme.sh 已是最新${C_RST}"
        return 0
    fi

    echo -e "${C_INFO}[1/3] 下载 acme.sh...${C_RST}"
    curl -sL https://get.acme.sh -o /tmp/acme-install.sh || {
        echo -e "${C_FAIL}下载失败, 请检查网络${C_RST}"
        return 1
    }

    echo -e "${C_INFO}[2/3] 安装 acme.sh 到 $ACME_HOME...${C_RST}"
    bash /tmp/acme-install.sh --home "$ACME_HOME" --accountemail "$ACME_EMAIL" 2>&1 | tail -5
    rm -f /tmp/acme-install.sh

    echo -e "${C_INFO}[3/3] 设置默认 CA...${C_RST}"
    bash "$ACME_HOME/acme.sh" --set-default-ca --server letsencrypt 2>/dev/null || true

    echo -e "${C_OK}acme.sh 安装完成${C_RST}"
    echo -e "${C_INFO}安装路径: $ACME_HOME/acme.sh${C_RST}"
    echo -e "${C_INFO}默认 CA: Let's Encrypt${C_RST}"
    echo -e "${C_INFO}账户邮箱: $ACME_EMAIL${C_RST}"
}

# ── 证书签发 ──────────────────────────────────────────────────
issue_cert() {
    echo -e "${C_WARN}>>> 签发 TLS 证书 <<<${C_RST}"

    if [ -z "$DOMAIN" ]; then
        echo -e "${C_FAIL}请通过 --domain 指定域名${C_RST}"
        return 1
    fi

    if [ ! -f "$ACME_HOME/acme.sh" ]; then
        echo -e "${C_FAIL}acme.sh 未安装, 请先运行 --install${C_RST}"
        return 1
    fi

    local keylength
    case "$KEY_TYPE" in
        ec256) keylength="ec-256" ;;
        ec384) keylength="ec-384" ;;
        rsa2048) keylength="2048" ;;
        rsa4096) keylength="4096" ;;
        *) keylength="ec-256" ;;
    esac

    echo -e "${C_INFO}域名: $DOMAIN${C_RST}"
    echo -e "${C_INFO}密钥类型: $keylength${C_RST}"

    local issue_cmd="$ACME_HOME/acme.sh --issue"

    if [ "$AUTH_MODE" = "dns" ]; then
        if [ -z "$DNS_PROVIDER" ]; then
            echo -e "${C_FAIL}DNS 模式需要 --dns <provider>${C_RST}"
            show_dns_providers
            return 1
        fi
        echo -e "${C_INFO}验证方式: DNS-01 ($DNS_PROVIDER)${C_RST}"
        issue_cmd="$issue_cmd --dns $DNS_PROVIDER"
    elif [ "$AUTH_MODE" = "standalone" ]; then
        echo -e "${C_INFO}验证方式: HTTP-01 (standalone)${C_RST}"
        echo -e "${C_WARN}standalone 模式需要 80 端口空闲${C_RST}"
        issue_cmd="$issue_cmd --standalone"
    else
        echo -e "${C_FAIL}请指定验证方式: --dns <provider> 或 --standalone${C_RST}"
        return 1
    fi

    issue_cmd="$issue_cmd -d $DOMAIN -k $keylength"

    echo -e "${C_INFO}执行: $issue_cmd${C_RST}"
    # shellcheck disable=SC2086
    bash $issue_cmd || {
        echo -e "${C_FAIL}证书签发失败${C_RST}"
        return 1
    }

    echo -e "${C_OK}证书签发成功: $DOMAIN${C_RST}"
    echo -e "${C_INFO}证书路径: $ACME_HOME/${DOMAIN}_ecc/ (EC) 或 $ACME_HOME/${DOMAIN}/ (RSA)${C_RST}"
}

# ── 证书续期 ──────────────────────────────────────────────────
renew_certs() {
    echo -e "${C_WARN}>>> 续期所有证书 <<<${C_RST}"

    if [ ! -f "$ACME_HOME/acme.sh" ]; then
        echo -e "${C_FAIL}acme.sh 未安装${C_RST}"
        return 1
    fi

    echo -e "${C_INFO}[1/2] 列出已签发证书...${C_RST}"
    bash "$ACME_HOME/acme.sh" --list 2>/dev/null || true

    echo ""
    echo -e "${C_INFO}[2/2] 续期即将过期的证书...${C_RST}"
    bash "$ACME_HOME/acme.sh" --renew-all 2>&1 || {
        echo -e "${C_WARN}部分证书续期可能失败, 请检查上方输出${C_RST}"
    }

    echo -e "${C_OK}续期检查完成${C_RST}"
}

# ── 证书部署 ──────────────────────────────────────────────────
deploy_cert() {
    echo -e "${C_WARN}>>> 部署证书到反代 <<<${C_RST}"

    if [ -z "$DOMAIN" ]; then
        echo -e "${C_FAIL}请通过 --domain 指定域名${C_RST}"
        return 1
    fi
    if [ -z "$PROXY_TYPE" ]; then
        echo -e "${C_FAIL}请通过 --proxy 指定反代类型 (nginx/caddy/haproxy/apache)${C_RST}"
        return 1
    fi

    if [ ! -f "$ACME_HOME/acme.sh" ]; then
        echo -e "${C_FAIL}acme.sh 未安装${C_RST}"
        return 1
    fi

    mkdir -p "$OUTPUT_DIR/deploy"

    local cert_dir
    cert_dir="$ACME_HOME/${DOMAIN}_ecc"
    [ ! -d "$cert_dir" ] && cert_dir="$ACME_HOME/${DOMAIN}"
    if [ ! -d "$cert_dir" ]; then
        echo -e "${C_FAIL}未找到 $DOMAIN 的证书, 请先签发${C_RST}"
        return 1
    fi

    local fullchain="$cert_dir/fullchain.cer"
    local keyfile="$cert_dir/${DOMAIN}.key"

    case "$PROXY_TYPE" in
        nginx)
            local deploy_dir="/etc/nginx/ssl/${DOMAIN}"
            cat > "$OUTPUT_DIR/deploy/nginx-ssl.conf" <<EOF
# Nginx TLS configuration for $DOMAIN
# Generated by tls_lifecycle.sh

ssl_certificate     ${deploy_dir}/fullchain.cer;
ssl_certificate_key ${deploy_dir}/${DOMAIN}.key;

ssl_protocols       TLSv1.2 TLSv1.3;
ssl_ciphers         ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
ssl_session_cache   shared:SSL:10m;
ssl_session_timeout 1d;
ssl_session_tickets off;

# OCSP stapling
ssl_stapling on;
ssl_stapling_verify on;

# HSTS
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
EOF
            echo -e "${C_INFO}Nginx 配置已生成: $OUTPUT_DIR/deploy/nginx-ssl.conf${C_RST}"
            echo -e "${C_WARN}部署步骤:${C_RST}"
            echo "  1. mkdir -p $deploy_dir"
            echo "  2. cp $fullchain $deploy_dir/fullchain.cer"
            echo "  3. cp $keyfile $deploy_dir/${DOMAIN}.key"
            echo "  4. 在 nginx server 块中 Include 上方配置"
            echo "  5. nginx -t && systemctl reload nginx"
            ;;
        caddy)
            cat > "$OUTPUT_DIR/deploy/Caddyfile" <<EOF
# Caddy TLS configuration for $DOMAIN
# Generated by tls_lifecycle.sh
# Caddy 自动管理 TLS, 此文件仅用于手动证书场景

$DOMAIN {
    tls $fullchain $keyfile {
        protocols tls1.2 tls1.3
        ciphers ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-RSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-RSA-AES256-GCM-SHA384
        alpn http/1.1 h2 h3
    }
    # 反代到后端
    reverse_proxy localhost:8080
}
EOF
            echo -e "${C_INFO}Caddyfile 已生成: $OUTPUT_DIR/deploy/Caddyfile${C_RST}"
            ;;
        haproxy)
            cat > "$OUTPUT_DIR/deploy/haproxy-tls.cfg" <<EOF
# HAProxy TLS configuration for $DOMAIN
# Generated by tls_lifecycle.sh

frontend https-${DOMAIN}
    bind *:443 ssl crt ${OUTPUT_DIR}/deploy/${DOMAIN}-combined.pem alpn h2,http/1.1
    http-response set-header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
    default_backend backend-${DOMAIN}

backend backend-${DOMAIN}
    server app1 127.0.0.1:8080 check
EOF
            echo -e "${C_INFO}HAProxy 配置已生成: $OUTPUT_DIR/deploy/haproxy-tls.cfg${C_RST}"
            echo -e "${C_WARN}HAProxy 需要合并证书和私钥:${C_RST}"
            echo "  cat $fullchain $keyfile > $OUTPUT_DIR/deploy/${DOMAIN}-combined.pem"
            echo "  chmod 600 $OUTPUT_DIR/deploy/${DOMAIN}-combined.pem"
            ;;
        apache)
            cat > "$OUTPUT_DIR/deploy/apache-ssl.conf" <<EOF
# Apache TLS configuration for $DOMAIN
# Generated by tls_lifecycle.sh

<VirtualHost *:443>
    ServerName $DOMAIN

    SSLEngine on
    SSLCertificateFile      ${fullchain}
    SSLCertificateKeyFile   ${keyfile}

    SSLProtocol             -all +TLSv1.2 +TLSv1.3
    SSLCipherSuite          ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
    SSLHonorCipherOrder     off
    SSLSessionTickets       off

    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"

    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/
</VirtualHost>
EOF
            echo -e "${C_INFO}Apache 配置已生成: $OUTPUT_DIR/deploy/apache-ssl.conf${C_RST}"
            ;;
        *)
            echo -e "${C_FAIL}不支持的反代类型: $PROXY_TYPE (可选: nginx/caddy/haproxy/apache)${C_RST}"
            return 1
            ;;
    esac

    # 设置 acme.sh 自动部署 hook
    echo -e "${C_INFO}设置 acme.sh 自动续期后部署 hook...${C_RST}"
    local install_cert_cmd="$ACME_HOME/acme.sh --install-cert -d $DOMAIN"
    case "$PROXY_TYPE" in
        nginx)
            install_cert_cmd="$install_cert_cmd --fullchain-file /etc/nginx/ssl/${DOMAIN}/fullchain.cer"
            install_cert_cmd="$install_cert_cmd --key-file /etc/nginx/ssl/${DOMAIN}/${DOMAIN}.key"
            install_cert_cmd="$install_cert_cmd --reloadcmd 'nginx -t && systemctl reload nginx'"
            ;;
        caddy)
            install_cert_cmd="$install_cert_cmd --fullchain-file /etc/caddy/ssl/${DOMAIN}/fullchain.cer"
            install_cert_cmd="$install_cert_cmd --key-file /etc/caddy/ssl/${DOMAIN}/${DOMAIN}.key"
            install_cert_cmd="$install_cert_cmd --reloadcmd 'systemctl reload caddy'"
            ;;
        haproxy)
            install_cert_cmd="$install_cert_cmd --reloadcmd 'cat /etc/haproxy/ssl/${DOMAIN}/fullchain.cer /etc/haproxy/ssl/${DOMAIN}/${DOMAIN}.key > /etc/haproxy/ssl/${DOMAIN}/combined.pem && systemctl reload haproxy'"
            ;;
        apache)
            install_cert_cmd="$install_cert_cmd --fullchain-file /etc/apache2/ssl/${DOMAIN}/fullchain.cer"
            install_cert_cmd="$install_cert_cmd --key-file /etc/apache2/ssl/${DOMAIN}/${DOMAIN}.key"
            install_cert_cmd="$install_cert_cmd --reloadcmd 'systemctl reload apache2'"
            ;;
    esac
    echo -e "${C_WARN}自动部署命令 (手动执行确认):${C_RST}"
    echo "  $install_cert_cmd"
}

# ── 证书撤销 ──────────────────────────────────────────────────
revoke_cert() {
    echo -e "${C_WARN}>>> 撤销证书 <<<${C_RST}"

    if [ -z "$DOMAIN" ]; then
        echo -e "${C_FAIL}请通过 --domain 指定域名${C_RST}"
        return 1
    fi
    if [ ! -f "$ACME_HOME/acme.sh" ]; then
        echo -e "${C_FAIL}acme.sh 未安装${C_RST}"
        return 1
    fi

    echo -e "${C_WARN}即将撤销 $DOMAIN 的证书, 此操作不可逆${C_RST}"
    read -r -p "确认撤销? (y/N): " ack
    if [[ ! "$ack" =~ ^[Yy]$ ]]; then
        echo -e "${C_INFO}已取消${C_RST}"
        return 0
    fi

    bash "$ACME_HOME/acme.sh" --revoke -d "$DOMAIN" 2>&1 || {
        echo -e "${C_FAIL}撤销失败${C_RST}"
        return 1
    }
    echo -e "${C_OK}证书已撤销: $DOMAIN${C_RST}"
}

# ── 证书监控 ──────────────────────────────────────────────────
monitor_certs() {
    echo -e "${C_WARN}>>> 证书过期监控 <<<${C_RST}"

    echo -e "${C_INFO}扫描系统中的 TLS 证书...${C_RST}"
    echo ""

    local found=0
    local now_epoch
    now_epoch=$(date +%s)

    # 扫描 acme.sh 管理的证书
    if [ -f "$ACME_HOME/acme.sh" ]; then
        echo -e "${C_INFO}[acme.sh 管理的证书]${C_RST}"
        bash "$ACME_HOME/acme.sh" --list 2>/dev/null | tail -n +2 | while IFS= read -r line; do
            local d
            d=$(echo "$line" | awk '{print $1}')
            local cert_dir="$ACME_HOME/${d}_ecc"
            [ ! -d "$cert_dir" ] && cert_dir="$ACME_HOME/${d}"
            if [ -f "$cert_dir/fullchain.cer" ]; then
                local expiry
                expiry=$(openssl x509 -in "$cert_dir/fullchain.cer" -noout -enddate 2>/dev/null | cut -d= -f2)
                if [ -n "$expiry" ]; then
                    local expiry_epoch
                    expiry_epoch=$(date -d "$expiry" +%s 2>/dev/null || date -j -f "%b %d %H:%M:%S %Y %Z" "$expiry" +%s 2>/dev/null || echo 0)
                    local days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
                    if [ "$days_left" -lt 0 ]; then
                        printf "  ${C_FAIL}EXPIRED${C_RST}  %-30s  expired %d days ago\n" "$d" "$(( -days_left ))"
                    elif [ "$days_left" -lt 15 ]; then
                        printf "  ${C_FAIL}CRITICAL${C_RST} %-30s  %d days left\n" "$d" "$days_left"
                    elif [ "$days_left" -lt 30 ]; then
                        printf "  ${C_WARN}WARNING${C_RST}  %-30s  %d days left\n" "$d" "$days_left"
                    else
                        printf "  ${C_OK}OK${C_RST}      %-30s  %d days left\n" "$d" "$days_left"
                    fi
                fi
            fi
        done
        found=1
        echo ""
    fi

    # 扫描常见证书路径
    echo -e "${C_INFO}[系统证书文件]${C_RST}"
    local cert_paths=(
        "/etc/nginx/ssl"
        "/etc/caddy/ssl"
        "/etc/haproxy/ssl"
        "/etc/apache2/ssl"
        "/etc/letsencrypt/live"
        "/etc/pki/tls"
        "/etc/ssl/private"
    )
    for base in "${cert_paths[@]}"; do
        if [ -d "$base" ]; then
            find "$base" -name "*.crt" -o -name "*.cer" -o -name "*.pem" 2>/dev/null | while IFS= read -r certfile; do
                local expiry
                expiry=$(openssl x509 -in "$certfile" -noout -enddate 2>/dev/null | cut -d= -f2) || continue
                [ -z "$expiry" ] && continue
                local expiry_epoch
                expiry_epoch=$(date -d "$expiry" +%s 2>/dev/null || date -j -f "%b %d %H:%M:%S %Y %Z" "$expiry" +%s 2>/dev/null || echo 0)
                [ "$expiry_epoch" -eq 0 ] && continue
                local days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
                if [ "$days_left" -lt 0 ]; then
                    printf "  ${C_FAIL}EXPIRED${C_RST}  %-50s  expired %d days ago\n" "$certfile" "$(( -days_left ))"
                elif [ "$days_left" -lt 15 ]; then
                    printf "  ${C_FAIL}CRITICAL${C_RST} %-50s  %d days left\n" "$certfile" "$days_left"
                elif [ "$days_left" -lt 30 ]; then
                    printf "  ${C_WARN}WARNING${C_RST}  %-50s  %d days left\n" "$certfile" "$days_left"
                else
                    printf "  ${C_OK}OK${C_RST}      %-50s  %d days left\n" "$certfile" "$days_left"
                fi
            done
            found=1
        fi
    done

    # 生成 cron 监控脚本
    mkdir -p "$OUTPUT_DIR"
    cat > "$OUTPUT_DIR/tls-monitor-cron.sh" <<'CRONEOF'
#!/bin/bash
# TLS certificate expiry monitor — cron job
# Add to crontab: 0 8 * * * /path/to/tls-monitor-cron.sh
# Alerts when any certificate expires within 30 days

ALERT_DAYS=30
ACME_HOME="${ACME_HOME:-/root/.acme.sh}"
ALERT_EMAIL="${ALERT_EMAIL:-root}"

now_epoch=$(date +%s)
alerts=""

check_cert() {
    local certfile="$1"
    local expiry
    expiry=$(openssl x509 -in "$certfile" -noout -enddate 2>/dev/null | cut -d= -f2) || return
    [ -z "$expiry" ] && return
    local expiry_epoch
    expiry_epoch=$(date -d "$expiry" +%s 2>/dev/null || date -j -f "%b %d %H:%M:%S %Y %Z" "$expiry" +%s 2>/dev/null || echo 0)
    [ "$expiry_epoch" -eq 0 ] && return
    local days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
    if [ "$days_left" -lt "$ALERT_DAYS" ]; then
        alerts+="  $certfile: $days_left days left (expires $expiry)\n"
    fi
}

# Check acme.sh certs
if [ -f "$ACME_HOME/acme.sh" ]; then
    bash "$ACME_HOME/acme.sh" --list 2>/dev/null | tail -n +2 | while IFS= read -r line; do
        d=$(echo "$line" | awk '{print $1}')
        cert_dir="$ACME_HOME/${d}_ecc"
        [ ! -d "$cert_dir" ] && cert_dir="$ACME_HOME/${d}"
        [ -f "$cert_dir/fullchain.cer" ] && check_cert "$cert_dir/fullchain.cer"
    done
fi

# Check system cert paths
for base in /etc/nginx/ssl /etc/caddy/ssl /etc/haproxy/ssl /etc/letsencrypt/live /etc/pki/tls /etc/ssl/private; do
    [ -d "$base" ] && find "$base" -name "*.crt" -o -name "*.cer" -o -name "*.pem" 2>/dev/null | while IFS= read -r f; do
        check_cert "$f"
    done
done

if [ -n "$alerts" ]; then
    echo -e "TLS Certificate Expiry Alert\n\nThe following certificates expire within $ALERT_DAYS days:\n\n$alerts" | \
        mail -s "[TLS Alert] Certificate expiry warning on $(hostname)" "$ALERT_EMAIL" 2>/dev/null || true
    echo -e "$alerts"
fi
CRONEOF
    chmod +x "$OUTPUT_DIR/tls-monitor-cron.sh"
    echo ""
    echo -e "${C_INFO}Cron 监控脚本已生成: $OUTPUT_DIR/tls-monitor-cron.sh${C_RST}"
    echo -e "${C_INFO}添加到 crontab: 0 8 * * * $OUTPUT_DIR/tls-monitor-cron.sh${C_RST}"

    if [ "$found" -eq 0 ]; then
        echo -e "${C_WARN}未找到任何证书文件${C_RST}"
    fi
}

# ── TLS 审计 ──────────────────────────────────────────────────
audit_tls() {
    echo -e "${C_WARN}>>> TLS 配置审计 (只读) <<<${C_RST}"
    echo ""
    init_report

    # --- acme.sh 状态 ---
    echo -e "${C_INFO}[acme.sh 状态]${C_RST}"
    run_check "TLS-001" "acme.sh 已安装" test -f "$ACME_HOME/acme.sh"
    run_check "TLS-002" "acme.sh cron 自动续期已配置" \
        bash -c "crontab -l 2>/dev/null | grep -q acme.sh"
    run_check "TLS-003" "acme.sh 默认 CA 已设置" \
        bash -c "bash $ACME_HOME/acme.sh --info 2>/dev/null | grep -qi 'server\|ca'"

    # --- 证书状态 ---
    echo ""
    echo -e "${C_INFO}[证书状态]${C_RST}"

    local now_epoch
    now_epoch=$(date +%s)

    # 检查 acme.sh 管理的证书过期时间
    if [ -f "$ACME_HOME/acme.sh" ]; then
        local cert_list
        cert_list=$(bash "$ACME_HOME/acme.sh" --list 2>/dev/null | tail -n +2)
        if [ -n "$cert_list" ]; then
            local cert_count
            cert_count=$(echo "$cert_list" | wc -l | tr -d ' ')
            run_check "TLS-004" "已管理 $cert_count 个证书" test "$cert_count" -gt 0

            echo "$cert_list" | while IFS= read -r line; do
                local d
                d=$(echo "$line" | awk '{print $1}')
                local cert_dir="$ACME_HOME/${d}_ecc"
                [ ! -d "$cert_dir" ] && cert_dir="$ACME_HOME/${d}"
                if [ -f "$cert_dir/fullchain.cer" ]; then
                    local expiry
                    expiry=$(openssl x509 -in "$cert_dir/fullchain.cer" -noout -enddate 2>/dev/null | cut -d= -f2)
                    if [ -n "$expiry" ]; then
                        local expiry_epoch
                        expiry_epoch=$(date -d "$expiry" +%s 2>/dev/null || date -j -f "%b %d %H:%M:%S %Y %Z" "$expiry" +%s 2>/dev/null || echo 0)
                        if [ "$expiry_epoch" -gt 0 ]; then
                            local days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
                            if [ "$days_left" -lt 0 ]; then
                                run_check "TLS-005" "$d 证书未过期" bash -c "exit 1"
                            elif [ "$days_left" -lt 15 ]; then
                                run_check "TLS-005" "$d 证书未过期 ($days_left 天剩余)" bash -c "exit 1"
                            elif [ "$days_left" -lt 30 ]; then
                                run_check "TLS-005" "$d 证书未过期 ($days_left 天剩余)" bash -c "exit 2"
                            else
                                run_check "TLS-005" "$d 证书未过期 ($days_left 天剩余" true
                            fi
                        fi
                    fi
                fi
            done
        else
            run_check "TLS-004" "已管理证书" bash -c "exit 2"
        fi
    else
        run_check "TLS-004" "已管理证书" bash -c "exit 2"
    fi

    # --- 证书密钥强度 ---
    echo ""
    echo -e "${C_INFO}[证书密钥强度]${C_RST}"

    local found_cert=0
    for certfile in /etc/nginx/ssl/*/*.cer /etc/caddy/ssl/*/*.cer /etc/letsencrypt/live/*/fullchain.pem; do
        [ -f "$certfile" ] || continue
        found_cert=1
        local key_type
        key_type=$(openssl x509 -in "$certfile" -noout -text 2>/dev/null | grep -A1 "Public Key Algorithm" | grep -io "rsa\|ec" | head -1)
        local key_size
        key_size=$(openssl x509 -in "$certfile" -noout -text 2>/dev/null | grep -oE "(256|384|2048|4096)" | head -1)
        if [ "$key_type" = "ec" ]; then
            if [ "$key_size" -ge 256 ]; then
                run_check "TLS-006" "$certfile 密钥强度: EC-$key_size" true
            else
                run_check "TLS-006" "$certfile 密钥强度: EC-$key_size (偏弱)" bash -c "exit 2"
            fi
        elif [ "$key_type" = "rsa" ]; then
            if [ "$key_size" -ge 2048 ]; then
                run_check "TLS-006" "$certfile 密钥强度: RSA-$key_size" true
            else
                run_check "TLS-006" "$certfile 密钥强度: RSA-$key_size (偏弱)" bash -c "exit 1"
            fi
        fi
    done
    [ "$found_cert" -eq 0 ] && run_check "TLS-006" "证书密钥强度检查" bash -c "exit 2"

    # --- TLS 协议版本 ---
    echo ""
    echo -e "${C_INFO}[TLS 协议版本]${C_RST}"

    # Nginx
    if check_cmd nginx; then
        local nginx_ssl
        nginx_ssl=$(nginx -T 2>/dev/null | grep -i "ssl_protocols" | head -1)
        if echo "$nginx_ssl" | grep -qi "TLSv1.3"; then
            run_check "TLS-007" "Nginx 启用 TLS 1.3" true
        elif echo "$nginx_ssl" | grep -qi "TLSv1.2"; then
            run_check "TLS-007" "Nginx 启用 TLS 1.3 (仅 1.2)" bash -c "exit 2"
        else
            run_check "TLS-007" "Nginx 启用 TLS 1.3" bash -c "exit 2"
        fi
        if echo "$nginx_ssl" | grep -qi "TLSv1\b" && ! echo "$nginx_ssl" | grep -qi "TLSv1\.1"; then
            run_check "TLS-008" "Nginx 禁用 TLS 1.0/1.1" true
        else
            run_check "TLS-008" "Nginx 禁用 TLS 1.0/1.1" bash -c "exit 2"
        fi
    else
        run_check "TLS-007" "Nginx TLS 1.3" bash -c "exit 2"
        run_check "TLS-008" "Nginx 禁用 TLS 1.0/1.1" bash -c "exit 2"
    fi

    # Caddy
    if check_cmd caddy; then
        run_check "TLS-009" "Caddy 自动 TLS 管理" true
    else
        run_check "TLS-009" "Caddy 自动 TLS 管理" bash -c "exit 2"
    fi

    # --- HSTS ---
    echo ""
    echo -e "${C_INFO}[HSTS]${C_RST}"

    if check_cmd nginx; then
        local nginx_hsts
        nginx_hsts=$(nginx -T 2>/dev/null | grep -i "Strict-Transport-Security" | head -1)
        if [ -n "$nginx_hsts" ]; then
            run_check "TLS-010" "Nginx HSTS 已配置" true
        else
            run_check "TLS-010" "Nginx HSTS 已配置" bash -c "exit 1"
        fi
    else
        run_check "TLS-010" "Nginx HSTS" bash -c "exit 2"
    fi

    # --- 证书自动续期 ---
    echo ""
    echo -e "${C_INFO}[自动续期]${C_RST}"

    if [ -f "$ACME_HOME/acme.sh" ]; then
        local cron_check
        cron_check=$(crontab -l 2>/dev/null | grep -c "acme.sh.*cron" || true)
        if [ "$cron_check" -gt 0 ]; then
            run_check "TLS-011" "acme.sh cron 自动续期已配置" true
        else
            run_check "TLS-011" "acme.sh cron 自动续期已配置" bash -c "exit 1"
        fi
    else
        run_check "TLS-011" "acme.sh cron 自动续期" bash -c "exit 2"
    fi

    if check_cmd certbot; then
        local certbot_timer
        certbot_timer=$(systemctl list-timers 2>/dev/null | grep -c certbot || true)
        if [ "$certbot_timer" -gt 0 ]; then
            run_check "TLS-012" "certbot 自动续期 timer 已配置" true
        else
            run_check "TLS-012" "certbot 自动续期 timer 已配置" bash -c "exit 2"
        fi
    else
        run_check "TLS-012" "certbot 自动续期 timer" bash -c "exit 2"
    fi

    # --- OCSP Stapling ---
    echo ""
    echo -e "${C_INFO}[OCSP Stapling]${C_RST}"

    if check_cmd nginx; then
        local nginx_ocsp
        nginx_ocsp=$(nginx -T 2>/dev/null | grep -i "ssl_stapling" | head -1)
        if [ -n "$nginx_ocsp" ]; then
            run_check "TLS-013" "Nginx OCSP Stapling 已配置" true
        else
            run_check "TLS-013" "Nginx OCSP Stapling 已配置" bash -c "exit 2"
        fi
    else
        run_check "TLS-013" "Nginx OCSP Stapling" bash -c "exit 2"
    fi

    print_summary
}

# ── 交互式向导 ────────────────────────────────────────────────
interactive_wizard() {
    while true; do
        clear
        echo -e "${C_OK}══════════════════════════════${C_RST}"
        echo -e "${C_OK}   TLS 证书生命周期管理      ${C_RST}"
        echo -e "${C_OK}══════════════════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 📦 安装 acme.sh"
        echo -e "  ${C_WARN}2.${C_RST} 🔑 签发证书"
        echo -e "  ${C_WARN}3.${C_RST} 🔄 续期所有证书"
        echo -e "  ${C_WARN}4.${C_RST} 📋 部署证书到反代"
        echo -e "  ${C_WARN}5.${C_RST} ❌ 撤销证书"
        echo -e "  ${C_WARN}6.${C_RST} 📊 监控证书过期"
        echo -e "  ${C_WARN}7.${C_RST} 🛡️ 审计 TLS 配置 (只读)"
        echo -e "  ${C_WARN}8.${C_RST} 📋 显示 DNS 提供商列表"
        echo -e "  ${C_WARN}0.${C_RST} 返回"
        echo
        local pick
        read -r -p "❯ 选择 [0-8]: " pick
        case $pick in
            1) install_acme; wait_key ;;
            2)
                read -r -p "域名: " DOMAIN
                echo "验证方式: 1) DNS-01  2) HTTP-01 (standalone)"
                read -r -p "选择 [1-2]: " am
                case $am in
                    1)
                        read -r -p "DNS 提供商 (如 cloudflare): " DNS_PROVIDER
                        AUTH_MODE="dns"
                        ;;
                    2) AUTH_MODE="standalone" ;;
                    *) echo "无效"; sleep 1; continue ;;
                esac
                issue_cert; wait_key
                ;;
            3) renew_certs; wait_key ;;
            4)
                read -r -p "域名: " DOMAIN
                echo "反代类型: 1) Nginx  2) Caddy  3) HAProxy  4) Apache"
                read -r -p "选择 [1-4]: " pt
                case $pt in
                    1) PROXY_TYPE="nginx" ;;
                    2) PROXY_TYPE="caddy" ;;
                    3) PROXY_TYPE="haproxy" ;;
                    4) PROXY_TYPE="apache" ;;
                    *) echo "无效"; sleep 1; continue ;;
                esac
                deploy_cert; wait_key
                ;;
            5)
                read -r -p "域名: " DOMAIN
                revoke_cert; wait_key
                ;;
            6) monitor_certs; wait_key ;;
            7) audit_tls; wait_key ;;
            8) show_dns_providers; wait_key ;;
            0) break ;;
            *) echo -e "${C_FAIL}无效输入${C_RST}"; sleep 1 ;;
        esac
    done
}

# ── 主入口 ────────────────────────────────────────────────────
main() {
    parse_args "$@"

    case "$MODE" in
        install) check_root; install_acme ;;
        issue) check_root; issue_cert ;;
        renew) check_root; renew_certs ;;
        deploy) check_root; deploy_cert ;;
        revoke) check_root; revoke_cert ;;
        monitor) check_root; monitor_certs ;;
        audit) audit_tls ;;
        interactive) interactive_wizard ;;
        *) echo "未知模式: $MODE"; exit 1 ;;
    esac
}

main "$@"
