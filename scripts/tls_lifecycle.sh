#!/bin/bash
# ════════════════════════════════════════════════════════════
#  tls_lifecycle.sh — TLS Certificate Lifecycle Management
#  Supported OS: Linux host
#  Run as: root
#  Mode: Issue + renew + deploy + monitor + audit (does not directly modify running reverse proxies)
#  Reference: acmesh-official/acme.sh
#         certbot/certbot
#         fabriziosalmi/certmate
#  Project home: https://github.com/0x10debug/vps-security-enhancement-scripts
# ════════════════════════════════════════════════════════════
#
# Usage:
#   sudo ./scripts/tls_lifecycle.sh                    # Interactive wizard
#   sudo ./scripts/tls_lifecycle.sh --install          # Install acme.sh
#   sudo ./scripts/tls_lifecycle.sh --issue            # Issue certificate (requires --domain --dns or --standalone)
#   sudo ./scripts/tls_lifecycle.sh --renew            # Renew all certificates
#   sudo ./scripts/tls_lifecycle.sh --deploy           # Deploy certificates to reverse proxy (requires --domain --proxy)
#   sudo ./scripts/tls_lifecycle.sh --revoke           # Revoke certificate (requires --domain)
#   sudo ./scripts/tls_lifecycle.sh --monitor          # Monitor certificate expiry status
#   sudo ./scripts/tls_lifecycle.sh --audit            # Read-only audit TLS config
#   sudo ./scripts/tls_lifecycle.sh --output ./tls-configs
#   sudo ./scripts/tls_lifecycle.sh --domain example.com --dns cloudflare
#   sudo ./scripts/tls_lifecycle.sh --domain example.com --standalone
#   sudo ./scripts/tls_lifecycle.sh --domain example.com --proxy nginx
#
# Exit codes:
#   0 — Success
#   1 — Parameter error / missing dependency
#   2 — Some features unavailable

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

# ── Parameter parsing ─────────────────────────────────────────────────
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
            *) echo "Unknown parameter: $1"; exit 1 ;;
        esac
    done
    if [ -z "$MODE" ]; then
        MODE="interactive"
    fi
    if [ -z "$OUTPUT_DIR" ]; then
        OUTPUT_DIR="./tls-configs"
    fi
}

# ── Report initialization ───────────────────────────────────────────────
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

# ── DNS provider list ────────────────────────────────────────────
show_dns_providers() {
    cat <<'EOF'
Supported DNS API providers (acme.sh):
  cloudflare     — Cloudflare DNS API
  dpdns          — DNSPod
  aliyun         — Aliyun DNS
  tencent        — Tencent Cloud DNS
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

Set environment variables to provide API credentials, e.g.:
  export CF_Token="your_cloudflare_api_token"
  export CF_Zone_ID="your_zone_id"
  export Ali_Key="your_aliyun_key"
  export Ali_Secret="your_aliyun_secret"

Full list at: https://github.com/acmesh-official/acme.sh/wiki/dnsapi
EOF
}

# ── acme.sh installation ──────────────────────────────────────────────
install_acme() {
    echo -e "${C_WARN}>>> Install acme.sh <<<${C_RST}"

    if [ -f "$ACME_HOME/acme.sh" ]; then
        echo -e "${C_INFO}acme.sh installed at $ACME_HOME, will attempt upgrade...${C_RST}"
        bash "$ACME_HOME/acme.sh" --upgrade 2>/dev/null || true
        echo -e "${C_OK}acme.sh is up to date${C_RST}"
        return 0
    fi

    echo -e "${C_INFO}[1/3] Download acme.sh...${C_RST}"
    curl -sL https://get.acme.sh -o /tmp/acme-install.sh || {
        echo -e "${C_FAIL}Download failed, please check network${C_RST}"
        return 1
    }

    echo -e "${C_INFO}[2/3] Install acme.sh to $ACME_HOME...${C_RST}"
    bash /tmp/acme-install.sh --home "$ACME_HOME" --accountemail "$ACME_EMAIL" 2>&1 | tail -5
    rm -f /tmp/acme-install.sh

    echo -e "${C_INFO}[3/3] Set default CA...${C_RST}"
    bash "$ACME_HOME/acme.sh" --set-default-ca --server letsencrypt 2>/dev/null || true

    echo -e "${C_OK}acme.sh installation complete${C_RST}"
    echo -e "${C_INFO}Install path: $ACME_HOME/acme.sh${C_RST}"
    echo -e "${C_INFO}Default CA: Let's Encrypt${C_RST}"
    echo -e "${C_INFO}Account email: $ACME_EMAIL${C_RST}"
}

# ── Certificate issuance ──────────────────────────────────────────────────
issue_cert() {
    echo -e "${C_WARN}>>> Issue TLS certificate <<<${C_RST}"

    if [ -z "$DOMAIN" ]; then
        echo -e "${C_FAIL}Please specify domain via --domain${C_RST}"
        return 1
    fi

    if [ ! -f "$ACME_HOME/acme.sh" ]; then
        echo -e "${C_FAIL}acme.sh not installed, please run --install first${C_RST}"
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

    echo -e "${C_INFO}Domain: $DOMAIN${C_RST}"
    echo -e "${C_INFO}Key type: $keylength${C_RST}"

    local issue_cmd="$ACME_HOME/acme.sh --issue"

    if [ "$AUTH_MODE" = "dns" ]; then
        if [ -z "$DNS_PROVIDER" ]; then
            echo -e "${C_FAIL}DNS mode requires --dns <provider>${C_RST}"
            show_dns_providers
            return 1
        fi
        echo -e "${C_INFO}Verification method: DNS-01 ($DNS_PROVIDER)${C_RST}"
        issue_cmd="$issue_cmd --dns $DNS_PROVIDER"
    elif [ "$AUTH_MODE" = "standalone" ]; then
        echo -e "${C_INFO}Verification method: HTTP-01 (standalone)${C_RST}"
        echo -e "${C_WARN}standalone mode requires port 80 to be free${C_RST}"
        issue_cmd="$issue_cmd --standalone"
    else
        echo -e "${C_FAIL}Please specify verification method: --dns <provider> or --standalone${C_RST}"
        return 1
    fi

    issue_cmd="$issue_cmd -d $DOMAIN -k $keylength"

    echo -e "${C_INFO}Execute: $issue_cmd${C_RST}"
    # shellcheck disable=SC2086
    bash $issue_cmd || {
        echo -e "${C_FAIL}Certificate issuance failed${C_RST}"
        return 1
    }

    echo -e "${C_OK}Certificate issued successfully: $DOMAIN${C_RST}"
    echo -e "${C_INFO}Certificate path: $ACME_HOME/${DOMAIN}_ecc/ (EC) or $ACME_HOME/${DOMAIN}/ (RSA)${C_RST}"
}

# ── Certificate renewal ──────────────────────────────────────────────────
renew_certs() {
    echo -e "${C_WARN}>>> Renew all certificates <<<${C_RST}"

    if [ ! -f "$ACME_HOME/acme.sh" ]; then
        echo -e "${C_FAIL}acme.sh Not installed${C_RST}"
        return 1
    fi

    echo -e "${C_INFO}[1/2] List issued certificates...${C_RST}"
    bash "$ACME_HOME/acme.sh" --list 2>/dev/null || true

    echo ""
    echo -e "${C_INFO}[2/2] Renew expiring certificates...${C_RST}"
    bash "$ACME_HOME/acme.sh" --renew-all 2>&1 || {
        echo -e "${C_WARN}Some certificate renewals may have failed, please check output above${C_RST}"
    }

    echo -e "${C_OK}Renewal check complete${C_RST}"
}

# ── Certificate deployment ──────────────────────────────────────────────────
deploy_cert() {
    echo -e "${C_WARN}>>> Deploy certificates to reverse proxy <<<${C_RST}"

    if [ -z "$DOMAIN" ]; then
        echo -e "${C_FAIL}Please specify domain via --domain${C_RST}"
        return 1
    fi
    if [ -z "$PROXY_TYPE" ]; then
        echo -e "${C_FAIL}Please specify reverse proxy type via --proxy (nginx/caddy/haproxy/apache)${C_RST}"
        return 1
    fi

    if [ ! -f "$ACME_HOME/acme.sh" ]; then
        echo -e "${C_FAIL}acme.sh Not installed${C_RST}"
        return 1
    fi

    mkdir -p "$OUTPUT_DIR/deploy"

    local cert_dir
    cert_dir="$ACME_HOME/${DOMAIN}_ecc"
    [ ! -d "$cert_dir" ] && cert_dir="$ACME_HOME/${DOMAIN}"
    if [ ! -d "$cert_dir" ]; then
        echo -e "${C_FAIL}Certificate for $DOMAIN not found, please issue first${C_RST}"
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
            echo -e "${C_INFO}Nginx config generated: $OUTPUT_DIR/deploy/nginx-ssl.conf${C_RST}"
            echo -e "${C_WARN}Deployment steps:${C_RST}"
            echo "  1. mkdir -p $deploy_dir"
            echo "  2. cp $fullchain $deploy_dir/fullchain.cer"
            echo "  3. cp $keyfile $deploy_dir/${DOMAIN}.key"
            echo "  4. Include the above config in nginx server block"
            echo "  5. nginx -t && systemctl reload nginx"
            ;;
        caddy)
            cat > "$OUTPUT_DIR/deploy/Caddyfile" <<EOF
# Caddy TLS configuration for $DOMAIN
# Generated by tls_lifecycle.sh
# Caddy auto-manages TLS, this file is only for manual certificate scenarios

$DOMAIN {
    tls $fullchain $keyfile {
        protocols tls1.2 tls1.3
        ciphers ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-RSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-RSA-AES256-GCM-SHA384
        alpn http/1.1 h2 h3
    }
    # Reverse proxy to backend
    reverse_proxy localhost:8080
}
EOF
            echo -e "${C_INFO}Caddyfile generated: $OUTPUT_DIR/deploy/Caddyfile${C_RST}"
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
            echo -e "${C_INFO}HAProxy config generated: $OUTPUT_DIR/deploy/haproxy-tls.cfg${C_RST}"
            echo -e "${C_WARN}HAProxy requires merging certificate and private key:${C_RST}"
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
            echo -e "${C_INFO}Apache config generated: $OUTPUT_DIR/deploy/apache-ssl.conf${C_RST}"
            ;;
        *)
            echo -e "${C_FAIL}Unsupported reverse proxy type: $PROXY_TYPE (available: nginx/caddy/haproxy/apache)${C_RST}"
            return 1
            ;;
    esac

    # Set acme.sh auto-deploy hook
    echo -e "${C_INFO}Setting acme.sh auto-renewal post-deploy hook...${C_RST}"
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
    echo -e "${C_WARN}Auto-deploy command (manually confirm execution):${C_RST}"
    echo "  $install_cert_cmd"
}

# ── Certificate revocation ──────────────────────────────────────────────────
revoke_cert() {
    echo -e "${C_WARN}>>> Revoke certificate <<<${C_RST}"

    if [ -z "$DOMAIN" ]; then
        echo -e "${C_FAIL}Please specify domain via --domain${C_RST}"
        return 1
    fi
    if [ ! -f "$ACME_HOME/acme.sh" ]; then
        echo -e "${C_FAIL}acme.sh Not installed${C_RST}"
        return 1
    fi

    echo -e "${C_WARN}About to revoke certificate for $DOMAIN, this operation is irreversible${C_RST}"
    read -r -p "Confirm revoke? (y/N): " ack
    if [[ ! "$ack" =~ ^[Yy]$ ]]; then
        echo -e "${C_INFO}Cancelled${C_RST}"
        return 0
    fi

    bash "$ACME_HOME/acme.sh" --revoke -d "$DOMAIN" 2>&1 || {
        echo -e "${C_FAIL}Revoke failed${C_RST}"
        return 1
    }
    echo -e "${C_OK}Certificate revoked: $DOMAIN${C_RST}"
}

# ── Certificate monitoring ──────────────────────────────────────────────────
monitor_certs() {
    echo -e "${C_WARN}>>> Certificate expiry monitoring <<<${C_RST}"

    echo -e "${C_INFO}Scanning TLS certificates in system...${C_RST}"
    echo ""

    local found=0
    local now_epoch
    now_epoch=$(date +%s)

    # Scan acme.sh managed certificates
    if [ -f "$ACME_HOME/acme.sh" ]; then
        echo -e "${C_INFO}[acme.sh managed certificates]${C_RST}"
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

    # Scan common certificate paths
    echo -e "${C_INFO}[System certificate files]${C_RST}"
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

    # Generate cron monitoring script
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
    echo -e "${C_INFO}Cron monitoring script generated: $OUTPUT_DIR/tls-monitor-cron.sh${C_RST}"
    echo -e "${C_INFO}Added to crontab: 0 8 * * * $OUTPUT_DIR/tls-monitor-cron.sh${C_RST}"

    if [ "$found" -eq 0 ]; then
        echo -e "${C_WARN}No certificate files found${C_RST}"
    fi
}

# ── TLS audit ──────────────────────────────────────────────────
audit_tls() {
    echo -e "${C_WARN}>>> TLS config audit (read-only) <<<${C_RST}"
    echo ""
    init_report

    # --- acme.sh status ---
    echo -e "${C_INFO}[acme.sh status]${C_RST}"
    run_check "TLS-001" "acme.sh Installed" test -f "$ACME_HOME/acme.sh"
    run_check "TLS-002" "acme.sh cron auto-renewal configured" \
        bash -c "crontab -l 2>/dev/null | grep -q acme.sh"
    run_check "TLS-003" "acme.sh default CA set" \
        bash -c "bash $ACME_HOME/acme.sh --info 2>/dev/null | grep -qi 'server\|ca'"

    # --- Certificate status ---
    echo ""
    echo -e "${C_INFO}[Certificate status]${C_RST}"

    local now_epoch
    now_epoch=$(date +%s)

    # Check acme.sh managed certificate expiry
    if [ -f "$ACME_HOME/acme.sh" ]; then
        local cert_list
        cert_list=$(bash "$ACME_HOME/acme.sh" --list 2>/dev/null | tail -n +2)
        if [ -n "$cert_list" ]; then
            local cert_count
            cert_count=$(echo "$cert_list" | wc -l | tr -d ' ')
            run_check "TLS-004" "$cert_count certificates managed" test "$cert_count" -gt 0

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
                                run_check "TLS-005" "$d Certificate not expired" bash -c "exit 1"
                            elif [ "$days_left" -lt 15 ]; then
                                run_check "TLS-005" "$d Certificate not expired ($days_left days remaining)" bash -c "exit 1"
                            elif [ "$days_left" -lt 30 ]; then
                                run_check "TLS-005" "$d Certificate not expired ($days_left days remaining)" bash -c "exit 2"
                            else
                                run_check "TLS-005" "$d Certificate not expired ($days_left days remaining" true
                            fi
                        fi
                    fi
                fi
            done
        else
            run_check "TLS-004" "Certificates managed" bash -c "exit 2"
        fi
    else
        run_check "TLS-004" "Certificates managed" bash -c "exit 2"
    fi

    # --- Certificate key strength ---
    echo ""
    echo -e "${C_INFO}[Certificate key strength]${C_RST}"

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
                run_check "TLS-006" "$certfile Key strength: EC-$key_size" true
            else
                run_check "TLS-006" "$certfile Key strength: EC-$key_size (weak)" bash -c "exit 2"
            fi
        elif [ "$key_type" = "rsa" ]; then
            if [ "$key_size" -ge 2048 ]; then
                run_check "TLS-006" "$certfile Key strength: RSA-$key_size" true
            else
                run_check "TLS-006" "$certfile Key strength: RSA-$key_size (weak)" bash -c "exit 1"
            fi
        fi
    done
    [ "$found_cert" -eq 0 ] && run_check "TLS-006" "Certificate key strength check" bash -c "exit 2"

    # --- TLS protocol versions ---
    echo ""
    echo -e "${C_INFO}[TLS protocol versions]${C_RST}"

    # Nginx
    if check_cmd nginx; then
        local nginx_ssl
        nginx_ssl=$(nginx -T 2>/dev/null | grep -i "ssl_protocols" | head -1)
        if echo "$nginx_ssl" | grep -qi "TLSv1.3"; then
            run_check "TLS-007" "Nginx enables TLS 1.3" true
        elif echo "$nginx_ssl" | grep -qi "TLSv1.2"; then
            run_check "TLS-007" "Nginx enables TLS 1.3 (only 1.2)" bash -c "exit 2"
        else
            run_check "TLS-007" "Nginx enables TLS 1.3" bash -c "exit 2"
        fi
        if echo "$nginx_ssl" | grep -qi "TLSv1\b" && ! echo "$nginx_ssl" | grep -qi "TLSv1\.1"; then
            run_check "TLS-008" "Nginx disables TLS 1.0/1.1" true
        else
            run_check "TLS-008" "Nginx disables TLS 1.0/1.1" bash -c "exit 2"
        fi
    else
        run_check "TLS-007" "Nginx TLS 1.3" bash -c "exit 2"
        run_check "TLS-008" "Nginx disables TLS 1.0/1.1" bash -c "exit 2"
    fi

    # Caddy
    if check_cmd caddy; then
        run_check "TLS-009" "Caddy automatic TLS management" true
    else
        run_check "TLS-009" "Caddy automatic TLS management" bash -c "exit 2"
    fi

    # --- HSTS ---
    echo ""
    echo -e "${C_INFO}[HSTS]${C_RST}"

    if check_cmd nginx; then
        local nginx_hsts
        nginx_hsts=$(nginx -T 2>/dev/null | grep -i "Strict-Transport-Security" | head -1)
        if [ -n "$nginx_hsts" ]; then
            run_check "TLS-010" "Nginx HSTS configured" true
        else
            run_check "TLS-010" "Nginx HSTS configured" bash -c "exit 1"
        fi
    else
        run_check "TLS-010" "Nginx HSTS" bash -c "exit 2"
    fi

    # --- Certificate auto-renewal ---
    echo ""
    echo -e "${C_INFO}[Auto-renewal]${C_RST}"

    if [ -f "$ACME_HOME/acme.sh" ]; then
        local cron_check
        cron_check=$(crontab -l 2>/dev/null | grep -c "acme.sh.*cron" || true)
        if [ "$cron_check" -gt 0 ]; then
            run_check "TLS-011" "acme.sh cron auto-renewal configured" true
        else
            run_check "TLS-011" "acme.sh cron auto-renewal configured" bash -c "exit 1"
        fi
    else
        run_check "TLS-011" "acme.sh cron auto-renewal" bash -c "exit 2"
    fi

    if check_cmd certbot; then
        local certbot_timer
        certbot_timer=$(systemctl list-timers 2>/dev/null | grep -c certbot || true)
        if [ "$certbot_timer" -gt 0 ]; then
            run_check "TLS-012" "certbot auto-renewal timer configured" true
        else
            run_check "TLS-012" "certbot auto-renewal timer configured" bash -c "exit 2"
        fi
    else
        run_check "TLS-012" "certbot auto-renewal timer" bash -c "exit 2"
    fi

    # --- OCSP Stapling ---
    echo ""
    echo -e "${C_INFO}[OCSP Stapling]${C_RST}"

    if check_cmd nginx; then
        local nginx_ocsp
        nginx_ocsp=$(nginx -T 2>/dev/null | grep -i "ssl_stapling" | head -1)
        if [ -n "$nginx_ocsp" ]; then
            run_check "TLS-013" "Nginx OCSP Stapling configured" true
        else
            run_check "TLS-013" "Nginx OCSP Stapling configured" bash -c "exit 2"
        fi
    else
        run_check "TLS-013" "Nginx OCSP Stapling" bash -c "exit 2"
    fi

    print_summary
}

# ── Interactive wizard ────────────────────────────────────────────────
interactive_wizard() {
    while true; do
        clear
        echo -e "${C_OK}══════════════════════════════${C_RST}"
        echo -e "${C_OK}   TLS certificate lifecycle management      ${C_RST}"
        echo -e "${C_OK}══════════════════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 📦 Install acme.sh"
        echo -e "  ${C_WARN}2.${C_RST} 🔑 Issue certificate"
        echo -e "  ${C_WARN}3.${C_RST} 🔄 Renew all certificates"
        echo -e "  ${C_WARN}4.${C_RST} 📋 Deploy certificates to reverse proxy"
        echo -e "  ${C_WARN}5.${C_RST} ❌ Revoke certificate"
        echo -e "  ${C_WARN}6.${C_RST} 📊 Monitor certificate expiry"
        echo -e "  ${C_WARN}7.${C_RST} 🛡️ Audit TLS config (read-only)"
        echo -e "  ${C_WARN}8.${C_RST} 📋 Show DNS provider list"
        echo -e "  ${C_WARN}0.${C_RST} Back"
        echo
        local pick
        read -r -p "Select [0-8]: " pick
        case $pick in
            1) install_acme; wait_key ;;
            2)
                read -r -p "Domain: " DOMAIN
                echo "Verification method: 1) DNS-01  2) HTTP-01 (standalone)"
                read -r -p "Select [1-2]: " am
                case $am in
                    1)
                        read -r -p "DNS provider (e.g. cloudflare): " DNS_PROVIDER
                        AUTH_MODE="dns"
                        ;;
                    2) AUTH_MODE="standalone" ;;
                    *) echo "Invalid"; sleep 1; continue ;;
                esac
                issue_cert; wait_key
                ;;
            3) renew_certs; wait_key ;;
            4)
                read -r -p "Domain: " DOMAIN
                echo "Reverse proxy type: 1) Nginx  2) Caddy  3) HAProxy  4) Apache"
                read -r -p "Select [1-4]: " pt
                case $pt in
                    1) PROXY_TYPE="nginx" ;;
                    2) PROXY_TYPE="caddy" ;;
                    3) PROXY_TYPE="haproxy" ;;
                    4) PROXY_TYPE="apache" ;;
                    *) echo "Invalid"; sleep 1; continue ;;
                esac
                deploy_cert; wait_key
                ;;
            5)
                read -r -p "Domain: " DOMAIN
                revoke_cert; wait_key
                ;;
            6) monitor_certs; wait_key ;;
            7) audit_tls; wait_key ;;
            8) show_dns_providers; wait_key ;;
            0) break ;;
            *) echo -e "${C_FAIL}Invalid input${C_RST}"; sleep 1 ;;
        esac
    done
}

# ── Main entry ────────────────────────────────────────────────────
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
        *) echo "Unknown mode: $MODE"; exit 1 ;;
    esac
}

main "$@"
