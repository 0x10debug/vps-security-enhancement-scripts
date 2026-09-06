#!/bin/bash
# shellcheck disable=SC2006  # Caddyfile heredoc uses escaped Caddy backtick strings; not shell substitution
# ════════════════════════════════════════════════════════════
#  waf_setup.sh — Web Application Firewall (Coraza + OWASP CRS v4)
#  Supported OS: Linux host
#  Run as: root
#  Mode: Deploy + config generation + audit (does not directly modify running reverse proxies)
#  Reference: corazawaf/coraza
#         zzmzm/tiyi
#         socfortress/waf-platform-public
#         OWASP Core Rule Set v4
#  Project home: https://github.com/0x10debug/vps-security-enhancement-scripts
# ════════════════════════════════════════════════════════════
#
# Usage:
#   sudo ./scripts/waf_setup.sh                    # Interactive wizard
#   sudo ./scripts/waf_setup.sh --install          # Install Coraza + CRS v4
#   sudo ./scripts/waf_setup.sh --caddy            # Generate Caddy + Coraza config
#   sudo ./scripts/waf_setup.sh --nginx            # Generate Nginx + Coraza config
#   sudo ./scripts/waf_setup.sh --haproxy          # Generate HAProxy + Coraza config
#   sudo ./scripts/waf_setup.sh --tune             # Generate rule tuning config
#   sudo ./scripts/waf_setup.sh --audit            # Read-only audit WAF config
#   sudo ./scripts/waf_setup.sh --output ./waf-configs
#   sudo ./scripts/waf_setup.sh --domain waf.example.com
#
# Exit codes:
#   0 — Success
#   1 — Parameter error / missing dependency
#   2 — Some features unavailable

set -euo pipefail

APP_NAME="waf_setup"
APP_VER="v3.0.0"
MODE=""
OUTPUT_DIR=""
DOMAIN=""
REPORT_DIR="/var/log/waf-audit"
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
            --caddy) MODE="caddy"; shift ;;
            --nginx) MODE="nginx"; shift ;;
            --haproxy) MODE="haproxy"; shift ;;
            --tune) MODE="tune"; shift ;;
            --audit) MODE="audit"; shift ;;
            --output) OUTPUT_DIR="$2"; shift 2 ;;
            --domain) DOMAIN="$2"; shift 2 ;;
            -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
            *) echo "Unknown parameter: $1"; exit 1 ;;
        esac
    done
    if [ -z "$MODE" ]; then
        MODE="interactive"
    fi
    if [ -z "$OUTPUT_DIR" ]; then
        OUTPUT_DIR="./waf-configs"
    fi
    if [ -z "$DOMAIN" ]; then
        DOMAIN="waf.vps.local"
    fi
}

# ── Report initialization ───────────────────────────────────────────────
init_report() {
    mkdir -p "$REPORT_DIR" 2>/dev/null || REPORT_DIR="/tmp/waf-audit"
    mkdir -p "$REPORT_DIR" 2>/dev/null || true
    REPORT_FILE="$REPORT_DIR/waf-audit-${TIMESTAMP}.txt"
    {
        echo "WAF Security Audit Report"
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

# ── Coraza + CRS installation ────────────────────────────────────────
install_coraza() {
    echo -e "${C_WARN}>>> Install Coraza WAF + OWASP CRS v4 <<<${C_RST}"
    mkdir -p "$OUTPUT_DIR/coraza"
    mkdir -p "$OUTPUT_DIR/crs"

    # Download OWASP CRS v4
    local crs_version="4.0.0"
    echo -e "${C_INFO}[1/3] Download OWASP CRS v${crs_version}...${C_RST}"
    curl -sL "https://github.com/coreruleset/coreruleset/archive/refs/tags/v${crs_version}.tar.gz" \
        -o /tmp/crs.tar.gz
    tar xzf /tmp/crs.tar.gz -C "$OUTPUT_DIR/crs/" --strip-components=1 2>/dev/null || {
        echo -e "${C_WARN}CRS download failed, generating minimal config as fallback${C_RST}"
        mkdir -p "$OUTPUT_DIR/crs/rules"
        cat > "$OUTPUT_DIR/crs/crs-setup.conf" <<'EOF'
# OWASP CRS v4 — Minimal Setup (fallback)
# SecRuleEngine On
# SecDefaultAction "phase:1,pass,log,tag:'OWASP_CRS'"
EOF
    }
    rm -f /tmp/crs.tar.gz

    # Generate Coraza config
    echo -e "${C_INFO}[2/3] Generate Coraza main config...${C_RST}"
    cat > "$OUTPUT_DIR/coraza/coraza.conf" <<'EOF'
# Coraza WAF Configuration
# Generated by waf_setup.sh

# Enable WAF engine
SecRuleEngine On

# Request body limit
SecRequestBodyLimit 134217728
SecRequestBodyNoFilesLimit 1048576
SecRequestBodyInMemoryLimit 131072

# Response body limit
SecResponseBodyLimit 524288

# Default action
SecDefaultAction "phase:1,pass,log,tag:'OWASP_CRS'"
SecDefaultAction "phase:2,pass,log,tag:'OWASP_CRS'"

# Include OWASP CRS
Include crs/crs-setup.conf
Include crs/rules/REQUEST-901-INITIALIZATION.conf
Include crs/rules/REQUEST-905-COMMON-PROTECTION.conf
Include crs/rules/REQUEST-911-METHOD-ENFORCEMENT.conf
Include crs/rules/REQUEST-913-SCANNER-DETECTION.conf
Include crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf
Include crs/rules/REQUEST-921-PROTOCOL-ATTACK.conf
Include crs/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf
Include crs/rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf
Include crs/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf
Include crs/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf
Include crs/rules/REQUEST-934-APPLICATION-ATTACK-GENERIC.conf
Include crs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf
Include crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf
Include crs/rules/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf
Include crs/rules/REQUEST-944-APPLICATION-ATTACK-JAVA.conf
Include crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf
Include crs/rules/RESPONSE-950-DATA-LEAKAGE.conf
Include crs/rules/RESPONSE-951-DATA-LEAKAGE-SQL.conf
Include crs/rules/RESPONSE-952-DATA-LEAKAGE-JAVA.conf
Include crs/rules/RESPONSE-953-DATA-LEAKAGE-PHP.conf
Include crs/rules/RESPONSE-954-DATA-LEAKAGE-IIS.conf
Include crs/rules/RESPONSE-959-BLOCKING-EVALUATION.conf

# Exclusion rules (adjust as needed)
# Include crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf

# Logging config
SecDebugLog /var/log/coraza/debug.log
SecDebugLogLevel 0
SecAuditEngine RelevantOnly
SecAuditLog /var/log/coraza/audit.log
SecAuditLogFormat JSON
SecAuditLogParts AFH
EOF

    # Generate Dockerfile
    echo -e "${C_INFO}[3/3] Generate Coraza Docker deployment files...${C_RST}"
    cat > "$OUTPUT_DIR/coraza/Dockerfile" <<'EOF'
# Coraza WAF Docker Image
FROM golang:1.22-alpine AS builder
RUN apk add --no-cache git
RUN go install github.com/corazawaf/coraza-spoa@latest

FROM alpine:3.20
RUN apk add --no-cache ca-certificates haproxy
COPY --from=builder /go/bin/coraza-spoa /usr/local/bin/coraza-spoa
COPY coraza.conf /etc/coraza/coraza.conf
COPY crs/ /etc/coraza/crs/
RUN mkdir -p /var/log/coraza
EXPOSE 9000
CMD ["coraza-spoa", "-config", "/etc/coraza/coraza.conf"]
EOF

    cat > "$OUTPUT_DIR/coraza/docker-compose.yml" <<EOF
# Coraza WAF Docker Compose
# Generated by waf_setup.sh
version: "3.8"
services:
  coraza:
    build: .
    container_name: coraza-waf
    restart: unless-stopped
    ports:
      - "127.0.0.1:9000:9000"
    volumes:
      - ./coraza.conf:/etc/coraza/coraza.conf:ro
      - ./crs:/etc/coraza/crs:ro
      - coraza-logs:/var/log/coraza
    healthcheck:
      test: ["CMD", "nc", "-z", "localhost", "9000"]
      interval: 30s
      timeout: 5s
      retries: 3
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"

volumes:
  coraza-logs:
EOF

    cat > "$OUTPUT_DIR/coraza/README.md" <<'EOF'
# Coraza WAF Deployment

## Overview
Coraza is a Go-based WAF engine compatible with ModSecurity SecRules.
This setup uses Coraza as a SPOA (HAProxy Stream Processing Offload Agent)
with OWASP CRS v4 rules.

## Deployment
1. `cd coraza/`
2. `docker compose up -d`
3. Configure HAProxy to use Coraza SPOA (see haproxy config)

## Configuration
- `coraza.conf` — Main WAF configuration
- `crs/` — OWASP Core Rule Set v4
- `Dockerfile` — Coraza SPOA image
- `docker-compose.yml` — Docker deployment

## Verification
```bash
# Test SQL injection detection
curl -H "Host: $DOMAIN" "http://localhost/?id=1' OR '1'='1"
# Should be blocked with 403
```
EOF

    echo -e "${C_OK}Coraza + CRS v4 installation config generated to: $OUTPUT_DIR/coraza/${C_RST}"
}

# ── Caddy + Coraza config ──────────────────────────────────────
generate_caddy_config() {
    echo -e "${C_WARN}>>> Generate Caddy + Coraza config <<<${C_RST}"
    mkdir -p "$OUTPUT_DIR/caddy"

    cat > "$OUTPUT_DIR/caddy/Caddyfile" <<EOF
# Caddy + Coraza WAF Configuration
# Generated by waf_setup.sh

{
    # Global options
    order coraza_waf before reverse_proxy
}

# WAF site
$DOMAIN {
    # Coraza WAF
    coraza_waf {
        directives `
            Include /etc/coraza/coraza.conf
        `
    }

    # Reverse proxy to backend
    reverse_proxy localhost:8080

    # Logging
    log {
        output file /var/log/caddy/waf-access.log
        format json
    }
}

# API site (stricter rules)
api.$DOMAIN {
    coraza_waf {
        directives `
            Include /etc/coraza/coraza.conf
            SecRuleEngine On
        `
    }

    reverse_proxy localhost:3000
}
EOF

    cat > "$OUTPUT_DIR/caddy/docker-compose.yml" <<'EOF'
# Caddy + Coraza WAF Docker Compose
version: "3.8"
services:
  caddy:
    image: caddy:2.9.0-alpine
    container_name: caddy-waf
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy-data:/data
      - caddy-config:/config
      - ../coraza:/etc/coraza:ro
      - caddy-logs:/var/log/caddy
    healthcheck:
      test: ["CMD", "caddy", "version"]
      interval: 30s
      timeout: 5s
      retries: 3
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"

volumes:
  caddy-data:
  caddy-config:
  caddy-logs:
EOF

    cat > "$OUTPUT_DIR/caddy/README.md" <<'EOF'
# Caddy + Coraza WAF

## Overview
Caddy v2.9 with Coraza WAF plugin. Automatic HTTPS + WAF protection.

## Deployment
1. Ensure Coraza configs are in ../coraza/
2. `docker compose up -d`
3. Caddy will auto-provision TLS certificates

## Configuration
- `Caddyfile` — Caddy config with coraza_waf directive
- `docker-compose.yml` — Docker deployment

## Notes
- Caddy's Coraza plugin uses caddy-coraza module
- For production, build a custom Caddy image with the plugin:
  ```bash
  xcaddy build --with github.com/corazawaf/coraza-caddy
  ```
EOF

    echo -e "${C_OK}Caddy + Coraza config generated to: $OUTPUT_DIR/caddy/${C_RST}"
}

# ── Nginx + Coraza config ──────────────────────────────────────
generate_nginx_config() {
    echo -e "${C_WARN}>>> Generate Nginx + Coraza config <<<${C_RST}"
    mkdir -p "$OUTPUT_DIR/nginx"

    cat > "$OUTPUT_DIR/nginx/nginx.conf" <<'EOF'
# Nginx + Coraza WAF Configuration
# Generated by waf_setup.sh

worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format waf '$remote_addr - $remote_user [$time_local] '
                   '"$request" $status $body_bytes_sent '
                   '"$http_referer" "$http_user_agent" '
                   'waf_action=$coraza_action';

    access_log /var/log/nginx/waf-access.log waf;

    # Coraza SPOA config (via stream module)
    # Requires nginx-plus or compiling coraza-nginx module

    upstream backend {
        server 127.0.0.1:8080;
    }

    server {
        listen 80;
        server_name _;

        # Coraza WAF (via module)
        # coraza on;
        # coraza_config_file /etc/coraza/coraza.conf;

        # Basic protection
        limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
        limit_req zone=general burst=20 nodelay;

        # Block common attacks
        if ($request_method !~ ^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)$) {
            return 405;
        }

        location / {
            proxy_pass http://backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Health check
        location /health {
            access_log off;
            return 200 "healthy\n";
        }
    }
}
EOF

    cat > "$OUTPUT_DIR/nginx/docker-compose.yml" <<'EOF'
# Nginx + Coraza WAF Docker Compose
# Note: Requires custom Nginx build with coraza-nginx module
version: "3.8"
services:
  nginx:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: nginx-waf
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ../coraza:/etc/coraza:ro
      - nginx-logs:/var/log/nginx
    healthcheck:
      test: ["CMD", "nginx", "-t"]
      interval: 30s
      timeout: 5s
      retries: 3

volumes:
  nginx-logs:
EOF

    cat > "$OUTPUT_DIR/nginx/Dockerfile" <<'EOF'
# Nginx with Coraza module
FROM golang:1.22-alpine AS builder
RUN apk add --no-cache git gcc musl-dev
RUN go install github.com/corazawaf/coraza-nginx@latest

FROM nginx:1.27.2-alpine
COPY --from=builder /go/bin/coraza-nginx /usr/local/bin/coraza-nginx
# Note: This is a simplified Dockerfile.
# For production, you need to compile nginx with the coraza module.
EOF

    cat > "$OUTPUT_DIR/nginx/README.md" <<'EOF'
# Nginx + Coraza WAF

## Overview
Nginx with Coraza WAF module. Requires custom Nginx build.

## Deployment
1. Build custom Nginx with coraza-nginx module
2. `docker compose up -d`

## Configuration
- `nginx.conf` — Nginx config with Coraza directives
- `Dockerfile` — Custom Nginx build (simplified)
- `docker-compose.yml` — Docker deployment

## Notes
- Nginx Coraza integration requires module compilation
- For HAProxy, use the SPOA approach (see haproxy config)
- Consider using Caddy for easier Coraza integration
EOF

    echo -e "${C_OK}Nginx + Coraza config generated to: $OUTPUT_DIR/nginx/${C_RST}"
}

# ── HAProxy + Coraza config ────────────────────────────────────
generate_haproxy_config() {
    echo -e "${C_WARN}>>> Generate HAProxy + Coraza SPOA config <<<${C_RST}"
    mkdir -p "$OUTPUT_DIR/haproxy"

    cat > "$OUTPUT_DIR/haproxy/haproxy.cfg" <<'EOF'
# HAProxy + Coraza SPOA Configuration
# Generated by waf_setup.sh

global
    log stdout format raw local0
    maxconn 4096
    daemon

defaults
    log global
    mode http
    option httplog
    option dontlognull
    timeout connect 5s
    timeout client 50s
    timeout server 50s

# Coraza SPOA (Stream Processing Offload Agent)
backend coraza_spoa
    mode tcp
    server s1 127.0.0.1:9000

frontend waf_frontend
    bind *:80
    bind *:443 ssl crt /etc/haproxy/ssl/cert.pem alpn h2,http/1.1

    # Coraza WAF check
    filter spoe engine coraza config /etc/haproxy/coraza-spoa.cfg

    # If WAF blocks, return 403
    http-request deny status 403 if { var(txn.coraza.action) -m str "denied" }

    # Rate limiting
    http-request track-sc0 src table rate_limit
    http-request deny status 429 if { sc_http_req_rate(0) gt 100 }

    default_backend app_backend

backend app_backend
    balance roundrobin
    option httpchk GET /health
    server app1 127.0.0.1:8080 check

# Rate limit table
backend rate_limit
    stick-table type ip size 100k expire 30s store http_req_rate(10s)
EOF

    cat > "$OUTPUT_DIR/haproxy/coraza-spoa.cfg" <<'EOF'
# Coraza SPOA Configuration for HAProxy
# Generated by waf_setup.sh

[spos]
spoa-agent = coraza
spoa-server = 127.0.0.1:9000

[coraza]
# WAF config files
config = /etc/coraza/coraza.conf

# Request parts to inspect
include = req_headers,req_body

# Response parts to inspect
include = res_headers,res_body
EOF

    cat > "$OUTPUT_DIR/haproxy/docker-compose.yml" <<'EOF'
# HAProxy + Coraza WAF Docker Compose
version: "3.8"
services:
  haproxy:
    image: haproxy:3.1.0-alpine
    container_name: haproxy-waf
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro
      - ./coraza-spoa.cfg:/usr/local/etc/haproxy/coraza-spoa.cfg:ro
      - ../coraza:/etc/coraza:ro
      - haproxy-logs:/var/log/haproxy
    depends_on:
      - coraza
    healthcheck:
      test: ["CMD", "haproxy", "-c", "-f", "/usr/local/etc/haproxy/haproxy.cfg"]
      interval: 30s
      timeout: 5s
      retries: 3

  coraza:
    build:
      context: ../coraza
      dockerfile: Dockerfile
    container_name: coraza-spoa
    restart: unless-stopped
    volumes:
      - ../coraza/coraza.conf:/etc/coraza/coraza.conf:ro
      - ../coraza/crs:/etc/coraza/crs:ro

volumes:
  haproxy-logs:
EOF

    cat > "$OUTPUT_DIR/haproxy/README.md" <<'EOF'
# HAProxy + Coraza WAF

## Overview
HAProxy with Coraza SPOA (Stream Processing Offload Agent).
This is the recommended integration for production WAF deployment.

## Architecture
```
Client → HAProxy (443) → Coraza SPOA (9000) → Backend (8080)
```

## Deployment
1. Ensure Coraza configs are in ../coraza/
2. `docker compose up -d`
3. HAProxy will forward traffic through Coraza SPOA for inspection

## Configuration
- `haproxy.cfg` — HAProxy config with SPOA filter
- `coraza-spoa.cfg` — SPOA connection config
- `docker-compose.yml` — Docker deployment (HAProxy + Coraza)

## Advantages
- HAProxy SPOA is the native Coraza integration method
- High performance (Go SPOA process)
- Non-blocking inspection
EOF

    echo -e "${C_OK}HAProxy + Coraza config generated to: $OUTPUT_DIR/haproxy/${C_RST}"
}

# ── Rule tuning config ─────────────────────────────────────────────
generate_tuning_config() {
    echo -e "${C_WARN}>>> Generate WAF rule tuning config <<<${C_RST}"
    mkdir -p "$OUTPUT_DIR/tuning"

    cat > "$OUTPUT_DIR/tuning/crs-setup.conf" <<'EOF'
# OWASP CRS v4 Tuning Configuration
# Generated by waf_setup.sh
#
# This file contains tuning parameters to reduce false positives
# while maintaining strong security posture.

# ── Anomaly scoring threshold ──
# Default 5 (inbound) / 4 (outbound)
# Lower = more permissive, Higher = more strict
SecAction "id:900100,phase:1,pass,nolog,setvar:tx.inbound_anomaly_score_threshold=5"
SecAction "id:900101,phase:1,pass,nolog,setvar:tx.outbound_anomaly_score_threshold=4"

# ── Concurrency detection ──
# Merge scores when multiple rules trigger simultaneously
SecAction "id:900110,phase:1,pass,nolog,setvar:tx.paranoia_level=1"

# ── Method allowlist ──
# Allowed methods: GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH
SecAction "id:900200,phase:1,pass,nolog,setvar:tx.allowed_methods='GET HEAD POST OPTIONS PUT DELETE PATCH'"

# ── Content-Type allowlist ──
SecAction "id:900220,phase:1,pass,nolog,setvar:tx.allowed_content_types='application/x-www-form-urlencoded|multipart/form-data|text/xml|application/xml|application/json|charset=utf-8'"

# ── Exclusion rules (reduce false positives) ──
# Exclude SQL injection check for specific parameters (for APIs)
# SecRuleUpdateTarget 942100 "!ARGS:api_key"
# SecRuleUpdateTarget 942100 "!ARGS:search_query"

# Exclude XSS check for specific paths (for rich text editors)
# SecRuleUpdateTarget 941100 "!ARGS:content"
# SecRuleUpdateTarget 941100 "!ARGS:description"

# ── Geo-location restrictions ──
# Requires MaxMind GeoIP2 installation
# SecGeoLookupDb /etc/geoip/GeoLite2-City.mmdb
# SecRule REMOTE_ADDR "@geoLookup" "chain,id:900700,phase:1,deny,status:403"
#     SecRule GEO:COUNTRY_CODE "!@in US CA GB DE JP" "msg:'Blocked by GeoIP'"

# ── Rate limiting ──
# Rate limiting via Coraza
# SecAction "id:900800,phase:1,pass,nolog,setvar:tx.rate_limit=100"

# ── Logging level ──
# Production recommendation: 0 (log only)
# Debug recommendation: 3 (verbose logging)
SecDebugLogLevel 0
EOF

    cat > "$OUTPUT_DIR/tuning/false-positive-handling.md" <<'EOF'
# WAF False Positive Handling Guide

## Overview
False positives (FP) are legitimate requests blocked by WAF rules.
This guide helps identify and resolve FPs without compromising security.

## Step 1: Identify False Positives
Monitor the Coraza audit log:
```bash
tail -f /var/log/coraza/audit.log | jq '.transaction.request.uri, .rules[].msg'
```

## Step 2: Analyze the Rule
Each blocked request includes:
- Rule ID (e.g., 942100 = SQL Injection)
- Matched data (which parameter triggered)
- Rule message

## Step 3: Create Exclusion
For legitimate requests that trigger rules, create targeted exclusions:

### Exclude specific parameter from a rule:
```apache
SecRuleUpdateTarget 942100 "!ARGS:search_query"
```

### Exclude specific parameter from all rules:
```apache
SecRuleRemoveById 942100 "ARGS:search_query"
```

### Exclude specific URL from a rule:
```apache
SecRuleRemoveById 942100 "REQUEST_URI:/api/search"
```

## Step 4: Adjust Paranoia Level
- PL1: Default, minimal FP
- PL2: More rules, some FP
- PL3: Aggressive, more FP
- PL4: Paranoid, many FP

```apache
SecAction "id:900110,phase:1,pass,nolog,setvar:tx.paranoia_level=1"
```

## Step 5: Use Anomaly Scoring
Instead of blocking on first match, use anomaly scoring:
- Each rule adds points to a score
- Request is blocked only if total score exceeds threshold
- This allows legitimate requests with minor matches to pass

## Common False Positives
| Rule | Common FP Cause | Fix |
|------|----------------|-----|
| 942100 (SQLi) | Search queries with SQL keywords | Exclude search parameter |
| 941100 (XSS) | Rich text editors with HTML | Exclude content parameter |
| 920300 (Protocol) | APIs with custom headers | Add header to allowed list |
| 932100 (RCE) | Shell-like commands in text | Exclude specific parameter |

## Testing After Changes
```bash
# Test legitimate request passes
curl "https://$DOMAIN/search?q=normal+query"
# Test attack is still blocked
curl "https://$DOMAIN/?id=1' OR '1'='1"
```
EOF

    cat > "$OUTPUT_DIR/tuning/README.md" <<'EOF'
# WAF Rule Tuning

## Overview
Tuning configuration for OWASP CRS v4 to balance security and usability.

## Files
- `crs-setup.conf` — CRS tuning parameters (anomaly scoring, paranoia level, exclusions)
- `false-positive-handling.md` — Guide for identifying and resolving false positives

## Key Parameters
- **inbound_anomaly_score_threshold**: 5 (default), lower = more permissive
- **paranoia_level**: 1 (default), higher = more rules but more FPs
- **allowed_methods**: HTTP methods that bypass method enforcement
- **allowed_content_types**: Content types that bypass content type checks

## Deployment
1. Copy crs-setup.conf to /etc/coraza/crs/crs-setup.conf
2. Restart Coraza: `docker restart coraza-spoa`
3. Monitor for false positives
4. Adjust exclusions as needed
EOF

    echo -e "${C_OK}Rule tuning config generated to: $OUTPUT_DIR/tuning/${C_RST}"
}

# ── Audit mode ─────────────────────────────────────────────────
audit_waf() {
    echo -e "${C_WARN}>>> WAF security audit <<<${C_RST}"
    echo -e "${C_INFO}Read-only mode, no configuration modified${C_RST}"
    echo ""

    init_report

    echo -e "${C_INFO}── Coraza installation check ──${C_RST}"

    run_check "WAF-1.1" "Coraza config file exists" \
        bash -c "find /etc/coraza /etc/nginx /etc/caddy /etc/haproxy -name 'coraza*' -o -name '*waf*' 2>/dev/null | head -1 | grep -q . && echo 'config found' && return 0 || echo 'no WAF config found' && return 2"

    run_check "WAF-1.2" "OWASP CRS rules directory exists" \
        bash -c "find /etc/coraza /opt/coraza -name 'crs' -type d 2>/dev/null | head -1 | grep -q . && echo 'CRS directory found' && return 0 || echo 'CRS directory not found' && return 2"

    run_check "WAF-1.3" "CRS v4 rules file exists" \
        bash -c "find / -path '*/crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf' 2>/dev/null | head -1 | grep -q . && echo 'CRS v4 SQLi rule found' && return 0 || echo 'CRS v4 rules not found' && return 2"

    echo ""
    echo -e "${C_INFO}── WAF engine status ──${C_RST}"

    run_check "WAF-2.1" "Coraza SPOA container running" \
        bash -c "docker ps --format '{{.Names}}' 2>/dev/null | grep -qi coraza && echo 'coraza container running' && return 0 || echo 'coraza container not running' && return 2"

    run_check "WAF-2.2" "WAF engine enabled (SecRuleEngine On)" \
        bash -c "find /etc/coraza -name '*.conf' -exec grep -l 'SecRuleEngine On' {} \; 2>/dev/null | head -1 | grep -q . && echo 'WAF engine enabled' && return 0 || echo 'WAF engine may be disabled' && return 2"

    run_check "WAF-2.3" "Request body size limit configured" \
        bash -c "find /etc/coraza -name '*.conf' -exec grep -l 'SecRequestBodyLimit' {} \; 2>/dev/null | head -1 | grep -q . && echo 'request body limit configured' && return 0 || echo 'request body limit not configured' && return 2"

    echo ""
    echo -e "${C_INFO}── Reverse proxy integration check ──${C_RST}"

    run_check "WAF-3.1" "HAProxy SPOA integration configured" \
        bash -c "grep -q 'coraza_spoa\|filter spoe' /etc/haproxy/haproxy.cfg 2>/dev/null && echo 'HAProxy SPOA configured' && return 0 || echo 'HAProxy SPOA not configured' && return 2"

    run_check "WAF-3.2" "Caddy Coraza plugin configured" \
        bash -c "grep -q 'coraza_waf' /etc/caddy/Caddyfile 2>/dev/null && echo 'Caddy Coraza configured' && return 0 || echo 'Caddy Coraza not configured' && return 2"

    run_check "WAF-3.3" "Nginx Coraza module configured" \
        bash -c "grep -q 'coraza' /etc/nginx/nginx.conf 2>/dev/null && echo 'Nginx Coraza configured' && return 0 || echo 'Nginx Coraza not configured' && return 2"

    echo ""
    echo -e "${C_INFO}── Rule config check ──${C_RST}"

    run_check "WAF-4.1" "Anomaly scoring mode enabled" \
        bash -c "find /etc/coraza -name '*.conf' -exec grep -l 'inbound_anomaly_score_threshold' {} \; 2>/dev/null | head -1 | grep -q . && echo 'anomaly scoring enabled' && return 0 || echo 'anomaly scoring not configured' && return 2"

    run_check "WAF-4.2" "SQL injection protection rules loaded" \
        bash -c "find / -path '*/crs/rules/REQUEST-942-*.conf' 2>/dev/null | head -1 | grep -q . && echo 'SQLi rules loaded' && return 0 || echo 'SQLi rules not found' && return 2"

    run_check "WAF-4.3" "XSS protection rules loaded" \
        bash -c "find / -path '*/crs/rules/REQUEST-941-*.conf' 2>/dev/null | head -1 | grep -q . && echo 'XSS rules loaded' && return 0 || echo 'XSS rules not found' && return 2"

    run_check "WAF-4.4" "RCE protection rules loaded" \
        bash -c "find / -path '*/crs/rules/REQUEST-932-*.conf' 2>/dev/null | head -1 | grep -q . && echo 'RCE rules loaded' && return 0 || echo 'RCE rules not found' && return 2"

    echo ""
    echo -e "${C_INFO}── Logging and monitoring ──${C_RST}"

    run_check "WAF-5.1" "Audit logging configured" \
        bash -c "find /etc/coraza -name '*.conf' -exec grep -l 'SecAuditLog' {} \; 2>/dev/null | head -1 | grep -q . && echo 'audit log configured' && return 0 || echo 'audit log not configured' && return 2"

    run_check "WAF-5.2" "Audit log file exists" \
        bash -c "find /var/log/coraza -name 'audit.log' 2>/dev/null | head -1 | grep -q . && echo 'audit log exists' && return 0 || echo 'audit log not found' && return 2"

    # Summary
    echo ""
    echo -e "${C_INFO}╔══════════════════════════════════════════╗${C_RST}"
    echo -e "${C_INFO}║  WAF Audit Summary                         ║${C_RST}"
    echo -e "${C_INFO}╚══════════════════════════════════════════╝${C_RST}"
    echo ""
    printf "  ${C_OK}PASS${C_RST}: %d\n" "$COUNT_PASS"
    printf "  ${C_FAIL}FAIL${C_RST}: %d\n" "$COUNT_FAIL"
    printf "  ${C_WARN}WARN${C_RST}: %d\n" "$COUNT_WARN"
    printf "  ${C_INFO}SKIP${C_RST}: %d\n" "$COUNT_SKIP"
    printf "  Total: %d\n" "$TOTAL_CHECKS"
    echo ""
    echo -e "Report: $REPORT_FILE"
}

# ── Interactive mode ───────────────────────────────────────────────
interactive_mode() {
    echo -e "${C_INFO}╔══════════════════════════════════════════╗${C_RST}"
    echo -e "${C_INFO}║  WAF Deployment Wizard                     ║${C_RST}"
    echo -e "${C_INFO}║  Coraza + OWASP CRS v4                     ║${C_RST}"
    echo -e "${C_INFO}║  $APP_NAME $APP_VER                          ║${C_RST}"
    echo -e "${C_INFO}╚══════════════════════════════════════════╝${C_RST}"
    echo ""

    echo -e "${C_INFO}Select operation:${C_RST}"
    echo -e "  ${C_WARN}1.${C_RST} Install Coraza + CRS v4"
    echo -e "  ${C_WARN}2.${C_RST} Generate Caddy + Coraza config"
    echo -e "  ${C_WARN}3.${C_RST} Generate Nginx + Coraza config"
    echo -e "  ${C_WARN}4.${C_RST} Generate HAProxy + Coraza config"
    echo -e "  ${C_WARN}5.${C_RST} Generate rule tuning config"
    echo -e "  ${C_WARN}6.${C_RST} Audit existing WAF config (read-only)"
    echo -e "  ${C_WARN}0.${C_RST} Exit"
    echo ""
    local pick
    read -r -p "Select [0-6]: " pick
    case $pick in
        1) install_coraza ;;
        2) generate_caddy_config ;;
        3) generate_nginx_config ;;
        4) generate_haproxy_config ;;
        5) generate_tuning_config ;;
        6) audit_waf || true ;;
        0) echo "Exit"; exit 0 ;;
        *) echo -e "${C_FAIL}Invalid input${C_RST}"; exit 1 ;;
    esac
}

# ── Main flow ───────────────────────────────────────────────────
main() {
    parse_args "$@"

    case "$MODE" in
        install) install_coraza ;;
        caddy) generate_caddy_config ;;
        nginx) generate_nginx_config ;;
        haproxy) generate_haproxy_config ;;
        tune) generate_tuning_config ;;
        audit) audit_waf || true ;;
        interactive) interactive_mode || true ;;
        *) echo "Unknown mode: $MODE"; exit 1 ;;
    esac
    return 0
}

main "$@"
