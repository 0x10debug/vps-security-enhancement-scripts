# Chapter 18: TLS Certificate Automation

> **Scenario**: You run three services on a VPS — a blog, an API, and a Grafana dashboard. Each uses a different subdomain, and each needs HTTPS. You don't want to manually renew certificates every three months, and you definitely don't want service interruptions from expired certificates causing user complaints.

## Why TLS Automation Is Needed

TLS certificates are the cornerstone of HTTPS. Without a valid certificate, browsers display security warnings, API clients refuse to connect, and search engines downgrade your ranking. But certificate management is a classic "important but not urgent" task — until the day it expires, then it becomes urgent.

Problems with manual certificate management:

1. **Easy to forget renewal** — Let's Encrypt certificates are valid for 90 days, commercial CAs typically 1 year. The human brain is not good at remembering such periodic tasks.
2. **Renewal requires downtime** — Traditional renewal requires restarting the web server. Without an automated process, you either stop manually or risk a hot swap.
3. **Multi-domain management chaos** — When running multiple subdomains on one VPS, managing each domain separately quickly becomes a nightmare.
4. **Failures are invisible** — When certificate renewal fails, there's no alert. You only find out when users report "your website is down."

## Tool Selection: acme.sh vs certbot

| Dimension | acme.sh | certbot |
|---|---|---|
| Dependencies | Pure shell, no dependencies | Python + virtual environment |
| Size | ~200KB | ~50MB (including dependencies) |
| DNS API support | 150+ providers | ~30 plugins |
| Auto-renewal | cron | systemd timer |
| ECC certificates | Native support | Requires extra configuration |
| Revoke/delete | Built-in | Built-in |
| Use case | Lightweight VPS environment | Servers with Python environment |

**Recommendation**: For VPS scenarios, prefer acme.sh — pure shell implementation, no dependencies, and the widest DNS API coverage (including domestic DNS providers).

## Issuance Strategy

### DNS-01 vs HTTP-01

| Verification method | Use case | Advantages | Limitations |
|---|---|---|---|
| DNS-01 | Wildcard certificates, internal services, port 80 occupied | No need to expose port 80, supports wildcards | Requires DNS API credentials |
| HTTP-01 | Single domain, simple deployment | Zero configuration | Port 80 must be available |

**Decision tree**:

```
Need wildcard certificate (*.example.com)?
├── Yes → DNS-01 (only option)
└── No
    ├── Port 80 available and don't want to configure DNS API → HTTP-01 (standalone)
    └── Port 80 occupied or have DNS API credentials → DNS-01
```

### Key Types

| Type | Recommended scenario | Performance | Compatibility |
|---|---|---|---|
| EC-256 | General recommendation | Fastest | 99% client support |
| EC-384 | High security requirements | Fast | 99% client support |
| RSA-2048 | Legacy client compatibility | Medium | 100% |
| RSA-4096 | Highest RSA security | Slow | 100% |

**Recommendation**: EC-256. Unless you have explicit legacy client compatibility requirements, RSA is unnecessary.

## Deploying to Reverse Proxy

### Nginx

```nginx
server {
    listen 443 ssl http2;
    server_name example.com;

    ssl_certificate     /etc/nginx/ssl/example.com/fullchain.cer;
    ssl_certificate_key /etc/nginx/ssl/example.com/example.com.key;

    # Only enable TLS 1.2 and 1.3
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;

    # Session cache
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;

    # HSTS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
}
```

acme.sh auto-deploy hook:
```bash
acme.sh --install-cert -d example.com \
    --fullchain-file /etc/nginx/ssl/example.com/fullchain.cer \
    --key-file       /etc/nginx/ssl/example.com/example.com.key \
    --reloadcmd      "nginx -t && systemctl reload nginx"
```

### Caddy

Caddy has built-in automatic TLS management and usually doesn't need acme.sh. But if you need manual certificate management (e.g., using an internal CA):

```caddyfile
example.com {
    tls /etc/caddy/ssl/example.com/fullchain.cer /etc/caddy/ssl/example.com/example.com.key {
        protocols tls1.2 tls1.3
    }
    reverse_proxy localhost:8080
}
```

### HAProxy

HAProxy requires merging the certificate and private key into a single PEM file:

```bash
cat fullchain.cer example.com.key > example.com-combined.pem
chmod 600 example.com-combined.pem
```

```haproxy
frontend https
    bind *:443 ssl crt /etc/haproxy/ssl/example.com-combined.pem alpn h2,http/1.1
    http-response set-header Strict-Transport-Security "max-age=63072000"
    default_backend backend
```

## Auto-Renewal

acme.sh automatically adds a cron task after installation:

```cron
# Check and renew expiring certificates daily at midnight
0 0 * * * /root/.acme.sh/acme.sh --cron --home /root/.acme.sh
```

### Verifying Auto-Renewal Works

```bash
# View cron tasks
crontab -l | grep acme

# Manually trigger renewal check
acme.sh --cron

# View renewal logs
tail -20 /root/.acme.sh/acme.sh.log
```

### Renewal Failure Troubleshooting

| Symptom | Possible cause | Solution |
|---|---|---|
| DNS verification failed | DNS API credentials expired | Update environment variables, re-run |
| HTTP verification failed | Port 80 occupied | Stop the service using port 80, or switch to DNS-01 |
| Renewal succeeded but service not updated | reloadcmd not configured | Add --reloadcmd parameter |
| Certificate directory doesn't exist | Path changed | Check --fullchain-file --key-file paths |

## Certificate Monitoring

### Automated Monitoring Script

This project's `tls_lifecycle.sh --monitor` scans all certificates and reports expiry status:

```bash
# Manual check
sudo ./scripts/tls_lifecycle.sh --monitor

# Generate cron monitoring script
sudo ./scripts/tls_lifecycle.sh --monitor --output ./tls-configs
# Then: crontab -e
# 0 8 * * * /path/to/tls-monitor-cron.sh
```

### Monitoring Alert Levels

| Level | Days remaining | Color | Action |
|---|---|---|---|
| OK | > 30 days | Green | No action needed |
| WARNING | 15-30 days | Yellow | Check if auto-renewal is working |
| CRITICAL | < 15 days | Red | Manually renew immediately |
| EXPIRED | < 0 days | Red | Certificate expired, service may be interrupted |

## TLS Audit

`tls_lifecycle.sh --audit` performs 13 read-only checks:

| Check ID | Check content |
|---|---|
| TLS-001 | acme.sh installed |
| TLS-002 | acme.sh cron auto-renewal configured |
| TLS-003 | acme.sh default CA set |
| TLS-004 | Number of managed certificates |
| TLS-005 | Certificate not expired |
| TLS-006 | Certificate key strength (EC-256+ or RSA-2048+) |
| TLS-007 | Nginx enables TLS 1.3 |
| TLS-008 | Nginx disables TLS 1.0/1.1 |
| TLS-009 | Caddy automatic TLS management |
| TLS-010 | HSTS configured |
| TLS-011 | acme.sh cron auto-renewal configured |
| TLS-012 | certbot auto-renewal timer |
| TLS-013 | OCSP Stapling configured |

## FAQ

### Q: How to issue a wildcard certificate?

```bash
acme.sh --issue -d *.example.com -d example.com --dns cloudflare -k ec-256
```

Requires DNS-01 verification. Note that wildcard certificates cover `*.example.com` but not `example.com` itself — you need to add `-d example.com` separately.

### Q: How to use Let's Encrypt certificates for internal services?

Internal services cannot pass HTTP-01 verification (external access to internal port 80 is not possible). Use DNS-01 verification — you only need the DNS record to point to a public IP; the service itself doesn't need to be publicly accessible.

### Q: Certificate issuance rate limits?

Let's Encrypt limits:
- 50 certificates per registered domain per week
- Maximum 100 domains per certificate
- 5 duplicate certificates per month
- 5 failed retries per hour

Normal usage won't trigger these limits. Use the `--staging` environment during testing to avoid consuming quota.

### Q: How to migrate to a new server?

```bash
# Old server: export
acme.sh --info -d example.com  # View config
cp -r /root/.acme.sh/ /backup/

# New server: import
cp -r /backup/.acme.sh/ /root/
acme.sh --renew -d example.com --force  # Force renewal to verify new server
```

## Collaboration with Other Tools

| Tool | Collaboration method |
|---|---|
| network-toolkit | Caddy/Nginx/HAProxy reverse proxy templates work with TLS deployment |
| monitor-stack | Certificate expiry alerts integrated into monitoring system |
| waf_setup.sh | WAF requires TLS termination; TLS certificates are a prerequisite for WAF deployment |
| zerotrust_setup.sh | Zero-trust network control plane requires TLS |

## Quick Reference

```bash
# Install
sudo ./scripts/tls_lifecycle.sh --install

# Issue (DNS verification)
sudo ./scripts/tls_lifecycle.sh --issue --domain example.com --dns cloudflare

# Issue (standalone)
sudo ./scripts/tls_lifecycle.sh --issue --domain example.com --standalone

# Deploy to Nginx
sudo ./scripts/tls_lifecycle.sh --deploy --domain example.com --proxy nginx

# Renew
sudo ./scripts/tls_lifecycle.sh --renew

# Monitor
sudo ./scripts/tls_lifecycle.sh --monitor

# Audit
sudo ./scripts/tls_lifecycle.sh --audit
```
