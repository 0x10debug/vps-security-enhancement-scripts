# WAF Deployment (Coraza + OWASP CRS v4)

> Web Application Firewall deployment with Coraza engine, OWASP Core Rule Set v4, and reverse proxy integration for Caddy, Nginx, and HAProxy.

## Overview

Web Application Firewalls (WAF) protect HTTP applications from common attacks (SQL injection, XSS, RCE, LFI, RFI, etc.) by inspecting and filtering requests. This chapter covers the WAF deployment tool:

- **`scripts/waf_setup.sh`** — Coraza WAF + OWASP CRS v4 deployment, reverse proxy integration, rule tuning, audit

## Architecture

```
┌────────┐    ┌──────────────┐    ┌──────────────┐    ┌────────┐
│ Client │───▶│  Reverse Proxy│───▶│  Coraza WAF  │───▶│ Backend│
│        │    │  (Caddy/Nginx │    │  (SPOA/Module)│    │  App   │
│        │    │   /HAProxy)   │    │  + CRS v4    │    │        │
└────────┘    └──────────────┘    └──────────────┘    └────────┘
```

## Components

| Component | Role | Technology |
|---|---|---|
| Coraza | WAF engine | Go-based, ModSecurity-compatible |
| OWASP CRS v4 | Rule set | Community-maintained attack signatures |
| HAProxy SPOA | Integration method | Stream Processing Offload Agent |
| Caddy plugin | Integration method | coraza-caddy module |
| Nginx module | Integration method | coraza-nginx module |

## Usage

```bash
# Interactive wizard
sudo ./scripts/waf_setup.sh

# Install Coraza + CRS v4
sudo ./scripts/waf_setup.sh --install

# Generate reverse proxy integration
sudo ./scripts/waf_setup.sh --caddy
sudo ./scripts/waf_setup.sh --nginx
sudo ./scripts/waf_setup.sh --haproxy

# Generate rule tuning config
sudo ./scripts/waf_setup.sh --tune

# Audit existing WAF config (read-only)
sudo ./scripts/waf_setup.sh --audit
```

## Reverse Proxy Integration

### HAProxy + Coraza SPOA (Recommended)

HAProxy's SPOA (Stream Processing Offload Agent) is the native Coraza integration method:
- High performance (Go SPOA process)
- Non-blocking inspection
- Native HAProxy filter mechanism

### Caddy + Coraza Plugin

Caddy v2.9 with coraza-caddy module:
- Automatic HTTPS
- Simple Caddyfile configuration
- Requires custom Caddy build (xcaddy)

### Nginx + Coraza Module

Nginx with coraza-nginx module:
- Requires module compilation
- Most complex setup
- Consider HAProxy or Caddy for easier deployment

## OWASP CRS v4 Rules

| Rule Set | ID Range | Protection |
|---|---|---|
| Initialization | 900-901 | CRS setup and initialization |
| Common Protection | 905 | HTTP protocol enforcement |
| Method Enforcement | 911 | HTTP method restrictions |
| Scanner Detection | 913 | Bot/scanner detection |
| Protocol Enforcement | 920 | HTTP protocol violations |
| Protocol Attacks | 921 | HTTP smuggling, request smuggling |
| LFI | 930 | Local File Inclusion |
| RFI | 931 | Remote File Inclusion |
| RCE | 932 | Remote Code Execution |
| PHP Attacks | 933 | PHP-specific attacks |
| Generic Attacks | 934 | Generic application attacks |
| XSS | 941 | Cross-Site Scripting |
| SQL Injection | 942 | SQL injection attacks |
| Session Fixation | 943 | Session fixation attacks |
| Java Attacks | 944 | Java-specific attacks |
| Data Leakage (Response) | 950-954 | Response data leakage detection |

## Rule Tuning

### Anomaly Scoring Mode

Instead of blocking on the first rule match, CRS uses anomaly scoring:
- Each rule adds points to a transaction score
- Request is blocked only if total score exceeds threshold
- Allows legitimate requests with minor matches to pass

```apache
# Default thresholds
SecAction "id:900100,phase:1,pass,nolog,setvar:tx.inbound_anomaly_score_threshold=5"
SecAction "id:900101,phase:1,pass,nolog,setvar:tx.outbound_anomaly_score_threshold=4"
```

### Paranoia Levels

| Level | Description | False Positive Risk |
|---|---|---|
| PL1 | Default, minimal FP | Low |
| PL2 | More rules | Medium |
| PL3 | Aggressive | High |
| PL4 | Paranoid | Very High |

### False Positive Handling

1. Monitor audit log for blocked legitimate requests
2. Identify the triggering rule ID and parameter
3. Create targeted exclusion:
   ```apache
   SecRuleUpdateTarget 942100 "!ARGS:search_query"
   ```
4. Test that attacks are still blocked

## Audit Checks (13 items)

| Section | Checks | Key Areas |
|---|---|---|
| Coraza Installation | 3 | Config file, CRS directory, CRS v4 rules |
| WAF Engine | 3 | Container running, engine enabled, body limit |
| Reverse Proxy | 3 | HAProxy SPOA, Caddy plugin, Nginx module |
| Rules | 4 | Anomaly scoring, SQLi, XSS, RCE rules |
| Logging | 2 | Audit log config, log file |

## Common Findings and Fixes

### WAF engine disabled (DetectionOnly mode)

**Risk**: Attacks detected but not blocked.
**Fix**: Set SecRuleEngine On in coraza.conf:
```apache
SecRuleEngine On
```

### No anomaly scoring configured

**Risk**: First rule match blocks request — high false positive rate.
**Fix**: Enable anomaly scoring in crs-setup.conf:
```apache
SecAction "id:900100,phase:1,pass,nolog,setvar:tx.inbound_anomaly_score_threshold=5"
```

### No audit logging

**Risk**: No visibility into blocked/flagged requests.
**Fix**: Configure audit logging in coraza.conf:
```apache
SecAuditEngine RelevantOnly
SecAuditLog /var/log/coraza/audit.log
SecAuditLogFormat JSON
```

## Integration with the Main Script

From `secure-vps`, WAF is accessible via:

```
B · Security hardening → b9 WAF deployment → Coraza + CRS v4
```

## Related Tools

| Tool | Repo | Focus |
|---|---|---|
| WAF setup (this script) | vps-security-enhancement-scripts | Coraza + CRS v4 deployment |
| Edge firewall | network-toolkit | nftables + ipset blocklist |
| Reverse proxy templates | network-toolkit | Caddy/Traefik/HAProxy configs |
| CrowdSec | vps-bootstrap | Intrusion detection + blocking |

## References

- [Coraza WAF](https://coraza.io/) — Official site
- [OWASP CRS v4](https://coreruleset.org/) — Core Rule Set project
- [Coraza SPOA](https://github.com/corazawaf/coraza-spoa) — HAProxy integration
- [coraza-caddy](https://github.com/corazawaf/coraza-caddy) — Caddy plugin
- [OWASP ModSecurity Core Rule Set Cheat Sheet](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x))
