# Chapter 20: CrowdSec Deployment and Intrusion Blocking

> **Scenario**: Your VPS is targeted by hundreds of IPs attempting SSH brute force attacks daily, and your Nginx logs are full of vulnerability scans and crawlers. Fail2Ban can block individual IPs, but it only reads local logs and only blocks locally, with no threat intelligence sharing. You need a modern intrusion prevention system that can collaborate across hosts, recognize complex attack patterns, and block at multiple layers (firewall/reverse proxy/CDN). CrowdSec is built for exactly this.

## Why CrowdSec Is Better Than Fail2Ban

Fail2Ban is a tool from 2004, designed for "scan logs + block IPs." It works well in single-host scenarios but has several fundamental limitations:

| Dimension | Fail2Ban | CrowdSec |
|---|---|---|
| Architecture | Single-host log scanning + local blocking | Engine + Bouncer decoupled, supports distributed |
| Detection capability | Regex matching single log lines | Scenario engine, supports time windows, counting, correlation |
| Threat intelligence | None | Crowdsourced threat intelligence, global IP reputation database |
| Blocking layers | Local firewall only | iptables / Nginx / Cloudflare / multi-layer |
| Resource usage | ~22MB RAM | ~85MB RAM (acceptable) |
| Community ecosystem | Scattered rules, each maintained separately | Hub centrally manages scenarios/parsers/bouncers |
| Scalability | Hard to scale across hosts | Central API + Console for centralized management |

**Core difference**: Fail2Ban is "each host fights alone," CrowdSec is "global hosts defend together." When your server is attacked and blocks IP `1.2.3.4`, this IP is reported to CrowdSec's global threat intelligence database, and all other CrowdSec users automatically pre-block this IP. Conversely, you also receive malicious IP lists reported by hosts from other countries in the community.

**Recommended strategy**: Both can coexist. Fail2Ban is suitable for lightweight single-host setups with only SSH protection; CrowdSec is suitable for scenarios requiring web protection, multi-host collaboration, and CDN-layer blocking. This script supports both.

## Architecture: Engine + Bouncer + Scenarios

CrowdSec's architecture is decoupled, with three core components each serving a specific purpose:

```
┌─────────────────────────────────────────────────────┐
│                    CrowdSec Architecture             │
│                                                     │
│  ┌──────────┐    ┌───────────┐    ┌──────────────┐  │
│  │ Log       │───▶│ CrowdSec  │───▶│  Bouncer     │  │
│  │ Source    │    │  Engine   │    │ (iptables/   │  │
│  │ (syslog/  │    │ + Scenarios│   │  nginx/CF)   │  │
│  │  nginx/  │    │ + Parsers │    │              │  │
│  │  sshd)   │    │           │    │              │  │
│  └──────────┘    └─────┬─────┘    └──────────────┘  │
│                        │                            │
│                        ▼                            │
│                 ┌─────────────┐                     │
│                 │  Local API  │                     │
│                 │  (decision  │                     │
│                 │   storage)  │                     │
│                 └──────┬──────┘                     │
│                        │                            │
│              ┌─────────┴──────────┐                 │
│              ▼                    ▼                 │
│       ┌────────────┐      ┌──────────────┐          │
│       │  Central   │      │  Notification │          │
│       │  API/Console│      │  System       │          │
│       │ (threat    │      │ (email/slack) │          │
│       │  intel)    │      │              │          │
│       └────────────┘      └──────────────┘          │
└─────────────────────────────────────────────────────┘
```

### 1. CrowdSec Engine (crowdsec service)

The engine is the brain, responsible for:
- **Reading logs**: Configures log sources via acquis.yaml (syslog, nginx access log, sshd log, etc.)
- **Parsing logs**: Uses parsers to transform unstructured logs into structured events
- **Scenario matching**: Uses scenarios to define attack patterns, e.g., "5 SSH failures from same IP within 10 seconds"
- **Generating decisions**: When scenarios match, generates block decisions and writes them to the local database
- **Reporting threat intelligence**: Reports malicious IPs to Central API (optional)

### 2. Bouncer (Block Executor)

Bouncers are the hands and feet, responsible for reading engine-generated decisions and executing blocks. Bouncers are decoupled from the engine and communicate via the Local API:

- **iptables bouncer**: Blocks at the system firewall layer, universal, no reverse proxy needed
- **nginx bouncer**: Blocks at the Nginx reverse proxy layer, returns 403, doesn't consume backend resources
- **Cloudflare bouncer**: Blocks at the CDN edge via Cloudflare API, malicious traffic never reaches your server

### 3. Scenarios and Collections

Scenarios are YAML-based attack detection rules that define "what behavior constitutes an attack." Collections are packages of scenarios + parsers:

- `crowdsecurity/sshd`: SSH brute force detection
- `crowdsecurity/http-cve`: Web CVE exploit detection
- `crowdsecurity/http-probing`: Web path probing scans
- `crowdsecurity/http-bad-user-agent`: Malicious crawler User-Agents

## Installation Methods

### Method 1: Interactive Wizard (Recommended)

```bash
sudo ./scripts/crowdsec_setup.sh
```

The wizard provides installation, scenario configuration, bouncer deployment, alerts, audit, and all other features.

### Method 2: Direct Command-Line Installation

```bash
# Install CrowdSec
sudo ./scripts/crowdsec_setup.sh --install

# Configure detection scenarios
sudo ./scripts/crowdsec_setup.sh --scenarios

# Deploy iptables bouncer
sudo ./scripts/crowdsec_setup.sh --bouncer --bouncer-type iptables

# Configure Slack alerts
sudo ./scripts/crowdsec_setup.sh --alerts --alert-type slack
```

### Installation Principle

The script prioritizes the official CrowdSec installation script (`raw.githubusercontent.com/crowdsecurity/crowdsec/master/scripts/install.sh`), which automatically detects the distribution and configures the appropriate package source. If the official script download fails, the script falls back to manually adding the packagecloud source and installing with `apt`/`yum`.

After installation, CrowdSec will:
1. Enable and start the `crowdsec` systemd service
2. Install the base scenario collection by default (sshd, linux)
3. Open the Local API (port 8081) for bouncer connections

## Scenario Selection and Configuration

### Recommended Scenario Collections

| Collection | Detection content | Applicable environment |
|---|---|---|
| `crowdsecurity/sshd` | SSH brute force | All hosts |
| `crowdsecurity/ssh-slow-bf` | SSH slow brute force (low frequency, long term) | All hosts |
| `crowdsecurity/http-cve` | Web CVE exploits (Log4Shell, etc.) | Web servers |
| `crowdsecurity/http-probing` | Path probing scans (/admin, /.env, etc.) | Web servers |
| `crowdsecurity/http-bad-user-agent` | Malicious crawlers, scanner UAs | Web servers |
| `crowdsecurity/http-sensitive-files` | Sensitive file access (.git, .aws, etc.) | Web servers |
| `crowdsecurity/whitelist-good-actors` | Whitelist known good actors (Googlebot, etc.) | Web servers |
| `crowdsecurity/nfx` | Network firewall log analysis | Hosts with iptables logs |
| `crowdsecurity/iptables-logs` | iptables DROP/REJECT logs | Hosts with iptables logs |
| `crowdsecurity/linux` | Linux system general scenarios | All hosts |

### Configuration Process

```bash
# Update Hub index and install recommended scenarios
sudo ./scripts/crowdsec_setup.sh --scenarios

# Or manually install individual collections
cscli collections install crowdsecurity/http-cve
cscli collections install crowdsecurity/http-probing

# Restart engine to load new scenarios
systemctl restart crowdsec
```

### Custom Scenarios

If built-in scenarios don't meet your needs, you can write custom scenarios. Scenario files go in `/etc/crowdsec/scenarios/`:

```yaml
# /etc/crowdsec/scenarios/custom-ssh-bf.yaml
type: trigger
name: custom-ssh-bf
description: "Custom SSH brute force (5 attempts/10 seconds)"
filter: "evt.Meta.log_type == 'ssh_failed-auth'"
groupby: "evt.Meta.source_ip"
distinct: "evt.Meta.target_user"
reprocess: true
labels:
  type: ssh_bruteforce
  scope: Ip
  behavior: "ssh:bruteforce"
  confidence: 3
  spoofable: 0
# 5 failures within a 10-second window
capacity: 5
leakspeed: "10s"
blackhole: 1m
```

After installation, run `cscli scenarios reload` to load.

## Bouncer Type Comparison

### iptables Bouncer (Recommended General Purpose)

```bash
sudo ./scripts/crowdsec_setup.sh --bouncer --bouncer-type iptables
```

- **Principle**: Blocks malicious IPs using iptables/nftables rules at the system firewall layer
- **Advantages**: Universal, no reverse proxy needed, effective at all traffic layers
- **Disadvantages**: Blocking occurs after traffic reaches the application (bandwidth already consumed)
- **Use case**: Directly connected services without reverse proxy, or as a base blocking layer

### Nginx Bouncer

```bash
sudo ./scripts/crowdsec_setup.sh --bouncer --bouncer-type nginx
```

- **Principle**: Returns 403 at the reverse proxy layer via Nginx module
- **Advantages**: Doesn't consume backend application resources, customizable responses
- **Disadvantages**: Requires Nginx, only effective for traffic passing through Nginx
- **Use case**: Web services already using Nginx reverse proxy

After deployment, ensure Nginx config loads the module:

```nginx
# nginx.conf top level
load_module modules/ngx_http_crowdsec_module.so;

# Inside server block
server {
    crowdsec on;
    crowdsec_sanitize_urls on;
}
```

### Cloudflare Bouncer

```bash
sudo ./scripts/crowdsec_setup.sh --bouncer --bouncer-type cloudflare
```

- **Principle**: Adds firewall rules at the CDN edge via Cloudflare API
- **Advantages**: Malicious traffic never reaches your server, zero bandwidth consumption
- **Disadvantages**: Requires Cloudflare account and API Token, only effective for CF-proxied domains
- **Use case**: Web services with domains already on Cloudflare

Requires Cloudflare API Token (permission: Zone.Firewall Rules). Get it at: `https://dash.cloudflare.com/profile/api-tokens`.

**Multi-layer blocking recommendation**: iptables (fallback) + Cloudflare (edge interception) dual bouncers for defense in depth.

## Alert Configuration

CrowdSec supports multiple alert notification methods, pushing real-time alerts when attacks are detected:

### Email Alerts

```bash
sudo ./scripts/crowdsec_setup.sh --alerts --alert-type email
```

Requires SMTP server information (host, port, username, password). After configuration, it's installed to `/etc/crowdsec/notifications/`.

### Webhook (Generic)

```bash
sudo ./scripts/crowdsec_setup.sh --alerts --alert-type webhook
```

POSTs JSON alert data to any HTTP endpoint, can integrate with self-built notification systems, DingTalk bots, WeChat Work, etc.

### Slack

```bash
sudo ./scripts/crowdsec_setup.sh --alerts --alert-type slack
```

Requires Slack Incoming Webhook URL. After configuration, CrowdSec alerts push to the specified Slack channel.

### Discord

```bash
sudo ./scripts/crowdsec_setup.sh --alerts --alert-type discord
```

Requires Discord Webhook URL. Suitable for gaming communities or teams using Discord.

### Alert Templates

Alert configurations use Go template syntax, available variables:
- `.AlertsCount`: Number of alerts in this batch
- `.Alerts`: Alert list, each containing `.Scenario`, `.Source.IP`, `.Decisions`

## Centralized Management: CrowdSec Console

CrowdSec provides a free Central API and Web Console for multi-host centralized management:

1. **Register Console**: Visit `https://app.crowdsec.net` to register a free account
2. **Enroll machines**: Run `cscli console enroll <ENROLL_KEY>` on each host
3. **Centralized view**: View all hosts' alerts, decisions, and metrics in the Console
4. **Threat intelligence sharing**: Your block decisions are reported to the community, and you receive the community's malicious IP lists

```bash
# Enroll host to Console
cscli console enroll YOUR_ENROLL_KEY

# View enrollment status
cscli console status
```

Console benefits:
- **Multi-host unified view**: One dashboard to see all servers' security status
- **Threat intelligence feedback loop**: IPs you report are shared and blocked by global users
- **Historical analysis**: Long-term storage of alert and decision data, supports retrospective analysis

## Integration with Main Script

The CrowdSec deployment script is integrated into the main script `vps_security_enhance.sh` B3 menu (intrusion blocking):

```
B3 Intrusion Blocking
├── 1. Fail2Ban deployment
├── 2. Fail2Ban status
├── 3. Fail2Ban logs
├── 4. Restart Fail2Ban
├── 5. CrowdSec full deployment wizard   ← calls crowdsec_setup.sh
├── 6. CrowdSec status                    ← calls crowdsec_setup.sh --status
├── 7. CrowdSec audit (read-only)         ← calls crowdsec_setup.sh --audit
└── 0. Back
```

Selecting 5/6/7 calls `scripts/crowdsec_setup.sh` in the corresponding mode. You can also run the script directly:

```bash
# Full wizard
sudo ./scripts/crowdsec_setup.sh

# Read-only audit (15 checks)
sudo ./scripts/crowdsec_setup.sh --audit

# View status
sudo ./scripts/crowdsec_setup.sh --status
```

## Read-Only Audit

`--audit` mode performs 15 read-only checks without modifying any configuration:

| Check item | Content |
|---|---|
| CS-001 | CrowdSec installed (cscli available) |
| CS-002 | crowdsec service running |
| CS-003 | crowdsec service enabled on boot |
| CS-004 | Hub updated |
| CS-005 | Number of installed scenario collections |
| CS-006 | SSH brute force scenario installed |
| CS-007 | At least one bouncer deployed |
| CS-008 | firewall/nginx/cloudflare bouncer running |
| CS-009 | Current block decision count |
| CS-010 | Alert notifications configured |
| CS-011 | Config files exist and are readable |
| CS-012 | CrowdSec API port (8080) listening |
| CS-013 | Local API port (8081) listening |
| CS-014 | Database file exists |
| CS-015 | Log file exists |

Audit report saved to `/var/log/crowdsec-audit/crowdsec-audit-<timestamp>.txt`.

## Troubleshooting

### Q: Bouncer not working after CrowdSec installation?

Check bouncer service status and logs:

```bash
systemctl status crowdsec-firewall-bouncer
journalctl -u crowdsec-firewall-bouncer -n 50
```

Common causes:
- Bouncer not registered with Local API: run `cscli bouncers list` to confirm
- API port unreachable: check if port 8081 is listening
- Wrong API URL in bouncer config: check configs under `/etc/crowdsec/bouncers/`

### Q: Scenarios installed but no alerts?

Confirm log source configuration is correct:

```bash
# View current log sources
cscli acquisitions list

# Test log parsing
cscli explain -f /var/log/auth.log -type syslog
```

If the parser can't recognize the log format, scenarios won't trigger. Common causes:
- Log path not configured in `acquis.yaml`
- Log format doesn't match parser (e.g., custom log format)
- Scenario `filter` conditions too strict

### Q: Cloudflare bouncer reports API error?

- Confirm API Token permissions include `Zone.Firewall Rules`
- Confirm Zone ID is correct (or leave empty for auto-detection)
- Check if the token in `/etc/crowdsec/bouncers/cloudflare.yaml` is valid

### Q: Can CrowdSec and Fail2Ban coexist?

Yes. They detect different logs, use different blocking mechanisms, and don't conflict. Common combination:
- Fail2Ban for SSH (lightweight, fast)
- CrowdSec for web attacks + threat intelligence sharing (comprehensive, collaborative)

Avoid both blocking the same IP redundantly to prevent confusion. Recommended division: SSH via Fail2Ban, web via CrowdSec.

### Q: How to check CrowdSec resource usage?

```bash
systemctl status crowdsec
# or
cscli metrics
# Memory usage
ps -o pid,rss,comm -p $(pgrep crowdsec)
```

CrowdSec normally uses about 85MB RAM. If abnormally high, it may be due to too many scenarios or excessive log volume.

### Q: How to clean up expired block decisions?

```bash
# View current decisions
cscli decisions list

# Delete all decisions (release all blocked IPs)
cscli decisions delete --all

# Delete decisions for a specific IP
cscli decisions delete --ip 1.2.3.4
```

Decisions have automatic expiry times (defined by the scenario's `duration`), so manual cleanup is usually unnecessary.

## Quick Reference

```bash
# Install CrowdSec
sudo ./scripts/crowdsec_setup.sh --install

# Configure detection scenarios
sudo ./scripts/crowdsec_setup.sh --scenarios

# Deploy bouncer
sudo ./scripts/crowdsec_setup.sh --bouncer --bouncer-type iptables
sudo ./scripts/crowdsec_setup.sh --bouncer --bouncer-type nginx
sudo ./scripts/crowdsec_setup.sh --bouncer --bouncer-type cloudflare

# Configure alerts
sudo ./scripts/crowdsec_setup.sh --alerts --alert-type email
sudo ./scripts/crowdsec_setup.sh --alerts --alert-type slack
sudo ./scripts/crowdsec_setup.sh --alerts --alert-type discord

# Hub management
sudo ./scripts/crowdsec_setup.sh --hub

# Status / logs / audit
sudo ./scripts/crowdsec_setup.sh --status
sudo ./scripts/crowdsec_setup.sh --logs
sudo ./scripts/crowdsec_setup.sh --audit

# Uninstall
sudo ./scripts/crowdsec_setup.sh --uninstall

# Common cscli commands
cscli metrics              # Detection metrics
cscli decisions list       # Block list
cscli alerts list          # Alert list
cscli bouncers list        # Bouncer list
cscli collections list     # Installed collections
cscli hub update           # Update Hub
cscli hub upgrade          # Upgrade collections
cscli console enroll KEY   # Enroll to Console
```
