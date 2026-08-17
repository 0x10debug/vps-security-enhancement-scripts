# Monitoring and Alerts

> Catch issues before your users do — lightweight monitoring to full observability stacks.

## Overview

Monitoring is the difference between "I know the server is down because I got a page" and "I know the server is down because users are emailing me." The goal of monitoring is to detect problems early enough to fix them before they impact users, and to provide the data needed to diagnose what went wrong after the fact.

This chapter covers two tiers of monitoring: lightweight self-hosted monitoring with Uptime Kuma (deployed via `vps_secure.sh`), and a full monitoring stack using **monitor-stack** from the 0x10debug ecosystem (Uptime Kuma + Prometheus + Grafana + Alertmanager). We cover what to monitor, alert channel selection, log management, and security monitoring. Each section follows the closed loop: **Problem (what can go undetected?) → Investigate (what should I monitor?) → Fix (deploy monitoring) → Verify (test that alerts fire)**.

## Problem: You Don't Know When Things Break

### The cost of not monitoring

Without monitoring, you discover problems through user reports. By then:
- The site has been down for 30 minutes (users noticed at minute 5, tried again at 10, emailed you at 30)
- You have no data about what happened (logs may have rotated, the crash is invisible)
- Your recovery is reactive and blind — you're guessing at the cause

With monitoring:
- You get paged within 60 seconds of the service going down
- You see the timeline: CPU spiked at 14:00, memory at 14:02, process killed at 14:03
- Your recovery is proactive and informed — you know exactly what broke

## Fix: Lightweight Monitoring with Uptime Kuma

### Deploy

```bash
secure-vps  # d1 → 2 → 3 (Uptime Kuma)
```

Deploys Uptime Kuma as a Docker container on port 3001:
- Persistent volume for monitor history and config
- Offers to open port 3001 in UFW

Access at `http://server-ip:3001` and create an admin account on first visit.

### What Uptime Kuma monitors

Uptime Kuma is a self-hosted alternative to UptimeRobot. It supports:

| Monitor type | What it checks | Use case |
|-------------|---------------|----------|
| HTTP(s) | URL returns 2xx within timeout | Website availability |
| HTTP(s) - Keyword | URL contains specific text | Content validation |
| TCP Port | Port accepts connections | Database/service reachability |
| Ping | ICMP echo | Server alive check |
| DNS | DNS resolution | Domain health |
| Push | Waits for a push from your app | Cron job / backup success |
| Steam | Game server query | Gaming servers |
| Docker Container | Container status via Docker socket | Container health |

### Recommended monitors for a VPS

```
1. HTTP monitor: https://your-site.com (60s interval)
   → Catches web server crashes, DNS issues, TLS expiry

2. TCP monitor: server-ip:50022 (60s interval)
   → Catches SSH unavailability (you can't fix what you can't access)

3. TCP monitor: server-ip:443 (60s interval)
   → Catches TLS termination issues separately from the app

4. Push monitor: https://kuma-url/api/push/xxx?status=up&msg=OK
   → Set up a cron job that pushes after successful backup
   → If backup fails, no push → Kuma alerts you

5. Docker container monitor: myapp (30s interval)
   → Catches container crashes/restarts
```

### Alert channels

Uptime Kuma supports multiple notification methods:

| Channel | Setup difficulty | Reliability | Best for |
|---------|-----------------|-------------|----------|
| Telegram | Easy (bot token) | High | Personal/small team |
| Email (SMTP) | Easy | Medium (spam filters) | Formal records |
| Discord | Easy (webhook URL) | High | Team channels |
| Slack | Easy (webhook URL) | High | Team channels |
| Webhook | Medium (custom endpoint) | High | Integration with other systems |
| PagerDuty | Medium | High | On-call rotation |
| Microsoft Teams | Easy (webhook) | High | Enterprise teams |

**Recommendation for solo operators**: Telegram — instant delivery, free, works on mobile, supports rich formatting. Set up a dedicated bot:

```bash
# Create a Telegram bot:
# 1. Message @BotFather on Telegram
# 2. /newbot → get bot token
# 3. Create a channel, add the bot as admin
# 4. In Uptime Kuma: Settings → Notifications → Telegram
# 5. Enter bot token and chat ID
```

### Verify alerts fire

```bash
# Test: stop a monitored service and confirm you get an alert:
docker stop myapp
# Within 60s (your monitor interval), you should receive:
# "🔴 myapp is DOWN"
# Start it again:
docker start myapp
# Within 60s:
# "✅ myapp is UP"
```

**Always test alert delivery**. A monitor that doesn't alert is worse than no monitor — it gives false confidence.

## Fix: Full Monitoring Stack (monitor-stack)

### When Uptime Kuma isn't enough

Uptime Kuma tells you *whether* a service is up. It doesn't tell you *why* it went down, or warn you *before* it goes down. For that, you need metrics: CPU, memory, disk, network, container stats, application-specific metrics.

**monitor-stack** from the 0x10debug ecosystem provides a complete observability stack:

| Component | Role | What it provides |
|-----------|------|-----------------|
| Prometheus | Metrics collection & storage | Time-series database, scraping, alerting rules |
| Grafana | Visualization | Dashboards, charts, historical trends |
| Alertmanager | Alert routing | Deduplication, grouping, routing to channels |
| Uptime Kuma | Uptime monitoring | External perspective (is it reachable?) |
| Node Exporter | Host metrics | CPU, memory, disk, network, filesystem |
| cAdvisor | Container metrics | Per-container CPU, memory, network, I/O |

### Deploy monitor-stack

monitor-stack deploys as a Docker Compose stack:

```bash
# monitor-stack provides a docker-compose.yml with all components
# pre-configured with sensible defaults and integrated dashboards

# After deployment:
# - Grafana: http://server-ip:3000 (dashboards)
# - Prometheus: http://server-ip:9090 (metrics query)
# - Alertmanager: http://server-ip:9093 (alert management)
# - Uptime Kuma: http://server-ip:3001 (uptime)
```

### What to monitor

#### Host-level metrics (Node Exporter)

| Metric | Alert threshold | Why |
|--------|----------------|-----|
| CPU usage | > 80% for 5 min | Sustained high CPU → response time degradation |
| Memory usage | > 90% for 2 min | Approaching OOM kill |
| Disk usage | > 85% | Risk of disk full → service failure |
| Disk I/O | > 80% util for 5 min | I/O bottleneck → slow responses |
| Load average | > nproc × 1.5 for 5 min | Overloaded → queuing |
| Network in/out | Context-dependent | Unusual spikes may indicate attack or misconfiguration |
| Filesystem read-only | Any | Disk corruption or remount → immediate action |

#### Container metrics (cAdvisor)

| Metric | Alert threshold | Why |
|--------|----------------|-----|
| Container down | Any | Service stopped |
| Container restart count | > 3 in 10 min | Crash loop |
| Container memory | > 90% of limit | Approaching OOM kill for the container |
| Container CPU | > 90% of limit for 5 min | Container is CPU-starved |

#### Application metrics (custom)

Depends on your application. Common patterns:
- HTTP 5xx error rate > 1% for 2 min
- Request latency p95 > 500ms for 5 min
- Database connection pool exhausted
- Queue depth > threshold

### Alert rules (Prometheus)

Example alertmanager rules for a VPS:

```yaml
# High CPU alert
- alert: HighCpuUsage
  expr: 100 - (avg by(instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "High CPU usage on {{ $labels.instance }}"

# High memory alert
- alert: HighMemoryUsage
  expr: (1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) * 100 > 90
  for: 2m
  labels:
    severity: critical
  annotations:
    summary: "High memory usage — OOM risk"

# Disk space alert
- alert: DiskSpaceLow
  expr: (1 - node_filesystem_avail_bytes{fstype!~"tmpfs|overlay"} / node_filesystem_size_bytes{fstype!~"tmpfs|overlay"}) * 100 > 85
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Disk space low on {{ $labels.mountpoint }}"

# Container down
- alert: ContainerDown
  expr: time() - container_last_seen{name!=""} > 60
  for: 1m
  labels:
    severity: critical
  annotations:
    summary: "Container {{ $labels.name }} is down"
```

### Alert severity levels

| Severity | Response time | Channel | Example |
|----------|--------------|---------|---------|
| Critical | < 5 min | Pager/Telegram (wake up) | Service down, disk full |
| Warning | < 30 min | Telegram/email | High CPU, disk 85% |
| Info | Next business day | Email/dashboard | Deploy completed, cert renews |

Don't make everything critical — alert fatigue leads to ignored alerts. Reserve critical for things that require immediate human action.

## Fix: Log Management

### journalctl (systemd logs)

```bash
# Recent logs (all services):
journalctl --since "1 hour ago" --no-pager | tail -50

# Specific service:
journalctl -u nginx --since today --no-pager

# Follow logs in real-time:
journalctl -f -u nginx

# Errors only:
journalctl -p err --since "1 hour ago"

# Disk usage of journals:
journalctl --disk-usage
# Archived and active journals take up 500M   ← may need limiting

# Limit journal size:
journalctl --vacuum-size=200M
journalctl --vacuum-time=7d

# Permanent limit in /etc/systemd/journald.conf:
# SystemMaxUse=200M
# MaxRetentionSec=7day
systemctl restart systemd-journald
```

### Log rotation (logrotate)

Most distros have logrotate pre-configured for `/var/log`. Check and adjust:

```bash
# Check logrotate config:
cat /etc/logrotate.conf
ls /etc/logrotate.d/

# Test a rotation:
logrotate -d /etc/logrotate.d/nginx   # dry-run
logrotate -f /etc/logrotate.d/nginx   # force rotation

# Typical config for an app log:
cat /etc/logrotate.d/myapp
# /var/log/myapp/*.log {
#     daily
#     rotate 7
#     compress
#     missingok
#     notifempty
#     create 0640 myapp myapp
# }
```

### Centralized logging (optional)

For multi-server environments, ship logs to a central location:

- **Loki + Promtail** (from Grafana ecosystem): lightweight, integrates with Grafana dashboards
- **ELK Stack** (Elasticsearch + Logstash + Kibana): powerful but resource-heavy
- **Vector**: modern, fast log shipper

For a single VPS, `journalctl` + `logrotate` is sufficient. Centralized logging becomes valuable when you manage 3+ servers and need to correlate events across them.

## Fix: Security Monitoring

### Fail2Ban logs

```bash
secure-vps  # b3 → 3 (查看拦截日志)
# Shows last 15 lines of /var/log/fail2ban.log

# Manual:
tail -f /var/log/fail2ban.log
# 2024-01-15 10:23:01 fail2ban.actions [1234]: NOTICE [sshd] Ban 185.220.101.45
# 2024-01-15 10:23:01 fail2ban.actions [1234]: NOTICE [sshd] Ban 45.227.255.206

# Current ban list:
fail2ban-client status sshd
# Currently banned: 12
# Banned IP list: 185.220.101.45 45.227.255.206 ...

# Check if a specific IP is banned:
fail2ban-client status sshd | grep 185.220.101.45
```

**Set up an alert** for unusual ban activity: if Fail2Ban bans >50 IPs in an hour, you're under a coordinated brute-force attack — investigate (Chapter 08).

### Auth logs

```bash
# Successful logins:
last -20
# root   pts/0  192.168.1.50  Mon Jan 15 10:23   still logged in
# deploy pts/1  10.0.0.5      Mon Jan 15 09:15 - 09:45  (00:30)

# Failed login attempts:
lastb -20
# root   ssh:notty  185.220.101.45  Mon Jan 15 10:22 - 10:22 (00:00)
# admin  ssh:notty  45.227.255.206  Mon Jan 15 10:22 - 10:22 (00:00)

# Auth log (Debian/Ubuntu):
grep 'Failed password' /var/log/auth.log | tail -20
grep 'Accepted' /var/log/auth.log | tail -20

# Auth log (RHEL):
grep 'Failed password' /var/log/secure | tail -20

# Via vps_secure.sh:
secure-vps  # c1 → 7 (登录轨迹 / Login Trail)
# Shows recent failed attempts and login history
```

### AIDE integrity monitoring

AIDE (Advanced Intrusion Detection Environment) tracks file changes. After the initial baseline (Chapter 02), it runs daily and reports any modified system files:

```bash
secure-vps  # b4 → 8 → 3 (AIDE 立即比对)
# Runs integrity check, reports any changed files

# Manual:
aide --check
# AIDE found differences between database and filesystem!
# Added: /usr/local/bin/suspicious_binary
# Changed: /etc/passwd (mtime, ctime, size)
# Removed: /etc/cron.d/backup

# Check the cron log:
cat /var/log/aide-cron.log
# Daily integrity report
```

**What to investigate**:
- **Added binaries** in system paths (`/usr/bin/`, `/usr/local/bin/`, `/sbin/`) → potential malware
- **Changed system configs** (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`) → potential unauthorized access
- **Changed binaries** (`/usr/bin/ssh`, `/usr/sbin/sshd`) → potential rootkit
- **Removed cron jobs** → attacker covering tracks

### Sudo audit log

If you enabled sudo auditing (Chapter 02):

```bash
cat /var/log/sudo.log
# Jan 15 10:23:01 : root : TTY=pts/0 ; PWD=/root ; COMMAND=/usr/bin/apt update
# Jan 15 11:45:30 : deploy : TTY=pts/1 ; PWD=/home/deploy ; COMMAND=/usr/bin/systemctl restart nginx

# Look for unexpected sudo usage, especially:
# - Commands you don't recognize
# - Users who shouldn't have sudo
# - Off-hours activity
```

## Cross-Reference: security-audit

For continuous security monitoring and drift detection, **security-audit** from the 0x10debug ecosystem provides:

- **CIS Benchmark scoring**: track compliance over time
- **Drift detection**: alert when security configurations change from baseline
- **Vulnerability scanning**: identify known CVEs in installed packages
- **Scheduled audits**: run automatically and report changes

Use security-audit alongside monitor-stack:
- monitor-stack → operational health (is the server working?)
- security-audit → security posture (is the server still hardened?)

## Verify: Monitoring Verification Checklist

### Uptime Kuma

```bash
# Confirm the container is running:
docker ps | grep uptime-kuma
# healthy, running

# Confirm the web UI is accessible:
curl -I http://localhost:3001
# HTTP/1.1 200 OK

# Test alert delivery (stop a monitored service, confirm alert arrives):
docker stop test-service
# Alert should arrive within monitor interval (60s)
docker start test-service
# Recovery alert should arrive
```

### monitor-stack (if deployed)

```bash
# All containers running:
docker ps --format '{{.Names}}: {{.Status}}' | grep -E 'prometheus|grafana|alertmanager|node-exporter|cadvisor'
# All should show "Up"

# Prometheus targets healthy:
curl -s http://localhost:9090/api/v1/targets | python3 -m json.tool | grep -E 'health|scrapeUrl'
# "health": "up" for all targets

# Grafana dashboards loading:
curl -I http://localhost:3000
# HTTP/1.1 302 (redirect to login) ← working

# Alertmanager receiving alerts:
curl -s http://localhost:9093/api/v2/alerts | python3 -m json.tool
# Shows active alerts (should be empty if everything is healthy)
```

### Log management

```bash
# Journal size under control:
journalctl --disk-usage
# Should be under your configured limit (e.g., 200M)

# Logrotate running:
systemctl status logrotate.timer
# active (running)

# Check for log files not being rotated:
find /var/log -name "*.log" -size +500M
# Any results = logrotate not covering those files
```

### Security monitoring

```bash
# Fail2Ban active:
systemctl is-active fail2ban    # active
fail2ban-client status sshd     # jail running

# AIDE baseline exists:
ls -la /var/lib/aide/aide.db.gz
# Should exist and be recent (or from initial setup)

# Sudo log being written:
ls -la /var/log/sudo.log
# File exists and is growing with sudo usage

# Auth log accessible:
tail -5 /var/log/auth.log    # or /var/log/secure
# Recent entries visible
```

## Common Scenarios

### Scenario: Disk filling up silently

```
Problem: Server runs fine for weeks, then suddenly crashes with "disk full".
Investigate:
  1. df -h / → check current usage
  2. du -sh /var/log/* | sort -rh | head → find the space hog
  3. Check if logrotate is configured for the growing log
Fix:
  1. Add logrotate config for the growing log file
  2. Set up monitor-stack disk usage alert (>85%)
  3. Add Docker log rotation (Ch.03) if Docker logs are the cause
Verify:
  1. Monitor shows disk usage stable over time
  2. Alert fires if disk crosses 85%
```

### Scenario: Container crash loop goes unnoticed

```
Problem: A container keeps crashing and restarting, but you only find out
         when a user reports the service is flaky.
Investigate:
  1. docker ps → check restart count
  2. docker logs <container> → see the crash reason
Fix:
  1. Fix the underlying crash (config error, OOM, etc.)
  2. Add Uptime Kuma Docker container monitor for that container
  3. Add monitor-stack alert: ContainerRestart > 3 in 10 min
Verify:
  1. Stop the container, confirm alert fires
  2. Restart loop, confirm restart alert fires
```

## What's Next

- **Chapter 08** — Incident response: using monitoring data during and after an incident
- **Chapter 05** — Performance tuning: using monitoring data to identify tuning opportunities
- **Chapter 02** — Security baseline: the security monitoring foundation
