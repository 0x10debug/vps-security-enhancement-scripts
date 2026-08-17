# Incident Response

> "I think I've been hacked" — the first 10 minutes, the first hour, and the days after.

## Overview

Incident response is the chapter you hope you never need, but must read before you need it. When you suspect a compromise, panic is your enemy — it leads to destructive actions that destroy evidence and make recovery harder. The disciplined approach is: isolate, assess, preserve evidence, then remediate. Speed matters, but not at the cost of losing the forensic trail that tells you how the attacker got in.

This chapter covers the first 10 minutes of an incident, checking for compromise using `vps_secure.sh` tools, malware detection with rkhunter and AIDE, post-incident password and key rotation, root cause analysis, recovery from backup or rebuild, and prevention. We follow the closed loop: **Problem (suspected compromise) → Investigate (what happened and how?) → Fix (contain, eradicate, recover) → Verify (confirm the attacker is gone and can't return)**. We cross-reference **backup-kit** for recovery and **vps-bootstrap** and **security-audit** for prevention.

## Problem: "I Think I've Been Hacked"

### Signs of compromise

You might suspect a compromise because of:
- Unexplained high CPU/network usage (cryptominer, spam relay)
- Files changed that you didn't change
- New user accounts you didn't create
- SSH logins from countries you don't operate from
- Your server is sending spam (provider notification)
- Your IP is on a blacklist
- A service is behaving strangely (redirects, defaced pages)
- Monitoring alerts you can't explain (Chapter 07)
- The provider suspended your server for abuse

### The first 10 minutes: STOP and THINK

**Do NOT**:
- Reboot the server (this clears memory, kills running malware, destroys process state)
- Delete suspicious files (destroys evidence)
- Immediately change passwords (the attacker may have a rootkit that captures the new password)
- Run a bunch of commands randomly (you may tip off the attacker that you're aware)

**DO**:
1. **Isolate the server** (below)
2. **Preserve evidence** (below)
3. **Assess the scope** (below)
4. **Then** remediate

## Fix: Isolate

### Step 1: Cut network access (if you can reach the server)

```bash
# Option A: Block all incoming traffic except your IP (if you know your IP):
ufw deny in to any
ufw allow in from <your-ip> to any port <ssh-port>

# Option B: Shut down the network interface entirely:
ip link set eth0 down
# WARNING: if you're connected via SSH, this disconnects you.
# Use the provider's VNC/console to reconnect.

# Option C: Power off via provider console (nuclear option):
# This stops the attack but loses volatile memory evidence.
# Use only if you can't secure the server while it's running.
```

**If you're locked out**: use the provider's VNC/console rescue mode. Most providers offer a web-based console that works even if SSH and networking are down.

### Step 2: Preserve volatile evidence (before anything changes)

```bash
# Save running processes:
ps aux > /tmp/evidence_ps_$(date +%Y%m%d%H%M%S).txt

# Save network connections:
ss -tulpn > /tmp/evidence_ss_$(date +%Y%m%d%H%M%S).txt
ss -tulpn | grep ESTAB >> /tmp/evidence_ss_$(date +%Y%m%d%H%M%S).txt

# Save memory info:
free -h > /tmp/evidence_free_$(date +%Y%m%d%H%M%S).txt

# Save login history:
last -50 > /tmp/evidence_last_$(date +%Y%m%d%H%M%S).txt
lastb -50 > /tmp/evidence_lastb_$(date +%Y%m%d%H%M%S).txt

# Save auth log:
cp /var/log/auth.log /tmp/evidence_auth_$(date +%Y%m%d%H%M%S).log
# (or /var/log/secure on RHEL)

# Save dmesg:
dmesg > /tmp/evidence_dmesg_$(date +%Y%m%d%H%M%S).txt

# Save crontab:
crontab -l > /tmp/evidence_crontab_$(date +%Y%m%d%H%M%S).txt

# Save Docker state:
docker ps -a > /tmp/evidence_docker_ps_$(date +%Y%m%d%H%M%S).txt

# Transfer all evidence to a safe location (NOT on this server):
scp /tmp/evidence_* root@safe-machine:/incidents/$(date +%Y%m%d)/
```

## Investigate: Check for Compromise

### Login trails

```bash
secure-vps  # c1 → 7 (登录轨迹 / Login Trail)
# Shows last 15 failed login attempts and recent login history
```

Manual investigation:

```bash
# Who logged in recently?
last -50
# Look for:
# - Logins from unexpected countries/IPs
# - Logins at unusual hours
# - Users you don't recognize

# Failed login attempts (brute-force evidence):
lastb -50

# Auth log — successful and failed SSH:
grep 'Accepted' /var/log/auth.log | tail -30
grep 'Failed password' /var/log/auth.log | tail -30

# Check for SSH key changes:
cat /root/.ssh/authorized_keys
# Compare with your known keys. Any unknown key = backdoor.
cat /home/*/.ssh/authorized_keys
# Check ALL users, not just root.
```

### Process list

```bash
# Look for suspicious processes:
ps aux --sort=-%cpu | head -20
# Red flags:
# - High CPU process with a weird name (xmrig, kdevtmpfsi, kinsing)
# - Process running from /tmp, /dev/shm, or /var/tmp
# - Process you don't recognize using lots of network
# - Python/perl processes you didn't start

# Check process executable paths:
ls -la /proc/*/exe 2>/dev/null | grep -E '/tmp|/dev/shm|/var/tmp'
# Any result = suspicious (malware often runs from temp directories)

# Find processes with deleted executables (rootkit indicator):
ls -la /proc/*/exe 2>/dev/null | grep '(deleted)'
# Some result = process binary was deleted after starting (common rootkit technique)
```

### Network connections

```bash
# Established connections to unexpected destinations:
ss -tunp | grep ESTAB
# Look for:
# - Connections to known mining pool ports (3333, 4444, 5555, 7777, 14444)
# - Connections to unknown foreign IPs
# - Outbound connections from processes that shouldn't make network calls

# Listening ports you didn't open:
ss -tlnp
# Compare with your known services. Any unknown listener = potential backdoor.

# Check for reverse shells (common attacker technique):
ss -tunp | grep -E 'ESTAB.*python|ESTAB.*bash|ESTAB.*nc'
```

### Unauthorized users

```bash
# Users with login shells:
grep -vE '/(nologin|false|sync)$' /etc/passwd
# Any user you didn't create = potential attacker account

# Users with UID 0 (root-equivalent):
awk -F: '$3==0 {print $1}' /etc/passwd
# Should be ONLY root. Any other = critical compromise.

# Users in sudo/wheel groups:
getent group sudo wheel
# Any unexpected member = privilege escalation

# Recently created users (check home directory timestamps):
ls -lt /home/
# New directories = recently created users

# Check /etc/passwd modification time:
stat /etc/passwd
# If recently modified and you didn't add a user = tampering
```

### Unauthorized SSH keys

```bash
# Check ALL authorized_keys files:
find / -name authorized_keys -exec ls -la {} \; -exec cat {} \; 2>/dev/null
# Compare every key with your known keys.
# Attackers add their keys to maintain access even if you change passwords.

# Check SSH config for unauthorized changes:
sshd -T | grep -E 'permitrootlogin|passwordauthentication|allowusers'
# If these changed from your baseline (Ch.02), the attacker may have weakened SSH.
```

### Unauthorized cron jobs

```bash
# User crontabs:
for user in $(cut -d: -f1 /etc/passwd); do
  crontab -u $user -l 2>/dev/null && echo "  ^-- user: $user"
done

# System cron:
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /etc/cron.daily/
ls -la /etc/cron.hourly/

# Look for:
# - Download commands (curl/wget to unknown URLs)
# - Base64-encoded commands (obfuscation)
# - Jobs running from /tmp or /dev/shm
# - Jobs you didn't create
```

## Investigate: Malware Detection

### rkhunter (rootkit hunter)

```bash
secure-vps  # b4 → 7 (Rkhunter 防御)
# Installs rkhunter, builds baseline, sets up daily cron scan
# Daily scan logs to /var/log/rkhunter-cron.log
```

Manual run:

```bash
rkhunter --update          # update rootkit signatures
rkhunter --check --sk      # scan without interactive prompts
# Warning: ... possible rootkit infection
# Checking for known rootkit files and directories
#   [ Warning ]: file '/usr/bin/sshd' has properties that suggest it was modified

cat /var/log/rkhunter-cron.log
# Daily scan results
```

**rkhunter checks for**:
- Known rootkit files and directories
- Modified system binaries (sshd, login, passwd)
- Hidden files in standard directories
- Suspicious kernel modules
- promiscuous network interfaces
- Unauthorized SSH keys in default locations

**False positives are common** after legitimate system updates. Always re-run after `apt upgrade` and update the baseline:

```bash
rkhunter --propupd    # update file property database after legitimate changes
```

### AIDE (file integrity)

```bash
secure-vps  # b4 → 8 → 3 (AIDE 立即比对)
# Compares current filesystem state against the baseline
```

Manual:

```bash
aide --check
# AIDE found differences:
# Added: /usr/local/bin/suspicious_binary    ← NEW FILE (investigate!)
# Changed: /etc/passwd                        ← MODIFIED (who changed it?)
# Changed: /usr/sbin/sshd                     ← MODIFIED (rootkit?)
# Removed: /etc/cron.d/backup                 ← DELETED (by whom?)
```

**Critical findings**:
- **Changed system binaries** (`/usr/bin/*`, `/usr/sbin/*`) → likely rootkit — the binary was replaced with a trojaned version
- **New SUID binaries** → privilege escalation backdoor
- **Changed `/etc/passwd` or `/etc/shadow`** → attacker added a user or changed a password
- **Changed `/etc/sudoers`** → attacker granted themselves sudo

If AIDE was not set up before the compromise, it can't help retroactively — but set it up now for future detection.

### Manual binary verification

```bash
# Verify package integrity against the package manager's database:
# Debian/Ubuntu:
dpkg --verify
# ??5??????   /usr/bin/ssh       ← "5" = md5 checksum mismatch (modified!)

# RHEL family:
rpm -Va
# S.5....T.  /usr/bin/ssh         ← "5" = md5 mismatch, "T" = mtime changed
```

Any mismatch on security-critical binaries (`ssh`, `sshd`, `login`, `passwd`, `sudo`) is a strong indicator of a rootkit.

## Fix: Post-Incident Actions

### Step 1: Password changes

Change ALL passwords, but only after you've isolated the server and preserved evidence:

```bash
# Root password:
passwd

# All user passwords:
for user in $(grep -vE '/(nologin|false)$' /etc/passwd | cut -d: -f1); do
  echo "Change password for $user"
  passwd $user
done

# Database passwords (if compromised):
docker exec -it mysqld mysql -u root -p -e "ALTER USER 'root'@'localhost' IDENTIFIED BY 'new-password';"
# Update your app's config with the new password
```

### Step 2: SSH key rotation

The attacker may have copied your private keys (if they had root access) or added their own public keys:

```bash
# Remove ALL unauthorized keys:
find / -name authorized_keys -exec sh -c 'echo "Reviewing: $1"; cat "$1"' _ {} \;

# After identifying unauthorized keys, remove them:
echo "" > /root/.ssh/authorized_keys
# Re-add ONLY your known keys (from GitHub or your local machine):
curl -sL https://github.com/yourname.keys >> /root/.ssh/authorized_keys

# Generate NEW SSH keys on your client (old keys may be compromised):
ssh-keygen -t ed25519 -C "you@server-new-$(date +%Y%m)"
# Deploy the new public key to the server
# Remove old keys from authorized_keys
```

### Step 3: Remove attacker access

```bash
# Remove unauthorized user accounts:
userdel -r suspicious_user    # -r removes home directory

# Remove unauthorized cron jobs:
crontab -r                    # remove current user's crontab (recreate legitimate ones)
rm /etc/cron.d/suspicious_job

# Kill malicious processes:
pkill -f xmrig
pkill -f kdevtmpfsi
# Find and kill by PID if name-based doesn't work:
ps aux | grep -E 'xmrig|kdevtmpfsi|kinsing'
kill -9 <pid>

# Remove malicious files:
rm -f /tmp/.X11-unix/xmrig
rm -f /usr/local/bin/suspicious_binary
# Be careful — only delete files you've confirmed are malicious
```

### Step 4: Log preservation

Before any cleanup, preserve all logs for forensic analysis:

```bash
# Copy all logs to a safe location:
tar czf /tmp/incident_logs_$(date +%Y%m%d).tar.gz /var/log/
scp /tmp/incident_logs_*.tar.gz root@safe-machine:/incidents/

# Include the evidence collected earlier:
scp /tmp/evidence_* root@safe-machine:/incidents/$(date +%Y%m%d)/
```

## Investigate: Root Cause Analysis

### How did they get in?

After containment, determine the entry vector. This determines your prevention strategy:

| Entry vector | Evidence | Prevention |
|-------------|----------|------------|
| Weak SSH password | auth.log shows successful login after brute force | Key-only auth (Ch.02) |
| Exposed database port | ss shows 3306/27017 listening on 0.0.0.0 | Firewall + bind to localhost |
| Vulnerable web app | Web access logs show exploit payload | Update app, WAF |
| Compromised dependency | Package install logs, npm/pip history | Lock dependencies, scan |
| Stolen credentials | Login from attacker's IP with valid creds | Key rotation, 2FA |
| Docker socket exposed | Portainer/Docker API on public port | Bind to localhost, firewall |
| Outdated software with CVE | Package versions match known CVEs | Automatic security updates (Ch.02) |

### Check the web server logs

```bash
# Nginx access log — look for exploit attempts:
grep -E 'union|select|script|eval|base64' /var/log/nginx/access.log | tail -50
# SQL injection, XSS, RCE attempts

# Check for successful exploitation:
grep ' 200 ' /var/log/nginx/access.log | grep -E 'upload|admin|shell|cmd'
# Successful requests to suspicious paths

# Check POST requests (data exfiltration or upload):
grep 'POST' /var/log/nginx/access.log | tail -50
```

### Check package installation history

```bash
# Debian/Ubuntu — what was installed recently:
grep ' installed ' /var/log/dpkg.log | tail -30
# 2024-01-15 10:23:45 install suspicious-package:amd64 1.0

# RHEL:
grep 'Installed:' /var/log/yum.log | tail -30
```

### Check command history

```bash
# Root's command history:
cat /root/.bash_history
# Look for commands you didn't run

# Other users:
cat /home/*/.bash_history
# Attackers sometimes forget to clear history

# Check if history was cleared (empty file is suspicious):
wc -l /root/.bash_history
# 0 lines = either new shell or history was wiped
```

## Fix: Recovery

### Option A: Restore from backup (if you trust the backup)

If you have clean backups from before the compromise (Chapter 06):

```bash
# 1. Provision a fresh server
# 2. Run secure-vps a1 (baseline setup)
# 3. Apply security baseline (Ch.02)
# 4. Restore data from backup (using backup-kit or manual restore)
# 5. Verify data integrity
# 6. Switch DNS to the new server
```

**Risk**: if the compromise predates your backup, you're restoring compromised data. Verify the backup's integrity (AIDE check, database consistency checks) before trusting it.

### Option B: Rebuild from scratch (safest)

If you can't trust any data on the compromised server:

```bash
# 1. Provision a fresh server
# 2. Run secure-vps a1 (baseline setup)
# 3. Apply FULL security baseline (Ch.02):
#    - SSH key-only auth
#    - Firewall (only needed ports)
#    - Fail2Ban
#    - Kernel hardening
#    - Password policy
#    - sudo audit
# 4. Install Docker (Ch.03)
# 5. Apply Docker UFW fix (Ch.03)
# 6. Deploy applications from known-good compose files
# 7. Restore ONLY database dumps (not full volumes) from backup
#    - Database dumps are safer than volume copies (less likely to contain malware)
# 8. Set up monitoring (Ch.07) before going live
# 9. Set up backups (Ch.06) with backup-kit
```

**This is the recommended approach for root-level compromises.** You can never be 100% certain you've removed all backdoors from a compromised system. A clean rebuild eliminates uncertainty.

### When to rebuild vs. restore

| Situation | Approach |
|-----------|----------|
| Attacker had root access | Rebuild (can't trust anything) |
| Attacker had user-level access only | Restore may be OK (after removing attacker's changes) |
| Web defacement only | Restore (low-depth compromise) |
| Cryptominer, no evidence of deeper access | Restore + patch the entry vector |
| Rootkit detected (rkhunter/AIDE) | Rebuild (rootkit may have hidden backdoors) |
| Uncertain about depth of compromise | Rebuild (safest) |

**Recommendation**: when in doubt, rebuild. The cost of a rebuild (2-4 hours) is far less than the cost of missing a backdoor and getting compromised again.

## Fix: Prevention

### Harden with vps-bootstrap

After recovery, apply modular hardening with **vps-bootstrap** to ensure the same attack vector can't be used again:

- SSH hardening module (key-only auth, non-standard port, AllowUsers)
- Firewall module (default deny, only needed ports)
- Kernel hardening module (CIS baseline sysctl params)
- Fail2Ban module (brute-force protection)
- Docker hardening (UFW takeover fix)

vps-bootstrap makes hardening reproducible — if you rebuild, you can reapply the exact same configuration from code.

### Continuous monitoring with security-audit

**security-audit** provides ongoing protection:

- **CIS Benchmark compliance scoring**: track your security posture over time
- **Drift detection**: alert when security configurations change from baseline
- **Vulnerability scanning**: identify known CVEs in installed packages
- **Scheduled audits**: run automatically and report changes

Set up security-audit to run weekly. If a future configuration change weakens your security, you'll know before an attacker exploits it.

### Update everything

```bash
# Full system update:
apt update && apt upgrade -y    # or: yum update -y

# Update Docker images:
docker compose pull
docker compose up -d

# Update all running containers (if using Watchtower):
# Watchtower checks daily and updates automatically
# (Ch.03 — but only for non-critical services)

# Check for known vulnerabilities:
apt list --upgradable
# Or use security-audit for CVE scanning
```

### Enable automatic security updates

```bash
secure-vps  # b4 → 6 (自动安全更新)
# Enables unattended-upgrades (Debian/Ubuntu) or dnf-automatic (RHEL)
# Installs security updates daily automatically
```

## Incident Checklist Template

Copy this into your runbook and fill in during an incident:

```
INCIDENT: [description]
DATE/TIME DETECTED: [timestamp]
DETECTED BY: [monitoring alert / user report / provider notification]

=== Phase 1: Isolate (first 10 minutes) ===
[ ] Server isolated (network blocked / VNC access only)
[ ] Volatile evidence captured (ps, ss, last, auth.log, dmesg)
[ ] Evidence transferred to safe location
[ ] Provider notified (if abuse/compromise)

=== Phase 2: Assess (first hour) ===
[ ] Login trails reviewed (secure-vps c1 → 7)
[ ] Process list reviewed for malware
[ ] Network connections reviewed for C2/exfil
[ ] User accounts checked for unauthorized additions
[ ] SSH keys checked for unauthorized additions
[ ] Cron jobs checked for persistence
[ ] rkhunter scan completed (secure-vps b4 → 7)
[ ] AIDE integrity check completed (secure-vps b4 → 8 → 3)
[ ] Root cause identified: [entry vector]

=== Phase 3: Remediate ===
[ ] Attacker access removed (users, keys, cron, processes)
[ ] All passwords changed
[ ] SSH keys rotated (new keys generated, old keys removed)
[ ] Vulnerability patched (entry vector closed)
[ ] Decision: rebuild or restore [chosen approach + reason]

=== Phase 4: Recover ===
[ ] Fresh server provisioned (if rebuild)
[ ] Baseline applied (secure-vps a1 + Ch.02 security baseline)
[ ] Data restored from backup (if applicable)
[ ] Monitoring deployed (Ch.07)
[ ] Backups configured (Ch.06, backup-kit)

=== Phase 5: Post-Incident ===
[ ] Root cause documented
[ ] Prevention measures implemented (vps-bootstrap, security-audit)
[ ] Incident report written
[ ] Lessons learned shared with team
[ ] Monitoring alerts tuned based on this incident
```

## What's Next

- **Chapter 02** — Security baseline: the prevention measures that stop most attacks before they happen
- **Chapter 06** — Backup and migration: the backups that make recovery possible
- **Chapter 07** — Monitoring and alerts: the detection that shortens incident response time
