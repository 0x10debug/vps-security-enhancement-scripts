# Security Baseline

> Harden SSH, firewall, fail2ban, and the kernel before you expose a single service to the internet.

## Overview

A VPS on the public internet receives SSH brute-force attempts within minutes of going online. The default configuration on most distros is built for convenience, not security: password authentication is enabled, SSH listens on port 22, the firewall is inactive, and there's no intrusion prevention. This chapter builds the security baseline that every server should have regardless of what it hosts.

We follow the closed loop: **Problem (default-soft server) → Investigate (what's exposed and weak?) → Fix (SSH hardening, firewall, fail2ban, kernel, password policy, sudo audit) → Verify (confirm each layer is active and tested)**. Each fix references the corresponding `vps_secure.sh` menu entry so you can apply it interactively, and cross-references the 0x10debug ecosystem tools for when you need modular, auditable, or compliance-grade hardening.

Security is layered. No single control is sufficient — SSH hardening alone won't stop a web app exploit, and a firewall alone won't stop credential stuffing. The baseline here addresses the most common attack vectors against the server itself: unauthorized login, port scanning, brute force, and kernel-level network abuse.

## Problem: The Default Server Is a Soft Target

```bash
# What a fresh Ubuntu/Debian server looks like to an attacker:
ss -tlnp | grep 22
# LISTEN 0.0.0.0:22  sshd   ← predictable port, password auth on

ufw status
# Status: inactive          ← no firewall at all

systemctl is-active fail2ban
# inactive                  ← no brute-force protection
```

Within an hour, bots will find your IP and start hammering port 22 with common credentials. If your root password is weak or reused, you're compromised before you finish setup.

## Investigate: What's Exposed and Weak

### SSH exposure

```bash
# What port is sshd actually listening on? (sshd -T expands Include directives)
sshd -T | grep -E '^port|^passwordauthentication|^permitrootlogin'
# port 22
# passwordauthentication yes
# permitrootlogin yes        ← root can login with password

# Recent failed login attempts (brute-force evidence):
secure-vps  # c1 → 7 (登录轨迹 / Login Trail)
# Shows last 15 failed attempts from /var/log/btmp
```

If you see dozens of failed attempts already, that's the background radiation of the internet — proof that the threat is real and continuous.

### Who has root access

```bash
# Users with sudo or wheel group membership:
getent group sudo wheel
# sudo:x:27:ubuntu,deploy

# Users with UID 0 (should be only root):
awk -F: '$3==0 {print $1}' /etc/passwd
# root

# Users with valid login shells:
grep -vE '/(nologin|false)$' /etc/passwd | cut -d: -f1
# root
# ubuntu
# deploy
```

Every account with a login shell is an attack surface. If there are accounts you don't recognize, investigate immediately (Chapter 08).

### Firewall state

```bash
ufw status verbose          # Debian/Ubuntu
firewall-cmd --list-all     # RHEL family
iptables -L -n              # raw view, always available
```

## Fix: SSH Hardening

### Step 1: Import your public key and disable password auth

The single most impactful security change: switch to key-only authentication.

```bash
secure-vps  # b1 → 2 (导入 GitHub 公钥并关闭密码登录)
# Enter your GitHub username: yourname
# Pulls https://github.com/yourname.keys into ~/.ssh/authorized_keys
# Then asks: disable password login now? (y/N)
```

What it does behind the scenes:
- Fetches your public keys from `github.com/<user>.keys`
- Appends to `~/.ssh/authorized_keys` (deduped, permissions 600)
- Sets `PasswordAuthentication no`, `PubkeyAuthentication yes`
- Sets `KbdInteractiveAuthentication no`, `ChallengeResponseAuthentication no` (if the sshd version supports them)
- Validates with `sshd -t` before restarting; auto-rolls back on failure

**Critical**: Do NOT close your current SSH session after this. Open a new terminal, confirm key-based login works, THEN close the original session. If you skip this and something is wrong, you're locked out.

If you don't use GitHub for key distribution, do it manually:

```bash
# On your local machine:
ssh-keygen -t ed25519 -C "you@server"
ssh-copy-id root@203.0.113.10

# On the server, after confirming key login works in a new terminal:
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sshd -t && systemctl restart sshd
```

### Step 2: Apply the SSH baseline parameter pack

```bash
secure-vps  # b1 → 3 (SSH 基线参数包)
```

This applies anti-brute-force parameters:

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `MaxAuthTries` | 3 | Max auth attempts per connection |
| `LoginGraceTime` | 30 | Disconnect if login not completed in 30s |
| `ClientAliveInterval` | 120 | Probe client every 2 min |
| `ClientAliveCountMax` | 3 | Drop after 3 missed probes (6 min) |
| `X11Forwarding` | no | Disable X11 forwarding (attack surface) |
| `UseDNS` | no | Skip reverse DNS, faster handshake |
| `PermitEmptyPasswords` | no | Reject empty passwords |
| `StrictModes` | yes | Validate key file ownership/permissions |
| `GSSAPIAuthentication` | no | Disable GSSAPI (unnecessary on VPS) |

These are conservative — they don't break normal SSH usage but eliminate common abuse patterns. `vps_secure.sh` snapshots the config before changes and auto-rolls back if `sshd -t` fails.

### Step 3: Change the SSH port

Moving off port 22 eliminates ~90% of automated brute-force traffic (bots scan port 22 by default). It's not real security (a targeted scan finds any port), but it dramatically reduces log noise and fail2ban load.

```bash
secure-vps  # b1 → 4 (更换 SSH 端口)
# Recommended: 20000-60000 (avoid well-known ports)
# Enter new port: 50022
```

What the script handles automatically:
- Checks the new port isn't already in use (`ss -tln`)
- **Opens the new port in the firewall BEFORE changing sshd** (prevents self-lockout)
- On SELinux Enforcing systems, registers the port with `semanage port -a -t ssh_port_t`
- Snapshots `sshd_config`, applies the change, validates with `sshd -t`
- Confirms sshd is actually listening on the new port (`ss -tln`)
- **Syncs Fail2Ban's jail port** to match (otherwise ban rules target the wrong port)
- Reminds you to update the cloud security group

**After changing the port, test from a new terminal:**

```bash
ssh -p 50022 root@203.0.113.10
# Must succeed before you close the original session.
```

### Step 4: Lock root password login (keep key login)

```bash
secure-vps  # b1 → 5 (封禁 root 密码登录)
```

Sets `PermitRootLogin prohibit-password` — root can still login with a key, but not with a password. This is the recommended balance: you keep root access for emergencies but eliminate password-based root attacks. The script checks that root actually has authorized keys before applying, and warns if not (to prevent accidental self-lockout).

### Step 5: Restrict login to specific users (AllowUsers)

```bash
secure-vps  # b1 → 6 (登录白名单 / AllowUsers)
# Enter allowed users: deploy ubuntu
```

Only the listed users can SSH in. All other accounts (system accounts, service accounts) are blocked from SSH even if they have valid credentials. The script validates that the usernames actually exist before applying — a typo in AllowUsers can lock everyone out.

## Fix: Firewall

### Deploy and configure

```bash
secure-vps  # b2 → 1 (初始化并启用)
```

This installs UFW (Debian/Ubuntu) or firewalld (RHEL family), then allows:
- The current SSH port (auto-detected via `sshd -T`)
- Port 80 (HTTP)
- Port 443 (HTTPS)

Default policy is **deny incoming, allow outgoing** — the correct baseline. You then open additional ports as needed:

```bash
secure-vps  # b2 → 3 (放行自定义端口)
# Enter port: 8080

# Or manually:
ufw allow 8080/tcp
ufw reload
```

### Check rules

```bash
secure-vps  # b2 → 2 (查看状态与规则)

# Manual:
ufw status numbered
#      [1] 50022/tcp         ALLOW IN    Anywhere
#      [2] 80/tcp            ALLOW IN    Anywhere
#      [3] 443/tcp           ALLOW IN    Anywhere
#      [4] 8080/tcp          ALLOW IN    Anywhere
```

**Principle**: open the minimum set of ports. Every open port is a potential attack surface. If you're not sure a service needs to be public, don't open it — use an SSH tunnel or WireGuard for private access instead.

## Fix: Fail2Ban

### Deploy

```bash
secure-vps  # b3 → 1 (部署防护)
```

Creates `/etc/fail2ban/jail.local` with:

```ini
[DEFAULT]
bantime = 86400      # 24 hours
findtime = 600       # 10 minute window
maxretry = 5         # 5 failures → ban

[sshd]
enabled = true
port = 50022         # auto-synced to your SSH port
backend = systemd    # Ubuntu/Debian (reads journald)
```

On RHEL/CentOS 7, it uses the default backend (reads `/var/log/secure`) because the older fail2ban doesn't support the systemd backend.

### Tune ban parameters

The defaults (5 tries → 24h ban) are reasonable for most servers. For higher-risk exposures, tighten:

```bash
# Edit /etc/fail2ban/jail.local:
[DEFAULT]
bantime = 259200     # 72 hours for repeat offenders
findtime = 3600      # 1 hour window
maxretry = 3         # stricter

# Or use recidive jail for chronic attackers:
[recidive]
enabled = true
bantime = 604800     # 7 days
findtime = 86400
maxretry = 3

systemctl restart fail2ban
```

### Monitor

```bash
secure-vps  # b3 → 2 (查看状态与封禁名单)
# Shows fail2ban-client status sshd: currently banned IPs, total banned

secure-vps  # b3 → 3 (查看拦截日志)
# Tails last 15 lines of /var/log/fail2ban.log
```

**Port sync is critical**: if you change the SSH port later (b1 → 4), `vps_secure.sh` automatically updates the Fail2Ban jail port. If you change it manually, you must update `/etc/fail2ban/jail.local` yourself — otherwise Fail2Ban monitors the wrong port and bans nothing.

## Fix: Kernel Hardening

```bash
secure-vps  # b4 → 2 (内核参数加固)
```

Writes `/etc/sysctl.d/99-secure-vps-kernel.conf` with CIS-baseline parameters adapted for VPS:

```ini
# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048

# Anti-spoofing (loose mode for multi-IP compatibility)
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2

# Reject source routing and redirects
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# ICMP hardening
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.log_martians = 1

# Kernel info restriction
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.perf_event_paranoid = 2
kernel.randomize_va_space = 2
fs.suid_dumpable = 0
```

**Note on `rp_filter=2`**: loose mode (2) is used instead of strict mode (1) because strict mode breaks multi-IP and policy-routing setups common on VPS. If your server has a single IP and simple routing, you can set it to 1 for stricter anti-spoofing.

**Note on `ptrace_scope=1`**: this restricts non-parent processes from debugging. Normal users running `strace` on their own processes will be limited — this is expected behavior, not a bug.

To undo (if something breaks):

```bash
secure-vps  # b4 → 3 (撤销内核加固)
# Removes the config file and reloads sysctl
```

## Fix: Docker UFW Bypass (Critical)

This is the most commonly missed security hole on Docker+UFW servers. See Chapter 03 for the full technical explanation — here's the summary:

**The problem**: When you run `docker run -p 8080:80 nginx`, Docker writes iptables rules directly, bypassing UFW entirely. The container's port is exposed to the public internet even if UFW denies it. Your firewall is an illusion.

**The fix**:

```bash
secure-vps  # d1 → 1 → 3 (Docker 引擎 → UFW 接管)
```

This sets `"iptables": false` in `/etc/docker/daemon.json` and injects a NAT rule for the docker0 bridge into `/etc/ufw/before.rules`. After this, all container ports are controlled by UFW — you must explicitly `ufw allow <port>` for each container you want public.

**Impact**: existing published container ports immediately become unreachable from outside (this is the point — you now control them). You must `ufw allow` each one intentionally.

**Only works on UFW systems** (Ubuntu/Debian). On firewalld systems, Docker integrates with firewalld differently and this bypass doesn't occur in the same way.

## Fix: Password Policy

```bash
secure-vps  # b4 → 4 (密码强度策略)
```

Installs `libpam-pwquality` (Debian/Ubuntu) or `libpwquality` (RHEL) and writes `/etc/security/pwquality.conf`:

```ini
minlen = 12           # minimum 12 characters
dcredit = -1          # at least 1 digit
ucredit = -1          # at least 1 uppercase
lcredit = -1          # at least 1 lowercase
ocredit = -1          # at least 1 special character
maxrepeat = 3         # no more than 3 identical consecutive chars
usercheck = 1         # reject passwords containing username
enforcing = 1         # enforce for all password changes
```

This only affects passwords set AFTER the policy is applied — existing passwords are not force-changed. New users and password resets must comply.

## Fix: Sudo Audit

```bash
secure-vps  # b4 → 5 (sudo 审计)
```

Creates `/etc/sudoers.d/95-secure-vps-audit`:

```
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
```

- `use_pty` runs sudo commands in a pseudo-terminal, preventing terminal hijacking and ensuring proper I/O logging
- `logfile` records every sudo invocation with user, command, and timestamp to `/var/log/sudo.log`

Check who has sudo:

```bash
cat /var/log/sudo.log    # audit trail
getent group sudo wheel  # who has sudo rights
```

## Fix: Attack Surface Reduction

```bash
secure-vps  # b4 → 10 (收缩攻击面)
```

Disables unnecessary services that ship enabled on minimal installs:
- `avahi-daemon` (mDNS/zeroconf — useless on a server)
- `cups` (printing — useless on a server)
- `bluetooth` (no Bluetooth hardware on VPS)
- `ModemManager` (modem management — no modems on VPS)

## Cross-Reference: Ecosystem Tools

### vps-bootstrap (modular hardening)

When you need reproducible, reviewable hardening across multiple servers, **vps-bootstrap** breaks the baseline into independent modules. Use it when:
- You manage a fleet and need identical configs
- You want the hardening documented as code (git-tracked)
- You need to reapply hardening after a rebuild

### security-audit (CIS compliance)

For compliance requirements (CIS Benchmark, PCI-DSS, etc.), **security-audit** runs a structured CIS benchmark assessment and produces a scored report. Use it when:
- You need to prove compliance to an auditor
- You want to track hardening drift over time
- You need specific CIS controls that go beyond the `vps_secure.sh` baseline

The `vps_secure.sh` baseline covers the most impactful CIS controls but is not a complete CIS implementation. For full coverage, run security-audit after applying the baseline.

## Verify: Security Verification Checklist

### SSH

```bash
sshd -T | grep -E 'port|passwordauthentication|permitrootlogin|maxauthtries|permitemptypasswords'
# port 50022
# passwordauthentication no
# permitrootlogin prohibit-password
# maxauthtries 3
# permitemptypasswords no

# Confirm key login works (new terminal):
ssh -p 50022 -i ~/.ssh/id_ed25519 root@203.0.113.10
# Must succeed.

# Confirm password login is rejected:
ssh -p 50022 root@203.0.113.10
# Permission denied (publickey).  ← password prompt should NOT appear
```

### Firewall

```bash
ufw status verbose | grep -E 'Status|Default|ALLOW'
# Status: active
# Default: deny (incoming), allow (outgoing)
# 50022/tcp ALLOW IN
# 80/tcp ALLOW IN
# 443/tcp ALLOW IN

# Test from external machine:
nmap -p 22,50022,80,443 203.0.113.10
# 22/tcp     closed    ← old port blocked
# 50022/tcp  open      ← new SSH port
# 80/tcp     open
# 443/tcp    open
```

### Fail2Ban

```bash
systemctl is-active fail2ban     # active
fail2ban-client status sshd      # jail running, port matches SSH
grep 'port' /etc/fail2ban/jail.local
# port = 50022   ← must match sshd port
```

### Kernel

```bash
sysctl net.ipv4.tcp_syncookies kernel.kptr_restrict kernel.randomize_va_space
# net.ipv4.tcp_syncookies = 1
# kernel.kptr_restrict = 2
# kernel.randomize_va_space = 2
```

### Password policy

```bash
cat /etc/security/pwquality.conf | grep -vE '^#|^$'
# minlen = 12, dcredit = -1, etc.

# Test: try setting a weak password for a test user:
passwd testuser
# New password: 123
# BAD: too short, too simplistic
# passwd: Authentication token manipulation error  ← policy enforced
```

### Sudo audit

```bash
cat /var/log/sudo.log
# May 15 10:23:01 : root : TTY=pts/0 ; PWD=/root ; COMMAND=/usr/bin/apt update

ls -la /etc/sudoers.d/95-secure-vps-audit
# -r--r----- 1 root root ... 95-secure-vps-audit
```

### Docker UFW bypass (if Docker is installed)

```bash
grep iptables /etc/docker/daemon.json
# "iptables": false   ← fix applied

# Run a test container with -p and confirm it's NOT reachable
# until you ufw allow the port:
docker run -d -p 9999:80 --name test nginx
curl -m 3 http://203.0.113.10:9999   # should timeout (UFW blocks)
ufw allow 9999/tcp
curl http://203.0.113.10:9999        # now works
ufw delete allow 9999/tcp
docker rm -f test
```

## What's Next

- **Chapter 03** — Docker operations: installation, mirror acceleration, log rotation, and the full Docker-UFW bypass explanation
- **Chapter 07** — Monitoring: how to detect brute-force attempts and intrusion indicators in real time
- **Chapter 08** — Incident response: what to do when the baseline wasn't enough
