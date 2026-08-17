# New Server Setup

> First 30 minutes on a fresh VPS: assess, harden, and verify before you deploy anything.

## Overview

You just received the welcome email from your VPS provider: an IP address, a root password, and a login command. What you do in the next 30 minutes determines whether this server survives its first week on the public internet. A default VPS is a soft target — predictable SSH port, password authentication enabled, no firewall, no fail2ban, no swap on small instances, and a timezone that probably isn't yours.

This chapter walks through the full first-login workflow: initial assessment, system update, timezone and clock sync, the quick-init path via `secure-vps` → `a1`, and the post-setup verification checklist. We follow the closed loop: **Problem (fresh unhardened server) → Investigate (what did the provider give me?) → Fix (update, harden, sync) → Verify (confirm every change took effect)**.

The goal is not to do everything manually — `vps_secure.sh` exists to automate the repetitive parts — but to understand what each step does, so when automation fails or behaves unexpectedly, you know exactly where to look.

## Problem: You Just Got a Fresh VPS

You SSH in for the first time:

```bash
ssh root@203.0.113.10
# Are you sure you want to continue connecting? yes
# root@203.0.113.10's password: ********
```

You are now root on a machine that the entire internet can reach. Before you install anything, you need to know what you're working with.

## Investigate: Initial Assessment

### What distro, what kernel, what resources

```bash
cat /etc/os-release
# PRETTY_NAME="Ubuntu 22.04.4 LTS"
# ID=ubuntu  VERSION_ID="22.04"

uname -r
# 5.15.0-101-generic   (BBR needs ≥ 4.9, this is fine)

lscpu | grep -E 'Model name|^CPU\(s\)|Architecture'
# Architecture:        x86_64
# CPU(s):              2
# Model name:          Intel Xeon E5-26xx (Skylake)

free -h
#               total   used   free   available
# Mem:          1.9Gi   120Mi  1.7Gi  1.7Gi

df -h /
# Filesystem  Size  Used Avail Use% Mounted on
# /dev/vda1   39G   2.1G  37G   6%  /
```

The fastest single command to get all of this at once is `secure-vps` → `c1` → `1` (主机档案 / Host Profile). It prints distro, kernel, architecture, CPU model, core count, RAM, disk, SSH port, uptime, virtualization type, and public IP geolocation in one screen. Run it before anything else — it's read-only and gives you the complete picture.

### Network configuration

```bash
ip -br addr
# lo               UNKNOWN        127.0.0.1/8 ::1/128
# eth0             UP             203.0.113.10/24

ip route
# default via 203.0.113.1 dev eth0

cat /etc/resolv.conf
# nameserver 8.8.8.8
# nameserver 1.1.1.1
```

Note the default gateway and DNS. If DNS is set to the provider's resolvers and they're slow or unreliable, you'll want to switch (covered below).

### Is there swap?

```bash
swapon --show
# (empty output = no swap)
```

Most small VPS instances (1-2 GB RAM) ship without swap. This is a ticking bomb — the first memory spike will trigger the OOM killer and silently kill your processes. We fix this in the initialization step.

### What's listening?

```bash
ss -tlnp
# State   Local Address:Port   Process
# LISTEN  0.0.0.0:22           sshd
```

On a clean install, only SSH should be listening. If you see other ports (3306, 6379, 8080), the provider pre-installed something — find out what before you expose it.

## Fix: The Initialization Workflow

### Option A: Quick init via secure-vps a1

The `a1` quick lane runs six operations in sequence:

1. **`pkg_upgrade_all`** — full system update (`apt upgrade` or `yum update`)
2. **`fw_init`** — deploy firewall (UFW on Debian/Ubuntu, firewalld on RHEL family), allow SSH/80/443
3. **`net_bbr_enable`** — enable BBR congestion control (requires kernel ≥ 4.9)
4. **`mem_swap_build`** — create swap file (default 1 GB, swappiness=10)
5. **`f2b_deploy`** — install Fail2Ban, ban 24h after 5 failed SSH attempts
6. **`kernel_arm_core`** — write CIS-baseline kernel sysctl params (SYN cookies, anti-spoofing, etc.)

```bash
# Get the script onto the server (pick one):
curl -fsSL https://raw.githubusercontent.com/0x10debug/vps-secure-script/main/vps_secure.sh -o vps_secure.sh
chmod +x vps_secure.sh
./vps_secure.sh

# At the menu, type: a1
# Confirm when prompted
```

This takes 2-10 minutes depending on how many packages need updating and your disk speed. When it finishes, you have a baseline-hardened server.

**When to use `a1`**: new server, you want the standard baseline fast, and you trust the default parameters (1 GB swap, BBR on, CIS kernel subset). This covers 90% of new-VPS scenarios.

### Option B: Modular hardening via vps-bootstrap

For production servers where you need to review and customize each hardening step, or where you need reproducible config-as-code, use **vps-bootstrap** instead. It breaks the same hardening into modular, reviewable units:

- SSH hardening module (separate from firewall module)
- Firewall module with explicit port declarations
- Kernel hardening module with documented sysctl choices
- Fail2Ban module with tunable ban policy

**When to use vps-bootstrap**: you're managing multiple servers and want the same config applied identically; you need to audit what changed and when; you're feeding the result into `security-audit` for CIS compliance scoring. The tradeoff is more setup time and more files to maintain, in exchange for reproducibility and auditability.

**Recommendation**: For a single VPS you're setting up by hand, `a1` is faster and sufficient. For a fleet or a server that will be audited, start with vps-bootstrap so the hardening is documented and repeatable.

### Manual steps a1 does NOT cover

`a1` gets the system baseline in place, but a few things require your judgment and must be done manually:

**Change the root password** (if the provider emailed you one):

```bash
passwd
# Enter new UNIX password: ********
# Retype: ********
# passwd: updated successfully
```

Even if you plan to switch to key-only auth immediately, change the password first — the provider's password may have been transmitted in plaintext or stored in their support system.

**Set the timezone** (a1 does not touch this):

```bash
secure-vps  # then c1 → 2 (时区切换)
# Pick from: Asia/Shanghai, Asia/Hong_Kong, Asia/Tokyo,
#            Asia/Singapore, Europe/London, America/New_York
```

Or manually:

```bash
timedatectl set-timezone Asia/Shanghai
timedatectl
# Time zone: Asia/Shanghai (CST, +0800)
# NTP service: inactive     ← needs fixing
```

**Configure NTP time sync** (a1 does not start NTP):

```bash
secure-vps  # then c1 → 3 (NTP 时间同步)
# This installs chrony or systemd-timesyncd and enables it.
```

Or manually on systemd-based distros:

```bash
apt install -y systemd-timesyncd   # Debian/Ubuntu
timedatectl set-ntp true
timedatectl
# NTP service: active
# System clock synchronized: yes
```

Why this matters: if the clock drifts, TLS certificate validation breaks, log timestamps become unreliable, and cron jobs fire at wrong times. On a fresh VPS the clock is usually correct, but without NTP it will drift over weeks.

## Verify: Post-Setup Checklist

After `a1` plus the manual steps, verify each change actually took effect. Never trust "it ran without errors" — confirm the end state.

### System updated

```bash
# Check for pending updates
apt list --upgradable 2>/dev/null | grep -c upgradable
# 0  ← should be zero

# Or on RHEL family
yum check-update | grep -c '\.el'
# 0
```

### Firewall active

```bash
ufw status verbose
# Status: active
# Default: deny (incoming), allow (outgoing)
# 22/tcp                     ALLOW IN    Anywhere
# 80/tcp                     ALLOW IN    Anywhere
# 443/tcp                    ALLOW IN    Anywhere

# RHEL family:
firewall-cmd --list-all
# active: yes
# ports: 22/tcp 80/tcp 443/tcp
```

### BBR enabled

```bash
sysctl net.ipv4.tcp_congestion_control
# net.ipv4.tcp_congestion_control = bbr

sysctl net.core.default_qdisc
# net.core.default_qdisc = fq
```

If it shows `cubic` or `reno`, BBR didn't apply — check kernel version (`uname -r` must be ≥ 4.9) and whether the `tcp_bbr` module loaded (`lsmod | grep bbr`).

### Swap created

```bash
swapon --show
# NAME      TYPE  SIZE  USED  PRIO
# /swapfile file  1G    0B    -2

free -h
# Swap: 1.0Gi  0B  1.0Gi

grep swapfile /etc/fstab
# /swapfile none swap sw 0 0  ← must persist across reboots

sysctl vm.swappiness
# vm.swappiness = 10  ← low value, prefer RAM over swap
```

### Fail2Ban running

```bash
systemctl is-active fail2ban
# active

fail2ban-client status sshd
# Status for the jail: sshd
# |- Currently failed: 0
# |- Currently banned: 0
# `- Total banned: 0
```

### Kernel hardening applied

```bash
sysctl net.ipv4.tcp_syncookies
# net.ipv4.tcp_syncookies = 1

sysctl kernel.kptr_restrict
# kernel.kptr_restrict = 2

ls -la /etc/sysctl.d/99-secure-vps-kernel.conf
# -rw-r--r-- 1 root root ... 99-secure-vps-kernel.conf
```

### Timezone and NTP

```bash
timedatectl
# Time zone: Asia/Shanghai (CST, +0800)
# NTP service: active
# System clock synchronized: yes
```

### SSH still accessible

```bash
# From your local machine, open a NEW terminal (don't close the existing session):
ssh root@203.0.113.10
# Should still connect with the password you set.
```

**Never close your working SSH session until you've confirmed a new session can connect.** If a1 or your manual changes locked you out, the working session is your lifeline to fix it.

## Common Pitfalls

### Wrong timezone causing log confusion

Symptom: you look at `/var/log/syslog` and the timestamps are 8 hours off from when you know something happened. You waste 20 minutes thinking logs are delayed or missing.

Cause: the provider set the timezone to UTC (or their local timezone), not yours. All logs, cron timestamps, and `journalctl --since` queries use the system timezone.

Fix: `secure-vps` → `c1` → `2`, or `timedatectl set-timezone <your_zone>`. Do this before you start generating logs you'll need to read.

### No swap on small VPS

Symptom: MySQL, Redis, or a Java process gets killed silently. `dmesg` shows `Out of memory: Killed process 1234 (mysqld)`.

Cause: 1 GB RAM VPS with zero swap. The first traffic spike or backup job pushes memory over the edge and the OOM kernel reaper fires.

Fix: `secure-vps` → `c2` → `2` (1 GB swap, recommended for 1-2 GB RAM). For larger servers with real workloads, size swap to 1-2x RAM only if you expect memory spikes; otherwise 1 GB is enough as an emergency buffer.

### Cloud security group vs OS firewall

`a1` configures the OS-level firewall (UFW/firewalld), but most cloud providers (AWS, GCP, Azure, Hetzner, Aliyun) also have an external security group / firewall at the network layer. **Both must allow a port for traffic to reach your service.** A common trap: you `ufw allow 443` but the cloud security group doesn't allow 443, so the service is unreachable and you blame UFW. Always check both layers — see Chapter 04 for the full decision tree.

### Changing SSH port without updating the cloud security group

If you later change the SSH port (Chapter 02), the cloud security group must also allow the new port. `vps_secure.sh` warns about this, but the warning is easy to miss. If you lock yourself out at the network layer, you'll need the provider's VNC/console rescue mode — which is slow and sometimes costs extra.

## What's Next

- **Chapter 02** — Security baseline: SSH key-only auth, port change, Fail2Ban tuning, the Docker-UFW bypass fix
- **Chapter 03** — Docker operations: installation, mirror acceleration, log rotation, the UFW bypass fix in detail
- **Chapter 04** — Network troubleshooting: the "service unreachable" decision tree
