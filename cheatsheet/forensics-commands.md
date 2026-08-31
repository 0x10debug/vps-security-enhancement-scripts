# Forensic Commands Cheatsheet

> One-page quick reference for incident response and forensic triage on Linux. Print on A4, pin to wall. All commands are **read-only** unless marked ⚠️.

---

## Process Investigation

| Command | What it does | Example |
|---|---|---|
| `ps auxww` | All processes (wide output) | `ps auxww \| grep -v '\['` |
| `ps -ef` | All processes with PPID | `ps -ef` |
| `ps -eo pid,ppid,user,cmd --forest` | Process tree | `ps -eo pid,ppid,user,cmd --forest` |
| `ps aux --sort=-%cpu \| head` | Top CPU consumers | `ps aux --sort=-%cpu \| head -20` |
| `ps aux --sort=-%mem \| head` | Top memory consumers | `ps aux --sort=-%mem \| head -20` |
| `top -b -n 1` | One-shot top snapshot | `top -b -n 1` |
| `pstree -p` | Tree view with PIDs | `pstree -p` |
| `cat /proc/<pid>/cmdline` | Exact command line (tr '\0' ' ') | `cat /proc/1234/cmdline \| tr '\0' ' '` |
| `readlink /proc/<pid>/exe` | Path to the binary | `readlink /proc/1234/exe` |
| `readlink /proc/<pid>/cwd` | Process working dir | `readlink /proc/1234/cwd` |
| `cat /proc/<pid>/maps` | Memory map (loaded libs) | `cat /proc/1234/maps` |
| `ls -l /proc/<pid>/fd` | Open file descriptors | `ls -l /proc/1234/fd` |
| `cat /proc/<pid>/environ` | Process environment | `cat /proc/1234/environ \| tr '\0' '\n'` |
| `lsof -p <pid>` | All open files for PID | `lsof -p 1234` |
| `lsof -i` | All network connections | `lsof -i` |

### Hidden process detection (rootkit indicator)

```bash
# PIDs in /proc but not shown by ps = possible rootkit
comm -23 \
  <(for p in /proc/[0-9]*; do basename "$p"; done | sort -n) \
  <(ps -e -o pid= | tr -d ' ' | sort -n)
```

### Processes running deleted binaries (malware indicator)

```bash
for p in /proc/[0-9]*; do
  exe=$(readlink "$p/exe" 2>/dev/null) || continue
  case "$exe" in *deleted*) echo "$(basename $p) $exe";; esac
done
```

---

## Network Investigation

| Command | What it does | Example |
|---|---|---|
| `ss -tlnp` | TCP listening ports + process | `ss -tlnp` |
| `ss -tulnpa` | All TCP/UDP sockets | `ss -tulnpa` |
| `ss -tunpa state established` | Established connections | `ss -tunpa state established` |
| `netstat -tlnp` | Listening (legacy) | `netstat -tlnp` |
| `netstat -tunpa \| grep ESTAB` | Established (legacy) | `netstat -tunpa \| grep ESTAB` |
| `lsof -i -nP` | Sockets by process | `lsof -i -nP` |
| `ip route` | Routing table | `ip route` |
| `ip neigh` | ARP/neighbor table | `ip neigh` |
| `cat /etc/resolv.conf` | DNS resolvers | `cat /etc/resolv.conf` |
| `cat /etc/hosts` | Static host entries | `cat /etc/hosts` |
| `iptables -L -n -v` | Firewall rules | `iptables -L -n -v` |
| `nft list ruleset` | nftables rules | `nft list ruleset` |
| `conntrack -L` | Tracked connections | `conntrack -L \| head` |
| `tcpdump -i any -n port 4444` | Live capture (⚠️ verbose) | `tcpdump -i any -n 'port 4444'` |

### Find outbound connections to non-local IPs

```bash
ss -tunpa state established | grep -vE '127\.0\.0\.|::1'
```

---

## File System Investigation

| Command | What it does | Example |
|---|---|---|
| `find / -xdev -type f -mtime -1` | Files modified in 24h | `find / -xdev -type f -mtime -1 2>/dev/null \| head` |
| `find / -xdev -type f -mmin -60` | Files modified in 60 min | `find / -xdev -type f -mmin -60 2>/dev/null` |
| `find / -xdev -perm -4000 -type f` | SUID binaries | `find / -xdev -perm -4000 -type f 2>/dev/null` |
| `find / -xdev -perm -2000 -type f` | SGID binaries | `find / -xdev -perm -2000 -type f 2>/dev/null` |
| `find / -xdev -type f -perm -0002` | World-writable files | `find / -xdev -type f -perm -0002 ! -path '/tmp/*' 2>/dev/null` |
| `find /tmp /var/tmp /dev/shm -type f` | Temp dir contents | `find /tmp /var/tmp /dev/shm -type f -ls` |
| `find / -name '.*' -type f` | Hidden files | `find /root /home /tmp -name '.*' -type f 2>/dev/null` |
| `stat <file>` | Full timestamps (atime/mtime/ctime) | `stat /usr/bin/ps` |
| `md5sum /usr/bin/*` | Hash system binaries | `md5sum /usr/bin/ss /usr/bin/ps /bin/ls` |
| `rpm -Va` | Verify RPM packages (RHEL) | `rpm -Va 2>/dev/null \| grep -E '^..5'` |
| `debsums -c` | Verify deb packages (Debian) | `debsums -c 2>/dev/null` |
| `mount \| column -t` | Mount points | `mount \| column -t` |
| `df -h` | Disk usage | `df -hT` |

### Compare against known-good binary hashes

```bash
# Debian/Ubuntu: reinstall a package and compare
apt-get install --reinstall -d coreutils   # download only
dpkg-deb -x /var/cache/apt/archives/coreutils*.deb /tmp/good
md5sum /tmp/good/bin/ls /bin/ls
```

---

## Log Analysis

| Command | What it does | Example |
|---|---|---|
| `tail -n 500 /var/log/auth.log` | Recent auth log | `tail -n 500 /var/log/auth.log` |
| `grep 'Failed password' /var/log/auth.log` | Failed SSH logins | `grep 'Failed password' /var/log/auth.log \| wc -l` |
| `grep 'Accepted' /var/log/auth.log` | Successful logins | `grep 'Accepted' /var/log/auth.log \| tail` |
| `grep 'session opened for user root' /var/log/auth.log` | Root logins | `grep 'session opened.*root' /var/log/auth.log` |
| `grep sudo /var/log/auth.log` | sudo usage | `grep -i sudo /var/log/auth.log \| tail` |
| `last -50` | Login history | `last -50` |
| `lastb -50` | Failed login attempts | `lastb -50` |
| `journalctl -b --no-pager` | Current boot logs | `journalctl -b --no-pager \| tail -500` |
| `journalctl -u ssh --since today` | SSH unit logs | `journalctl -u ssh --since today` |
| `ausearch -m all --start today` | auditd events | `ausearch -m all --start today` |
| `aureport --summary` | audit summary | `aureport --summary` |
| `grep POST /var/log/nginx/access.log` | Web POST requests | `grep POST /var/log/nginx/access.log \| tail` |
| `grep -vE 'GET /(css\|js\|img)' access.log` | Non-static requests | `grep -vE 'GET .*\.(css\|js\|png\|jpg)' access.log \| tail` |

### Find logins from unexpected IPs

```bash
# All successful SSH logins with source IP
grep 'Accepted' /var/log/auth.log | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | sort | uniq -c | sort -rn
```

---

## Memory Analysis

> Full memory dumps are large (RAM-sized) and usually out of scope for VPS triage. Process memory maps give most of the value at a fraction of the cost.

| Command | What it does | Example |
|---|---|---|
| `cat /proc/<pid>/maps` | Memory regions of a process | `cat /proc/1234/maps` |
| `cat /proc/<pid>/smaps` | Detailed memory stats | `cat /proc/1234/smaps \| head` |
| `cat /proc/<pid>/status` | Memory + state summary | `cat /proc/1234/status` |
| `cat /proc/meminfo` | System memory info | `cat /proc/meminfo` |
| `free -h` | RAM + swap usage | `free -h` |
| `vmstat 1 5` | Memory/swap activity (5 samples) | `vmstat 1 5` |

### Process memory maps for top CPU processes

```bash
for pid in $(ps -eo pid= --sort=-%cpu | head -10 | tr -d ' '); do
  echo "=== PID $pid ==="
  cat /proc/$pid/maps 2>/dev/null
done
```

### Full memory dump (only if needed, requires LiME/avml)

```bash
# ⚠️ Produces a file the size of RAM. Use only for serious incidents.
# Linux Memory Extractor (avml) — works on modern kernels
avml memory.lime
sha256sum memory.lime   # record hash immediately
```

---

## Persistence Checks

| Command | What it does | Example |
|---|---|---|
| `crontab -l` | Root's crontab | `crontab -l` |
| `cat /etc/crontab` | System crontab | `cat /etc/crontab` |
| `ls -la /etc/cron.d/` | Cron drop-in dir | `ls -la /etc/cron.d/ && cat /etc/cron.d/*` |
| `for u in $(cut -d: -f1 /etc/passwd); do crontab -u $u -l 2>/dev/null; done` | All user crontabs | (see below) |
| `systemctl list-units --type=service --all` | All services | `systemctl list-units --type=service --all` |
| `systemctl list-timers --all` | All timers | `systemctl list-timers --all` |
| `systemctl list-unit-files --state=enabled` | Enabled units | `systemctl list-unit-files --state=enabled` |
| `cat /etc/rc.local` | Legacy startup script | `cat /etc/rc.local 2>/dev/null` |
| `ls -la /etc/init.d/` | SysV init scripts | `ls -la /etc/init.d/` |
| `ls -la /etc/profile.d/` | Profile drop-ins | `ls -la /etc/profile.d/ && cat /etc/profile.d/*.sh` |
| `cat /etc/ld.so.preload` | Library preload (rootkit!) | `cat /etc/ld.so.preload 2>/dev/null` |
| `find / -name authorized_keys` | All SSH key files | `find / -name authorized_keys 2>/dev/null -exec cat {} \;` |
| `cat /root/.bashrc` | Root shell rc | `cat /root/.bashrc` |
| `cat /etc/passwd` | User accounts | `awk -F: '$3==0{print}' /etc/passwd` |
| `cat /etc/shadow` | Password hashes | `cat /etc/shadow` |
| `grep -r NOPASSWD /etc/sudoers /etc/sudoers.d/` | Passwordless sudo | `grep -rn NOPASSWD /etc/sudoers /etc/sudoers.d/ 2>/dev/null` |

### All user crontabs at once

```bash
cut -d: -f1 /etc/passwd | while IFS= read -r u; do
  c=$(crontab -u "$u" -l 2>/dev/null) || continue
  [ -n "$c" ] && echo "=== $u ===" && echo "$c"
done
```

### Suspicious cron/systemd patterns

```bash
# Look for downloaders / reverse shells in cron and systemd units
grep -riE 'wget|curl|nc |ncat|bash -i|/dev/tcp|python -c|perl -e' \
  /etc/cron* /etc/crontab /var/spool/cron /etc/systemd/system 2>/dev/null
```

---

## Evidence Collection

### Order of volatility (RFC 3227)

Collect in this order: **network state → processes → memory maps → temp files → disk (logs, recent files) → remote logs**.

### Using the triage script

```bash
# Full read-only collection (all categories + manifest + archive)
sudo ./scripts/incident_triage.sh collect --output ./triage-out

# Quick 30-second overview
sudo ./scripts/incident_triage.sh quick

# 16 read-only audit checks for incident indicators
sudo ./scripts/incident_triage.sh audit

# Verify and analyze a collected archive (on a separate workstation)
./scripts/incident_triage.sh analyze incident-triage-*.tar.gz

# Generate a summary report
./scripts/incident_triage.sh report incident-triage-*.tar.gz
```

### Manual evidence hashing

```bash
# Hash every file in a collection directory
find ./evidence -type f -exec sha256sum {} \; > hashes.txt

# Verify later
sha256sum -c hashes.txt

# Hash a single artifact and record it
sha256sum suspicious_file > suspicious_file.sha256
```

### Chain of custody essentials

- Record **UTC timestamp** at collection (`date -u +%Y-%m-%dT%H:%M:%SZ`)
- Record **collector identity** (`user@host`)
- Record **SHA-256** of every artifact and the final archive
- Copy archives to **offline trusted storage** — never leave the only copy on the compromised host
- Work on **copies**, never the original
- Log every person who handles the evidence

### Snapshot before acting

```bash
# Most VPS providers: take a snapshot BEFORE containment/eradication
# This is your forensic fallback. A snapshot preserves disk state but
# NOT memory or network state — collect those first with the triage script.
```

---

## Quick Triage One-Liners

```bash
# Who is logged in right now
who; w

# Top 10 CPU hogs
ps aux --sort=-%cpu | head -11

# Listening ports with process
ss -tlnp

# Established outbound (non-local)
ss -tunpa state established | grep -vE '127\.|::1'

# UID 0 accounts (should be only root)
awk -F: '$3==0{print}' /etc/passwd

# Failed SSH attempts (count)
grep -c 'Failed password' /var/log/auth.log 2>/dev/null

# Recent root logins
grep 'session opened.*root' /var/log/auth.log 2>/dev/null | tail

# Files modified in last 24h
find / -xdev -type f -mtime -1 2>/dev/null | head -50

# SUID binaries
find / -xdev -perm -4000 -type f 2>/dev/null

# Rootkit check: ld.so.preload
cat /etc/ld.so.preload 2>/dev/null   # should be empty/absent

# Suspicious cron
grep -riE 'wget|curl|bash -i|/dev/tcp' /etc/cron* /var/spool/cron 2>/dev/null
```

---

## Related

- [Handbook 21 — Incident Response & Forensics](../handbook/21-incident-response-forensics.md): full methodology and NIST lifecycle
- [Handbook 03 — Incident Response](../handbook/03-incident-response.md): first-10-minutes mindset
- [Security Commands Cheatsheet](security-commands.md): general security command reference
- [Security Troubleshooting Tree](security-troubleshooting-tree.md): decision trees including "suspicious activity"
