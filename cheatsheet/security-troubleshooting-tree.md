# VPS Security Troubleshooting Decision Tree

> Flowchart-style quick reference for common VPS security problems. Print on A4, pin to wall. Follow the branches top-down; each `→` is the next diagnostic step.

---

## 1. Can't SSH into server

```
Can't SSH?
├─ Connection refused ────────────── Is sshd running?
│   ├─ Console/VNC access → systemctl status sshd
│   ├─ Start it: systemctl start sshd
│   └─ Not installed? → apt install openssh-server
├─ Connection timeout ────────────── Firewall or network blocking?
│   ├─ Check: ufw status  /  firewall-cmd --list-all
│   ├─ Allow SSH: ufw allow <port>/tcp
│   └─ Cloud provider security group? check console
├─ Auth failed ───────────────────── Key or password issue?
│   ├─ Verbose: ssh -v user@host
│   ├─ Wrong key: ssh -i ~/.ssh/id_ed25519 user@host
│   ├─ Key perms: chmod 600 ~/.ssh/id_ed25519
│   └─ Password reset: console access → passwd <user>
├─ Wrong port ────────────────────── Did you change SSH port?
│   ├─ Try: ssh -p <new_port> user@host
│   └─ Check: grep -i "^Port" /etc/ssh/sshd_config
├─ "Permission denied (publickey)" ─ Password auth disabled?
│   ├─ Console: set PasswordAuthentication yes temporarily
│   └─ Or add pubkey to ~/.ssh/authorized_keys
└─ Server down ───────────────────── No response at all
    ├─ Console/VNC access
    ├─ Check: uptime, dmesg, journalctl -b
    └─ Maybe OOM-killed: dmesg | grep -i oom
```

## 2. Service unreachable from outside

```
Service unreachable?
├─ Is the service running? ───────── ss -tlnp | grep <port>
│   └─ No → systemctl start <svc>
├─ Bound to 0.0.0.0 (not 127.0.0.1)?  ss -tlnp
│   └─ 127.0.0.1 only → edit config, bind 0.0.0.0, restart
├─ Firewall blocking? ────────────── ufw status / firewall-cmd --list-all
│   ├─ ufw allow <port>/tcp
│   └─ Cloud security group too
├─ Docker bypassing UFW? ─────────── iptables -L -n | grep DOCKER
│   ├─ Published port ignores UFW (see docker cheatsheet)
│   └─ Fix: vps_secure.sh  →  d1  →  Docker  →  UFW 接管
├─ DNS resolving? ────────────────── dig <domain> +short
│   ├─ Wrong IP → fix DNS A record
│   └─ No answer → check resolver: dig @1.1.1.1 <domain>
├─ Network route? ────────────────── traceroute <server_ip>
│   └─ Drops before server → upstream/ISP issue
└─ Reverse proxy upstream down? ──── nginx -t; check upstream blocks
```

## 3. Disk full

```
Disk full?
├─ Confirm: df -h
├─ What's using space? ───────────── du -sh /* | sort -rh | head
│   └─ Drill down: du -sh /var/* | sort -rh | head
├─ Common culprits:
│   ├─ /var/log ──── journalctl --vacuum-time=7d
│   │                rm old *.log.*; logrotate -f
│   ├─ /var/lib/docker ── docker system prune -a --volumes
│   ├─ /tmp ─────── rm files older than 7d: find /tmp -mtime +7 -delete
│   ├─ /var/cache/apt ── apt-get clean
│   └─ user uploads ─── archive or move to object storage
├─ Inode exhaustion? ─────────────── df -i
│   └─ Tons of tiny files: find / -xdev -printf '%h\n' | sort | uniq -c | sort -rn | head
├─ Deleted file still held open? ─── lsof +L1
│   └─ Restart the process holding it, or kill <pid>
└─ Still full? ───────────────────── ncdu /  (interactive scan)
```

## 4. High CPU / Memory

```
High CPU/Memory?
├─ Who's hogging? ────────────────── top / htop  (press M to sort mem, P for CPU)
├─ CPU:
│   ├─ Known service ──── check its config (worker count, threads)
│   ├─ Unknown process ── ps aux | grep <name>; lsof -p <pid>
│   └─ Suspect malware ── vps_secure.sh  →  b4  →  Rkhunter
├─ Memory:
│   ├─ OOM killer active? ── dmesg | grep -i oom
│   ├─ Add swap ─────────── vps_secure.sh  →  c2  →  Swap
│   ├─ Check: free -h
│   └─ Cache vs real: free -h (look at "available", not "used")
├─ Load high but CPU idle? ───────── I/O wait
│   ├─ iostat -x 1   (look at %util, await)
│   └─ iotop         (per-process I/O)
└─ Single-core saturation? ───────── uptime shows load vs nproc
    └─ nproc; compare to load average
```

## 5. Docker container won't start

```
Container won't start?
├─ Check logs: docker logs <name>
├─ Common errors:
│   ├─ "bind: address already in use"
│   │   └─ ss -tlnp | grep <port>  → stop the hog, or change port
│   ├─ "permission denied" on volume
│   │   └─ chown -R <uid>:<gid> <host-path>; check image USER
│   ├─ "no such image"
│   │   └─ docker pull <image>
│   ├─ "Cannot connect to the Docker daemon"
│   │   └─ systemctl status docker; systemctl start docker
│   └─ Config/app error
│       └─ read docker logs carefully — usually the real cause
├─ Inspect: docker inspect <name>
│   └─ check State.Error, HostConfig.Binds, NetworkSettings
├─ Exit code: docker inspect -f '{{.State.ExitCode}}' <name>
└─ Recreate: docker rm <name> → docker run ...  (or compose down/up)
```

## 6. Website slow

```
Website slow?
├─ Server-side:
│   ├─ CPU/Memory high? → troubleshooting tree #4
│   ├─ Disk I/O slow? ── iostat -x 1  (high await = slow disk)
│   └─ Bandwidth saturated? ── bench.sh / iftop / nethogs
├─ Network:
│   ├─ High latency? ── ping <server>; mtr <server>
│   ├─ Packet loss? ── mtr --report <server>
│   ├─ BBR enabled? ── vps_secure.sh  →  c2  →  BBR
│   └─ TCP tuning? ── sysctl net.ipv4.tcp_congestion_control
├─ App:
│   ├─ Database slow? ── slow query log; EXPLAIN on suspects
│   ├─ Memory leak? ── monitor RSS over time (pidstat -r 60)
│   └─ Too many connections? ── check max_connections, ulimit -n
└─ CDN / Proxy:
    ├─ TTFB from origin ── curl -w "%{time_starttransfer}\n" -o /dev/null -s <url>
    └─ Upstream response time in nginx access log ($upstream_response_time)
```

## 7. Suspicious activity detected

```
Suspicious activity?
├─ Check logins ──────────────────── vps_secure.sh  →  c1  →  登录轨迹
│   ├─ last            (successful logins)
│   ├─ lastb           (failed logins)
│   └─ /var/log/auth.log  (Debian) / /var/log/secure (RHEL)
├─ Check processes ───────────────── ps aux; top; pstree -p
│   └─ Unknown? → lsof -p <pid>; cat /proc/<pid>/cmdline
├─ Check network ─────────────────── ss -tlnp; ss -tnp
│   └─ Unexpected listener? → who started it? lsof -i :<port>
├─ Check new/modified files ──────── find / -newer /tmp/marker -type f 2>/dev/null
│   └─ Or: find /etc /usr/bin /usr/sbin -mtime -1
├─ Rootkit scan ──────────────────── vps_secure.sh  →  b4  →  Rkhunter
├─ Integrity check ───────────────── vps_secure.sh  →  b4  →  AIDE
├─ If confirmed breach:
│   ├─ Isolate ────── block external access (ufw default deny)
│   ├─ Preserve ───── DON'T reboot (RAM evidence in /proc)
│   ├─ Assess ─────── what was accessed/modified (audit logs, AIDE report)
│   └─ Recover ────── restore from backup (backup-kit); rebuild if unsure
└─ Harden after recovery ─────────── vps-bootstrap, security-audit, rotate all keys
```

---

**Cross-references:** `vps_secure.sh` is the project's hardening script — run it interactively and follow the menu letters (b4, c1, c2, d1). `backup-kit` is the project's backup tooling. See the project handbook for full context.
