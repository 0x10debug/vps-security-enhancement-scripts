# systemd Cheatsheet

> One-page quick reference for service management on systemd VPS. Print on A4.

---

## Service Management

| Command | What it does | Example |
|---|---|---|
| `systemctl start <svc>` | Start service | `systemctl start nginx` |
| `systemctl stop <svc>` | Stop service | `systemctl stop nginx` |
| `systemctl restart <svc>` | Restart | `systemctl restart sshd` |
| `systemctl reload <svc>` | Reload config (no downtime) | `systemctl reload nginx` |
| `systemctl enable <svc>` | Start on boot | `systemctl enable ufw` |
| `systemctl disable <svc>` | Don't start on boot | `systemctl disable apache2` |
| `systemctl enable --now <svc>` | Enable + start in one shot | `systemctl enable --now fail2ban` |
| `systemctl status <svc>` | Full status | `systemctl status sshd` |
| `systemctl is-active <svc>` | `active` / `inactive` | `systemctl is-active nginx` |
| `systemctl is-enabled <svc>` | `enabled` / `disabled` | `systemctl is-enabled ufw` |
| `systemctl is-failed <svc>` | `failed` / `clean` | `systemctl is-failed nginx` |
| `systemctl list-units` | Loaded units | `systemctl list-units --type=service` |
| `systemctl list-unit-files` | All unit files | `systemctl list-unit-files --state=enabled` |
| `systemctl list-units --failed` | Failed units | `systemctl list-units --failed` |
| `systemctl daemon-reload` | Reload after unit file edit | **always run after editing a unit file** |
| `systemctl reset-failed` | Clear failed state | `systemctl reset-failed nginx` |

## Logging (journalctl)

| Command | What it does | Example |
|---|---|---|
| `journalctl -u <svc>` | Logs for one service | `journalctl -u nginx` |
| `journalctl -u <svc> -f` | Follow (live) | `journalctl -u sshd -f` |
| `journalctl --since "1 hour ago"` | Time window | `journalctl --since today --until "1 hour ago"` |
| `journalctl --since "2024-01-01" --until "2024-01-02"` | Date range | |
| `journalctl -p err` | Errors only | `journalctl -p err -b` (since boot) |
| `journalctl -p warning` | Warnings+ | `journalctl -p warning -u docker` |
| `journalctl -b` | Current boot | `journalctl -b -p err` |
| `journalctl -b -1` | Previous boot | `journalctl -b -1 -p err` |
| `journalctl -k` | Kernel ring only | `journalctl -k -b` |
| `journalctl --vacuum-time=7d` | Drop logs older than 7d | frees `/var/log/journal` |
| `journalctl --vacuum-size=500M` | Cap journal size | |
| `journalctl --disk-usage` | Show journal size | |
| `journalctl --no-pager -n 200 <svc>` | No pager, last 200 | pipe to grep |

## Targets (runlevels)

| Command | What it does | Example |
|---|---|---|
| `systemctl get-default` | Show default target | usually `multi-user.target` |
| `systemctl set-default multi-user.target` | Boot to CLI (runlevel 3) | |
| `systemctl set-default graphical.target` | Boot to GUI (runlevel 5) | |
| `systemctl isolate <target>` | Switch now | `systemctl isolate rescue.target` |
| `systemctl list-units --type=target` | All active targets | |

Common targets: `multi-user.target` (CLI), `graphical.target` (GUI), `rescue.target` (single-user root), `emergency.target` (minimal root).

## Timers (cron alternative)

| Command | What it does | Example |
|---|---|---|
| `systemctl list-timers` | All timers + next run | `systemctl list-timers --all` |
| `systemctl enable --now <timer>` | Enable + start timer | `systemctl enable --now fstrim.timer` |
| `systemctl status <timer>` | Timer status | `systemctl status logrotate.timer` |
| `systemctl list-timers --failed` | Broken timers | |

## Unit Files

**Locations:**
- `/etc/systemd/system/` — custom / overrides (highest priority)
- `/run/systemd/system/` — runtime-generated
- `/lib/systemd/system/` or `/usr/lib/systemd/system/` — package-installed (don't edit)

| Command | What it does | Example |
|---|---|---|
| `systemctl cat <svc>` | Show merged unit file | `systemctl cat nginx` |
| `systemctl edit <svc>` | Create override drop-in | `systemctl edit nginx` → writes `/etc/systemd/system/nginx.service.d/override.conf` |
| `systemctl edit --full <svc>` | Edit full unit file | `systemctl edit --full myapp` |
| `systemctl show <svc>` | All properties (machine-readable) | `systemctl show nginx -p ExecStart` |
| `systemctl list-dependencies <svc>` | Dependency tree | `systemctl list-dependencies nginx` |

**After editing any unit file → `systemctl daemon-reload` then `systemctl restart <svc>`.**

## Troubleshooting

| Symptom | Fix |
|---|---|
| Service won't start | `systemctl status <svc>` → read the "Main PID" + error line; `journalctl -u <svc> -b -p err` |
| Edited unit file, no effect | `systemctl daemon-reload` then `restart` |
| Stuck in `failed` state | `systemctl reset-failed <svc>` |
| Don't know why it started | `systemctl list-dependencies <svc>`; check `.wants` dirs |
| Unit file not found | Check path: `systemctl cat <svc>`; verify filename = `<name>.service` |
| Override not applied | `systemctl cat <svc>` to confirm merge; `daemon-reload` |
| Service runs but port dead | `ss -tlnp \| grep <port>`; check `ExecStart` binds to `0.0.0.0` not `127.0.0.1` |
| Logs rotated away | `journalctl --vacuum-*` only trims; for retention edit `/etc/systemd/journald.conf` `SystemMaxUse=` |

## Common Services to Know

| Service | Role |
|---|---|
| `sshd` / `ssh` | SSH daemon — never disable on remote VPS |
| `fail2ban` | Brute-force protection |
| `ufw` / `firewalld` | Firewall frontends (pick one, not both) |
| `docker` | Docker daemon |
| `nginx` / `caddy` | Web server / reverse proxy |
| `chronyd` / `systemd-timesyncd` | NTP time sync (pick one) |
| `auditd` | Security auditing |
| `rsyslog` / `systemd-journald` | Logging |
| `cron` / `crond` | Cron jobs |
| `NetworkManager` / `systemd-networkd` | Networking |
