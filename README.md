# VPS Handbook — The Bedside Book for VPS & Cloud Ops

A complete VPS operations toolkit: an interactive bash script for server hardening, diagnostics, and benchmarking, plus an 8-chapter scenario-driven handbook and 4 printable cheatsheets. Everything an ops engineer needs, in one repo.

> Single file. Zero dependencies. One command to start. Plus a real handbook that tells you *why*, not just *how*.

## Quick Start

```bash
wget -O vps_secure.sh https://raw.githubusercontent.com/0x10debug/vps-handbook/main/vps_secure.sh && chmod +x vps_secure.sh && ./vps_secure.sh
```

On a fresh server, select **`a1` Full Initialization** — completes in ~10 minutes: system update → firewall → BBR → swap → Fail2Ban → kernel hardening.

After installing the global command, type `secure-vps` from anywhere to launch.

## What's Inside

### The Script (`vps_secure.sh`)

A 2370-line interactive bash tool covering:

| Zone | Features |
|---|---|
| **A · Quick** | Full initialization, system update, toolbox, performance tuning, user management |
| **B · Security** | SSH hardening, firewall (UFW/Firewalld), Fail2Ban, defense in depth (kernel, password policy, sudo audit, auto updates, Rkhunter, AIDE, auditd, Lynis) |
| **C · Docker & Apps** | Docker engine, mirror acceleration, UFW bypass fix, Portainer, Watchtower, Uptime Kuma, 1Panel |
| **D · Diagnostics** | Real-time dashboard, YABS benchmark, bandwidth test, streaming unlock, route trace, IP quality score |
| **Z · Maintenance** | Global command, self-update |

### The Handbook (`handbook/`)

8 scenario-driven chapters, each following "Problem → Investigate → Fix → Verify":

| Chapter | Topic | Key Scenarios |
|---|---|---|
| [01](handbook/01-new-server-setup.md) | New Server Setup | First login, initial assessment, quick init, post-setup verification |
| [02](handbook/02-security-baseline.md) | Security Baseline | SSH, firewall, Fail2Ban, kernel hardening, Docker UFW bypass, password policy |
| [03](handbook/03-docker-ops.md) | Docker Operations | Installation, mirror acceleration, UFW fix, container management, cleanup |
| [04](handbook/04-network-troubleshoot.md) | Network Troubleshooting | "Service unreachable" decision tree, DNS, routing, bandwidth, BBR |
| [05](handbook/05-performance-tuning.md) | Performance Tuning | BBR, swap, disk I/O, memory, CPU, Docker resource limits |
| [06](handbook/06-backup-migration.md) | Backup & Migration | Strategy selection, Docker volume backup, server migration, recovery drills |
| [07](handbook/07-monitoring-alerts.md) | Monitoring & Alerts | Uptime Kuma, full monitoring stack, alert channels, log management |
| [08](handbook/08-incident-response.md) | Incident Response | "I've been hacked" first 10 minutes, compromise detection, recovery |

### The Cheatsheets (`cheatsheet/`)

4 one-page printable reference cards:

| Cheatsheet | Content |
|---|---|
| [essential-commands.md](cheatsheet/essential-commands.md) | System, process, network, file, text, user, cron, disk, package commands |
| [docker-commands.md](cheatsheet/docker-commands.md) | Docker & Docker Compose commands, one-liners, debugging |
| [systemd-commands.md](cheatsheet/systemd-commands.md) | Service management, journalctl, targets, timers, troubleshooting |
| [troubleshooting-tree.md](cheatsheet/troubleshooting-tree.md) | 7 decision trees: SSH fail, service unreachable, disk full, high CPU, container fail, slow website, suspicious activity |

## Security Design

### Three Iron Rules (built into the script)

1. **Snapshot → Validate → Rollback**: Before modifying `sshd_config` / `daemon.json` / `sudoers`, a timestamped snapshot is saved. Before restarting services, `sshd -t` / `visudo -cf` validation runs. If validation fails, automatic rollback — **never locks you out**.
2. **Linkage Consistency**: When changing SSH port, Fail2Ban ban port is automatically synced. Rollback is also linked.
3. **Read-Only First**: Scans and audits never modify the system. All destructive operations require confirmation.

### Security Audit Notes

The script was audited for supply chain security:

| Risk Area | Status | Notes |
|---|---|---|
| Hardcoded secrets | ✅ Clean | No passwords, keys, or IPs hardcoded |
| External script execution | ⚠️ Documented | Docker install (`get.docker.com`), YABS (`yabs.sh`), bench.sh, NextTrace, IPQuality, 融合怪 — all from official sources, all require user confirmation |
| `eval` usage | ✅ Safe | Only used for package manager commands (`eval "$PKG_INSTALL foo"`) — no user input reaches eval |
| `rm -rf` usage | ✅ Guarded | Only in Docker uninstall, requires double confirmation |
| Self-update mechanism | ✅ HTTPS | Downloads from GitHub raw over HTTPS |
| Input validation | ✅ Present | All interactive inputs validated before use |

## Script vs Modular: Which to Use?

| Need | Use |
|---|---|
| Quick start, one command, menu-driven | **vps_secure.sh** (this repo) |
| Modular, CLI-driven, per-module control | [vps-bootstrap](https://github.com/0x10debug/vps-bootstrap) |
| CIS benchmark audit, drift detection | [security-audit](https://github.com/0x10debug/security-audit) |

Both vps_secure.sh and vps-bootstrap cover SSH/firewall/Fail2Ban/kernel hardening — they're two entry points to the same capability. The script is for "I just want it done", the modular tools are for "I want to control each step and integrate with other tools".

## Full 0x10debug VPS Tool Suite

- [awesome-vps](https://github.com/0x10debug/awesome-vps) — Curated VPS tools list
- [vps-bootstrap](https://github.com/0x10debug/vps-bootstrap) — Modular VPS hardening CLI
- [compose-recipes](https://github.com/0x10debug/compose-recipes) — Self-hosted app suites
- [network-toolkit](https://github.com/0x10debug/network-toolkit) — Reverse proxy, SSL, tunnel
- [monitor-stack](https://github.com/0x10debug/monitor-stack) — Uptime, metrics, alerts
- [backup-kit](https://github.com/0x10debug/backup-kit) — Encrypted backup with recovery drills
- [security-audit](https://github.com/0x10debug/security-audit) — CIS Benchmark audit and drift detection
- [ai-workstation](https://github.com/0x10debug/ai-workstation) — Self-hosted AI with Ollama

## System Requirements

- Ubuntu 20.04+ / Debian 10+ / CentOS 7/8 / AlmaLinux / Rocky Linux
- Root access, recommended on a clean system image
- Benchmark and speed tests generate significant network traffic

## Credits

Benchmark and detection capabilities use: [YABS](https://github.com/masonr/yabs) · [bench.sh](https://bench.sh) · [NextTrace](https://github.com/nxtrace/NTrace-core) · [融合怪](https://github.com/spiritLHLS/ecs) · [IPQuality](https://github.com/xykt/IPQuality) · [Lynis](https://cisofy.com/lynis/) · [Endlessh](https://github.com/skeeto/endlessh). App deployment uses [Docker](https://docker.com) and [1Panel](https://1panel.cn) official scripts.

## License

[MIT](LICENSE) © 2026 0x10debug
