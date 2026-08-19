# VPS Security Enhancement Scripts — Harden Your VPS from First Login to Incident Response

A security-first interactive bash script for VPS hardening, with a scenario-driven handbook and cheatsheets included. One script, zero dependencies, one command to start — plus a real handbook that tells you *why*, not just *how*.

> This is a **living repo**: the script and handbook expand by security direction over time. The current release ships a 2650-line interactive script + 8-chapter handbook + 4 cheatsheets as the starting point. Future iterations add CIS/STIG audit, container/K8s security, cloud CIS baselines, database hardening, big-data SSL, zero-trust, WAF, TLS lifecycle, secret scanning, and CrowdSec-based incident response.

## Quick Start

```bash
wget -O vps_security_enhance.sh https://raw.githubusercontent.com/0x10debug/vps-security-enhancement-scripts/main/vps_security_enhance.sh && chmod +x vps_security_enhance.sh && ./vps_security_enhance.sh
```

On a fresh server, select **`a1` Full Security Init** — completes in ~10 minutes: system update → firewall → BBR → swap → Fail2Ban → kernel hardening.

After installing the global command, type `secure-vps` from anywhere to launch.

## What It Does

The script (`vps_security_enhance.sh`) is organized by **security layers**, not by ops workflow:

| Zone | Layer | Features |
|---|---|---|
| **A · Quick** | — | Full security init (update + firewall + BBR + swap + Fail2Ban + kernel) |
| **B · Access Security** | L4 Network | SSH hardening, firewall (UFW/Firewalld), intrusion ban (Fail2Ban + CrowdSec) |
| **C · Defense in Depth** | L0-L3 | Baseline scan, kernel hardening, audit & integrity (auditd/AIDE/Rkhunter/Lynis), password & access control |
| **D · Secure Ops** | — | Container security (Docker/Portainer/Watchtower/1Panel), security monitoring (Uptime Kuma), network diagnostics, system tools |
| **E · Incident & Recovery** | L6 Detection | Emergency triage (compromise check, login history, suspicious cron), performance & resource (BBR/swap/bench) |
| **Z · Maintenance** | — | Global command, self-update |

### Security Layer Roadmap

The 7-layer architecture (L0 → L6) guides the iteration plan. Each layer maps to dedicated scripts and handbook chapters added over the 9-day iteration cycle:

| Layer | Scope | Status |
|---|---|---|
| L0 | Compliance audit (CIS Benchmark, STIG) | CIS audit script added (Phase 2); STIG planned |
| L1 | Container & Kubernetes security | Planned (Phase 3) |
| L2 | Cloud platform CIS baselines (AWS/GCP/Azure) | Planned (Phase 4) |
| L3 | Data security (database hardening, big-data SSL/audit) | Planned (Phase 5) |
| L4 | Network & perimeter (zero-trust, WAF) | Planned (Phase 6) |
| L5 | Key & certificate security (TLS lifecycle, secret scanning) | Planned (Phase 7) |
| L6 | Detection & response (CrowdSec, incident triage) | CrowdSec integrated in B3; full deployment planned (Phase 8) |

See [`dev-docs/0015`](https://github.com/0x10debug/vps-security-enhancement-scripts/blob/main/dev-docs/0015-vps-security-enhancement-scripts-branch-strategy.md) for the full branch strategy.

## Security Design

### Three Iron Rules (built into the script)

1. **Snapshot → Validate → Rollback**: Before modifying `sshd_config` / `daemon.json` / `sudoers`, a timestamped snapshot is saved. Before restarting services, `sshd -t` / `visudo -cf` validation runs. If validation fails, automatic rollback — **never locks you out**.
2. **Linkage Consistency**: When changing SSH port, Fail2Ban ban port is automatically synced. Rollback is also linked.
3. **Read-Only First**: Scans and audits never modify the system. All destructive operations require confirmation.

### Supply Chain Audit

| Risk Area | Status | Notes |
|---|---|---|
| Hardcoded secrets | ✅ Clean | No passwords, keys, or IPs hardcoded |
| External script execution | ⚠️ Documented | Docker install (`get.docker.com`), CrowdSec install, YABS, bench.sh, NextTrace, IPQuality, 融合怪 — all from official sources, all require user confirmation |
| `eval` usage | ✅ Safe | Only used for package manager commands (`eval "$PKG_INSTALL foo"`) — no user input reaches eval |
| `rm -rf` usage | ✅ Guarded | Only in Docker uninstall, requires double confirmation |
| Self-update mechanism | ✅ HTTPS | Downloads from GitHub raw over HTTPS |
| Input validation | ✅ Present | All interactive inputs validated before use |
| shellcheck | ✅ Clean | Zero warnings at `-S warning` level |

## Handbook (Included)

9 scenario-driven chapters organized by security layer. Each follows "Problem → Investigate → Fix → Verify":

| Chapter | Topic | Security Angle |
|---|---|---|
| [01](handbook/01-first-login-security.md) | First Login Security | First 30 minutes: assessment & hardening |
| [02](handbook/02-security-baseline.md) | Security Baseline | SSH, firewall, Fail2Ban/CrowdSec, kernel, Docker UFW bypass, password policy |
| [03](handbook/03-incident-response.md) | Incident Response | "I've been hacked" first 10 minutes, compromise detection, recovery |
| [04](handbook/04-security-monitoring.md) | Security Monitoring | TLS expiry, SSH unreachable, intrusion detection, log management |
| [05](handbook/05-backup-security.md) | Backup Security | Backup as a safety net: credential protection, recovery drills |
| [06](handbook/06-container-security.md) | Container Security | Docker UFW bypass, isolation, resource limits |
| [07](handbook/07-network-security-diagnostics.md) | Network Security Diagnostics | Firewall, TLS, IP quality troubleshooting |
| [08](handbook/08-resource-security.md) | Resource Security | Resource exhaustion defense, crypto performance |
| [09](handbook/09-cis-stig-compliance.md) | CIS & STIG Compliance | Automated compliance audit against CIS Benchmarks |

## Cheatsheets

4 one-page printable reference cards:

| Cheatsheet | Content |
|---|---|
| [security-commands.md](cheatsheet/security-commands.md) | Security-related command quick reference |
| [container-security-commands.md](cheatsheet/container-security-commands.md) | Container security commands |
| [systemd-commands.md](cheatsheet/systemd-commands.md) | Service management, journalctl, targets, timers |
| [security-troubleshooting-tree.md](cheatsheet/security-troubleshooting-tree.md) | 7 decision trees: SSH fail, service unreachable, disk full, high CPU, container fail, slow website, suspicious activity |

## Script vs Modular: Which to Use?

| Need | Use |
|---|---|
| Quick start, one command, menu-driven | **vps_security_enhance.sh** (this repo) |
| Modular, CLI-driven, per-module control | [vps-bootstrap](https://github.com/0x10debug/vps-bootstrap) |
| CIS benchmark audit, drift detection | [security-audit](https://github.com/0x10debug/security-audit) |

Both `vps_security_enhance.sh` and `vps-bootstrap` cover SSH/firewall/Fail2Ban/kernel hardening — they're two entry points to the same capability. The script is for "I just want it done", the modular tools are for "I want to control each step and integrate with other tools".

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

Benchmark and detection capabilities use: [YABS](https://github.com/masonr/yabs) · [bench.sh](https://bench.sh) · [NextTrace](https://github.com/nxtrace/NTrace-core) · [融合怪](https://github.com/spiritLHLS/ecs) · [IPQuality](https://github.com/xykt/IPQuality) · [Lynis](https://cisofy.com/lynis/) · [Endlessh](https://github.com/skeeto/endlessh). Intrusion detection integrates [CrowdSec](https://github.com/crowdsecurity/crowdsec). App deployment uses [Docker](https://docker.com) and [1Panel](https://1panel.cn) official scripts.

## License

[MIT](LICENSE) © 2026 0x10debug
