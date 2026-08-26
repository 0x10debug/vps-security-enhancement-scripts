# Runtime Security (Falco + Tetragon)

> Detect and block malicious behavior in real time — from shell escapes to crypto miners to reverse shells — using eBPF-based runtime security tools.

## Overview

Static security (CIS benchmarks, Dockerfile hardening, image scanning) secures the **configuration**. But what happens when an attacker bypasses configuration and starts executing inside your containers? Runtime security is the last line of defense: it watches what processes actually **do** and alerts on (or blocks) suspicious behavior.

This chapter covers the runtime security deployment tool shipped with this repo:

- **`scripts/runtime_security_setup.sh`** — Falco + Tetragon deployment configuration generator

The tool generates **deployment templates** (docker-compose, configuration, rules) rather than installing directly, giving you full control over what gets deployed.

## Falco vs Tetragon

| Dimension | Falco | Tetragon |
|---|---|---|
| Type | Detection (alerting) | Detection + Enforcement |
| Actions | Alert only | Sigkill, Kill, Post, Override |
| Rules format | YAML rules | Kubernetes TracingPolicy YAML |
| Community | CNCF graduated | Cilium project |
| Best for | Audit logging, alerting pipeline | Real-time enforcement, blocking |
| Driver | eBPF (modern) or kernel module (legacy) | eBPF only (requires BTF) |

**Recommended**: Deploy both — Falco for alerting (rich rules, JSON output, integrations) + Tetragon for enforcement (immediate threat neutralization). Defense in depth.

## Prerequisites

- **Linux kernel >= 5.4** (for eBPF)
- **BTF support**: `/sys/kernel/btf/vmlinux` must exist
- **Docker** (for container deployment)
- **Root access** (eBPF requires CAP_BPF, CAP_PERFMON, CAP_SYS_ADMIN)

Check your system:
```bash
uname -r                           # kernel version
ls -la /sys/kernel/btf/vmlinux      # BTF support
```

## Usage

```bash
# Interactive wizard (recommended for first-time users)
sudo ./scripts/runtime_security_setup.sh

# Generate Falco deployment configuration
sudo ./scripts/runtime_security_setup.sh --falco

# Generate Tetragon deployment configuration
sudo ./scripts/runtime_security_setup.sh --tetragon

# Generate both (defense in depth)
sudo ./scripts/runtime_security_setup.sh --falco
sudo ./scripts/runtime_security_setup.sh --tetragon

# Audit current runtime security status (read-only)
sudo ./scripts/runtime_security_setup.sh --audit

# List available detection rules
sudo ./scripts/runtime_security_setup.sh --rules

# Specify output directory
sudo ./scripts/runtime_security_setup.sh --falco --output ./my-configs
```

### Output

The tool generates deployment-ready configuration in the specified output directory:

```
runtime-security-configs/
├── falco/
│   ├── compose.yml              # docker-compose template
│   ├── falco.yaml               # Falco main configuration
│   ├── rules/
│   │   └── vps-custom-rules.yaml  # 5 custom VPS security rules
│   └── README.md                # Deployment instructions
└── tetragon/
    ├── compose.yml              # docker-compose template
    ├── policies/
    │   ├── block-shell-in-container.yaml  # Enforcement: kill shell in container
    │   ├── protect-etc.yaml     # Monitoring: /etc write attempts
    │   └── monitor-network.yaml # Monitoring: container outbound connections
    └── README.md                # Deployment instructions
```

### Integration with the Main Script

From `secure-vps`, the runtime security setup is accessible via:

```
D · 安全运维 → d1 容器安全 → 运行时安全部署
```

## Custom Falco Rules

The tool generates 5 custom rules tailored for VPS security:

| Rule | Priority | What it detects |
|---|---|---|
| Shell Spawned in Container | WARNING | bash/sh/zsh spawned inside a container (potential escape) |
| Read SSH Secret File | WARNING | SSH private key read by non-ssh process |
| Write below /etc | ERROR | Unauthorized writes to /etc/ (config tampering) |
| Crypto Miner Process | CRITICAL | xmrig/stratum/minerd or stratum+tcp in cmdline |
| Reverse Shell Connection | CRITICAL | Shell process connecting to non-localhost IP |

Plus 100+ built-in Falco rules covering:
- Terminal shell in container
- Contact cloud metadata service from container
- Container drift (new executable created)
- Privileged container started
- User management binaries in container
- Suspicious network tools (nmap, nc, socat)
- Unauthorized outbound traffic

## Tetragon Enforcement Policies

| Policy | Action | What it does |
|---|---|---|
| block-shell-in-container | Sigkill | Immediately kills any shell spawned in a container |
| protect-etc | Post (log) | Logs all write attempts to /etc/ |
| monitor-network | Post (log) | Logs container outbound connections (rate-limited 5s) |

Tetragon can **block** events in real time (Sigkill), unlike Falco which only alerts. This makes Tetragon suitable for zero-trust enforcement where suspicious behavior should be stopped immediately.

## Integration with Other Tools

### With Loki/Promtail (log aggregation from monitor-stack)
Falco JSON output → file → Promtail → Loki → Grafana dashboards.

### With Alertmanager (alerting from monitor-stack)
Enable `http_output` in falco.yaml to send events to a webhook → Alertmanager → Slack/Telegram.

### With CrowdSec (from vps-bootstrap)
Falco CRITICAL alerts → webhook → CrowdSec bouncer → IP ban. CrowdSec handles network-level threats; Falco handles runtime-level threats.

### With auditd (from vps-bootstrap)
auditd provides file integrity + privileged command audit at the **host** level. Falco/Tetragon provide runtime security at the **container** level. Together they cover both host and container runtime threats.

## Common Scenarios

### Scenario: Detecting a Crypto Miner

A compromised container starts mining cryptocurrency:

1. **Falco detects**: `Crypto Miner Process` rule triggers (CRITICAL)
2. **Tetragon blocks**: (if deployed) `block-shell-in-container` policy kills the miner process
3. **Alert sent**: Falco JSON event → Loki → Grafana dashboard shows CRITICAL alert
4. **Response**: CrowdSec bans the source IP if attack came from network

### Scenario: Container Shell Escape

An attacker exploits a vulnerability and spawns a shell inside a container:

1. **Tetragon blocks**: `block-shell-in-container` policy Sigkills the shell immediately
2. **Falco alerts**: `Shell Spawned in Container` rule triggers (WARNING)
3. **Investigation**: Falco event shows container name, image, parent process, cmdline
4. **Response**: Stop the compromised container, investigate the vulnerability

### Scenario: Reverse Shell

An attacker establishes a reverse shell from a container:

1. **Falco detects**: `Reverse Shell Connection` rule triggers (CRITICAL)
2. **Alert sent**: Event includes destination IP and port
3. **Response**: CrowdSec bans the destination IP, block at firewall

## Tuning

### Reducing Alert Noise
- Set `priority: warning` in falco.yaml (production) instead of `debug` (troubleshooting)
- Add exceptions to built-in rules in `falco_rules.local.yaml`
- Use `outputs.rate` and `outputs.max_burst` for rate limiting

### Adding Custom Rules
Add YAML files to `rules/` directory — Falco auto-reloads on file change:
```yaml
- rule: My Custom Rule
  desc: Detect something specific
  condition: >
    evt.type = execve and proc.name = suspicious_binary
  output: "Suspicious process: %proc.name %proc.cmdline"
  priority: WARNING
  tags: [custom, mitre_execution]
```

### Tetragon Policy Actions
- `Sigkill` — immediate termination (most aggressive)
- `Kill` — terminate with SIGTERM
- `Post` — log after event (no blocking, for monitoring)
- `Override` — modify event arguments (advanced)

## Related Tools in the 0x10debug Suite

| Tool | Repo | Focus |
|---|---|---|
| Runtime security (this script) | vps-security-enhancement-scripts | Falco + Tetragon deployment |
| Docker audit | vps-security-enhancement-scripts | CIS Docker Benchmark |
| Dockerfile hardener | vps-security-enhancement-scripts | Build-time Dockerfile analysis |
| K8s audit | vps-security-enhancement-scripts | CIS Kubernetes Benchmark |
| CrowdSec | vps-bootstrap | Network-level intrusion prevention |
| auditd | vps-bootstrap | Host-level file integrity + privileged command audit |
| Loki + Promtail | monitor-stack | Log aggregation for Falco events |
| Blackbox Exporter | monitor-stack | Service availability monitoring |

## References

- [Falco](https://falco.org/) — CNCF graduated runtime security project
- [Falco documentation](https://falco.org/docs/) — Official docs
- [Falco rules](https://falco.org/docs/rules/) — Rule language reference
- [Tetragon](https://tetragon.cilium.io/) — Cilium eBPF-based security observability and enforcement
- [Tetragon TracingPolicy](https://tetragon.cilium.io/docs/concepts/tracingpolicies/) — Policy spec
- [eBPF](https://ebpf.io/) — eBPF foundation
- [MITRE ATT&CK](https://attack.mitre.org/) — Attack techniques (referenced in rule tags)
