# Container Security Audit (CIS Docker Benchmark)

> Automated compliance checking against the CIS Docker Benchmark — secure your container runtime without spending hours with the 300-page benchmark document.

## Overview

Docker containers are ubiquitous in modern VPS deployments, but the default configuration prioritizes convenience over security. The **CIS Docker Benchmark** provides vetted, consensus-based configuration guidelines for securing Docker daemon, images, container runtime, and network.

This chapter covers the automated Docker security audit tool shipped with this repo:

- **`scripts/docker_security_audit.sh`** — CIS Docker Benchmark audit (40+ checks)

The tool is **read-only**: it checks your Docker configuration and running containers, but never modifies anything.

## What It Checks

The Docker security audit covers 7 major sections:

| Section | Scope | Key Checks |
|---|---|---|
| 1.x Daemon Config | Daemon running, systemd managed, auditd rules, daemon.json | userns-remap, live restore, content trust, containerd runtime |
| 2.x Daemon Files | File permissions on Docker config and runtime files | daemon.json, /etc/docker/, docker.socket, docker.service, /var/lib/docker/, docker.sock |
| 3.x Container Images | Image tag hygiene, vulnerability scanning, rootless mode | no :latest tags, specific tags, image scanner, trusted base images |
| 4.x Container Runtime | Container isolation and resource limits | no privileged, no dangerous caps, no host PID/IPC/UTS/net/userns, non-root user, no docker.sock mount, no sensitive mounts, memory/CPU limits, read-only rootfs, healthcheck |
| 5.x Security Operations | MAC, seccomp, cgroups, secrets, network exposure | AppArmor/SELinux profiles, seccomp not unconfined, PID limits, Docker secrets, API TLS |
| 6.x Network | Bridge network, firewall integration, daemon port | no default bridge, DOCKER-USER chain, no exposed daemon port |
| 7.x Logging | Log rotation, central logging | log max-size configured, forwarding to syslog/fluentd/gelf |

## Usage

```bash
# Full audit (all running containers)
sudo ./scripts/docker_security_audit.sh

# Audit specific container only
sudo ./scripts/docker_security_audit.sh --container my-app

# Quiet mode (summary only)
sudo ./scripts/docker_security_audit.sh --quiet

# JSON only (for CI/CD integration — prints JSON report path)
sudo ./scripts/docker_security_audit.sh --json
```

### Output

Each run produces two reports in `/var/log/docker-audit/`:

| Report | Format | Use Case |
|---|---|---|
| `docker-audit-<timestamp>.txt` | Human-readable | Manual review, evidence for audits |
| `docker-audit-<timestamp>.json` | Machine-readable | CI/CD integration, trend tracking |

### Integration with the Main Script

From `secure-vps`, the Docker audit is accessible via:

```
D · 安全运维 → d1 容器安全 → Docker 合规审计
```

This calls `scripts/docker_security_audit.sh` and displays the summary.

## Common Findings and Fixes

### FAIL: Containers running as root

**Fix**: Add `USER <non-root-user>` to your Dockerfile, or specify `--user` in docker run/compose.

### FAIL: No memory/CPU limits

**Fix**: In docker-compose.yml:
```yaml
services:
  app:
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '1.0'
```

### FAIL: No healthcheck

**Fix**: Add healthcheck to compose:
```yaml
services:
  app:
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 5s
      retries: 3
```

### FAIL: docker.sock mounted in container

**Risk**: Container can control the Docker daemon (equivalent to root access).
**Fix**: Use [docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy) to expose only needed API endpoints.

### FAIL: No log rotation

**Fix**: In `/etc/docker/daemon.json`:
```json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
```

## Related Tools in the 0x10debug Suite

| Tool | Repo | Focus |
|---|---|---|
| Docker audit (this script) | vps-security-enhancement-scripts | Quick check, single-host |
| Docker + K8s audit platform | [security-audit](https://github.com/0x10debug/security-audit) | Modular, CI/CD, multi-host |
| Docker compose hardening | [compose-recipes](https://github.com/0x10debug/compose-recipes) | Pinned tags, healthchecks, socket-proxy |

## References

- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker) — Official benchmark (free download)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/) — Docker official docs
- [CIS Docker Benchmark v1.6.0](https://www.cisecurity.org/benchmark/docker) — Reference version for this audit
