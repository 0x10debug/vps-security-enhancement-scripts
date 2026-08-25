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

---

# Dockerfile Hardening

> Catch insecure patterns in your Dockerfiles before they ship — from `:latest` tags to hardcoded secrets to missing healthchecks.

## Overview

While the Docker security audit (above) checks the **runtime** environment, the Dockerfile hardener checks the **build-time** definition. Insecure Dockerfiles lead to bloated, vulnerable images that no amount of runtime hardening can fully fix.

This section covers:

- **`scripts/dockerfile_hardener.sh`** — Dockerfile security analysis + automatic fix mode (18 rules)

The tool supports **read-only analysis** (default) and **auto-fix mode** (`--fix`).

## What It Checks

18 rules across 6 categories:

| Rule | Severity | Category | What it detects |
|---|---|---|---|
| DF-001 | error | Base image | `FROM :latest` or missing version tag |
| DF-002 | warning | User | Missing `USER` directive (runs as root) |
| DF-003 | error | User | `USER root` explicitly declared |
| DF-004 | error | Secrets | Hardcoded secrets in `ENV` (PASSWORD/KEY/TOKEN) |
| DF-005 | error | Secrets | Secrets in `ARG` (persists in image history) |
| DF-006 | warning | Health | Missing `HEALTHCHECK` directive |
| DF-007 | warning | Instructions | `ADD` used instead of `COPY` (non-URL/tar) |
| DF-008 | warning | Hygiene | `apt-get install` without cache cleanup |
| DF-009 | info | Hygiene | `apt-get install` without `--no-install-recommends` |
| DF-010 | error | Permissions | `chmod 777` (world-writable) |
| DF-011 | warning | Instructions | `sudo` used in `RUN` (unnecessary in containers) |
| DF-012 | error | Supply chain | `curl ... \| bash` (blind remote execution) |
| DF-013 | warning | Copy | `COPY . .` (may copy sensitive files) |
| DF-014 | warning | Hygiene | Missing `.dockerignore` |
| DF-015 | warning | Process | Shell-form `ENTRYPOINT`/`CMD` (signal handling) |
| DF-016 | info | Layers | Too many `RUN` instructions (>10) |
| DF-017 | info | Network | Too many `EXPOSE` ports (>5) |
| DF-018 | info | Build | No multi-stage build |

## Usage

```bash
# Analyze a single Dockerfile
./scripts/dockerfile_hardener.sh Dockerfile

# Analyze + auto-fix (creates Dockerfile.hardened.<timestamp>)
./scripts/dockerfile_hardener.sh --fix Dockerfile

# SARIF v2.1.0 output (for GitHub Code Scanning / CI integration)
./scripts/dockerfile_hardener.sh --sarif Dockerfile

# Recursive scan of a directory
./scripts/dockerfile_hardener.sh -r ./my-project/

# Quiet mode (summary only)
./scripts/dockerfile_hardener.sh --quiet Dockerfile
```

### Auto-Fix Mode

`--fix` applies safe, non-destructive fixes to a copy of the original file:

| Fix | Action |
|---|---|
| `ADD` → `COPY` | Converts non-URL/non-tar `ADD` to `COPY` |
| Missing `HEALTHCHECK` | Appends a default HTTP healthcheck |
| Missing apt cleanup | Appends `rm -rf /var/lib/apt/lists/*` |
| Missing `.dockerignore` | Creates one with common exclusions |

Fixes that require human judgment (like `:latest` → specific version) are flagged but not auto-applied.

### Output

Each run produces:

| Report | Format | Use Case |
|---|---|---|
| `dockerfile-hardener-<timestamp>.txt` | Human-readable | Manual review |
| `dockerfile-hardener-<timestamp>.sarif` | SARIF v2.1.0 | GitHub Code Scanning, CI/CD |

### Integration with the Main Script

From `secure-vps`, the Dockerfile hardener is accessible via:

```
D · 安全运维 → d1 容器安全 → Dockerfile 加固
```

## Common Findings and Fixes

### FAIL: FROM :latest

**Risk**: Image content changes unpredictably, breaking reproducibility.
**Fix**: Pin to a specific version:
```dockerfile
FROM nginx:1.27.2-alpine    # instead of nginx:latest
```

### FAIL: Hardcoded secrets in ENV/ARG

**Risk**: Secrets are baked into image layers and recoverable via `docker history`.
**Fix**: Use runtime injection or BuildKit secrets:
```dockerfile
# Bad
ENV API_KEY=sk-1234567890

# Good (BuildKit)
RUN --mount=type=secret,id=api_key \
    API_KEY=$(cat /run/secrets/api_key) ./configure
```

### FAIL: curl | bash

**Risk**: Blindly executes arbitrary remote code with no integrity check.
**Fix**: Download, verify checksum, then execute:
```dockerfile
RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh && \
    echo "expected_sha256  /tmp/install.sh" | sha256sum -c && \
    sh /tmp/install.sh && rm /tmp/install.sh
```

### WARN: Shell-form ENTRYPOINT/CMD

**Risk**: PID 1 is `/bin/sh -c`, which doesn't forward signals (SIGTERM for graceful shutdown).
**Fix**: Use exec form:
```dockerfile
CMD ["python", "server.py"]    # instead of: CMD python server.py
```

## Secure Dockerfile Template

```dockerfile
# Pin specific version
FROM python:3.12.7-slim AS builder

# No-install-recommends + cleanup in same layer
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy only needed files (not COPY . .)
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r /app/requirements.txt

# Multi-stage: runtime image
FROM python:3.12.7-slim AS runtime

# Non-root user
RUN useradd -r -s /bin/false appuser
USER appuser

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --chown=appuser:appuser ./app /app

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Exec form
CMD ["python", "/app/server.py"]
```

## References

- [Dockerfile reference](https://docs.docker.com/engine/reference/builder/) — Official Docker docs
- [Dockerfile best practices](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/) — Docker official guide
- [SARIF v2.1.0 spec](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) — Static Analysis Results Interchange Format
- [dockerfile-hardener](https://github.com/macbuildssys/dockerfile-hardener) — Reference project
