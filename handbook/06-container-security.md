# Container Security

> Docker on a VPS from a security angle — UFW bypass fix, isolation, resource limits, and the pitfalls most tutorials miss.

## Overview

Docker is the standard way to deploy applications on a VPS: it packages dependencies, isolates processes, and makes deployments reproducible. But Docker on a VPS has three traps that catch nearly every operator: mirror pull failures in Asia, log files filling the disk silently, and the infamous UFW bypass that exposes container ports directly to the internet regardless of your firewall rules.

This chapter covers the full Docker lifecycle on a VPS: installation via `vps_secure.sh` or the official script, mirror acceleration for users in China/Asia, log rotation to prevent disk exhaustion, the UFW bypass fix in detail (why it happens and how `vps_secure.sh` fixes it), container management tools (Portainer, Watchtower, Uptime Kuma), 1Panel as an alternative, volume backup strategy, and cleanup operations. We follow the closed loop for each problem: **Problem → Investigate → Fix → Verify**.

## Problem: You Need Docker on the VPS

### Install via vps_secure.sh

```bash
secure-vps  # d1 → 1 → 1 (Docker 引擎 → 安装引擎)
```

This calls the official Docker installation script (`get.docker.com`), then enables and starts the Docker service. It works on all supported distros (Ubuntu, Debian, CentOS, AlmaLinux, Rocky).

### Install manually

```bash
curl -fsSL https://get.docker.com | bash -s docker
systemctl enable docker
systemctl start docker

# Verify:
docker --version
# Docker version 24.0.7

docker run --rm hello-world
# Hello from Docker!
```

### Post-install: add your user to the docker group (optional)

```bash
usermod -aG docker deploy
# Log out and back in for it to take effect
# WARNING: docker group members have root-equivalent access.
# Only add users you fully trust.
```

## Problem: Image Pulls Are Slow or Failing (Asia/China)

### Investigate

```bash
docker pull nginx
# Trying to pull repository docker.io/library/nginx ...
# net/http: TLS handshake timeout   ← symptom in China/Asia
```

Docker Hub's registry is hosted in the US/EU. From China or high-latency Asian networks, pulls timeout or crawl at KB/s.

### Fix: Mirror acceleration

```bash
secure-vps  # d1 → 1 → 2 (镜像加速与日志轮转)
# Choose:
#   1. docker.1ms.run
#   2. docker.m.daocloud.io
#   3. Both
#   4. Custom mirror URLs
```

This writes `/etc/docker/daemon.json` with registry mirrors and log rotation:

```json
{
  "registry-mirrors": ["https://docker.1ms.run", "https://docker.m.daocloud.io"],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "50m",
    "max-file": "3"
  }
}
```

Then restarts Docker. The script snapshots the existing `daemon.json` first and auto-rolls back if Docker fails to restart.

### Verify

```bash
docker info | grep -A5 'Registry Mirrors'
# Registry Mirrors:
#  https://docker.1ms.run/
#  https://docker.m.daocloud.io/

time docker pull nginx
# real 0m3.2s   ← was timing out before
```

**Note**: public mirrors go up and down. If pulls start failing again after weeks/months, re-run `d1 → 1 → 2` and pick different mirrors, or use option 4 to enter custom mirror URLs.

## Problem: Disk Filling Up From Container Logs

### Investigate

```bash
df -h /
# /dev/vda1  39G  35G  4G  90%  /   ← disk almost full

du -sh /var/lib/docker/containers/*/  | sort -rh | head -5
# 15G  /var/lib/docker/containers/abc123/
# 8G   /var/lib/docker/containers/def456/
```

By default, Docker's `json-file` log driver writes container stdout/stderr to a JSON file with **no size limit**. A chatty container (Nginx access logs, app debug output) can fill the disk in days.

### Fix: Log rotation

The `d1 → 1 → 2` step above already sets global log rotation (`max-size: 50m`, `max-file: 3` — max 150 MB per container). But this only applies to containers created AFTER the change. Existing containers keep their old log settings.

For existing containers, either recreate them or set per-container log limits:

```bash
# Per-container limit at run time:
docker run -d \
  --log-driver json-file \
  --log-opt max-size=10m \
  --log-opt max-file=3 \
  --name myapp myimage

# Or in docker-compose.yml:
services:
  myapp:
    image: myimage
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
```

### Clean up existing bloated logs

```bash
# Truncate log files for running containers (doesn't stop them):
truncate -s 0 /var/lib/docker/containers/*/*-json.log

# Or use secure-vps cleanup:
secure-vps  # c1 → 8 (系统清理)
# Offers to prune unused Docker images/containers (volumes untouched)
```

### Verify

```bash
# Check the global setting:
cat /etc/docker/daemon.json | grep -A3 log
# "log-driver": "json-file",
# "log-opts": { "max-size": "50m", "max-file": "3" }

# Check a container's effective log config:
docker inspect --format='{{.HostConfig.LogConfig}}' myapp
# {json-file map[max-file:3 max-size:10m]}
```

## Problem: Docker Bypasses UFW (Critical)

This is the most important section in this chapter. If you run Docker with UFW on Ubuntu/Debian, your firewall is probably not doing what you think it is.

### The Problem Explained

When you run:

```bash
docker run -d -p 8080:80 nginx
```

You expect UFW to control whether port 8080 is reachable. You check:

```bash
ufw status
# Status: active
# 8080/tcp is NOT in the allow list
```

So port 8080 should be blocked, right? **Wrong.** Test from an external machine:

```bash
curl http://203.0.113.10:8080
# <!DOCTYPE html>
# <html><body>Welcome to nginx!</body></html>   ← IT'S REACHABLE
```

**Why this happens**: Docker doesn't use UFW to open ports. When Docker starts, it inserts its own iptables rules directly into the `DOCKER` and `DOCKER-USER` chains. These rules sit in the `nat` and `filter` tables and take precedence over UFW's rules for published ports. The `-p 8080:80` flag tells Docker to DNAT traffic to the container, and Docker's iptables rules allow it through — UFW never sees it.

This means: **every container you run with `-p` is exposed to the public internet, regardless of your UFW rules.** On a server where you think only ports 22/80/443 are open, you might actually have 8080, 3306, 6379, and more exposed through Docker.

### Investigate

```bash
# Check if Docker is managing iptables:
iptables -L DOCKER -n
# Chain DOCKER (1 references)
# target  prot  opt  source   destination
# ACCEPT  tcp   --  0.0.0.0/0  0.0.0.0/0  tcp dpt:8080   ← exposed!

# List all Docker-published ports:
docker ps --format '{{.Names}}: {{.Ports}}'
# nginx: 0.0.0.0:8080->80/tcp
# redis: 0.0.0.0:6379->6379/tcp   ← Redis exposed to internet!

# Check if the fix is already applied:
grep iptables /etc/docker/daemon.json
# (empty = not fixed, bypass is active)
```

### Fix: UFW Takeover

```bash
secure-vps  # d1 → 1 → 3 (UFW 接管 / 修复端口绕过)
```

What this does, step by step:

1. **Sets `"iptables": false` in `/etc/docker/daemon.json`** — tells Docker to stop managing iptables rules itself. Docker will no longer auto-open ports for `-p` published containers.

2. **Injects a NAT rule into `/etc/ufw/before.rules`**:
   ```
   *nat
   :POSTROUTING ACCEPT [0:0]
   -A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE
   COMMIT
   ```
   This provides outbound NAT for the default `docker0` bridge network (172.17.0.0/16), so containers can still reach the internet for pulling packages, making API calls, etc.

3. **Reloads UFW and restarts Docker.**

After this fix, container ports are **only reachable if you explicitly `ufw allow` them** — exactly how you'd expect a firewall to work.

### Impact (Important)

After applying the fix:
- **All currently published container ports immediately become unreachable from outside.** This is the intended behavior — you now control them via UFW.
- You must `ufw allow <port>/tcp` for each container port you want public.
- **Custom bridge networks need their own NAT rules.** The fix only covers the default `docker0` (172.17.0.0/16). If you create custom networks (`docker network create --subnet 172.18.0.0/16 mynet`), add a corresponding MASQUERADE line for that subnet in `/etc/ufw/before.rules` (look for the `SECURE_VPS_DOCKER_MASQ` marker).

### Verify

```bash
# Confirm the fix is active:
grep iptables /etc/docker/daemon.json
# "iptables": false

grep SECURE_VPS_DOCKER_MASQ /etc/ufw/before.rules
# -A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE

# Test: run a container with -p, confirm it's blocked by default:
docker run -d -p 9999:80 --name test nginx
curl -m 3 http://203.0.113.10:9999
# curl: (28) Connection timed out   ← UFW is blocking it (correct!)

# Now allow it:
ufw allow 9999/tcp
curl http://203.0.113.10:9999
# <!DOCTYPE html>...   ← now reachable

# Clean up:
ufw delete allow 9999/tcp
docker rm -f test
```

### Undo (if needed)

```bash
secure-vps  # d1 → 1 → 3 again (detects fix is active, offers to undo)
# Restores daemon.json and before.rules from snapshots
```

**Only works on UFW systems.** On firewalld (RHEL family), Docker integrates with firewalld's `docker` zone and the bypass behavior is different. If you're on RHEL and concerned about container port exposure, use `firewall-cmd --zone=public --remove-port=<port>/tcp` and verify with `iptables -L DOCKER -n`.

## Container Management Tools

### Portainer (Web management panel)

```bash
secure-vps  # d1 → 2 → 1 (Portainer)
```

Deploys Portainer CE on port 9000 with:
- Docker socket mounted (`/var/run/docker.sock`) for full Docker control
- Persistent volume `portainer_data`
- Offers to open port 9000 in UFW

Access at `http://server-ip:9000` and set an admin password on first login.

**Use it for**: visual container management, log viewing, image management, stack (compose) deployment. Good for teams where not everyone is comfortable with the CLI.

**Security note**: Portainer with the Docker socket mounted has root-equivalent access. Protect port 9000 carefully — restrict to a VPN or SSH tunnel if possible.

### Watchtower (automatic container updates)

```bash
secure-vps  # d1 → 2 → 2 (Watchtower)
```

Deploys Watchtower, which checks for image updates every 24 hours and automatically recreates containers with the new image. Good for keeping side projects and personal services patched.

**Use it for**: non-critical services where auto-update risk is acceptable. **Do NOT use it for** production databases or services where an update breaking behavior would cause downtime. For those, update manually with tested images.

### Uptime Kuma (uptime monitoring)

```bash
secure-vps  # d1 → 2 → 3 (Uptime Kuma)
```

Deploys Uptime Kuma on port 3001 — a lightweight self-hosted uptime monitor with a web UI. Configure HTTP/TCP/ping monitors and get alerts via Telegram, email, Discord, webhooks, etc. See Chapter 07 for monitoring strategy.

### 1Panel (alternative management panel)

```bash
secure-vps  # d1 → 3 (1Panel 面板)
```

1Panel is a Chinese-origin server management panel that combines Docker management, website hosting, database management, firewall config, and file management in one UI. It's heavier than Portainer but more full-featured for users who want a "cPanel-like" experience.

**Use it when**: you're managing a server that hosts multiple websites/apps and want a unified panel for everything (not just Docker). **Avoid it when**: you want minimal installed components and prefer CLI control — Portainer + CLI is lighter and more transparent.

## Volume Backup Strategy

### What to back up

Docker volumes are where your persistent data lives. Containers are ephemeral; volumes are not (unless you delete them). The critical volumes to back up:

```bash
# List all volumes:
docker volume ls
# DRIVER  VOLUME NAME
# local   portainer_data
# local   myapp_db_data
# local   myapp_uploads

# Find which containers use which volumes:
docker inspect --format='{{.Name}}: {{range .Mounts}}{{.Name}} {{end}}' $(docker ps -aq)
# /myapp: myapp_db_data myapp_uploads
```

### vps_secure.sh approach (manual tar)

For a quick one-off volume backup:

```bash
# Back up a volume to a tarball:
docker run --rm -v myapp_db_data:/data -v $(pwd):/backup alpine \
  tar czf /backup/myapp_db_data_$(date +%Y%m%d).tar.gz -C /data .

# Restore:
docker run --rm -v myapp_db_data:/data -v $(pwd):/backup alpine \
  tar xzf /backup/myapp_db_data_20240115.tar.gz -C /data
```

### backup-kit (recommended for production)

For automated, encrypted, deduplicated backups, use **backup-kit** from the 0x10debug ecosystem. It supports:
- **restic**: encrypted, deduplicated backups to local/S3/B2
- **kopia**: similar to restic with a GUI option
- **borgmatic**: Borg-based with config-driven schedules

Use backup-kit when:
- You need scheduled, automated backups (cron or systemd timers)
- You want encryption (volumes may contain secrets, user data)
- You need deduplication (daily volume backups of similar data)
- You want restore testing (backup-kit includes a drill feature)

See Chapter 06 for the full backup and recovery workflow.

## Docker Cleanup

### Prune unused resources

```bash
secure-vps  # c1 → 8 (系统清理)
# Offers to run: docker system prune -af
# (removes stopped containers, unused networks, dangling images, build cache)
# Volumes are NOT touched (safe).
```

Manual cleanup:

```bash
# Remove stopped containers:
docker container prune

# Remove unused images (not referenced by any container):
docker image prune -a

# Remove unused volumes (CAREFUL — this deletes volume data):
docker volume prune
# Only run this if you're sure no volume you need is "unused"

# Full cleanup (everything except volumes):
docker system prune -a

# Nuclear option (including volumes):
docker system prune -a --volumes
# Only when you want a clean slate.
```

### Check disk usage

```bash
docker system df
# TYPE      TOTAL  ACTIVE  SIZE   RECLAIMABLE
# Images    15     8       5.2GB  2.1GB (40%)
# Containers 12    10      340MB  50MB (14%)
# Volumes   5      5       8.1GB  0B (0%)
# Build Cache  20   0      1.5GB  1.5GB

# "RECLAIMABLE" shows what prune would free.
```

## Common Issues

### Container can't resolve DNS

```bash
docker run --rm alpine nslookup google.com
# nslookup: can't resolve 'google.com': Try again
```

**Cause**: Docker's embedded DNS (127.0.0.11) forwards to the host's `/etc/resolv.conf`. If the host DNS is broken, containers can't resolve.

**Fix**:

```bash
# Check host DNS:
cat /etc/resolv.conf
# nameserver 8.8.8.8   ← if missing or wrong, fix it

# Switch DNS via secure-vps:
secure-vps  # c1 → 4 (DNS 切换)
# Options: Cloudflare (1.1.1.1), Google (8.8.8.8), AliDNS (223.5.5.5), custom

# Restart Docker to pick up the change:
systemctl restart docker
```

If you applied the UFW takeover fix, also check that the docker0 NAT rule is present (containers need NAT for outbound DNS):

```bash
grep SECURE_VPS_DOCKER_MASQ /etc/ufw/before.rules
# Must show the MASQUERADE line for 172.17.0.0/16
```

### Port conflict

```bash
docker run -d -p 80:80 nginx
# docker: Error response from daemon: driver failed programming external
# connectivity on endpoint web: Bind for 0.0.0.0:80 failed: port is already allocated.
```

**Investigate**:

```bash
ss -tlnp | grep ':80 '
# LISTEN 0.0.0.0:80  nginx (host)   ← host nginx is using port 80

docker ps --format '{{.Names}}: {{.Ports}}' | grep 80
# oldweb: 0.0.0.0:80->80/tcp        ← another container has it
```

**Fix**: stop the conflicting process/container, or use a different host port (`-p 8080:80`).

### Disk full, Docker won't start

```bash
systemctl start docker
# Job for docker.service failed. See "systemctl status docker.service"
journalctl -u docker --no-pager -n 10
# failed to start daemon: error while opening Docker datastore: no space left on device
```

**Fix**: free space without Docker (it can't start to help):

```bash
# Clear package cache:
apt clean          # or: yum clean all

# Clear old logs:
journalctl --vacuum-size=100M

# Clear Docker's dead logs manually:
rm /var/lib/docker/containers/*/*-json.log

# Now Docker should start:
systemctl start docker
docker system prune -af   # clean up properly
```

## What's Next

- **Chapter 02** — Security baseline: the UFW bypass fix in the context of the full security stack
- **Chapter 06** — Backup and migration: volume backup strategy and recovery drills with backup-kit
- **Chapter 07** — Monitoring: Uptime Kuma deployment and what to monitor for Docker containers
