# Backup Security

> Backups are your safety net — insurance you pay for before you need them, with credential protection and recovery drills.

## Overview

Every ops engineer knows they should back up. Most learn the hard way that "I have backups" and "I can restore from backups" are two completely different statements. A backup you've never tested is a hope, not a backup. This chapter covers what to back up on a VPS, how to choose a backup strategy, Docker volume backup approaches, server migration, the `vps_secure.sh` self-update mechanism, and — most importantly — recovery drills.

We follow the closed loop for each scenario: **Problem (what could I lose?) → Investigate (what's critical and where is it?) → Fix (implement backup) → Verify (test the restore)**. We cross-reference **backup-kit** from the 0x10debug ecosystem for production-grade automated backups with encryption, deduplication, and restore testing.

## Problem: What Would You Lose If the Server Died Right Now?

### Investigate: What to back up

Before setting up backups, inventory what matters. On a typical VPS, the critical data falls into categories:

```bash
# 1. Application data (the stuff you can't recreate)
ls -la /data/                    # custom app data directory
docker volume ls                 # Docker persistent volumes
docker inspect --format='{{range .Mounts}}{{.Source}} ({{.Name}}){{"\n"}}{{end}}' $(docker ps -q)
# /var/lib/docker/volumes/myapp_db_data/_data (myapp_db_data)
# /var/lib/docker/volumes/myapp_uploads/_data (myapp_uploads)

# 2. Configuration (hours of work to recreate)
ls /etc/nginx/sites-enabled/     # web server configs
ls /etc/docker/                  # Docker daemon config
cat /etc/fail2ban/jail.local     # Fail2Ban config
ls /etc/sysctl.d/99-secure-vps-*.conf  # kernel/BBR/swap tuning

# 3. Databases (the irreplaceable business data)
docker exec mysqld mysqldump --all-databases --single-transaction > /dev/null 2>&1
# Test: can you dump the database? If not, you can't back it up.

# 4. System state (less critical, but annoying to lose)
crontab -l                       # scheduled jobs
systemctl list-unit-files --state=enabled  # enabled services
```

### The backup inventory

| Category | Location | Frequency | Why |
|----------|----------|-----------|-----|
| App data | `/data/`, Docker volumes | Daily | Business-critical, irreplaceable |
| Databases | In-container or `/var/lib/mysql` | Daily (hot dump) | Transactional data, constantly changing |
| Configs | `/etc/` (selective) | On change + weekly | Hours to recreate, easy to back up |
| Docker compose files | `~/compose/`, `/opt/` | On change | Defines your deployment |
| Cron jobs | `crontab -l` output | On change | Scheduled tasks, easy to forget |
| SSH keys | `~/.ssh/` | Once + on change | Access credentials |

## Fix: Backup Strategy Selection

### Option A: Manual tar (simple, no automation)

For a single small server with infrequent changes:

```bash
# Quick manual backup of configs + data:
tar czf /tmp/backup_$(date +%Y%m%d).tar.gz \
  /data/ \
  /etc/nginx/ \
  /etc/docker/daemon.json \
  /etc/fail2ban/jail.local \
  /etc/sysctl.d/99-secure-vps-*.conf \
  /root/.ssh/authorized_keys \
  ~/compose/

# Transfer to another machine:
scp /tmp/backup_20240115.tar.gz user@backup-server:/backups/
```

**Pros**: simple, no dependencies, works everywhere.
**Cons**: no encryption, no deduplication, no automation, easy to forget, large files.

**Use for**: one-off backups before making changes, or very small servers with minimal data.

### Option B: backup-kit with restic (recommended)

**backup-kit** from the 0x10debug ecosystem provides structured backup management using restic:

- **Encrypted**: backups are encrypted client-side, safe for cloud storage
- **Deduplicated**: only changed blocks are stored, saving space
- **Incremental**: fast daily backups after the initial full backup
- **Scheduled**: cron or systemd timer integration
- **Multi-destination**: local, S3, B2, SFTP

```bash
# Typical restic workflow (backup-kit wraps this):
restic init --repo s3:s3.amazonaws.com/my-backup-bucket
restic backup /data/ /etc/nginx/ --repo s3:s3.amazonaws.com/my-backup-bucket
restic snapshots --repo s3:s3.amazonaws.com/my-backup-bucket
# ID      Date      Host    Tags  Directory
# abc123  2024-01-15  vps01        /data/, /etc/nginx/
```

**Pros**: encrypted, deduplicated, automated, supports cloud storage, includes restore drill tooling.
**Cons**: more setup than tar, requires learning restic commands.

**Use for**: any server with data you care about. This is the recommended approach.

### Option C: backup-kit with kopia

Kopia is similar to restic but with a GUI option and slightly different deduplication approach:

**Pros**: GUI available, good for visual browsing of snapshots, strong deduplication.
**Cons**: less mature than restic for CLI-only environments, larger resource footprint.

**Use for**: environments where a GUI is valuable, or teams preferring kopia's workflow.

### Option D: backup-kit with borgmatic

Borg-based backups with YAML configuration:

**Pros**: config-driven (YAML), very mature deduplication, strong community.
**Cons**: Borg doesn't support cloud storage natively (needs B2 via rclone or SFTP).

**Use for**: SFTP-based backup destinations, or teams already using Borg.

### Recommendation

For most VPS operators: **backup-kit with restic**. It balances encryption, deduplication, cloud storage support, and ease of use. Use the manual tar approach only for one-off snapshots before risky changes.

## Fix: Docker Volume Backup

### The challenge with Docker volumes

Docker volumes live at `/var/lib/docker/volumes/<name>/_data/`. You can't just `tar` the directory while the container is running and writing to it — you'll get an inconsistent backup.

### Approach 1: Stop-and-copy (safe, brief downtime)

```bash
# Stop the container, copy the volume, restart:
docker stop myapp
docker run --rm -v myapp_db_data:/data -v $(pwd):/backup alpine \
  tar czf /backup/myapp_db_data_$(date +%Y%m%d).tar.gz -C /data .
docker start myapp
```

**Pros**: guaranteed consistent backup.
**Cons**: downtime during backup (seconds to minutes depending on volume size).

### Approach 2: Database-aware dump (no downtime)

For databases, use the database's native dump tool — it produces a consistent snapshot without stopping the container:

```bash
# MySQL/MariaDB:
docker exec mysqld mysqldump -u root -p<password> --all-databases --single-transaction \
  > /backups/mysql_$(date +%Y%m%d).sql

# PostgreSQL:
docker exec postgres pg_dumpall -U postgres \
  > /backups/postgres_$(date +%Y%m%d).sql

# Redis (BGSAVE creates a snapshot):
docker exec redis redis-cli BGSAVE
sleep 5
docker cp redis:/data/dump.rdb /backups/redis_$(date +%Y%m%d).rdb
```

**Pros**: no downtime, consistent dump.
**Cons**: only works for databases with dump tools; doesn't back up the volume itself.

### Approach 3: backup-kit (automated, recommended)

backup-kit handles Docker volume backups with proper consistency:

```bash
# backup-kit can:
# 1. Run database dumps before backing up volumes
# 2. Back up volumes while running (restic handles file-level dedup)
# 3. Schedule automatically
# 4. Test restores periodically
```

**Use backup-kit when**: you have multiple containers with volumes and databases, and you need automated, consistent backups without manual intervention.

## Fix: Server Migration

### Scenario: Moving to a new VPS

Whether upgrading to a bigger server, changing providers, or relocating to a different region, migration follows the same pattern: export → transfer → verify → switch.

### Step 1: Export from the old server

```bash
# On the old server:
# 1. Dump databases:
docker exec mysqld mysqldump -u root -p<password> --all-databases --single-transaction \
  > /tmp/migration/mysql_dump.sql

# 2. Export Docker volumes:
for vol in $(docker volume ls -q); do
  docker run --rm -v $vol:/data -v /tmp/migration:/backup alpine \
    tar czf /backup/volume_${vol}.tar.gz -C /data .
done

# 3. Export configs:
tar czf /tmp/migration/configs.tar.gz \
  /etc/nginx/ /etc/docker/daemon.json /etc/fail2ban/jail.local \
  /etc/sysctl.d/99-secure-vps-*.conf \
  /root/.ssh/authorized_keys \
  ~/compose/ /data/

# 4. Export crontab:
crontab -l > /tmp/migration/crontab.txt

# 5. List enabled services:
systemctl list-unit-files --state=enabled > /tmp/migration/enabled_services.txt
```

### Step 2: Transfer to the new server

```bash
# From the old server:
rsync -avz --progress /tmp/migration/ root@new-server:/tmp/migration/

# Or via scp:
scp -r /tmp/migration/ root@new-server:/tmp/migration/
```

### Step 3: Set up the new server

```bash
# On the new server:
# 1. Run initial setup (Chapter 01):
secure-vps  # a1 (quick init)

# 2. Apply security baseline (Chapter 02):
# SSH hardening, firewall, fail2ban, etc.

# 3. Install Docker:
secure-vps  # d1 → 1 → 1

# 4. Restore configs:
cd /tmp/migration
tar xzf configs.tar.gz -C /

# 5. Restore Docker volumes:
for vol_archive in /tmp/migration/volume_*.tar.gz; do
  vol_name=$(basename $vol_archive .tar.gz | sed 's/volume_//')
  docker volume create $vol_name
  docker run --rm -v $vol_name:/data -v /tmp/migration:/backup alpine \
    tar xzf /backup/$(basename $vol_archive) -C /data
done

# 6. Restore databases:
docker exec -i mysqld mysql -u root -p<password> < /tmp/migration/mysql_dump.sql

# 7. Restore crontab:
crontab /tmp/migration/crontab.txt

# 8. Start your compose stack:
cd ~/compose && docker compose up -d
```

### Step 4: Verify before switching DNS

```bash
# Test the new server locally (add to /etc/hosts on your machine):
# 203.0.113.20  myapp.example.com

curl -I https://myapp.example.com
# HTTP/2 200   ← working

# Test database connectivity:
docker exec -it mysqld mysql -u root -p -e "SHOW DATABASES;"
# Database list matches old server

# Compare data:
# Old server: docker exec mysqld mysql -e "SELECT COUNT(*) FROM users;" myapp
# New server: docker exec mysqld mysql -e "SELECT COUNT(*) FROM users;" myapp
# Counts must match
```

### Step 5: Switch DNS

```bash
# Lower DNS TTL before migration (do this 24h before):
# Set TTL to 300 (5 min) so the switch propagates quickly

# Update A record to new server IP
# Wait for propagation (check: dig @8.8.8.8 myapp.example.com +short)

# Keep the old server running for 48h as a fallback
# Monitor both old and new server logs during the transition
```

## Fix: vps_secure.sh Self-Update

### Script migration between servers

When migrating, you'll want `vps_secure.sh` on the new server too. Two approaches:

```bash
# Option 1: Fresh download on the new server:
curl -fsSL https://raw.githubusercontent.com/0x10debug/vps-secure-script/main/vps_secure.sh -o vps_secure.sh
chmod +x vps_secure.sh

# Option 2: Copy from old server:
scp root@old-server:~/vps_secure.sh ./
```

### Self-update mechanism

`vps_secure.sh` can update itself in place:

```bash
secure-vps  # z3 (检查更新)
```

The self-update process (`secure_vps_self_update`):
1. Downloads the latest version from the upstream URL to a temp file
2. Extracts the version string (`APP_VER`) from the download
3. Compares with the current version — if same, reports "already up to date"
4. If newer: validates the download with `bash -n` (syntax check)
5. Only if syntax check passes: overwrites the running script
6. Re-executes itself with the new version

**Safety features**:
- Downloads to a temp file first, never directly over the running script
- Syntax validation before overwriting (a broken script won't replace a working one)
- Version comparison prevents unnecessary updates
- The `secure-vps` global symlink (if installed via `z1`) follows the source file automatically

### Install as global command

```bash
secure-vps  # z1 (安装全局命令)
# Creates symlink: /usr/local/bin/secure-vps → /path/to/vps_secure.sh
# After this, you can run `secure-vps` from any directory
# The symlink follows the source file, so updates apply automatically
```

## Fix: Recovery Drill

### Why you must test restores

A backup that has never been restored is unproven. Common failures discovered during drills:
- The backup is corrupted (incomplete, truncated)
- The backup is missing critical files you forgot to include
- The restore process doesn't work as documented
- The restore takes longer than your RTO (Recovery Time Objective) allows
- Dependencies are missing on the restore target (wrong Docker version, missing tools)

### Drill procedure

```bash
# 1. Provision a fresh test server (same OS, same Docker version)
# 2. Run secure-vps a1 (baseline setup)
# 3. Restore from backup:
#    - Restore configs
#    - Restore Docker volumes
#    - Restore database dumps
#    - Start the application stack
# 4. Verify:
#    - Application loads and responds correctly
#    - Database queries return expected data
#    - User accounts exist and can authenticate
#    - All services are healthy (docker ps, systemctl status)
# 5. Measure:
#    - How long did the restore take? (compare to your RTO)
#    - Did anything fail? (fix the backup or the restore process)
# 6. Document:
#    - Write down the exact restore steps
#    - Note any manual interventions needed
#    - Update the backup if anything was missing
```

### backup-kit drill feature

**backup-kit** includes a restore drill tool that automates this process:
- Provisions a temporary restore target
- Runs the restore automatically
- Verifies key data points
- Reports pass/fail with details
- Tears down the temporary target

Use the drill feature monthly for production servers. A monthly drill catches backup corruption, configuration drift, and process gaps before a real incident does.

## Common Pitfalls

### Backing up a running database without a snapshot

```bash
# WRONG — inconsistent backup:
tar czf db_backup.tar.gz /var/lib/mysql/
# MySQL is writing while tar reads → corrupted backup

# RIGHT — use mysqldump with --single-transaction:
mysqldump --single-transaction --all-databases > db_dump.sql
# --single-transaction creates a consistent snapshot without locking

# RIGHT — or stop the database first:
docker stop mysqld
tar czf db_backup.tar.gz /var/lib/docker/volumes/mysql_data/_data/
docker start mysqld
```

### Forgetting to back up cron jobs

Cron jobs live in `/var/spool/cron/crontabs/` and are only visible via `crontab -l`. If you migrate without exporting crontabs, your scheduled backups, log rotation, and maintenance tasks silently stop running.

```bash
# Always export crontab as part of migration:
crontab -l > /tmp/migration/crontab.txt

# And system-wide cron:
cp -r /etc/cron.d/ /tmp/migration/cron.d/
cp /etc/crontab /tmp/migration/
```

### Forgetting to back up Docker compose files

Your `docker-compose.yml` files define your entire deployment. If you only back up volumes and data but not the compose files, you'll spend hours reconstructing the service configuration during recovery.

```bash
# Include compose files in backup:
tar czf backup.tar.gz ~/compose/ /opt/*/docker-compose.yml
```

### Not testing the offsite backup

If your backup is on the same provider as your server, a provider outage takes down both. Always maintain at least one offsite backup copy (different provider, S3, B2, or a local machine).

### Backup encryption without key backup

If you encrypt backups (restic, kopia, Borg all do) but don't back up the encryption key/repo password separately, losing the key means losing all backups — permanently.

```bash
# Store the repo password in a password manager, AND in a separate file:
echo "my-restic-password" > /root/.restic-password
chmod 600 /root/.restic-password
# Back up this file to a DIFFERENT location than the backups
```

## What's Next

- **Chapter 07** — Monitoring: detecting backup failures before you need to restore
- **Chapter 08** — Incident response: using backups during recovery from compromise
- **Chapter 03** — Docker operations: volume management in the Docker context
