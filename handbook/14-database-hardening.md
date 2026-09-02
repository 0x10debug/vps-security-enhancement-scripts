# Database Security Hardening (MySQL/PostgreSQL/Redis/MongoDB)

> Automated CIS benchmark auditing and hardened configuration generation for the four most common VPS databases — secure your data layer without reading 400+ pages of benchmark documents.

## Overview

Databases are the crown jewels of most VPS deployments. Default configurations prioritize ease of setup over security: open network bindings, no authentication, weak password policies, no encryption, no audit logging. The **CIS Database Benchmarks** provide vetted, consensus-based configuration guidelines for securing MySQL, PostgreSQL, Redis, and MongoDB.

This chapter covers the database hardening tool shipped with this repo:

- **`scripts/database_hardening.sh`** — Multi-database CIS audit + hardened config generator

The tool operates in two modes:
1. **Audit mode** (`--audit`): Read-only checks against running databases
2. **Config generation mode** (`--mysql`/`--postgres`/`--redis`/`--mongodb`): Generates hardened configuration files for manual deployment

## What It Checks

| Database | Sections | Checks | Key Areas |
|---|---|---|---|
| MySQL/MariaDB | Auth, Network, Logging | 11 | Root password, anonymous accounts, host wildcards, password validation, bind-address, SSL, log_error, general_log, binlog, audit plugin |
| PostgreSQL | Auth, Network, Logging | 11 | Superuser password, public schema grants, pg_hba.conf (scram-sha-256, no md5), listen_addresses, SSL, password_encryption, logging_collector, log_connections, log_line_prefix |
| Redis | Auth, Network, Data | 9 | requirepass, ACL, bind, protected-mode, port/TLS, rename-command, maxmemory, maxmemory-policy |
| MongoDB | Auth, Network, Data | 8 | Authentication, user roles, bindIp, TLS, port, auditLog, authorization, journaling |

## Usage

```bash
# Interactive wizard (auto-detects installed databases)
sudo ./scripts/database_hardening.sh

# Audit all detected databases (read-only)
sudo ./scripts/database_hardening.sh --audit

# Generate hardened configuration for specific database
sudo ./scripts/database_hardening.sh --mysql
sudo ./scripts/database_hardening.sh --postgres
sudo ./scripts/database_hardening.sh --redis
sudo ./scripts/database_hardening.sh --mongodb

# Specify output directory
sudo ./scripts/database_hardening.sh --mysql --output ./my-configs

# Audit specific section only
sudo ./scripts/database_hardening.sh --audit --section auth
sudo ./scripts/database_hardening.sh --audit --section network
sudo ./scripts/database_hardening.sh --audit --section logging
```

### Database Auto-Detection

The tool auto-detects installed databases via:
- CLI availability (`mysql`, `psql`, `redis-cli`, `mongosh`/`mongo`)
- Docker container images (`mysql`, `postgres`, `redis`, `mongo`)

### Output

**Audit mode** produces reports in `/var/log/db-hardening/`:
- `db-audit-<timestamp>.txt` — Human-readable report
- `db-audit-<timestamp>.json` — Machine-readable (for CI/CD)

**Config generation mode** produces hardened configs in the output directory:
```
db-hardening-configs/
├── mysql/
│   ├── hardened-mysqld.cnf    # MySQL/MariaDB hardened config
│   └── README.md              # Deployment instructions
├── postgresql/
│   ├── hardened-postgresql.conf  # PostgreSQL hardened config
│   ├── hardened-pg_hba.conf      # Client authentication config
│   └── README.md                 # Deployment instructions
├── redis/
│   ├── hardened-redis.conf    # Redis hardened config
│   └── README.md              # Deployment instructions
└── mongodb/
    ├── hardened-mongod.conf   # MongoDB hardened config
    └── README.md              # Deployment instructions
```

### Integration with the Main Script

From `secure-vps`, the database hardening is accessible via:

```
D · Security operations → d6 Database security → Database hardening
```

## Common Findings and Fixes

### MySQL: Anonymous accounts exist

**Risk**: Anyone can connect without credentials.
**Fix**:
```sql
DELETE FROM mysql.user WHERE user='';
FLUSH PRIVILEGES;
```

### MySQL: bind-address is 0.0.0.0

**Risk**: Database accessible from any IP.
**Fix**: Edit `my.cnf`:
```ini
[mysqld]
bind-address = 127.0.0.1
```

### PostgreSQL: md5 authentication in pg_hba.conf

**Risk**: md5 is deprecated and vulnerable to replay attacks.
**Fix**: Edit `pg_hba.conf`, replace `md5` with `scram-sha-256`:
```
host all all 127.0.0.1/32 scram-sha-256
```
Then update passwords:
```sql
ALTER USER myuser WITH PASSWORD 'newpassword';
```

### PostgreSQL: listen_addresses is '*'

**Risk**: Database listens on all interfaces.
**Fix**: Edit `postgresql.conf`:
```ini
listen_addresses = 'localhost'
```

### Redis: No password set

**Risk**: Anyone who can reach the port has full access.
**Fix**: Edit `redis.conf`:
```ini
requirepass YourStrongPasswordHere
```

### Redis: Dangerous commands not renamed

**Risk**: `FLUSHDB`, `FLUSHALL`, `CONFIG`, `DEBUG` can cause data loss or information leakage.
**Fix**: Edit `redis.conf`:
```ini
rename-command FLUSHDB ""
rename-command FLUSHALL ""
rename-command CONFIG ""
rename-command DEBUG ""
```

### MongoDB: Authorization not enabled

**Risk**: Anyone who can reach the port has full access.
**Fix**: Create admin user first, then enable in `mongod.conf`:
```yaml
security:
  authorization: enabled
```

### MongoDB: bindIp includes 0.0.0.0

**Risk**: Database accessible from any IP.
**Fix**: Edit `mongod.conf`:
```yaml
net:
  bindIp: 127.0.0.1
```

## Hardened Configuration Highlights

### MySQL
- `bind-address = 127.0.0.1`
- `local_infile = OFF` (prevents file reading via SQL)
- `skip_show_database = ON`
- `binlog_format = ROW` with 7-day retention
- validate_password plugin configuration

### PostgreSQL
- `password_encryption = scram-sha-256`
- `ssl = on`
- `logging_collector = on` with log_connections/disconnections
- `log_line_prefix = '%m [%p] %u@%d %h '`
- pgaudit preload for detailed audit logging
- pg_hba.conf: scram-sha-256 only, no md5, no trust

### Redis
- `bind 127.0.0.1` + `protected-mode yes`
- Unix socket instead of TCP (`port 0`, `unixsocket`)
- `requirepass` set
- Dangerous commands disabled (FLUSHDB, FLUSHALL, KEYS, CONFIG, DEBUG, SHUTDOWN)
- `maxmemory` + `allkeys-lru` policy

### MongoDB
- `bindIp: 127.0.0.1`
- `tls.mode: requireTLS`
- `authorization: enabled`
- `auditLog` to file (JSON format)
- `enableLocalhostAuthBypass: false`

## Relationship to Other Tools

| Tool | Scope | Type |
|---|---|---|
| This script | MySQL + PostgreSQL + Redis + MongoDB | Audit + config generation |
| [pgbench](https://www.postgresql.org/docs/current/pgbench.html) | PostgreSQL performance | Benchmarking |
| [mysqltuner](https://github.com/major/MySQLTuner-perl) | MySQL performance tuning | Performance analysis |
| [redis-benchmark](https://redis.io/topics/benchmarks) | Redis performance | Benchmarking |
| [Lynis](https://github.com/CISOfy/lynis) | Host-level CIS | General security audit |

## Related Tools in the 0x10debug Suite

| Tool | Repo | Focus |
|---|---|---|
| Database hardening (this script) | vps-security-enhancement-scripts | CIS DB benchmarks + config generation |
| db-backup | backup-kit | Database-aware backup (pg_dump/mysqldump/redis/mongodump) |
| Docker audit | vps-security-enhancement-scripts | CIS Docker Benchmark |
| K8s audit | vps-security-enhancement-scripts | CIS Kubernetes Benchmark |

## References

- [CIS MySQL Database Benchmark](https://www.cisecurity.org/benchmark/mysql) — Official benchmark
- [CIS PostgreSQL Benchmark](https://www.cisecurity.org/benchmark/postgresql) — Official benchmark
- [CIS Redis Benchmark](https://www.cisecurity.org/benchmark/redis) — Official benchmark
- [CIS MongoDB Benchmark](https://www.cisecurity.org/benchmark/mongodb) — Official benchmark
- [OWASP Database Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html) — OWASP
- [PostgreSQL Security Documentation](https://www.postgresql.org/docs/current/security.html) — PostgreSQL
- [Redis Security Documentation](https://redis.io/topics/security) — Redis
- [MongoDB Security Checklist](https://docs.mongodb.com/manual/administration/security-checklist/) — MongoDB
