#!/bin/bash
# ════════════════════════════════════════════════════════════
#  database_hardening.sh — Database Security Hardening (MySQL/PostgreSQL/Redis/MongoDB)
#  Supported OS: Linux host (requires database installed or running via Docker)
#  Run as: root or database superuser
#  Mode: Read-only audit + config generation (does not directly modify running databases)
#  Reference: CIS MySQL Database Benchmark v2.0
#         CIS PostgreSQL Benchmark v15.0
#         CIS Redis Benchmark v1.0
#         CIS MongoDB Benchmark v1.0
#         OWASP Database Security Cheat Sheet
#  Project home: https://github.com/0x10debug/vps-security-enhancement-scripts
# ════════════════════════════════════════════════════════════
#
# Usage:
#   sudo ./scripts/database_hardening.sh                    # Interactive wizard
#   sudo ./scripts/database_hardening.sh --audit            # Read-only audit all detected databases
#   sudo ./scripts/database_hardening.sh --mysql            # Generate MySQL hardening config
#   sudo ./scripts/database_hardening.sh --postgres         # Generate PostgreSQL hardening config
#   sudo ./scripts/database_hardening.sh --redis            # Generate Redis hardening config
#   sudo ./scripts/database_hardening.sh --mongodb          # Generate MongoDB hardening config
#   sudo ./scripts/database_hardening.sh --output ./configs # Specify config output directory
#   sudo ./scripts/database_hardening.sh --section auth     # Audit authentication section only
#
# Exit codes:
#   0 — Success
#   1 — Parameter error / No database to detect
#   2 — Some features unavailable

set -euo pipefail
# shellcheck disable=SC2154
# Variables assigned inside bash -c strings are not seen by shellcheck

APP_NAME="database_hardening"
APP_VER="v3.0.0"
MODE=""
OUTPUT_DIR=""
SECTION_FILTER=""
REPORT_DIR="/var/log/db-hardening"
TIMESTAMP=$(date +%Y%m%d%H%M%S)

COUNT_PASS=0
COUNT_FAIL=0
COUNT_WARN=0
COUNT_SKIP=0
TOTAL_CHECKS=0
JSON_RESULTS="["
DETECTED_DBS=""

C_FAIL='\033[0;31m'
C_OK='\033[0;32m'
C_WARN='\033[0;33m'
C_INFO='\033[0;34m'
C_RST='\033[0m'

# ── Parameter parsing ─────────────────────────────────────────────────
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --audit) MODE="audit"; shift ;;
            --mysql) MODE="mysql"; shift ;;
            --postgres) MODE="postgres"; shift ;;
            --redis) MODE="redis"; shift ;;
            --mongodb) MODE="mongodb"; shift ;;
            --section) SECTION_FILTER="$2"; shift 2 ;;
            --output) OUTPUT_DIR="$2"; shift 2 ;;
            -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
            *) echo "Unknown parameter: $1"; exit 1 ;;
        esac
    done
    if [ -z "$MODE" ]; then
        MODE="interactive"
    fi
    if [ -z "$OUTPUT_DIR" ]; then
        OUTPUT_DIR="./db-hardening-configs"
    fi
}

# ── Database detection ───────────────────────────────────────────────
detect_databases() {
    DETECTED_DBS=""

    # MySQL/MariaDB
    if command -v mysql >/dev/null 2>&1 || command -v mariadb >/dev/null 2>&1; then
        DETECTED_DBS="$DETECTED_DBS mysql"
    fi
    # MySQL in Docker
    if command -v docker >/dev/null 2>&1; then
        if docker ps --format '{{.Image}}' 2>/dev/null | grep -qiE "mysql|mariadb"; then
            DETECTED_DBS="$DETECTED_DBS mysql"
        fi
    fi

    # PostgreSQL
    if command -v psql >/dev/null 2>&1; then
        DETECTED_DBS="$DETECTED_DBS postgres"
    fi
    if command -v docker >/dev/null 2>&1; then
        if docker ps --format '{{.Image}}' 2>/dev/null | grep -qi "postgres"; then
            DETECTED_DBS="$DETECTED_DBS postgres"
        fi
    fi

    # Redis
    if command -v redis-cli >/dev/null 2>&1; then
        DETECTED_DBS="$DETECTED_DBS redis"
    fi
    if command -v docker >/dev/null 2>&1; then
        if docker ps --format '{{.Image}}' 2>/dev/null | grep -qi "redis"; then
            DETECTED_DBS="$DETECTED_DBS redis"
        fi
    fi

    # MongoDB
    if command -v mongosh >/dev/null 2>&1 || command -v mongo >/dev/null 2>&1; then
        DETECTED_DBS="$DETECTED_DBS mongodb"
    fi
    if command -v docker >/dev/null 2>&1; then
        if docker ps --format '{{.Image}}' 2>/dev/null | grep -qi "mongo"; then
            DETECTED_DBS="$DETECTED_DBS mongodb"
        fi
    fi

    DETECTED_DBS=$(echo "$DETECTED_DBS" | xargs | tr ' ' '\n' | sort -u | tr '\n' ' ' | xargs)
}

# ── Report initialization ───────────────────────────────────────────────
init_report() {
    if ! mkdir -p "$REPORT_DIR" 2>/dev/null; then
        REPORT_DIR="/tmp/db-hardening"
        mkdir -p "$REPORT_DIR" 2>/dev/null || true
    fi
    local report="$REPORT_DIR/db-audit-${TIMESTAMP}.txt"
    REPORT_FILE="$report"
    {
        echo "Database Security Audit Report"
        echo "================================"
        echo "Date: $(date)"
        echo "Host: $(hostname 2>/dev/null || echo 'N/A')"
        echo "Databases: $DETECTED_DBS"
        echo "Script: $APP_NAME $APP_VER"
        echo ""
    } > "$report"
}

# ── Check functions ─────────────────────────────────────────────────
run_check() {
    local cis_id="$1" desc="$2"
    shift 2
    local result evidence rc

    evidence=$("$@" 2>&1) && rc=0 || rc=$?
    case $rc in
        0) result="PASS" ;;
        1) result="FAIL" ;;
        2) result="WARN" ;;
        *) result="SKIP" ;;
    esac

    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    case "$result" in
        PASS) COUNT_PASS=$((COUNT_PASS + 1)) ;;
        FAIL) COUNT_FAIL=$((COUNT_FAIL + 1)) ;;
        WARN) COUNT_WARN=$((COUNT_WARN + 1)) ;;
        SKIP) COUNT_SKIP=$((COUNT_SKIP + 1)) ;;
    esac

    local color
    case "$result" in
        PASS) color="$C_OK" ;;
        FAIL) color="$C_FAIL" ;;
        WARN) color="$C_WARN" ;;
        SKIP) color="$C_INFO" ;;
    esac
    printf "  ${color}%-4s${C_RST} %s  %s\n" "$result" "$cis_id" "$desc"

    {
        echo ""
        echo "[$result] $cis_id $desc"
        echo "  Evidence: $evidence"
    } >> "$REPORT_FILE"

    local json_entry
    json_entry=$(printf '{"id":"%s","description":"%s","result":"%s","evidence":"%s"}' \
        "$cis_id" "${desc//\"/\\\"}" "$result" "${evidence//\"/\\\"}")
    if [ "$TOTAL_CHECKS" -gt 1 ]; then
        JSON_RESULTS="$JSON_RESULTS,$json_entry"
    else
        JSON_RESULTS="$JSON_RESULTS$json_entry"
    fi
}

# ── MySQL audit ───────────────────────────────────────────────
audit_mysql() {
    echo ""
    echo "━━━ MySQL/MariaDB CIS Benchmark ━━━"

    local mysql_cmd
    if command -v mysql >/dev/null 2>&1; then
        mysql_cmd="mysql"
    else
        mysql_cmd="mariadb"
    fi

    echo -e "  ${C_INFO}── Authentication and access control ──${C_RST}"

    run_check "MYSQL-1.1" "Ensure root account has a password set" \
        bash -c "$mysql_cmd -u root -e 'SELECT user,host FROM mysql.user WHERE user=\"root\" AND authentication_string=\"\";' 2>/dev/null | grep -q . && echo 'root has empty password' && return 1 || echo 'root password set or no root user' && return 0"

    run_check "MYSQL-1.2" "Ensure no anonymous accounts exist" \
        bash -c "$mysql_cmd -u root -e 'SELECT user,host FROM mysql.user WHERE user=\"\";' 2>/dev/null | grep -q . && echo 'anonymous accounts exist' && return 1 || echo 'no anonymous accounts' && return 0"

    run_check "MYSQL-1.3" "Ensure no user has host wildcard '%'" \
        bash -c "count=\$($mysql_cmd -u root -e 'SELECT COUNT(*) FROM mysql.user WHERE host=\"%\";' -sN 2>/dev/null || echo 0); echo \"\$count users with host %\"; [ \"\$count\" -eq 0 ] && return 0 || return 1"

    run_check "MYSQL-1.4" "Ensure password validation plugin is installed" \
        bash -c "$mysql_cmd -u root -e 'SHOW PLUGINS;' 2>/dev/null | grep -qi 'validate_password' && echo 'validate_password installed' && return 0 || echo 'validate_password not installed' && return 2"

    echo -e "  ${C_INFO}── Network and connectivity ──${C_RST}"

    run_check "MYSQL-2.1" "Ensure bind-address is not 0.0.0.0" \
        bash -c "val=\$($mysql_cmd -u root -e 'SHOW VARIABLES LIKE \"bind_address\";' -sN 2>/dev/null | awk '{print \$2}' || echo '*'); echo \"bind_address=\$val\"; [ \"\$val\" != \"*\" ] && [ \"\$val\" != \"0.0.0.0\" ] && return 0 || return 1"

    run_check "MYSQL-2.2" "Ensure SSL/TLS is enabled for connections" \
        bash -c "$mysql_cmd -u root -e 'SHOW VARIABLES LIKE \"have_ssl\";' -sN 2>/dev/null | awk '{print \$2}' | grep -qi 'YES' && echo 'SSL enabled' && return 0 || echo 'SSL not enabled' && return 2"

    run_check "MYSQL-2.3" "Ensure skip-networking is considered for local-only" \
        bash -c "$mysql_cmd -u root -e 'SHOW VARIABLES LIKE \"skip_networking\";' -sN 2>/dev/null | awk '{print \$2}' | grep -qi 'OFF' && echo 'networking enabled (check if needed)' && return 2 || echo 'networking disabled' && return 0"

    echo -e "  ${C_INFO}── Data and logs ──${C_RST}"

    run_check "MYSQL-3.1" "Ensure log_error is set" \
        bash -c "val=$($mysql_cmd -u root -e 'SHOW VARIABLES LIKE \"log_error\";' -sN 2>/dev/null | awk '{print \$2}' || echo ''); [ -n \"\$val\" ] && echo \"log_error=\$val\" && return 0 || echo 'log_error not set' && return 2"

    run_check "MYSQL-3.2" "Ensure general_log is not enabled in production" \
        bash -c "val=$($mysql_cmd -u root -e 'SHOW VARIABLES LIKE \"general_log\";' -sN 2>/dev/null | awk '{print \$2}' || echo 'OFF'); [ \"\$val\" = \"OFF\" ] && echo 'general_log off' && return 0 || echo 'general_log on (performance impact)' && return 2"

    run_check "MYSQL-3.3" "Ensure binlog is enabled for replication/recovery" \
        bash -c "val=$($mysql_cmd -u root -e 'SHOW VARIABLES LIKE \"log_bin\";' -sN 2>/dev/null | awk '{print \$2}' || echo 'OFF'); [ \"\$val\" = \"ON\" ] && echo 'binlog enabled' && return 0 || echo 'binlog disabled' && return 2"

    run_check "MYSQL-3.4" "Ensure audit plugin is installed (enterprise/community)" \
        bash -c "$mysql_cmd -u root -e 'SHOW PLUGINS;' 2>/dev/null | grep -qiE 'audit|audit_log' && echo 'audit plugin installed' && return 0 || echo 'no audit plugin' && return 2"
}

# ── PostgreSQL audit ──────────────────────────────────────────
audit_postgres() {
    echo ""
    echo "━━━ PostgreSQL CIS Benchmark ━━━"

    local psql_cmd="psql"
    local psql_args="-U postgres -t -A"

    echo -e "  ${C_INFO}── Authentication and access control ──${C_RST}"

    run_check "PG-1.1" "Ensure superuser has password set" \
        bash -c "$psql_cmd $psql_args -c \"SELECT COUNT(*) FROM pg_shadow WHERE passwd IS NULL AND usesuper='t';\" 2>/dev/null | grep -q '^0$' && echo 'all superusers have passwords' && return 0 || echo 'superuser with empty password' && return 1"

    run_check "PG-1.2" "Ensure no public schema grants" \
        bash -c "count=\$($psql_cmd $psql_args -c \"SELECT COUNT(*) FROM information_schema.table_privileges WHERE grantee='PUBLIC';\" 2>/dev/null || echo 999); echo \"\$count PUBLIC grants\"; [ \"\$count\" -eq 0 ] && return 0 || return 2"

    run_check "PG-1.3" "Ensure pg_hba.conf uses scram-sha-256" \
        bash -c "conf=\$(find /etc/postgresql /var/lib/postgresql -name pg_hba.conf 2>/dev/null | head -1); [ -n \"\$conf\" ] && grep -v '^#' \"\$conf\" | grep -v '^\s*\$' | grep -q 'scram-sha-256' && echo 'scram-sha-256 found' && return 0 || echo 'scram-sha-256 not found' && return 2"

    run_check "PG-1.4" "Ensure md5 authentication is not used" \
        bash -c "conf=\$(find /etc/postgresql /var/lib/postgresql -name pg_hba.conf 2>/dev/null | head -1); [ -n \"\$conf\" ] && grep -v '^#' \"\$conf\" | grep -v '^\s*\$' | grep -q 'md5' && echo 'md5 found (deprecated)' && return 1 || echo 'no md5 auth' && return 0"

    echo -e "  ${C_INFO}── Network and connectivity ──${C_RST}"

    run_check "PG-2.1" "Ensure listen_addresses is not '*'" \
        bash -c "val=\$($psql_cmd $psql_args -c 'SHOW listen_addresses;' 2>/dev/null || echo '*'); echo \"listen_addresses=\$val\"; [ \"\$val\" != \"*\" ] && return 0 || return 1"

    run_check "PG-2.2" "Ensure SSL is enabled" \
        bash -c "val=\$($psql_cmd $psql_args -c 'SHOW ssl;' 2>/dev/null || echo 'off'); [ \"\$val\" = \"on\" ] && echo 'SSL enabled' && return 0 || echo 'SSL disabled' && return 1"

    run_check "PG-2.3" "Ensure password_encryption is scram-sha-256" \
        bash -c "val=\$($psql_cmd $psql_args -c 'SHOW password_encryption;' 2>/dev/null || echo 'md5'); [ \"\$val\" = \"scram-sha-256\" ] && echo 'scram-sha-256' && return 0 || echo \"password_encryption=\$val\" && return 1"

    echo -e "  ${C_INFO}── Data and logs ──${C_RST}"

    run_check "PG-3.1" "Ensure logging_collector is enabled" \
        bash -c "val=\$($psql_cmd $psql_args -c 'SHOW logging_collector;' 2>/dev/null || echo 'off'); [ \"\$val\" = \"on\" ] && echo 'logging_collector on' && return 0 || echo 'logging_collector off' && return 1"

    run_check "PG-3.2" "Ensure log_connections is enabled" \
        bash -c "val=\$($psql_cmd $psql_args -c 'SHOW log_connections;' 2>/dev/null || echo 'off'); [ \"\$val\" = \"on\" ] && echo 'log_connections on' && return 0 || echo 'log_connections off' && return 2"

    run_check "PG-3.3" "Ensure log_disconnections is enabled" \
        bash -c "val=\$($psql_cmd $psql_args -c 'SHOW log_disconnections;' 2>/dev/null || echo 'off'); [ \"\$val\" = \"on\" ] && echo 'log_disconnections on' && return 0 || echo 'log_disconnections off' && return 2"

    run_check "PG-3.4" "Ensure log_line_prefix includes timestamp and user" \
        bash -c "val=\$($psql_cmd $psql_args -c 'SHOW log_line_prefix;' 2>/dev/null || echo ''); echo \"\$val\" | grep -q '%m' && echo \"\$val\" | grep -q '%u' && echo 'prefix includes timestamp+user' && return 0 || echo 'prefix missing timestamp or user' && return 2"
}

# ── Redis audit ───────────────────────────────────────────────
audit_redis() {
    echo ""
    echo "━━━ Redis CIS Benchmark ━━━"

    local redis_cmd="redis-cli"

    echo -e "  ${C_INFO}── Authentication and access control ──${C_RST}"

    run_check "REDIS-1.1" "Ensure requirepass is set" \
        bash -c "$redis_cmd CONFIG GET requirepass 2>/dev/null | tail -1 | grep -q . && echo 'requirepass set' && return 0 || echo 'no password set' && return 1"

    run_check "REDIS-1.2" "Ensure ACL is configured (Redis 6+)" \
        bash -c "$redis_cmd ACL LIST 2>/dev/null | grep -v 'user default' | grep -q . && echo 'ACL users configured' && return 0 || echo 'no custom ACL users' && return 2"

    echo -e "  ${C_INFO}── Network and connectivity ──${C_RST}"

    run_check "REDIS-2.1" "Ensure bind is not 0.0.0.0" \
        bash -c "val=$($redis_cmd CONFIG GET bind 2>/dev/null | tail -1 || echo '0.0.0.0'); echo \"bind=\$val\"; [ \"\$val\" != \"0.0.0.0\" ] && [ \"\$val\" != \"\" ] && return 0 || return 1"

    run_check "REDIS-2.2" "Ensure protected-mode is enabled" \
        bash -c "val=$($redis_cmd CONFIG GET protected-mode 2>/dev/null | tail -1 || echo 'no'); [ \"\$val\" = \"yes\" ] && echo 'protected-mode on' && return 0 || echo 'protected-mode off' && return 1"

    run_check "REDIS-2.3" "Ensure port is not default 6379 (or bound to localhost)" \
        bash -c "port=$($redis_cmd CONFIG GET port 2>/dev/null | tail -1 || echo 6379); bind=$($redis_cmd CONFIG GET bind 2>/dev/null | tail -1 || echo ''); [ \"\$port\" != \"6379\" ] && echo \"port=\$port\" && return 0 || echo \"\$bind\" | grep -q '127.0.0.1' && echo 'bound to localhost' && return 0 || echo 'default port on public interface' && return 2"

    run_check "REDIS-2.4" "Ensure TLS is enabled" \
        bash -c "$redis_cmd CONFIG GET tls-port 2>/dev/null | tail -1 | grep -qv '^0$' && echo 'TLS port set' && return 0 || echo 'TLS not configured' && return 2"

    echo -e "  ${C_INFO}── Data and security ──${C_RST}"

    run_check "REDIS-3.1" "Ensure rename-command is used for dangerous commands" \
        bash -c "conf=\$(find /etc/redis /var/lib/redis -name 'redis.conf' 2>/dev/null | head -1); [ -n \"\$conf\" ] && grep -q 'rename-command' \"\$conf\" && echo 'rename-command configured' && return 0 || echo 'no rename-command' && return 2"

    run_check "REDIS-3.2" "Ensure maxmemory is set" \
        bash -c "val=$($redis_cmd CONFIG GET maxmemory 2>/dev/null | tail -1 || echo 0); [ \"\$val\" != \"0\" ] && echo \"maxmemory=\$val\" && return 0 || echo 'maxmemory not set' && return 2"

    run_check "REDIS-3.3" "Ensure maxmemory-policy is set" \
        bash -c "val=$($redis_cmd CONFIG GET maxmemory-policy 2>/dev/null | tail -1 || echo 'noeviction'); [ \"\$val\" != \"noeviction\" ] && echo \"policy=\$val\" && return 0 || echo 'policy=noeviction (default)' && return 2"
}

# ── MongoDB audit ─────────────────────────────────────────────
audit_mongodb() {
    echo ""
    echo "━━━ MongoDB CIS Benchmark ━━━"

    local mongo_cmd
    if command -v mongosh >/dev/null 2>&1; then
        mongo_cmd="mongosh"
    else
        mongo_cmd="mongo"
    fi

    echo -e "  ${C_INFO}── Authentication and access control ──${C_RST}"

    run_check "MONGO-1.1" "Ensure authentication is enabled" \
        bash -c "$mongo_cmd --quiet --eval 'db.runCommand({connectionStatus:1})' 2>/dev/null | grep -q 'authVersion' && echo 'auth may be enabled' && return 0 || echo 'auth status unclear' && return 2"

    run_check "MONGO-1.2" "Ensure no users with unnecessary roles" \
        bash -c "$mongo_cmd --quiet --eval 'db.getSiblingDB(\"admin\").system.users.find({}).toArray()' 2>/dev/null | grep -q . && echo 'users exist (check roles manually)' && return 2 || echo 'no users or cannot query' && return 2"

    echo -e "  ${C_INFO}── Network and connectivity ──${C_RST}"

    run_check "MONGO-2.1" "Ensure bindIp is not 0.0.0.0" \
        bash -c "val=$($mongo_cmd --quiet --eval 'db.serverStatus().host' 2>/dev/null || echo 'unknown'); conf=\$(find /etc/mongod* -name '*.conf' 2>/dev/null | head -1); [ -n \"\$conf\" ] && grep -A5 'net:' \"\$conf\" | grep 'bindIp' | grep -q '0.0.0.0' && echo 'bindIp includes 0.0.0.0' && return 1 || echo 'bindIp restricted' && return 0"

    run_check "MONGO-2.2" "Ensure TLS is enabled" \
        bash -c "conf=\$(find /etc/mongod* -name '*.conf' 2>/dev/null | head -1); [ -n \"\$conf\" ] && grep -A10 'net:' \"\$conf\" | grep -q 'tls' && echo 'TLS configured' && return 0 || echo 'TLS not configured' && return 2"

    run_check "MONGO-2.3" "Ensure port is not default 27017 (or bound to localhost)" \
        bash -c "conf=\$(find /etc/mongod* -name '*.conf' 2>/dev/null | head -1); [ -n \"\$conf\" ] && port=\$(grep -A5 'net:' \"\$conf\" | grep 'port' | awk '{print \$2}' || echo 27017); [ \"\$port\" != \"27017\" ] && echo \"port=\$port\" && return 0 || echo 'default port (check bindIp)' && return 2"

    echo -e "  ${C_INFO}── Data and audit ──${C_RST}"

    run_check "MONGO-3.1" "Ensure auditLog is configured" \
        bash -c "conf=\$(find /etc/mongod* -name '*.conf' 2>/dev/null | head -1); [ -n \"\$conf\" ] && grep -q 'auditLog' \"\$conf\" && echo 'auditLog configured' && return 0 || echo 'no auditLog' && return 2"

    run_check "MONGO-3.2" "Ensure authorization is enabled" \
        bash -c "conf=\$(find /etc/mongod* -name '*.conf' 2>/dev/null | head -1); [ -n \"\$conf\" ] && grep -A5 'security:' \"\$conf\" | grep 'authorization' | grep -q 'enabled' && echo 'authorization enabled' && return 0 || echo 'authorization not enabled' && return 1"

    run_check "MONGO-3.3" "Ensure journaling is enabled" \
        bash -c "$mongo_cmd --quiet --eval 'db.serverStatus().dur' 2>/dev/null | grep -q . && echo 'journaling active' && return 0 || echo 'journaling status unclear' && return 2"
}

# ── Config generation ─────────────────────────────────────────────────
generate_mysql_config() {
    echo -e "${C_WARN}>>> Generate MySQL hardening config <<<${C_RST}"
    mkdir -p "$OUTPUT_DIR/mysql"
    cat > "$OUTPUT_DIR/mysql/hardened-mysqld.cnf" <<'EOF'
# MySQL/MariaDB Hardened Configuration
# Generated by database_hardening.sh
# Reference: CIS MySQL Database Benchmark v2.0

[mysqld]
# ── Network ──
bind-address = 127.0.0.1
# For remote access, use specific IP:
# bind-address = 192.168.1.100

# ── Authentication ──
# Install validate_password plugin:
# INSTALL PLUGIN validate_password SONAME 'validate_password.so';
# validate_password_length = 14
# validate_password_mixed_case_count = 1
# validate_password_number_count = 1
# validate_password_special_char_count = 1
# validate_password_policy = MEDIUM

# ── SSL/TLS ──
# require_secure_transport = ON
# ssl-ca = /etc/mysql/ssl/ca.pem
# ssl-cert = /etc/mysql/ssl/server-cert.pem
# ssl-key = /etc/mysql/ssl/server-key.pem

# ── Logging ──
log_error = /var/log/mysql/error.log
# general_log = OFF (default, enable only for debugging)
# general_log_file = /var/log/mysql/general.log
log_bin = /var/log/mysql/mysql-bin.log
binlog_format = ROW
binlog_expire_logs_seconds = 604800

# ── Audit (MySQL Enterprise or community audit plugin) ──
# plugin-load = audit_log.so
# audit_log_format = JSON
# audit_log_policy = ALL

# ── Security ──
local_infile = OFF
skip_show_database = ON
# secure_file_priv = /var/lib/mysql-files

# ── Performance (safe defaults) ──
max_connections = 100
wait_timeout = 600
interactive_timeout = 600
EOF

    cat > "$OUTPUT_DIR/mysql/README.md" <<'EOF'
# MySQL/MariaDB Hardening Configuration

## Usage
1. Backup current config: `cp /etc/mysql/my.cnf /etc/mysql/my.cnf.bak`
2. Copy hardened config: `cp hardened-mysqld.cnf /etc/mysql/conf.d/`
3. Restart MySQL: `systemctl restart mysql` (or `mariadb`)
4. Verify: `mysql -u root -p -e "SHOW VARIABLES LIKE 'bind_address';"`

## Key Changes
- bind-address restricted to 127.0.0.1 (change if remote access needed)
- local_infile disabled (prevents file reading via SQL)
- skip_show_database enabled (hides DB list from non-privileged users)
- binlog enabled with 7-day retention
- validate_password plugin configuration (uncomment after install)

## Post-Install Steps
1. Install validate_password plugin:
   ```sql
   INSTALL PLUGIN validate_password SONAME 'validate_password.so';
   ```
2. Remove anonymous accounts:
   ```sql
   DELETE FROM mysql.user WHERE user='';
   ```
3. Remove remote root:
   ```sql
   DELETE FROM mysql.user WHERE user='root' AND host NOT IN ('localhost','127.0.0.1','::1');
   ```
4. Enable SSL (generate certificates first)
5. Install audit plugin for compliance
EOF
    echo -e "${C_OK}MySQL config generated to: $OUTPUT_DIR/mysql/${C_RST}"
}

generate_postgres_config() {
    echo -e "${C_WARN}>>> Generate PostgreSQL hardening config <<<${C_RST}"
    mkdir -p "$OUTPUT_DIR/postgresql"
    cat > "$OUTPUT_DIR/postgresql/hardened-postgresql.conf" <<'EOF'
# PostgreSQL Hardened Configuration
# Generated by database_hardening.sh
# Reference: CIS PostgreSQL Benchmark v15.0

# ── Network ──
listen_addresses = 'localhost'
# For remote access: listen_addresses = '192.168.1.100'
port = 5432

# ── Authentication ──
password_encryption = scram-sha-256

# ── SSL/TLS ──
ssl = on
# ssl_ca_file = '/etc/postgresql/ssl/ca.pem'
# ssl_cert_file = '/etc/postgresql/ssl/server-cert.pem'
# ssl_key_file = '/etc/postgresql/ssl/server-key.pem'

# ── Logging ──
logging_collector = on
log_directory = 'log'
log_filename = 'postgresql-%Y-%m-%d.log'
log_rotation_age = 1d
log_rotation_size = 100MB
log_connections = on
log_disconnections = on
log_line_prefix = '%m [%p] %u@%d %h '
log_statement = 'ddl'
log_min_messages = 'warning'

# ── Security ──
shared_preload_libraries = 'pgaudit'
# pgaudit.log = 'write,ddl,role'
# pgaudit.log_parameter = on

# ── Performance (safe defaults) ──
max_connections = 100
shared_buffers = 256MB
effective_cache_size = 1GB
work_mem = 4MB
maintenance_work_mem = 64MB
EOF

    cat > "$OUTPUT_DIR/postgresql/hardened-pg_hba.conf" <<'EOF'
# PostgreSQL Client Authentication (pg_hba.conf)
# Generated by database_hardening.sh

# TYPE  DATABASE  USER  ADDRESS          METHOD
local   all       all                    peer
host    all       all   127.0.0.1/32     scram-sha-256
host    all       all   ::1/128          scram-sha-256
# For remote access (replace with your network):
# host  all       all   192.168.1.0/24   scram-sha-256
# Require SSL for remote:
# hostssl all     all   0.0.0.0/0        scram-sha-256
EOF

    cat > "$OUTPUT_DIR/postgresql/README.md" <<'EOF'
# PostgreSQL Hardening Configuration

## Usage
1. Find config location: `SHOW config_file;` (as postgres user)
2. Backup: `cp postgresql.conf postgresql.conf.bak`
3. Copy hardened config: `cp hardened-postgresql.conf /etc/postgresql/*/main/postgresql.conf`
4. Copy pg_hba: `cp hardened-pg_hba.conf /etc/postgresql/*/main/pg_hba.conf`
5. Restart: `systemctl restart postgresql`

## Key Changes
- listen_addresses restricted to localhost
- password_encryption = scram-sha-256 (not md5)
- SSL enabled
- logging_collector + log_connections + log_disconnections
- pgaudit preload (install pgaudit extension first)
- pg_hba.conf: scram-sha-256 only, no md5, no trust

## Post-Install Steps
1. Install pgaudit:
   ```sql
   CREATE EXTENSION pgaudit;
   ```
2. Update all user passwords to use scram-sha-256:
   ```sql
   ALTER USER username WITH PASSWORD 'newpassword';
   ```
3. Generate SSL certificates if not present
4. Test connection: `psql -U postgres -h localhost`
EOF
    echo -e "${C_OK}PostgreSQL config generated to: $OUTPUT_DIR/postgresql/${C_RST}"
}

generate_redis_config() {
    echo -e "${C_WARN}>>> Generate Redis hardening config <<<${C_RST}"
    mkdir -p "$OUTPUT_DIR/redis"
    cat > "$OUTPUT_DIR/redis/hardened-redis.conf" <<'EOF'
# Redis Hardened Configuration
# Generated by database_hardening.sh
# Reference: CIS Redis Benchmark v1.0

# ── Network ──
bind 127.0.0.1
# For remote access: bind 192.168.1.100
protected-mode yes
port 0
# Use Unix socket instead of TCP:
unixsocket /var/run/redis/redis-server.sock
unixsocketperm 700
# Or non-default port:
# port 6390

# ── TLS ──
# tls-port 6390
# tls-cert-file /etc/redis/ssl/redis.crt
# tls-key-file /etc/redis/ssl/redis.key
# tls-ca-cert-file /etc/redis/ssl/ca.crt
# tls-auth-clients yes

# ── Authentication ──
requirepass CHANGE_ME_TO_STRONG_PASSWORD
# ACL file (Redis 6+):
# aclfile /etc/redis/users.acl

# ── Dangerous command renaming ──
rename-command FLUSHDB ""
rename-command FLUSHALL ""
rename-command KEYS ""
rename-command CONFIG ""
rename-command DEBUG ""
rename-command SHUTDOWN ""

# ── Memory ──
maxmemory 512mb
maxmemory-policy allkeys-lru

# ── Logging ──
logfile /var/log/redis/redis-server.log
loglevel notice

# ── Security ──
# Disable dangerous commands for non-admin users via ACL
EOF

    cat > "$OUTPUT_DIR/redis/README.md" <<'EOF'
# Redis Hardening Configuration

## Usage
1. Backup: `cp /etc/redis/redis.conf /etc/redis/redis.conf.bak`
2. Copy: `cp hardened-redis.conf /etc/redis/redis.conf`
3. Set password: edit `requirepass` line
4. Restart: `systemctl restart redis`

## Key Changes
- bind restricted to 127.0.0.1
- protected-mode enabled
- TCP port disabled, Unix socket used (more secure)
- requirepass set (MUST change the placeholder!)
- Dangerous commands disabled (FLUSHDB, FLUSHALL, KEYS, CONFIG, DEBUG, SHUTDOWN)
- maxmemory + allkeys-lru policy set

## Post-Install Steps
1. Set a strong password (replace CHANGE_ME_TO_STRONG_PASSWORD)
2. If remote access needed:
   - Set bind to specific IP
   - Enable TLS
   - Keep protected-mode yes
3. Configure ACL (Redis 6+) for fine-grained access:
   ```
   # users.acl
   user admin on >strong_password ~* +@all
   user app on >app_password ~app:* +@read +@write -@dangerous
   ```
4. Test: `redis-cli -a yourpassword ping`
EOF
    echo -e "${C_OK}Redis config generated to: $OUTPUT_DIR/redis/${C_RST}"
}

generate_mongodb_config() {
    echo -e "${C_WARN}>>> Generate MongoDB hardening config <<<${C_RST}"
    mkdir -p "$OUTPUT_DIR/mongodb"
    cat > "$OUTPUT_DIR/mongodb/hardened-mongod.conf" <<'EOF'
# MongoDB Hardened Configuration
# Generated by database_hardening.sh
# Reference: CIS MongoDB Benchmark v1.0

# ── Network ──
net:
  port: 27017
  bindIp: 127.0.0.1
  # For remote access: bindIp: 127.0.0.1,192.168.1.100
  tls:
    mode: requireTLS
    certificateKeyFile: /etc/mongodb/ssl/mongodb.pem
    CAFile: /etc/mongodb/ssl/ca.pem

# ── Security ──
security:
  authorization: enabled
  # clusterAuthMode: x509 (for replica sets)

# ── Audit ──
auditLog:
  destination: file
  format: JSON
  path: /var/log/mongodb/audit.log

# ── Storage ──
storage:
  dbPath: /var/lib/mongodb
  journal:
    enabled: true
  wiredTiger:
    engineConfig:
      cacheSizeGB: 1

# ── Logging ──
systemLog:
  destination: file
  path: /var/log/mongodb/mongod.log
  logAppend: true
  logRotate: reopen

# ── Operation ──
operationProfiling:
  mode: slowOp
  slowOpThresholdMs: 100

# ── Set Parameter ──
setParameter:
  enableLocalhostAuthBypass: false
EOF

    cat > "$OUTPUT_DIR/mongodb/README.md" <<'EOF'
# MongoDB Hardening Configuration

## Usage
1. Backup: `cp /etc/mongod.conf /etc/mongod.conf.bak`
2. Copy: `cp hardened-mongod.conf /etc/mongod.conf`
3. Generate TLS certificates (or comment out TLS section)
4. Restart: `systemctl restart mongod`

## Key Changes
- bindIp restricted to 127.0.0.1
- TLS required (generate certificates first)
- authorization enabled (must create admin user first!)
- auditLog to file (JSON format)
- journaling enabled
- localhost auth bypass disabled

## Post-Install Steps
1. Create admin user BEFORE enabling authorization:
   ```js
   use admin
   db.createUser({
     user: "admin",
     pwd: "strong_password",
     roles: [{ role: "root", db: "admin" }]
   })
   ```
2. Generate TLS certificates:
   ```bash
   openssl req -newkey rsa:4096 -nodes -keyout mongodb.key -x509 -out mongodb.crt -days 365
   cat mongodb.key mongodb.crt > mongodb.pem
   ```
3. Create application users with least privilege:
   ```js
   use myapp
   db.createUser({
     user: "appuser",
     pwd: "app_password",
     roles: [{ role: "readWrite", db: "myapp" }]
   })
   ```
4. Test: `mongosh "mongodb://admin:password@localhost:27017/admin?tls=true"`
EOF
    echo -e "${C_OK}MongoDB config generated to: $OUTPUT_DIR/mongodb/${C_RST}"
}

# ── Audit mode ─────────────────────────────────────────────────
audit_all() {
    echo -e "${C_WARN}>>> Database security audit <<<${C_RST}"
    echo -e "${C_INFO}Read-only mode, no database config modified${C_RST}"
    echo ""

    init_report

    if [ -z "$DETECTED_DBS" ]; then
        echo -e "${C_WARN}No database detected${C_RST}"
        echo -e "${C_INFO}Supported: MySQL, PostgreSQL, Redis, MongoDB${C_RST}"
        return 0
    fi

    echo -e "${C_INFO}Detected: $DETECTED_DBS${C_RST}"
    echo ""

    for db in $DETECTED_DBS; do
        case "$db" in
            mysql) [ -z "$SECTION_FILTER" ] || [ "$SECTION_FILTER" = "auth" ] || [ "$SECTION_FILTER" = "network" ] || [ "$SECTION_FILTER" = "logging" ] && audit_mysql ;;
            postgres) [ -z "$SECTION_FILTER" ] || [ "$SECTION_FILTER" = "auth" ] || [ "$SECTION_FILTER" = "network" ] || [ "$SECTION_FILTER" = "logging" ] && audit_postgres ;;
            redis) [ -z "$SECTION_FILTER" ] || [ "$SECTION_FILTER" = "auth" ] || [ "$SECTION_FILTER" = "network" ] || [ "$SECTION_FILTER" = "logging" ] && audit_redis ;;
            mongodb) [ -z "$SECTION_FILTER" ] || [ "$SECTION_FILTER" = "auth" ] || [ "$SECTION_FILTER" = "network" ] || [ "$SECTION_FILTER" = "logging" ] && audit_mongodb ;;
        esac
    done

    # JSON report
    echo "${JSON_RESULTS}]" > "$REPORT_DIR/db-audit-${TIMESTAMP}.json"

    # Summary
    echo ""
    echo -e "${C_INFO}╔══════════════════════════════════════════╗${C_RST}"
    echo -e "${C_INFO}║  Database Security Audit Summary          ║${C_RST}"
    echo -e "${C_INFO}╚══════════════════════════════════════════╝${C_RST}"
    echo -e "${C_INFO}Databases: $DETECTED_DBS${C_RST}"
    echo ""
    printf "  ${C_OK}PASS${C_RST}: %d\n" "$COUNT_PASS"
    printf "  ${C_FAIL}FAIL${C_RST}: %d\n" "$COUNT_FAIL"
    printf "  ${C_WARN}WARN${C_RST}: %d\n" "$COUNT_WARN"
    printf "  ${C_INFO}SKIP${C_RST}: %d\n" "$COUNT_SKIP"
    printf "  Total: %d\n" "$TOTAL_CHECKS"
    echo ""
    echo -e "Report: $REPORT_FILE"
}

# ── Interactive mode ───────────────────────────────────────────────
interactive_mode() {
    echo -e "${C_INFO}╔══════════════════════════════════════════╗${C_RST}"
    echo -e "${C_INFO}║  Database Hardening Wizard                ║${C_RST}"
    echo -e "${C_INFO}║  $APP_NAME $APP_VER                         ║${C_RST}"
    echo -e "${C_INFO}╚══════════════════════════════════════════╝${C_RST}"
    echo ""

    detect_databases
    if [ -n "$DETECTED_DBS" ]; then
        echo -e "${C_INFO}Detected: $DETECTED_DBS${C_RST}"
    else
        echo -e "${C_WARN}No installed database detected${C_RST}"
    fi
    echo ""

    echo -e "${C_INFO}Select action:${C_RST}"
    echo -e "  ${C_WARN}1.${C_RST} Audit all detected databases (read-only)"
    echo -e "  ${C_WARN}2.${C_RST} Generate MySQL hardening config"
    echo -e "  ${C_WARN}3.${C_RST} Generate PostgreSQL hardening config"
    echo -e "  ${C_WARN}4.${C_RST} Generate Redis hardening config"
    echo -e "  ${C_WARN}5.${C_RST} Generate MongoDB hardening config"
    echo -e "  ${C_WARN}0.${C_RST} Exit"
    echo ""
    local pick
    read -r -p "Select [0-5]: " pick
    case $pick in
        1) audit_all ;;
        2) generate_mysql_config ;;
        3) generate_postgres_config ;;
        4) generate_redis_config ;;
        5) generate_mongodb_config ;;
        0) echo "Exit"; exit 0 ;;
        *) echo -e "${C_FAIL}Invalid input${C_RST}"; exit 1 ;;
    esac
}

# ── Main flow ───────────────────────────────────────────────────
main() {
    parse_args "$@"
    detect_databases

    case "$MODE" in
        audit)
            audit_all || true
            ;;
        mysql)
            generate_mysql_config
            ;;
        postgres)
            generate_postgres_config
            ;;
        redis)
            generate_redis_config
            ;;
        mongodb)
            generate_mongodb_config
            ;;
        interactive)
            interactive_mode || true
            ;;
        *)
            echo "Unknown mode: $MODE"; exit 1
            ;;
    esac
    return 0
}

main "$@"
