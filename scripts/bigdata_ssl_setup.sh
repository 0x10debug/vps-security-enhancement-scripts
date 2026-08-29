#!/bin/bash
# ════════════════════════════════════════════════════════════
#  bigdata_ssl_setup.sh — Big Data Platform SSL/TLS Certificate Setup
#  适用系统: Linux 主机 (需 Java keytool + openssl)
#  运行身份: root 或对应服务账号
#  模式: 证书生成 + 配置生成 (不直接修改运行中的服务)
#  参考: thammuio/bigdata-ssl-runbook
#         Apache Hadoop SSL/TLS Documentation
#         Apache Kafka Security Documentation
#  项目主页: https://github.com/0x10debug/vps-security-enhancement-scripts
# ════════════════════════════════════════════════════════════
#
# 用法:
#   sudo ./scripts/bigdata_ssl_setup.sh                    # 交互式向导
#   sudo ./scripts/bigdata_ssl_setup.sh --generate         # 生成 CA + 服务端 + 客户端证书
#   sudo ./scripts/bigdata_ssl_setup.sh --hadoop           # 生成 Hadoop SSL 配置
#   sudo ./scripts/bigdata_ssl_setup.sh --kafka            # 生成 Kafka SSL 配置
#   sudo ./scripts/bigdata_ssl_setup.sh --hbase            # 生成 HBase SSL 配置
#   sudo ./scripts/bigdata_ssl_setup.sh --cassandra        # 生成 Cassandra SSL 配置
#   sudo ./scripts/bigdata_ssl_setup.sh --audit            # 只读审计现有 SSL 配置
#   sudo ./scripts/bigdata_ssl_setup.sh --output ./ssl-configs  # 指定输出目录
#   sudo ./scripts/bigdata_ssl_setup.sh --domain example.com    # 指定域名
#
# 退出码:
#   0 — 成功
#   1 — 参数错误 / 依赖缺失
#   2 — 部分功能不可用

set -euo pipefail

APP_NAME="bigdata_ssl_setup"
APP_VER="v3.0.0"
MODE=""
OUTPUT_DIR=""
DOMAIN=""
REPORT_DIR="/var/log/bigdata-ssl"
TIMESTAMP=$(date +%Y%m%d%H%M%S)

COUNT_PASS=0
COUNT_FAIL=0
COUNT_WARN=0
COUNT_SKIP=0
TOTAL_CHECKS=0

C_FAIL='\033[0;31m'
C_OK='\033[0;32m'
C_WARN='\033[0;33m'
C_INFO='\033[0;34m'
C_RST='\033[0m'

# ── 参数解析 ─────────────────────────────────────────────────
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --generate) MODE="generate"; shift ;;
            --hadoop) MODE="hadoop"; shift ;;
            --kafka) MODE="kafka"; shift ;;
            --hbase) MODE="hbase"; shift ;;
            --cassandra) MODE="cassandra"; shift ;;
            --audit) MODE="audit"; shift ;;
            --output) OUTPUT_DIR="$2"; shift 2 ;;
            --domain) DOMAIN="$2"; shift 2 ;;
            -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
            *) echo "未知参数: $1"; exit 1 ;;
        esac
    done
    if [ -z "$MODE" ]; then
        MODE="interactive"
    fi
    if [ -z "$OUTPUT_DIR" ]; then
        OUTPUT_DIR="./bigdata-ssl-configs"
    fi
    if [ -z "$DOMAIN" ]; then
        DOMAIN="vps.local"
    fi
}

# ── 依赖检查 ─────────────────────────────────────────────────
check_dependencies() {
    local missing=""
    command -v openssl >/dev/null 2>&1 || missing="$missing openssl"
    command -v keytool >/dev/null 2>&1 || missing="$missing keytool"
    if [ -n "$missing" ]; then
        echo -e "${C_FAIL}缺少依赖:$missing${C_RST}"
        echo -e "${C_INFO}请安装: apt install openssl default-jdk (或 yum install openssl java-openjdk)${C_RST}"
        return 1
    fi
    return 0
}

# ── 报告初始化 ───────────────────────────────────────────────
init_report() {
    mkdir -p "$REPORT_DIR" 2>/dev/null || REPORT_DIR="/tmp/bigdata-ssl"
    mkdir -p "$REPORT_DIR" 2>/dev/null || true
    local report="$REPORT_DIR/ssl-audit-${TIMESTAMP}.txt"
    REPORT_FILE="$report"
    {
        echo "Big Data SSL/TLS Audit Report"
        echo "==============================="
        echo "Date: $(date)"
        echo "Host: $(hostname 2>/dev/null || echo 'N/A')"
        echo "Script: $APP_NAME $APP_VER"
        echo ""
    } > "$report"
}

# ── 检查函数 ─────────────────────────────────────────────────
run_check() {
    local id="$1" desc="$2"
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
    printf "  ${color}%-4s${C_RST} %s  %s\n" "$result" "$id" "$desc"

    {
        echo ""
        echo "[$result] $id $desc"
        echo "  Evidence: $evidence"
    } >> "$REPORT_FILE"
}

# ── CA + 证书生成 ────────────────────────────────────────────
generate_certificates() {
    echo -e "${C_WARN}>>> 生成 CA + 服务端 + 客户端证书 <<<${C_RST}"
    echo -e "${C_INFO}输出目录: $OUTPUT_DIR${C_RST}"
    echo -e "${C_INFO}域名: $DOMAIN${C_RST}"
    echo ""

    mkdir -p "$OUTPUT_DIR/ca"
    mkdir -p "$OUTPUT_DIR/server"
    mkdir -p "$OUTPUT_DIR/client"
    mkdir -p "$OUTPUT_DIR/keystores"
    mkdir -p "$OUTPUT_DIR/truststores"

    local ca_key="$OUTPUT_DIR/ca/ca-key.pem"
    local ca_cert="$OUTPUT_DIR/ca/ca-cert.pem"
    local server_key="$OUTPUT_DIR/server/server-key.pem"
    local server_csr="$OUTPUT_DIR/server/server.csr"
    local server_cert="$OUTPUT_DIR/server/server-cert.pem"
    local client_key="$OUTPUT_DIR/client/client-key.pem"
    local client_csr="$OUTPUT_DIR/client/client.csr"
    local client_cert="$OUTPUT_DIR/client/client-cert.pem"
    local server_keystore="$OUTPUT_DIR/keystores/server.keystore.jks"
    local client_keystore="$OUTPUT_DIR/keystores/client.keystore.jks"
    local server_truststore="$OUTPUT_DIR/truststores/server.truststore.jks"
    local client_truststore="$OUTPUT_DIR/truststores/client.truststore.jks"

    local ca_pass="changeit-ca"
    local server_pass="changeit-server"
    local client_pass="changeit-client"
    local store_pass="changeit"

    # ── 1. 生成 CA ──
    echo -e "${C_INFO}[1/8] 生成 CA 私钥和证书...${C_RST}"
    openssl req -new -x509 -keyout "$ca_key" -out "$ca_cert" -days 3650 \
        -subj "/CN=BigData-CA/OU=Security/O=0x10debug/L=VPS/ST=NA/C=US" \
        -passout "pass:$ca_pass" 2>&1 | sed 's/^/  /'

    # ── 2. 生成服务端证书 ──
    echo -e "${C_INFO}[2/8] 生成服务端私钥和 CSR...${C_RST}"
    openssl req -new -newkey rsa:2048 -nodes -keyout "$server_key" -out "$server_csr" \
        -subj "/CN=$DOMAIN/OU=BigData/O=0x10debug/L=VPS/ST=NA/C=US" 2>&1 | sed 's/^/  /'

    echo -e "${C_INFO}[3/8] 用 CA 签发服务端证书 (SAN)...${C_RST}"
    cat > "$OUTPUT_DIR/server-san.cnf" <<EOF
[v3_ext]
subjectAltName = @alt_names
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = $DOMAIN
DNS.2 = localhost
DNS.3 = $(hostname 2>/dev/null || echo 'vps')
IP.1 = 127.0.0.1
EOF
    openssl x509 -req -CA "$ca_cert" -CAkey "$ca_key" -in "$server_csr" -out "$server_cert" \
        -days 3650 -CAcreateserial -passin "pass:$ca_pass" \
        -extfile "$OUTPUT_DIR/server-san.cnf" -extensions v3_ext 2>&1 | sed 's/^/  /'

    # ── 3. 生成客户端证书 ──
    echo -e "${C_INFO}[4/8] 生成客户端私钥和 CSR...${C_RST}"
    openssl req -new -newkey rsa:2048 -nodes -keyout "$client_key" -out "$client_csr" \
        -subj "/CN=bigdata-client/OU=BigData/O=0x10debug/L=VPS/ST=NA/C=US" 2>&1 | sed 's/^/  /'

    echo -e "${C_INFO}[5/8] 用 CA 签发客户端证书...${C_RST}"
    openssl x509 -req -CA "$ca_cert" -CAkey "$ca_key" -in "$client_csr" -out "$client_cert" \
        -days 3650 -CAcreateserial -passin "pass:$ca_pass" 2>&1 | sed 's/^/  /'

    # ── 4. 生成 Java KeyStores ──
    echo -e "${C_INFO}[6/8] 生成服务端 KeyStore...${C_RST}"
    # PKCS12 → JKS
    local server_p12="$OUTPUT_DIR/keystores/server.p12"
    openssl pkcs12 -export -in "$server_cert" -inkey "$server_key" \
        -out "$server_p12" -name "$DOMAIN" \
        -passout "pass:$server_pass" 2>&1 | sed 's/^/  /'
    keytool -importkeystore -srckeystore "$server_p12" -srcstoretype PKCS12 \
        -srcstorepass "$server_pass" -destkeystore "$server_keystore" \
        -deststoretype JKS -deststorepass "$store_pass" 2>&1 | sed 's/^/  /' || true

    echo -e "${C_INFO}[7/8] 生成客户端 KeyStore...${C_RST}"
    local client_p12="$OUTPUT_DIR/keystores/client.p12"
    openssl pkcs12 -export -in "$client_cert" -inkey "$client_key" \
        -out "$client_p12" -name "bigdata-client" \
        -passout "pass:$client_pass" 2>&1 | sed 's/^/  /'
    keytool -importkeystore -srckeystore "$client_p12" -srcstoretype PKCS12 \
        -srcstorepass "$client_pass" -destkeystore "$client_keystore" \
        -deststoretype JKS -deststorepass "$store_pass" 2>&1 | sed 's/^/  /' || true

    echo -e "${C_INFO}[8/8] 生成 TrustStores (CA 导入)...${C_RST}"
    keytool -importcert -alias CARoot -file "$ca_cert" \
        -keystore "$server_truststore" -storepass "$store_pass" \
        -noprompt 2>&1 | sed 's/^/  /' || true
    keytool -importcert -alias CARoot -file "$ca_cert" \
        -keystore "$client_truststore" -storepass "$store_pass" \
        -noprompt 2>&1 | sed 's/^/  /' || true

    # ── 5. 生成密码文件 ──
    cat > "$OUTPUT_DIR/ssl-credentials.env" <<EOF
# Big Data SSL/TLS Credentials
# Generated by $APP_NAME $APP_VER
# WARNING: Store this file securely! These are your SSL private key passwords.

CA_PASSWORD=$ca_pass
SERVER_PASSWORD=$server_pass
CLIENT_PASSWORD=$client_pass
KEYSTORE_PASSWORD=$store_pass
TRUSTSTORE_PASSWORD=$store_pass
CA_CERT=$ca_cert
SERVER_CERT=$server_cert
CLIENT_CERT=$client_cert
DOMAIN=$DOMAIN
EOF
    chmod 600 "$OUTPUT_DIR/ssl-credentials.env"

    # ── 6. 生成 README ──
    cat > "$OUTPUT_DIR/README.md" <<EOF
# Big Data SSL/TLS Certificates

Generated by $APP_NAME $APP_VER on $(date)

## Directory Structure
\`\`\`
bigdata-ssl-configs/
├── ca/
│   ├── ca-cert.pem          # CA 证书 (分发到所有节点)
│   └── ca-key.pem           # CA 私钥 (仅 CA 服务器保留)
├── server/
│   ├── server-cert.pem      # 服务端证书
│   ├── server-key.pem       # 服务端私钥
│   └── server.csr           # CSR (可删除)
├── client/
│   ├── client-cert.pem      # 客户端证书
│   ├── client-key.pem       # 客户端私钥
│   └── client.csr           # CSR (可删除)
├── keystores/
│   ├── server.keystore.jks  # 服务端 KeyStore (Java)
│   └── client.keystore.jks  # 客户端 KeyStore (Java)
├── truststores/
│   ├── server.truststore.jks # 服务端 TrustStore
│   └── client.truststore.jks # 客户端 TrustStore
├── ssl-credentials.env      # 密码文件 (chmod 600!)
└── README.md                # 本文件
\`\`\`

## Deployment Steps
1. Distribute CA certificate to all nodes
2. Distribute server keystore + truststore to server nodes
3. Distribute client keystore + truststore to client nodes
4. Configure each platform (Hadoop/Kafka/HBase/Cassandra) to use these certificates
5. Secure ssl-credentials.env (or better, use a secrets manager)

## Security Notes
- CA private key (ca-key.pem) should be kept offline after initial setup
- All passwords are in ssl-credentials.env — change them for production!
- Certificates are valid for 3650 days (10 years) — adjust if needed
- SAN includes: $DOMAIN, localhost, $(hostname 2>/dev/null || echo 'vps'), 127.0.0.1
EOF

    echo ""
    echo -e "${C_OK}证书生成完成!${C_RST}"
    echo -e "${C_INFO}输出目录: $OUTPUT_DIR${C_RST}"
    echo -e "${C_WARN}密码文件: $OUTPUT_DIR/ssl-credentials.env (chmod 600)${C_RST}"
    echo -e "${C_WARN}请修改默认密码用于生产环境!${C_RST}"
}

# ── Hadoop SSL 配置生成 ──────────────────────────────────────
generate_hadoop_ssl_config() {
    echo -e "${C_WARN}>>> 生成 Hadoop SSL 配置 <<<${C_RST}"
    mkdir -p "$OUTPUT_DIR/hadoop"

    cat > "$OUTPUT_DIR/hadoop/core-site.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<?xml-stylesheet type="text/xsl" href="configuration.xsl"?>
<configuration>
  <!-- 启用 Hadoop RPC 加密 -->
  <property>
    <name>hadoop.rpc.protection</name>
    <value>privacy</value>
  </property>
  <!-- 启用 HTTPS -->
  <property>
    <name>hadoop.ssl.enabled</name>
    <value>true</value>
  </property>
  <!-- 启用 HTTP 传输加密 -->
  <property>
    <name>hadoop.http.transport.algorithm</name>
    <value>tls</value>
  </property>
</configuration>
EOF

    cat > "$OUTPUT_DIR/hadoop/ssl-server.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <property>
    <name>ssl.server.truststore.location</name>
    <value>/etc/hadoop/ssl/server.truststore.jks</value>
  </property>
  <property>
    <name>ssl.server.truststore.password</name>
    <value>changeit</value>
  </property>
  <property>
    <name>ssl.server.truststore.type</name>
    <value>JKS</value>
  </property>
  <property>
    <name>ssl.server.keystore.location</name>
    <value>/etc/hadoop/ssl/server.keystore.jks</value>
  </property>
  <property>
    <name>ssl.server.keystore.password</name>
    <value>changeit</value>
  </property>
  <property>
    <name>ssl.server.keystore.type</name>
    <value>JKS</value>
  </property>
  <property>
    <name>ssl.server.keystore.keypassword</name>
    <value>changeit</value>
  </property>
</configuration>
EOF

    cat > "$OUTPUT_DIR/hadoop/ssl-client.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <property>
    <name>ssl.client.truststore.location</name>
    <value>/etc/hadoop/ssl/client.truststore.jks</value>
  </property>
  <property>
    <name>ssl.client.truststore.password</name>
    <value>changeit</value>
  </property>
  <property>
    <name>ssl.client.truststore.type</name>
    <value>JKS</value>
  </property>
  <property>
    <name>ssl.client.keystore.location</name>
    <value>/etc/hadoop/ssl/client.keystore.jks</value>
  </property>
  <property>
    <name>ssl.client.keystore.password</name>
    <value>changeit</value>
  </property>
  <property>
    <name>ssl.client.keystore.type</name>
    <value>JKS</value>
  </property>
</configuration>
EOF

    cat > "$OUTPUT_DIR/hadoop/README.md" <<'EOF'
# Hadoop SSL/TLS Configuration

## Deployment
1. Copy ssl-server.xml and ssl-client.xml to /etc/hadoop/conf/
2. Copy keystores and truststores to /etc/hadoop/ssl/
3. Update core-site.xml with hadoop.rpc.protection=privacy
4. Restart HDFS and YARN daemons

## Key Configuration
- `hadoop.rpc.protection=privacy` — RPC 加密 + 认证
- `hadoop.ssl.enabled=true` — HTTPS 启用
- ssl-server.xml — 服务端 KeyStore/TrustStore
- ssl-client.xml — 客户端 KeyStore/TrustStore

## Verification
```bash
# 检查 HDFS HTTPS
curl -k https://namenode:50470/jmx
# 检查 YARN HTTPS
curl -k https://resourcemanager:8090/jmx
```
EOF
    echo -e "${C_OK}Hadoop SSL 配置已生成到: $OUTPUT_DIR/hadoop/${C_RST}"
}

# ── Kafka SSL 配置生成 ───────────────────────────────────────
generate_kafka_ssl_config() {
    echo -e "${C_WARN}>>> 生成 Kafka SSL 配置 <<<${C_RST}"
    mkdir -p "$OUTPUT_DIR/kafka"

    cat > "$OUTPUT_DIR/kafka/server-ssl.properties" <<'EOF'
# Kafka Broker SSL Configuration
# Generated by bigdata_ssl_setup.sh

# 监听器配置
listeners=SSL://:9093
advertised.listeners=SSL://vps.local:9093
inter.broker.listener.name=SSL

# SSL 配置
ssl.enabled.protocols=TLSv1.2,TLSv1.3
ssl.protocol=TLSv1.3
ssl.client.auth=required

# KeyStore (服务端)
ssl.keystore.location=/etc/kafka/ssl/server.keystore.jks
ssl.keystore.password=changeit
ssl.key.password=changeit
ssl.keystore.type=JKS

# TrustStore (验证客户端)
ssl.truststore.location=/etc/kafka/ssl/server.truststore.jks
ssl.truststore.password=changeit
ssl.truststore.type=JKS

# 安全提供者
ssl.provider=org.openssl.OpenSSLProvider
ssl.endpoint.identification.algorithm=HTTPS
EOF

    cat > "$OUTPUT_DIR/kafka/client-ssl.properties" <<'EOF'
# Kafka Client SSL Configuration
# Generated by bigdata_ssl_setup.sh

security.protocol=SSL
ssl.enabled.protocols=TLSv1.2,TLSv1.3
ssl.protocol=TLSv1.3

# 客户端 KeyStore
ssl.keystore.location=/etc/kafka/ssl/client.keystore.jks
ssl.keystore.password=changeit
ssl.key.password=changeit
ssl.keystore.type=JKS

# 客户端 TrustStore
ssl.truststore.location=/etc/kafka/ssl/client.truststore.jks
ssl.truststore.password=changeit
ssl.truststore.type=JKS

# 主机名验证
ssl.endpoint.identification.algorithm=HTTPS
EOF

    cat > "$OUTPUT_DIR/kafka/README.md" <<'EOF'
# Kafka SSL/TLS Configuration

## Deployment
1. Copy server-ssl.properties settings to server.properties
2. Copy keystores and truststores to /etc/kafka/ssl/
3. Restart Kafka broker

## Client Configuration
1. Copy client-ssl.properties to client machine
2. Copy client keystore and truststore to /etc/kafka/ssl/
3. Use with kafka-console-producer/consumer:
   ```bash
   kafka-console-producer --bootstrap-server vps.local:9093 \
     --producer.config client-ssl.properties --topic test
   ```

## Key Configuration
- `ssl.client.auth=required` — 双向 TLS
- `ssl.protocol=TLSv1.3` — 强制 TLS 1.3
- `ssl.endpoint.identification.algorithm=HTTPS` — 主机名验证

## Verification
```bash
# 检查 SSL 端口
openssl s_client -connect vps.local:9093 -showcerts
# Kafka ACL with SSL
kafka-acls --bootstrap-server vps.local:9093 \
  --command-config client-ssl.properties --list
```
EOF
    echo -e "${C_OK}Kafka SSL 配置已生成到: $OUTPUT_DIR/kafka/${C_RST}"
}

# ── HBase SSL 配置生成 ───────────────────────────────────────
generate_hbase_ssl_config() {
    echo -e "${C_WARN}>>> 生成 HBase SSL 配置 <<<${C_RST}"
    mkdir -p "$OUTPUT_DIR/hbase"

    cat > "$OUTPUT_DIR/hbase/hbase-site.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <!-- 启用 RPC 加密 -->
  <property>
    <name>hbase.rpc.protection</name>
    <value>privacy</value>
  </property>
  <!-- 启用 HBase REST SSL -->
  <property>
    <name>hbase.rest.ssl.enabled</name>
    <value>true</value>
  </property>
  <!-- KeyStore 配置 -->
  <property>
    <name>hbase.rest.ssl.keystore.store</name>
    <value>/etc/hbase/ssl/server.keystore.jks</value>
  </property>
  <property>
    <name>hbase.rest.ssl.keystore.password</name>
    <value>changeit</value>
  </property>
  <property>
    <name>hbase.rest.ssl.keystore.keypassword</name>
    <value>changeit</value>
  </property>
  <!-- Thrift SSL -->
  <property>
    <name>hbase.thrift.ssl.enabled</name>
    <value>true</value>
  </property>
  <property>
    <name>hbase.thrift.ssl.keystore.store</name>
    <value>/etc/hbase/ssl/server.keystore.jks</value>
  </property>
  <property>
    <name>hbase.thrift.ssl.keystore.password</name>
    <value>changeit</value>
  </property>
</configuration>
EOF

    cat > "$OUTPUT_DIR/hbase/README.md" <<'EOF'
# HBase SSL/TLS Configuration

## Deployment
1. Copy hbase-site.xml settings to /etc/hbase/conf/hbase-site.xml
2. Copy keystores to /etc/hbase/ssl/
3. Restart HBase Master and RegionServer

## Key Configuration
- `hbase.rpc.protection=privacy` — RPC 加密
- `hbase.rest.ssl.enabled=true` — REST API SSL
- `hbase.thrift.ssl.enabled=true` — Thrift SSL

## Verification
```bash
# 检查 HBase REST SSL
curl -k https://hbase-master:8080/
# 检查 HBase Master UI
curl -k https://hbase-master:16010/
```
EOF
    echo -e "${C_OK}HBase SSL 配置已生成到: $OUTPUT_DIR/hbase/${C_RST}"
}

# ── Cassandra SSL 配置生成 ───────────────────────────────────
generate_cassandra_ssl_config() {
    echo -e "${C_WARN}>>> 生成 Cassandra SSL 配置 <<<${C_RST}"
    mkdir -p "$OUTPUT_DIR/cassandra"

    cat > "$OUTPUT_DIR/cassandra/cassandra.yaml" <<'EOF'
# Cassandra SSL/TLS Configuration
# Generated by bigdata_ssl_setup.sh
# Add these settings to your cassandra.yaml

# 启用客户端-服务器加密
client_encryption_options:
  enabled: true
  optional: false
  keystore: /etc/cassandra/ssl/server.keystore.jks
  keystore_password: changeit
  require_client_auth: true
  truststore: /etc/cassandra/ssl/server.truststore.jks
  truststore_password: changeit
  protocol: TLS
  algorithm: SunX509
  store_type: JKS
  cipher_suites: [TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256]

# 启用节点间加密
server_encryption_options:
  internode_encryption: all
  keystore: /etc/cassandra/ssl/server.keystore.jks
  keystore_password: changeit
  truststore: /etc/cassandra/ssl/server.truststore.jks
  truststore_password: changeit
  protocol: TLS
  algorithm: SunX509
  store_type: JKS
  require_client_auth: true
  cipher_suites: [TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256]
EOF

    cat > "$OUTPUT_DIR/cassandra/cqlshrc" <<'EOF'
# cqlsh SSL Configuration
# Place at ~/.cassandra/cqlshrc

[connection]
hostname = vps.local
port = 9042
factory = cqlshlib.ssl.ssl_transport_factory

[ssl]
certfile = /etc/cassandra/ssl/ca-cert.pem
validate = true
userkey = /etc/cassandra/ssl/client-key.pem
usercert = /etc/cassandra/ssl/client-cert.pem
EOF

    cat > "$OUTPUT_DIR/cassandra/README.md" <<'EOF'
# Cassandra SSL/TLS Configuration

## Deployment
1. Add settings from cassandra.yaml to /etc/cassandra/cassandra.yaml
2. Copy keystores and truststores to /etc/cassandra/ssl/
3. Copy CA cert and client certs for cqlsh
4. Restart Cassandra

## Key Configuration
- `client_encryption_options.enabled=true` — 客户端加密
- `server_encryption_options.internode_encryption=all` — 节点间加密
- `require_client_auth=true` — 双向 TLS

## Verification
```bash
# 检查 Cassandra SSL 端口
openssl s_client -connect vps.local:9042 -showcerts
# 使用 cqlsh with SSL
cqlsh vps.local 9042 --ssl
```
EOF
    echo -e "${C_OK}Cassandra SSL 配置已生成到: $OUTPUT_DIR/cassandra/${C_RST}"
}

# ── 审计模式 ─────────────────────────────────────────────────
audit_ssl_config() {
    echo -e "${C_WARN}>>> 大数据平台 SSL/TLS 审计 <<<${C_RST}"
    echo -e "${C_INFO}只读模式, 不修改任何配置${C_RST}"
    echo ""

    init_report

    echo -e "${C_INFO}── 通用 SSL 检查 ──${C_RST}"

    run_check "SSL-1.1" "openssl 已安装" \
        command -v openssl

    run_check "SSL-1.2" "keytool 已安装 (Java)" \
        command -v keytool

    echo ""
    echo -e "${C_INFO}── Hadoop SSL 检查 ──${C_RST}"

    run_check "HADOOP-1.1" "Hadoop SSL 已启用" \
        bash -c "grep -q 'hadoop.ssl.enabled.*true' /etc/hadoop/conf/core-site.xml 2>/dev/null && echo 'SSL enabled' && return 0 || echo 'SSL not enabled or config not found' && return 2"

    run_check "HADOOP-1.2" "Hadoop RPC 加密已启用" \
        bash -c "grep -q 'hadoop.rpc.protection.*privacy' /etc/hadoop/conf/core-site.xml 2>/dev/null && echo 'RPC privacy enabled' && return 0 || echo 'RPC privacy not enabled' && return 2"

    run_check "HADOOP-1.3" "Hadoop ssl-server.xml 存在" \
        bash -c "[ -f /etc/hadoop/conf/ssl-server.xml ] && echo 'exists' && return 0 || echo 'not found' && return 2"

    run_check "HADOOP-1.4" "Hadoop ssl-client.xml 存在" \
        bash -c "[ -f /etc/hadoop/conf/ssl-client.xml ] && echo 'exists' && return 0 || echo 'not found' && return 2"

    echo ""
    echo -e "${C_INFO}── Kafka SSL 检查 ──${C_RST}"

    run_check "KAFKA-1.1" "Kafka SSL 监听器已配置" \
        bash -c "grep -q 'SSL://' /etc/kafka/server.properties 2>/dev/null && echo 'SSL listener configured' && return 0 || echo 'SSL listener not found' && return 2"

    run_check "KAFKA-1.2" "Kafka ssl.client.auth 已配置" \
        bash -c "grep -q 'ssl.client.auth' /etc/kafka/server.properties 2>/dev/null && echo 'client auth configured' && return 0 || echo 'client auth not configured' && return 2"

    run_check "KAFKA-1.3" "Kafka KeyStore 已配置" \
        bash -c "grep -q 'ssl.keystore.location' /etc/kafka/server.properties 2>/dev/null && echo 'keystore configured' && return 0 || echo 'keystore not configured' && return 2"

    run_check "KAFKA-1.4" "Kafka 使用 TLS 1.2+" \
        bash -c "grep -q 'TLSv1.2\|TLSv1.3' /etc/kafka/server.properties 2>/dev/null && echo 'TLS 1.2+ configured' && return 0 || echo 'TLS version not specified' && return 2"

    echo ""
    echo -e "${C_INFO}── HBase SSL 检查 ──${C_RST}"

    run_check "HBASE-1.1" "HBase RPC 加密已启用" \
        bash -c "grep -q 'hbase.rpc.protection.*privacy' /etc/hbase/conf/hbase-site.xml 2>/dev/null && echo 'RPC privacy enabled' && return 0 || echo 'not enabled' && return 2"

    run_check "HBASE-1.2" "HBase REST SSL 已启用" \
        bash -c "grep -q 'hbase.rest.ssl.enabled.*true' /etc/hbase/conf/hbase-site.xml 2>/dev/null && echo 'REST SSL enabled' && return 0 || echo 'not enabled' && return 2"

    echo ""
    echo -e "${C_INFO}── Cassandra SSL 检查 ──${C_RST}"

    run_check "CASS-1.1" "Cassandra 客户端加密已启用" \
        bash -c "grep -q 'client_encryption_options' /etc/cassandra/cassandra.yaml 2>/dev/null && grep -A5 'client_encryption_options' /etc/cassandra/cassandra.yaml 2>/dev/null | grep -q 'enabled: true' && echo 'client encryption enabled' && return 0 || echo 'not enabled' && return 2"

    run_check "CASS-1.2" "Cassandra 节点间加密已启用" \
        bash -c "grep -q 'internode_encryption.*all' /etc/cassandra/cassandra.yaml 2>/dev/null && echo 'internode encryption enabled' && return 0 || echo 'not enabled' && return 2"

    echo ""
    echo -e "${C_INFO}── 证书检查 ──${C_RST}"

    run_check "CERT-1.1" "CA 证书存在" \
        bash -c "find /etc/hadoop/ssl /etc/kafka/ssl /etc/hbase/ssl /etc/cassandra/ssl -name 'ca-cert.pem' -o -name 'ca*.pem' 2>/dev/null | head -1 | grep -q . && echo 'CA cert found' && return 0 || echo 'CA cert not found' && return 2"

    run_check "CERT-1.2" "证书未过期 (检查最近找到的)" \
        bash -c "cert=\$(find /etc/hadoop/ssl /etc/kafka/ssl /etc/hbase/ssl /etc/cassandra/ssl -name '*.pem' 2>/dev/null | head -1); [ -n \"\$cert\" ] && openssl x509 -in \"\$cert\" -noout -checkend 86400 2>/dev/null && echo 'cert valid > 24h' && return 0 || echo 'no valid cert found' && return 2"

    # 摘要
    echo ""
    echo -e "${C_INFO}╔══════════════════════════════════════════╗${C_RST}"
    echo -e "${C_INFO}║  Big Data SSL/TLS Audit Summary            ║${C_RST}"
    echo -e "${C_INFO}╚══════════════════════════════════════════╝${C_RST}"
    echo ""
    printf "  ${C_OK}PASS${C_RST}: %d\n" "$COUNT_PASS"
    printf "  ${C_FAIL}FAIL${C_RST}: %d\n" "$COUNT_FAIL"
    printf "  ${C_WARN}WARN${C_RST}: %d\n" "$COUNT_WARN"
    printf "  ${C_INFO}SKIP${C_RST}: %d\n" "$COUNT_SKIP"
    printf "  Total: %d\n" "$TOTAL_CHECKS"
    echo ""
    echo -e "报告: $REPORT_FILE"
}

# ── 交互式模式 ───────────────────────────────────────────────
interactive_mode() {
    echo -e "${C_INFO}╔══════════════════════════════════════════╗${C_RST}"
    echo -e "${C_INFO}║  Big Data SSL/TLS Setup Wizard             ║${C_RST}"
    echo -e "${C_INFO}║  $APP_NAME $APP_VER                          ║${C_RST}"
    echo -e "${C_INFO}╚══════════════════════════════════════════╝${C_RST}"
    echo ""

    if ! check_dependencies; then
        return 1
    fi

    echo -e "${C_INFO}选择操作:${C_RST}"
    echo -e "  ${C_WARN}1.${C_RST} 生成 CA + 服务端 + 客户端证书"
    echo -e "  ${C_WARN}2.${C_RST} 生成 Hadoop SSL 配置"
    echo -e "  ${C_WARN}3.${C_RST} 生成 Kafka SSL 配置"
    echo -e "  ${C_WARN}4.${C_RST} 生成 HBase SSL 配置"
    echo -e "  ${C_WARN}5.${C_RST} 生成 Cassandra SSL 配置"
    echo -e "  ${C_WARN}6.${C_RST} 审计现有 SSL 配置 (只读)"
    echo -e "  ${C_WARN}0.${C_RST} 退出"
    echo ""
    local pick
    read -r -p "❯ 选择 [0-6]: " pick
    case $pick in
        1) generate_certificates ;;
        2) generate_hadoop_ssl_config ;;
        3) generate_kafka_ssl_config ;;
        4) generate_hbase_ssl_config ;;
        5) generate_cassandra_ssl_config ;;
        6) audit_ssl_config || true ;;
        0) echo "退出"; exit 0 ;;
        *) echo -e "${C_FAIL}无效输入${C_RST}"; exit 1 ;;
    esac
}

# ── 主流程 ───────────────────────────────────────────────────
main() {
    parse_args "$@"

    case "$MODE" in
        generate)
            check_dependencies && generate_certificates
            ;;
        hadoop)
            generate_hadoop_ssl_config
            ;;
        kafka)
            generate_kafka_ssl_config
            ;;
        hbase)
            generate_hbase_ssl_config
            ;;
        cassandra)
            generate_cassandra_ssl_config
            ;;
        audit)
            audit_ssl_config || true
            ;;
        interactive)
            interactive_mode || true
            ;;
        *)
            echo "未知模式: $MODE"; exit 1
            ;;
    esac
    return 0
}

main "$@"
