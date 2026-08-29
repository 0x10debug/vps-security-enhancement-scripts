# Big Data Security (Hadoop/Spark SSL + Security Audit)

> Automated SSL/TLS certificate setup and security configuration auditing for big data platforms — secure your Hadoop, Kafka, HBase, Cassandra, and Spark deployments.

## Overview

Big data platforms (Hadoop, Spark, Kafka, HBase, Cassandra) handle massive volumes of sensitive data but their default configurations often lack encryption, authentication, and audit logging. This chapter covers two tools shipped with this repo:

- **`scripts/bigdata_ssl_setup.sh`** — SSL/TLS certificate generation and platform-specific configuration
- **`scripts/bigdata_security_audit.sh`** — Read-only security audit for Hadoop and Spark

## SSL/TLS Certificate Setup

### What It Generates

| Component | Description |
|---|---|
| CA (Certificate Authority) | Self-signed CA for internal PKI |
| Server certificate | With SAN (Subject Alternative Names) for hostname verification |
| Client certificate | For mutual TLS (mTLS) authentication |
| Java KeyStores | server.keystore.jks, client.keystore.jks |
| Java TrustStores | server.truststore.jks, client.truststore.jks |
| PEM certificates | For non-Java platforms (Cassandra, etc.) |
| Credentials file | All passwords in one file (chmod 600) |

### Platform Configurations

| Platform | Config Files | Key Settings |
|---|---|---|
| Hadoop | core-site.xml, ssl-server.xml, ssl-client.xml | hadoop.ssl.enabled, hadoop.rpc.protection=privacy |
| Kafka | server-ssl.properties, client-ssl.properties | SSL:// listener, ssl.client.auth=required, TLS 1.3 |
| HBase | hbase-site.xml | hbase.rpc.protection=privacy, REST/Thrift SSL |
| Cassandra | cassandra.yaml, cqlshrc | client_encryption_options, internode_encryption=all |

### Usage

```bash
# Interactive wizard
sudo ./scripts/bigdata_ssl_setup.sh

# Generate CA + server + client certificates
sudo ./scripts/bigdata_ssl_setup.sh --generate --domain vps.example.com

# Generate platform-specific SSL config
sudo ./scripts/bigdata_ssl_setup.sh --hadoop
sudo ./scripts/bigdata_ssl_setup.sh --kafka
sudo ./scripts/bigdata_ssl_setup.sh --hbase
sudo ./scripts/bigdata_ssl_setup.sh --cassandra

# Specify output directory
sudo ./scripts/bigdata_ssl_setup.sh --generate --output ./my-ssl-configs
```

### Prerequisites

- `openssl` — for certificate generation
- `keytool` (Java JDK) — for Java KeyStore/TrustStore generation

## Security Audit

### What It Checks

**Hadoop** (12 checks across 4 sections):

| Section | Checks | Key Areas |
|---|---|---|
| Authentication | 3 | Kerberos enabled, authorization enabled, NameNode keytab |
| SSL/TLS | 3 | SSL enabled, RPC privacy, DataNode encryption |
| Permissions | 3 | HDFS permissions, ACLs, YARN queue ACL |
| Audit Logging | 2 | HDFS audit log, YARN audit log |

**Spark** (10 checks across 4 sections):

| Section | Checks | Key Areas |
|---|---|---|
| Authentication | 2 | Kerberos enabled, auth secret |
| SSL/TLS | 3 | SSL enabled, RPC encryption, UI SSL |
| Permissions | 3 | UI ACL, view ACLs, event log ACL |
| Audit Logging | 2 | Event log enabled, event log directory |

### Usage

```bash
# Audit all detected platforms
sudo ./scripts/bigdata_security_audit.sh

# Audit specific platform
sudo ./scripts/bigdata_security_audit.sh --hadoop
sudo ./scripts/bigdata_security_audit.sh --spark

# JSON output for CI/CD
sudo ./scripts/bigdata_security_audit.sh --json
```

### Output

Reports in `/var/log/bigdata-audit/`:
- `bigdata-audit-<timestamp>.txt` — Human-readable
- `bigdata-audit-<timestamp>.json` — Machine-readable

## Common Findings and Fixes

### Hadoop: Kerberos not enabled

**Risk**: No authentication — any user can submit jobs or access HDFS.
**Fix**: Configure Kerberos in core-site.xml:
```xml
<property>
  <name>hadoop.security.authentication</name>
  <value>kerberos</value>
</property>
<property>
  <name>hadoop.security.authorization</name>
  <value>true</value>
</property>
```

### Hadoop: RPC protection not set to privacy

**Risk**: Data in transit can be intercepted.
**Fix**: Set in core-site.xml:
```xml
<property>
  <name>hadoop.rpc.protection</name>
  <value>privacy</value>
</property>
```

### Kafka: SSL not enabled

**Risk**: Unencrypted communication between producers/consumers and brokers.
**Fix**: Configure SSL listener in server.properties:
```properties
listeners=SSL://:9093
ssl.keystore.location=/etc/kafka/ssl/server.keystore.jks
ssl.keystore.password=changeit
ssl.client.auth=required
```

### Spark: Event log not enabled

**Risk**: No audit trail of Spark applications.
**Fix**: Set in spark-defaults.conf:
```properties
spark.eventLog.enabled true
spark.eventLog.dir hdfs://namenode:8020/spark-logs
```

### Cassandra: Client encryption not enabled

**Risk**: Unencrypted client-server communication.
**Fix**: In cassandra.yaml:
```yaml
client_encryption_options:
  enabled: true
  keystore: /etc/cassandra/ssl/server.keystore.jks
  keystore_password: changeit
  require_client_auth: true
```

## Integration with the Main Script

From `secure-vps`, big data security is accessible via:

```
D · 安全运维 → d7 大数据安全 → SSL 证书生成 / 安全审计
```

## Relationship to Other Tools

| Tool | Scope | Type |
|---|---|---|
| This script (SSL setup) | Hadoop/Kafka/HBase/Cassandra SSL | Config generation |
| This script (audit) | Hadoop/Spark security audit | Read-only audit |
| [hadoop-sec-bench](https://github.com/Treydone/hadoop-sec-bench) | Hadoop security benchmarking | Active scanning |
| [BigDataAudit](https://github.com/cys3c/BigDataAudit) | Hadoop security audit | Read-only audit |
| [bigdata-ssl-runbook](https://github.com/thammuio/bigdata-ssl-runbook) | Big data SSL setup guide | Documentation |

## Related Tools in the 0x10debug Suite

| Tool | Repo | Focus |
|---|---|---|
| Big data SSL setup (this script) | vps-security-enhancement-scripts | Certificate generation + platform config |
| Big data security audit (this script) | vps-security-enhancement-scripts | Hadoop/Spark security audit |
| Database hardening | vps-security-enhancement-scripts | MySQL/PG/Redis/MongoDB CIS audit |
| Cloud CIS baseline | vps-security-enhancement-scripts | AWS/GCP/Azure CIS audit |

## References

- [Apache Hadoop Security](https://hadoop.apache.org/docs/current/hadoop-project-dist/hadoop-common/Security.html) — Official docs
- [Apache Kafka Security](https://kafka.apache.org/documentation/#security) — Official docs
- [Apache Spark Security](https://spark.apache.org/docs/latest/security.html) — Official docs
- [Apache HBase Security](https://hbase.apache.org/book.html#security) — Official docs
- [Cassandra Security](https://cassandra.apache.org/doc/latest/operating/security.html) — Official docs
- [CIS Benchmark for Hadoop](https://www.cisecurity.org/benchmark/hadoop) — CIS benchmark
