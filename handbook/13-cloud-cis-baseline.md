# Cloud Platform CIS Baseline (AWS/GCP/Azure)

> Automated compliance checking against CIS benchmarks for AWS, GCP, and Azure — secure your cloud infrastructure without reading 600+ pages of benchmark documents.

## Overview

Cloud platforms (AWS, GCP, Azure) provide powerful infrastructure but their default configurations prioritize convenience over security. The **CIS Cloud Platform Foundations Benchmarks** provide vetted, consensus-based configuration guidelines for securing cloud accounts across IAM, networking, logging, and encryption.

This chapter covers the automated cloud CIS baseline audit tool shipped with this repo:

- **`scripts/cloud_cis_baseline.sh`** — Multi-cloud CIS baseline audit (40+ checks per provider)

The tool is **read-only**: it queries your cloud infrastructure via the official CLIs (aws/gcloud/az) but never modifies anything. It auto-detects which cloud providers you're authenticated to and audits all of them in a single run.

## What It Checks

40+ checks per provider across 4 sections, aligned with CIS benchmarks:

| Section | AWS | GCP | Azure |
|---|---|---|---|
| IAM | Root user access keys, MFA, password policy, unused keys, inline policies | Service account key age, user-managed keys, 2FA, owner role | MFA for privileged users, guest accounts, custom owner roles, password policy |
| Network | Security groups (SSH/RDP/all ports open to 0.0.0.0/0), VPC flow logs, default SG, NACLs | Firewall rules (SSH/RDP/all ports), VPC flow logs, default network | NSG rules (SSH/RDP/all ports), Network Watcher |
| Logging | CloudTrail (multi-region, validation, encryption, CloudWatch), AWS Config, S3 access logging | Cloud Audit Logs (admin read, data read), logging sinks | Activity log alerts (NSG changes), diagnostic settings |
| Encryption | S3 default encryption, EBS volume encryption, RDS encryption, KMS key rotation | CMEK for Compute disks, Cloud SQL, GCS buckets | Disk encryption, storage account HTTPS-only, SQL TDE |

## Prerequisites

### AWS
```bash
# Install AWS CLI
pip install awscli  # or brew install awscli

# Authenticate
aws configure
# Enter Access Key ID, Secret Access Key, region, output format
```

### GCP
```bash
# Install Google Cloud CLI
# https://cloud.google.com/sdk/docs/install

# Authenticate
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
```

### Azure
```bash
# Install Azure CLI
brew install azure-cli  # macOS

# Authenticate
az login
```

## Usage

```bash
# Auto-detect authenticated providers and audit all
./scripts/cloud_cis_baseline.sh

# Audit specific provider only
./scripts/cloud_cis_baseline.sh --provider aws
./scripts/cloud_cis_baseline.sh --provider gcp
./scripts/cloud_cis_baseline.sh --provider azure

# Audit specific section only
./scripts/cloud_cis_baseline.sh --section iam
./scripts/cloud_cis_baseline.sh --section network
./scripts/cloud_cis_baseline.sh --section logging
./scripts/cloud_cis_baseline.sh --section encryption

# Combine provider + section
./scripts/cloud_cis_baseline.sh --provider aws --section iam

# Quiet mode (summary only)
./scripts/cloud_cis_baseline.sh --quiet

# JSON output (for CI/CD integration)
./scripts/cloud_cis_baseline.sh --json
```

### Output

Each run produces two reports in `/var/log/cloud-cis-audit/`:

| Report | Format | Use Case |
|---|---|---|
| `cloud-cis-audit-<timestamp>.txt` | Human-readable | Manual review, compliance evidence |
| `cloud-cis-audit-<timestamp>.json` | Machine-readable | CI/CD integration, trend tracking |

### Integration with the Main Script

From `secure-vps`, the cloud CIS baseline audit is accessible via:

```
D · 安全运维 → d2 云安全 → 云平台 CIS 基线审计
```

## Common Findings and Fixes

### AWS: Security group allows 0.0.0.0/0 on port 22

**Risk**: SSH accessible from anywhere — brute force attacks.
**Fix**: Restrict to your IP:
```bash
aws ec2 authorize-security-group-ingress \
  --group-id sg-xxxxxxxx \
  --protocol tcp \
  --port 22 \
  --cidr YOUR.IP.ADDRESS/32
```

### AWS: Root account has access keys

**Risk**: Root keys have unlimited access — if leaked, full account compromise.
**Fix**: Delete root keys and use IAM users/roles instead:
```bash
aws iam delete-access-key \
  --user-name root \
  --access-key-id AKIAIOSFODNN7EXAMPLE
```

### AWS: CloudTrail not enabled

**Risk**: No audit trail of API calls — undetectable intrusions.
**Fix**: Create a multi-region trail:
```bash
aws cloudtrail create-trail \
  --name multi-region-trail \
  --s3-bucket-name your-cloudtrail-bucket \
  --is-multi-region-trail \
  --enable-log-file-validation
```

### GCP: Default network in use

**Risk**: Default network has permissive firewall rules — not suitable for production.
**Fix**: Create a custom VPC and migrate workloads:
```bash
gcloud compute networks create custom-vpc --subnet-mode=custom
```

### Azure: Storage account allows HTTP

**Risk**: Data in transit can be intercepted.
**Fix**: Enable HTTPS-only:
```bash
az storage account update \
  --name mystorageaccount \
  --resource-group myresourcegroup \
  --https-only true
```

## Multi-Cloud Strategy

For organizations using multiple cloud providers:

1. **Run this audit regularly** (weekly or monthly) across all providers
2. **Track trends** using the JSON output — compare pass/fail rates over time
3. **Prioritize fixes** by severity: FAIL (must fix) > WARN (should fix) > SKIP (investigate)
4. **Use Infrastructure as Code** (Terraform/Pulumi) to prevent configuration drift
5. **Integrate with CI/CD** — run `--json` mode in pipelines and fail on new FAILs

## Relationship to Other Tools

| Tool | Scope | Type |
|---|---|---|
| This script | AWS + GCP + Azure CIS baselines | Read-only audit |
| [Prowler](https://github.com/prowler-cloud/prowler) | AWS CIS + 300+ checks | Active scanning |
| [ScoutSuite](https://github.com/nccgroup/ScoutSuite) | Multi-cloud security auditing | Read-only audit |
| [terraform-aws-secure-baseline](https://github.com/nozaq/terraform-aws-secure-baseline) | AWS CIS baseline as Terraform | Infrastructure as Code |
| [Forseti Security](https://github.com/forseti-security/forseti-security) | GCP security posture | Active monitoring |

For production multi-cloud security, consider Prowler (AWS) or ScoutSuite (multi-cloud) for deeper analysis. This script is designed for quick, dependency-free audits from any VPS with cloud CLIs installed.

## Related Tools in the 0x10debug Suite

| Tool | Repo | Focus |
|---|---|---|
| Cloud CIS baseline (this script) | vps-security-enhancement-scripts | Quick multi-cloud CIS check |
| CIS Benchmark audit | vps-security-enhancement-scripts | Host-level CIS (Linux) |
| STIG audit | vps-security-enhancement-scripts | DISA STIG compliance |
| Docker audit | vps-security-enhancement-scripts | CIS Docker Benchmark |
| K8s audit | vps-security-enhancement-scripts | CIS Kubernetes Benchmark |

## References

- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services) — Official benchmark
- [CIS Google Cloud Platform Foundation Benchmark](https://www.cisecurity.org/benchmark/google_cloud_platform) — Official benchmark
- [CIS Microsoft Azure Foundations Benchmark](https://www.cisecurity.org/benchmark/azure) — Official benchmark
- [AWS Security Best Practices](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/) — AWS Well-Architected
- [GCP Security Best Practices](https://cloud.google.com/security/best-practices) — Google Cloud
- [Azure Security Best Practices](https://docs.microsoft.com/en-us/azure/security/fundamentals/best-practices) — Microsoft
