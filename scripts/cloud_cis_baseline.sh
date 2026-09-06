#!/bin/bash
# ════════════════════════════════════════════════════════════
#  cloud_cis_baseline.sh — Cloud Platform CIS Baseline Audit
#  Supported OS: Any Linux host with cloud CLI access (aws/gcloud/az)
#  Run as: Regular user (requires authenticated cloud CLI)
#  Audit mode: Read-only, no modifications to cloud resources
#  Reference: CIS AWS Foundations Benchmark v3.0
#         CIS Google Cloud Platform Foundation Benchmark v3.0
#         CIS Microsoft Azure Foundations Benchmark v4.0
#         nozaq/terraform-aws-secure-baseline (1198 stars)
#  Project home: https://github.com/0x10debug/vps-security-enhancement-scripts
# ════════════════════════════════════════════════════════════
#
# Usage:
#   ./scripts/cloud_cis_baseline.sh                     # Auto-detect installed cloud CLIs and audit
#   ./scripts/cloud_cis_baseline.sh --provider aws      # Audit only AWS
#   ./scripts/cloud_cis_baseline.sh --provider gcp      # Audit only GCP
#   ./scripts/cloud_cis_baseline.sh --provider azure    # Audit only Azure
#   ./scripts/cloud_cis_baseline.sh --json              # Output JSON report path
#   ./scripts/cloud_cis_baseline.sh --quiet             # Summary only
#   ./scripts/cloud_cis_baseline.sh --section iam       # Audit IAM section only
#   ./scripts/cloud_cis_baseline.sh --section network   # Audit network section only
#   ./scripts/cloud_cis_baseline.sh --section logging   # Audit logging section only
#   ./scripts/cloud_cis_baseline.sh --section encryption # Audit encryption section only
#
# Exit codes:
#   0 — Audit complete
#   1 — Parameter error / No cloud CLI available

set -euo pipefail

APP_NAME="cloud_cis_baseline"
APP_VER="v3.0.0"
PROVIDER_FILTER=""
SECTION_FILTER=""
QUIET=0
JSON_ONLY=0
REPORT_DIR="/var/log/cloud-cis-audit"
REPORT_TXT=""
REPORT_JSON=""
TIMESTAMP=$(date +%Y%m%d%H%M%S)

COUNT_PASS=0
COUNT_FAIL=0
COUNT_WARN=0
COUNT_SKIP=0
TOTAL_CHECKS=0
JSON_RESULTS="["
ACTIVE_PROVIDERS=""

C_FAIL='\033[0;31m'
C_OK='\033[0;32m'
C_WARN='\033[0;33m'
C_INFO='\033[0;34m'
C_RST='\033[0m'

# ── Parameter parsing ─────────────────────────────────────────────────
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --provider) PROVIDER_FILTER="$2"; shift 2 ;;
            --section) SECTION_FILTER="$2"; shift 2 ;;
            --quiet) QUIET=1; shift ;;
            --json) JSON_ONLY=1; shift ;;
            -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
            *) echo "Unknown parameter: $1"; exit 1 ;;
        esac
    done
}

# ── Cloud CLI detection ──────────────────────────────────────────────
detect_providers() {
    ACTIVE_PROVIDERS=""
    if command -v aws >/dev/null 2>&1 && aws sts get-caller-identity >/dev/null 2>&1; then
        ACTIVE_PROVIDERS="$ACTIVE_PROVIDERS aws"
    fi
    if command -v gcloud >/dev/null 2>&1 && gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null | head -1 | grep -q .; then
        ACTIVE_PROVIDERS="$ACTIVE_PROVIDERS gcp"
    fi
    if command -v az >/dev/null 2>&1 && az account show >/dev/null 2>&1; then
        ACTIVE_PROVIDERS="$ACTIVE_PROVIDERS azure"
    fi

    ACTIVE_PROVIDERS=$(echo "$ACTIVE_PROVIDERS" | xargs)

    if [ -z "$ACTIVE_PROVIDERS" ]; then
        echo -e "${C_FAIL}No authenticated cloud CLI detected (aws/gcloud/az)${C_RST}"
        echo -e "${C_INFO}Please install and authenticate at least one cloud CLI${C_RST}"
        echo -e "${C_INFO}  AWS:   aws configure${C_RST}"
        echo -e "${C_INFO}  GCP:   gcloud auth login${C_RST}"
        echo -e "${C_INFO}  Azure: az login${C_RST}"
        exit 1
    fi

    if [ -n "$PROVIDER_FILTER" ]; then
        if ! echo "$ACTIVE_PROVIDERS" | grep -qw "$PROVIDER_FILTER"; then
            echo -e "${C_FAIL}Specified provider $PROVIDER_FILTER not authenticated or not installed${C_RST}"
            exit 1
        fi
        ACTIVE_PROVIDERS="$PROVIDER_FILTER"
    fi
}

# ── Report initialization ───────────────────────────────────────────────
init_report() {
    if ! mkdir -p "$REPORT_DIR" 2>/dev/null; then
        REPORT_DIR="/tmp/cloud-cis-audit"
        mkdir -p "$REPORT_DIR" 2>/dev/null || true
    fi
    REPORT_TXT="$REPORT_DIR/cloud-cis-audit-${TIMESTAMP}.txt"
    REPORT_JSON="$REPORT_DIR/cloud-cis-audit-${TIMESTAMP}.json"
    {
        echo "Cloud Platform CIS Baseline Audit Report"
        echo "=========================================="
        echo "Date: $(date)"
        echo "Host: $(hostname 2>/dev/null || echo 'N/A')"
        echo "Providers: $ACTIVE_PROVIDERS"
        echo "Script: $APP_NAME $APP_VER"
        echo ""
    } > "$REPORT_TXT"
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

    if [ "$QUIET" -eq 0 ]; then
        local color
        case "$result" in
            PASS) color="$C_OK" ;;
            FAIL) color="$C_FAIL" ;;
            WARN) color="$C_WARN" ;;
            SKIP) color="$C_INFO" ;;
        esac
        printf "  ${color}%-4s${C_RST} %s  %s\n" "$result" "$cis_id" "$desc"
    fi

    {
        echo ""
        echo "[$result] $cis_id $desc"
        echo "  Evidence: $evidence"
    } >> "$REPORT_TXT"

    local json_entry
    json_entry=$(printf '{"id":"%s","description":"%s","result":"%s","evidence":"%s"}' \
        "$cis_id" "${desc//\"/\\\"}" "$result" "${evidence//\"/\\\"}")
    if [ "$TOTAL_CHECKS" -gt 1 ]; then
        JSON_RESULTS="$JSON_RESULTS,$json_entry"
    else
        JSON_RESULTS="$JSON_RESULTS$json_entry"
    fi
}

# ── AWS CIS Baseline ─────────────────────────────────────────

aws_iam_section() {
    echo -e "  ${C_INFO}── AWS IAM ──${C_RST}"

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AWS-1.1" "Ensure IAM root user is not used (no access keys)" \
        bash -c 'keys=$(aws iam list-access-keys --user-name root --query "AccessKeyMetadata" --output text 2>/dev/null | wc -l); [ "$keys" -eq 0 ] && echo "root has no access keys" && return 0 || echo "root has $keys access keys" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AWS-1.2" "Ensure MFA is enabled for root account" \
        bash -c 'mfa=$(aws iam list-virtual-mfa-devices --assignment-status Assigned --output text 2>/dev/null | grep -c "root" || true); [ "$mfa" -gt 0 ] && echo "root MFA enabled" && return 0 || echo "root MFA not enabled" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AWS-1.3" "Ensure hardware MFA is enabled for root (if supported)" \
        bash -c 'hw_mfa=$(aws iam list-mfa-devices --user-name root --query "MFADevices" --output text 2>/dev/null | wc -l); [ "$hw_mfa" -gt 0 ] && echo "hardware MFA enabled" && return 0 || echo "no hardware MFA (virtual only)" && return 2'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AWS-1.4" "Ensure no IAM users have inline policies" \
        bash -c 'inline=$(aws iam list-users --query "Users[*].UserName" --output text 2>/dev/null | while read -r u; do aws iam list-user-policies --user-name "$u" --query "PolicyNames" --output text 2>/dev/null; done | wc -l); echo "$inline inline policies"; [ "$inline" -eq 0 ] && return 0 || return 2'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AWS-1.5" "Ensure IAM password policy requires uppercase" \
        bash -c 'pp=$(aws iam get-account-password-policy --query "PasswordPolicy.RequireUppercaseCharacters" --output text 2>/dev/null || echo "false"); [ "$pp" = "true" ] && echo "uppercase required" && return 0 || echo "uppercase not required" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AWS-1.6" "Ensure IAM password policy requires lowercase" \
        bash -c 'pp=$(aws iam get-account-password-policy --query "PasswordPolicy.RequireLowercaseCharacters" --output text 2>/dev/null || echo "false"); [ "$pp" = "true" ] && echo "lowercase required" && return 0 || echo "lowercase not required" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AWS-1.7" "Ensure IAM password policy requires symbols" \
        bash -c 'pp=$(aws iam get-account-password-policy --query "PasswordPolicy.RequireSymbols" --output text 2>/dev/null || echo "false"); [ "$pp" = "true" ] && echo "symbols required" && return 0 || echo "symbols not required" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AWS-1.8" "Ensure IAM password policy requires numbers" \
        bash -c 'pp=$(aws iam get-account-password-policy --query "PasswordPolicy.RequireNumbers" --output text 2>/dev/null || echo "false"); [ "$pp" = "true" ] && echo "numbers required" && return 0 || echo "numbers not required" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AWS-1.9" "Ensure IAM password policy minimum length is 14 or greater" \
        bash -c 'len=$(aws iam get-account-password-policy --query "PasswordPolicy.MinimumPasswordLength" --output text 2>/dev/null || echo 0); [ "$len" -ge 14 ] && echo "min length $len" && return 0 || echo "min length $len (expect >=14)" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AWS-1.10" "Ensure IAM password policy prevents password reuse" \
        bash -c 'reuse=$(aws iam get-account-password-policy --query "PasswordPolicy.PasswordReusePrevention" --output text 2>/dev/null || echo 0); [ "$reuse" -ge 3 ] && echo "reuse prevention $reuse" && return 0 || echo "reuse prevention $reuse (expect >=3)" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AWS-1.11" "Ensure no IAM users have unused access keys (>90 days)" \
        bash -c 'unused=$(aws iam list-access-keys --query "AccessKeyMetadata[*].[UserName,CreateDate]" --output text 2>/dev/null | while read -r user date; do age=$(( ( $(date +%s) - $(date -d "$date" +%s 2>/dev/null || echo 0) ) / 86400 )); [ "$age" -gt 90 ] && echo "$user"; done | wc -l); echo "$unused keys older than 90 days"; [ "$unused" -eq 0 ] && return 0 || return 2'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AWS-1.12" "Ensure MFA is enabled for all IAM users with console access" \
        bash -c 'nomfa=$(aws iam list-users --query "Users[*].UserName" --output text 2>/dev/null | while read -r u; do mfa=$(aws iam list-mfa-devices --user-name "$u" --query "MFADevices" --output text 2>/dev/null | wc -l); has_login=$(aws iam get-login-profile --user-name "$u" --output text 2>/dev/null && echo 1 || echo 0); [ "$has_login" -eq 1 ] && [ "$mfa" -eq 0 ] && echo "$u"; done | wc -l); echo "$nomfa users with console access but no MFA"; [ "$nomfa" -eq 0 ] && return 0 || return 1'
}

aws_network_section() {
    echo -e "  ${C_INFO}── AWS Network ──${C_RST}"

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AWS-2.1" "Ensure no security groups allow 0.0.0.0/0 inbound on port 22" \
        bash -c 'open_ssh=$(aws ec2 describe-security-groups --filters "Name=ip-permission.from-port,Values=22" "Name=ip-permission.cidr,Values=0.0.0.0/0" --query "SecurityGroups[*].GroupName" --output text 2>/dev/null | wc -l); echo "$open_ssh security groups with 0.0.0.0/0 on port 22"; [ "$open_ssh" -eq 0 ] && return 0 || return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AWS-2.2" "Ensure no security groups allow 0.0.0.0/0 inbound on port 3389 (RDP)" \
        bash -c 'open_rdp=$(aws ec2 describe-security-groups --filters "Name=ip-permission.from-port,Values=3389" "Name=ip-permission.cidr,Values=0.0.0.0/0" --query "SecurityGroups[*].GroupName" --output text 2>/dev/null | wc -l); echo "$open_rdp security groups with 0.0.0.0/0 on port 3389"; [ "$open_rdp" -eq 0 ] && return 0 || return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AWS-2.3" "Ensure no security groups allow 0.0.0.0/0 inbound on all ports" \
        bash -c 'open_all=$(aws ec2 describe-security-groups --filters "Name=ip-permission.cidr,Values=0.0.0.0/0" --query "SecurityGroups[?IpPermissions[?FromPort==\`0\` && ToPort==\`65535\`]].GroupName" --output text 2>/dev/null | wc -l); echo "$open_all security groups with 0.0.0.0/0 on all ports"; [ "$open_all" -eq 0 ] && return 0 || return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AWS-2.4" "Ensure VPC flow logging is enabled in all VPCs" \
        bash -c 'vpcs=$(aws ec2 describe-vpcs --query "Vpcs[*].VpcId" --output text 2>/dev/null | wc -w); flow_logs=$(aws ec2 describe-flow-logs --query "FlowLogs[*].ResourceId" --output text 2>/dev/null | sort -u | wc -l); echo "$flow_logs/$vpcs VPCs with flow logs"; [ "$flow_logs" -ge "$vpcs" ] && return 0 || return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AWS-2.5" "Ensure default security group restricts all traffic" \
        bash -c 'default_sg=$(aws ec2 describe-security-groups --filters "Name=group-name,Values=default" --query "SecurityGroups[?IpPermissions==\`[]\` && IpPermissionsEgress==\`[]\`].GroupId" --output text 2>/dev/null | wc -l); echo "$default_sg default SGs with no rules"; [ "$default_sg" -gt 0 ] && return 0 || return 2'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AWS-2.6" "Ensure no network ACLs allow 0.0.0.0/0 inbound" \
        bash -c 'open_nacls=$(aws ec2 describe-network-acls --query "NetworkAcls[*].Entries[?Egress==\`false\` && CidrBlock==\`0.0.0.0/0\`]" --output text 2>/dev/null | wc -l); echo "$open_nacls NACLs with 0.0.0.0/0 inbound"; [ "$open_nacls" -eq 0 ] && return 0 || return 2'
}

aws_logging_section() {
    echo -e "  ${C_INFO}── AWS Logging ──${C_RST}"

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AWS-3.1" "Ensure CloudTrail is enabled in all regions" \
        bash -c 'trails=$(aws cloudtrail describe-trails --query "trailList[?IsMultiRegionTrail==\`true\`].Name" --output text 2>/dev/null | wc -w); echo "$trails multi-region trails"; [ "$trails" -gt 0 ] && return 0 || return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AWS-3.2" "Ensure CloudTrail log file validation is enabled" \
        bash -c 'validation=$(aws cloudtrail describe-trails --query "trailList[?LogFileValidationEnabled==\`true\`].Name" --output text 2>/dev/null | wc -w); echo "$validation trails with log validation"; [ "$validation" -gt 0 ] && return 0 || return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AWS-3.3" "Ensure CloudTrail logs to S3 bucket with server-side encryption" \
        bash -c 'encrypted=$(aws cloudtrail describe-trails --query "trailList[*].S3BucketName" --output text 2>/dev/null | while read -r b; do enc=$(aws s3api get-bucket-encryption --bucket "$b" --query "ServerSideEncryptionConfiguration" --output text 2>/dev/null && echo 1 || echo 0); [ "$enc" -eq 1 ] && echo "$b"; done | wc -l); echo "$encrypted trails with encrypted S3"; [ "$encrypted" -gt 0 ] && return 0 || return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AWS-3.4" "Ensure CloudTrail is integrated with CloudWatch Logs" \
        bash -c 'cw_logs=$(aws cloudtrail describe-trails --query "trailList[?CloudWatchLogsLogGroupArn!=null].Name" --output text 2>/dev/null | wc -w); echo "$cw_logs trails with CloudWatch integration"; [ "$cw_logs" -gt 0 ] && return 0 || return 2'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AWS-3.5" "Ensure AWS Config is enabled in all regions" \
        bash -c 'config_recorders=$(aws configservice describe-configuration-recorders --query "ConfigurationRecorders[?recordingGroup.allSupported==\`true\`].name" --output text 2>/dev/null | wc -w); echo "$config_recorders config recorders (all supported)"; [ "$config_recorders" -gt 0 ] && return 0 || return 2'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AWS-3.6" "Ensure S3 bucket access logging is enabled for CloudTrail buckets" \
        bash -c 'logging=$(aws cloudtrail describe-trails --query "trailList[*].S3BucketName" --output text 2>/dev/null | while read -r b; do log=$(aws s3api get-bucket-logging --bucket "$b" --query "LoggingEnabled" --output text 2>/dev/null || echo "false"); [ "$log" = "True" ] && echo "$b"; done | wc -l); echo "$logging CloudTrail buckets with access logging"; [ "$logging" -gt 0 ] && return 0 || return 2'
}

aws_encryption_section() {
    echo -e "  ${C_INFO}── AWS Encryption ──${C_RST}"

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AWS-4.1" "Ensure all S3 buckets have default encryption (SSE) enabled" \
        bash -c 'buckets=$(aws s3api list-buckets --query "Buckets[*].Name" --output text 2>/dev/null | wc -w); encrypted=$(aws s3api list-buckets --query "Buckets[*].Name" --output text 2>/dev/null | while read -r b; do aws s3api get-bucket-encryption --bucket "$b" --query "ServerSideEncryptionConfiguration" --output text 2>/dev/null && echo "$b"; done | wc -l); echo "$encrypted/$buckets buckets with default encryption"; [ "$encrypted" -ge "$buckets" ] && return 0 || return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AWS-4.2" "Ensure EBS volumes are encrypted" \
        bash -c 'volumes=$(aws ec2 describe-volumes --query "Volumes[*].VolumeId" --output text 2>/dev/null | wc -w); encrypted=$(aws ec2 describe-volumes --query "Volumes[?Encrypted==\`true\`].VolumeId" --output text 2>/dev/null | wc -w); echo "$encrypted/$volumes EBS volumes encrypted"; [ "$encrypted" -ge "$volumes" ] && return 0 || return 2'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AWS-4.3" "Ensure RDS instances have encryption at rest enabled" \
        bash -c 'rds=$(aws rds describe-db-instances --query "DBInstances[*].DBInstanceIdentifier" --output text 2>/dev/null | wc -w); encrypted=$(aws rds describe-db-instances --query "DBInstances[?StorageEncrypted==\`true\`].DBInstanceIdentifier" --output text 2>/dev/null | wc -w); echo "$encrypted/$rds RDS instances encrypted"; [ "$encrypted" -ge "$rds" ] && return 0 || return 2'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AWS-4.4" "Ensure KMS keys have rotation enabled" \
        bash -c 'keys=$(aws kms list-keys --query "Keys[*].KeyId" --output text 2>/dev/null | wc -w); rotated=$(aws kms list-keys --query "Keys[*].KeyId" --output text 2>/dev/null | while read -r k; do aws kms get-key-rotation-status --key-id "$k" --query "KeyRotationEnabled" --output text 2>/dev/null; done | grep -c "True" || true); echo "$rotated/$keys KMS keys with rotation"; [ "$rotated" -ge "$keys" ] && return 0 || return 2'
}

audit_aws() {
    echo ""
    echo "━━━ AWS CIS Foundations Benchmark ━━━"
    local account
    account=$(aws sts get-caller-identity --query "Account" --output text 2>/dev/null || echo "unknown")
    echo -e "${C_INFO}Account: $account${C_RST}"
    echo "AWS Account: $account" >> "$REPORT_TXT"

    case "$SECTION_FILTER" in
        iam) aws_iam_section ;;
        network) aws_network_section ;;
        logging) aws_logging_section ;;
        encryption) aws_encryption_section ;;
        "")
            aws_iam_section
            aws_network_section
            aws_logging_section
            aws_encryption_section
            ;;
        *) echo "Unknown AWS section: $SECTION_FILTER"; return ;;
    esac
}

# ── GCP CIS Baseline ─────────────────────────────────────────

gcp_iam_section() {
    echo -e "  ${C_INFO}── GCP IAM ──${C_RST}"

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "GCP-1.1" "Ensure no service account keys older than 90 days" \
        bash -c 'old_keys=$(gcloud iam service-accounts list --format="value(email)" 2>/dev/null | while read -r sa; do gcloud iam service-accounts keys list --iam-account "$sa" --format="value(keyValidAfterTime)" 2>/dev/null | while read -r d; do age=$(( ( $(date +%s) - $(date -d "$d" +%s 2>/dev/null || echo 9999999999) ) / 86400 )); [ "$age" -gt 90 ] && echo "$sa"; done; done | wc -l); echo "$old_keys service account keys older than 90 days"; [ "$old_keys" -eq 0 ] && return 0 || return 2'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "GCP-1.2" "Ensure no user-managed service account keys exist (use GCP-managed)" \
        bash -c 'user_keys=$(gcloud iam service-accounts list --format="value(email)" 2>/dev/null | while read -r sa; do gcloud iam service-accounts keys list --iam-account "$sa" --key-types=USER_MANAGED --format="value(keyId)" 2>/dev/null; done | wc -l); echo "$user_keys user-managed keys"; [ "$user_keys" -eq 0 ] && return 0 || return 2'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "GCP-1.3" "Ensure 2FA/MFA is enforced for all users" \
        bash -c 'accounts=$(gcloud organizations list --format="value(name)" 2>/dev/null | head -1); [ -n "$accounts" ] && echo "org-level MFA check (requires org admin)" && return 0 || echo "no organization (project-level)" && return 2'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "GCP-1.4" "Ensure no service accounts have Owner role" \
        bash -c 'owners=$(gcloud projects get-iam-policy "$(gcloud config get-value project 2>/dev/null)" --format="value(bindings.role)" --flatten="bindings[].members" 2>/dev/null | grep -c "roles/owner" || true); echo "$owners owner bindings"; [ "$owners" -eq 0 ] && return 0 || return 2'
}

gcp_network_section() {
    echo -e "  ${C_INFO}── GCP Network ──${C_RST}"

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "GCP-2.1" "Ensure no firewall rules allow 0.0.0.0/0 inbound on SSH (port 22)" \
        bash -c 'open_ssh=$(gcloud compute firewall-rules list --format="value(name)" --filter="sourceRanges:0.0.0.0/0 AND allowed[].ports:22" 2>/dev/null | wc -l); echo "$open_ssh firewall rules with 0.0.0.0/0 on port 22"; [ "$open_ssh" -eq 0 ] && return 0 || return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "GCP-2.2" "Ensure no firewall rules allow 0.0.0.0/0 inbound on RDP (port 3389)" \
        bash -c 'open_rdp=$(gcloud compute firewall-rules list --format="value(name)" --filter="sourceRanges:0.0.0.0/0 AND allowed[].ports:3389" 2>/dev/null | wc -l); echo "$open_rdp firewall rules with 0.0.0.0/0 on port 3389"; [ "$open_rdp" -eq 0 ] && return 0 || return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "GCP-2.3" "Ensure no firewall rules allow 0.0.0.0/0 inbound on all ports" \
        bash -c 'open_all=$(gcloud compute firewall-rules list --format="value(name)" --filter="sourceRanges:0.0.0.0/0" 2>/dev/null | while read -r r; do ports=$(gcloud compute firewall-rules describe "$r" --format="value(allowed[].ports)" 2>/dev/null); echo "$ports" | grep -q "0-65535" && echo "$r"; done | wc -l); echo "$open_all firewall rules with 0.0.0.0/0 on all ports"; [ "$open_all" -eq 0 ] && return 0 || return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "GCP-2.4" "Ensure VPC Flow Logs are enabled for all subnets" \
        bash -c 'subnets=$(gcloud compute networks subnets list --format="value(name)" 2>/dev/null | wc -l); flow_logs=$(gcloud compute networks subnets list --format="value(name,enableFlowLogs)" 2>/dev/null | grep -c "True" || true); echo "$flow_logs/$subnets subnets with flow logs"; [ "$flow_logs" -ge "$subnets" ] && return 0 || return 2'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "GCP-2.5" "Ensure default network is not used" \
        bash -c 'default_net=$(gcloud compute networks list --format="value(name)" --filter="name=default" 2>/dev/null | wc -l); echo "$default_net default networks"; [ "$default_net" -eq 0 ] && return 0 || return 2'
}

gcp_logging_section() {
    echo -e "  ${C_INFO}── GCP Logging ──${C_RST}"

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "GCP-3.1" "Ensure Cloud Audit Logs are enabled" \
        bash -c 'sinks=$(gcloud logging sinks list --format="value(name)" 2>/dev/null | wc -l); echo "$sinks logging sinks"; [ "$sinks" -gt 0 ] && return 0 || return 2'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "GCP-3.2" "Ensure audit logging config includes admin read" \
        bash -c 'project=$(gcloud config get-value project 2>/dev/null); audit_config=$(gcloud projects describe "$project" --format="value(parent.policy.auditConfigs)" 2>/dev/null || echo ""); echo "$audit_config" | grep -q "ADMIN_READ" && echo "admin read logged" && return 0 || echo "admin read not logged" && return 2'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "GCP-3.3" "Ensure audit logging config includes data read" \
        bash -c 'project=$(gcloud config get-value project 2>/dev/null); audit_config=$(gcloud projects describe "$project" --format="value(parent.policy.auditConfigs)" 2>/dev/null || echo ""); echo "$audit_config" | grep -q "DATA_READ" && echo "data read logged" && return 0 || echo "data read not logged" && return 2'
}

gcp_encryption_section() {
    echo -e "  ${C_INFO}── GCP Encryption ──${C_RST}"

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "GCP-4.1" "Ensure CMEK is enabled for Compute Engine disks" \
        bash -c 'disks=$(gcloud compute disks list --format="value(name)" 2>/dev/null | wc -l); encrypted=$(gcloud compute disks list --format="value(name,encryption.kind)" 2>/dev/null | grep -c "CMEK" || true); echo "$encrypted/$disks disks with CMEK"; [ "$encrypted" -ge "$disks" ] && return 0 || return 2'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "GCP-4.2" "Ensure Cloud SQL instances have encryption at rest" \
        bash -c 'instances=$(gcloud sql instances list --format="value(name)" 2>/dev/null | wc -l); encrypted=$(gcloud sql instances list --format="value(name,settings.ipConfiguration.requireSsl)" 2>/dev/null | wc -l); echo "$instances Cloud SQL instances"; return 0'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "GCP-4.3" "Ensure GCS buckets have default encryption (CMEK or CSEK)" \
        bash -c 'buckets=$(gsutil ls 2>/dev/null | wc -l); encrypted=$(gsutil ls 2>/dev/null | while read -r b; do gsutil kms encryption -d "$b" 2>/dev/null && echo "$b"; done | wc -l); echo "$encrypted/$buckets buckets with CMEK"; [ "$encrypted" -ge "$buckets" ] && return 0 || return 2'
}

audit_gcp() {
    echo ""
    echo "━━━ GCP CIS Foundation Benchmark ━━━"
    local project
    project=$(gcloud config get-value project 2>/dev/null || echo "unknown")
    echo -e "${C_INFO}Project: $project${C_RST}"
    echo "GCP Project: $project" >> "$REPORT_TXT"

    case "$SECTION_FILTER" in
        iam) gcp_iam_section ;;
        network) gcp_network_section ;;
        logging) gcp_logging_section ;;
        encryption) gcp_encryption_section ;;
        "")
            gcp_iam_section
            gcp_network_section
            gcp_logging_section
            gcp_encryption_section
            ;;
        *) echo "Unknown GCP section: $SECTION_FILTER"; return ;;
    esac
}

# ── Azure CIS Baseline ───────────────────────────────────────

azure_iam_section() {
    echo -e "  ${C_INFO}── Azure IAM ──${C_RST}"

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AZ-1.1" "Ensure MFA is enabled for all privileged users" \
        bash -c 'privileged=$(az ad user list --query "[?assignedRoles[?roleName=='"'"'owner'"'"' || roleName=='"'"'contributor'"'"']].userPrincipalName" --output text 2>/dev/null | wc -w); echo "$privileged privileged users (MFA check requires Graph API)"; return 2'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AZ-1.2" "Ensure no guest user accounts exist" \
        bash -c 'guests=$(az ad user list --query "[?userType=='"'"'Guest'"'"'].userPrincipalName" --output text 2>/dev/null | wc -w); echo "$guests guest users"; [ "$guests" -eq 0 ] && return 0 || return 2'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AZ-1.3" "Ensure there are no custom subscription owner roles" \
        bash -c 'custom_owner=$(az role definition list --custom-role-only true --query "[?roleName.contains(@, '"'"'owner'"'"')].roleName" --output text 2>/dev/null | wc -w); echo "$custom_owner custom owner roles"; [ "$custom_owner" -eq 0 ] && return 0 || return 2'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AZ-1.4" "Ensure Azure AD Password Policy requires minimum 14 characters" \
        bash -c 'policy=$(az ad user list --query "length" --output text 2>/dev/null || echo "N/A"); echo "password policy (requires Graph API for details)"; return 2'
}

azure_network_section() {
    echo -e "  ${C_INFO}── Azure Network ──${C_RST}"

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AZ-2.1" "Ensure no Network Security Group allows 0.0.0.0/0 inbound on SSH (port 22)" \
        bash -c 'open_ssh=$(az network nsg list --query "[].name" --output text 2>/dev/null | while read -r nsg; do az network nsg rule list --nsg-name "$nsg" --query "[?access=='"'"'Allow'"'"' && sourceAddressPrefix=='"'"'*'"'"' && destinationPortRange=='"'"'22'"'"'].name" --output text 2>/dev/null; done | wc -l); echo "$open_ssh NSG rules allowing * on port 22"; [ "$open_ssh" -eq 0 ] && return 0 || return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AZ-2.2" "Ensure no NSG allows 0.0.0.0/0 inbound on RDP (port 3389)" \
        bash -c 'open_rdp=$(az network nsg list --query "[].name" --output text 2>/dev/null | while read -r nsg; do az network nsg rule list --nsg-name "$nsg" --query "[?access=='"'"'Allow'"'"' && sourceAddressPrefix=='"'"'*'"'"' && destinationPortRange=='"'"'3389'"'"'].name" --output text 2>/dev/null; done | wc -l); echo "$open_rdp NSG rules allowing * on port 3389"; [ "$open_rdp" -eq 0 ] && return 0 || return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AZ-2.3" "Ensure Network Watcher is enabled" \
        bash -c 'watchers=$(az network watcher list --query "[].name" --output text 2>/dev/null | wc -w); echo "$watchers network watchers"; [ "$watchers" -gt 0 ] && return 0 || return 2'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AZ-2.4" "Ensure no NSG allows 0.0.0.0/0 inbound on all ports" \
        bash -c 'open_all=$(az network nsg list --query "[].name" --output text 2>/dev/null | while read -r nsg; do az network nsg rule list --nsg-name "$nsg" --query "[?access=='"'"'Allow'"'"' && sourceAddressPrefix=='"'"'*'"'"' && destinationPortRange=='"'"'*'"'"'].name" --output text 2>/dev/null; done | wc -l); echo "$open_all NSG rules allowing * on all ports"; [ "$open_all" -eq 0 ] && return 0 || return 1'
}

azure_logging_section() {
    echo -e "  ${C_INFO}── Azure Logging ──${C_RST}"

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AZ-3.1" "Ensure Activity Log Alert exists for Create/Update Security Rule" \
        bash -c 'alerts=$(az monitor activity-log alert list --query "[?condition.allOf[?equals=='Microsoft.Network/networkSecurityGroups/write']].name" --output text 2>/dev/null | wc -w); echo "$alerts activity log alerts for NSG changes"; [ "$alerts" -gt 0 ] && return 0 || return 2'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AZ-3.2" "Ensure Activity Log Alert exists for Create/Update Network Security Group" \
        bash -c 'alerts=$(az monitor activity-log alert list --query "[?condition.allOf[?equals=='Microsoft.Network/networkSecurityGroups/securityRules/write']].name" --output text 2>/dev/null | wc -w); echo "$alerts activity log alerts for security rule changes"; [ "$alerts" -gt 0 ] && return 0 || return 2'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AZ-3.3" "Ensure Diagnostic Settings are configured for all subscriptions" \
        bash -c 'subs=$(az account list --query "[].id" --output text 2>/dev/null | wc -w); settings=$(az monitor diagnostic-settings subscription list --query "value[].name" --output text 2>/dev/null | wc -w); echo "$settings/$subs subscriptions with diagnostic settings"; [ "$settings" -ge "$subs" ] && return 0 || return 2'
}

azure_encryption_section() {
    echo -e "  ${C_INFO}── Azure Encryption ──${C_RST}"

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AZ-4.1" "Ensure Azure Disk Encryption is enabled for OS and data disks" \
        bash -c 'vms=$(az vm list --query "[].name" --output text 2>/dev/null | wc -w); encrypted=$(az vm list-disk-encryption-status --query "[?diskEncryptionEnabled=='"'"'true'"'"'].name" --output text 2>/dev/null | wc -w || echo 0); echo "$encrypted/$vms VMs with disk encryption"; [ "$encrypted" -ge "$vms" ] && return 0 || return 2'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AZ-4.2" "Ensure Storage Accounts have secure transfer required" \
        bash -c 'accounts=$(az storage account list --query "[].name" --output text 2>/dev/null | wc -w); secure=$(az storage account list --query "[?enableHttpsTrafficOnly=='"'"'true'"'"'].name" --output text 2>/dev/null | wc -w); echo "$secure/$accounts storage accounts with HTTPS only"; [ "$secure" -ge "$accounts" ] && return 0 || return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "AZ-4.3" "Ensure SQL Server TDE (Transparent Data Encryption) is enabled" \
        bash -c 'servers=$(az sql server list --query "[].name" --output text 2>/dev/null | wc -w); tde=$(az sql server list --query "[].name" --output text 2>/dev/null | while read -r s; do az sql db tde show --server "$s" --database master --query "state" --output text 2>/dev/null; done | grep -c "Enabled" || true); echo "$tde/$servers SQL servers with TDE"; [ "$tde" -ge "$servers" ] && return 0 || return 2'
}

audit_azure() {
    echo ""
    echo "━━━ Azure CIS Foundation Benchmark ━━━"
    local sub
    sub=$(az account show --query "name" --output text 2>/dev/null || echo "unknown")
    echo -e "${C_INFO}Subscription: $sub${C_RST}"
    echo "Azure Subscription: $sub" >> "$REPORT_TXT"

    case "$SECTION_FILTER" in
        iam) azure_iam_section ;;
        network) azure_network_section ;;
        logging) azure_logging_section ;;
        encryption) azure_encryption_section ;;
        "")
            azure_iam_section
            azure_network_section
            azure_logging_section
            azure_encryption_section
            ;;
        *) echo "Unknown Azure section: $SECTION_FILTER"; return ;;
    esac
}

# ── JSON report ────────────────────────────────────────────────
write_json_report() {
    echo "${JSON_RESULTS}]" > "$REPORT_JSON"
}

# ── Summary ─────────────────────────────────────────────────────
print_summary() {
    echo ""
    echo -e "${C_INFO}╔══════════════════════════════════════════╗${C_RST}"
    echo -e "${C_INFO}║  Cloud CIS Baseline Audit Summary         ║${C_RST}"
    echo -e "${C_INFO}║  $APP_NAME $APP_VER                         ║${C_RST}"
    echo -e "${C_INFO}╚══════════════════════════════════════════╝${C_RST}"
    echo -e "${C_INFO}Providers: $ACTIVE_PROVIDERS${C_RST}"
    echo ""
    printf "  ${C_OK}PASS${C_RST}: %d\n" "$COUNT_PASS"
    printf "  ${C_FAIL}FAIL${C_RST}: %d\n" "$COUNT_FAIL"
    printf "  ${C_WARN}WARN${C_RST}: %d\n" "$COUNT_WARN"
    printf "  ${C_INFO}SKIP${C_RST}: %d\n" "$COUNT_SKIP"
    printf "  Total: %d\n" "$TOTAL_CHECKS"
    echo ""
    echo -e "Report: $REPORT_TXT"
    if [ "$JSON_ONLY" -eq 1 ]; then
        echo -e "JSON: $REPORT_JSON"
    fi
}

# ── Main flow ───────────────────────────────────────────────────
main() {
    parse_args "$@"
    detect_providers
    init_report

    if [ "$QUIET" -eq 0 ]; then
        echo ""
        echo -e "${C_INFO}╔══════════════════════════════════════════╗${C_RST}"
        echo -e "${C_INFO}║  Cloud Platform CIS Baseline Audit        ║${C_RST}"
        echo -e "${C_INFO}║  $APP_NAME $APP_VER                         ║${C_RST}"
        echo -e "${C_INFO}╚══════════════════════════════════════════╝${C_RST}"
        echo -e "${C_INFO}Providers: $ACTIVE_PROVIDERS${C_RST}"
        echo -e "${C_INFO}Mode: READ-ONLY (no changes)${C_RST}"
        echo ""
    fi

    for p in $ACTIVE_PROVIDERS; do
        case "$p" in
            aws) audit_aws ;;
            gcp) audit_gcp ;;
            azure) audit_azure ;;
        esac
    done

    write_json_report
    print_summary

    if [ "$JSON_ONLY" -eq 1 ]; then
        echo "$REPORT_JSON"
    fi
    return 0
}

main "$@"
