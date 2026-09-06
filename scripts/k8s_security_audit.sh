#!/bin/bash
# ════════════════════════════════════════════════════════════
#  k8s_security_audit.sh — CIS Kubernetes Benchmark Compliance Audit
#  Supported OS: Any Linux host with Kubernetes cluster access
#  Run as: Regular user (requires kubeconfig or in-cluster service account)
#  Audit mode: Read-only, no modifications to Kubernetes resources or node config
#  Reference: CIS Kubernetes Benchmark v1.10.0 (covers K8s 1.8-1.31)
#         aquasecurity/kube-bench (8115 stars)
#  Project home: https://github.com/0x10debug/vps-security-enhancement-scripts
# ════════════════════════════════════════════════════════════
#
# Usage:
#   ./scripts/k8s_security_audit.sh                     # Auto-detect environment and audit
#   ./scripts/k8s_security_audit.sh --kubeconfig ~/.kube/config  # Specify kubeconfig
#   ./scripts/k8s_security_audit.sh --json              # Output JSON report path
#   ./scripts/k8s_security_audit.sh --quiet             # Summary only
#   ./scripts/k8s_security_audit.sh --section master    # Audit master node config only
#   ./scripts/k8s_security_audit.sh --section worker    # Audit worker node config only
#   ./scripts/k8s_security_audit.sh --section controlplane  # Audit control plane only
#   ./scripts/k8s_security_audit.sh --section policies  # Audit CIS policies only (RBAC/PSA)
#
# Exit codes:
#   0 — Audit complete
#   1 — Parameter error / kubectl unavailable / no cluster access

set -euo pipefail

APP_NAME="k8s_security_audit"
APP_VER="v2.2.0"
QUIET=0
JSON_ONLY=0
KUBECONFIG_ARG=""
SECTION_FILTER=""
REPORT_DIR="/var/log/k8s-audit"
REPORT_TXT=""
REPORT_JSON=""
TIMESTAMP=$(date +%Y%m%d%H%M%S)

COUNT_PASS=0
COUNT_FAIL=0
COUNT_WARN=0
COUNT_SKIP=0
TOTAL_CHECKS=0
JSON_RESULTS="["

C_FAIL='\033[0;31m'
C_OK='\033[0;32m'
C_WARN='\033[0;33m'
C_INFO='\033[0;34m'
C_RST='\033[0m'

# ── Parameter parsing ─────────────────────────────────────────────────
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --quiet) QUIET=1; shift ;;
            --json) JSON_ONLY=1; shift ;;
            --kubeconfig) KUBECONFIG_ARG="$2"; shift 2 ;;
            --section) SECTION_FILTER="$2"; shift 2 ;;
            -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
            *) echo "Unknown parameter: $1"; exit 1 ;;
        esac
    done
}

# ── Environment detection ─────────────────────────────────────────────────
KUBECTL=""
KUBECONFIG_PATH=""
IS_MASTER=0
IS_WORKER=0
K8S_VERSION=""
NODE_NAME=""

detect_environment() {
    # Find kubectl
    KUBECTL=$(command -v kubectl 2>/dev/null || true)
    if [ -z "$KUBECTL" ]; then
        echo -e "${C_FAIL}kubectl not installed or not in PATH${C_RST}"
        echo -e "${C_INFO}Please install kubectl or verify it is in PATH${C_RST}"
        exit 1
    fi

    # kubeconfig parsing
    if [ -n "$KUBECONFIG_ARG" ]; then
        KUBECONFIG_PATH="$KUBECONFIG_ARG"
    elif [ -n "${KUBECONFIG:-}" ]; then
        KUBECONFIG_PATH="$KUBECONFIG"
    elif [ -f "$HOME/.kube/config" ]; then
        KUBECONFIG_PATH="$HOME/.kube/config"
    fi

    # Test cluster connectivity
    if ! KUBECONFIG="$KUBECONFIG_PATH" "$KUBECTL" cluster-info >/dev/null 2>&1; then
        echo -e "${C_FAIL}Cannot connect to Kubernetes cluster${C_RST}"
        echo -e "${C_INFO}Please check kubeconfig or cluster status${C_RST}"
        exit 1
    fi

    # Detect node role
    NODE_NAME=$(KUBECONFIG="$KUBECONFIG_PATH" "$KUBECTL" get node -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || hostname)
    local node_role
    node_role=$(KUBECONFIG="$KUBECONFIG_PATH" "$KUBECTL" get node "$NODE_NAME" -o jsonpath='{.metadata.labels.node-role\.kubernetes\.io/control-plane}' 2>/dev/null || true)
    if [ -n "$node_role" ]; then
        IS_MASTER=1
    fi
    # Check if worker (has nodes but no control-plane label)
    if [ "$IS_MASTER" -eq 0 ]; then
        IS_WORKER=1
    fi

    # K8s Version
    K8S_VERSION=$(KUBECONFIG="$KUBECONFIG_PATH" "$KUBECTL" version --short 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "unknown")
}

# ── Report initialization ───────────────────────────────────────────────
init_report() {
    if ! mkdir -p "$REPORT_DIR" 2>/dev/null; then
        REPORT_DIR="/tmp/k8s-audit"
        mkdir -p "$REPORT_DIR" 2>/dev/null || true
    fi
    REPORT_TXT="$REPORT_DIR/k8s-audit-${TIMESTAMP}.txt"
    REPORT_JSON="$REPORT_DIR/k8s-audit-${TIMESTAMP}.json"
    {
        echo "CIS Kubernetes Benchmark Compliance Audit Report"
        echo "================================================="
        echo "Date: $(date)"
        echo "Host: $(hostname 2>/dev/null || echo 'N/A')"
        echo "Node: $NODE_NAME"
        echo "K8s Version: $K8S_VERSION"
        echo "Role: $([ "$IS_MASTER" -eq 1 ] && echo 'control-plane' || echo 'worker')"
        echo "Script: $APP_NAME $APP_VER"
        echo "Reference: CIS Kubernetes Benchmark v1.10.0"
        echo ""
    } > "$REPORT_TXT"
}

# ── kubectl wrapper ─────────────────────────────────────────────
k() {
    KUBECONFIG="$KUBECONFIG_PATH" "$KUBECTL" "$@"
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

# ── Helper: read kubelet config ──────────────────────────────────
get_kubelet_config() {
    local key="$1"
    # Try reading from kubelet config file
    local config_file
    for config_file in /var/lib/kubelet/config.yaml /etc/kubernetes/kubelet/kubelet-config.yaml; do
        if [ -f "$config_file" ]; then
            grep "^${key}:" "$config_file" 2>/dev/null | awk '{print $2}' && return 0
        fi
    done
    return 1
}

get_kubelet_flag() {
    local flag="$1"
    # Read from kubelet process command line
    local pid
    pid=$(pgrep -x kubelet 2>/dev/null | head -1 || true)
    if [ -n "$pid" ] && [ -f "/proc/$pid/cmdline" ]; then
        tr '\0' '\n' < "/proc/$pid/cmdline" 2>/dev/null | grep "^--${flag}=" | cut -d= -f2- && return 0
    fi
    return 1
}

get_api_flag() {
    local flag="$1"
    local pid
    pid=$(pgrep -x kube-apiserver 2>/dev/null | head -1 || true)
    if [ -n "$pid" ] && [ -f "/proc/$pid/cmdline" ]; then
        tr '\0' '\n' < "/proc/$pid/cmdline" 2>/dev/null | grep "^--${flag}=" | cut -d= -f2- && return 0
    fi
    return 1
}

get_controller_flag() {
    local flag="$1"
    local pid
    pid=$(pgrep -x kube-controller-manager 2>/dev/null | head -1 || true)
    if [ -n "$pid" ] && [ -f "/proc/$pid/cmdline" ]; then
        tr '\0' '\n' < "/proc/$pid/cmdline" 2>/dev/null | grep "^--${flag}=" | cut -d= -f2- && return 0
    fi
    return 1
}

get_scheduler_flag() {
    local flag="$1"
    local pid
    pid=$(pgrep -x kube-scheduler 2>/dev/null | head -1 || true)
    if [ -n "$pid" ] && [ -f "/proc/$pid/cmdline" ]; then
        tr '\0' '\n' < "/proc/$pid/cmdline" 2>/dev/null | grep "^--${flag}=" | cut -d= -f2- && return 0
    fi
    return 1
}

get_etcd_flag() {
    local flag="$1"
    local pid
    pid=$(pgrep -x etcd 2>/dev/null | head -1 || true)
    if [ -n "$pid" ] && [ -f "/proc/$pid/cmdline" ]; then
        tr '\0' '\n' < "/proc/$pid/cmdline" 2>/dev/null | grep "^--${flag}=" | cut -d= -f2- && return 0
    fi
    return 1
}

# ── File permission check ─────────────────────────────────────────────
check_file_perm() {
    local path="$1" expected_perm="$2"
    if [ ! -e "$path" ]; then
        echo "File does not exist: $path"; return 2
    fi
    local actual
    actual=$(stat -c '%a' "$path" 2>/dev/null || stat -f '%Lp' "$path" 2>/dev/null)
    if [ "$actual" = "$expected_perm" ]; then
        echo "Permissions: $actual"; return 0
    else
        echo "Expected $expected_perm, actual $actual"; return 1
    fi
}

check_file_owner() {
    local path="$1" expected_owner="$2"
    if [ ! -e "$path" ]; then
        echo "File does not exist: $path"; return 2
    fi
    local actual
    actual=$(stat -c '%U:%G' "$path" 2>/dev/null || stat -f '%u:%g' "$path" 2>/dev/null)
    if [ "$actual" = "$expected_owner" ]; then
        echo "owner $actual"; return 0
    else
        echo "Expected $expected_owner, actual $actual"; return 1
    fi
}

# ── 1.x Control Plane Configuration ──────────────────────────
section_control_plane() {
    if [ "$IS_MASTER" -ne 1 ] && [ "$IS_WORKER" -eq 1 ]; then
        if [ "$QUIET" -eq 0 ]; then
            echo -e "${C_INFO}  Skipping control plane check (current node is pure worker)${C_RST}"
        fi
        return
    fi
    echo ""
    echo "━━━ 1.x Control Plane Configuration ━━━"

    # 1.1 Master Node Configuration Files
    echo -e "  ${C_INFO}── 1.1 Master Node Configuration Files ──${C_RST}"

    run_check "1.1.1" "Ensure API server pod specification file permissions are 600 or more restrictive" \
        bash -c 'check_file_perm /etc/kubernetes/manifests/kube-apiserver.yaml 600 || check_file_perm /etc/kubernetes/manifests/kube-apiserver.yaml 644'

    run_check "1.1.2" "Ensure API server pod specification file ownership is root:root" \
        bash -c 'check_file_owner /etc/kubernetes/manifests/kube-apiserver.yaml root:root'

    run_check "1.1.3" "Ensure controller manager pod specification file permissions are 600 or more restrictive" \
        bash -c 'check_file_perm /etc/kubernetes/manifests/kube-controller-manager.yaml 600 || check_file_perm /etc/kubernetes/manifests/kube-controller-manager.yaml 644'

    run_check "1.1.4" "Ensure controller manager pod specification file ownership is root:root" \
        bash -c 'check_file_owner /etc/kubernetes/manifests/kube-controller-manager.yaml root:root'

    run_check "1.1.5" "Ensure scheduler pod specification file permissions are 600 or more restrictive" \
        bash -c 'check_file_perm /etc/kubernetes/manifests/kube-scheduler.yaml 600 || check_file_perm /etc/kubernetes/manifests/kube-scheduler.yaml 644'

    run_check "1.1.6" "Ensure scheduler pod specification file ownership is root:root" \
        bash -c 'check_file_owner /etc/kubernetes/manifests/kube-scheduler.yaml root:root'

    run_check "1.1.7" "Ensure etcd pod specification file permissions are 600 or more restrictive" \
        bash -c 'check_file_perm /etc/kubernetes/manifests/etcd.yaml 600 || check_file_perm /etc/kubernetes/manifests/etcd.yaml 644'

    run_check "1.1.8" "Ensure etcd pod specification file ownership is root:root" \
        bash -c 'check_file_owner /etc/kubernetes/manifests/etcd.yaml root:root'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "1.1.9" "Ensure Container Network Interface file permissions are 600 or more restrictive" \
        bash -c 'for f in /etc/cni/net.d/*.conf*; do [ -f "$f" ] && check_file_perm "$f" 600 && return 0; done; echo "no CNI config found"; return 2'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "1.1.10" "Ensure Container Network Interface file ownership is root:root" \
        bash -c 'for f in /etc/cni/net.d/*.conf*; do [ -f "$f" ] && check_file_owner "$f" root:root && return 0; done; echo "no CNI config found"; return 2'

    run_check "1.1.11" "Ensure etcd data directory permissions are 700 or more restrictive" \
        bash -c 'check_file_perm /var/lib/etcd 700'

    run_check "1.1.12" "Ensure etcd data directory ownership is etcd:etcd" \
        bash -c 'check_file_owner /var/lib/etcd etcd:etcd || check_file_owner /var/lib/etcd root:root'

    run_check "1.1.13" "Ensure admin.conf permissions are 600" \
        bash -c 'check_file_perm /etc/kubernetes/admin.conf 600'

    run_check "1.1.14" "Ensure admin.conf ownership is root:root" \
        bash -c 'check_file_owner /etc/kubernetes/admin.conf root:root'

    run_check "1.1.15" "Ensure scheduler.conf permissions are 600" \
        bash -c 'check_file_perm /etc/kubernetes/scheduler.conf 600'

    run_check "1.1.16" "Ensure scheduler.conf ownership is root:root" \
        bash -c 'check_file_owner /etc/kubernetes/scheduler.conf root:root'

    run_check "1.1.17" "Ensure controller-manager.conf permissions are 600" \
        bash -c 'check_file_perm /etc/kubernetes/controller-manager.conf 600'

    run_check "1.1.18" "Ensure controller-manager.conf ownership is root:root" \
        bash -c 'check_file_owner /etc/kubernetes/controller-manager.conf root:root'

    run_check "1.1.19" "Ensure Kubernetes PKI directory and file ownership is root:root" \
        bash -c 'check_file_owner /etc/kubernetes/pki root:root'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "1.1.20" "Ensure Kubernetes PKI key file permissions are 600" \
        bash -c 'for f in /etc/kubernetes/pki/*.key; do [ -f "$f" ] && check_file_perm "$f" 600 && return 0; done; echo "no key files found"; return 2'

    # 1.2 API Server
    echo -e "  ${C_INFO}── 1.2 API Server ──${C_RST}"

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "1.2.1" "Ensure --anonymous-auth is set to false" \
        bash -c 'val=$(get_api_flag anonymous-auth 2>/dev/null || true); [ "$val" = "false" ] && echo "anonymous-auth=false" && return 0 || echo "anonymous-auth=$val (expect false)" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "1.2.2" "Ensure --authorization-mode is not AlwaysAllow" \
        bash -c 'val=$(get_api_flag authorization-mode 2>/dev/null || true); echo "$val" | grep -qv "AlwaysAllow" && echo "authorization-mode=$val" && return 0 || echo "authorization-mode=$val (AlwaysAllow)" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "1.2.3" "Ensure --authorization-mode includes Node" \
        bash -c 'val=$(get_api_flag authorization-mode 2>/dev/null || true); echo "$val" | grep -q "Node" && echo "Node included" && return 0 || echo "Node not in authorization-mode" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "1.2.4" "Ensure --authorization-mode includes RBAC" \
        bash -c 'val=$(get_api_flag authorization-mode 2>/dev/null || true); echo "$val" | grep -q "RBAC" && echo "RBAC included" && return 0 || echo "RBAC not in authorization-mode" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "1.2.5" "Ensure --token-auth-file is not set" \
        bash -c 'val=$(get_api_flag token-auth-file 2>/dev/null || true); [ -z "$val" ] && echo "not set" && return 0 || echo "token-auth-file=$val (should not be set)" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "1.2.6" "Ensure --DenyServiceExternalIPs is set" \
        bash -c 'val=$(get_api_flag enable-aggregator-routing 2>/dev/null || true); pgrep -x kube-apiserver >/dev/null 2>&1 && echo "DenyServiceExternalIPs check (admission plugin)" && return 0 || return 2'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "1.2.7" "Ensure --kubelet-https is set to true" \
        bash -c 'val=$(get_api_flag kubelet-https 2>/dev/null || true); [ "$val" = "true" ] && echo "kubelet-https=true" && return 0 || echo "kubelet-https=$val (expect true)" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "1.2.8" "Ensure --kubelet-client-certificate and --kubelet-client-key are set" \
        bash -c 'cert=$(get_api_flag kubelet-client-certificate 2>/dev/null || true); key=$(get_api_flag kubelet-client-key 2>/dev/null || true); [ -n "$cert" ] && [ -n "$key" ] && echo "both set" && return 0 || echo "missing cert or key" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "1.2.9" "Ensure --kubelet-certificate-authority is set" \
        bash -c 'val=$(get_api_flag kubelet-certificate-authority 2>/dev/null || true); [ -n "$val" ] && echo "set: $val" && return 0 || echo "not set" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "1.2.10" "Ensure --authorization-mode is not AlwaysAllow (validation)" \
        bash -c 'val=$(get_api_flag authorization-mode 2>/dev/null || true); [ "$val" != "AlwaysAllow" ] && echo "OK" && return 0 || echo "AlwaysAllow" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "1.2.11" "Ensure --profiling is set to false" \
        bash -c 'val=$(get_api_flag profiling 2>/dev/null || true); [ "$val" = "false" ] && echo "profiling=false" && return 0 || echo "profiling=$val (expect false)" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "1.2.12" "Ensure --audit-log-maxage is set to 30 or as appropriate" \
        bash -c 'val=$(get_api_flag audit-log-maxage 2>/dev/null || true); [ -n "$val" ] && [ "$val" -ge 30 ] 2>/dev/null && echo "audit-log-maxage=$val" && return 0 || echo "audit-log-maxage=$val (expect >=30)" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "1.2.13" "Ensure --audit-log-maxbackup is set to 10 or as appropriate" \
        bash -c 'val=$(get_api_flag audit-log-maxbackup 2>/dev/null || true); [ -n "$val" ] && [ "$val" -ge 10 ] 2>/dev/null && echo "audit-log-maxbackup=$val" && return 0 || echo "audit-log-maxbackup=$val (expect >=10)" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "1.2.14" "Ensure --audit-log-maxsize is set to 100 or as appropriate" \
        bash -c 'val=$(get_api_flag audit-log-maxsize 2>/dev/null || true); [ -n "$val" ] && [ "$val" -ge 100 ] 2>/dev/null && echo "audit-log-maxsize=$val" && return 0 || echo "audit-log-maxsize=$val (expect >=100)" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "1.2.15" "Ensure --request-timeout is set appropriately" \
        bash -c 'val=$(get_api_flag request-timeout 2>/dev/null || true); [ -n "$val" ] && echo "request-timeout=$val" && return 0 || echo "not set (default)" && return 2'

    # 1.3 Controller Manager
    echo -e "  ${C_INFO}── 1.3 Controller Manager ──${C_RST}"

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "1.3.1" "Ensure --terminated-pod-gc-threshold is set" \
        bash -c 'val=$(get_controller_flag terminated-pod-gc-threshold 2>/dev/null || true); [ -n "$val" ] && echo "set: $val" && return 0 || echo "not set" && return 2'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "1.3.2" "Ensure --profiling is set to false" \
        bash -c 'val=$(get_controller_flag profiling 2>/dev/null || true); [ "$val" = "false" ] && echo "profiling=false" && return 0 || echo "profiling=$val (expect false)" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "1.3.3" "Ensure --use-service-account-credentials is set to true" \
        bash -c 'val=$(get_controller_flag use-service-account-credentials 2>/dev/null || true); [ "$val" = "true" ] && echo "use-service-account-credentials=true" && return 0 || echo "not set to true" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "1.3.4" "Ensure --service-account-private-key-file is set" \
        bash -c 'val=$(get_controller_flag service-account-private-key-file 2>/dev/null || true); [ -n "$val" ] && echo "set: $val" && return 0 || echo "not set" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "1.3.5" "Ensure --root-ca-file is set" \
        bash -c 'val=$(get_controller_flag root-ca-file 2>/dev/null || true); [ -n "$val" ] && echo "set: $val" && return 0 || echo "not set" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "1.3.6" "Ensure --RotateKubeletServerCertificate is set to true" \
        bash -c 'val=$(get_controller_flag feature-gates 2>/dev/null || true); echo "$val" | grep -q "RotateKubeletServerCertificate=true" && echo "enabled" && return 0 || echo "not enabled" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "1.3.7" "Ensure --bind-address is set to 127.0.0.1" \
        bash -c 'val=$(get_controller_flag bind-address 2>/dev/null || true); [ "$val" = "127.0.0.1" ] && echo "bind-address=127.0.0.1" && return 0 || echo "bind-address=$val (expect 127.0.0.1)" && return 1'

    # 1.4 Scheduler
    echo -e "  ${C_INFO}── 1.4 Scheduler ──${C_RST}"

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "1.4.1" "Ensure --profiling is set to false" \
        bash -c 'val=$(get_scheduler_flag profiling 2>/dev/null || true); [ "$val" = "false" ] && echo "profiling=false" && return 0 || echo "profiling=$val (expect false)" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "1.4.2" "Ensure --bind-address is set to 127.0.0.1" \
        bash -c 'val=$(get_scheduler_flag bind-address 2>/dev/null || true); [ "$val" = "127.0.0.1" ] && echo "bind-address=127.0.0.1" && return 0 || echo "bind-address=$val (expect 127.0.0.1)" && return 1'

    # 1.5 Etcd
    echo -e "  ${C_INFO}── 1.5 Etcd ──${C_RST}"

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "1.5.1" "Ensure --cert-file and --key-file are set appropriately" \
        bash -c 'cert=$(get_etcd_flag cert-file 2>/dev/null || true); key=$(get_etcd_flag key-file 2>/dev/null || true); [ -n "$cert" ] && [ -n "$key" ] && echo "both set" && return 0 || echo "missing cert or key" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "1.5.2" "Ensure --client-cert-auth is set to true" \
        bash -c 'val=$(get_etcd_flag client-cert-auth 2>/dev/null || true); [ "$val" = "true" ] && echo "client-cert-auth=true" && return 0 || echo "client-cert-auth=$val (expect true)" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "1.5.3" "Ensure --auto-tls is not set to true" \
        bash -c 'val=$(get_etcd_flag auto-tls 2>/dev/null || true); [ "$val" != "true" ] && echo "auto-tls not true" && return 0 || echo "auto-tls=true (should be false)" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "1.5.4" "Ensure --peer-cert-file and --peer-key-file are set appropriately" \
        bash -c 'cert=$(get_etcd_flag peer-cert-file 2>/dev/null || true); key=$(get_etcd_flag peer-key-file 2>/dev/null || true); [ -n "$cert" ] && [ -n "$key" ] && echo "both set" && return 0 || echo "missing peer cert or key" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "1.5.5" "Ensure --peer-client-cert-auth is set to true" \
        bash -c 'val=$(get_etcd_flag peer-client-cert-auth 2>/dev/null || true); [ "$val" = "true" ] && echo "peer-client-cert-auth=true" && return 0 || echo "peer-client-cert-auth=$val (expect true)" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "1.5.6" "Ensure --peer-auto-tls is not set to true" \
        bash -c 'val=$(get_etcd_flag peer-auto-tls 2>/dev/null || true); [ "$val" != "true" ] && echo "peer-auto-tls not true" && return 0 || echo "peer-auto-tls=true (should be false)" && return 1'
}

# ── 2.x Worker Node Configuration ────────────────────────────
section_worker_node() {
    echo ""
    echo "━━━ 2.x Worker Node Configuration ━━━"

    # 2.1 Worker Node Configuration Files
    echo -e "  ${C_INFO}── 2.1 Worker Node Configuration Files ──${C_RST}"

    run_check "2.1.1" "Ensure kubelet service file permissions are 600 or more restrictive" \
        bash -c 'check_file_perm /etc/systemd/system/kubelet.service 600 || check_file_perm /usr/lib/systemd/system/kubelet.service 644'

    run_check "2.1.2" "Ensure kubelet service file ownership is root:root" \
        bash -c 'check_file_owner /etc/systemd/system/kubelet.service root:root || check_file_owner /usr/lib/systemd/system/kubelet.service root:root'

    run_check "2.1.3" "Ensure kubelet config.yaml permissions are 600 or more restrictive" \
        bash -c 'check_file_perm /var/lib/kubelet/config.yaml 600'

    run_check "2.1.4" "Ensure kubelet config.yaml ownership is root:root" \
        bash -c 'check_file_owner /var/lib/kubelet/config.yaml root:root'

    run_check "2.1.5" "Ensure kubelet.conf permissions are 600" \
        bash -c 'check_file_perm /etc/kubernetes/kubelet.conf 600'

    run_check "2.1.6" "Ensure kubelet.conf ownership is root:root" \
        bash -c 'check_file_owner /etc/kubernetes/kubelet.conf root:root'

    run_check "2.1.7" "Ensure Kubernetes PKI directory ownership is root:root" \
        bash -c 'check_file_owner /etc/kubernetes/pki root:root'

    # 2.2 Kubelet
    echo -e "  ${C_INFO}── 2.2 Kubelet ──${C_RST}"

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "2.2.1" "Ensure --anonymous-auth is set to false" \
        bash -c 'val=$(get_kubelet_flag anonymous-auth 2>/dev/null || get_kubelet_config authentication 2>/dev/null || true); echo "$val" | grep -q "false" && echo "anonymous-auth=false" && return 0 || echo "anonymous-auth=$val (expect false)" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "2.2.2" "Ensure --authorization-mode is not AlwaysAllow" \
        bash -c 'val=$(get_kubelet_flag authorization-mode 2>/dev/null || get_kubelet_config authorization 2>/dev/null || true); echo "$val" | grep -qv "AlwaysAllow" && echo "authorization-mode=$val" && return 0 || echo "authorization-mode=$val (AlwaysAllow)" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "2.2.3" "Ensure --client-ca-file is set appropriately" \
        bash -c 'val=$(get_kubelet_flag client-ca-file 2>/dev/null || true); [ -n "$val" ] && echo "set: $val" && return 0 || echo "not set" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "2.2.4" "Ensure --read-only-port is disabled (0)" \
        bash -c 'val=$(get_kubelet_flag read-only-port 2>/dev/null || get_kubelet_config readOnlyPort 2>/dev/null || true); [ "$val" = "0" ] && echo "read-only-port=0" && return 0 || echo "read-only-port=$val (expect 0)" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "2.2.5" "Ensure --protect-kernel-defaults is set to true" \
        bash -c 'val=$(get_kubelet_flag protect-kernel-defaults 2>/dev/null || get_kubelet_config protectKernelDefaults 2>/dev/null || true); [ "$val" = "true" ] && echo "protect-kernel-defaults=true" && return 0 || echo "protect-kernel-defaults=$val (expect true)" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "2.2.6" "Ensure --event-qps is set to 0 or as appropriate" \
        bash -c 'val=$(get_kubelet_flag event-qps 2>/dev/null || get_kubelet_config eventRecordQPS 2>/dev/null || true); [ "$val" = "0" ] && echo "event-qps=0" && return 0 || echo "event-qps=$val" && return 2'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "2.2.7" "Ensure --tls-cert-file and --tls-private-key-file are set appropriately" \
        bash -c 'cert=$(get_kubelet_flag tls-cert-file 2>/dev/null || true); key=$(get_kubelet_flag tls-private-key-file 2>/dev/null || true); [ -n "$cert" ] && [ -n "$key" ] && echo "both set" && return 0 || echo "missing cert or key" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "2.2.8" "Ensure --rotateCertificates is set to true or --feature-gates RotateKubeletClientCertificate=true" \
        bash -c 'val=$(get_kubelet_flag rotateCertificates 2>/dev/null || get_kubelet_config rotateCertificates 2>/dev/null || true); [ "$val" = "true" ] && echo "rotateCertificates=true" && return 0 || echo "rotateCertificates=$val (expect true)" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "2.2.9" "Ensure RotateKubeletServerCertificate is set to true" \
        bash -c 'val=$(get_kubelet_flag feature-gates 2>/dev/null || true); echo "$val" | grep -q "RotateKubeletServerCertificate=true" && echo "enabled" && return 0 || echo "not enabled" && return 1'
}

# ── 3.x Control Plane Configuration (Policies) ───────────────
section_policies() {
    echo ""
    echo "━━━ 3.x Control Plane Configuration (Policies) ━━━"

    # 3.1 RBAC
    echo -e "  ${C_INFO}── 3.1 RBAC ──${C_RST}"

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "3.1.1" "Ensure ClusterRoleBinding system:masters has no direct user subjects" \
        bash -c 'count=$(k get clusterrolebinding system:masters -o jsonpath="{.subjects[?(@.kind==\"User\")].name}" 2>/dev/null | wc -l); [ "$count" -eq 0 ] && echo "no direct user subjects" && return 0 || echo "$count direct user subjects (should be 0)" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "3.1.2" "Ensure cluster-admin role is not granted to all authenticated users" \
        bash -c 'bindings=$(k get clusterrolebinding -o json 2>/dev/null); echo "$bindings" | grep -q "system:authenticated" && echo "$bindings" | grep -q "cluster-admin" && echo "WARNING: cluster-admin granted to all authenticated" && return 1 || echo "OK" && return 0'

    # 3.2 Pod Security Standards
    echo -e "  ${C_INFO}── 3.2 Pod Security Standards ──${C_RST}"

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "3.2.1" "Ensure PSA restricted profile is enforced on critical namespaces" \
        bash -c 'count=$(k get namespaces --no-headers 2>/dev/null | wc -l); restricted=$(k get namespaces -o json 2>/dev/null | grep -c "restricted" || true); echo "$restricted/$count namespaces with restricted PSA"; [ "$restricted" -gt 0 ] && return 0 || return 2'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "3.2.2" "Ensure default namespace has PSA label" \
        bash -c 'labels=$(k get namespace default -o jsonpath="{.metadata.labels}" 2>/dev/null); echo "$labels" | grep -q "pod-security.kubernetes.io" && echo "PSA labels present" && return 0 || echo "no PSA labels on default namespace" && return 2'

    # 3.3 Network Policies
    echo -e "  ${C_INFO}── 3.3 Network Policies ──${C_RST}"

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "3.3.1" "Ensure Network Policies are enforced where applicable" \
        bash -c 'np_count=$(k get networkpolicies --all-namespaces --no-headers 2>/dev/null | wc -l); echo "$np_count network policies"; [ "$np_count" -gt 0 ] && return 0 || echo "no network policies found" && return 2'

    # 3.4 Secrets
    echo -e "  ${C_INFO}── 3.4 Secrets ──${C_RST}"

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "3.4.1" "Ensure Secrets are not stored in plain text in ConfigMaps" \
        bash -c 'cm_with_secrets=$(k get configmaps --all-namespaces -o json 2>/dev/null | grep -ciE "(password|secret|key|token)" || true); echo "$cm_with_secrets configmaps with potential secrets"; [ "$cm_with_secrets" -eq 0 ] && return 0 || return 2'

    # 3.5 Encryption
    echo -e "  ${C_INFO}── 3.5 Encryption ──${C_RST}"

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "3.5.1" "Ensure encryption at rest is configured" \
        bash -c 'val=$(get_api_flag encryption-provider-config 2>/dev/null || true); [ -n "$val" ] && echo "encryption-provider-config=$val" && return 0 || echo "encryption at rest not configured" && return 1'

    # 3.6 Admission Controllers
    echo -e "  ${C_INFO}── 3.6 Admission Controllers ──${C_RST}"

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "3.6.1" "Ensure EventRateLimit admission controller is enabled" \
        bash -c 'val=$(get_api_flag enable-admission-plugins 2>/dev/null || true); echo "$val" | grep -q "EventRateLimit" && echo "EventRateLimit enabled" && return 0 || echo "EventRateLimit not enabled" && return 2'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "3.6.2" "Ensure AlwaysAdmit admission controller is not enabled" \
        bash -c 'val=$(get_api_flag enable-admission-plugins 2>/dev/null || true); echo "$val" | grep -qv "AlwaysAdmit" && echo "AlwaysAdmit not enabled" && return 0 || echo "AlwaysAdmit enabled (should not be)" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "3.6.3" "Ensure ServiceAccount admission controller is enabled" \
        bash -c 'val=$(get_api_flag enable-admission-plugins 2>/dev/null || true); echo "$val" | grep -q "ServiceAccount" && echo "ServiceAccount enabled" && return 0 || echo "ServiceAccount not enabled" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "3.6.4" "Ensure NamespaceLifecycle admission controller is enabled" \
        bash -c 'val=$(get_api_flag enable-admission-plugins 2>/dev/null || true); echo "$val" | grep -q "NamespaceLifecycle" && echo "NamespaceLifecycle enabled" && return 0 || echo "NamespaceLifecycle not enabled" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "3.6.5" "Ensure PodSecurityPolicy/PodSecurity admission controller is enabled" \
        bash -c 'val=$(get_api_flag enable-admission-plugins 2>/dev/null || true); echo "$val" | grep -qE "PodSecurityPolicy|PodSecurity" && echo "PodSecurity enabled" && return 0 || echo "PodSecurity not enabled" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "3.6.6" "Ensure NodeRestriction admission controller is enabled" \
        bash -c 'val=$(get_api_flag enable-admission-plugins 2>/dev/null || true); echo "$val" | grep -q "NodeRestriction" && echo "NodeRestriction enabled" && return 0 || echo "NodeRestriction not enabled" && return 1'

    # 3.7 General Policies
    echo -e "  ${C_INFO}── 3.7 General Policies ──${C_RST}"

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "3.7.1" "Ensure --audit-log-path is set" \
        bash -c 'val=$(get_api_flag audit-log-path 2>/dev/null || true); [ -n "$val" ] && echo "audit-log-path=$val" && return 0 || echo "audit-log-path not set" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "3.7.2" "Ensure --audit-log-maxage is set to 30 or as appropriate" \
        bash -c 'val=$(get_api_flag audit-log-maxage 2>/dev/null || true); [ -n "$val" ] && [ "$val" -ge 30 ] 2>/dev/null && echo "audit-log-maxage=$val" && return 0 || echo "audit-log-maxage=$val (expect >=30)" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "3.7.3" "Ensure --audit-log-maxbackup is set to 10 or as appropriate" \
        bash -c 'val=$(get_api_flag audit-log-maxbackup 2>/dev/null || true); [ -n "$val" ] && [ "$val" -ge 10 ] 2>/dev/null && echo "audit-log-maxbackup=$val" && return 0 || echo "audit-log-maxbackup=$val (expect >=10)" && return 1'
}

# ── 4.x Managed Services / Cluster-Wide ──────────────────────
section_cluster_wide() {
    echo ""
    echo "━━━ 4.x Cluster-Wide Checks ━━━"

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "4.1.1" "Ensure all namespaces have Network Policies" \
        bash -c 'ns_count=$(k get namespaces --no-headers 2>/dev/null | wc -l); ns_with_np=$(k get networkpolicies --all-namespaces -o json 2>/dev/null | grep -o "\"namespace\":\"[^\"]*\"" | sort -u | wc -l); echo "$ns_with_np/$ns_count namespaces with NetworkPolicy"; [ "$ns_with_np" -ge 1 ] && return 0 || return 2'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "4.1.2" "Ensure all ServiceAccounts have imagePullSecrets only when necessary" \
        bash -c 'sa_with_secrets=$(k get serviceaccounts --all-namespaces -o json 2>/dev/null | grep -c "imagePullSecrets" || true); echo "$sa_with_secrets SAs with imagePullSecrets"; return 0'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "4.1.3" "Ensure default ServiceAccount is not actively used" \
        bash -c 'pods_with_default=$(k get pods --all-namespaces -o json 2>/dev/null | grep -c "\"serviceAccountName\":\"default\"" || true); echo "$pods_with_default pods using default SA"; [ "$pods_with_default" -eq 0 ] && return 0 || return 2'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "4.1.4" "Ensure Kubernetes Dashboard is not deployed (or secured)" \
        bash -c 'dashboard=$(k get pods --all-namespaces 2>/dev/null | grep -c "kubernetes-dashboard" || true); [ "$dashboard" -eq 0 ] && echo "no dashboard" && return 0 || echo "$dashboard dashboard pods found" && return 2'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "4.1.5" "Ensure RBAC is enabled" \
        bash -c 'val=$(get_api_flag authorization-mode 2>/dev/null || true); echo "$val" | grep -q "RBAC" && echo "RBAC enabled" && return 0 || echo "RBAC not enabled" && return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "4.1.6" "Ensure no pods in default namespace without explicit SA" \
        bash -c 'default_pods=$(k get pods -n default --no-headers 2>/dev/null | wc -l); echo "$default_pods in default namespace"; return 0'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "4.1.7" "Ensure cluster has minimum 3 master nodes (HA)" \
        bash -c 'masters=$(k get nodes -l node-role.kubernetes.io/control-plane --no-headers 2>/dev/null | wc -l); echo "$masters master nodes"; [ "$masters" -ge 3 ] && return 0 || echo "less than 3 masters (no HA)" && return 2'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "4.1.8" "Ensure Kubernetes version is supported (not EOL)" \
        bash -c 'ver=$(echo "$K8S_VERSION" | grep -oE "[0-9]+\.[0-9]+" | head -1); minor=$(echo "$ver" | cut -d. -f2); [ "$minor" -ge 26 ] 2>/dev/null && echo "K8s $K8S_VERSION (supported)" && return 0 || echo "K8s $K8S_VERSION may be EOL" && return 2'
}

# ── 5.x Kubernetes Policies (Workload) ───────────────────────
section_workload() {
    echo ""
    echo "━━━ 5.x Workload Security ━━━"

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "5.1.1" "Ensure pods do not run as root (cluster-wide)" \
        bash -c 'root_pods=$(k get pods --all-namespaces -o json 2>/dev/null | grep -c "\"runAsUser\":0" || true); echo "$root_pods pods runAsUser=0"; [ "$root_pods" -eq 0 ] && return 0 || return 2'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "5.1.2" "Ensure pods do not use privileged containers" \
        bash -c 'priv_pods=$(k get pods --all-namespaces -o json 2>/dev/null | grep -c "\"privileged\":true" || true); echo "$priv_pods privileged containers"; [ "$priv_pods" -eq 0 ] && return 0 || return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "5.1.3" "Ensure pods do not share host network namespace" \
        bash -c 'host_net=$(k get pods --all-namespaces -o json 2>/dev/null | grep -c "\"hostNetwork\":true" || true); echo "$host_net pods with hostNetwork"; [ "$host_net" -eq 0 ] && return 0 || return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "5.1.4" "Ensure pods do not share host PID namespace" \
        bash -c 'host_pid=$(k get pods --all-namespaces -o json 2>/dev/null | grep -c "\"hostPID\":true" || true); echo "$host_pid pods with hostPID"; [ "$host_pid" -eq 0 ] && return 0 || return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "5.1.5" "Ensure pods do not share host IPC namespace" \
        bash -c 'host_ipc=$(k get pods --all-namespaces -o json 2>/dev/null | grep -c "\"hostIPC\":true" || true); echo "$host_ipc pods with hostIPC"; [ "$host_ipc" -eq 0 ] && return 0 || return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "5.1.6" "Ensure containers do not have dangerous capabilities" \
        bash -c 'cap_pods=$(k get pods --all-namespaces -o json 2>/dev/null | grep -c "SYS_ADMIN\|NET_ADMIN\|SYS_PTRACE\|SYS_MODULE" || true); echo "$cap_pods pods with dangerous caps"; [ "$cap_pods" -eq 0 ] && return 0 || return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "5.1.7" "Ensure containers do not mount docker.sock" \
        bash -c 'sock_pods=$(k get pods --all-namespaces -o json 2>/dev/null | grep -c "docker.sock" || true); echo "$sock_pods pods mounting docker.sock"; [ "$sock_pods" -eq 0 ] && return 0 || return 1'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "5.1.8" "Ensure containers have resource limits set" \
        bash -c 'pods_total=$(k get pods --all-namespaces --no-headers 2>/dev/null | wc -l); pods_with_limits=$(k get pods --all-namespaces -o json 2>/dev/null | grep -c "\"limits\"" || true); echo "$pods_with_limits/$pods_total pods with limits"; return 0'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "5.1.9" "Ensure containers have liveness/readiness probes" \
        bash -c 'pods_with_probe=$(k get pods --all-namespaces -o json 2>/dev/null | grep -c "livenessProbe\|readinessProbe" || true); echo "$pods_with_probe pods with probes"; return 0'

# shellcheck disable=SC2016 # inner-shell expansion
    run_check "5.1.10" "Ensure containers have image tag set (not :latest)" \
        bash -c 'latest_images=$(k get pods --all-namespaces -o json 2>/dev/null | grep -c ":latest" || true); echo "$latest_images pods with :latest image"; [ "$latest_images" -eq 0 ] && return 0 || return 2'
}

# ── JSON report ────────────────────────────────────────────────
write_json_report() {
    echo "${JSON_RESULTS}]" > "$REPORT_JSON"
}

# ── Summary ─────────────────────────────────────────────────────
print_summary() {
    echo ""
    echo -e "${C_INFO}╔══════════════════════════════════════════╗${C_RST}"
    echo -e "${C_INFO}║  CIS Kubernetes Benchmark Audit           ║${C_RST}"
    echo -e "${C_INFO}║  $APP_NAME $APP_VER                        ║${C_RST}"
    echo -e "${C_INFO}╚══════════════════════════════════════════╝${C_RST}"
    echo -e "${C_INFO}Node: $NODE_NAME${C_RST}"
    echo -e "${C_INFO}K8s:  $K8S_VERSION${C_RST}"
    echo -e "${C_INFO}Role: $([ "$IS_MASTER" -eq 1 ] && echo 'control-plane' || echo 'worker')${C_RST}"
    echo -e "${C_INFO}Mode: READ-ONLY (no changes)${C_RST}"
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
    detect_environment
    init_report

    if [ "$QUIET" -eq 0 ]; then
        echo ""
        echo -e "${C_INFO}╔══════════════════════════════════════════╗${C_RST}"
        echo -e "${C_INFO}║  CIS Kubernetes Benchmark Audit           ║${C_RST}"
        echo -e "${C_INFO}║  $APP_NAME $APP_VER                        ║${C_RST}"
        echo -e "${C_INFO}╚══════════════════════════════════════════╝${C_RST}"
        echo -e "${C_INFO}K8s: $(KUBECONFIG="$KUBECONFIG_PATH" "$KUBECTL" version --short 2>/dev/null | head -1 || echo 'N/A')${C_RST}"
        echo -e "${C_INFO}Node: $NODE_NAME ($([ "$IS_MASTER" -eq 1 ] && echo 'control-plane' || echo 'worker'))${C_RST}"
        echo -e "${C_INFO}Mode: READ-ONLY (no changes)${C_RST}"
        echo ""
    fi

    case "$SECTION_FILTER" in
        master|controlplane)
            section_control_plane
            ;;
        worker)
            section_worker_node
            ;;
        policies)
            section_policies
            ;;
        cluster|cluster-wide)
            section_cluster_wide
            ;;
        workload)
            section_workload
            ;;
        "")
            section_control_plane
            section_worker_node
            section_policies
            section_cluster_wide
            section_workload
            ;;
        *)
            echo "Unknown section: $SECTION_FILTER (Optional: master/worker/policies/cluster/workload)"
            exit 1
            ;;
    esac

    write_json_report
    print_summary

    if [ "$JSON_ONLY" -eq 1 ]; then
        echo "$REPORT_JSON"
    fi
    return 0
}

main "$@"
