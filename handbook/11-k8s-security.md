# Kubernetes Security Audit (CIS Kubernetes Benchmark)

> Automated compliance checking against the CIS Kubernetes Benchmark — secure your K8s control plane, worker nodes, and workloads without reading the 300-page benchmark document.

## Overview

Kubernetes is the de facto container orchestrator, but its default configuration prioritizes functionality over security. The **CIS Kubernetes Benchmark** provides vetted, consensus-based configuration guidelines for securing the control plane (API server, controller manager, scheduler, etcd), worker nodes (kubelet), and cluster-wide policies (RBAC, Pod Security, Network Policies).

This chapter covers the automated K8s security audit tool shipped with this repo:

- **`scripts/k8s_security_audit.sh`** — CIS Kubernetes Benchmark audit (60+ checks across 5 sections)

The tool is **read-only**: it checks your cluster configuration and running workloads, but never modifies anything. It works both **in-cluster** (via service account) and **externally** (via kubeconfig).

## What It Checks

60+ checks across 5 major sections, aligned with CIS Kubernetes Benchmark v1.10.0:

| Section | Scope | Key Checks |
|---|---|---|
| 1.x Control Plane | API server, controller manager, scheduler, etcd configuration | anonymous-auth, authorization-mode (RBAC+Node), profiling, audit logging, etcd TLS + client-cert-auth, file permissions on manifest/config files |
| 2.x Worker Node | kubelet configuration and service files | anonymous-auth, authorization-mode, client-ca-file, read-only-port, protect-kernel-defaults, certificate rotation, file permissions |
| 3.x Policies | RBAC, Pod Security Standards, Network Policies, Secrets, Encryption, Admission Controllers | cluster-admin not granted to all, PSA restricted enforced, NetworkPolicy present, encryption at rest, EventRateLimit/ServiceAccount/NamespaceLifecycle/PodSecurity/NodeRestriction admission plugins |
| 4.x Cluster-Wide | HA, version support, dashboard, default SA usage | ≥3 master nodes, K8s version not EOL, no Kubernetes Dashboard, default SA not used |
| 5.x Workload | Running pod security posture | no root, no privileged, no hostNetwork/PID/IPC, no dangerous caps, no docker.sock mount, resource limits, probes, no :latest images |

## Usage

```bash
# Auto-detect environment and run full audit
./scripts/k8s_security_audit.sh

# Specify kubeconfig explicitly
./scripts/k8s_security_audit.sh --kubeconfig ~/.kube/config

# Audit only specific section
./scripts/k8s_security_audit.sh --section master       # control plane only
./scripts/k8s_security_audit.sh --section worker       # worker node only
./scripts/k8s_security_audit.sh --section policies     # RBAC/PSA/NetworkPolicy
./scripts/k8s_security_audit.sh --section cluster      # cluster-wide checks
./scripts/k8s_security_audit.sh --section workload     # running pod security

# Quiet mode (summary only)
./scripts/k8s_security_audit.sh --quiet

# JSON only (for CI/CD integration — prints JSON report path)
./scripts/k8s_security_audit.sh --json
```

### Environment Detection

The script auto-detects:
- **kubectl** location (must be in PATH)
- **kubeconfig** (from `--kubeconfig`, `$KUBECONFIG` env, or `~/.kube/config`)
- **Node role** (control-plane vs worker, via `node-role.kubernetes.io/control-plane` label)
- **K8s version** (via `kubectl version`)

On a **pure worker node**, control plane checks (1.x) are skipped automatically.

### Output

Each run produces two reports in `/var/log/k8s-audit/`:

| Report | Format | Use Case |
|---|---|---|
| `k8s-audit-<timestamp>.txt` | Human-readable | Manual review, evidence for audits |
| `k8s-audit-<timestamp>.json` | Machine-readable | CI/CD integration, trend tracking |

### Integration with the Main Script

From `secure-vps`, the K8s audit is accessible via:

```
D · Security operations → d1 Container security → K8s security audit
```

This calls `scripts/k8s_security_audit.sh` and displays the summary.

## Common Findings and Fixes

### FAIL: --anonymous-auth is true (API server)

**Risk**: Unauthenticated users can access the API server.
**Fix**: Edit `/etc/kubernetes/manifests/kube-apiserver.yaml`:
```yaml
spec:
  containers:
  - command:
    - kube-apiserver
    - --anonymous-auth=false
```

### FAIL: --authorization-mode is AlwaysAllow

**Risk**: No authorization checks — any authenticated user can perform any action.
**Fix**: Set to `Node,RBAC`:
```yaml
- --authorization-mode=Node,RBAC
```

### FAIL: --profiling is true (API server / controller manager / scheduler)

**Risk**: Profiling endpoint exposes sensitive runtime information.
**Fix**:
```yaml
- --profiling=false
```

### FAIL: etcd --client-cert-auth is not true

**Risk**: Unauthenticated clients can access etcd (the cluster's source of truth).
**Fix**: Edit `/etc/kubernetes/manifests/etcd.yaml`:
```yaml
- --client-cert-auth=true
```

### FAIL: kubelet --anonymous-auth is true

**Risk**: Unauthenticated users can query kubelet API (pod logs, exec, etc.).
**Fix**: Edit `/var/lib/kubelet/config.yaml`:
```yaml
authentication:
  anonymous:
    enabled: false
```

### FAIL: No Network Policies

**Risk**: All pods can communicate with all other pods by default (flat network).
**Fix**: Add a default deny NetworkPolicy, then allow specific traffic:
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

### FAIL: Encryption at rest is not configured

**Risk**: Secrets stored in etcd are readable if etcd is compromised.
**Fix**: Create an encryption configuration and enable it:
```yaml
# /etc/kubernetes/encryption-config.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources:
  - secrets
  providers:
  - aescbc:
      keys:
      - name: key1
        secret: <base64-encoded-32-byte-key>
  - identity: {}
```
```yaml
# kube-apiserver.yaml
- --encryption-provider-config=/etc/kubernetes/encryption-config.yaml
```

### WARN: Pods running as root

**Risk**: Container escape + root = full node compromise.
**Fix**: Use Pod Security Standards restricted profile:
```yaml
# namespace labels
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

### WARN: Privileged containers

**Risk**: Privileged containers have full host access (equivalent to running on the host).
**Fix**: Remove `securityContext.privileged: true` or set to `false`.

## Relationship to kube-bench

This script is inspired by [aquasecurity/kube-bench](https://github.com/aquasecurity/kube-bench) (8115 stars) but is a standalone Bash implementation with these differences:

| Dimension | kube-bench | This script |
|---|---|---|
| Language | Go | Bash |
| Dependencies | Go binary, JSON config | kubectl + bash |
| Installation | Download binary | Already in repo |
| Cluster access | Reads local files | kubectl + local files |
| Workload checks | No | Yes (5.x section) |
| Report format | JSON, TXT | JSON, TXT |
| CI/CD | Native | Via `--json` flag |

For production CI/CD pipelines, kube-bench may be more suitable (faster, structured output). For ad-hoc VPS audits and quick checks, this script requires zero installation beyond kubectl.

## Related Tools in the 0x10debug Suite

| Tool | Repo | Focus |
|---|---|---|
| K8s audit (this script) | vps-security-enhancement-scripts | Quick check, single-cluster |
| Docker audit | vps-security-enhancement-scripts | CIS Docker Benchmark |
| Dockerfile hardener | vps-security-enhancement-scripts | Build-time Dockerfile analysis |
| K8s + Docker audit platform | [security-audit](https://github.com/0x10debug/security-audit) | Modular, CI/CD, multi-cluster |

## References

- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes) — Official benchmark (free download)
- [CIS Kubernetes Benchmark v1.10.0](https://www.cisecurity.org/benchmark/kubernetes) — Reference version for this audit
- [kube-bench](https://github.com/aquasecurity/kube-bench) — Go-based reference implementation
- [Kubernetes Security Documentation](https://kubernetes.io/docs/concepts/security/) — K8s official docs
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) — K8s official PSA docs
