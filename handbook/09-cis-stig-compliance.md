# CIS & STIG Compliance Audit

> Automated compliance checking against CIS Benchmarks and DISA STIG — know exactly where your server stands, without spending hours with a checklist.

## Overview

Security frameworks like **CIS Benchmarks** and **DISA STIG** provide vetted, consensus-based configuration guidelines. They're the gold standard for server hardening, and many compliance regimes (PCI-DSS, HIPAA, FedRAMP) explicitly reference them. But running through a 300-page benchmark document manually is impractical.

This chapter covers the automated compliance audit tools shipped with this repo:

- **`scripts/cis_benchmark_audit.sh`** — CIS Benchmark audit (Ubuntu/Debian/RHEL family, Level 1 & 2)
- **`scripts/stig_compliance_check.sh`** — DISA STIG compliance check (planned, Phase 2)

Both tools are **read-only**: they check your system's current configuration and report compliance status, but never modify anything.

## CIS Benchmark Audit

### What It Checks

The CIS Benchmark audit covers 6 major sections, each with multiple control items:

| Section | Scope | Key Checks |
|---|---|---|
| 1.x Initial Setup | Filesystem, updates, MAC, bootloader, kernel | cramfs disabled, /tmp options, AppArmor/SELinux, ASLR, core dumps, kptr_restrict |
| 2.x Services | Time sync, X Window, unnecessary services | chrony/ntpd, no X11, no Avahi/CUPS/DHCP/LDAP/NFS/DNS/FTP |
| 3.x Network | IPv6, redirects, forwarding, firewall | IP forwarding disabled, SYN cookies, firewall installed & active |
| 4.x Logging | rsyslog, journald, logrotate, auditd | rsyslog enabled, auditd installed & enabled, log retention |
| 5.x Access | Cron, SSH, sudo, password policy, accounts | SSH hardening (14 checks), faillock, no empty passwords, UID 0 only root |
| 6.x Maintenance | File permissions, user/home hygiene | /etc/passwd/shadow perms, no world-writable files, no SUID/SGID surprises |

### Usage

```bash
# Interactive (prompts for level)
sudo ./scripts/cis_benchmark_audit.sh

# Level 1 (baseline — most important checks)
sudo ./scripts/cis_benchmark_audit.sh --level 1

# Level 2 (deep — includes stricter checks)
sudo ./scripts/cis_benchmark_audit.sh --level 2

# Quiet mode (summary only, no per-check output)
sudo ./scripts/cis_benchmark_audit.sh --level 1 --quiet

# JSON only (for CI/CD integration — prints JSON report path)
sudo ./scripts/cis_benchmark_audit.sh --level 1 --json
```

### Output

Each run produces two reports in `/var/log/cis-audit/`:

| Report | Format | Use Case |
|---|---|---|
| `cis-audit-<timestamp>.txt` | Human-readable | Manual review, evidence for audits |
| `cis-audit-<timestamp>.json` | Machine-readable | CI/CD integration, trend tracking |

The console output shows each check with its CIS ID, result (PASS/FAIL/WARN/SKIP), and a compliance percentage summary.

### Result Codes

| Code | Meaning | Action |
|---|---|---|
| **PASS** | Configuration meets the CIS recommendation | None needed |
| **FAIL** | Configuration does not meet the recommendation | Fix recommended |
| **WARN** | Check could not be definitively evaluated | Manual review needed |
| **SKIP** | Check skipped (e.g., Level 2 check in Level 1 mode) | Run Level 2 if relevant |

### Integration with the Main Script

From `secure-vps`, the CIS audit is accessible via:

```
C · 纵深防御 → c3 审计与完整性 → CIS 合规审计
```

This calls `scripts/cis_benchmark_audit.sh --level 1` and displays the summary.

## CIS Benchmark Levels

CIS defines two compliance levels:

| Level | Philosophy | When to Use |
|---|---|---|
| **Level 1** | Baseline security — practical, low risk of breaking functionality | All servers, starting point |
| **Level 2** | Defense in depth — stricter, may impact some workloads | High-security environments, compliance requirements |

**Recommendation**: Start with Level 1, fix all FAIL items, then run Level 2 and evaluate each FAIL against your specific workload.

## STIG Compliance Check

DISA STIG (Security Technical Implementation Guide) is the US Department of Defense's hardening standard. It's stricter than CIS and required for US government systems.

The `scripts/stig_compliance_check.sh` covers:

- **70+ checks** across 7 sections mapped to STIG SRG (Security Requirements Guide) IDs
- **Severity classification**: CAT I (high), CAT II (medium), CAT III (low)
- **Modular control**: `--enable`/`--disable` specific SRG IDs
- **Scanner mode**: `--scanner` runs all checks without prompts
- **Read-only**: never modifies system configuration
- **Dual report**: TXT (human) + JSON (CI/CD)

### What It Checks

| Section | SRG Range | Key Checks |
|---|---|---|
| Access Control | SRG-OS-000023~031 | SSH root login, protocol, MaxAuthTries, ClientAliveInterval, access restrictions |
| Audit & Accountability | SRG-OS-000032~042 | auditd installed/enabled, audit rules for login/logout/session/deletion/permission changes |
| Identification & Auth | SRG-OS-000043~051 | No empty passwords, UID 0 only root, password minlen/complexity/reuse/lockout, no duplicate UIDs |
| System Integrity | SRG-OS-000052~061 | ASLR, core dumps, kptr/dmesg/perf/ptrace restrict, AIDE installed + initialized + cron, rsyslog |
| Config Management | SRG-OS-000062~074 | /etc/passwd/shadow/group/gshadow perms, cron dirs perms, no world-writable/unowned/ungrouped files |
| Network Security | SRG-OS-000075~084 | IP forwarding, redirects, source route, ICMP, SYN cookies, firewall installed + active |
| OS Hardening | SRG-OS-000085~093 | MAC (SELinux/AppArmor), bootloader password, warning banners, time sync, no X11, no unnecessary services |

### Usage

```bash
# Scanner mode (all checks, no prompts)
sudo ./scripts/stig_compliance_check.sh --scanner

# Enable only specific SRG IDs
sudo ./scripts/stig_compliance_check.sh --enable SRG-OS-000023 --enable SRG-OS-000024

# Disable specific checks
sudo ./scripts/stig_compliance_check.sh --disable SRG-OS-000089

# Quiet mode (summary only)
sudo ./scripts/stig_compliance_check.sh --scanner --quiet

# JSON only (for CI/CD)
sudo ./scripts/stig_compliance_check.sh --scanner --json
```

### STIG Severity Categories

| Category | Severity | Action |
|---|---|---|
| **CAT I** | High — directly exploitable | Must fix immediately |
| **CAT II** | Medium — indirect risk | Fix recommended |
| **CAT III** | Low — best practice | Fix when possible |

The summary report includes a severity breakdown showing CAT I and CAT II FAIL counts separately, so you can prioritize fixes.

## Compliance vs Hardening

| Aspect | Compliance Audit | Hardening |
|---|---|---|
| What it does | Checks current state against a standard | Changes configuration to meet a standard |
| Risk | Zero (read-only) | Low-moderate (may affect functionality) |
| When to run | Before hardening (baseline), after hardening (verify), periodically (drift) | After baseline audit, when fixing FAIL items |
| Tool in this repo | `cis_benchmark_audit.sh` | `secure-vps` (interactive menu) |

**Recommended workflow**:
1. Run `cis_benchmark_audit.sh --level 1` to get baseline
2. Use `secure-vps` to fix FAIL items (SSH, firewall, kernel, etc.)
3. Re-run the audit to verify improvements
4. Set up periodic audits (cron) to detect configuration drift

## Related Tools in the 0x10debug Suite

| Tool | Repo | Focus |
|---|---|---|
| CIS/STIG audit (this script) | vps-security-enhancement-scripts | Interactive, single-server |
| CIS benchmark + drift detection | [security-audit](https://github.com/0x10debug/security-audit) | Modular, CI/CD integration, multi-server |

Both tools cover CIS Benchmarks — this script is the "quick check" entry point, `security-audit` is the "continuous compliance" platform.

## References

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/) — Official benchmark documents (free download)
- [DISA STIG](https://public.cyber.mil/stigs/) — Official STIG documents
- [CIS-CAT Pro Assessor](https://learn.cisecurity.org/cis-cat-pro) — Commercial CIS assessment tool (reference implementation)
- [SiteQ8/CIS-Benchmark-Compliance-Checker](https://github.com/SiteQ8/CIS-Benchmark-Compliance-Checker) — Multi-platform open-source checker (inspiration)
