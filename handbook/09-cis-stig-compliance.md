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

## STIG Compliance (Planned)

DISA STIG (Security Technical Implementation Guide) is the US Department of Defense's hardening standard. It's stricter than CIS and required for US government systems.

The planned `stig_compliance_check.sh` will cover:

- STIG Category 1 (high severity) checks
- Modular control (enable/disable specific checks)
- Scanner mode for batch assessment
- Mapping to STIG SRG (Security Requirements Guide) IDs

**Status**: Planned for Phase 2 iteration. See `dev-docs/0015` branch strategy.

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
