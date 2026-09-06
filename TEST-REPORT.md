# TEST-REPORT

Living per-iteration test report, maintained per the Testing Discipline iron
rule (main repo AGENTS.md, 2026-09-06). Release-cycle reports are separate
(`TEST-REPORT-v<version>.md`, retained for trend comparison).

Layer definitions: L1 static (bash -n, shellcheck, gitleaks, no-Chinese scan),
L2 config validation, L3 runtime smoke in a disposable environment, L4
host-level lifecycle.

---

## 2026-09-06T20:10:13Z — commit 2e6ebd0 (Round 2 Day 11 backfill: l17-l20)

**Layers executed: L1, L2, L3. L4 not run.**

| Check | Result |
|---|---|
| L1 bash -n sweep (17 files) | PASS |
| L1 shellcheck -S style, strict (pinned v0.11.0 locally, CI-pinned) | PASS (0 findings; 226 justified directives) |
| L1 gitleaks history scan (allowlists: handbook placeholders) | PASS (exit 0) |
| L1 no-Chinese content scan (ideographs + fullwidth punctuation) | PASS |
| L1 tests/run-tests.sh --ci (28 checks incl. cross-references, usage smoke) | PASS (28/0, ALL GREEN) |
| L2 CI on GitHub: strict shellcheck + test-suite job, run 34044997129 | PASS |
| L3 `bash vps_security_enhance.sh -h` inside Docker `ubuntu:22.04` | PASS (usage renders; root gate unchanged without args) |

Defects found during this development cycle (all fixed pre-push, verified in
the same cycle):

- SC2016 real-bug subset: 8 JMESPath queries in `cloud_cis_baseline.sh` Azure
  checks lost their string-literal quotes to parent-shell splice; az received
  invalid queries and `2>/dev/null` hid the errors, silently reporting 0.
  Fixed with re-quote idiom; stubbed end-to-end replay verifies quoted
  literals now reach az.
- Runner/local shellcheck version skew (runner 0.9 flagged SC2002 on
  `cat /proc/loadavg | awk`): line rewritten and CI toolchain pinned to
  v0.11.0 (commit 115446c).
- `-h` required root (privilege gate preceded argument parsing): usage now
  prints before the gate (l20).

Known issues (open):

- `APP_VER` inside `vps_security_enhance.sh` reads `v2.0.0` while the
  repository is tagged v4.0.0 — version string drift, cosmetic but
  misleading. Scheduled for the v5.0.0 release cycle (iter/l22).

Untested (honest boundaries):

- L3 limited to usage smoke of the entry point and scripts' `-h` paths; audit
  logic was NOT executed against live services in containers this cycle.
- L4 host-level lifecycle (hardening actions, rollback, SSH survival) not
  run — no disposable VM provisioned; blocked, not passed. The v4.0.0 full
  test report (126 tests, Docker Ubuntu 22.04) covers tag v4.0.0 only, not
  commits after it.
