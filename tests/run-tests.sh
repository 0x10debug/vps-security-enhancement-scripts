#!/usr/bin/env bash
# tests/run-tests.sh — Re-runnable verification suite for this repository.
#
# Layers:
#   L1 static     bash -n, strict shellcheck, no-Chinese scan, secret scan,
#                 README/report cross-references
#   L2 structural handbook/cheatsheet presence, LICENSE, entry-point probe
#   L3 smoke      every script answers -h/--help (or usage exit) without
#                 side effects
#
# Usage:
#   tests/run-tests.sh [--ci]
#   --ci  skip checks whose tooling is provided by dedicated CI jobs
#         (gitleaks), keep everything else; exit non-zero on any failure.
#
# What this suite proves: the repository is internally consistent, statically
# clean, and every script surfaces its usage safely. What it does NOT prove:
# audit logic correctness on real hosts - that requires the full test cycles
# recorded in TEST-REPORT-*.md.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CI_MODE=false

usage() {
    cat <<USAGE
tests/run-tests.sh - re-runnable verification suite for this repository

Usage:
  tests/run-tests.sh [--ci]

Layers: L1 static, L2 structural, L3 usage smoke. See tests/README.md.
  --ci   skip checks covered by dedicated CI jobs (gitleaks)
USAGE
}
[[ "${1:-}" == "--help" || "${1:-}" == "-h" ]] && { usage; exit 0; }
[[ "${1:-}" == "--ci" ]] && CI_MODE=true
if [[ -n "${1:-}" && "${1:-}" != "--ci" ]]; then
    echo "unknown argument: $1" >&2
    usage >&2
    exit 2
fi

pass=0
fail=0
failures=()

ok() { pass=$((pass + 1)); echo "ok   - $1"; }
bad() { fail=$((fail + 1)); failures+=("$1"); echo "FAIL - $1"; }
section() { echo ""; echo "=== $1 ==="; }

# ── L1 static ────────────────────────────────────────────────────────────────
section "L1 static"

sh_files=()
while IFS= read -r -d '' f; do sh_files+=("$f"); done < <(find "$ROOT" -name '*.sh' -not -path '*/.git/*' -print0)
if [[ ${#sh_files[@]} -eq 0 ]]; then
    bad "no shell scripts found (repository layout changed?)"
fi

if bash -n "${sh_files[@]}" 2>/dev/null; then
    ok "bash -n: ${#sh_files[@]} scripts parse"
else
    for f in "${sh_files[@]}"; do bash -n "$f" || bad "bash -n: $f"; done
fi

if command -v shellcheck >/dev/null 2>&1; then
    sc_failed=0
    for f in "${sh_files[@]}"; do
        shellcheck -S style "$f" || sc_failed=1
    done
    if [[ $sc_failed -eq 0 ]]; then
        ok "shellcheck -S style: zero findings"
    else
        bad "shellcheck -S style reported findings (gate is strict since iter/l18)"
    fi
else
    bad "shellcheck not installed - cannot run the strict gate"
fi

if command -v grep >/dev/null 2>&1 && grep -rIPqn '[\x{3000}-\x{303F}\x{3400}-\x{4DBF}\x{4E00}-\x{9FFF}\x{F900}-\x{FAFF}\x{FE30}-\x{FE4F}\x{FF00}-\x{FFEF}]' --exclude-dir=.git "$ROOT" 2>/dev/null; then
    bad "no-Chinese policy: CJK characters or fullwidth punctuation found"
else
    ok "no-Chinese policy: clean"
fi

if [[ $CI_MODE == false ]]; then
    if command -v gitleaks >/dev/null 2>&1; then
        if gitleaks detect --source "$ROOT" --redact >/dev/null 2>&1; then
            ok "gitleaks: history scan clean"
        else
            bad "gitleaks: leaks found (see .gitleaks.toml for scoped allowlists)"
        fi
    else
        echo "skip - gitleaks not installed"
    fi
else
    echo "skip - gitleaks (--ci: dedicated secret-scan job covers this)"
fi

report="$ROOT/TEST-REPORT-v4.0.0.md"
if [[ -f $report ]]; then
    if grep -q 'TEST-REPORT-v4.0.0.md' "$ROOT/README.md"; then
        ok "README references the current test report"
    else
        bad "README does not reference TEST-REPORT-v4.0.0.md"
    fi
    uncovered=0
    for s in "${sh_files[@]}"; do
        base="$(basename "$s")"
        # Coverage applies to production scripts; the suite itself ships later
        # than the report and is covered by its own gates.
        [[ $s == "$SCRIPT_DIR"/* ]] && continue
        if ! grep -qF "$base" "$report"; then
            bad "shipped script not covered by the test report: $base"
            uncovered=1
        fi
    done
    [[ $uncovered -eq 0 ]] && ok "every shipped script is covered by the test report"
else
    bad "TEST-REPORT-v4.0.0.md missing from repo root"
fi

# ── L2 structural ────────────────────────────────────────────────────────────
section "L2 structural"

handbook_count=$(find "$ROOT/handbook" -name '*.md' 2>/dev/null | wc -l | tr -d ' ')
if [[ $handbook_count -ge 20 ]]; then
    ok "handbook chapters present ($handbook_count >= 20)"
else
    bad "handbook chapters dropped below declared baseline ($handbook_count < 20)"
fi

cheat_count=$(find "$ROOT/cheatsheet" -name '*.md' 2>/dev/null | wc -l | tr -d ' ')
if [[ $cheat_count -ge 4 ]]; then
    ok "cheatsheets present ($cheat_count >= 4)"
else
    bad "cheatsheets dropped below declared baseline ($cheat_count < 4)"
fi

if grep -q '^MIT' "$ROOT/LICENSE" 2>/dev/null; then
    ok "LICENSE is MIT"
else
    bad "LICENSE is not MIT"
fi

main_script="$ROOT/vps_security_enhance.sh"
if [[ -f $main_script ]]; then
    help_out=$(timeout 10 bash "$main_script" -h 2>&1)
    if echo "$help_out" | grep -q 'Usage:'; then
        ok "entry point: -h prints usage without root"
    else
        bad "entry point: -h did not print usage"
    fi
    noarg_out=$(timeout 10 bash -c "echo q | bash '$main_script' 2>&1 | head -3" || true)
    if echo "$noarg_out" | grep -q "run as root"; then
        ok "entry point probe: root gate fires as before (no root in test env)"
    else
        bad "entry point probe output changed unexpectedly: $noarg_out"
    fi
else
    bad "main script missing"
fi

# ── L3 smoke: every script answers -h/--help safely ─────────────────────────
section "L3 smoke"

smoke_failed=0
for f in "${sh_files[@]}"; do
    base="$(basename "$f")"
    out=$(timeout 10 bash "$f" -h 2>&1)
    rc=$?
    out_head=$(printf '%s\n' "$out" | head -5)
    if [[ $rc -eq 124 ]]; then
        bad "smoke: $base hung on -h (timeout)"
        smoke_failed=1
    elif echo "$out_head" | grep -qiE 'usage|help|option'; then
        ok "smoke: $base prints usage"
    elif [[ $rc -eq 0 ]]; then
        ok "smoke: $base exits cleanly on -h"
    else
        bad "smoke: $base produced no usage on -h (exit $rc): $(echo "$out_head" | head -1)"
        smoke_failed=1
    fi
done
[[ $smoke_failed -eq 0 ]] || true

# ── summary ──────────────────────────────────────────────────────────────────
section "summary"
echo "passed: $pass  failed: $fail"
if [[ $fail -gt 0 ]]; then
    printf 'failed checks:\n'
    printf '  - %s\n' "${failures[@]}"
    exit 1
fi
echo "ALL GREEN"
exit 0
