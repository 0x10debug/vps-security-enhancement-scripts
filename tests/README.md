# tests/

Re-runnable verification suite. Run from anywhere:

```bash
tests/run-tests.sh          # full suite (includes local gitleaks if installed)
tests/run-tests.sh --ci     # CI mode (skips checks covered by dedicated jobs)
```

## What each layer proves

| Layer | Proves | Does NOT prove |
|---|---|---|
| L1 static | scripts parse, strict shellcheck cleanliness, no-Chinese policy, README/report cross-references | runtime behavior on real hosts |
| L2 structural | declared assets exist (handbook, cheatsheets, LICENSE, entry point) | content correctness of chapters |
| L3 smoke | every script surfaces usage on `-h` safely, without side effects or hangs | audit logic, host changes |

Host-level audit correctness is proven only by the full manual test cycles
recorded in `TEST-REPORT-*.md` per the convention in `AGENTS.md`.
