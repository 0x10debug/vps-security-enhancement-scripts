# Contributing to VPS Security Enhancement Scripts

Thanks for your interest in improving this project. Contributions of bug
reports, script fixes, hardening additions, and handbook improvements are all
welcome.

## How to Report a Bug

Open a GitHub issue using the `bug_report` template. Include:

- The script involved and the exact command or menu path you ran
- The distribution and version (`cat /etc/os-release`)
- What you expected versus what happened, with the relevant output
- Whether the effect was cosmetic, a wrong check result, or a system change

Security-sensitive reports (a check that weakens a system, a command injection,
a secret leak): do NOT include real credentials, IPs of production hosts, or
full forensic output. Redact first.

## How to Propose a Change

1. Fork, then create a branch from `main` named `iter/<short-description>`.
2. Keep each branch to one coherent change.
3. Follow the existing script conventions: `#!/usr/bin/env bash`,
   `set -euo pipefail` where the script structure allows it, functions with a
   leading underscore for internal helpers, and user-facing messages in
   English.
4. Run the gates locally before opening a PR:

```bash
find . -name '*.sh' -not -path './.git/*' -print0 | xargs -0 -n1 bash -n
find . -name '*.sh' -not -path './.git/*' -print0 | xargs -0 -n1 shellcheck -S style
```

5. CI runs bash -n, a strict shellcheck gate (style severity), gitleaks secret
   scanning, and a no-Chinese content policy check. A PR is mergeable only when
   all of them are green.
6. If your change alters the output of a check (values, verdicts, or report
   fields), say so explicitly in the PR - check-result changes are reviewed
   more carefully than cosmetic ones.

## Handbook and Cheatsheets

Handbook chapters (`handbook/`) are the core of this project. New chapters
should explain why, not just how: the decision tree, the verification command,
and the rollback path. Cross-reference the matching script if one exists.

## Testing Convention

Full test cycles follow the convention recorded in `AGENTS.md`: a report file
`TEST-REPORT-v<version>.md` in the repo root, English only, with test count,
environment, per-case results, and defect list. Existing reports are kept for
trend comparison.

## License

By contributing, you agree that your contributions are licensed under the
MIT License of this repository.

## Code of Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
