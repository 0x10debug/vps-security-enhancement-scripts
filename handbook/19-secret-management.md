# Chapter 19: Key Management and Secret Scanning

> **Scenario**: You push a new project to GitHub, only to discover that the database password and API key in your `.env` file were also pushed. Even if you immediately delete the file and recommit, the credentials still exist in git history. Anyone who can clone the repository can find your passwords with `git log -p`. You need to know: how to scan for leaked secrets, how to clean up history, and how to prevent it from happening again.

## Why Secret Scanning Is Necessary

Secret leakage is one of the most common security incidents in the cloud era. According to GitGuardian's annual report, thousands of new secret leakage events occur on GitHub daily, and leaked secrets are exploited by attackers within an average of 4 hours.

Typical paths of secret leakage:

1. **Accidental commit** — `.env` files or config files containing real secrets get committed by `git add .`
2. **Hardcoding** — API keys written directly in code for "convenient debugging" and forgotten
3. **Historical residue** — Secrets committed early on, files later deleted, but git history retains them
4. **Copy-paste** — Snippets containing real secrets copied from documentation or test code

## Tool Selection: gitleaks vs trufflehog

| Dimension | gitleaks | trufflehog |
|---|---|---|
| Speed | Fast (regex matching) | Slow (verifies each secret) |
| Accuracy | Medium (has false positives) | High (verifies secret validity) |
| Verification | No verification | Sends requests to APIs to verify |
| Git history | Native support | Native support |
| CI integration | Lightweight | Heavier |
| Use case | Quick scanning + pre-commit | Deep audit + leak confirmation |

**Recommended combination**: Use gitleaks for daily quick scanning and pre-commit blocking, and trufflehog periodically for deep verification.

## Scanning Strategy

### Quick Scan (gitleaks)

```bash
# Scan current workspace
sudo ./scripts/secret_scan.sh --scan --path /your/project

# Scan git history (all commits)
sudo ./scripts/secret_scan.sh --scan-git --path /your/project
```

gitleaks uses 100+ built-in rules to detect common secret patterns:
- AWS Access Key (`AKIA...`)
- GitHub Token (`ghp_...`, `gho_...`)
- GitLab Token (`glpat-...`)
- Slack Token (`xox...`)
- OpenAI API Key (`sk-...`)
- Google API Key (`AIza...`)
- Private key files (`-----BEGIN ... PRIVATE KEY-----`)
- Database connection strings
- Generic password/secret patterns

### Deep Scan (trufflehog)

```bash
# Deep scan (verifies if secrets are still valid)
sudo ./scripts/secret_scan.sh --deep --path /your/project
```

trufflehog sends verification requests to the corresponding API for each discovered secret:
- AWS key → attempts STS GetCallerIdentity call
- GitHub token → attempts /user API call
- Database password → attempts connection

**Note**: The verification process sends requests to external APIs. If a secret has already leaked, this doesn't increase risk (attackers are doing the same thing). But if a secret is a false positive, the verification request may trigger the API's anomaly detection.

### Scanning Decision Tree

```
Need to scan for secrets?
├── Daily development → gitleaks quick scan (--scan)
├── Code audit → gitleaks + trufflehog (--scan + --deep)
├── Suspected historical leak → gitleaks git history scan (--scan-git)
└── CI/CD pipeline → gitleaks pre-commit + GitHub Actions
```

## CI/CD Integration

### GitHub Actions

```bash
# Generate GitHub Actions config
sudo ./scripts/secret_scan.sh --ci --output ./ci-configs
# Copy to project:
cp ci-configs/github-actions/secret-scan.yml .github/workflows/
```

The generated workflow automatically runs gitleaks on every push and PR, blocking merges if secrets are found.

### pre-commit hook

```bash
# Generate pre-commit hook
sudo ./scripts/secret_scan.sh --ci --output ./ci-configs
# Install:
cp ci-configs/pre-commit-hook.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

The pre-commit hook scans staged files before every `git commit`, blocking commits if secrets are found.

### .gitleaksignore

For known false positives, add them to `.gitleaksignore`:

```
# Format: <fingerprint>
# Obtained from the "Fingerprint" field in gitleaks JSON output
a1b2c3d4e5f6:src/config/example.ts:42
```

## Secret Leak Emergency Response

### Step 1: Confirm Leak Scope

```bash
# Scan git history
sudo ./scripts/secret_scan.sh --scan-git --path /your/project

# Deep verify if leaked secrets are still valid
sudo ./scripts/secret_scan.sh --deep --path /your/project
```

### Step 2: Immediately Rotate All Leaked Secrets

**This is the most important step.** Don't try to clean git history first — the secrets have already leaked, and cleaning history doesn't undo the leak.

| Secret type | Rotation method |
|---|---|
| AWS Access Key | IAM console → delete old key → create new key |
| GitHub Token | Settings → Developer settings → delete old token → create new token |
| Database password | Change database password + update all services using it |
| API Key | Regenerate on the corresponding platform |
| SSH private key | Generate new key pair + update authorized_keys |

### Step 3: Clean Git History

```bash
# Using git filter-repo (recommended)
pip install git-filter-repo
git filter-repo --invert-paths --path .env --path config/secrets.yml

# Or using BFG Repo-Cleaner
java -jar bfg.jar --delete-files .env
java -jar bfg.jar --replace-text passwords.txt
git reflog expire --expire=now --all
git gc --prune=now --aggressive
```

### Step 4: Notify Relevant Parties

- Notify everyone with repository access
- If the repository is public, assume secrets have been obtained by unknown third parties
- Update all secret variables in CI/CD
- Check for abnormal API calls (review cloud platform logs)

## Key Management Audit

`secret_scan.sh --audit` performs 13 read-only checks:

| Check ID | Check content |
|---|---|
| SEC-001 | gitleaks installed |
| SEC-002 | trufflehog installed |
| SEC-003 | Sensitive files exist and are in .gitignore |
| SEC-004 | .gitignore exists |
| SEC-005 | .gitignore contains secret-related patterns |
| SEC-006 | No hardcoded secret patterns found |
| SEC-007 | GitHub Actions has no hardcoded secrets |
| SEC-008 | GitHub Actions uses secrets variables |
| SEC-009 | pre-commit hook includes secret scanning |
| SEC-010 | .gitleaksignore exists |
| SEC-011 | gitleaks.toml custom config exists |
| SEC-012 | Sensitive file permissions (600/400) |
| SEC-013 | Docker Compose secret management |

## Key Management Best Practices

### 1. Never Hardcode Secrets

```bash
# ❌ Wrong
API_KEY="sk-1234567890abcdef..."

# ✅ Correct
API_KEY="${API_KEY:?API_KEY not set}"
# Get from environment variables, .env files, or secret management services
```

### 2. Keep .env Files Out of Version Control

```gitignore
# .gitignore
.env
.env.*
!.env.example
```

### 3. Use .env.example as a Template

```bash
# .env.example (committed)
DATABASE_URL=postgresql://user:pass@localhost:5432/db
API_KEY=your_api_key_here

# .env (not committed, real values)
DATABASE_URL=postgresql://admin:s3cr3t@prod-db:5432/myapp
API_KEY=sk-real-key-here
```

### 4. File Permissions

```bash
chmod 600 ~/.env
chmod 600 ~/.ssh/id_rsa
chmod 600 ~/.ssh/id_ed25519
chmod 600 ~/.aws/credentials
```

### 5. Docker secrets

```yaml
# docker-compose.yml
services:
  app:
    environment:
      - DATABASE_PASSWORD_FILE=/run/secrets/db_password
    secrets:
      - db_password

secrets:
  db_password:
    file: ./secrets/db_password.txt
```

## FAQ

### Q: Too many gitleaks false positives?

1. Add false positives to `.gitleaksignore`
2. Add paths or regexes to the `[allowlist]` section in `gitleaks.toml`
3. Use the `# gitleaks:allow` comment for test files

### Q: Do I need to force push after cleaning git history?

Yes. Cleaning history rewrites all commit hashes, requiring `git push --force`. Ensure all collaborators pull old code to back up local branches first, then re-clone after the force push.

### Q: How soon must secrets be rotated after a leak?

**Immediately.** GitHub's scanning bots detect secrets pushed to public repositories within minutes and notify the corresponding platform. AWS automatically disables leaked keys within 1-2 hours. Don't wait — rotate immediately.

### Q: Do private repositories also need secret scanning?

Yes. While the risk of secret leakage in private repositories is lower than in public ones, it still exists:
- Departing collaborators still hold secrets
- Repository accidentally made public
- Third-party integrations (CI/CD, code analysis) gain access
- Supply chain attacks

## Quick Reference

```bash
# Install tools
sudo ./scripts/secret_scan.sh --install

# Audit key management
sudo ./scripts/secret_scan.sh --audit

# Quick scan
sudo ./scripts/secret_scan.sh --scan --path /project

# Git history scan
sudo ./scripts/secret_scan.sh --scan-git --path /project

# Deep verification
sudo ./scripts/secret_scan.sh --deep --path /project

# Generate CI config
sudo ./scripts/secret_scan.sh --ci --output ./ci-configs
```
