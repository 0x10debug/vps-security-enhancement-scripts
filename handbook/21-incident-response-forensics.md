# Incident Response & Forensic Triage

> When the alarm fires, the clock starts. What you collect in the first hour determines whether you can answer "how did they get in?" — or whether you're left rebuilding blind.

## Overview

This chapter is the operational companion to [Chapter 03 (Incident Response)](03-incident-response.md). Chapter 03 covers the *mindset* — the first 10 minutes, what not to do, when to isolate. This chapter covers the *method*: a disciplined, repeatable forensic triage workflow that preserves evidence in order of volatility, builds a defensible chain of custody, and feeds directly into root-cause analysis and reporting.

We follow the **NIST SP 800-61** incident lifecycle and **RFC 3227** order-of-volatility, and we use the `scripts/incident_triage.sh` tool to automate read-only collection. The closed loop here is: **Problem (suspected compromise) → Investigate (collect & preserve evidence) → Fix (contain, eradicate, recover) → Verify (confirm root cause closed, attacker cannot return)**.

> ⚠️ **Read-only discipline**: The triage script and every command in this chapter are non-destructive. They never kill processes, delete files, or modify configs. Containment is a separate, deliberate step you take *after* evidence is preserved.

---

## Incident Response Phases (NIST SP 800-61)

NIST defines six phases. Triage sits at the boundary of **Detection & Analysis** and **Containment** — you collect enough to understand scope, then contain.

### 1. Preparation

Done *before* an incident. This is where 80% of incident response success is decided.

- Install and test the triage tooling (`incident_triage.sh`, `rkhunter`, `AIDE`, `auditd`)
- Document out-of-band communication (don't use the possibly-compromised server's email/chat to coordinate response)
- Know your provider's isolation/snapshot/console features
- Maintain a known-good baseline (AIDE database, package manifest) — see [Chapter 09 (CIS & STIG)](09-cis-stig-compliance.md)
- Pre-stage a forensic workstation or trusted jump host
- Run `incident_triage.sh audit` periodically as a baseline so you know what "normal" looks like

### 2. Detection & Analysis

Recognize the signal. Common detection sources:

- Monitoring alerts (high CPU, unexpected outbound traffic, disk fill) — [Chapter 04](04-security-monitoring.md)
- Provider abuse notification (spam, DDoS origin, blacklist)
- CrowdSec / Fail2Ban alerts — [Chapter 02](02-security-baseline.md)
- Anomalous logins (geo, time, frequency)
- Files changed that you didn't change
- A service behaving strangely

Once you suspect compromise, **stop poking**. Every command you run on a live system can tip off the attacker (if they have a rootkit) or overwrite volatile evidence (memory, process tables, network state). Move to triage collection immediately.

### 3. Containment

Stop the bleeding *without* destroying evidence. Short-term containment (isolate the host on the network) precedes long-term containment (clean the system or rebuild). See [Containment Strategies](#containment-strategies) below.

### 4. Eradication

Remove the attacker's foothold: malicious persistence (cron, systemd, authorized_keys, rootkits), backdoor accounts, compromised binaries. This is where you *do* delete things — but only after evidence is preserved and the root cause is understood.

### 5. Recovery

Restore from known-good backup or rebuild from a clean image. Verify the rebuilt system against the baseline before returning to production. See [Chapter 05 (Backup Security)](05-backup-security.md).

### 6. Lessons Learned

Write the post-incident report within 48 hours while memory is fresh. Answer: how did they get in, what was the impact, what detection gap let it run, what will you change? Feed findings back into Preparation.

---

## Triage Methodology: What to Collect and in What Order

### Order of Volatility (RFC 3227)

Collect the most fragile evidence first. Once it's gone, it's gone forever.

| Order | Artifact | Volatility | Tool |
|---|---|---|---|
| 1 | CPU caches, registers | seconds | (out of scope for VPS triage) |
| 2 | Memory (process state, network connections) | minutes | `ss`, `ps`, `/proc/*/maps` |
| 3 | Network state (connections, routing, ARP) | minutes | `ss`/`netstat`, `ip route` |
| 4 | Running processes | minutes | `ps aux`, `top` |
| 5 | Temporary files (`/tmp`, `/dev/shm`) | hours | `find`, `ls` |
| 6 | Disk (recently modified files, logs) | hours-days | `find -mtime`, log tails |
| 7 | Remote logs / backups | days-weeks | syslog server, backup-kit |

The `incident_triage.sh collect` command follows this order: it grabs processes and network state first, then persistence mechanisms, then logs, then filesystem, then user accounts.

### Triage Collection Checklist

In the first hour, collect (in this order):

1. **Network state** — established connections, listening ports, routing. An attacker's reverse shell shows up here *now*; it may not be there in 10 minutes.
2. **Processes** — full process list, process tree, top CPU/memory consumers, hidden PIDs, processes running deleted binaries.
3. **Memory maps** — `/proc/<pid>/maps` for top processes (full memory dumps are too large for VPS triage; maps show loaded libraries and anomalous regions).
4. **Persistence** — cron, systemd units/timers, rc.local, profile.d, authorized_keys, shell rc files, `/etc/ld.so.preload`. This tells you how they survive a reboot.
5. **Logs** — auth.log, syslog, audit log, web server logs, journalctl. Focus on failed logins, root logins, sudo, and suspicious entries.
6. **Filesystem** — recently modified files (24h), SUID/SGID binaries, world-writable files, `/tmp` contents, hidden files.
7. **User accounts** — UID 0 accounts, login shells, sudoers, recent logins.
8. **System info** — hostname, uptime, kernel, OS, who's logged in.

> **Why this order?** If the attacker detects you, the first thing they lose is network state and processes (they kill their tools). Persistence and logs on disk survive longer. Collect volatile first, durable second.

---

## Forensic Collection Best Practices

### Evidence Chain of Custody

Every artifact must be attributable, verifiable, and tamper-evident. The `incident_triage.sh` script handles this automatically:

- **Timestamp**: UTC ISO-8601 recorded in every artifact header and the manifest.
- **Collector identity**: `user@host` recorded in the manifest.
- **SHA-256 hashes**: every artifact is hashed; a `sha256sums.txt` file and `manifest.json` record all hashes. The archive itself is hashed.
- **Manifest**: a JSON manifest lists every file, its hash, and byte size. The `analyze` subcommand re-verifies hashes on extraction.

To preserve the chain after collection:

1. Copy the `.tar.gz` archive to **offline, trusted storage** immediately (a separate workstation, encrypted USB, or object storage you control). Don't leave the only copy on the possibly-compromised host.
2. Record the archive's SHA-256 in your incident log (the script prints it).
3. Never modify the archive. Work on copies. If you extract for analysis, extract into a fresh temp dir and discard it after.
4. Note who collected it, when, from where, and who has handled it since.

### Read-Only Discipline

The triage script is strictly read-only. It does not:

- Kill or signal any process
- Modify, delete, or create any system file (only creates files in your output directory)
- Install packages
- Change network state
- Restart services

This is critical: a panicked admin who starts killing processes and deleting files destroys the very evidence needed to understand the intrusion. **Collect first, act second.**

### Don't Tip Off the Attacker

If the attacker has an active rootkit or is watching for response activity:

- Avoid loud commands that scan the whole filesystem repeatedly (one `find` pass is fine; a loop is not)
- Don't restart services or reboot (clears memory, kills malware, destroys process state)
- Don't change passwords on the compromised host (a keylogger may capture the new one) — rotate from a known-clean host after isolation
- Consider collecting the triage archive and copying it off-host *before* any containment action

---

## Using the `incident_triage.sh` Script

The script lives at `scripts/incident_triage.sh` and is also reachable from the main menu (`e1` → Incident Triage). It requires root (to read system logs and process maps).

### Subcommands

| Command | What it does | Time |
|---|---|---|
| `collect` | Full read-only triage: all 7 categories + manifest + tar.gz archive | 1-3 min |
| `quick` | Fast overview: system, top processes, ports, connections, UID 0, cron, recent files | ~30s |
| `audit` | 16 read-only checks for incident indicators (PASS/WARN/FAIL) | ~10s |
| `analyze <archive>` | Extract & verify an archive, re-check hashes, scan for suspicious indicators | ~30s |
| `report <archive>` | Generate a human-readable summary report from an archive | ~10s |
| (no args) | Interactive wizard | — |

### Typical Workflow

```bash
# 1. You suspect compromise. FIRST, collect evidence (read-only, safe to run on live host):
sudo ./scripts/incident_triage.sh collect --output ./triage-out

# 2. Copy the archive OFF the host to trusted storage:
scp ./triage-out/incident-triage-*.tar.gz analyst@workstation:~/cases/

# 3. Run a quick audit for immediate indicators while you decide on containment:
sudo ./scripts/incident_triage.sh audit

# 4. On your workstation, analyze the preserved archive:
./scripts/incident_triage.sh analyze ~/cases/incident-triage-20260830143000.tar.gz

# 5. Generate a summary report for the incident record:
./scripts/incident_triage.sh report ~/cases/incident-triage-20260830143000.tar.gz
```

### What the Archive Contains

```
incident-<timestamp>/
├── manifest.json              # schema, timestamp, collector, per-file SHA-256
├── sha256sums.txt             # plain-text checksum list
├── 01-hostname.txt            # system info (hostname, uptime, uname, who, last)
├── 01-os-release.txt
├── 02-ps-aux.txt              # full process list
├── 02-ps-tree.txt             # process tree
├── 02-hidden-pids.txt         # /proc PIDs missing from ps (rootkit indicator)
├── 02-exe-paths.txt           # process exe paths (flags deleted binaries)
├── 02-memory-maps.txt         # /proc/<pid>/maps for top processes
├── 03-ss-all.txt              # all sockets
├── 03-ss-listen.txt           # listening ports
├── 03-established.txt         # established connections
├── 03-route.txt, 03-arp.txt, 03-dns-*.txt
├── 04-crontab-*.txt           # cron (root, /etc/crontab, /etc/cron.d, all users)
├── 04-systemd-*.txt           # services, timers, enabled units
├── 04-authorized-keys.txt     # SSH keys for all users
├── 04-ld-so-preload.txt       # rootkit indicator
├── 05-auth-log.txt, 05-syslog.txt, 05-messages.txt, 05-*.txt  # logs (last 500 lines)
├── 05-suspicious.txt          # grep of failed login / sudo / root entries
├── 06-recent-modified.txt     # files modified in last 24h
├── 06-suid-sgid.txt, 06-world-writable.txt, 06-tmp-contents.txt
├── 07-passwd.txt, 07-shadow.txt, 07-uid0.txt, 07-sudoers*.txt
└── 07-last-logins.txt, 07-lastb.txt
```

### The 16 Audit Checks (`audit` subcommand)

| ID | Check | FAIL means |
|---|---|---|
| IR-01 | UID 0 accounts = only root | extra root-level account (backdoor) |
| IR-02 | root password non-empty | trivially exploitable |
| IR-03 | no world-writable files in /etc | config tampering possible |
| IR-04 | no unusual SUID binaries | privilege escalation binary planted |
| IR-05 | /etc/ld.so.preload empty | rootkit hooking library loading |
| IR-06 | no processes running deleted binaries | malware deleted its own binary after launch |
| IR-07 | no hidden PIDs | rootkit hiding processes from ps |
| IR-08 | authorized_keys inventory | unexpected SSH keys present |
| IR-09 | cron has no suspicious entries | downloader/reverse-shell in cron |
| IR-10 | no executables in /tmp | malware staging in /tmp |
| IR-11 | SSH failure count | brute-force in progress |
| IR-12 | recent root logins | unexpected direct root access |
| IR-13 | non-system user inventory | unexpected new user account |
| IR-14 | no NOPASSWD:ALL sudoers | passwordless root for an attacker |
| IR-15 | established outbound count | excessive C2/beaconing connections |
| IR-16 | no recently modified system binaries | replaced system binaries (trojanized) |

A WARN (return code 2) is informational — investigate but don't panic. A FAIL (return code 1) is a strong indicator worth immediate follow-up.

---

## Common Attack Patterns and What to Look For

### 1. Cryptominer

**Signs**: sustained high CPU, process named `xmrig`, `kdevtmpfsi`, `kinsing`, random names in `/tmp` or `/dev/shm`, outbound to mining pools (stratum protocol, ports 3333/4444/5555/14444).

**Triage focus**: `02-ps-cpu-top.txt`, `02-exe-paths.txt` (often runs from /tmp or a deleted binary), `04-crontab-*.txt` (persistence via cron pulling the miner back), `03-established.txt` (pool connections).

### 2. Reverse Shell / C2 Beacon

**Signs**: outbound connection to an unknown IP on a non-standard port, process running `bash -i`, `nc`, `python -c 'import socket...'`, `perl -e`, frequent short-lived connections (beaconing).

**Triage focus**: `03-established.txt` (the connection), `02-ps-aux.txt` (the shell process, often a child of a web server or cron), `05-*.txt` logs (how it got launched — web exploit, cron).

### 3. SSH Brute-Force Success

**Signs**: many `Failed password` entries in auth.log followed by a single `Accepted password`/`Accepted publickey` from the same or nearby IP, then new user creation or authorized_keys addition.

**Triage focus**: `05-auth-log.txt` + `05-suspicious.txt`, `07-passwd.txt` (new users), `04-authorized-keys.txt` (planted keys), `07-last-logins.txt`.

### 4. Web Shell

**Signs**: unexpected PHP/JSP/ASPX files in web root, POST requests to odd filenames in access logs, process children of the web server running shell commands.

**Triage focus**: `06-recent-modified.txt` (new files in web root), `05-nginx-access.txt`/`05-apache-access.txt` (POST to suspicious URIs), `02-ps-tree.txt` (shell as child of nginx/apache/php-fpm).

### 5. Rootkit

**Signs**: hidden PIDs (in `/proc` but not in `ps`), `/etc/ld.so.preload` non-empty, system binaries with wrong checksums, `dmesg` shows nothing but system is clearly compromised.

**Triage focus**: `02-hidden-pids.txt`, `04-ld-so-preload.txt`, `06-recent-modified.txt` (modified `/usr/bin` binaries), `02-exe-paths.txt` (deleted binaries). Cross-check with `rkhunter` and `AIDE` from [Chapter 09](09-cis-stig-compliance.md).

### 6. Persistence via systemd

**Signs**: unexpected systemd services or timers, especially ones that download/execute from the internet or run from `/tmp`/`/home`.

**Triage focus**: `04-systemd-services.txt`, `04-systemd-timers.txt`, `04-systemd-enabled.txt`. Look for unit files in `/etc/systemd/system/` or `~/.config/systemd/user/`.

---

## Containment Strategies

**Containment happens after evidence collection.** The goal is to stop the attacker's access and spread without destroying the forensic record you just built.

### Network Isolation (preferred first step)

Isolate the host at the network layer so the attacker can't exfiltrate, beacon, or pivot — but the host stays running so evidence in memory and on disk is preserved.

- **Provider-level**: Most VPS providers (AWS, GCP, Azure, Hetzner, DigitalOcean) let you detach the public IP or place the instance in an isolated security group/VPC. This is the cleanest method — the host keeps running, you keep console access.
- **Host firewall**: If provider-level isn't available, drop all non-essential traffic:
  ```bash
  # Allow only your management IP, drop the rest (keep SSH to yourself)
  iptables -A INPUT -p tcp --dport 22 -s <your-ip> -j ACCEPT
  iptables -P INPUT DROP
  iptables -P OUTPUT DROP
  iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  ```
  ⚠️ Test this from a *second* session — don't lock yourself out. See [Chapter 02](02-security-baseline.md) firewall guidance.
- **Snapshot**: Take a provider snapshot *before* any further action. This is your forensic fallback if a containment step goes wrong.

### Process Kill (selective)

Only after evidence is collected and the network is isolated. Kill the specific malicious process(es), not the whole system:

```bash
# Identify the PID from your triage (02-ps-aux.txt)
kill -TERM <pid>      # graceful first
kill -9 <pid>         # force if needed
```

Do **not** reboot — rebooting clears memory, kills the malware, and may trigger a persistence mechanism that re-launches in a different form, making the trail harder to follow.

### Account Lockout

If the attacker has a known account or planted an SSH key:

```bash
# Lock a user account (prevents login, preserves the account for forensics)
usermod -L <username>      # lock password
# Remove a planted authorized_key (after recording its hash in your incident log)
# Rotate all credentials from a KNOWN-CLEAN host, not the compromised one
```

---

## Post-Incident Analysis and Reporting

### Root Cause Analysis

With the triage archive in hand, work backward from the attacker's foothold to the entry point:

1. **Persistence** → how do they survive reboot? (cron, systemd, authorized_keys)
2. **Process** → what was running? Trace parent processes to the launch point.
3. **Logs** → when did the attacker first appear? What happened just before? (web exploit, SSH login, package install)
4. **Files** → what was created/modified? Web shells, dropped tools, modified configs.
5. **Entry vector** → tie it together: e.g., "outdated web app → web shell → reverse shell → cron persistence → cryptominer."

### The Post-Incident Report

Write it within 48 hours. The `incident_triage.sh report` subcommand generates a skeleton; you fill in the analysis. A good report covers:

- **Timeline**: detection time, containment time, eradication time, recovery time
- **Scope**: what systems/data were affected
- **Entry vector**: how they got in (with evidence references to the archive)
- **Persistence mechanisms found**: list each, with the artifact file that shows it
- **Impact**: data exfiltrated? services degraded? lateral movement?
- **Detection gap**: why wasn't it caught sooner? What alert should have fired?
- **Actions taken**: isolation, eradication, recovery steps
- **Lessons learned**: concrete changes (patch the web app, enable CrowdSec scenario X, add monitoring for Y)
- **Evidence reference**: archive filename, SHA-256, storage location

---

## Legal Considerations and Evidence Preservation

If the incident may involve legal action (data breach notification, law enforcement, insurance claim, employment dispute), the forensic record must be defensible:

- **Don't alter the original archive.** Work on copies. Store the original write-protected.
- **Chain of custody log**: who collected the evidence, when, where it was stored, who accessed it, every transfer. The script's manifest records collection metadata; you maintain the handling log.
- **Timestamps in UTC**: the script records UTC ISO-8601. Keep your incident log in UTC too.
- **Don't over-collect private data.** The triage script captures `/etc/shadow` and user SSH keys — these are sensitive. Restrict access to the archive to the response team. Encrypt it at rest (e.g., `gpg -c archive.tar.gz`).
- **Preserve volatile evidence before powering off.** If you must power off (e.g., provider demands it for abuse), run `collect` first. A snapshot is not a substitute for volatile-state collection — snapshots don't capture memory or network state unless it's a memory-inclusive snapshot.
- **Know your obligations**: breach notification laws (GDPR Art. 33, various US state laws) may require notifying affected parties within 72 hours of becoming aware. The triage archive helps you determine *if* personal data was accessed and *when* the breach started.
- **Coordinate with your provider**: if the host is a VPS, your provider may have network logs (flow data, abuse reports) that complement your host-side collection. Request them early — providers rotate these.

> **The single most important rule**: when in doubt, collect and preserve before you act. A preserved archive you never need costs you a few minutes. A destroyed evidence trail you needed costs you the ability to ever answer "what happened."

---

## Cross-References

- [Chapter 03 — Incident Response](03-incident-response.md): the first-10-minutes mindset, "I've been hacked" decision flow
- [Chapter 02 — Security Baseline](02-security-baseline.md): Fail2Ban/CrowdSec detection that feeds triage
- [Chapter 04 — Security Monitoring](04-security-monitoring.md): the alerts that trigger triage
- [Chapter 05 — Backup Security](05-backup-security.md): recovery from known-good backups
- [Chapter 09 — CIS & STIG Compliance](09-cis-stig-compliance.md): AIDE/rkhunter baseline integrity
- [Cheatsheet — Forensics Commands](../cheatsheet/forensics-commands.md): one-page command reference
