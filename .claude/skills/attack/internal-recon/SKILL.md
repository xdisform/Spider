---
name: attack-internal-recon
description: Read-only inside-the-box enumeration once a shell:<host> is held — linPEAS stealth profile (never -a) or manual SUID/sudo/caps/cron/writable/interesting-files. Changes nothing; output is analysed locally. ATT&CK Discovery. Feeds privesc and loot; a found in-scope cred provides creds:<p>@<host>.
category: post-foothold
tags: [discovery, enumeration, linpeas, winpeas, suid, sudo, cron, read-only, post-foothold]
cwe_ids: [CWE-200, CWE-538]
chains_with: [attack-privesc, attack-loot, attack-lateral]
tools: [peass-ng, pspy]
version: "1.0"
---

# Internal recon (Discovery, read-only)

## Objective
Once a `shell:<host>` is honestly held, map the box **read-only**: who am I, what OS/kernel, what are the
privilege-escalation vectors (SUID/SGID, `sudo -l`, file capabilities, cron, writable paths), and where
do interesting files/creds live. This is the Discovery step (ATT&CK **T1082/T1083/T1033/T1057/T1518/
T1046**) that *feeds* `privesc` and `loot` — it **changes nothing** on the host.

## Gate (check BEFORE anything)
This class is `stage:"post-foothold"`; it only fires when the scheduler has already proven `shell:<host>`
(so a valid shell is held — you never log in, forge, or crack to obtain it). Run **every** on-host command
through `tools/leash-foothold.sh <target_dir> <host> <cmd>` — it host-pins the foothold channel and
refuses destructive verbs. If you somehow reached here without a shell, return
`proven_state:'blocked', blocked_reason:'needs_session'`.

## Methodology (read-only)
1. **Baseline:** `id; whoami; uname -a; hostname; cat /etc/os-release` (Linux) / `whoami /all; systeminfo`
   (Windows). Confirm the account and OS so the right lookup data (GTFOBins vs LOLBAS) applies downstream.
2. **PE vectors — automated (preferred):** linPEAS in the **stealth** profile only —
   `bin/.peass/linpeas.sh -s` (skips the slow/noisy checks). **NEVER `-a`** (its "all" mode adds process
   monitoring and **user brute-forcing** — forbidden). For Windows: `bin/.peass/winPEASx64.exe` /
   `winPEAS.bat`. linPEAS *enumerates*, it does not exploit; red/yellow findings are ~95% PE vectors.
   `pspy` (no root needed) is a safe read-only cron/process snoop.
3. **PE vectors — manual (when a script can't run):**
   - SUID/SGID: `find / -perm -4000 -type f 2>/dev/null` (and `-2000`)
   - sudo rights: `sudo -l` (no password prompt abused — read the policy only)
   - capabilities: `getcap -r / 2>/dev/null`
   - cron: `crontab -l; ls -la /etc/cron.* /etc/crontab; cat /etc/cron.d/*`
   - writable sensitive paths: writable `/etc/passwd`, service unit files, `$PATH` dirs, cron scripts
   - interesting files: `~/.ssh/`, `.env`, `*.conf`/DB configs, shell history, backups, mounted shares
4. **Analyse LOCALLY.** linPEAS/winPEAS output is parsed on the operator box, not on the target — only the
   script delivery/exec rides the leashed channel (mirrors the EXIF local-analysis split). Keeps heavy
   parsing off the target and the network quiet.

## What counts as a finding
Internal recon itself `provides:[]` — it produces **knowledge**, a map of vectors, not an elevation. Its
value is the concrete input to `privesc` (a specific SUID/sudo/caps/cron misconfig) and `loot` (where the
objective/creds live). **If** you read a credential or key for **another in-scope host**, that is a real
finding and `provides:["creds:<principal>@<that-host>"]` — the graph edge `lateral` consumes.

## Evidence
Under `raw/attack-<id>/`: the `leash-foothold.sh` ledger lines, the raw enumeration output (linPEAS log /
command transcripts), and a short local analysis naming the candidate vectors. A vector with no captured
output is a lead, not an asset.

## Red line
**Read-only. Change nothing.** linPEAS stealth only, never `-a` (no brute/process-snoop beyond `pspy`'s
passive read). No writes, no config edits, no persistence/implant, no destructive command — the
`leash-foothold.sh` denylist enforces this structurally. Everything stays on the single in-scope foothold
host; a credential found for a host **not** in `scope.yaml` is a LEAD recorded in `state.json`, never acted
on.
