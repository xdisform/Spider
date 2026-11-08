---
name: attack-privesc
description: Enumerate → look up → ONE deterministic single-step privilege escalation from a CONCRETE misconfig (GTFOBins SUID/sudo/caps, LOLBAS, or a known-CVE one-shot). The oracle is a DEMONSTRATED privileged action (id→uid=0 / root-only read), never a scanner's colour. Forbidden: brute/crack root, box-crashing kernel exploits, persistence. provides:["admin:<host>"].
category: post-foothold
tags: [privilege-escalation, gtfobins, lolbas, suid, sudo, capabilities, admin, post-foothold]
cwe_ids: [CWE-250, CWE-269, CWE-732]
chains_with: [attack-internal-recon, attack-loot]
tools: [gtfobins-data, lolbas-data, peass-ng]
version: "1.0"
---

# Privilege escalation (ONE oracle-proven step)

## Objective
Turn a **concrete** enumeration finding into **one** deterministic, single-step escalation to a privileged
account, and **prove** it with a demonstrated privileged action. ATT&CK **T1548** (Abuse Elevation Control)
/ **T1068** (Exploitation for PrivEsc) / **T1078** (Valid Accounts). On proof it
`provides:["admin:<host>"]`, which unlocks any `requires:["admin:<host>"]` loot (root-only files).

## Gate (check BEFORE anything)
`stage:"post-foothold"`, `requires:["shell:<host>"]` — fires only after a shell is proven. Run every
on-host command through `tools/leash-foothold.sh <target_dir> <host> <cmd>`. You need a **concrete vector
from `internal-recon`** (a specific SUID binary, a `sudo -l` entry, a writable cron/caps). Without one,
return `proven_state:'not_reproduced'` (no vector) — do **not** sweep exploits blindly.

## Methodology (enumerate → lookup → ONE step)
1. **Take ONE concrete misconfig** from `internal-recon` (e.g. `sudo -l` allows `/usr/bin/find`; `vim` is
   SUID-root; `python3` has `cap_setuid+ep`).
2. **Deterministic lookup — no brute:**
   - **Linux → GTFOBins** (`bin/.gtfobins`, offline `api.json` + per-binary pages): filter the dataset for
     that binary's **Sudo** / **SUID** / **Capabilities** function → you get the **one exact command**
     (e.g. `sudo find . -exec /bin/sh \; -quit`, `./vim -c ':!/bin/sh -p'`).
   - **Windows → LOLBAS** (`bin/.lolbas`, `api/lolbas.json`): match the binary's `Commands[]` by
     `Privileges`/`Category` (UAC Bypass/Execute) and OS → the single documented command.
   - **Known-CVE:** only a **single public one-shot** for a confirmed version — never a chain of exploits.
3. **Execute the single step** through `leash-foothold.sh` (safe-PoC: spawn a proof shell / run `id`).
4. **Prove it (the oracle).**

## What counts as a finding (the oracle)
`admin:<host>` is granted **only** on a **demonstrated privileged action**, never on linPEAS's colour or a
suggestion:
- `id` → `uid=0(root)` (or the elevated group/role), shown **before and after** the step, **or**
- a **root-only file read** within the program's safe-PoC policy (e.g. the first bytes of `/etc/shadow`).
Capture under `raw/validate-<id>/`. A plausible vector that you did **not** convert to a proven privileged
action is a `not_reproduced` lead — not a finding.

## Evidence
Under `raw/attack-<id>/` and `raw/validate-<id>/`: the `internal-recon` vector cited, the GTFOBins/LOLBAS
entry used, the `leash-foothold.sh` ledger line, and the before/after `id` (or the root-only byte
signature) that is the oracle.

## Red line
**ONE deterministic single step from a concrete misconfig.** FORBIDDEN: brute-forcing or cracking root's
password; a **destructive or box-crashing kernel exploit** (route those to `human_review` via
`proven_state:'blocked'`); any **persistence/implant/backdoor** (Spider models no persistence, and the
`leash-foothold.sh` denylist refuses `useradd`/`authorized_keys`/cron-install/etc. structurally). If
proving it would require defeating a control **as an attack**, STOP → `proven_state:'blocked',
blocked_reason:'safeguard'` (a hand-off, never an evasion).
