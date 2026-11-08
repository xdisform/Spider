---
name: attack-loot
description: Bounded, objective-first Collection once a shell:<host>/foothold:<host> is held — read the flag/objective files first (the flag usually lives behind the foothold), then in-scope creds/keys. No mass-exfil, no whole-filesystem copy, no destruction. A found objective artifact is the execution_evidence for the P1 objective oracle; a found in-scope cred provides creds:<p>@<host>. ATT&CK Collection / Credential Access.
category: post-foothold
tags: [collection, loot, objective, flag, credentials, secrets, bounded, post-foothold]
cwe_ids: [CWE-522, CWE-312, CWE-200]
chains_with: [attack-internal-recon, attack-privesc, attack-lateral, attack-objective-capture]
tools: [peass-ng]
version: "1.0"
---

# Loot (Collection, objective-first, bounded)

## Objective
Read the **objective-relevant** files the foothold was *for* — the flag usually lives behind the foothold
(tickytask's EXIF-in-the-diagram endgame) — and then any in-scope credentials/keys that extend the graph.
ATT&CK **T1005** (Data from Local System) with Credential Access **T1552** (Unsecured Credentials) /
**T1555** (Credentials from Password Stores). This class is the primary **feeder** of P1's objective
oracle.

## Gate (check BEFORE anything)
`stage:"post-foothold"`, `requires:["shell:<host>"]` (OS files) **or** `["foothold:<host>"]` (app-level
read). Run every on-host read through `tools/leash-foothold.sh <target_dir> <host> <cmd>` — it bounds the
loot (byte cap + bulk-copy refusal) and refuses destructive verbs. Root-only targets may require
`requires:["admin:<host>"]` first (the `privesc` output).

## Methodology (objective-first, then secrets)
1. **Objective first.** Read `scope.objective.goal` + `scope.objective.flag_format` (and
   `objective.where_hint`). Go straight for it: the hinted file, the user/app home, the generated
   artifact. A single `cat <path>` (or `exiftool -a -u -g1 <file>` for metadata-hidden flags) is usually
   the whole game. **Match against `flag_format` and SAVE the producing command's output under `raw/`** —
   that saved artifact is your `execution_evidence` for the objective oracle.
2. **Then in-scope secrets (bounded):** the classic locations only —
   - SSH material: `~/.ssh/id_*`, `~/.ssh/config`, `known_hosts`, `authorized_keys` (**read** only)
   - app secrets: `.env`, `config.php`/`settings.py`/`application.yml`, DB connection strings
   - history + caches: `~/.bash_history`, `~/.*_history`, `.netrc`, cloud creds (`~/.aws/credentials`)
   - backups / dumps already present on disk
3. **Attribute creds to a host.** A credential/key that authenticates an **in-scope** host
   `provides:["creds:<principal>@<host>"]` — the edge `lateral` consumes. A cred for an out-of-scope host
   is a LEAD only.

## What counts as a finding (the oracle)
- **Objective / flag (feeds P1):** the looted string matches `scope.objective.flag_format`/`scope.objective.goal` **and**
  is **re-derivable from a saved file under `raw/`** (the looted artifact + the exact command that
  retrieved it). A value typed from memory or not traceable to a saved artifact **fails**.
- **Looted credential:** a real secret read from the host, attributed to an in-scope host; its proof is
  the file/command that produced it (the authenticated use is proven by `lateral`/`cred-access`, not here).

## Evidence
Under `raw/attack-<id>/`: the `leash-foothold.sh` ledger lines, the retrieved artifact(s), and the command
that produced each. Keep it **minimal** — the objective bytes + the specific secret, never a tree dump.

## Red line
**Bounded Collection.** Objective-relevant files and specific in-scope secrets only — **no mass-exfil, no
whole-filesystem copy, no archiving a tree** (`leash-foothold.sh` caps output bytes and refuses
`tar`-create / `scp -r` / `rsync` / `zip -r` of a tree), **no destruction**. Read, do not modify; never
append to `authorized_keys` or install anything (no persistence). A secret for an out-of-scope host is a
lead, never acted on.
