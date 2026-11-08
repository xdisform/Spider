---
name: nonhttp-cred-surface
description: Read-only recon of non-HTTP services (ssh/ftp/smb/rdp/db/...) — fingerprint version + auth mode and emit foothold-producer hypotheses for a bounded default-cred control-test. No login attempts here.
category: recon
tags: [ssh, ftp, smb, credentials, non-http, foothold]
chains_with: [port-service, auth-flow]
tools: [nuclei, naabu]
version: "1.0"
---

# Non-HTTP service & credential surface

## Objective
Turn the open non-HTTP ports `port-service` found into **foothold hypotheses**. For every non-HTTP
in-scope service, fingerprint its version and auth mode **read-only**, identify the product so the
right small default-cred set applies, and emit `class:<svc>-default-cred` hypotheses that the attack
phase may prove **only if the scope enables the control-test**. A reachable non-HTTP service is a
first-class **foothold producer** in the attack dependency graph — it is the SSH/FTP door the
web-centric phases never owned. **No login attempts in recon — this lens is strictly read-only.**

## Methodology (read-only)
1. **Pin scope first.** Non-HTTP tools don't honor the HTTP leash — gate every command with
   `python tools/guard.py --scope "$LEASH_SCOPE" --check "<cmd>"` and route through
   `tools/leash-tcp.sh <target_dir> <host> <cmd>`. One host, never a range, never `-iL`.
2. **Banner + version.** Grab the service banner / version (SSH `OpenSSH x.y`, FTP `220`, SMB dialect,
   DB handshake). This names the product → which small default set is even relevant.
3. **Auth-mode pre-condition (the key signal).** Determine whether a credential control-test could
   *legitimately* apply, without attempting a login:
   - **SSH:** does the server offer `password` auth at all? (`nuclei` default-login SSH templates check
     `response.UserAuth` includes `password` as a pre-condition; if it's key-only, a password control-test
     is N/A — say so.)
   - **FTP/SMB:** is **anonymous** login advertised/allowed? (an anonymous read is itself a finding lead.)
   - **DB/redis/vnc:** is auth required at all, or open? (an unauthenticated datastore is an
     `exposed-datastores` lead, not a cred test.)
4. **Emit the hypothesis.** For each service where a bounded default/weak-cred control-test could apply,
   emit a hypothesis: `class: ssh-default-cred | ftp-anonymous | smb-default-login | <svc>-default-cred`,
   `stage: "foothold"`, `provides: ["creds:<principal>@<host>", "session:<host>", "foothold:<host>"]`,
   a concrete `how_to_prove` (which template/set, pre-condition, expected oracle = a real authenticated
   action), and the evidence path. Mark `confidence` by how strong the signal is.

## What to return
Per service: version, auth mode, the pre-condition verdict (control-test applies / N/A and why), and the
foothold hypothesis with its `provides` tokens. If the product offers no password/anon surface, return it
as N/A — that is a real, honest result, not a gap.

## Evidence
Banner grabs + the `guard.py` check that authorized each probe + any `nuclei` detect-mode output, all
under `raw/nonhttp-cred-surface/`. A claim with no evidence file is a lead, not an asset.

## Red line
Recon here is **observation only**. The actual control-test runs in the attack phase via the
`cred-access` class, and **only** if `scope policies.default_cred_control_test.enabled`. Never attempt a
login in recon, never flood, never a range. Proving a *control is absent* (a default cred ships) is a
control-test; brute-forcing another person's account is forbidden.
