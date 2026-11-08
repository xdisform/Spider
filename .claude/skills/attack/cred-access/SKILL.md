---
name: attack-cred-access
description: Bounded, policy-gated default/weak-credential CONTROL-TEST on non-HTTP services (ssh/ftp/smb/db/...) — spray-not-brute, capped, lockout-aware. Proves a service ships a default cred (a control is absent); it is NOT a brute-force of others.
category: network-service
tags: [credentials, default-creds, ssh, ftp, smb, control-test, foothold]
cwe_ids: [CWE-1392, CWE-521, CWE-287]
chains_with: [attack-idor, attack-auth-bypass]
tools: [nuclei, netexec]
version: "1.0"
---

# Credential access (default-cred control-test)

## Objective
Prove that an in-scope non-HTTP service accepts a **default or well-known-weak** credential — i.e. the
control (strong, non-default auth) is **absent**. A proven cred is a **foothold**: it `provides`
`creds:<principal>@<host>` / `session:<host>`, which unlocks the dependent hypotheses the scheduler held
back. This is a **control-test, not a brute-force**: a tiny curated set, one attempt per principal,
lockout-aware, stop-at-first. Brute-forcing another person's password is forbidden and out of scope.

## Gate (check BEFORE anything)
Run **only** if `scope policies.default_cred_control_test.enabled` is true **and** `<service>` is in
`policies.default_cred_control_test.services`. If not, STOP and return
`proven_state:'blocked', blocked_reason:'policy'` with a `note` on what the operator would need to enable.
Do not attempt a single login before this gate passes.

## Methodology (spray-not-brute)
1. **Pre-condition.** Only act where the auth even applies: SSH offers `password` auth; FTP/SMB allow the
   login mode you're testing. (nuclei's default-login templates enforce this as a template pre-condition.)
2. **Route through the enforcer.** Every attempt goes through `tools/leash-cred.sh <target_dir> <host> <cmd>`
   — it host-pins (via `guard.py --cred-mode`), paces with an explicit delay+jitter (burst = 1), keeps a
   per-(host,principal) attempt ledger capped at `max_tries_per_principal`, and aborts on a lockout signal.
3. **Primary engine — nuclei default-logins** (already shipped, structurally safe):
   `bin/nuclei -t bin/.nuclei/default-logins -u <svc>://<host> -nc` — `attack: pitchfork` (line-by-line
   SPRAY, not cartesian), `stop-at-first-match`, pre-condition gated. Prefer this.
4. **Secondary — NetExec** when you need multi-protocol breadth: `nxc <proto> <host> -u users.txt -p pass.txt
   --no-bruteforce` (the `--no-bruteforce` pairs line-by-line = spray; `guard.py --cred-mode` REJECTS the
   command without it). Small curated sets only (`default-creds-curated`, ≤ `max_pairs`).
5. **Fallback — patator** `--rate-limit <= inter_attempt_delay_s`, one pass, `-x ignore:...` on failure.
6. **Stop conditions (hard):** stop at the first valid pair; stop on ANY lockout/throttle/`429`/tarpit
   signal and return `proven_state:'blocked', blocked_reason:'policy'`; never exceed `max_pairs` or
   `max_tries_per_principal`; never `--continue-on-success` past the one-pass spray; never OTP/2FA brute.

## What counts as a finding
- **Finding (severity by CVSS, often high):** a default/weak cred that **works** — proven by a REAL
  authenticated action with it (SSH `id`/`whoami` within the RCE safe-PoC policy; an authenticated
  directory listing; a DB `SELECT @@version`). The scanner's `[+]` line is NOT proof (nuclei has had
  false-positive issues) — the oracle is the authenticated action.
- **Lead / N/A:** no default cred accepted, or the pre-condition didn't apply (key-only SSH) — an honest
  negative, report it as such.

## Evidence
Under `raw/attack-<id>/`: the `guard.py --cred-mode` check that authorized the command, the
`leash-cred.sh` ledger lines, the tool output, and the **authenticated-action proof** (the oracle). A
proven cred is written to `state.json.creds` by the synthesizer and `provides` its capability tokens.

## Red line
Spray not brute; curated set not wordlist dump; capped and lockout-aware; one host pinned, never a range.
Proving a control is absent (a default cred ships) is authorized control-testing; account-takeover of
others, flooding, cartesian brute, and evading a lockout are forbidden.
