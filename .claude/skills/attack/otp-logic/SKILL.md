---
name: attack-otp-logic
description: Prove a LEGITIMATE, non-brute OTP/2FA logic flaw into a server-valid session (leak, account-binding repoint, predictable/reused code, simple-bypass, loose-compare). A foothold producer. Never brute the code space; never touch a safeguard-flagged path.
category: authentication
tags: [otp, 2fa, mfa, auth, foothold, logic-flaw, session]
cwe_ids: [CWE-287, CWE-640, CWE-308, CWE-310, CWE-304]
chains_with: [attack-idor, attack-auth-bypass, access-control]
tools: [curl, httpx, hurl, jwt-hack, flask-unsign]
version: "1.0"
---

# OTP/2FA logic (attack class)

## Objective
Turn a recon `otp-logic` hypothesis into a **server-valid session** by a legitimate logic flaw — the
second foothold door. A proven session is a foothold: it `provides` `session:<host>`, unlocking the
dependent hypotheses (BOLA/IDOR/authenticated actions) the F4 scheduler held back. This is the exact
door the tickytask register-crash could not open inside the red line.

## Red line (read before you act)
This is a LOGIC play, **never a brute of the code space** (forbidden flood) and **never** an attack
on a safeguard-flagged path (e.g. the register-crash). Do not evade any safety refusal. If the only
remaining play is code-brute or crossing the safeguard, STOP and return
`proven_state:'blocked', blocked_reason:'safeguard'` with a `note` on the narrow control-test a human
could run. A safeguard block is a hand-off, not evidence the bug is absent. Own test accounts only;
stop at the first valid session.

## Ordering rule (the honest-scope lesson — do this first)
Determine the session shape: forge a bare/garbage session value and request a protected page.
- **401/403 => server-signed session.** Rank **leak -> binding -> predictable/reuse** first;
  pursue response/status tampering LAST or not at all — tampering a server-validated flow fools only
  the SPA and mints no server-valid session (so it never reaches the BOLA).
- **200 w/ client-trusted flag => the client decides.** Response/status tampering is in play
  (Synack: `400 {"size":0}` -> `200 {"size":1}`, `"actionResult":"challenge"` -> `"success"`).

## Methodology (prove ONE to a server-valid session, then stop)
1. **Leak.** The code or a `pending`/`mfa`/`otp_token` was returned in the pre-OTP response or a
   `/resend`/`/me` follow-up -> submit it to the verify endpoint; capture the minted session.
2. **Account-binding repoint.** The verify request carries a client-controlled
   `account`/`user`/`username`/`verify` field -> set it to the victim, submit YOUR OWN delivered
   code, reach the victim's authenticated resource (PortSwigger broken-logic).
3. **Predictable / static / reuse.** Derive the next code from observed staticness/sequence and use
   it ONCE; or replay a used/expired code if it is still accepted.
4. **Simple-bypass.** Reach a post-login resource directly after step-1 creds, with no code.
5. **Loose-compare / type-confusion.** A SINGLE well-formed probe per variant: numeric vs string,
   leading-zero, `null`, `[]`, `"000000"`, boolean. Not a sweep — one honest probe each.

## The oracle (no oracle, no finding)
A **protected resource/identity reached with a SERVER-VALID session** minted via the OTP step:
`401/403 -> 200` with privileged content that **re-fetches cleanly in a fresh request** (proving the
session is server-side valid, not an SPA state flip). Save the OTP submission request/response + the
authed-resource fetch under `raw/attack-<id>/`. `oracle_type:'otp-logic-session'`. The validator
(`proof/oracles/SKILL.md`) re-derives it. For account-binding, the privileged content must be the
VICTIM's (owner-id != you), same discipline as BOLA.

## What counts
- **Finding (severity by CVSS — auth bypass to a session is commonly high):** a server-valid session
  via one of the logic paths, oracle-met.
- **Foothold:** the session `provides:["session:<host>"]`; the synthesizer records the capability so
  the next wave unlocks the dependents.
- **Lead / blocked:** no logic flaw found => honest `not_reproduced`. Only a code-brute or
  safeguard-path would reach it => `blocked, blocked_reason:'safeguard'` (hand off; do not attempt).

## Red line (restated)
No brute of the code space, no flood, no touching a safeguard-flagged path, stop at first valid
session. Proving a broken OTP *logic* is authorized testing; grinding the code space or evading a
safeguard is not.
