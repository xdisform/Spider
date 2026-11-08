---
name: otp-logic
description: Inspect an OTP/2FA step's LOGIC (leak, account-binding, predictability, enforcement, reuse, loose-compare) to find a legitimate, non-brute path to a session. Never brute the code space.
category: recon
tags: [osint, auth, otp, 2fa, mfa, foothold, logic-flaw]
cwe_ids: [CWE-287, CWE-640, CWE-308, CWE-310]
chains_with: [auth-flow, access-control, attack-otp-logic]
tools: [httpx, curl, jwt-hack, flask-unsign]
version: "1.0"
---

# OTP/2FA logic (recon lens)

## Objective
When login gates behind an OTP/2FA step, understand the step's **logic** so the attack phase knows
which legitimate play reaches a session — never the code space. Read-only: observe and emit
hypotheses; the session is PROVEN in attack. A reachable OTP gate is a **foothold producer** for the
F4 dependency graph (`stage:foothold`, `provides:["session:<host>"]`).

## Red line (read first)
Observation + logic only. NEVER brute the OTP code space (that is forbidden flood). NEVER touch a
safeguard-flagged path (e.g. a register-crash the fleet is blocked on). Use only test accounts you
control; honor `policies.forbidden:[flood]` and the rate cap. A leaked/guessable/repointable/reusable
code is a **lead**; it is never "exploited" here.

## Methodology (WSTG-ATHN-11 + PortSwigger + Synack, all inside the red line)
1. **Trigger.** Identify the OTP gate from the auth-flow map — e.g. login `409/200` ->
   `POST /api/auth/otp|/verify|/login2`. Capture the full pre-OTP response (body + headers +
   `Set-Cookie`) with `tools/leashed.sh`.
2. **LEAK (highest value, zero risk — the check tickytask skipped).** Grep that response and any
   `/resend`, `/me`, `/refresh` follow-up for the code itself or a `pending`/`mfa`/`otp_token` value
   that the verify endpoint would accept. If the second factor is a token returned to the client, it
   is no factor at all.
3. **BINDING.** Does the verify request carry a **client-controlled** `account`/`user`/`username`/
   `verify` field (tickytask's `{username, otp}` does)? Flag an account-binding candidate — attack
   repoints it to a victim and submits the attacker's OWN delivered code (PortSwigger broken-logic;
   WSTG "tied to the correct user account").
4. **PREDICTABLE/STATIC.** Request your OWN code twice (own account, within caps) and diff —
   identical, sequential, or constant-seeded => predictable. TOTP/HOTP seeded with a constant or a
   wide accept-window (prev/current/next all valid) is a control defect. No brute.
5. **ENFORCEMENT (simple-bypass).** After the gate, request a post-login page directly — authed
   content without the code => the step is not enforced server-side.
6. **REUSE.** Is a used or expired code still accepted on a later submit (own account)?
7. **LOOSE-COMPARE.** Note how the field is compared: numeric vs string, leading-zero, `null`, `[]`,
   `"000000"` — a SINGLE well-formed probe per variant, policy-capped, for attack to test.

## Session-shape check (sets the attack ordering)
Record whether the session is a **server-signed cookie** (forge a bare value -> 401) or a
client-trusted flag. If server-signed, mark the hypotheses so attack ranks **leak/binding/
predictable** above response-tampering (tampering a server-validated flow fools only the SPA).

## What to return
`class:"otp-logic"` hypotheses (one per surface: `leak` / `account-binding` / `predictable` /
`simple-bypass` / `reuse` / `loose-compare`), each `stage:"foothold"`, `provides:["session:<host>"]`,
`requires:[]`, with the captured evidence file under `raw/<label>/` and a concrete `how_to_prove`.
Also return the session-shape note.

## Notes
Login/verify requests are target-facing -> `tools/leashed.sh`; decoding a `pending`/JWT token with
`jwt-hack`, or a Flask cookie with `flask-unsign`, is offline. A weak OTP logic is a lead; the
server-valid session is proven in `attack/otp-logic`, never claimed here. The two highest-value,
zero-risk checks (LEAK + PREDICTABLE) can be machine-checked on already-captured responses with
`python tools/otp-logic-probe.py` — it touches no network and feeds attack a deterministic candidate.
