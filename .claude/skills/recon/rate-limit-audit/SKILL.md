---
name: rate-limit-audit
description: Prove the ABSENCE of a rate-limit / account-lockout control — a paid defect class — without brute-forcing anyone.
category: recon
tags: [rate-limit, control-test, lockout, auth, brute-as-control]
tools: [rate-limit-probe.py, curl, httpx]
version: "1.0"
---

# Rate-limit / lockout control audit

## Objective
Demonstrate that a sensitive endpoint (login, OTP, password-reset, token, API key) enforces **no
rate-limit or lockout** — a real, frequently-paid control defect — by showing N requests go through
without a `429`/`419`/lockout. This is a **control test, not a brute-force**: you never try to guess
another person's credentials; you use your OWN test account (or a benign endpoint) and count.

> Only run this when the target's `scope.yaml` `policies.rate_limit_test.enabled: true`. Respect
> `max_requests_per_endpoint` and `own_accounts_only`. It runs THROUGH the leash — audited, header-
> tagged, in-scope.

## Methodology
1. **Pick the endpoint.** A login/OTP/reset/token endpoint on a critical-priority host. Use your own
   test account with a wrong password (login) or your own identifier (OTP/reset) — never a real user.
2. **Run the control-test through the leash:**
   ```bash
   python tools/rate-limit-probe.py --target-dir <target_dir> \
     --url https://<host>/<auth-endpoint> --method POST \
     --data '{"username":"<own-test-acct>","password":"wrong"}' --count 50
   ```
   It records the status curve and stops early if it ever sees `429`/`419`.
3. **Interpret.** No `429`/`419`/lockout after the cap → **control defect**. A lockout/limit → control
   present (record which request number triggered it). OTP/reset endpoints with no limit = often HIGH
   (enables offline/online brute by others). Login with no lockout = HIGH/CRIT depending on the program.
4. **Do NOT** exceed `max_requests_per_endpoint`, never target other users, never flood beyond the cap.

## What counts as a finding
- **High/Critical:** an authentication/OTP/reset endpoint with no rate-limit or lockout, proven by the
  status curve (e.g. 50× `200/401` with zero `429`). Severity per the program's own class ceiling.
- **Lead only:** a non-sensitive endpoint with no limit, or a limit you did hit.

## Evidence
The `raw/rate-limit/<host>.json` curve (all status codes + verdict) and the leash audit lines proving
the requests were in-scope and paced. State clearly it was your own account.
