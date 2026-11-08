---
name: attack-auth-bypass
description: Authentication/authorization bypass — reach protected endpoints and actions via 403 busting, forced browsing, and privilege escalation.
category: web-application
tags: [auth, authz, access-control, forced-browsing, privilege-escalation]
cwe_ids: [CWE-287, CWE-284]
chains_with: [attack-jwt, attack-idor]
tools: [nomore403, ffuf, jwt-hack, curl]
version: "1.0"
---

# Auth / authz bypass

## Objective
Reach a protected endpoint, action, or identity you should not — proven by the response you get with
the boundary crossed, shown before/after. A `200` on an admin path is not enough; the protected
content or the completed privileged action is. Runs go through the leash:
`tools/leashed.sh $T bin/<tool> …` (`$T` = target dir).

## Methodology
1. **Map the boundary.** From recon, list what should be gated: `/admin`, internal APIs, other users'
   actions, and the auth model (session cookie, bearer/JWT, role claim, IP allowlist). Note which
   return 401/403 vs redirect.
2. **Forced browsing.** Discover hidden protected surface:
   `tools/leashed.sh $T bin/ffuf -u "$U/FUZZ" -w wordlists/content.txt -mc 200,301,302,401,403 -o raw/auth/ffuf.json`.
   Every 401/403 is a candidate to bust in step 3; every unexpected 200 is a candidate leak.
3. **Bust 401/403.** Run nomore403 over each gated path — it sweeps header injection
   (`X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL`), verb tampering, path/case/encoding tricks,
   and trailing chars: `tools/leashed.sh $T bin/nomore403 -u "$U/admin"`. A technique returning the
   protected body (not just 200) is the crossing — capture which trick worked.
4. **Privilege escalation.** As a low-priv identity, invoke high-priv actions: tamper `role`/`isAdmin`
   in body/JWT (forge via `attack-jwt`), replay an admin-only request with your own session, or hit
   an object that belongs to another tenant (chain `attack-idor`). Show low-priv → high-priv result.
5. **Missing auth.** Retry protected requests with the credential stripped entirely (no cookie/token)
   — an unauthenticated success is the most severe form.

## What counts as a finding
- **Critical/High:** a protected action completed or protected data returned without the required
  auth/role — before/after showing the boundary crossed. Unauthenticated access to admin = critical.
- **Lead only:** a bypass returns `200` but an empty/placeholder/your-own-scope body, or a discovered
  path with no protection to cross — a `[UNCONFIRMED CANDIDATE]` (see `poc-standard`).

## Evidence
Under `raw/auth/`: the baseline denied request/response, the bypassing request (with the exact trick —
header, verb, path, or forged token), and the protected response it unlocked, side by side, plus a
runnable PoC and one-line repro. All target-facing HTTP goes through `tools/leashed.sh`.
