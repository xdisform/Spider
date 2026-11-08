---
name: auth-flow
description: Map the target's authentication — login, OAuth, JWT, session and reset/registration flows and their token shapes.
category: recon
tags: [osint, auth, jwt, oauth, session]
chains_with: [attack-jwt, attack-idor, access-control]
tools: [katana, httpx, jwt-hack]
version: "1.0"
---

# Auth-flow mapping

## Objective
Understand how the target authenticates and tracks identity — the flows, the token shapes, the roles
— so the attack phase knows where the boundaries sit. Read-only: observe, never bypass here.

## Methodology
1. **Find the flows.** From the crawl (`endpoint-deep`) locate login, logout, register, password
   reset, MFA, and OAuth/SSO endpoints. `httpx -sc -location -json` to see redirects and set-cookie.
2. **Read the tokens.** Capture what a normal session issues: cookie flags (HttpOnly/Secure/
   SameSite), bearer tokens, any JWT. Decode JWTs offline with `jwt-hack` — note `alg`, `kid`,
   issuer, claims, and whether `alg:none`/weak-secret looks plausible (proof happens later in
   `attack-jwt`).
3. **Map registration/reset.** How accounts are created, how reset tokens are formed (guessable?
   emailed? returned in-response?), whether email verification is enforced, and if role can be
   self-selected at signup.
4. **Enumerate roles.** With test accounts you control, record which flow yields which role/scope and
   how the app represents it (a claim, a cookie, a path). This feeds `access-control` and IDOR.

## What to return
The auth surface: each flow's endpoints, the token/session shape (with a decoded sample), how role
is represented, and any weak-looking construction called out as a **lead** (guessable reset token,
weak JWT alg, missing cookie flags). Save decoded tokens and flow captures under `raw/<label>/`.

## Notes
Use only test accounts you control — never a real user's credentials or session. Login and flow
requests are target-facing → `tools/leashed.sh`; decoding tokens with `jwt-hack` is offline. A weak
token shape is a lead; the bypass is proven in the attack phase per `poc-standard`, not claimed here.
