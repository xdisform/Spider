---
name: oauth-pkce
description: Map the OAuth2/OIDC flow — authorization-code + PKCE, redirect_uri handling, state/nonce, token endpoints, implicit leftovers — and the redirect-to-token-theft surface. Read-only.
category: recon
tags: [oauth, oidc, pkce, redirect-uri, token, sso]
chains_with: [auth-flow, attack-open-redirect, attack-jwt, attack-cors]
tools: [httpx, curl]
version: "1.0"
---

# OAuth2 / OIDC flow mapping

## Objective
Understand exactly how the target's OAuth/OIDC works — the endpoints, the grant, and how
`redirect_uri`, `state`, `nonce` and PKCE are validated — so the attack phase knows which theft surface
is real. **Read the flow; do not exploit here.** Every seam becomes a finding only when the attack phase
proves it per `poc-standard`.

## Methodology
1. **Find the endpoints.** From the crawl and the discovery document, capture the authorization, token,
   jwks, userinfo and revocation endpoints:
   ```bash
   tools/leashed.sh targets/<t> bin/httpx -u https://<host>/.well-known/openid-configuration -json
   ```
2. **Read one full flow (own test account).** Walk a login and record every parameter on the authorize
   request: `response_type` (`code` vs `token` — an implicit leftover?), `client_id`, `redirect_uri`,
   `scope`, `state`, `nonce`, and `code_challenge` + `code_challenge_method` (PKCE present? `S256` or
   `plain`?). `curl -sD-` each hop through the leash, following the redirects to the callback.
3. **Probe redirect_uri validation (read-only).** Note how strict the match is — exact vs prefix vs
   substring, whether an extra path/query/fragment, a sibling subdomain, or an open redirect on an
   already-allowlisted host would satisfy it. Do **not** complete a theft; record only whether the seam
   exists (a loose match + an open redirect on an allowed host = the classic code/token-exfil chain →
   `attack-open-redirect`).
4. **Read the token + anti-replay posture.** Is `state` bound to the session and verified on callback
   (CSRF on the OAuth dance)? Is `nonce` checked in the `id_token`? Is PKCE actually enforced at the
   token endpoint (does a code redeem with a missing or mismatched verifier)? Decode the tokens offline
   with `bin/jwt-hack` for `alg`/`kid`/claims — a weak `alg` is a lead for `attack-jwt`.

## What counts as a finding
- **Nothing is proven here** — this lens produces a map and leads. A missing or `plain` PKCE, a loose
  `redirect_uri` match, an unverified `state`, or an implicit-grant leftover are **leads**; each becomes
  a finding only when the attack phase demonstrates account takeover or code/token theft per
  `poc-standard` (proven ATO = critical). Call each seam out explicitly with the chain that would prove
  it (`attack-open-redirect`, `attack-cors`, `attack-jwt`).

## Evidence
The discovery JSON, the full authorize→callback→token capture with every parameter, a decoded sample
token, and each seam recorded as a lead with its proving chain — all under `raw/<label>/`. Use only test
accounts you control; all requests go through `tools/leashed.sh`.
