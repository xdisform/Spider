---
name: session-fixation
description: Map the session + CSRF surface — cookie flags, Set-Cookie on the auth boundary, fixation vs rotation, CSRF token presence/binding, logout invalidation.
category: recon
tags: [session, csrf, cookies, fixation, samesite, logout]
chains_with: [auth-flow, attack-cors, attack-idor, attack-auth-bypass]
tools: [httpx, curl]
version: "1.0"
---

# Session + CSRF surface mapping

## Objective
Read how the target issues, protects, rotates and revokes session identity, and whether state-changing
actions are CSRF-protected — so the attack phase knows which boundary to push. **Read-only:** observe the
flags and lifecycle; the bypass is proven later per `poc-standard`. Use only test accounts you control.

## Methodology
1. **Inventory the cookies.** On an authenticated flow, capture every `Set-Cookie` and its flags —
   `HttpOnly`, `Secure`, `SameSite` (None/Lax/Strict), `Path`, `Domain`, expiry:
   ```bash
   tools/leashed.sh targets/<t> curl -sD- -o /dev/null https://<host>/login \
     --data 'user=<own-acct>&pass=<own-pass>'
   ```
   A session cookie missing `HttpOnly`/`Secure`, or with `SameSite=None`, is a lead (feeds
   `attack-cors` and XSS-to-session-theft).
2. **Test fixation vs rotation (own accounts).** Record the pre-auth session id, authenticate, then
   compare: does the id **change** on the privilege boundary (login), or is the pre-auth id reused
   post-login? A reused id = a session-fixation seam — capture the before/after ids on the two accounts
   you control.
3. **Map the CSRF posture.** For each state-changing endpoint (settings, email/password change,
   transfer, role change) record whether a CSRF token is present, whether it is **bound to the session**
   (swap in another of your sessions' token — does it still validate?), and whether `SameSite` alone is
   the only defense. Read-only: note presence/binding; the forgery is proven in the attack phase.
4. **Logout + lifecycle.** After logout, replay a captured pre-logout cookie/token — is it invalidated
   server-side or still accepted? Do password change, reset, and concurrent-session limits invalidate
   old sessions? Each gap is a lead with a before/after transcript.

## What counts as a finding
- **Confirmed here** only where the lifecycle proof is self-contained on your own accounts: a session id
  **not rotated on login** (fixation), or a session/token still accepted **after logout or password
  change** — shown with the before/after transcript (typically medium; high when it enables takeover of
  another identity, which is proven in the attack phase).
- **Lead only:** a missing cookie flag, an absent or unbound CSRF token, or `SameSite=None` — surface
  that needs `attack-cors` / `attack-auth-bypass` to turn into proven impact — an
  `[UNCONFIRMED CANDIDATE]` per `poc-standard`.

## Evidence
The `Set-Cookie` captures with flags, the before/after session-id transcript, the post-logout replay
response, and any unbound-CSRF-token test — all under `raw/<label>/`, using only test accounts you
control. All requests go through `tools/leashed.sh`.
