---
name: attack-keycloak-realm
description: Keycloak / IdP-broker testing (standard class) — realm/client discovery, redirect_uri validation, token/alg handling, admin-cli rate-limit control-test, and IdP broker misconfig, to obtain an unauthorized token/context or prove a control defect.
category: web-application
tags: [keycloak, oidc, idp, sso, broker, auth]
cwe_ids: [CWE-287]
chains_with: [attack-jwt, attack-auth-bypass, attack-open-redirect, attack-saml]
tools: [jwt-hack, curl, httpx]
version: "1.0"
---

# Keycloak / IdP-broker testing

## Objective
Obtain a token or authenticated context from a Keycloak/OIDC realm you should not have — or prove a
concrete defect in the realm/broker configuration — demonstrated by using the token/context to reach a
protected resource, shown before/after. Runs go through the leash: `tools/leashed.sh $T bin/<tool> …`
(`$T` = target dir).

## Methodology
1. **Discover realm & clients.** Pull the discovery doc and JWKS:
   `tools/leashed.sh $T bin/httpx -u "https://sso.target/realms/<realm>/.well-known/openid-configuration" -json`.
   Enumerate realms (default `master`), the authorize/token/introspection endpoints, and public clients;
   read a live token's structure with `bin/jwt-hack decode "$JWT"`.
2. **redirect_uri validation.** For each client, test the `redirect_uri` on the authorize endpoint —
   wildcards, subpath append, `@`-host, `localhost`/loopback, and open-redirect on a trusted host (chain
   `attack-open-redirect`). Inspect the `Location`: an honored off-client redirect leaks the code/token.
3. **Token / alg handling.** Run the `attack-jwt` battery against realm tokens — `alg:none`, RS256→HS256
   confusion using the realm JWKS public key as the HMAC secret, `kid`/`jku` injection, weak client
   secret. A forged token a resource server accepts is a break (CWE-347).
4. **Grant / public-client abuse.** Test whether a public client permits the `password` (ROPC) or
   `client_credentials` grant, or token exchange, without a secret, and whether `offline_access` is
   issued. An unexpected grant that mints a usable token is a defect — prove it by calling a protected API.
5. **admin-cli rate-limit control-test.** As a **control test only**, check whether the `admin-cli` token
   endpoint enforces brute-force lockout with a small, policy-bounded burst of failed logins (respect
   safe-PoC limits). No lockout is a proven control defect (CWE-307 class) — this tests the control, it is
   never a credential-stuffing run to actually break in.
6. **IdP broker misconfig.** Where the realm brokers an external IdP, test whether it validates the
   upstream issuer/assertion (chain `attack-saml`) and whether `firstBrokerLogin` links accounts by
   unverified email — a link onto a victim's account is ATO.

## What counts as a finding
- **Critical/High:** a token or session for an identity/role you don't own, used to reach a protected
  resource (realm-management/admin = critical); or a control defect proven end to end — a leaked
  code/token from a redirect_uri flaw, a forged token accepted, missing brute-force protection.
- **Lead only:** a permissive-looking config with no token obtained and no boundary crossed — a
  `[UNCONFIRMED CANDIDATE]` per `poc-standard`.

## Evidence
Under `raw/keycloak/`: the discovery/JWKS output, the exact authorize/token requests, the token obtained
(decoded header+claims) and the protected response it unlocked, a note of the specific misconfig, and a
runnable PoC. All target-facing HTTP goes through `tools/leashed.sh`; keep any burst inside safe-PoC limits.
