---
name: attack-graphql
description: Exploit GraphQL to proven impact — BOLA/IDOR across objects, authz bypass, injection through resolvers, and batching/alias abuse — with a reproducible PoC.
category: attack
class: graphql
cwe_ids: [CWE-639, CWE-863, CWE-284]
tags: [graphql, bola, idor, authz, injection, batching]
tools: [clairvoyance, graphw00f, nuclei, httpx]
version: "1.0"
---

# GraphQL exploitation

## Objective
Turn a mapped GraphQL endpoint (see `recon/graphql`) into **proven** impact: read another tenant's
data, call a mutation you shouldn't, reach an admin field, or inject through a resolver — each with a
reproducible PoC, not an "an attacker could".

## The repertoire (iterate — do not one-shot)
1. **BOLA / cross-object read.** With YOUR OWN low-priv token, request another object by id/UUID
   (`query{ user(id:"<other>"){ email } }`, `node(id:)`, `orders(filter:)`). Proof = a record that is
   demonstrably **not yours** (use two own test accounts; the cross-account row is the oracle).
2. **Broken function-level authz.** Call privileged mutations/queries (`deleteUser`, `setRole`,
   `adminSettings`) as a normal user. Reaching them unauth/low-priv with a state change you can read
   back = proven. Honor scope: prove on your own objects, never destroy others' data.
3. **Injection through resolvers.** A field feeding a DB/OS/template downstream → SQLi/NoSQLi/SSTI via
   the argument. Use the class oracle (`database()`/`@@version` only for SQLi; OOB callback for blind).
   Route sqlmap at the single resolver param if warranted.
4. **Introspection + suggestion leakage.** If introspection is off but field-suggestion is on
   (`clairvoyance`), the recovered schema itself can be the info-disclosure finding on strict programs.
5. **Batching / alias abuse.** Many aliased queries in one request to bypass rate-limits or amplify —
   prove the *control gap* (e.g. password-reset/OTP brute via aliases) as a **control test** within
   `policies.rate_limit_test`, on your own account, never a flood.

## Proof & limits
- `impact_proven` needs `execution_evidence`: the cross-account record, the mutation's read-back, the
  DB banner, or the OOB callback id. high/critical REQUIRES it.
- Safe-PoC policy from scope applies verbatim (SQLi = `database()/@@version`; RCE = `whoami/id`). No
  mass-exfiltration — one proving record is enough; on reaching real user data, stop and record access.
- Batching/brute stays within `policies.rate_limit_test`, own accounts only. No DoS via deep/nested
  query explosion against production.

## What to return
The candidate schema with `proven_state`, the exact query/mutation, the response proving impact, and a
runnable PoC (a `.hurl`/curl script replaying it) under `raw/attack-<h>/`. Origin-check: confirm it's
the real in-scope host, not your own egress.
