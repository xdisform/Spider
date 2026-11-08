---
name: attack-request-smuggling
description: HTTP request smuggling / desync — split the front-end and back-end view of a request boundary to poison, bypass, or capture other users' traffic.
category: web-application
tags: [request-smuggling, desync, http, cl-te, te-cl]
cwe_ids: [CWE-444]
chains_with: [attack-open-redirect, attack-cors]
tools: [smuggler, curl]
version: "1.0"
---

# HTTP request smuggling (desync)

## Objective
Prove the front-end and back-end disagree on where one request ends — so a byte sequence you send is
parsed as a *second* request by the back-end. The proof is a smuggled request that produces an effect
the normal path cannot: a poisoned response, a bypassed control, or a captured victim request.

## Methodology
1. **Find a desync-capable chain.** You need a reverse proxy / CDN in front of an origin (from recon:
   `Via`, `Server`, `X-Cache`, differing 4xx handling). Smuggling needs two hops that parse
   `Content-Length` vs `Transfer-Encoding` differently.
2. **Probe the variants** against the target through the leash:
   ```bash
   tools/leashed.sh targets/<t> bin/smuggler -u https://app.target/
   ```
   It time-tests **CL.TE**, **TE.CL**, and **TE.TE** (an obfuscated `Transfer-Encoding` one hop
   honors and the other ignores). A reproducible, one-variant timeout is a candidate — not yet proof.
3. **Confirm with a benign desync.** On one keep-alive connection send the smuggled prefix, then a
   normal follow-up; a differential response (your follow-up gets the smuggled route's answer)
   confirms the boundary split. Keep the smuggled request non-destructive — a `GET` to a marker path.
4. **Escalate for impact, in policy.** Demonstrate one concrete effect: bypass a front-end auth/ACL to
   reach a restricted path, poison a cached entry, or capture the *next* user's request headers. One
   proven effect is enough — never weaponize broadly or leave a persistent poisoned cache entry.

## What counts as a finding
- **High/Critical:** a reproduced desync with a concrete effect — control bypass, cache poisoning, or
  a captured victim request (captured credentials/session = critical).
- **Lead only:** a timing differential from `smuggler` with no reproduced second-request effect — a
  `[UNCONFIRMED CANDIDATE]` per `poc-standard`, not a finding, until the split is demonstrated.

## Evidence
The exact raw smuggling request(s) — byte-exact, headers and CRLFs preserved — the differential
responses proving the split, and a runnable PoC (a raw-socket script), all under `raw/<label>/`.
