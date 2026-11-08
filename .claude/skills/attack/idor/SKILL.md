---
name: attack-idor
description: Insecure Direct Object Reference / BOLA — access another user's or tenant's objects by changing an identifier.
category: web-application
tags: [idor, bola, access-control, authz]
cwe_ids: [CWE-639, CWE-284]
chains_with: [attack-jwt]
tools: [hurl, httpx, ffuf, arjun, curl]
version: "1.0"
---

# IDOR / BOLA

## Objective
Prove you can read or act on an object that belongs to a **different** user/tenant by manipulating
an identifier — with side-by-side proof it isn't your own data.

## Methodology
1. **Two accounts.** You need account A (yours) and a second identity B (another test account, or a
   second object you own) to prove the boundary crossed. Never use a real user's data.
2. **Map object refs.** From recon: numeric ids, UUIDs, slugs, filenames, account/tenant ids in
   paths, query, body, or headers. Note predictable vs random.
3. **Swap and observe.** As A, request B's object id (GET/PUT/DELETE/PATCH — test each verb; write
   ops are higher impact). Does A get B's data or mutate B's object?
4. **Escalate.** Enumerate a small, safe range to show scale; test tenant crossing; test whether an
   unauthenticated request works (worse). Stay within policy — no mass extraction.

## What counts as a finding
- **High/Critical:** B's private data returned to A, or A mutating B's object — proven with the two
  responses showing distinct owners. Unauth access or tenant crossing = critical.
- **Lead only:** the id is manipulable but the response is empty/403/your-own-data.

## Evidence
Both requests (A→A and A→B) and both responses under `raw/<label>/`, with the field that proves
different ownership highlighted (id/email/record). Use `hurl` to make it a repeatable PoC.
