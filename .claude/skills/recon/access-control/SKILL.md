---
name: access-control
description: Read-only mapping of object references, tenant boundaries and admin-vs-user endpoints for later IDOR/BOLA.
category: recon
tags: [osint, access-control, authz, idor, tenancy]
chains_with: [attack-idor, auth-flow]
tools: [httpx, katana, ffuf, arjun]
version: "1.0"
---

# Access-control mapping

## Objective
Chart where the app makes authorization decisions — every object reference, tenant identifier, and
admin-only endpoint — so the attack phase can test crossing them. This is reconnaissance: observe
the boundaries, never cross them here.

## Methodology
1. **Inventory object refs.** From the crawl + `param-mining`, list every identifier a request
   carries: numeric ids, UUIDs, slugs, filenames, `account`/`tenant`/`org` ids in path, query, body,
   headers. Note predictable (sequential/short) vs random — predictable = higher IDOR value.
2. **Map tenant boundaries.** With two test accounts (and two tenants if the app is multi-tenant),
   record which ids belong to which identity. `httpx` each account's own objects to capture the
   baseline "my data" response — the reference the attack phase will diff against.
3. **Separate privilege tiers.** Identify admin/staff/internal endpoints (`/admin`, `/manage`,
   `/internal`, elevated API scopes) via crawl and `ffuf`, and which role each *should* need (from
   `auth-flow`). Do not invoke the actions — record the surface only.
4. **Spot missing-check smells.** Endpoints that take an id but show no obvious ownership check,
   write verbs on shared objects, and `arjun`-found hidden id params — flag each as an IDOR/BOLA
   candidate.

## What to return
The object-reference map (ref type, predictability, owning identity), the tenant layout, the
admin-vs-user split, and a ranked list of IDOR/BOLA candidates for `attack-idor`. Save the baseline
own-data responses and the endpoint inventory under `raw/<label>/`. Everything here is a lead — a
boundary is only "broken" once the attack phase returns another identity's data per `poc-standard`.

## Notes
Strictly read-only, and only against objects your own test accounts own — never fetch or mutate a
real user's data during recon. All requests are target-facing → `tools/leashed.sh`.
