---
name: endpoint-deep
description: Enumerate API routes, versions, swagger/graphql schemas and undocumented actions behind a target.
category: recon
tags: [osint, api, endpoints, attack-surface]
chains_with: [attack-idor, attack-ssrf, param-mining]
tools: [katana, httpx, nuclei, gau, ffuf, oasdiff]
version: "1.1"
---

# Deep endpoint enumeration

## Objective
Map the full route surface — every API version, documented and hidden action, and any schema the
app leaks (OpenAPI/Swagger, GraphQL introspection). Routes are **leads** for the attack phase.

## Methodology
1. **Crawl.** `katana -jc -d 3` for the live route tree (JS-aware) and `gau <domain>` for historical
   URLs the crawler won't reach. Merge, dedupe, keep only in-scope.
2. **Fingerprint routes.** `httpx -sc -title -method -json` over the URL set — which are live, which
   verbs answer, JSON vs HTML. Flag `/api`, `/v1..vN`, `/internal`, `/admin`, write actions.
3. **Grab schemas.** Probe the usual schema paths (`/swagger.json`, `/openapi.json`, `/api-docs`,
   `/graphql`). If GraphQL, attempt a read-only introspection query — a full schema hands you every
   type and mutation. A live schema is a map of the whole API.
3a. **Diff the spec against the last run (oasdiff).** When a schema is captured AND a prior
   `/swagger`/`openapi` snapshot exists (from `state.json`/a previous `raw/<label>/` or the operator),
   diff them — most hunters read the spec once and forget it, so the deltas between releases (a new
   `/internal`/`debug` route, a param added, an endpoint that dropped its auth requirement) are where
   the fresh, under-tested surface lives:
   `bin/oasdiff diff -base raw/<label>/openapi.prev.json -revision raw/<label>/openapi.json -f json > raw/<label>/oasdiff.json`
   (add `bin/oasdiff breaking ...` to isolate authz/endpoint changes). Save the current spec as the
   baseline for next run. Each added/authz-changed endpoint is a `class:hidden-route` hypothesis. Local
   on already-fetched specs — no leash. (First run with no baseline: skip and note it.)
4. **Find undocumented.** `ffuf` against the discovered base paths with an API wordlist to surface
   routes the crawl missed; `nuclei -tags exposure,misconfig` to catch exposed panels, debug
   endpoints, and config leaks.

## What to return
The route inventory (path, verbs, status, content-type), any schema captured, and the higher-value
routes called out (auth, admin, api, internal, write) for follow-up. Save the crawl output, schemas,
and nuclei hits under `raw/<label>/`. An exposed endpoint is a lead until its impact is proven per
`poc-standard`.

## Notes
All crawling and probing is target-facing → `tools/leashed.sh`. `gau` history is passive → direct.
Introspection and schema pulls are read-only — never call the mutations you discover.
