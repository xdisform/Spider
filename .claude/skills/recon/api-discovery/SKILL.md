---
name: api-discovery
description: Discover REST/API routes that directory fuzzing misses — from Swagger/OpenAPI specs and kitebuilder API wordlists, with correct methods and content types.
category: recon
tags: [osint, api, endpoints, idor, bola, attack-surface]
tools: [kiterunner, autoswagger, schemathesis, restler, httpx, katana, uro]
version: "1.3"
---

# API route discovery

## Objective
The highest-value modern bugs (IDOR/BOLA, mass-assignment, broken function-level authz) live on API
routes that are never linked and that path-fuzzers miss — because they need the right **method**,
`Content-Type: application/json`, and a real route grammar. Enumerate that API surface.

## Methodology
1. **Harvest specs first.** Look for `swagger.json`, `openapi.json`, `/v2/api-docs`, `/graphql`,
   `.well-known/`, and API base URLs from `js-secret-mining`/`archive-urls`. A spec is a map of every
   route + param — feed it straight to the attack phase.
2. **Kiterunner (the edge over ffuf).** With the kitebuilder wordlist:
   `tools/leashed.sh targets/<t> bin/kr scan https://<host> -w bin/.wordlists/kite/routes-large.kite -x 10 --fail-status-codes 400,404 -o json > raw/api-discovery/<host>.json`.
   `kr` replays real route templates with proper verbs/headers, so it finds `POST /api/v2/users/{id}`
   that a GET-only wordlist never reveals. Rate-cap it — this is noisy.
3. **Replay a spec with Autoswagger.** If you found a Swagger/OpenAPI doc, Autoswagger reads the
   LIVE SCHEMA and replays every endpoint with valid method + params, expecting 401/403 and flagging
   anything that returns 200: `tools/leashed.sh targets/<t> python bin/autoswagger https://<host> -v --output raw/api-discovery/<host>-autoswagger.json`.
   It also scans responses for PII (via Presidio) and secrets. This finds hidden-api + BOLA/BOPLA
   that `kr`'s wordlist pass cannot reach — because here the parameter grammar is right. Default scan
   is GET-only (safe). `--brute` mode is gated behind operator approval (may trigger WAF or consume
   nonce). Fallback if the schema is absent: `kr brute` the documented routes, or walk them with
   `httpx`/`curl` to see which are live and which enforce authz.
3a. **Schema-driven property fuzzing (schemathesis).** When a real OpenAPI/GraphQL spec was harvested,
   drive it with schemathesis to generate edge-case + stateful (OpenAPI-links) requests the
   wordlist/replay passes never produce — it surfaces schema violations, unhandled `500`s, and
   state-mutation inconsistencies:
   `tools/leashed.sh targets/<t> bin/schemathesis run <openapi-url> --checks all --report junit --report-junit-path raw/api-discovery/schemathesis.xml`
   RECON-grade = lean on the conformance / `5xx` / `response_schema_conformance` checks (read-leaning);
   a crash or a schema break is a `class:<endpoint>` hypothesis (500 → error-handling/DoS, authz-shaped
   response mismatch → `class:idor`/`auth-bypass`). Leashed + rate-capped; it can exercise MUTATING
   endpoints, so keep it to non-mutating checks in recon — full fuzz is attack-scope.
3b. **Stateful API-flow grammar (restler) — INTRUSIVE, gated.** When a spec exists AND scope permits
   mutations (staging/test env with create/delete allowed), RESTler is the only tool that reconstructs
   multi-step FLOWS — it infers request dependencies (create resource → capture `id` → reuse downstream)
   and builds a stateful grammar, catching sequence-authz / state-dependent bugs a flat fuzz never
   reaches (checkout, onboarding, multi-step forms):
   ```bash
   bin/restler compile --api_spec raw/api-discovery/openapi.json      # build the grammar (local, no traffic)
   tools/leashed.sh targets/<t> bin/restler test --grammar_file Compile/grammar.py \
     --dictionary_file Compile/dict.json --settings <cfg>             # SMOKE: one pass per request
   ```
   RECON-grade = `compile` (offline) + `test` (one request each, smoke) ONLY — it surfaces the dependency
   graph + which sequences error/leak as hypotheses. **Do NOT run full `fuzz` here** — it hammers the API
   and CREATES/DELETES real resources (attack-scope + operator GO). Gate hard: never on prod, always
   leashed + rate-capped. A sequence that returns another tenant's object cross-flow → `class:idor`; a
   step reachable out of order → `class:auth-bypass`/business-logic.
4. **Dedupe + hand off.** `uro` the discovered URL set to collapse noise; tag object-ref routes
   (`/{id}`, `/users/`, `/orders/`) as IDOR/BOLA candidates.

## What to return
Live API routes with method + auth requirement + any `{id}`/object-ref params, grouped by resource.
Emit hypotheses `class: idor` (object-ref routes), `class: auth-bypass` (unauth-reachable privileged
routes), `class: graphql` (if a GraphQL endpoint is found → hand to the graphql lens). Evidence under
`raw/api-discovery/`.

## Notes
All through the leash, rate-capped (`kr -x` concurrency low). No prebuilt `kr` on Windows — use WSL
or `go build`; if `kr` is absent, fall back to `ffuf` with the SecLists `api-endpoints` list +
`-X POST -H 'Content-Type: application/json'`. Reaching a route ≠ a finding — the attack phase proves
the authz break.
