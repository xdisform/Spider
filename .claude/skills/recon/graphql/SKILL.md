---
name: graphql
description: Find and map GraphQL endpoints — fingerprint the engine and recover the schema even when introspection is disabled — to seed the GraphQL attack playbook.
category: recon
tags: [graphql, api, introspection, schema, bola]
tools: [graphw00f, clairvoyance, graphql-cop, httpx, nuclei]
version: "1.1"
---

# GraphQL surface mapping

## Objective
GraphQL collapses a whole API behind one endpoint and a client-controlled query — a rich, often
under-tested surface for BOLA/IDOR, injection, authz bypass, and DoS via query depth/batching. Find
the endpoint, identify the engine, and recover the schema so the attack phase has a map.

## Methodology
1. **Locate the endpoint.** Common paths: `/graphql`, `/graphiql`, `/api/graphql`, `/v1/graphql`,
   `/query`. Confirm with a minimal `{__typename}` query (`httpx`/`curl`, through the leash).
2. **Fingerprint the engine.** `bin/graphw00f -d -t https://<host>/graphql` → the implementation
   (Apollo, Hasura, graphql-ruby, Graphene, …). The engine dictates which bugs apply (e.g. Hasura
   role headers, Apollo introspection defaults, batching behavior).
3. **Introspection first.** Try a full introspection query. If enabled → save the complete schema
   (every type, field, mutation) — this is the whole attack map.
4. **Schema recovery when introspection is OFF (the edge).** `clairvoyance` brute-forces field names
   via the error-suggestion oracle and reconstructs the schema even with introspection disabled:
   `bin/.pyenv/Scripts/python -m clairvoyance -o raw/graphql/schema.json -w bin/.wordlists/seclists/raft-large-words.txt https://<host>/graphql`
   (use the pyenv python; on Linux/macOS `bin/.pyenv/bin/python`).
5. **Flag the juicy operations.** Mutations (state change), queries returning other users' objects,
   admin/role fields, and any field taking an `id`/filter → IDOR/BOLA/authz candidates.
6. **Audit the endpoint for misconfigs (graphql-cop).** Beyond the schema, test the endpoint itself for
   the classic GraphQL weaknesses — this is where paid GraphQL bugs actually sit, and most recon stops
   at the introspection dump:
   `tools/leashed.sh targets/<t> bin/graphql-cop -t https://<host>/graphql -o json > raw/graphql/graphql-cop.json`
   It flags field-suggestion leaks with introspection OFF (confirms the clairvoyance path), alias/batch
   overloading (DoS/rate-limit bypass), CSRF-via-GET, and debug/trace modes. Map each positive to a
   hypothesis: batch/alias → `class:graphql` (DoS/authz-amplification), CSRF-GET → `class:csrf`,
   suggestion-leak → feeds step 4. Through the leash, rate-capped (it sends several probe queries).

## What to return
The endpoint, engine, whether introspection is open, the recovered schema file, and a ranked list of
suspicious operations. Emit hypotheses `class: graphql` with concrete `how_to_prove` (e.g. "query
`user(id:)` cross-account with a low-priv token"). Evidence under `raw/graphql/`.

## Notes
All through the leash, rate-capped — clairvoyance sends many small queries; keep inside the program
cap. This is recon: map and hypothesize, do not exfiltrate other users' data here — that's the
`attack/graphql` phase under the safe-PoC policy.
