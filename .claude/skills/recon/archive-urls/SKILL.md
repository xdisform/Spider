---
name: archive-urls
description: Mine historical/archived URLs (Wayback, Common Crawl, OTX, URLScan) for old endpoints, dead params, and forgotten routes.
category: recon
tags: [osint, wayback, historical, endpoints, params]
chains_with: [web-crawl, content-discovery, http-probe]
tools: [gau, uro, gf]
version: "1.1"
---

# Archived URL mining

## Objective
Recover the endpoints and parameters a target exposed in the past — old API routes, deprecated pages,
and legacy params that are often still live and far less-tested than the current surface.

## Methodology
1. **Pull the archives.** Passive OSINT, run direct: `bin/gau <domain> --subs --threads 5 > urls.txt`
   (Wayback Machine, Common Crawl, AlienVault OTX, URLScan). `--subs` folds in subdomains.
1a. **Dedupe the firehose.** `gau` returns tens of thousands of near-identical URLs — collapse them
   to a unique, testable set with `cat urls.txt | bin/uro > urls-uro.txt` (drops static assets,
   folds `?id=1`/`?id=2` duplicates, normalizes). This is the single biggest quality gate before
   attack — everything downstream tests the uro'd set, not the raw dump.
2. **Extract params + tag by class.** Grep the query-string URLs for distinct param names, then
   pattern-tag them with gf (patterns in `bin/.gf`): `GF_PATH=bin/.gf bin/gf ssrf|redirect|sqli|ssti|lfi < urls-uro.txt`.
   Each tag file is a ready-made attack queue — `?redirect=`→open-redirect, `?url=`→ssrf, `?file=`→lfi,
   `?id=`→idor, `?q=`→sqli/xss — handed straight to the matching attack class.
3. **Filter to interesting.** Keep archived paths worth re-testing: `.json`/`.xml`/`.bak`/`.old`,
   `/api`, `/admin`, `/internal`, upload/download handlers, and old versioned routes.
4. **Confirm liveness.** Hand the candidate URLs to `http-probe` (httpx, leashed) — many archived URLs
   are dead, but the ones that still 200 are prime, under-tested targets.

## What to return
The deduped historical URL set, the extracted parameter inventory, and the subset confirmed still live
— each tagged where it maps to an attack class. Scope-filtered; out-of-scope archived hosts are leads.

## Evidence
The raw `gau` URL dump and the extracted param / interesting-URL lists, under `raw/archive-urls/`.

## Notes
`gau` queries third-party archive APIs, NOT the target — run it direct, WITHOUT the leash (the leash
would 403 it as off-scope). Only re-probe recovered URLs whose host is in `scope.yaml`.
