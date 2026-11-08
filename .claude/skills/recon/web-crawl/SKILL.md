---
name: web-crawl
description: Crawl live in-scope apps to harvest endpoints, forms, parameters, hidden routes, and API surfaces for the attack phase.
category: recon
tags: [crawl, endpoints, params, api, forms]
chains_with: [archive-urls, content-discovery, js-secret-mining]
tools: [katana, hakrawler, gospider]
version: "1.1"
---

# Web crawling & endpoint harvest

## Objective
Walk each high-priority app the way a browser would and extract its real attack surface: every
endpoint, form, parameter, and API route — the inputs the attack phase will actually test.

## Methodology
1. **Crawl live apps (katana, primary).** Target-facing, so leash it:
   `tools/leashed.sh targets/<t> bin/katana -u https://<host> -d 3 -jc -kf robotstxt,sitemapxml -aff -fs fqdn -json`.
   `-jc` parses JavaScript for routes, `-kf` seeds from robots/sitemap, `-fs fqdn` keeps the crawl on
   the in-scope host.
1a. **Second-crawler sweep (hakrawler + gospider).** Different crawlers model links differently and each
   catches routes the others miss — run two more and merge-dedup with katana (more coverage = more attack
   surface). Both are target-facing → leash them, stay on the in-scope host:
   `echo https://<host> | tools/leashed.sh targets/<t> bin/hakrawler -d 3 -subs -u` (fast; pulls hrefs,
   src, forms, JS links) and
   `tools/leashed.sh targets/<t> bin/gospider -s https://<host> -d 3 -c 5 --sitemap --robots -a --json`
   (parallel; `-a` also mines archive/otx/commoncrawl URLs for the host). Rate-capped by the leash.
2. **Harvest params & forms.** Pull query params, form fields, and JSON body keys out of the crawl —
   these are the injection points that feed sqli/idor/ssrf/xss selection.
3. **Surface API routes.** Note `/api`, `/graphql`, `/v1`, versioned and internal-looking paths; a
   GraphQL endpoint gets introspection in the attack phase. Flag auth/session flows.
4. **Merge sources.** Union katana's live endpoints with `archive-urls` (historical) and
   `content-discovery` (brute-forced) into one deduped endpoint+param inventory.

## What to return
A deduped inventory of endpoints, each with its method(s), parameters, and whether it's a form / API /
auth route — tagged by the app it came from. Interesting routes (admin, upload, redirect, fetch,
debug) called out as attack leads. Scope-filtered.

## Evidence
The raw `katana` JSON crawl output and the extracted endpoint/param list, under `raw/web-crawl/`.

## Notes
Crawling is target-facing — always through `tools/leashed.sh` (rate-capped so you don't hammer the
app). Stay on in-scope hosts; an out-of-scope link katana discovers is a lead, not a crawl target.
