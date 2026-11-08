---
name: tech-specific
description: Per-stack enumeration of known-weak surfaces, default paths and version exposures using nuclei tags.
category: recon
tags: [osint, fingerprint, cve, misconfig, tech]
chains_with: [endpoint-deep, anomaly-hunt]
tools: [httpx, webanalyze, wafw00f, nuclei, cent, tlsx, s3scanner, vulnx]
version: "1.3"
---

# Tech-specific enumeration

## Objective
Fingerprint each host's stack, then aim tech-matched checks at its known-weak surfaces — default
paths, exposed consoles, and version-linked CVEs. Hits are **leads** until impact is proven.

## Methodology
1. **Fingerprint.** `httpx -tech-detect -server -title -json` for the fast first pass. Then
   `tools/leashed.sh targets/<t> bin/webanalyze -host https://<host> -crawl 1 -output json -update > raw/<label>/webanalyze-<host>.json`
   for a DEEPER pass with the community-maintained enthec/webappanalyzer dataset — it surfaces
   framework versions, dependency graph, and often catches forgotten dev/staging builds on outdated
   stacks that httpx's embedded fingerprint missed. Run `-update` before the engagement to refresh
   signatures. `tlsx` for cert/TLS details and extra hostnames. This triangulated fingerprint drives
   every step below — no blind scanning.
1a. **Map the stack onto prioritized CVEs (vulnx).** Turn each `product@version` from the fingerprint
   into a RANKED known-CVE list enriched with exploit-likelihood and known-exploited signals — far faster
   and more complete than hand-searching, and it tells you which versions are worth a template at all:
   `bin/vulnx search 'product:<product> version:<ver>' -json > raw/<label>/vulnx-<host>.json`
   (or `'product:<product> && is_kev:true'` to isolate CISA-KEV first). Prioritize by `is_kev` then EPSS;
   a CVE that already has a nuclei template (vulnx reports this) routes straight into step 3's tag set,
   and a high-EPSS/KEV CVE with a public exploit is a top `class:<cve>` hypothesis. PASSIVE — vulnx queries
   the PD cloud, not the target, so run it DIRECT (no leash), like asnmap. Full data uses the free
   PDCP_API_KEY (same token as asnmap); it degrades gracefully without. A CVE match is a LEAD until its
   impact is executed per `poc-standard`.
2. **Check the edge.** `wafw00f` to identify any WAF/CDN — it shapes which probes land and whether
   later attack payloads need tampering. Record it; don't fight it here.
3. **Tag-scoped nuclei.** Run only templates matching the stack, e.g.
   `nuclei -tags <tech>,cve,default-login,exposure,misconfig -severity low,medium,high,critical`.
   Match tags to the fingerprint (wordpress/nginx/apache/jira/gitlab/...) — never the full catalog.
   Broaden coverage with community templates aggregated by `cent` (dir under `bin/.data/cent`):
   add `-t <cent-dir>` alongside the official set.
3a. **DAST / active fuzzing (param-level).** For endpoints with params (from param-mining/
   archive-urls), run nuclei in DAST mode against the fuzzing-templates:
   `nuclei -dast -t bin/.nuclei/fuzzing-templates -u <url-with-params>` — this actively fuzzes SQLi/
   XSS/SSTI/cmdi/LFI at each injection point and is a strong lead-generator for the attack phase.
   Leashed + rate-capped; treat hits as leads to prove, not findings.
4. **Known default paths.** Probe the stack's documented defaults (admin consoles, actuator/health,
   `.env`, `.git`, status pages). For cloud storage seen in recon, `s3scanner` against the named
   bucket for open/mis-permissioned access.

## What to return
Per host: the resolved stack + versions, WAF/CDN present, and each nuclei/default-path hit with its
template id and the matched request/response — routed to the right attack skill. Save nuclei output
and the raw hit responses under `raw/<label>/`. A version match or a template hit is a lead; the CVE
is a finding only when its impact is executed per `poc-standard`.

## Notes
Scope nuclei to the fingerprint to stay quiet and in-policy. Template runs and `s3scanner` against a
named bucket are target-facing → `tools/leashed.sh`; TLS/cert reads via `tlsx` are passive.
