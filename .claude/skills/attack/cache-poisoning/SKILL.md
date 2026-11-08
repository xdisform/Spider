---
name: cache-poisoning
description: Web cache poisoning + web cache deception + CPDoS — oracle-grade proof via persistence re-fetch, not just reflection.
category: attack
tags: [web-cache-poisoning, cache-deception, cpdos, http]
tools: [wcvs, hurl]
version: "1.0"
---

# Web cache poisoning / deception

## Objective
Prove that an attacker's input is cached by the shared cache (CDN or app) and served to subsequent
victims (poisoning), or that a victim's authenticated content is cached under a path they do not own
(deception). nuclei covers generic header-reflection — this skill proves the full oracle
(persistence after a cold re-fetch, from a different session).

## Methodology

1. **Scope check first.** Confirm the program allows cache testing — some BB scopes forbid it
   because a successful poison affects other users. If the policy excludes it: STOP and record it as
   a lead for manual coordination with the program.

2. **Fingerprint the cache.** Identify the CDN/cache layer (Cloudflare, Fastly, Varnish, Akamai, nginx
   proxy_cache) from `httpx -server -title` output. The cache-key normalization rules differ per
   vendor and shape every subsequent probe.

3. **WCVS scan with the lowest-impact profile.** Start conservative to avoid flooding the CDN:
   ```bash
   tools/leashed.sh targets/<t> bin/wcvs \
     -u https://<host> \
     --threads 2 \
     -gr -gp \
     --crawl \
     --output raw/<label>/wcvs-<host>.json
   ```
   WCVS runs 10 poisoning techniques (header-oriented, parameter-cloaking, path-based) + 3 deception
   techniques + CPDoS checks. The `-gr -gp` flags group output for easier reading. Scale threads only
   after a clean low-thread baseline confirms the backend survives.

4. **Validate every hit with an oracle re-fetch.** WCVS flags candidates; validation needs a
   SEPARATE verification pass from a clean client (no cookies, different IP if possible):
   ```bash
   # Attacker request (saved in WCVS output as <attacker.hurl>)
   bin/hurl raw/<label>/attack-<id>.hurl
   # Wait for cache TTL window to open
   sleep 5
   # Victim re-fetch (no attacker inputs — the poisoned payload must come back)
   bin/hurl raw/<label>/victim-<id>.hurl --test
   ```
   The oracle is: the victim's cold-fetched response contains the attacker's payload (or the leaked
   victim content for deception). Without that persistence proof, it is a header-reflection lead at
   most, never a cache-poisoning finding.

5. **Minimize blast radius.** Use payloads that are visibly identifiable but harmless (a
   `<!--pentest-marker--><!--RID:<run_id>-->` comment, not an active XSS). If the poison lands, do
   NOT escalate — the proof is the persistence of your marker on a cold fetch. The attack-operator
   explicitly does not weaponize into stored XSS, redirect chains, or auth-bypass unless the program
   policy allows a chained demonstration.

## What to return
`{proven_state, cache_vendor, technique, injected_header_or_param, oracle_fetch_evidence, ttl_observed}`
with `proven_state: impact_proven` only when the victim cold-fetch oracle fires. Otherwise
`misconfig_proven` (reflection but no persistence) or `not_reproduced`.

## Evidence
WCVS JSON + both `.hurl` scripts (attacker + victim) + both response files, under `raw/<label>/`.
Timestamps on both fetches so the TTL window is reconstructible.

## Oracle
From `.claude/skills/proof/oracles/SKILL.md` row: *persistence after cold re-fetch from a clean
session* — the attacker payload (or deceived content) comes back on a GET that carries no attacker
header/param.

## Hard constraints
- **Never run against a program that excludes cache testing in its scope.**
- Start at `--threads 2`; raise only after a baseline run shows no backend timeouts.
- Payload = inert marker, never a weaponized XSS/open-redirect. The persistence IS the finding.
- Through `tools/leashed.sh` always — the leash enforces the `X-Bug-Bounty` header AND the rate cap.

## Notes
Cache-poisoning oracles are vendor-sensitive — Cloudflare normalizes casing differently than Fastly;
the technique that worked on Varnish may silently fail on CloudFront. Always carry the vendor
fingerprint from step 2 into the report so the reviewer can reproduce.
