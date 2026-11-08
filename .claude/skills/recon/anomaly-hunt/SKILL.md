---
name: anomaly-hunt
description: Small non-destructive differential probes that surface error leaks, verbose responses and timing/behaviour anomalies.
category: recon
tags: [osint, differential, error-leak, timing, behaviour]
chains_with: [attack-sqli, attack-ssrf, endpoint-deep]
tools: [httpx, ffuf, nuclei, cachex]
version: "1.1"
---

# Anomaly hunting

## Objective
Poke the app with tiny, safe, paired probes and watch where it behaves *differently* — error
disclosures, stack traces, and timing/behaviour splits that point the attack phase at a real sink.
Non-destructive by design; every anomaly is a **lead**.

## Methodology
1. **Baseline first.** Capture a normal response per endpoint (status, size, timing, headers) with
   `httpx -sc -cl -rt -json`. You can't spot an anomaly without the baseline to diff against.
2. **Differential pairs.** Send minimal paired inputs and diff the two responses: valid vs malformed
   value, present vs absent param, one quote/brace vs none, wrong content-type. A response that
   *changes* (error text, size jump, new header, 500) marks a live sink — a pointer, not proof.
3. **Provoke error leaks.** Bad types, oversized-but-safe values, unexpected verbs, broken JSON —
   watch for stack traces, framework debug pages, SQL/ORM errors, internal paths, and version
   strings. These name the backend and hand injection context to the attack phase.
4. **Timing/behaviour.** Note endpoints whose latency shifts with input (login user-enumeration by
   timing; `SLEEP`-sensitive params — one, small). `ffuf -mc all` with a compact list to surface
   status/size outliers; `nuclei -tags exposure,error` for known verbose-response patterns.
5. **Cache-poisoning behaviour (cachex).** On cacheable responses (a `Cache-Control`/`Age`/`X-Cache`
   header, a CDN edge from `tech-specific`), probe whether an UNKEYED input (header like
   `X-Forwarded-Host`/`X-Forwarded-Scheme`, a cache-buster param) is reflected AND persists for the next
   clean request — the signature of exploitable cache poisoning, not mere reflection:
   ```bash
   tools/leashed.sh targets/<t> bin/cachex -l raw/<label>/cacheable-urls.txt -m multi -j -o raw/<label>/cachex.json
   ```
   cachex does the baseline→poisoned→**clean-request persistence re-fetch** itself, so a positive is
   a weaponizable lead, not noise. Emit `class:cache-poisoning` (carry the unkeyed input + the proof of
   persistence into `how_to_prove`) → `attack/cache-poisoning` weaponizes it with `wcvs`. Leashed, LOW
   threads (CDN-flood risk); only where scope permits cache testing. A `--brute`-style sweep is attack-scope.

## What to return
The anomalies ranked by what they suggest: each with the paired request/response, the delta observed
(error string, size/timing split, leaked path/version), and the sink class it points to
(SQLi/SSTI/SSRF/auth). Save both halves of each pair under `raw/<label>/`. An anomaly is a lead only
— the class is confirmed when the attack phase executes it per `poc-standard`.

## Notes
Keep probes small and non-destructive — one `SLEEP`, no bulk, nothing that writes or deletes. All
probing is target-facing → `tools/leashed.sh`, rate-capped. When in doubt, under-send.
