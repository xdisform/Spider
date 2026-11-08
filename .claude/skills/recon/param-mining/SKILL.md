---
name: param-mining
description: Discover hidden GET/POST/JSON parameters and injectable inputs a target accepts but never advertises.
category: recon
tags: [osint, parameters, fuzzing, attack-surface]
chains_with: [attack-sqli, attack-ssrf, attack-idor]
tools: [x8, arjun, katana, gau, httpx]
version: "1.1"
---

# Parameter mining

## Objective
Find the inputs an endpoint honours but never shows you — hidden query, body, and JSON params that
widen the injection surface for the attack phase. Every param is a **lead**, not a finding.

## Methodology
1. **Pick endpoints.** From recon (`endpoint-deep`, `js-secret-mining`) take the live routes worth
   fuzzing — anything that reflects, filters, searches, redirects, or takes an id.
2. **Seed a wordlist.** Harvest candidate param names from the app's own JS and history:
   `katana -jc` and `gau <domain>` → grep param names, feed them to arjun with `-w`. App-specific
   names beat generic lists and stay quiet.
3. **Mine each verb.** `arjun -u <url> -m GET,POST,JSON` — it diffs responses to spot params the
   endpoint silently processes. Note which content-type works (form vs JSON) for each hit.
3a. **Deeper pass with x8.** Where arjun is thin, `bin/x8 -u <url> -X GET POST -w <wordlist>` goes
   further — it fuzzes query, body, JSON **and header** params and detects by response-diff with
   better signal on stubborn endpoints. Point `-w` at `bin/.wordlists/seclists/raft-large-words.txt`
   plus the app-specific names harvested in step 2. Low concurrency, leashed.
4. **Classify the hits.** Tag every found param by likely sink: fetch-like (`url/next/callback` →
   SSRF), id-like (`id/user/account` → IDOR), query-like (`q/search/filter/sort` → SQLi/XSS),
   template-like (`name/msg` → SSTI). This routing tells the attack phase where to push.

## What to return
Per endpoint: the hidden params found, the working method/content-type, and the sink class guessed
for each — so the attack skills know what to try. Back every hit with the arjun output under
`raw/<label>/`. A discovered param is a lead; impact is proven later per `poc-standard`, never
claimed here.

## Notes
arjun's probes are target-facing — run them through `tools/leashed.sh` (in scope, header-tagged,
rate-capped). Seeding from `gau` history is passive and runs direct. Keep wordlists tight; don't
hammer an endpoint to find one param.
