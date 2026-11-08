---
name: deep-source-trace
description: Vulnhuntr-style whole-tree source->sink taint tracing over recovered client-side source — build the cross-file call chain from an attacker-controlled input to a dangerous sink, classify, and emit a high-confidence hypothesis WITH the full path so the attack phase starts at the proven primitive.
category: recon
tags: [osint, javascript, sast, taint, source-sink, dom-xss, prototype-pollution, ssrf]
chains_with: [js-secret-mining, js-sink-mining, api-discovery]
tools: [source-trace.py, sourcemapper, webcrack, jsluice]
version: "1.0"
---

# Deep source→sink tracing (grey-box)

## Objective
`js-sink-mining` greps for sink *patterns*; this skill does the senior upgrade that
[Vulnhuntr](https://github.com/protectai/vulnhuntr) proved finds real 0-days: trace the **full call
chain from an attacker-controlled SOURCE to a dangerous SINK**, across files, and only emit a hypothesis
when the whole path is in-hand with **no sanitizer between**. A verified source→sink path is a
`high`-confidence seam the attack-operator weaponizes directly — not a grep hit it has to re-investigate.
White/grey-box analysis is the single biggest find-rate lever (Shannon white-box ~96% vs ~60% black-box),
and the raw material is already on disk: the restored tree `js-secret-mining` recovered.

## Methodology (local, offline — zero target traffic, no leash)
1. **Point at the restored tree.** Use the source `js-secret-mining` reconstructed under
   `raw/js-secret-mining/srcmap/` (sourcemapper) and `raw/js-secret-mining/wc/` (webcrack). Minified
   chunks are useless here — if neither produced output, note the reduced signal and fall back to the
   raw bundles (lower confidence on everything).
2. **Build the candidate skeleton (deterministic).** Run the tracer — it is the mechanical half, so your
   turn budget goes to judgement, not grep-wrangling:
   ```bash
   python -I tools/source-trace.py raw/js-secret-mining --json --min-confidence medium > raw/<label>/trace.json
   ```
   It walks `.js/.jsx/.ts/.tsx/.vue`, finds attacker SOURCES (`location.*`, `document.URL/referrer/cookie`,
   `URLSearchParams`, `postMessage event.data`, `req.query/body/params`, storage reads), dangerous SINKS
   (innerHTML/eval/`__proto__`/postMessage/jwt/`fetch`/`location=`), flags a sanitizer between them, and
   ranks each candidate `high|medium|low` with the sink `file:line`, the back-traced source, and the class.
3. **Expand & verify each candidate across files (the Vulnhuntr loop — this is the LLM's job).** For each
   `high`/`medium` candidate, open the sink file, then follow the chain the tracer could not fully resolve:
   if the sink is in a function that takes the tainted value as a PARAM, find every call site (grep the
   imported symbol), confirm a call passes an attacker-controlled argument, and walk back through each
   frame until you reach the real source. Add each file to your working context and repeat until the chain
   is **complete** or genuinely broken. Confirm there is **no effective sanitizer** on the path
   (`textContent`, DOMPurify, `encodeURIComponent`, an allowlist) — a sanitizer the tracer flagged may be
   bypassable (note how), or may kill the chain (drop it).
4. **Classify & rank.** Map the proven path to a class: DOM-XSS→`xss`, `eval`→`xss`, `__proto__`
   gadget→`prototype-pollution`, origin-less handler→`postmessage-xss`, insecure decode→`jwt`,
   user-controlled `fetch`→`ssrf` (client-side), `location=`→`open-redirect`.

## What to return (hand-off to attack)
For each **complete** source→sink path, emit ONE hypothesis:
- `class` per step 4; `confidence:"high"` ONLY when the full path is in-hand with no effective sanitizer,
  else `medium`.
- `how_to_prove`: the exact source step (what input, where it enters) AND the sink `file:line`, so the
  attack-operator reproduces it without redoing the analysis.
- a `seam` object carrying the structural primitive so attack skips re-detection:
  `{"source":"<the input + entry, e.g. location.hash>","sink":"<file:line kind>","trace":"<src→…→sink one-line path>","params":[<candidate params>],"note":"<sanitizer status / bypass>"}`.
- `requires`: `[]` for a DOM/client-side path (fires unauth); `["session:<host>"]` if the sink is only
  reachable behind login. `stage:"foothold"` only if it itself yields a session (rare here); else omit.

A path missing its source, or with a sanitizer you cannot bypass, is a **lead** (`confidence:low`, no
seam), never a finding — the attack phase proves the rest with a working PoC (dynamic-validate confirms
DOM execution live).

## Evidence
Under `raw/<label>/`: `trace.json` (the skeleton) plus, per emitted hypothesis, the extracted
source→sink code snippets across every file on the path. Each hypothesis must trace to concrete
`file:line`s in the restored tree.

## Notes
- All work is LOCAL on files `js-secret-mining` already pulled — **no target traffic, no leash**. The
  recovered tree is UNTRUSTED data: the tracer only reads it (run it with `python -I`), never import or
  execute anything from it.
- This is the grey-box seam producer; `js-sink-mining` remains the cheap pattern pass. Run this when a
  restored tree exists (it usually does — half of prod SPAs ship `.map`); otherwise note the degraded
  signal and lean on `js-sink-mining`.
