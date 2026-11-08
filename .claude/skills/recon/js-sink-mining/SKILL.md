---
name: js-sink-mining
description: Taint-flow and sink-pattern mining in reconstructed client-side JS — DOM-XSS, prototype pollution, postMessage without origin check, insecure JWT handling, SSRF from fetch.
category: recon
tags: [osint, javascript, sast, dom-xss, prototype-pollution, postmessage]
chains_with: [js-secret-mining, api-discovery]
tools: [sourcemapper, webcrack, jsluice]
version: "1.0"
---

# JS sink mining

## Objective
Modern SPAs push significant attack surface to the browser. Regex/AST scanners (jsluice, trufflehog)
find URLs and secrets, but miss the client-side **sinks** where data flows into dangerous APIs. This
skill finds the sink patterns and the taint flows into them — DOM-XSS, prototype pollution,
`postMessage` handlers without origin check, insecure JWT verification, SSRF from `fetch()`.

## Methodology

1. **Prepare readable source** (depends on `recon/js-secret-mining`). Pull the restored source tree
   from step 1a (sourcemapper) or step 1b (webcrack) of js-secret-mining. Minified JS is not useful
   here — sinks look like `a=b.c(d)` and are impossible to classify. If neither sourcemapper nor
   webcrack produced output for this target, fall back to grepping raw bundles with the patterns
   below — lower signal, catches obvious cases only.

2. **Grep the high-risk sink patterns.** Over the restored tree, run pattern passes:
   ```bash
   SRC=raw/js-sink-mining/src
   # DOM-XSS sinks
   grep -rnE 'innerHTML\s*=|outerHTML\s*=|document\.write|insertAdjacentHTML|dangerouslySetInnerHTML' "$SRC"
   # eval-family
   grep -rnE 'eval\(|new Function\(|setTimeout\([^,]*(["\x27])[^"\x27]+\1' "$SRC"
   # prototype pollution gadget patterns
   grep -rnE '__proto__|Object\.prototype|prototype\s*\[|constructor\s*\[' "$SRC"
   # postMessage without origin filter
   grep -rnE 'addEventListener\(\s*["\x27]message["\x27]' "$SRC" -A 10 | grep -v 'event\.origin'
   # JWT handling
   grep -rnE 'jwt\.(decode|verify|sign)\(|atob\([^)]*split' "$SRC"
   # SSRF from client (fetch with user-controlled URL)
   grep -rnE 'fetch\(\s*(window\.location|location\.|params\.|url\s*\+)' "$SRC"
   # open redirect sinks
   grep -rnE 'location\.(href|assign|replace)\s*=|window\.open\(' "$SRC"
   ```
   Save hits to `raw/<label>/sinks.txt` with file:line references.

3. **Taint-trace the top candidates.** For each sink hit, trace back from the sink to its source
   (URL/query/hash/postMessage data/storage read) through 2-3 call frames. A real finding needs:
   source is attacker-controlled + no sanitizer between source and sink + the sink actually executes
   or stores. Use `jsluice urls` on the surrounding file to see which routes activate the module.

4. **Hand off to attack.** Every confirmed sink + taint path becomes a hypothesis for the attack
   phase: class `xss` (DOM-XSS), `prototype-pollution`, `postmessage-xss`, `jwt` (crypto issue),
   `ssrf` (client-side), `open-redirect`. Include the sink file:line AND the source step so the
   attack-operator reproduces it without re-doing the analysis.

## What to return
A list of taint candidates: `{sink_file, sink_line, sink_kind, source_hint, path_summary, confidence}`.
Confidence is `high` only when the full source→sink path is in-hand and no sanitizer sits between
them; otherwise `medium` (needs attack-phase proof).

## Evidence
Raw sink grep output + the extracted source snippets around each hit under `raw/<label>/`. Each
candidate must trace to a file:line in the restored tree.

## Notes
- All work is LOCAL on files already pulled by `js-secret-mining` — zero target traffic, no leash
  needed. Only the original JS fetch (done by js-secret-mining) goes through the leash.
- No regex pattern is a proof. A sink grep hit without a verified taint source is a **lead**, not
  a finding. The attack phase (`.claude/skills/attack/xss`, `/sqli`, `/ssti`, `/jwt`, etc.) proves
  it with a working PoC.
- CodeQL CLI will replace the pattern-grep passes in a future iteration (ship-next) — see
  `brain/spider.md` roadmap. For now, grep is honest and cheap.
