---
name: js-secret-mining
description: Pull JavaScript and source maps to extract hidden endpoints, parameters, internal hosts and leaked secrets.
category: recon
tags: [osint, javascript, secrets, endpoints]
tools: [jsluice, sourcemapper, webcrack, katana, httpx, trufflehog, gau, linkfinder, secretfinder]
version: "1.2"
---

# JS & secret mining

## Objective
Modern apps ship their attack surface in their JS. Extract the endpoints, parameters, internal
hostnames and any leaked credentials the frontend reveals.

## Methodology
1. **Collect JS.** `katana -jc` (crawl + JS parsing) and `gau` for historical JS URLs; download the
   bundles (and `.map` source maps if exposed — they de-minify to original source).
1a. **Recover source maps if present (sourcemapper).** For every JS URL, probe `<url>.map` and well-
   known CDN patterns. If a `.map` resolves, reconstruct the original source tree:
   `tools/leashed.sh targets/<t> bin/sourcemapper -url https://<host>/_next/static/chunks/main.js.map -output raw/<label>/srcmap/<host>/`.
   The `sourcesContent` field inside the map rebuilds un-minified TS/JSX with comments, variable
   names, backend paths, feature flags, and test creds — in one shot often the richest recon artifact
   on a target. Half of prod SPAs in 2026 still ship `.map` by accident.
1b. **Unpack bundles with no .map (webcrack).** When `.map` is absent, webcrack splits webpack 4/5 +
   Browserify bundles back into separate modules AND de-obfuscates obfuscator.io/JSFuck/unminify
   output: `webcrack raw/<label>/<bundle>.js -o raw/<label>/wc/<bundle>/`. The restored
   `src/components/*.jsx` is 10× more useful for downstream jsluice/trufflehog/sinks mining than the
   raw minified chunk. Output directory MUST be isolated per-run (never follow symlinks into shared
   trees — bundle contents are untrusted). Runs LOCAL on the downloaded file; no leash needed.
2. **Extract endpoints & params (parser, not regex).** `bin/jsluice urls <file.js>` and
   `bin/jsluice secrets <file.js>` — jsluice walks the JS **AST**, so it recovers URL paths, API
   routes, the params each call sends, and secrets with far less noise than grep. Run it over every
   downloaded bundle AND over the restored tree from steps 1a/1b
   (`for f in $(find raw/<label> -name '*.js' -o -name '*.jsx' -o -name '*.ts'); do jsluice urls "$f"; done`).
   These feed deep-recon param-mining, api-discovery, and the attack phase. Note auth flows and API
   base URLs. *If `jsluice` is absent (bare Windows has no CGO build — see arsenal), fall back to
   regex extraction of URL/route/`fetch(`/`axios`/`api` patterns over the bundles plus the step-4
   secret scan — lower signal, same goal.*
2a. **Regex endpoint + secret pass (LinkFinder + SecretFinder).** Complement jsluice's AST walk with a
   regex sweep — the two disagree, and the union catches more. Over each bundle AND the restored tree:
   `bin/linkfinder -i 'raw/<label>/**/*.js' -o cli` (endpoints/relative paths jsluice's parser skips) and
   `bin/secretfinder -i 'raw/<label>/**/*.js' -o cli` (API keys, tokens, cloud creds via 100+ signatures).
   For a single live bundle you can point `-i https://<host>/app.js` (that fetch is target-facing → wrap
   it: `tools/leashed.sh targets/<t> bin/linkfinder -i https://<host>/app.js -o cli`); the local tree is
   offline, no leash. Feed found endpoints into api-discovery/param-mining and secrets into trufflehog
   verification. A regex secret hit is a LEAD until verified live (trufflehog) or proven in attack.

3. **Find internal hosts.** Internal/staging hostnames, cloud endpoints, and non-prod URLs leaked
   in JS become high-value assets (and possibly leads if out of scope).
4. **Hunt secrets.** `trufflehog filesystem <dir>` over the downloaded JS — it verifies live
   credentials, killing false positives. API keys, tokens, and signing secrets are findings on
   their own (validate impact before claiming).

## What to return
Discovered endpoints/params (with the JS file they came from), internal hostnames, and any verified
secret (with what it unlocks). Evidence = the JS file + the extracted line under `raw/<label>/`.

## Notes
A leaked secret is only a *finding* once you've shown what it grants (and it's in scope) — otherwise
it's a strong lead for the attack phase. Fetch JS through the leash.
