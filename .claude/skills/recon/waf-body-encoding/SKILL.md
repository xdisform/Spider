---
name: waf-body-encoding
description: Map where the edge WAF and the origin disagree on how a request body is framed and decoded — chunked vs length, charset, multipart, gzip, double-encoding — the seam later bypasses ride.
category: recon
tags: [waf, bypass, encoding, transfer-encoding, content-type, edge]
chains_with: [http-probe, attack-request-smuggling, attack-sqli, attack-xss]
tools: [httpx, curl, nuclei, smugglex, unwaf]
version: "1.1"
---

# WAF / edge body-encoding disagreement mapping

## Objective
Find the requests where the front-end WAF/CDN and the origin parse a body **differently** — a body the
WAF passes clean but the origin decodes into something dangerous. This lens maps the seam; the actual
injection through it is proven in the matching attack lens per `poc-standard`, not here.

## Methodology
1. **Confirm there is an edge — and where it actually filters (unwaf).** From `http-probe`, know the
   WAF/CDN (`bin/wafw00f`) and that an origin sits behind it (`Server`/`Via`/`X-Cache`, differing 4xx
   handling). No edge in front → the origin sees your body verbatim and this lens is moot. Then run
   `tools/leashed.sh targets/<t> bin/unwaf -d <host> --json > raw/<label>/unwaf-<host>.json` — it scores
   origin-vs-edge behavioral divergence (HTML similarity, TLS fingerprint, headers) and surfaces candidate
   origin IPs, telling you WHERE the WAF genuinely inspects vs merely proxies. A reachable origin that
   bypasses the edge entirely is itself a `class:waf-bypass`/`class:info-disclosure` lead; the divergence
   map tells the framing passes below which sink to aim at. A candidate origin IP is a LEAD (confirm it is
   in-scope before probing it — a new host is never a target).
2. **Establish the block baseline.** Send a body carrying a benign canary marker the WAF is known to
   block, straight through the leash, and confirm the `403`/`406` — that is the control you are trying to
   slip past:
   ```bash
   tools/leashed.sh targets/<t> curl -sD- -o /dev/null https://<host>/<sink> \
     --data 'q=<benign-canary-marker>'
   ```
3. **Vary the framing, re-send the same canary — one axis at a time** so any pass is attributable:
   - `Transfer-Encoding: chunked` vs `Content-Length` (and both together) — does the WAF inspect the
     de-chunked body the origin actually reassembles?
   - `Content-Type` charset (`utf-16`, `utf-7`, `ibm500`) and a `form` vs `json` type/body mismatch.
   - `multipart/form-data` boundary abuse — the marker in a part the WAF fails to reassemble.
   - Body compression: `Content-Encoding: gzip` a gzipped body — does the WAF inflate before inspecting?
   - Single vs double URL-/unicode-encoding that the origin normalizes but the WAF does not.
3a. **Desync detection (smugglex).** The chunked/`Transfer-Encoding` axis above is exactly where
   request-smuggling lives — run the dedicated detector over the live host set to classify the desync
   discrepancy precisely (CL.TE/TE.CL/TE.TE, H2C, HTTP/2-downgrade H2.CL/H2.TE, CL.0):
   ```bash
   echo "https://<host>" | tools/leashed.sh targets/<t> bin/smugglex -f json -o raw/<label>/smugglex-<host>.json
   ```
   This is DETECTION, not exploitation — a positive is a `class:request-smuggling` hypothesis handed to
   `attack/request-smuggling` (where `smuggler` weaponizes it), with the smugglex technique + evidence in
   `how_to_prove` so the attack-operator reproduces it without re-discovering the variant. Leashed,
   rate-capped; only run where scope permits smuggling tests. Prebuilt binary — no cargo.
4. **Record the disagreements.** Per variant note the WAF verdict (block/pass) against the origin
   behavior (reflected? processed? distinct error?). A canary the WAF now passes but the origin still
   decodes = a live bypass seam. `bin/nuclei -tags waf` where templates exist widens coverage;
   `bin/difft` on the paired responses makes the disagreement obvious.

## What counts as a finding
- **Not proven here.** The seam is a **lead** — a mapped disagreement, not harm. It becomes a finding
  only when an attack lens drives a real payload (`attack-sqli`/`attack-xss`/`attack-request-smuggling`)
  through that exact framing and proves impact per `poc-standard`; severity is then the underlying
  class's. A chunked/`Transfer-Encoding` disagreement that yields a desync → `attack-request-smuggling`.
- **Lead only:** any framing that flips the WAF verdict with no proven downstream impact yet — an
  `[UNCONFIRMED CANDIDATE]`.

## Evidence
Per variant: the byte-exact request (framing headers + body preserved), the WAF response, the origin
response, and the diff showing the disagreement — all under `raw/<label>/`, each noting the single axis
that changed. Keep canaries benign markers; all requests go through `tools/leashed.sh` and the seam is
handed to the attack phase, which respects the program's safe-PoC limits.
