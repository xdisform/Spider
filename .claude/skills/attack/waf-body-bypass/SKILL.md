---
name: attack-waf-body-bypass
description: Bypass a WAF/edge to reach the origin via request-body encoding — chunked TE, charset, multipart boundary, content-type confusion, double-encoding — to deliver an otherwise-blocked payload to a known-vuln sink.
category: web-application
tags: [waf, bypass, edge, encoding, evasion]
cwe_ids: [CWE-693]
chains_with: [attack-sqli, attack-xss, attack-ssti, attack-request-smuggling]
tools: [wafrift, curl, nuclei, ffuf]
version: "1.1"
---

# WAF / edge body-encoding bypass

## Objective
Prove that a payload the WAF/edge blocks still reaches and fires at the origin when the request body is
re-encoded so the inspector and the origin disagree on how to parse it. The finding is not the `403→200`
flip — it is the **sink's proven impact** delivered past the control. Runs go through the leash:
`tools/leashed.sh $T bin/<tool> …` (`$T` = target dir).

## Methodology
1. **Establish the block.** Send the known-good sink payload raw and confirm the edge rejects it, so you
   have a baseline the encoding must beat. Note the block signal (403/406/challenge/scrubbed body) and
   the WAF fingerprint from response headers/behavior:
   `tools/leashed.sh $T curl -sD- -o /dev/null "$U" --data 'q=<blocked-payload>'`.
2. **Chunked / Transfer-Encoding.** Frame the body as `Transfer-Encoding: chunked` so the WAF's flat-body
   signature never sees the contiguous token but the origin reassembles it — split the signature bytes
   across chunk boundaries with `curl --data-binary @chunked.raw` and a manual `Transfer-Encoding` header.
3. **Charset / content-type confusion.** Declare a charset the WAF won't normalize (utf-16, utf-7,
   ibm500/EBCDIC) or a `Content-Type` the two hops parse differently (JSON body sent as `text/plain`,
   form body the app treats as JSON) so the token is invisible to the signature but decoded by the origin.
4. **Multipart boundary tricks.** Wrap the parameter in `multipart/form-data` with boundary quirks the
   WAF's multipart parser mishandles but the framework accepts — duplicated/oversized boundary,
   `filename` vs `name` confusion, nested parts, leading whitespace.
5. **Double / mixed encoding.** URL-, unicode-, overlong-UTF-8-, or double-URL-encode the signature bytes
   (`%2527`, mixed case) so the WAF's single-pass decode misses what the app's decode reconstitutes. Fuzz
   the encoding space at scale against the sink with `bin/ffuf` and screen reachable origin paths with
   `bin/nuclei`, both through the leash.
6. **Automate the whole mutation search with `bin/wafrift`** (the weaponizer — don't hand-ladder all of
   steps 2–5 when a search engine can). Feed it the blocked payload + param; it hill-climbs/anneals the
   encoding × grammar × content-type × parser-differential space against the live edge until a variant
   PASSES, keeping the winning pipeline per WAF:
   `tools/leashed.sh $T bin/wafrift scan --target "$U" --param q --payload "<blocked-payload>" --grammar <sqli|xss|cmdi|ssti|ssrf> --format json -o raw/<label>/wafrift.json`.
   It also emits desync requests: `bin/wafrift smuggle-emit ...` (hand to `attack-request-smuggling`). Take
   the winning encoded form and deliver it by hand/`curl` so you own the exact bytes for the PoC. Rate-capped,
   leashed; cloud-WAF coverage is beta — fall back to the manual ladders above when it comes up empty.
7. **Confirm at the sink.** A bypass is real only when the delivered payload PROVES the sink's impact — the
   SQLi DB string, the XSS callback, the SSTI eval (see `poc-standard`). Chain to the sink skill for that.
   The `403→200` flip alone, with no sink impact, is `[UNCONFIRMED CANDIDATE]`, never the finding.

## What counts as a finding
- **High/Critical:** an edge-blocked payload delivered by an encoding trick that then proves the sink's
  impact at the origin — severity = the **sink's** proven impact (auth-context/data exfil = critical).
- **Lead only:** the encoding turns a `403` into a `200` but the sink shows no impact (WAF-only defense,
  patched app), or the origin never decoded it — a `[UNCONFIRMED CANDIDATE]` per `poc-standard`.

## Evidence
Under `raw/<label>/`: the baseline blocked request/response, the encoded bypassing request byte-exact
(headers and CRLFs preserved), the sink response proving impact, a note of the exact encoding that
worked, and a runnable PoC. All target-facing HTTP goes through `tools/leashed.sh`.
