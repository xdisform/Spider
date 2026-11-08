---
name: waf-mutation
description: When a payload is WAF/filter-blocked, don't hand-guess — run wafrift's evolutionary bypass search (encoding/grammar/content-type/parser-differential mutation, metaheuristic-ranked, gene-bank persisted) to find a variant that passes AND still achieves the class oracle. A bypass that doesn't reach impact is not a finding.
category: proof
tags: [waf, bypass, mutation, evolutionary, wafrift, detonation]
chains_with: [oracles, poc-standard, waf-body-bypass, dynamic-validate]
tools: [wafrift, interactsh-client, curl]
version: "1.0"
---

# WAF mutation (evolutionary bypass → re-prove impact)

## Objective
A blocked payload (403/429/challenge/sanitized) means your input reached a **defense, not the bug** — the
hypothesis may still be real. Instead of hand-laddering encodings, run `bin/wafrift`'s metaheuristic search
(hill-climb / annealing / tabu / MAP-Elites) over the encoding + grammar + content-type + parser-
differential space until a variant **passes the WAF**, then confirm the bypassing variant **still achieves
the class oracle**. The gene-bank persists what landed, so later payloads for the same WAF start ahead. This
is the loop the field uses for adaptive exploitation (WAF-A-MoLE's confidence-priority queue; wafrift's
evolutionary search) — it turns a WAF wall into a solved parameter, not a dead lead.

## When to run
Any time an in-scope attack class (SQLi / XSS / SSTI / RCE·cmd-inj / SSRF / XXE / LDAP / path-traversal)
is reproducibly blocked by a WAF/CDN/edge filter — typically after the Advisor's reflect pass names a
"WAF/filter block" as the failure reason, or when the operator sees a 403/challenge on an otherwise-sound
payload. Not for a payload that is simply wrong (fix the payload first).

## Methodology (all target-facing — through the leash, in scope, rate-capped)
1. **Fingerprint the defense.** `tools/leashed.sh <target_dir> bin/wafrift detect --target "<url>"` — know
   which WAF (Cloudflare/Akamai/Fastly/Imperva/F5/AWS-WAF) so the search uses the right dialect/gene-bank.
2. **Search for a bypass that STILL EXECUTES.** Prefer the detonation-guided mode — it only accepts a
   variant that passes the WAF **and** actually fires the effect, proven in wafrift's sandbox:
   ```bash
   tools/leashed.sh <target_dir> bin/wafrift exploit --target "<url>" --param <p> \
     --grammar <sqli|xss|cmdi|ssti|ssrf|ldap|path-trav> --payload "<the blocked payload>" \
     --format json -o raw/<label>/wafrift-exploit.json
   ```
   If detonation isn't applicable, use `scan` to rank bypassing variants by WAF-pass confidence, then
   detonate the top candidates yourself against the real sink.
3. **Re-prove the CLASS oracle with the winning variant.** A variant that merely returns 200 is NOT proof.
   Take the bypassing payload and re-run the class's own oracle (`proof/oracles`): OOB callback for blind
   SSRF/RCE/XXE (unique interactsh token), DB banner for SQLi, command output for RCE, DOM execution via
   `proof/dynamic-validate` for XSS. The finding is the bypassing variant that achieves that oracle.
4. **For reflected XSS, consider the WAF-blind lane.** `bin/wafrift client-deliver ...` emits the
   fragment / window.name / postMessage / storage / client-route channels whose taint source never reaches
   the server — no WAF inspects them; prove with DOM execution (`proof/dynamic-validate`), not a server
   response.

## What counts as a finding
- **Finding:** a bypassing payload that **passes the WAF AND meets the class oracle** — report the variant,
  the oracle evidence, and the exact `wafrift` invocation under `raw/<label>/`. Severity = the class's, not
  "a WAF bypass" on its own.
- **Lead:** a variant that passes the WAF but you could not re-prove impact — the bug may not be there;
  note it, don't inflate "I beat the WAF" into a vuln.

## Oracle (load-bearing)
The oracle is the **underlying class's oracle re-met by the bypassing variant** (`proof/oracles`), not
"wafrift reported a bypass". A WAF bypass with no downstream impact is not a finding. Keep the search
bounded by the leash rate-cap — evolutionary ≠ flood.

## Red line
In-scope hosts only, through the leash, safe-PoC limits (RCE = whoami/id/hostname). The mutation search is
capped by the leash; never turn it into a flood or a brute. `origin-hints`/`origin_bypass` only against
authorized in-scope origins. The safeguard red line, the oracle gate, and the skeptic lenses are unchanged.
