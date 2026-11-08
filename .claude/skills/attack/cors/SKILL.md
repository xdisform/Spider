---
name: attack-cors
description: CORS misconfiguration — a permissive cross-origin policy that lets an attacker page read another origin's authenticated responses.
category: web-application
tags: [cors, access-control, cross-origin, data-theft]
cwe_ids: [CWE-942]
chains_with: [attack-open-redirect, attack-idor]
tools: [nuclei, curl]
version: "1.0"
---

# CORS misconfiguration

## Objective
Prove an origin you control can read a *credentialed* cross-origin response it shouldn't — the target
reflects/allows your `Origin` **and** sets `Access-Control-Allow-Credentials: true`, exposing a
victim's authenticated data. The finding is the readable sensitive response, not the header alone.

## Methodology
1. **Enumerate CORS behavior.** For each interesting (ideally authenticated) endpoint, replay the
   request with an attacker `Origin` and inspect the ACAO/ACAC response headers through the leash:
   ```bash
   tools/leashed.sh targets/<t> curl -sD- -o /dev/null https://api.target/me \
     -H 'Origin: https://evil.example' -H "Cookie: $SESSION"
   tools/leashed.sh targets/<t> bin/nuclei -u https://api.target -tags cors
   ```
2. **Classify the flaw.** Exploitable cases: `Access-Control-Allow-Origin` **reflects an arbitrary
   Origin** with `Allow-Credentials: true`; ACAO `null` accepted (reachable from a sandboxed iframe);
   weak regex trusting `target.com.evil.example` / `eviltarget.com`; or an `http://` origin trusted
   (network MITM). `ACAO: *` alone (credentials disallowed) is informational unless the data is public.
3. **Prove readability.** Host a PoC page on your origin that does a credentialed
   `fetch(target, {credentials:'include'})` and exfiltrates the body; run it under a logged-in victim
   session and capture the cross-origin data your page actually read. That read is the impact.
4. **Bypass origin allowlists.** Where a subdomain is trusted, a reflected/subdomain origin obtained
   via `attack-open-redirect` or a subdomain takeover can satisfy the check — note the chain.

## What counts as a finding
- **High/Critical:** attacker origin + credentials proven to read a victim's private/authenticated
  data (session, PII, tokens = critical) — demonstrated with the body your page exfiltrated.
- **Lead only:** a permissive header (`ACAO: *`, reflected origin) with **no** credentialed, sensitive
  data actually read — a `[UNCONFIRMED CANDIDATE]` per `poc-standard` until the read is shown.

## Evidence
The request/response showing the reflected `Origin` + `Allow-Credentials: true`, the PoC HTML page,
and the cross-origin body it exfiltrated, all under `raw/<label>/`.
