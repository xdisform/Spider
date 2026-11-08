---
name: attack-open-redirect
description: Open redirect — force the app to send a user or the server to an attacker-chosen destination, then escalate to SSRF, OAuth token theft, or filter bypass.
category: web-application
tags: [open-redirect, redirect, ssrf, oauth, phishing]
cwe_ids: [CWE-601]
chains_with: [attack-ssrf, attack-cors]
tools: [nuclei, ffuf, curl]
version: "1.0"
---

# Open redirect

## Objective
Prove a redirect parameter sends the user (or the server) to a destination you control, and — where
scope allows — turn that primitive into real impact: SSRF, OAuth/`token` leakage, or a security-
control bypass. A bare cross-domain redirect is low; the finding lives in the escalation.

## Methodology
1. **Find redirect sinks.** Params that steer a `Location:` / `window.location`: `next=`, `url=`,
   `redirect=`, `return=`, `dest=`, `continue=`, `callback=`, plus login/logout/SSO return paths.
   Mine them from recon endpoints and JS.
2. **Fuzz candidates** through the leash and read the resulting `Location`:
   ```bash
   tools/leashed.sh targets/<t> bin/ffuf -w payloads.txt \
     -u 'https://app.target/login?next=FUZZ' -mc 301,302,303,307,308
   tools/leashed.sh targets/<t> bin/nuclei -u https://app.target -tags redirect
   ```
   Confirm the response `Location` (or a client-side hop) points at your external origin.
3. **Bypass naive filters.** If `https://evil.example` is blocked: `//evil.example`, `/\evil.example`,
   `https:evil.example`, `https://app.target@evil.example`, whitelisted host as subdomain/path
   (`https://app.target.evil.example`), unicode/backslash tricks, double-encoding.
4. **Escalate.** A server-side follow (redirect → internal URL) becomes SSRF (see `attack-ssrf`); an
   OAuth/SSO `redirect_uri` that honors your host leaks the `code`/`token` — prove it by capturing the
   credential that lands on your listener. That captured value is the real impact.

## What counts as a finding
- **High/Critical:** the redirect steals a token/`code`, or drives SSRF to an internal/metadata
  resource (captured secret = critical) — proven with the leaked value on your side.
- **Medium:** a clean, reproducible cross-domain redirect usable for credible phishing.
- **Lead only:** reflection in `Location` that a browser does not actually follow off-domain — a
  `[UNCONFIRMED CANDIDATE]` per `poc-standard` until impact is shown.

## Evidence
The request, the `Location` / hop showing the external destination, and — for escalation — the
captured token or the internal SSRF response body, all under `raw/<label>/`.
