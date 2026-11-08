---
name: takeover
description: Detect subdomain takeover across the resolved host surface — dangling CNAMEs pointing at claimable third-party services.
category: recon
tags: [takeover, subdomain, dangling-cname, dns, quick-win]
tools: [subzy, dnsx, httpx, nuclei]
version: "1.0"
---

# Subdomain takeover detection

## Objective
Find in-scope hostnames whose DNS still points at a de-provisioned third-party service (S3, GitHub
Pages, Heroku, Azure, Fastly, Shopify, …). A claimable dangling record is a frequently-paid
high/critical — and the entry link for session/cookie-theft chains.

## Methodology
1. **Feed the resolved surface.** Take the hosts from `subdomain-enum` / `state.json` (CNAME targets
   matter most — `dnsx -cname -resp`).
2. **Fingerprint for takeover.** `tools/leashed.sh targets/<t> bin/subzy run --targets hosts.txt --hide_fails --output raw/takeover/subzy.json`
   — subzy matches 80+ service "not-claimed" signatures. Cross-check with `nuclei -tags takeover`.
3. **Confirm, don't claim.** A positive = the service edge returns the claimable fingerprint
   (e.g. NoSuchBucket, "There isn't a GitHub Pages site here"). Capture the response as proof.
   **Do NOT actually register/claim** the resource — reproducing the dangling fingerprint IS the
   PoC; claiming it would be acting on third-party infrastructure.
4. **Scope-gate.** Only in-scope hosts. A dangling out-of-scope host is a lead.

## What to return
Each candidate host → the dangling CNAME target, the service, the matched fingerprint, and the
evidence file. Mark `class: takeover` so the attack phase proves it (and the chain-builder can wire
it into cookie/session theft on the parent domain).

## Notes
All HTTP through the leash. This is a fast, high-value first-pass — run it early on the freshly
resolved surface. Confirmation = the fingerprint response under `raw/takeover/`, never a real claim.
