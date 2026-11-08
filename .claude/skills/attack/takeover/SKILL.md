---
name: attack-takeover
description: Prove a subdomain takeover — a dangling DNS record pointing at a claimable third-party service — by reproducing the claimable fingerprint, without claiming third-party infrastructure.
category: attack
class: takeover
cwe_ids: [CWE-284, CWE-350]
tags: [takeover, subdomain, dangling-cname, dns, session-theft]
tools: [subzy, dnsx, httpx, nuclei]
version: "1.0"
---

# Subdomain takeover — proof

## Objective
Confirm that an in-scope hostname's DNS points at a de-provisioned, **claimable** third-party service
— to a reproducible PoC — and (via the chain-builder) show the security impact on the parent domain.

## Methodology (iterate; confirm, do not claim)
1. **Re-resolve the record.** `bin/dnsx -cname -resp` on the candidate host — capture the dangling
   CNAME/target (e.g. `*.s3.amazonaws.com`, `*.github.io`, `*.herokudns.com`, `*.azurewebsites.net`).
2. **Reproduce the claimable fingerprint.** Fetch the service edge through the leash and capture the
   exact "unclaimed" response (`NoSuchBucket`, "There isn't a GitHub Pages site here",
   "No such app", Fastly/Shopify/Zendesk not-configured). Cross-confirm with
   `bin/subzy run --targets host.txt` and `nuclei -tags takeover`. **That fingerprint response IS the
   PoC** — save the request/response under `raw/attack-<h>/`.
3. **Do NOT claim the resource.** Registering the bucket/page/app would mean acting on third-party
   infrastructure and serving content from the victim's name — out of bounds. The reproduced
   fingerprint + the resolution chain is sufficient, accepted proof for every major program.
4. **Severity by impact (chain).** A bare takeover of a marketing host is medium; a takeover of a host
   that the parent domain sets cookies for, loads scripts from, or uses in OAuth/SSO redirects is
   high/critical — note the parent-domain relationship for the chain-builder (cookie/session theft,
   script injection, OAuth token theft).

## What to return
`proven_state: misconfig_proven` with: the host, the dangling target, the service, the captured
fingerprint response (`evidence`/`poc_path`), and the parent-domain impact theory. Origin-check: the
fingerprint must come from the real service edge for the in-scope host, not your own egress.

## Notes
All HTTP through the leash. Never claim/register the dangling resource; reproduction of the unclaimed
fingerprint is the finding. Keep it in scope — a dangling out-of-scope host is a lead for the operator.
