---
name: http-probe
description: Probe hosts for live HTTP/S — status, title, tech stack, TLS, and the WAF/CDN fronting them — to triage the web attack surface.
category: recon
tags: [http, liveness, tech-detect, tls, waf]
chains_with: [port-service, web-crawl, visual-recon]
tools: [httpx, wafw00f]
version: "1.0"
---

# HTTP probing & WAF detection

## Objective
Turn a list of hosts/ports into a triaged web surface: what's actually live, its status/title, the
tech behind it, its TLS posture, and whether a WAF/CDN sits in front (which shapes every later attack).

## Methodology
1. **Liveness + first look.** Target-facing, so leash it:
   `tools/leashed.sh targets/<t> bin/httpx -l hosts.txt -sc -title -tech-detect -server -cdn -tls-grab -json`.
   One pass captures status, title, technologies, TLS cert/version, and the CDN flag.
2. **Cover every web port.** Feed the `host:port` pairs `port-service` found so non-443 web services
   (8080/8443/etc.) are probed too, not just the roots.
3. **WAF fingerprint.** `tools/leashed.sh targets/<t> bin/wafw00f -a https://<host>` to name the WAF
   (Cloudflare/Akamai/AWS/…). A detected WAF changes payload strategy and later explains 403s.
4. **Prioritize.** Rank by title/tech/status: login, admin, api, dashboard, staging, `.git`, default
   pages, and outdated framework versions rank highest and feed `web-crawl` + `content-discovery` first.

## What to return
Per live host: status, title, tech stack, TLS summary, CDN/WAF verdict, and a priority score. Dead
hosts dropped. High-priority apps flagged for crawl / content-discovery / visual-recon. Scope-filtered.

## Evidence
The `httpx` JSON lines and the `wafw00f` output per host, under `raw/http-probe/`.

## Notes
All probing is target-facing — every `httpx`/`wafw00f` run goes through `tools/leashed.sh` (in-scope,
header-tagged, rate-capped). A tech/version banner is a lead; a version-specific CVE is a finding only
once the attack phase proves it per `poc-standard`.
