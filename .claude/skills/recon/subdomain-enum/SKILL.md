---
name: subdomain-enum
description: Enumerate the subdomain/asset surface of an in-scope target, resolve it, and keep only what's in scope.
category: recon
tags: [osint, subdomains, dns, attack-surface]
tools: [subfinder, amass, theHarvester, asnmap, tlsx, dnsx, httpx, alterx, puredns, maigret, spiderfoot]
version: "1.3"
---

# Subdomain & asset enumeration

## Objective
Discover as much of the target's host surface as possible, resolve it, and hand the live in-scope
hosts to the rest of the pipeline. Anything not in `scope.yaml` is a **lead**, never a target.

## Methodology
1. **Passive enum.** `subfinder -d <domain> -all -silent` (CT logs, DNS aggregators, search). More
   provider API keys = more sources.
1b. **Amass passive sweep.** `bin/amass enum -passive -d <domain> -json raw/<label>/amass.json`.
   Amass queries a wider set of passive sources than subfinder (CIRCL, CommonCrawl, URLScan, GitHub,
   social APIs, DNSDB) — run BOTH and merge-dedup. Amass also maps the org's ASN graph:
   `bin/amass intel -org "<ORG_NAME>" -json raw/<label>/amass-intel.json` discovers related domains
   the org owns but that subfinder won't see (sister brands, acquired properties). Pure passive, no leash.
1c. **theHarvester cross-source enum.** `bin/theHarvester -d <domain> -b all -f raw/<label>/harvester`
   (uses Python 3.14 — call via `bin/theHarvester` wrapper). Pulls subdomains, emails, and IPs from
   search engines (Bing/DuckDuckGo/Baidu), Shodan, Hunter, SecurityTrails, VirusTotal, and others.
   Especially valuable for **email addresses** (→ identity leads for password-spray scope, org-chart
   mapping) and for catching subdomains that neither subfinder nor amass hit. Passive, no leash.
1d. **Identity OSINT (maigret).** When theHarvester or other sources yield employee names/handles,
   run `bin/maigret <username> --json flat --folderoutput raw/<label>/maigret/<user>/` to discover
   accounts across 2500+ platforms (GitHub, GitLab, Pastebin, dev forums). Leaked repos/gists/pastes
   containing internal hostnames, API keys, or config files are high-value leads. Passive, no leash.
1e. **Spiderfoot aggregation (optional, heavyweight).** If the above sources leave gaps or for a
   thorough initial sweep: `bin/sf -s <domain> -t INTERNET_NAME,IP_ADDRESS,EMAILADDR -q -o json
   > raw/<label>/spiderfoot.json`. Spiderfoot runs 200+ modules in one pass (DNS, WHOIS, search,
   pastebin, threat intel, social). It's slow but comprehensive — use when time allows or when the
   target surface seems larger than subfinder+amass reveal. Passive, no leash.
1a. **ASN pivot (asnmap).** Discovery TOP-DOWN from the legal entity, not just from the domain.
   `echo "<ORG_NAME_OR_ASN>" | bin/asnmap -silent -json > raw/<label>/asnmap-org.json` and
   `bin/asnmap -d <domain> -silent -json`. This expands the target's full IP footprint (every CIDR
   the org owns, per IPtoASN data) which subfinder/tlsx cannot — subfinder sees only published DNS,
   asnmap sees the whole AS. Pipe into naabu→httpx:
   `echo "<ORG>" | bin/asnmap -silent | bin/naabu -silent | bin/httpx -silent`.
   Needs `PDCP_API_KEY` env var (ProjectDiscovery Cloud free tier). Pure passive, no leash.
2. **Cert pivot.** `tlsx` on known hosts — SAN fields reveal more names; loop them back into step 3.
2a. **Active permutation brute (surface expansion).** Passive only sees what's published — brute the
   rest. Generate candidates with `alterx` (permutations of known names + a wordlist:
   `bin/.wordlists/seclists/subdomains-top1million-110000.txt`) and resolve them. Default path, no
   build needed: `bin/alterx -l known.txt -enrich | bin/dnsx -silent -a -resp`. Heavy/scale path (if
   provisioned): pipe into `bin/puredns resolve` (needs massdns) for throughput + wildcard filtering.
   These are passive-to-resolver (hit DNS, not the target web app) — run DIRECT, not through the leash.
4. **Liveness + first-look.** `httpx -sc -title -tech-detect -json` on resolved hosts to see what's
   actually up, its stack, and its priority.
5. **Scope-filter.** Split results: in-scope (per `scope.yaml`, exact vs subdomain rule) → assets;
   out-of-scope → `leads` in the return (do NOT probe them further).

## What to return
Every in-scope host with: resolved IP, live HTTP status/title/tech, and a priority guess (login/
admin/api/staging = higher). Out-of-scope discoveries as leads. All backed by files under
`raw/<label>/`.

## Notes
All HTTP goes through the leash (in scope, header-tagged, rate-capped). Keep passive-first; only
resolve/probe in-scope hosts.
