---
name: dns-intel
description: Map a target's DNS surface — records, mail auth (SPF/DMARC), PTR/netblock/ASN, and CDN/WAF edge — from resolvers and certs.
category: recon
tags: [osint, dns, email-security, asn, cdn]
chains_with: [subdomain-enum, http-probe]
tools: [dnsx, tlsx, theHarvester]
version: "1.1"
---

# DNS & edge intelligence

## Objective
Build the DNS picture of the in-scope target: what resolves, where its mail goes, whether email
spoofing is possible (SPF/DMARC), which netblocks/ASNs the assets live in, and whether a CDN/WAF
fronts the origin. All passive — resolvers and certificates, never the target's app.

## Methodology
1. **Core records.** `bin/dnsx -l hosts.txt -a -aaaa -cname -mx -ns -soa -txt -caa -resp -json` —
   A/AAAA (origin IPs), CNAME (points at a CDN/SaaS?), NS/SOA (DNS provider), CAA (which CAs may issue).
2. **Mail auth.** Pull TXT for the apex and `_dmarc.<domain>`: `bin/dnsx -d <domain> -txt -resp`.
   Read SPF (`v=spf1`, `-all` vs `~all`/`?all`) and DMARC (`p=none` = effectively spoofable). A missing
   or `p=none` DMARC, or an overly-broad SPF, is a reportable email-security lead.
2a. **theHarvester email intel.** `bin/theHarvester -d <domain> -b all -f raw/dns-intel/harvester`
   pulls email addresses tied to the domain from search engines, Hunter, Shodan, SecurityTrails.
   Cross-reference the MX records from step 1 with the harvested emails — mismatches (emails hosted
   on a different MX than the domain's own) reveal shadow mail infrastructure. The email list itself
   feeds password-spray scope and org-chart mapping for the attack phase.
3. **Reverse & netblock.** `bin/dnsx -l ips.txt -ptr -resp` for PTR names; group the A-record IPs into
   /24s and note the owning ASN/provider (hosting vs corporate netblock) — this scopes `port-service`.
4. **Edge / CDN / WAF.** A CNAME to a known CDN (cloudfront/fastly/akamai/cloudflare) or the cert
   issuer via `bin/tlsx -l hosts.txt -san -cn -issuer -json` reveals the fronting layer. Flag hosts
   whose A record is a CDN edge vs a bare origin IP — an exposed origin behind a CDN is high-value.

## What to return
Per in-scope name: resolved records, mail-auth verdict (SPF/DMARC), owning netblock/ASN, and edge type
(CDN-fronted vs direct origin). Any exposed origin IP behind a CDN, and any weak/absent DMARC, are
leads for the attack and reporting phases. Out-of-scope names stay leads, never targets.

## Evidence
The raw `dnsx`/`tlsx` JSON, the SPF/DMARC TXT strings verbatim, and the IP→netblock mapping, saved
under `raw/dns-intel/`.

## Notes
All passive OSINT — run `dnsx`/`tlsx` direct, NOT through the leash (they hit resolvers/CAs, not the
target; the leash would 403 them as off-scope). Check every probed name against `scope.yaml`.
