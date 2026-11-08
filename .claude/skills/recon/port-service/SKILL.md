---
name: port-service
description: Discover open TCP ports on in-scope hosts/CIDRs and map each to its service, scope-pinned so no out-of-scope host is touched.
category: recon
tags: [ports, services, network, attack-surface]
chains_with: [dns-intel, http-probe]
tools: [naabu]
version: "1.0"
---

# Port & service discovery

## Objective
Enumerate the reachable TCP ports on in-scope hosts and CIDRs and map each open port to its likely
service, so the pipeline sees every network entry point — not just 443.

## Methodology
1. **Pin the scope first.** `naabu` does NOT honor the HTTP leash, so gate it with the guard before
   every run: `python tools/guard.py --scope "$(cat targets/<t>/scope.txt)" --check "bin/naabu -host <host>"`.
   Run only if it exits 0. Never feed `-list`/`-iL` target files the guard can't see into.
2. **Discover ports.** `bin/naabu -host <in-scope host or CIDR> -top-ports 1000 -rate <capped> -json`
   (or `-p -` for a full sweep when the program allows and time permits). Respect the program's rate
   limit — loud scans get you blocked, not more findings.
3. **Service hint.** Map each open port to its default service (22/ssh, 3306/mysql, 6379/redis,
   9200/elastic, 5601/kibana …). naabu gives the port; the service *name* here is a hypothesis, not a
   proven version.
4. **Hand off.** Feed every open HTTP/S port to `http-probe` (httpx) for real service and tech
   fingerprinting; feed non-web services (db/cache/admin/mgmt) to the attack phase as exposure leads.

## What to return
Per host: the open-port list with the guessed service, the netblock it sits in, and a priority note
(exposed db/cache/admin/mgmt ports rank high). Web ports flagged for `http-probe`. Everything checked
against `scope.yaml` — an IP that merely resolved in but isn't in scope is a lead, never a scan target.

## Evidence
The `naabu` JSON output and the `guard.py` check that authorized the scan, under `raw/port-service/`.

## Notes
An open port is exposure, not yet a finding. A reachable service (e.g. an unauthenticated Redis)
becomes a finding only when the attack phase proves impact per `poc-standard`; until then it is a
strong lead.
