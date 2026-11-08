---
name: exposed-datastores
description: Find and safely prove exposed backups, data stores, and source/config leaks — .git, .env, DB dumps, open buckets, unauth databases and admin panels.
category: recon
tags: [exposure, backups, datastore, git, secrets, buckets, disclosure]
chains_with: [content-discovery, cloud-assets, js-secret-mining, port-service]
tools: [httpx, nuclei, ffuf, gitleaks, trufflehog, s3scanner, curl]
version: "1.0"
---

# Exposed backups & data stores

## Objective
The highest-yield recon class: an unauthenticated backup, source tree, config file, or data store
that hands you the app's secrets or its data directly. Locate them in scope and prove **ACCESS** with
the smallest PoC possible — one config file, one key, one record — never mass-exfiltrate.

## Methodology
1. **VCS exposure (.git/.svn/.hg).** Probe for a live repo dir:
   `tools/leashed.sh targets/<t> bin/httpx -l hosts.txt -path /.git/HEAD,/.git/config,/.svn/entries,/.hg/requires -mc 200 -json`.
   Proof = fetch `/.git/config` (remote URL) and one packed object to show the tree is dumpable; run
   `bin/gitleaks detect --no-git --source <dumped>` on what you pulled to confirm live secrets. Don't bulk-clone.
2. **Config & env leaks.** Hunt `/.env`, `/config.php.bak`, `/appsettings.json`, `/wp-config.php~`,
   `/.aws/credentials` via `content-discovery` fuzzing, then fetch one:
   `tools/leashed.sh targets/<t> curl -s https://<host>/.env`. Verify it holds a LIVE secret with
   `bin/trufflehog filesystem <dir>` (verified findings only) — a working key beats a template.
3. **Backup archives & DB dumps.** Fuzz `.bak/.old/.zip/.tar.gz/.sql/.sql.gz/.dump` against known names:
   `tools/leashed.sh targets/<t> bin/ffuf -u https://<host>/FUZZ -w backups.txt -mc 200 -rate 20 -t 10 -json -o raw/exposed-datastores/<host>.json`.
   Confirm it's a REAL dump with a range request, not a full pull:
   `tools/leashed.sh targets/<t> curl -sr 0-2047 https://<host>/db.sql` — SQL header / archive magic bytes = proof.
4. **Source maps.** Fetch one `*.js.map`; `sourcesContent` present = original source recovered (feeds `js-secret-mining`).
5. **Object storage.** Open S3/GCS/Azure buckets tied to the target — run `cloud-assets` (`bin/s3scanner`,
   direct/off-leash): list one key, read one benign object. A public-writable bucket is high on its own.
6. **Unauthenticated data stores (HTTP).** Elasticsearch/CouchDB/Kibana/Jenkins on live hosts:
   `tools/leashed.sh targets/<t> bin/nuclei -l hosts.txt -tags exposure,misconfig,panel,logs -severity medium,high,critical`.
   Prove with ONE metadata read — ES `/_cat/indices`, CouchDB `/_all_dbs`, Jenkins `/script` reachable — not a document dump.
7. **Non-HTTP stores (Mongo/Redis).** Find the open port via `port-service` (`bin/naabu`), then probe through
   the TCP leash so it stays scope-pinned:
   `tools/leash-tcp.sh targets/<t> <host> bin/nuclei -u <host>:<port> -tags network,redis,mongodb`.
   Read one `INFO`/`serverStatus` field as proof of unauth access, never the keyspace.
8. **DB & admin panels.** A reachable phpMyAdmin/Adminer login is a LEAD; unauthenticated or default-cred
   entry that returns data is the finding — hand it to the attack phase to prove access.

## What counts as a finding
Severity is set by **PROVEN** impact per `poc-standard`, nothing less:
- **Critical:** an exposed store / backup / `.git` that yields live credentials or real user/business
  data you actually read back — one record or one working key is enough.
- **High:** unauthenticated read of a data store, or a downloadable dump/source tree whose sensitivity
  you demonstrate, or a public-writable bucket.
- **Medium / lead:** the file or panel is reachable (200 / login page) but you have not retrieved
  sensitive data or a live secret — a reachable `/admin` or an empty `.env` template is a lead, not a finding.

## Evidence
Under `raw/exposed-datastores/`: the exact request(s) carrying the mandatory scope header, the response
proving access (the `.git/config`, the range-request bytes, the verified-secret line, the single listed
key/record), and a runnable PoC (`.sh`/`.hurl`) a triager can replay. Keep one benign artifact only —
capturing volume is itself a policy violation.

## Notes
Off-leash/passive: `s3scanner` (hits cloud endpoints, not the target), and `gitleaks`/`trufflehog` over
already-downloaded local files. Target-facing HTTP (`httpx`, `nuclei`, `ffuf`, `curl`) always through
`tools/leashed.sh`; non-HTTP stores through `tools/leash-tcp.sh` (fail-closed on off-scope). Stay inside
the program's safe-PoC limits — read the minimum that proves access, and never delete, overwrite, or
bulk-download.
