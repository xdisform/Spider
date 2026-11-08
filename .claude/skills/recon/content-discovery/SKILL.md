---
name: content-discovery
description: Brute-force directories, files, backups, and admin panels on live apps with a rate-capped, leashed wordlist fuzz.
category: recon
tags: [fuzzing, content-discovery, directories, backups, admin]
chains_with: [http-probe, web-crawl]
tools: [feroxbuster, ffuf]
version: "1.1"
---

# Content & path discovery

## Objective
Find the routes the app doesn't link to: hidden directories, admin panels, backup/config files, and
leftover artifacts (`.git`, `.env`, `*.bak`, `/backup/`) that the crawl and the archives miss.

## Methodology
1. **Fuzz paths.** Target-facing and noisy, so leash AND rate-cap it. Wordlists ship in
   `bin/.wordlists/seclists/` (`raft-large-directories.txt`, `directory-list-2.3-medium.txt`).
   - Single pass: `tools/leashed.sh targets/<t> bin/ffuf -u https://<host>/FUZZ -w bin/.wordlists/seclists/raft-large-directories.txt -mc 200,204,301,302,401,403 -rate 20 -t 10 -json -o raw/content-discovery/<host>.json`.
   - **Recursive (deeper trees):** `tools/leashed.sh targets/<t> bin/feroxbuster -u https://<host> -w bin/.wordlists/seclists/raft-large-directories.txt --rate-limit 20 -d 3 --json -o raw/content-discovery/<host>-ferox.json` — feroxbuster auto-recurses into discovered dirs and filters soft-404s, catching nested routes a one-level ffuf pass misses.
   Keep the rate inside the program's limit — content discovery is where scanners get banned.
2. **Backup & config hunt.** Second pass with a backup/extension list (`.bak`, `.old`, `.zip`, `.sql`,
   `.env`, `~`) appended to known filenames, plus `.git/HEAD`, `.svn/`, `/actuator`, `/server-status`.
3. **Admin & staging.** Wordlist for `/admin`, `/console`, `/manage`, `/debug`, `/internal`; a
   200/401/403 there is a strong lead (a reachable admin panel is not access — that's the attack phase).
4. **Triage.** Discard soft-404s (calibrate against a random path first); keep the real hits and feed
   them back into `web-crawl` and attack selection.

## What to return
The discovered paths with status/size/words, grouped by type (admin / backup / config / api /
source-leak). Source-code leaks (`.git`, `.env`, `.sql` dumps) are high-priority — flag them for
immediate attack-phase verification. Scope-filtered.

## Evidence
The `ffuf` JSON per host and the fetched proof of any exposed file (e.g. the `.git/config` body or the
first bytes of a backup), under `raw/content-discovery/`.

## Notes
Always through `tools/leashed.sh` and rate-capped. A 200 on `/admin` or a downloadable `.env` is a
lead until the attack phase proves it grants access or leaks live secrets per `poc-standard` — an
`.env` with a working key that unlocks data is a finding; an empty template is not.
