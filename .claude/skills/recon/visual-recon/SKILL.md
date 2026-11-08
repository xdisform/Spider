---
name: visual-recon
description: Screenshot live in-scope apps to triage the surface at scale and spot login/admin/staging/default pages worth attacking.
category: recon
tags: [screenshots, triage, visual, surface]
chains_with: [http-probe, content-discovery, web-crawl]
tools: [httpx, gowitness]
version: "1.1"
---

# Visual recon

## Objective
Capture a screenshot of every live app so you can triage hundreds of hosts by eye in minutes — finding
the login portals, admin consoles, staging/default installs, and verbose error pages that a status
code alone hides.

## Methodology
1. **Screenshot at scale (httpx).** Target-facing, so leash it:
   `tools/leashed.sh targets/<t> bin/httpx -l live-hosts.txt -screenshot -system-chrome -sc -title -json -srd raw/visual-recon/`.
   httpx drives headless Chrome and writes a PNG per host alongside the status/title metadata.
1a. **gowitness (deeper visual recon).** For richer output — perception hashing, tech detection, and
   a browseable report DB — also run:
   `tools/leashed.sh targets/<t> bin/gowitness scan file -f live-hosts.txt --screenshot-path raw/visual-recon/gowitness/`.
   gowitness produces an SQLite DB with per-URL metadata (response headers, TLS info, console logs,
   network events) alongside the screenshots — richer than httpx's JSON for triage. Its perception
   hashes let you cluster visually-identical pages (CDN defaults, parked domains) and focus on the
   unique ones. Run BOTH: httpx for quick status/tech, gowitness for deep visual+header context.
2. **Cover discovered paths.** Feed not just roots but the interesting paths from `content-discovery`
   and `web-crawl` (login, admin, dashboards) so the shots capture the real entry points.
3. **Eyeball & bucket.** Sort the images: login/auth, admin/console, default-install (Apache/nginx/
   Tomcat/phpMyAdmin), staging/dev banners, verbose errors, and blank/parked. Default installs and
   exposed admin UIs jump the attack queue.
4. **Flag for follow-up.** Each interesting screenshot becomes a tagged lead (host + path + why) for
   the attack phase and for `content-discovery` to go deeper.

## What to return
The screenshot set with per-host status/title, bucketed by page type, and a shortlist of the
highest-value visual leads (exposed admin, likely default creds, staging, sensitive info on-screen).
Scope-filtered.

## Evidence
The per-host PNGs and the `httpx` JSON metadata, under `raw/visual-recon/`.

## Notes
Screenshotting loads the target in a real browser — always through `tools/leashed.sh` (in-scope,
rate-capped). A revealing screenshot is a lead; access or impact (e.g. default creds actually working)
is proven only in the attack phase per `poc-standard`.
