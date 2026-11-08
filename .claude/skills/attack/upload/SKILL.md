---
name: attack-upload
description: Unrestricted file upload — bypass upload validation to plant an executable webshell (RCE) or a stored-XSS payload served in-origin.
category: web-application
tags: [file-upload, webshell, rce, stored-xss, bypass]
cwe_ids: [CWE-434]
chains_with: [oob-interactsh, attack-ssrf]
tools: [fuxploider, wafrift, curl, interactsh-client]
version: "1.1"
---

# Malicious file upload

## Objective
Prove the app accepts and *serves or executes* a file it should reject — the win is either code
execution from an uploaded shell or a stored payload that runs in the app's origin. Acceptance alone
is not the finding; the served/executed artifact is.

## Methodology
1. **Map the upload.** Avatar/attachment/import/document endpoints, the storage path files land at,
   and every check (client- and server-side extension allow/deny, `Content-Type`, magic bytes, size).
2. **Fuzz the bypass** through the leash:
   ```bash
   tools/leashed.sh targets/<t> bin/fuxploider --url https://app.target/upload --not-regex "error"
   ```
   `fuxploider` walks extension / `Content-Type` / magic-byte combinations and reports which the
   server accepts and where the file becomes reachable. Confirm the accepted file is retrievable
   (`curl`) at a served URL.
3. **Prove execution (RCE).** If an executable type lands in an executed path, upload a minimal shell
   and run only the policy-safe proof command (`id` / `whoami` / `hostname`). For a blind / no-output
   sink, make the payload call out and confirm out-of-band:
   ```bash
   bin/interactsh-client -json -o raw/<label>/interactsh.jsonl &   # see oob-interactsh
   ```
   A caught callback (its JSONL line) or the returned command output is the execution_evidence.
4. **Or prove stored XSS / SSRF.** If code won't execute: an HTML/SVG served in-origin with an
   `alert`-equivalent DOM effect (stored XSS), or an SVG/XXE parsed server-side reaching your
   interactsh domain (upload → SSRF, see `attack-ssrf`). Capture the *fired* effect, not just accept.

## Escalation ladder — "accepted" is rung 0; climb to RCE
Acceptance is never the finding. Climb until served→executed, then mint the foothold:
1. **Accepted** (rung 0, NOT a finding) — server stores a file it should reject.
2. **Served** — the file is retrievable at a URL in the app origin (`curl` it back). For HTML/SVG served
   in-origin that is stored-XSS (fires in victim context) → High.
3. **Executed** — the upload lands in an interpreter-executed path (`.php`/`.jsp`/`.aspx`/`.phtml`, or a
   path-traversal filename `../`, double-extension, null-byte, magic-byte+polyglot, `.htaccess` handler
   override). Upload a minimal shell, run **only** `whoami`/`id`. Command output mints `shell:<host>` +
   `foothold:<host>` → the post-foothold stage fires next wave.
4. **Parser-side (SSRF/XXE)** — an SVG/XML parsed server-side reaching your interactsh domain = upload→SSRF
   (chain into `attack-ssrf`'s ladder → cloud/internal). An image library (ImageMagick/Ghostscript) exec is RCE.
Bypass the validator with `bin/fuxploider` (extension/MIME/magic-byte combos); if a WAF/CDN strips the body,
mutate the multipart/content-type through `bin/wafrift` (content-type + multipart-boundary lens). Safe-PoC
only (`whoami`), never a persistent shell.

## What counts as a finding
- **Critical:** RCE — the proof command's output, or an OOB callback, from the uploaded file.
- **High:** stored XSS executing in-origin, or an upload-driven SSRF with a captured callback/response.
- **Lead only:** the server *accepts* a dangerous file but you can't show it served, executed, or
  parsed — a `[UNCONFIRMED CANDIDATE]` per `poc-standard`, never a critical, without execution_evidence.

## Evidence
The accepted upload request, the served URL / execution response (command output, OOB line, or fired
XSS), and a runnable PoC, all under `raw/<label>/`.
