---
name: attack-info-disclosure
description: Sensitive information disclosure — an exposed actuator/heapdump/env, source map, stack trace, or backup leaks a secret that is then PROVEN to work (authenticates / crosses a boundary).
category: web-application
tags: [info-disclosure, actuator, heapdump, source-map, stack-trace, secret-leak, spring-boot]
cwe_ids: [CWE-200, CWE-215, CWE-532, CWE-540]
chains_with: [attack-auth-bypass, attack-idor, attack-deser, oob-interactsh, poc-standard]
tools: [curl, httpx, trufflehog, gitleaks]
version: "1.0"
---

# Information disclosure (secret-that-works)

## Objective
Prove an exposed surface leaks a secret AND that the secret **actually works** — it authenticates, decrypts,
or crosses a trust boundary. A bare `200` on `/actuator/health`, a stack trace, or a `.map` file is **info,
not a finding**, until the leaked value is shown to do something. This is the anti-"bare 200" discipline:
the oracle is the leaked value used to cross a boundary. Target HTTP via the leash (`tools/leashed.sh $T …`).

## Fingerprints (requires)
- **Spring Boot Actuator:** `/actuator`, `/actuator/{heapdump,env,mappings,configprops,beans,threaddump}`,
  `/env`, `/heapdump`, `/metrics` reachable unauth.
- **Source maps:** `*.js.map` (webpack/react/angular) exposing source, internal routes, embedded keys.
- **Verbose errors / stack traces:** framework debug pages (Tomcat/Django/Werkzeug/Rails) leaking paths,
  tokens, SQL, internal hosts.
- **Exposed VCS/backup/config:** `.git/`, `.env`, `*.bak`, `backup.zip`, `web.config`, `application.yml`.
- **Test/staging instance leak:** a non-prod host exposing creds/data for the prod boundary.

## Methodology
1. **Enumerate the surface** (recon already flagged most): actuator paths, `.map` files, debug endpoints,
   `.git`/`.env`. Probe READ-ONLY, minimal, in policy.
2. **Extract the secret.** For a heapdump: download and mine it (`bin/trufflehog filesystem raw/info/heapdump`,
   or strings for `Authorization`, session tokens, DB creds, API keys). For `/env`/`configprops`: read the
   decrypted/leaked props. For source maps: recover source → embedded keys/endpoints. For `.git`: reconstruct
   and `bin/gitleaks`/`bin/trufflehog` it.
3. **PROVE it works (the oracle).** Use the leaked value legitimately: a leaked session/bearer reaches a
   protected resource (401/403 → 200 with that principal's private content that survives a fresh request); a
   leaked API key authenticates to its API and returns private data; a leaked DB cred is a `creds:` token
   (hand to `attack-auth-bypass`/post-foothold, do NOT mass-dump). Chain upward: a leaked signing key →
   `attack-deser`/`jwt` forge; a heapdump session → ATO.
4. **Severity by what the secret unlocks**, proven only — a leaked live admin token reaching admin data is
   critical; an exposed `.map` with no working secret is low/info.

## Red line
Read only what proves the secret works — no mass-exfil, no whole-dump copy, no destruction. A leaked cred is
used for ONE boundary-crossing proof, then stop (that's a foothold, hand it to the scheduler). Never brute.

## What counts as a finding
- **Critical/High:** leaked secret PROVEN to authenticate / decrypt / cross a boundary (token works, cred
  logs in, key signs) — graded by what it unlocks.
- **Low:** exposure reproduced (actuator/heapdump/.map/.git reachable) but no working secret extracted —
  a `misconfig_proven` lead, never buried as info, never inflated to high without the working secret.
- **Lead only:** a bare `200`/health page / generic error with nothing sensitive — `[UNCONFIRMED CANDIDATE]`.

## Evidence (under `raw/info/`)
The request reaching the exposed surface, the extracted secret (redacted in the report, full under raw/),
AND the request that USES it crossing the boundary (before/after: 401/403 → 200 with private content), the
trufflehog/gitleaks output, and a runnable PoC. Oracle row: *Auth bypass / ATO (boundary crossed)* /
*IDOR (cross-account record)* once the secret is exercised — a bare exposure alone is not the oracle.
