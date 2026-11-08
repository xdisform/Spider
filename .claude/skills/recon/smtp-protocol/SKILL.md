---
name: smtp-protocol
description: Map SMTP/IMAP semantics on in-scope MX — sender-spoof (SPF gap), RCPT user-enumeration, AUTH exposure, STARTTLS downgrade. Gated, non-HTTP-leashed.
category: recon
tags: [smtp, imap, email, spf, starttls, enumeration]
chains_with: [dns-intel, port-service]
tools: [smtpeek, testssl, curl]
version: "1.1"
---

# SMTP / IMAP semantics probe

## Objective
Read what the in-scope mail surface actually accepts and enforces — whether it will relay or accept a
spoofed sender, leak which mailboxes exist, offer credentials in cleartext, or drop TLS — and hand each
proven weakness to triage as a mail-security defect. This is a non-HTTP lens, so it never goes through
the HTTP leash.

> **Gate.** Only run when `scope.yaml` `policies.smtp_semantics_probe.enabled: true`. Respect
> `max_recipients` (RCPT enumeration cap) and `max_from_variants` (sender-spoof cap). Every connection
> goes through `tools/leash-tcp.sh <target_dir> <mx-host> …` (the non-HTTP scope audit — fail-closed on
> an off-scope host). **If the policy is not enabled, report the lens gated and skip it.**

## Methodology
1. **Scope the mail hosts.** From `dns-intel` (MX records) and `port-service` take the in-scope MX and
   the open mail ports (25/465/587, IMAP 143/993). Every dialog below is prefixed with
   `tools/leash-tcp.sh targets/<t> <mx>` so an off-scope host is refused before a packet leaves.
2. **Banner + capabilities.** Open the SMTP dialog and issue `EHLO <yourdomain>`; read the advertised
   extensions — AUTH mechanisms, `STARTTLS`, `SIZE`, `VRFY`/`EXPN`. Drive the raw dialog through the
   leash with `swaks` if it is installed (optional, not bundled in `bin/`), otherwise an
   `openssl s_client -starttls smtp -connect <mx>:587` session or `curl -v smtp://<mx>:25`. `bin/smtpeek`
   also returns a structured banner/capabilities + TLS-posture dump in one pass (`-m enum` with no user
   list = recon-only).
3. **Sender-spoof / SPF gap (cap: `max_from_variants`).** With `MAIL FROM:` set to a spoofed in-scope
   sender and, separately, an external sender, offer `RCPT TO:` a mailbox **you control**, and see
   whether the server accepts the message without SPF/DMARC rejection (or accepts external→external =
   open relay). The proof is an accepted/delivered spoofed message to your own in-scope test mailbox.
4. **RCPT / VRFY user-enumeration (cap: `max_recipients`).** Primary tool `bin/smtpeek` through the
   non-HTTP leash — it drives VRFY/EXPN/RCPT with adaptive delay + stealth modes and emits a structured
   valid-vs-invalid oracle:
   ```bash
   tools/leash-tcp.sh targets/<t> <mx> bin/smtpeek -d <domain> -u users.txt -m combined -s starttls \
     -f json -o raw/<label>/smtpeek-<mx>.json
   ```
   Keep `users.txt` trimmed to `max_recipients` — do NOT sweep a full user list. Manual fallback: send
   `RCPT TO:` (or `VRFY`/`EXPN`) for a known-valid and a known-invalid local-part and diff the response
   codes/text. A reliable valid-vs-invalid oracle = an enumeration defect.
5. **AUTH exposure + STARTTLS downgrade.** Note if `AUTH LOGIN/PLAIN` is offered *before* STARTTLS
   (cleartext credential exposure). Test TLS posture with
   `tools/leash-tcp.sh targets/<t> <mx> bin/testssl --starttls smtp <mx>:587` — flag missing/optional
   STARTTLS, downgrade-able sessions, and weak protocols/ciphers.

## What counts as a finding
- **High/Critical:** a spoofed or relayed message proven accepted/delivered to an in-scope mailbox you
  control (open relay / SPF-not-enforced usable for phishing → program ceiling), or `AUTH` credentials
  accepted over an un-upgraded cleartext session.
- **Low/Medium:** a reliable RCPT/VRFY user-enumeration oracle, proven with the paired responses.
- **Lead only:** advertised `VRFY`, an AUTH mechanism list, or a `testssl` protocol warning with no
  accept/oracle demonstrated — an `[UNCONFIRMED CANDIDATE]` per `poc-standard`.

## Evidence
The exact SMTP dialog (EHLO / MAIL FROM / RCPT TO transcript with response codes), the
`raw/leash-tcp.jsonl` audit lines proving each host was in-scope, the `testssl` output, and a runnable
repro — all under `raw/<label>/`. State that recipients were your own and the caps were respected.
