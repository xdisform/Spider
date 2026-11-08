---
name: oob-interactsh
description: Prove blind / second-order vulnerabilities with an out-of-band callback (interactsh). The only proof for bugs the in-line proxy can't see.
category: proof
tags: [oob, oast, interactsh, ssrf, blind-rce, blind-xxe, blind-sqli]
version: "1.0"
chains_with: [poc-standard]
---

# OOB confirmation with interactsh

Blind bugs — SSRF with no response, blind RCE/XXE/SQLi, blind XSS — leave no in-band proof. The
proof is an **out-of-band callback**: you inject a unique payload domain; if the target's backend
reaches it, you catch the DNS/HTTP hit. A caught callback is undeniable execution_evidence.

## Flow
1. **Start the client** (arsenal `bin/interactsh-client`), get a unique payload domain and stream
   events as JSON:
   ```bash
   bin/interactsh-client -json -o raw/<label>/interactsh.jsonl &
   # note the payload domain it prints, e.g. cXXXX.oast.pro
   ```
2. **Inject the payload domain** into the suspected sink — a URL parameter (SSRF), an XML entity
   (XXE), a hostname field, a template, a command context — one unique subdomain per injection so
   you know which one fired:
   ```
   https://app.target/fetch?url=http://<uniq>.<payload-domain>/
   ```
3. **Watch for the callback.** A DNS or HTTP event for your unique subdomain in
   `raw/<label>/interactsh.jsonl` = the backend reached out = the bug fired. That JSONL line is
   your `execution_evidence` (record the subdomain, protocol, source IP, timestamp).
4. **Escalate if in scope** — SSRF that reaches internal/metadata endpoints: follow the callback
   with a real internal fetch and capture the response (still within policy, no destructive calls).

## Notes
- Correlate each injection to its unique subdomain so a callback maps to exactly one payload.
- The public interactsh server works out of the box; a self-hosted `interactsh-server` gives a
  private, scope-isolated channel if the program requires it.
- `nuclei` and `dalfox` can drive interactsh automatically for OOB/blind-XSS correlation.
- No callback ≠ safe: it may be egress-filtered. Say "no OOB observed" honestly; don't claim proof.
