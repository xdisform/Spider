---
name: attack-ssrf
description: Server-Side Request Forgery — make the server fetch attacker-chosen URLs to reach internal services and cloud metadata.
category: web-application
tags: [ssrf, injection, cloud, blind]
cwe_ids: [CWE-918]
chains_with: [oob-interactsh, attack-xxe]
tools: [interactsh-client, nuclei, wafrift, httpx, curl]
version: "1.1"
---

# SSRF

## Objective
Prove the server makes a request to a destination you control or to an internal resource it
shouldn't reach — and capture the proof (an OOB callback, or the internal response body).

## Methodology
1. **Find sinks.** Any input that becomes a server-side request: `url=`, `image=`, `callback=`,
   `webhook=`, `next=`, PDF/SVG/preview generators, URL importers, XML parsers (XXE→SSRF),
   link-unfurlers. Mine them from recon endpoints/params.
2. **Confirm blind, first.** Point the sink at a unique interactsh domain (see `oob-interactsh`).
   A DNS/HTTP callback = confirmed SSRF. This is your baseline proof.
3. **Reach internal.** If in scope and policy allows, target internal ranges and cloud metadata
   (`169.254.169.254` and provider paths). Capture the returned body as impact.
4. **Bypass filters.** If naive URLs are blocked: alternate IP encodings (decimal/octal/hex),
   `[::]`/IPv6, DNS rebinding, redirects to internal, `@`-tricks, unicode, uppercase scheme.

## Escalation ladder — SSRF is a pivot, not the finish (climb to internal RCE)
A blind callback proves the sink; it is the START. A senior walks SSRF to cloud/infra takeover. Climb the
rung the environment exposes, proving each primitive minimally and **minting the capability**:
1. **Blind OOB** (baseline) — unique interactsh callback = confirmed SSRF.
2. **Internal read** — fetch an internal-only service (`http://127.0.0.1:<admin-port>/`, internal dashboards,
   `/server-status`, ES/Kibana/Consul/etcd) and return a body that proves cross-boundary read.
3. **Cloud metadata → creds** — AWS `169.254.169.254/latest/meta-data/iam/security-credentials/` (IMDSv1) or
   the IMDSv2 token dance (`PUT /latest/api/token` then `GET` with `X-aws-ec2-metadata-token`); GCP
   `metadata.google.internal` with `Metadata-Flavor: Google`; Azure `169.254.169.254/metadata/identity/...`.
   A returned access key/token = **critical** → provides `creds:cloud@<host>`; pivot with the cloud MCP/CLI
   (STS `get-caller-identity`, list S3/Secrets) to prove data impact — never beyond the recovered scope.
4. **gopher:// / protocol smuggling** — where the fetcher allows non-HTTP schemes, `gopher://` to internal
   Redis (`SLAVEOF`/`CONFIG SET dir` → webshell, or read keys), memcached, internal SMTP, or an unauth
   internal HTTP API; `dict://`/`file://` for read. This is the SSRF→internal-RCE bridge → mints `shell:<host>`.
5. **Internal RCE** — chain the reached internal service's own vuln (an internal Jenkins/Actuator/Struts) to
   command execution; prove with `whoami` only. Mints `shell:`+`foothold:` → post-foothold stage fires next wave.
Honour safe-PoC at every rung (read-only metadata fetch, `whoami` only). If a rung needs a destructive
internal write or a safeguard — STOP, return `blocked` with the rung reached. Filter bypass: alternate IP
encodings, `[::]`, DNS rebinding, redirect-to-internal, `@`-tricks, and `bin/wafrift` to mutate a blocked URL.

## What counts as a finding
- **Critical:** cloud-metadata credentials returned, or SSRF chained to an internal response proving
  compromise (Redis/admin API), or internal RCE.
- **High:** blind-but-confirmed SSRF (unique OOB callback), or an internal/metadata response short of creds.
- **Lead only:** the parameter looks fetch-like but no callback and no internal response.

## Evidence
The exact injecting request, the interactsh JSONL callback line (unique subdomain), and any
internal response body — all under `raw/<label>/`.
