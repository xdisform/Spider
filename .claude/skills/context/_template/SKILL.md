---
name: context-<target-or-family>
description: Knowledge pack — known stack, typical paths, weak endpoints and disclosure history for <target/family>.
category: context
tags: [context, <target>, <stack>]
version: "1.0"
---

# Context: <target / tech family>

## Stack fingerprint
- Web/edge: <CDN/WAF/server, e.g. NGINX + a WAF appliance + a CDN edge>
- App frameworks: <CMS / Rails / Next.js / headless-CMS / Keycloak / ...>
- Auth/IdP: <Keycloak realms, SAML/OIDC brokers, SSO>
- Data/infra hints: <cloud, storage, known internal hosts>

## Typical / known-weak paths (probe these first)
- `<path>` — <why it matters, e.g. /api/admin/<resource> = admin API disclosure>
- `<path>` — <...>

## Known disclosure history (avoid duplicates, learn the classes)
- <#id / class / severity> — <one line; what was accepted before on this program>

## Applicable templates / CVEs
- nuclei tags: `<tags>`; CVE templates: `<list>` (LLM orchestrates known-good, doesn't reinvent).

## Chain hints for this target
- <e.g. a Keycloak realm with many IdP brokers → SAML ACS/XSW surface; CORS on a headless-CMS host → credentialed cross-origin read>

Keep this factual and sourced. It is a map, not a claim — agents still prove everything in scope.
