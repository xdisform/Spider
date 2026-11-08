---
name: attack-ognl
description: OGNL / SpEL / expression-language injection — user input reaches a server-side expression evaluator (Struts, Atlassian, Spring), escalating to code execution.
category: web-application
tags: [ognl, spel, mvel, expression-injection, struts, atlassian, spring, rce]
cwe_ids: [CWE-917, CWE-94]
chains_with: [oob-interactsh, attack-ssti, attack-rce, poc-standard]
tools: [interactsh-client, curl, httpx]
version: "1.0"
---

# OGNL / SpEL / EL injection

## Objective
Prove user input is evaluated by a server-side expression language (OGNL in Struts2/Atlassian, SpEL in
Spring, MVEL, JSP EL) and escalate to **command execution** — proof is command output (`id`/`whoami`/
`hostname` only, per policy) or an **OOB callback**, not a reflected `${...}` or a 500. Target HTTP via the
leash (`tools/leashed.sh $T …`); blind OOB via interactsh direct. OGNL is EL-specific SSTI — if the engine
is a template (Jinja/Freemarker/Velocity) use `attack-ssti` instead.

## Fingerprints (requires)
- **Struts2** (`.action`/`.do`, `Content-Type` parsing (S2-045), `redirect:`/`method:` params, OGNL error
  leaks), **Atlassian** Confluence/Jira (`%{...}` in a reachable param — CVE-2021-26084 shape),
  **Spring** (`#{...}` / SpelExpressionParser bound to a param, `spring-expression` on the classpath),
  **MVEL/JSP-EL**. Signal: a `${7*7}`/`%{7*7}`/`#{7*7}` → `49` reduction, or an OGNL/SpEL class in a stack trace.

## Methodology
1. **Find the sink.** Params reflected into an OGNL/SpEL context: Struts param interceptors, redirect/
   action names, Atlassian macro/params, Spring `@Value`/SpEL-bound fields, search/filter DSLs.
2. **Confirm evaluation (baseline).** A math/concat probe that REDUCES server-side (`%{7*7}`→`49`,
   `#{7*7}`→`49`, `${7*191}`) — distinct from a literal reflection. Vary the delimiters per engine.
3. **Prove BLIND first.** Make the expression resolve a unique interactsh host
   (`#{T(java.lang.Runtime)...}` / OGNL `(new java.net.URL('http://<token>.oob')).openStream()` style) and
   watch `bin/interactsh-client -json -o raw/ognl/oob.jsonl`. A callback = server-side eval.
4. **Escalate to command output** within safe-PoC: the minimal `Runtime.exec`/`ProcessBuilder` OGNL/SpEL
   one-liner that returns `id`/`hostname`. Capture the exact output. Stop at proof.
5. **Guarded engines** (OGNL SecurityManager / allowlist): note it, try the known sandbox-escape for that
   version only; if it needs defeating a control as an attack → `blocked`.

## Red line
No brute of a secret, no destructive/DoS expression, no shell/persistence. A sandbox you can only cross by
evading a safeguard is `blocked:safeguard` — hand off, do not evade.

## What counts as a finding
- **Critical:** command output (`id`/`whoami`) returned, or an OOB callback from the expression.
- **High:** confirmed server-side eval (arithmetic reduced) with no command path reached yet.
- **Lead only:** `${7*7}`/`%{7*7}` stays literal — `[UNCONFIRMED CANDIDATE]`, never an OGNL finding.

## Evidence (under `raw/ognl/`)
The injecting request, the reduced-expression or command-output response, the interactsh callback line,
the detected engine/version, and a runnable PoC. Oracle rows: *RCE (command output)* / *SSRF / blind RCE
(OOB)* in `proof/oracles`.
