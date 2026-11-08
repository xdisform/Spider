---
name: attack-prototype-pollution
description: Prove client- or server-side prototype pollution — inject into Object.prototype via __proto__/constructor.prototype and chain the polluted property to a real gadget (DOM-XSS, auth/logic bypass, or RCE on a vulnerable server sink). Oracle = the gadget fires, not just a polluted property.
category: web-application
tags: [prototype-pollution, proto, gadget, dom-xss, rce]
cwe_ids: [CWE-1321]
chains_with: [attack-xss, attack-rce, deep-source-trace, js-sink-mining]
tools: [curl, nuclei]
version: "1.0"
---

# Prototype pollution

## Objective
Prove that attacker input reaches `Object.prototype` (via `__proto__`, `constructor.prototype`, or a
merge/clone/path-set gadget) **and** that the polluted property drives a concrete impact. A polluted
property on its own is a misconfig; the finding is the **gadget**: DOM-XSS, an auth/logic bypass (a
truthy flag the app reads off the prototype), or server-side RCE where a polluted property lands in a
dangerous sink (child_process options, template engine, `Function`). `deep-source-trace`/`js-sink-mining`
usually hand this over with the source→sink chain already mapped — start from the seam, prove the gadget.

## Methodology
Route all target-facing requests through the leash (`tools/leashed.sh <target_dir> ...`); stay in scope.
1. **Confirm the pollution primitive.** Client-side: a URL/hash/JSON input parsed by a vulnerable
   merge/clone (lodash `merge`/`defaultsDeep`, `$.extend(true,...)`, query-string parsers) with a
   `__proto__[x]` / `constructor[prototype][x]` key. Server-side: a JSON body with `__proto__` reaching
   a recursive merge. Verify the property actually lands on the prototype (a fresh `{}` now carries `x`).
2. **Find the gadget — this is the finding.**
   - **DOM-XSS:** a polluted property flows into an HTML/script sink (`innerHTML`, a template option,
     a sanitizer config key like `ALLOWED_ATTR`). Chain to script execution → confirm with
     `dynamic-validate` (real DOM execution, not a reflected string).
   - **Auth/logic bypass:** the app reads a flag off the prototype (`isAdmin`, `role`, a feature gate)
     because its own object did not define it. Prove the privileged state server-side.
   - **Server RCE:** the polluted key reaches `child_process` spawn options (`shell`, `NODE_OPTIONS`,
     `env`), an EJS/Handlebars/Pug compile option, or `Function`. Prove command execution within the
     safe-PoC policy (whoami/id/hostname only) or an OOB callback (interactsh).
3. **Keep the PoC bounded.** Pollute ONE property, prove ONE gadget, then stop — never leave the
   prototype globally polluted on a shared/stateful service; use your own session/object where possible.

## What counts as a finding
- **High/Critical:** pollution + a proven gadget — DOM-XSS (high), auth/logic bypass to privilege
  (high), or RCE (critical, with execution_evidence).
- **Misconfig (low/medium):** the prototype is demonstrably pollutable (a fresh object carries the
  injected property) but you could not chain a gadget — report with the runnable PoC under `raw/`, do not
  inflate to high.
- **Lead:** a `__proto__` key is accepted but you cannot show it reached the prototype — prove it first.

## Oracle (load-bearing)
Per `proof/oracles/SKILL.md`: the gadget must FIRE on re-run — DOM execution captured by
`dynamic-validate`, the privileged server action succeeding, or command output / an OOB callback for
RCE. A polluted property with no gadget is the misconfig oracle (a fresh object shows the injected
property), not the impact oracle. Narration is not proof.

## Evidence
Under `raw/attack-<id>/`: the exact polluting request/input, proof the property reached the prototype,
and the gadget firing (DOM execution artifact, privileged response, or command output / OOB callback id),
plus a runnable PoC.

## Red line
In-scope targets only, through the leash, safe-PoC limits honored (RCE = whoami/id/hostname). Do not
leave a shared prototype globally polluted; nothing destructive, no DoS. The safeguard red line, the
oracle gate, and the skeptic lenses are unchanged.
