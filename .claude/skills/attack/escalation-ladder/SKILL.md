---
name: attack-escalation-ladder
description: After a foothold is proven, decide the single highest-value next rung (web/cloud/identity) and reuse a proven credential across the in-scope estate — routed entirely through the existing privesc/lateral/loot/cred-access packs, scope- and policy-gated, oracle-proven, never a safeguard evasion.
category: post-exploitation
tags: [escalation, post-exploitation, token, cloud, cred-reuse, planner]
cwe_ids: [CWE-269, CWE-522]
chains_with: [attack-privesc, attack-lateral, attack-loot, attack-cred-access, attack-ssrf]
tools: []
version: "1.0"
---

# Escalation ladder (post-foothold planner)

## Objective
A proven foothold (a `session:`/`shell:`/`token:`/`creds:` capability the attack graph already holds) is
the **start** of the finding, not the end — a lone medium foothold that is never climbed is why a run
ends with "one low". This pack is the senior reflex that decides the **single highest-value next rung**
and routes it to the pack that already owns that technique. It does not introduce a new exploit path; it
makes sure the obvious next step is actually taken, in scope, within policy, and proven by the oracle.

## Principle
Each confirmed foothold should produce exactly one explicit, provable next move — a composite hypothesis
the chain-builder emits and the re-attack wave proves through the unchanged oracle gate:
1. **Reuse the credential you already hold.** A proven `creds:<p>@<hostA>` is a lead that the SAME
   principal may authenticate on OTHER in-scope hosts/services. Propose a cred-reuse composite
   (`class:cred-access`, `host:<hostB>`, `requires:["creds:<p>@<hostA>"]`, `provides:["session:<hostB>"]`)
   for each in-scope host that offers that auth — handled entirely by `attack-cred-access` (spray-not-
   brute, `tools/leash-cred.sh`, one pass, policy-gated). This is the lateral-movement multiplier.
2. **Climb on the host you hold.** A `shell:`/`foothold:<host>` routes to `attack-privesc` (one oracle-
   proven single-step escalation), `attack-internal-recon` (read-only enumeration), and `attack-loot`
   (read the objective-relevant secret/file) per those packs — nothing new here, just sequenced.
3. **Follow identity, not just the box.** A stolen web session / OAuth or API token is a lead to the
   accounts and services that trust it — map where the token is accepted and prove one concrete
   privileged action it unlocks (authz boundary crossed, a second account reached). A cloud credential
   found on a held host is a lead for `attack-ssrf`/`attack-loot` to prove one scoped cloud read. Consult
   the target/program context pack and HackTricks for the stack-specific rung; prove ONE, then stop.
4. **Prefer the shortest path to the objective.** In flag/bounty mode, pick the rung that most reduces
   distance to the objective (foothold → loot the flag, or medium → the eligible high-tier impact), not
   the flashiest.

## What counts as a finding
The finding is always the **next rung proven**, graded by the impact it reaches (cred-reuse to a new
service = the new service's impact; privesc = the privileged action; identity reuse = the authz boundary
crossed). This pack never grades itself — the destination pack's oracle does.

## Oracle
Delegated to the destination pack's oracle (`proof/oracles/SKILL.md`): a real authenticated action with
the reused cred, a demonstrated privileged action for privesc, a crossed authz boundary for identity
reuse. A plan or a "could pivot" is NOT a finding — only a rung the oracle re-derives.

## Red line (hard — the same gates as every other pack)
In-scope hosts only (`tools/guard.py`), through the leash, safe-PoC limits honored. Cred reuse runs ONLY
where `policies.default_cred_control_test.enabled`, through `tools/leash-cred.sh`, as a single spray of
the SAME proven principal — never a brute, never a wordlist, never past the first lockout signal. Pivot
ONLY to hosts in `scope.yaml`; a reachable host that is NOT in scope is a LEAD recorded in `state.json`,
never attacked. Nothing destructive, no persistence/implant. If a rung would require defeating an auth
control as an attack, return `proven_state:'blocked'`, `blocked_reason:'safeguard'` — a hand-off, never an
evasion. The safeguard red line, the oracle gate, and the skeptic lenses are unchanged.
