---
name: attack-lateral
description: Incalmo-style reachability-disciplined pivot — enumerate neighbours reachable FROM the footholded host, but act ONLY on a host already in scope.yaml (guard.py-asserted). A reachable host NOT in scope is a LEAD, never a target. A working pivot cred for an in-scope host2 provides creds:<p>@<host2>, the graph edge that unlocks host2's hypotheses next wave. ATT&CK Lateral Movement T1021. No scanning/flooding of out-of-scope ranges.
category: post-foothold
tags: [lateral-movement, pivot, reachability, in-scope, creds, post-foothold]
cwe_ids: [CWE-284, CWE-306]
chains_with: [attack-internal-recon, attack-loot, attack-cred-access]
tools: [guard.py, netexec]
version: "1.0"
---

# Lateral movement (in-scope reachability only)

## Objective
Use a held `shell:<host>` to move to an **in-scope** neighbour, turning a looted credential into an
authenticated action on a second host. ATT&CK **T1021** (Remote Services). A proven pivot
`provides:["creds:<principal>@<host2>"]` — the Incalmo attack-graph edge that lets the scheduler unlock
`host2`'s hypotheses in the next wave. Spider's `scope.yaml` + `state.json` **are** the environment-state /
attack-graph pair; this class reuses them, it does **not** relax them.

## Gate (check BEFORE anything)
`stage:"post-foothold"`, `requires:["shell:<host>"]`. Run on-host enumeration through
`tools/leash-foothold.sh <target_dir> <host> <cmd>`. **Before acting on ANY neighbour**, assert it is in
scope:
```
python tools/guard.py --scope "$LEASH_SCOPE" --check "<neighbour-host-or-ip>"
```
Off-scope ⇒ it is a **LEAD** recorded in `state.json.leads`, and you STOP (never touch it). In-scope ⇒ the
cross-host action itself runs through the normal leash (`leash-tcp.sh`/`leashed.sh`, or `cred-access` for a
service login), pinned to that exact host — never a range.

## Methodology (reachability-disciplined)
1. **Enumerate neighbours (read-only, from the foothold):** ARP/`ip neigh`, `ss -tnp`/`netstat`,
   `~/.ssh/config`+`known_hosts`, mounted shares, app config pointing at DB/next-hop hosts. This maps
   *reachability from the controlled asset* (Incalmo's model), nothing more.
2. **Intersect with scope.** Keep only neighbours already in `scope.yaml` (guard.py-asserted). Everything
   else → `leads`. A new host is **never** promoted to a target by this class — only the operator widens
   scope (P2 `AskUserQuestion` + logged `plan_revisions`).
3. **Pivot with a looted cred** (from `loot`) to the in-scope host2, over the leash, pinned. The pivot is a
   legitimate authenticated use of a credential you already hold — not a crack.

## What counts as a finding (the oracle)
An **authenticated action on an in-scope neighbour** performed with a looted credential — e.g. an SSH
`id`/`whoami` on host2, an authenticated listing — **plus** the `guard.py` scope assertion that authorised
it. The scanner's "reachable" line is not proof; the cross-host authenticated action is. On proof,
`provides:["creds:<principal>@<host2>"]`.

## Evidence
Under `raw/attack-<id>/`: the neighbour enumeration output, the `guard.py --check` result proving host2 is
in scope, the `leash-foothold.sh`/`leash-tcp.sh` ledger lines, and the cross-host authenticated-action
proof.

## Red line
**Pivot ONLY to a host already in `scope.yaml`** (guard.py-asserted, fail-closed). A reachable host **not**
in scope is a LEAD, never attacked. **No scanning or flooding of out-of-scope ranges**, no pivot via an
auth-crack (use a looted or operator-supplied cred; a door reachable only by defeating a control as an
attack ⇒ `proven_state:'blocked', blocked_reason:'safeguard'`). No persistence on either host.
