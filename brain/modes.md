# Mode registry — the self-distributing router's data (P2)

> The single, authoritative registry for every engagement **mode**. A mode is a *classification of the
> engagement* that selects which recon lenses and attack classes run, and in what order. This file is
> **data + doctrine the brain reads** (workflow scripts never touch disk); `workflows/classify.mjs`
> proposes a plan from it, and the recon/attack workflows gate purely on a `modes:` string tag — so a
> **new mode = a row here + tagged lenses + attack classes**, with no router-core or scheduler change.
> Adding a mode is a data edit, never a code one. This is what makes the brain *extensible by data*.

## Two-level planner (why nothing here touches the scheduler)

The brain is a **two-level planner**, and the two levels never touch each other:

- **Macro (this file + `classify.mjs`): the router.** Reads the target's shape (scope + the one liveness
  fact + local artifact file-types) and *proposes* which cycles/lenses/modes run, in what order
  (`proposed_phases`). This is the CALDERA bucket-state-machine / PentestGPT task-tree level.
- **Micro (fix1 F4 wave scheduler, untouched): hypothesis order inside attack.** `requires`/`provides`
  capability tokens stage foothold producers first and unlock dependents as tokens are proven.

The router shapes **which producers exist** (by shaping the lens set); F4 schedules them. The router
**never** touches `requires`/`provides`, the oracle, the 4 skeptic lenses, the single-writer synthesizer,
or the leash/scope authority. A mode is a *lens/cycle selection*, **never** a capability or a policy
relaxation — choosing a mode never enables a control-test or relaxes a safeguard.

## The mode vocabulary (two closed sets)

| set | values | used as |
|---|---|---|
| **fine lens-modes** (`chosen_modes` / `args.modes`) | `web` · `network` · `service` · `api` · `ctf-pwn` · `ctf-rev` · `ctf-crypto` · `ctf-forensics` · `ctf-stego` | the per-lens `modes:` tag the recon mode gate intersects. This is the set the router EMITS as `chosen_modes` and the brain passes as `args.modes`. |
| **coarse labels** (`classification.mode` / `scope.engagement.type`) | `web` · `network` · `service` · `api` · `binary` · `file` · `ctf` · `mixed` | the human-readable committed label (the attack banner's `ENGAGEMENT MODE:` line + `scope.engagement.type`). |

`chosen_modes` is always the **fine** set — it is what actually lights lenses. The coarse labels
`binary`/`file`/`ctf`/`mixed` are *inputs/hints* the router expands to fine modes (below). Keep this file
in sync with the `modes:` tags in `workflows/recon-1.mjs` + `workflows/recon-2.mjs` and the classes in
`workflows/attack.mjs` — they are the ground truth the gate runs on.

### Coarse → fine expansion (C1 — the router does this before dispatch)

| `scope.engagement.type` (coarse) | router expands `chosen_modes` to (fine) | note |
|---|---|---|
| `binary` | `ctf-pwn`, `ctf-rev` | an executable artifact: pwn (memory-safety) + rev (understand the check) |
| `file` | `ctf-forensics`, `ctf-stego`, `ctf-crypto` | a document / image / capture / ciphertext |
| `ctf` | the `ctf-*` modes implied by `engagement.challenges[].category` | per-challenge categories drive the exact fine set |
| `mixed` | the union of every applicable fine mode, ordered foothold-first | more than one shape present |
| `auto` (default / absent) | the classifier decides from the facts | a reachable web host ⇒ the full web set |

`flag_format` and `objective.goal` live **only** in the top-level `objective{}` block (P1 owns them);
the router *reads* them as a classification + ordering bias (an objective "recover the flag from the
provided image" + an `artifacts:[diagram.png]` ⇒ `mode:file`), it never defines them.

## The registry

Each row: the signal that selects the mode, the recon lenses it turns on (keys in
`recon-1.mjs`/`recon-2.mjs`), the attack class families it feeds, the default cycle order, and the
ATT&CK tactic it opens at.

| mode | signal (scope.yaml + the one liveness fact + local `file` magic) | recon lenses turned on | attack classes | opens at (ATT&CK) |
|---|---|---|---|---|
| `web` | a host answers HTTP(S), or `services` list http(s) | **r1:** subdomain-enum, dns-intel, takeover, http-probe, web-crawl, archive-urls, js-secret-mining, cloud-assets, content-discovery, visual-recon · **r2:** param-mining, endpoint-deep, api-discovery, graphql, auth-flow, access-control, tech-specific, anomaly-hunt, exposed-datastores, waf-body-encoding, oauth-pkce, session-fixation | jwt, idor, sqli, ssrf, ssti, xss, xxe, cors, upload, takeover, graphql, saml, keycloak-realm, open-redirect, request-smuggling, waf-body-bypass, auth-bypass, deser, ognl, rce, info-disclosure | Recon → Initial Access |
| `network` | non-HTTP ports in `services`, or `netblocks` present | **r1:** subdomain-enum, dns-intel, port-service, cloud-assets · **r2:** tech-specific, exposed-datastores, smtp-protocol, nonhttp-cred-surface | cred-access (service foothold), + web classes on any HTTP found | Recon → Credential/Initial Access |
| `service` | a specific interactive non-HTTP service (ssh/ftp/smb/rdp/db/redis/vnc/telnet) in scope | **r1:** port-service · **r2:** smtp-protocol, nonhttp-cred-surface | cred-access (gated default-cred control-test) → `creds:`/`session:`/`shell:` | Credential Access → Initial Access |
| `api` | OpenAPI/Swagger/GraphQL present, little/no HTML | **r2:** endpoint-deep, api-discovery, graphql, auth-flow, access-control, oauth-pkce | idor (BOLA), auth-bypass (authz), graphql, jwt, open-redirect (oauth) | Recon → Initial Access |
| `ctf-pwn` | a pwn/binary challenge artifact (ELF/PE) under `artifacts/`, or `challenges[].category: pwn` | **r2:** ctf-pwn-triage | pwn | local solve → flag (Collection/Impact) |
| `ctf-rev` | a rev artifact (native/.NET/JVM/.pyc/wasm) | **r2:** ctf-rev-triage | rev | local solve → flag |
| `ctf-crypto` | source/params/ciphertext (`.py`/`.sage`/pubkey) | **r2:** ctf-crypto-triage | crypto | local solve → flag |
| `ctf-forensics` | a pcap/memory-image/disk-image/blob | **r2:** ctf-forensics-triage | forensics | local carve → flag |
| `ctf-stego` | an image/audio carrier | **r2:** ctf-stego-triage | stego | local extract → flag |
| `binary` *(coarse)* | `engagement.type: binary` or `artifacts[]` is an executable | expands to `ctf-pwn` + `ctf-rev` | pwn, rev, artifact-analysis | local solve → flag |
| `file` *(coarse)* | `engagement.type: file` or `artifacts[]` is a document/image/capture | expands to `ctf-forensics` + `ctf-stego` + `ctf-crypto` | forensics, stego, crypto, artifact-analysis | local solve → flag |
| `mixed` *(coarse)* | more than one of the above | the union of the applicable rows | the union, foothold-first | foothold-first |

**Always-on lenses (untagged — fire in every mode, self-gating):** `otp-logic` and `post-foothold-recon`
in `recon-2` carry **no** `modes:` tag and run regardless; they emit zero hypotheses when there is no OTP
gate / no foothold surface (the shipped `nonhttp-cred-surface` precedent). The `artifact-analysis` attack
class and the post-foothold classes (`internal-recon`/`privesc`/`loot`/`lateral`), the `objective-capture`
producer (flag mode), the `otp-logic` door, and the policy-gated `interactive-exploit` class compose
through the F4 graph independent of the mode — a mode never gates them off.

## Default cycle plans (`proposed_phases`)

The router proposes a foothold-first, ATT&CK-ordered cycle plan. Defaults:

- **A reachable web/network/service/api target** → `[classify, recon-1, recon-2, attack, chain]` with the
  full `chosen_modes` set on each recon cycle. This is **byte-for-byte today's flow** — `web∪network∪
  service∪api` equals the entire current lens list (every current lens carries `web` or `network`), so
  `Array.filter` selects the whole list in order.
- **A pure artifact (no reachable host — a CTF binary/file)** → `[classify, attack, objective-check]`:
  skip the web OSINT recon cycles entirely; the attack cycle runs the `ctf-*` solve class on the provided
  `artifacts/` and the P1 objective oracle declares the flag captured. (Recon-1/recon-2 are simply not
  launched by the brain for this plan; the workflows' empty-guard fallback is only a safety net.)
- **`mixed`** → `[classify, recon-1, recon-2, attack, chain]`, ordered foothold-first.

## The two backward-compat locks the router must honor

1. **Default = the full web set for any reachable host.** The classifier is *required by its own rules*
   to put every applicable `web`/`network`/`service`/`api` mode in `chosen_modes` whenever a host is
   reachable. Narrowing below the full web set happens **only** when there is no reachable host (a pure
   artifact). A web-reachable target therefore runs the identical fleet fan-out as today.
2. **Fail-open.** On classifier error / timeout / low confidence, the brain uses
   `chosen_modes:['web','network']` — the standard playbook. `['web','network']` already lights **every**
   current non-CTF lens (each carries `web` or `network`), so fail-open == today's run.

An absent router (`args.modes` undefined) is the third lock, enforced in the workflows: `ACTIVE===LENSES`.

## The living loop (agents propose; the operator approves)

The router feeds the fleet AND the fleet feeds the router. Recon/attack results carry additive
`proposed_modes[]` / `proposed_ideas[]` (ignored when empty). A discovery implying an un-chosen mode
(port-service finds `ssh:22` with password auth on a web run; `exposed-datastores` finds a binary dump)
→ the brain raises **one** `AskUserQuestion` (*add mode X? / keep plan / stop*), logs a
`run.json.plan_revisions[]` row (`from`/`to`/`why`/`by`/`ts`), and on accept re-runs the affected cycle
with the widened `args.modes`. Nothing widens scope or mode **silently**; out-of-scope discoveries stay
leads. The `plan_revisions[]` log is the self-distributing brain's audit trail — the operator can see
exactly why and when the fleet widened.

**The router also proposes the OBJECTIVE mode (fix3 B7).** In addition to the engagement modes, the router
proposes the `scope.objective.mode` axis (`impact | flag | bounty`) as an additive `proposed_objective`
— **`bounty` by default** for a reachable web/api bug-bounty target (a `scope.program{}` block or a known
bounty `scope.platform`, no CTF/flag objective), `flag` for a pure artifact with a `flag_format`/goal,
`impact` otherwise. The objective mode is **orthogonal** to `chosen_modes` (the engagement shape) and is
defined in `brain/bounty.md` (B1); the operator approves it at GO #1 (`go.objective`). Like an engagement
mode, an objective-mode selection **never relaxes a policy or grants a capability** — it only orients the
fleet; until the operator approves `bounty`, the run is byte-identical to today's `impact` default.

## Registering a new mode (the data-only recipe)

1. Add a **row** to the registry above (signal → lenses → attack classes → cycle order → ATT&CK tactic),
   and to the coarse→fine table if it has a coarse label.
2. **Tag** its recon lenses with the new `modes:` string (or add new lenses so tagged) in
   `recon-1.mjs`/`recon-2.mjs`, and add its attack class(es) to `ATTACK_SKILLS`/`CLASS_ALIASES` in
   `attack.mjs` with a matching `.claude/skills/attack/<class>/SKILL.md` and an oracle row in
   `.claude/skills/proof/oracles/SKILL.md`.
3. Add the fine value to the `LENS_MODES` vocabulary in `classify.mjs` (and the coarse label to
   `MODE_LABELS`).

No change to the router core, the wave scheduler, or the oracle. That is the whole point.

## Red line

The router **classifies and sequences only** — it issues **zero target packets before GO**, reasoning
over `scope.yaml`, the single already-authorized liveness probe, and `file`-type output on **local**
operator-supplied artifacts. It never bypasses a safeguard, cracks/evades auth, or floods. A mode
selection can never turn on an evasion: it only enables lenses/classes that themselves obey the red line
(`cred-access` still refuses unless `policies.default_cred_control_test.enabled`; a post-foothold class
still needs a proven/operator-supplied foothold). The operator GO is preserved — the router makes GO #1
richer (it shows the proposed plan), never automatic.
