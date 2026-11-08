# brain/corpus — the senior-brain decision-intelligence store

A precondition-keyed store of **distilled senior exemplars**: the tacit "signal → tried → dead-end →
pivot → key technique → what-proof-counts" loop that separates a senior from a junior, lifted out of
publicly disclosed reports/writeups and made retrievable. It primes Spider's fleet agents to **find AND
PROVE faster on authorized, in-scope targets** — it is **never** a way to claim a finding without an
oracle-proven PoC.

## What is here

| File | Contents |
|------|----------|
| `exemplars.jsonl` | one line per distilled senior exemplar (67 records across all six dossiers) |
| `payloads.jsonl`  | one line per exemplar's verbatim payload/command, or a `status:"OMITTED"` + `resolve_from` pointer |
| `negative.jsonl`  | reusable cross-engagement negative knowledge + per-class clean-target base-rate STOP rules (D5) |
| `corpus.md`       | this README |
| `index.json`      | **machine-generated** by `tools/corpus_index.py` — NOT hand-edited, NOT created here (tools-builder owns it) |

## The three schemas (one JSON object per line)

**exemplars.jsonl**
```
{id, class, source, target_fingerprint:{framework,version,header,param,response_shape},
 trigger_signal, decision_trace (string: "tried X (dead-end) -> pivot Y -> technique Z"),
 key_technique, payload_ref, proof_oracle (string: shape + the .claude/skills/proof/oracles/SKILL.md row),
 reusable_vs_instance: "reusable-technique"|"patched-instance"|"both",
 novelty:{vrt,patched_in}, hit_rate:{tries:0,wins:0}, ts}
```
`class` is ALWAYS one of the shipped `ATTACK_SKILLS` slugs (`workflows/attack.mjs:30`), so corpus keys stay
in lockstep with the skill packs. `payload_ref` ↔ the matching `payloads.jsonl` `id`.

**payloads.jsonl**
```
{id, class, requires_fingerprint:[tokens], template, note,
 payload (verbatim) + status:"present"   |   status:"OMITTED" + resolve_from, payload_ref}
```
`payload_ref` links back to the exemplar `id`. `resolve_from` names where to source the real bytes
(exploit-db / nuclei-templates / a PoC repo) keyed by the same fingerprint — H1 pages hide payloads, and
that OMITTED flag IS the reproduction-gap signal for the executor.

**negative.jsonl**
```
{id, scope:{class, fingerprint:[tokens]}, fact, consumed_by:["planner-skip","oracle-reject"]}
```
`ng-0001..` = reusable dead-ends / false-positive signatures / version gates (e.g. "WAF block pages return
200", "exiftool ignores the extension", "LIBXML_NONET only blocks http:// not php://", "__free_hook dead in
glibc>=2.34", "SOCKS can't carry raw nmap"). `ng-0101..` = D5 per-class clean-target base-rates — when to
STOP so a primed agent does not force a false positive on a genuinely clean target.

## Invariants (the moat — never violated by this store)

- **Single writer.** `brain/corpus/` has exactly ONE writer, the `corpus-curator` agent (this batch-0 seed
  was authored by the `corpus-seeder` group under that same single-writer rule). Fleet agents NEVER write
  the corpus; they return `used_exemplars[]` and the curator reconciles. (Consistency-gate lesson.)
- **The oracle is NEVER cited as proof.** An exemplar's `proof_oracle` is a HINT for what shape of proof to
  PRODUCE on the live target. It is **forbidden** as a citation of proof. `validateMission()`, the 4 skeptic
  lenses (incl. the origin-check hard veto) and the single-writer synthesizer are UNTOUCHED and never see
  the exemplar. If ever in doubt, the oracle wins and the exemplar is discarded (anchoring guard, D3 / `ng-0028`).
- **Patched specifics never prime.** Retrieval surfaces only `reusable-technique`; a `patched-instance` on a
  matching version is gated out (`novelty.patched_in` + the version-gate negatives). Kills the $0 patched-instance trap.
- **Distilled from PUBLICLY DISCLOSED material only.** Stores the technique + the oracle *shape*, never a
  live secret; `OMITTED` is labeled, never fabricated.

## How retrieval / injection consume it

The brain reads `brain/corpus/` itself (scripts never touch disk). `tools/retrieve.py` scores
`(class × fingerprint-overlap × reusable)` against the live `state.json` world-model and returns top-K ≤ 5
**reusable-technique** exemplars (a runnable payload outranks an OMITTED one — D4). The brain then passes
NON-SECRET descriptors as `args.exemplars[<hypothesis-id>]` (and `args.reflex_cards[<lens>]`), mirroring the
`args.session` / `args.objective` passthrough in `brain/mission.md`. `attack.mjs exploitMission()` injects an
`exemplarBlock` and `recon-2.mjs mission()` a `reflexCard` — both evaluate to `''` when the args are absent,
so the missions stay byte-identical to today (backward-compat is law). `negative.jsonl` is consumed by the
planner (`planner-skip`) and named to the oracle (`oracle-reject`).

## Provenance

Distilled from publicly disclosed reports and writeups — HackerOne, GitHub advisories, CTF,
Standoff RU, and researcher / AI-hunter writeups (batch-0, 2026-10-04). Class mapping note: free-form `vuln_class` from the dossiers is mapped onto the
closest shipped `ATTACK_SKILLS` slug; where no dedicated slug exists (business-logic race, OS/argument
command injection, Java deserialization, LFI→RCE, web-cache-deception, supply-chain name-hijack,
charset filter-bypass) the most-general-correct slug is used and the mapping is noted inline in that
record's `decision_trace` (e.g. `[map: ... -> auth-bypass, no race slug in ATTACK_SKILLS]`).
