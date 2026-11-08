# Data contract — one canon, no drift

Every engagement lives in `targets/<target>/`. Flat, prompt-readable, no database.
The brain, every workflow agent, and the synthesizer read/write exactly these shapes.
Keep them stable so the brain can synthesize across agents and resume across runs.

```
targets/<target>/
  scope.yaml        # authorized scope + rules (the ONLY authority for what may be touched)
  leash.env         # machine-readable leash config, generated from scope.yaml
  session.env       # OPERATOR-SUPPLIED foothold (cookie/bearer/SSH material); SECRET, never committed;
                    #   auto-injected by the leash AFTER the scope-lock, on in-scope requests only (F1)
  run.json          # GO decisions: fleet size, model tier, phases done, timestamps
  state.json        # world model: hosts, services, creds, capabilities, leads, hypotheses, confirmed, refuted
  findings.jsonl    # canonical findings, one JSON per line (written ONLY by the synthesizer)
  raw/<agent>/      # per-agent evidence + result.json (each agent writes its own dir — no races)
  artifacts/        # OPTIONAL (P3 CTF): operator-supplied challenge files (binary/pcap/image/ciphertext) or an
                    #   in-scope download. Analyzed LOCALLY/OFFLINE; only a download (or a pwn remote `nc`
                    #   delivery) is network traffic — the leash/guard still gate that. Absent on a plain web run.
  docs/
    01-recon-surface.md      # synth after recon-1: every host / IP / tech / priority
    02-infra-hypotheses.md   # synth after recon-2: infra map + ranked hypotheses to prove
    99-infra-final.md        # official end state: proven findings + open hypotheses + full map
  killchain.md      # synthesized chain(s): entry -> escalation -> lateral -> objective
  report.md         # submission-ready human report (from /report)
  priorart.json     # OPTIONAL (fix3 B3, bounty mode). The prior-art / dedup index built EARLY by the
                    #   reused duplicate-scout (prior-art mode) from public disclosure indices + local
                    #   files — PASSIVE OSINT, no target traffic. Read upstream (orient the fleet) and at
                    #   the /report + /triage gates. Schema below. Absent on a plain run (nothing builds it).
  submitted/        # OPTIONAL (fix3 B6, bounty mode). One operator-attested submission+outcome record per
    <finding-id>.json #   finding (operator/brain-written, like run.json/session.env — NOT an agent, NOT the
                    #   synthesizer). Own schema tools/schema/outcome.schema.json. Read by duplicate-scout
                    #   (most-reliable dedup source) + folded into state.json techniques/dead_paths by the
                    #   synthesizer. Spider RECORDS; the operator SUBMITS. Absent on a plain run.
```

## scope.yaml
```yaml
target: acme
program: "Acme BB"                              # program name (public or private / invite-only). BACKWARD-COMPAT: a string here = the name only (today's behavior). In BOUNTY mode `program` may instead be the MAP form (the economics block near the bottom — fix3), which carries the name as `program.name`. The two forms are mutually exclusive; the brain normalizes (string => args.program undefined; map => args.program = the economics). A plain run keeps the string => byte-identical.
platform: "BI.ZONE | Standoff 365 | HackerOne | YesWeHack | Bugcrowd | private"
program_url: ""                                 # public program page if public; BLANK for private/closed — fine
policy_url: ""                                  # program rules/ROE page if available (optional)
researcher: "<your handle>"                     # the participant; attests authorization + goes in the ID header
required_header: "X-Bug-Bounty: <handle>"       # every HTTP request must carry this
rate_limit_rps: 5                               # aggregate cap across the whole fleet
scope_exact: true                               # true = exact hosts only; false = allow subdomains
engagement:                                     # OPTIONAL (P2/P3/C1). Omit entirely => type:auto => classifier auto-detects => today's web behavior
  type: auto                                    # auto | web | network | service | api | binary | file | ctf | mixed
  modes: []                                     # OPTIONAL explicit mode set; [] => router auto-detects. Vocabulary: web|network|service|api|binary|file|ctf-pwn|ctf-rev|ctf-crypto|ctf-forensics|ctf-stego
  artifacts: []                                 # OPTIONAL local files placed under targets/<t>/artifacts/ (binary/pcap/doc/image) — analyzed LOCALLY, never fetched
  challenges: []                                # OPTIONAL CTF input contract: [{name, category:pwn|rev|crypto|forensics|stego, artifact, remote, libc}] — see docs/scope.example.yaml
hosts:
  - host: app.acme.com
    ip: 203.0.113.10
    priority: critical                          # critical | high | medium | low
netblocks: []                                   # optional in-scope CIDRs
out_of_scope: [status.acme.com]
policies:
  rce_proof: "whoami|id|hostname only"          # program's safe-PoC limits
  sqli_proof: "database()|@@version only"
  rate_limit_test: { enabled: true, max_requests_per_endpoint: 50, own_accounts_only: true }
  password_spray_light: { enabled: false, max_tries_per_account: 5, own_accounts_only: true }
  default_cred_control_test:                      # F5: non-HTTP/service default-or-weak-cred CONTROL-TEST
    enabled: false                                #   operator opt-in per engagement (OFF => cred-access refuses)
    services: [ssh, ftp, smb, rdp, mysql, mssql, redis, vnc, telnet]
    max_pairs: 20                                 #   SMALL curated default/weak set — never a wordlist dump
    pairing_mode: spray                           #   line-by-line (nuclei pitchfork / nxc --no-bruteforce); brute FORBIDDEN
    stop_at_first: true
    rps: 1                                         #   <= rate_limit_rps
    inter_attempt_delay_s: 3                       #   explicit min delay (NOT a token bucket)
    jitter_s: 2
    max_tries_per_principal: 1                     #   one failed attempt per account => no lockouts
    lockout_backoff_s: 300                         #   on any lockout/throttle signal: stop + back off
    anon_login_check: true                         #   FTP/SMB anon + SSH "is password auth even on?" pre-check
  smtp_semantics_probe: { enabled: false, max_recipients: 20, max_from_variants: 5 }
  interactive_protocol:                           # P5: hold a socket/REPL and exploit a logic bug over a conversation
    enabled: false                                #   operator opt-in per engagement (OFF => interactive-exploit refuses, lens NOT added)
    protos: [tcp, tls, ws, wss, pty]              #   allowed transports (pty = a spawned client/console via pexpect)
    ports: []                                     #   OPTIONAL extra port allow-list ([] = any in-scope port a service was found on)
    max_frames: 500                               #   total send+recv frames per held session (anti-flood)
    max_bytes: 1048576                            #   total payload bytes per session (anti-flood)
    max_session_s: 120                            #   wall-clock cap per held session
    idle_timeout_s: 10                            #   per-recv timeout (no infinite hang)
    allow_interactive_passthrough: false          #   permit Remote.interactive() manual driving (still fully logged)
  forbidden: [flood, account-takeover-of-others, destructive, social-engineering, physical]
  # control-test (proving a control is ABSENT) is not brute-force of others — see brain/scope.md
  # and docs/scope.example.yaml for the full policy tree + guardrails.
objective:                                      # OPTIONAL (P1). Absent => mode:impact == today's bug-bounty behavior (iterate to dry)
  mode: impact                                  # impact (DEFAULT) | flag (objective/CTF-driven; a captured flag is TERMINAL) | bounty (fix3; hunt PAYABLE findings, iterate until the eligible-novel surface is dry — a payable finding is a MILESTONE, not terminal)
  goal: "read /flag on app.acme.com and return its contents"   # human goal; injected into EVERY mission in flag mode (and in bounty mode: "find and prove payable vulnerabilities on the in-scope assets of <program>")
  flag_format: 'flag\{[^}]{1,128}\}'            # regex the FLAG ORACLE matches captured strings against. flag_format lives ONLY here (C1). flag-mode-only; ignored in bounty mode. Defaults to flag\{[^}]+\} if omitted
  where_hint: "likely behind the authenticated export (EXIF of the generated diagram)"  # OPTIONAL steer — a lead, never authority or proof
  # --- bounty-mode-only keys (fix3; all OPTIONAL, absent => today's behavior) ---
  min_payable_tier: P4                          # fix3 B2 (owner): the program's PAY FLOOR — the lowest reward tier that still pays, transcribed from the brief. A finding whose evidence-derived `tier` is below this is Informative-equivalent (expected_value 0, payout_ready false). Reads B5's P1..P5 tier vocabulary; defines no new one. (NB: this is the SUBMISSION floor; program.min_pursue_priority (B4) is the distinct EFFORT floor.)
  novelty:                                      # fix3 B3 (owner): the prior-art / dedup controls. Absent => novelty-scout lens never pushed; synthesizer writes no novelty fields (byte-identical to today)
    check: auto                                 #   auto | off
    disclosure_urls: []                         #   OPTIONAL non-H1 disclosure index URL(s) the operator supplies (public program data)
    changelog_urls: []                          #   OPTIONAL changelog/release-notes URL(s) — "already fixed?" + narrow-fix variant seeds
    submitted_archive: true                     #   read targets/<t>/submitted/ as a dedup source (default true)
    drop_duplicates: false                      #   when true + mode:bounty, a HIGH-confidence likely-duplicate LEAF (exact novelty_ref, no novel dependent) is held as a lead instead of run (default false)
    waive_unverified: false                     #   when true, a could-not-verify finding may clear the dedup rung on operator waiver (default false; NEVER auto-promoted)
# ─── program (MAP form, fix3 bounty mode) ─── This is the SAME top-level `program` key shown above as a
# scalar name — here in its OPTIONAL MAP form (mutually exclusive with the scalar; supply ONE). The brain
# builds args.program from it. Absent (or the scalar name form) => mode:bounty degrades to a severity-floor
# + dedup heuristic (EV "unknown", a generic table is NOT assumed) and args.program is undefined. Public
# program data — NOT a secret; safe to embed in a mission like flag_format, unlike session.env.
program:                                        # OPTIONAL (fix3). The program's PUBLISHED economics, transcribed by the operator.
  name: "Acme BB"                               # fix3: the program name (carries the scalar form's value into the map). Used for the authorization string in bounty mode
  severity_scheme: cvss                         # fix3 B1: cvss (H1/Intigriti/YWH) | vrt (Bugcrowd P1..P5) | custom
  currency: USD                                 # fix3 B1: ISO-ish currency label for EV reporting
  reward_table:                                 # fix3 B5 (owner): tier -> reward range, transcribed from the brief. Keys are the VRT priorities P1..P5. P5 ABSENT => not payable. An omitted tier => unknown range (EV "unknown", not 0). B5 references program.reward_table (it lives HERE, not under objective).
    tiers: { P1: [5000, 20000], P2: [2000, 5000], P3: [500, 2000], P4: [100, 500] }
  asset_tiers: []                               # fix3 B1 (YWH model): [{ match: "<host or glob>", multiplier: 1.0 }] asset-value weighting; default 1.0 for unlisted hosts
  eligible_classes: []                          # fix3 B1/B4: vuln classes the brief pays for. [] => any in-scope class is eligible
  excluded_classes: []                          # fix3 B1/B4: known-ineligible classes (self-xss, missing-spf/dmarc, clickjacking-non-sensitive, rate-limit-non-auth, verbose-version-banner, ...). NEVER submitted, never burn fleet — but kept as a noted LEAD, never silently dropped
  exclusions:                                   # fix3 B4 (owner): the program's OWN "won't pay" list, keyword-matched exactly as attack CLASS_ALIASES matches (lower-cased substring, first-match-wins)
    - { match: "self-xss", reason: "program excludes self-XSS", action: note, vrt: "" }
    # action enum: note (down-rank to a noted lead — never pursued/submitted) | control-test-only (pursue only as a bounded control-test per policies.*) | downrank (pursue, but last)
  vrt_version: ""                               # fix3 B4: the VRT snapshot the operator transcribed against (audit)
  platform_taxonomy: vrt                        # fix3 B4: vrt | cwe-cvss — which vocabulary /report emits (Bugcrowd P-ratings vs H1 CWE+CVSS-environmental)
  vrt_overrides: []                             # fix3 B4: OPTIONAL per-program priority/mapping overrides — [{ match, vrt, priority }] (brief restriction / unusual impact)
  min_pursue_priority: P4                       # fix3 B4 (owner): pursue classes at/above this VRT priority; below => note-only. The EFFORT floor (distinct from objective.min_payable_tier, the SUBMISSION floor). Absent => pursue all, note P5
  dedup_posture: public                         # fix3 B1/B3: public (disclosed reports searchable) | archive (operator submission archive only) | private (CANNOT dedup-check => honest could-not-verify, never auto-novel)
  report_template: ""                           # fix3 B7: OPTIONAL path/URL to the program's own report template /report adheres to. Non-secret. Absent => /report uses the platform_taxonomy default template
  submission_platform: ""                       # fix3 B6: OPTIONAL — lets /outcome --pull read the operator's OWN report states/payouts (operator's own token, never stored)
```
`mode`/`goal` are the only required keys when `objective` is present; `flag_format` defaults to
`flag\{[^}]+\}`; `where_hint` is optional. `engagement`, `objective`, and `program` are all optional and
**absent on a plain web run** (type auto-detects to web, mode defaults to impact == today). The bounty-mode
keys (`objective.mode:bounty`, `objective.min_payable_tier`, `objective.novelty{}`, the whole `program{}`
block) are additive: absent, every bounty code path short-circuits to empty and the run is byte-identical.

## run.json
```json
{"fleet": 10, "model_tier": "strong", "phases_done": ["recon-1"], "go": {"scope": true}, "ts": "ISO-8601"}
```
`fleet` ∈ {5,10,15}; `model_tier` ∈ {fast, strong}. Chosen once at the scope GO, fixed for the run,
passed into every workflow via `args`.

**Optional additive plan + preflight fields (P2 router / P7 egress — all ignorable; absent ⇒ today's run):**
```json
{"fleet":10,"model_tier":"strong","phases_done":["recon-1"],"go":{"scope":true,"plan":true},"ts":"ISO-8601",
 "classification":{"mode":"web","confidence":"high","signals":["203.0.113.10:443 http 200","openapi:/v3/api-docs"],"ts":"ISO-8601"},
 "chosen_modes":["web","network"],
 "proposed_phases":[{"cycle":"recon-1","modes":["web","network"]},{"cycle":"recon-2","modes":["web","network"]},{"cycle":"attack","modes":["web","network"]},{"cycle":"chain"}],
 "plan_revisions":[{"from":["web"],"to":["web","service"],"why":"recon-1 found ssh:22 offering password auth","by":"recon-operator port-service","ts":"ISO-8601"}],
 "preflight":{"egress":{"verdict":"egress_ok|warn|conflict","reason":"","target":"host:port","default_route_iface":"","vpn_kind":"","ts":"ISO-8601"}}}
```
- `classification` (P2) — the committed mode + why (auditable). `chosen_modes` — the active mode set
  (drives `args.modes`). `proposed_phases` — the ordered cycle plan the operator approved. `plan_revisions`
  — the append-only log of mid-run re-routes (from/to/why/by/ts), so the self-distributing brain is
  auditable. `go.plan:true` — the operator approved the proposed plan at GO #1 (same gate as `go.scope`).
- `preflight.egress` (P7) records the F9 egress/VPN-conflict verdict (`arsenal/probe.py --egress`); a
  `conflict` must be cleared before GO. It carries no secret and is written by the brain at preflight.
- All of these are additive and ignorable: absent, the cycle runs exactly as today.

## finding — one JSON object per line in findings.jsonl
```json
{"id":"f-0001","target":"host|url","type":"RCE|IDOR|SSRF|...",
 "severity":"info|low|medium|high|critical","title":"...","detail":"how it was found",
 "evidence":"path under raw/","execution_evidence":"proof output or OOB callback id",
 "oracle_type":"the class oracle met (OOB callback|DB banner|command output|...)","oracle_evidence":"path/line that re-derives it",
 "verified":true,"refuted":false,"ts":"ISO-8601"}
```
**Gate (enforced in `tools/schema/finding.schema.json` and by the verifier):** an impact/injection
class claimed `high`/`critical` **without** `execution_evidence` is a *candidate*, auto-downgraded to
`medium` and titled `[UNCONFIRMED CANDIDATE]`. `refuted:true` never reaches a report.

**Bounty-mode economic fields (fix3; ALL OPTIONAL — additive, bounty-mode-only, written only by the
synthesizer; absent on an impact/flag run ⇒ the line is byte-identical to today).** Each field has
exactly ONE owner (the canonical field contract, §Canonical field contract below), so no two points
invent clashing names:
```json
{ "vrt":"broken_access_control.insecure_direct_object_references",   // B4: the dotted VRT class id
  "priority":"P2",                                                    // B4: VRT baseline priority P1..P5|varies (the CLASS baseline — distinct from `severity` and from B5 `tier`)
  "eligibility":"payable",                                            // B4: payable | excluded | control-test-only | unknown (vs program.eligible/excluded_classes). `severity` is NEVER changed by eligibility
  "eligibility_reason":"",                                            // B4: why (e.g. "matches program.exclusions self-xss")
  "cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",       // B5: the CVSS 3.1 vector built from PROVEN impact
  "cvss_score":9.8,                                                   // B5: Roundup-derived from the vector (deterministic; tools/ev-score.py). `severity` stays the canonical band; cvss_score is its auditable derivation
  "tier":"P1",                                                        // B5: the evidence-derived REWARD tier (CVSS band cross-checked vs `priority`, resolved through program.reward_table)
  "tier_reward":[5000,20000],                                         // B5: [min,max] from reward_table (omitted in ordinal mode)
  "expected_value":9500,                                              // B5: reward_value(tier) x novelty_confidence x eligibility_confidence — a RANKING scalar, NEVER a payout claim
  "ev_basis":{"reward_value":19000,"novelty_confidence":1.0,"eligibility_confidence":1.0,"mode":"monetary"}, // B5: the EV audit trail (mode: monetary|ordinal)
  "novelty":"novel",                                                  // B3: novel | likely-duplicate | could-not-verify. could-not-verify is NEVER auto-promoted to novel
  "novelty_ref":"",                                                   // B3: the matching disclosed ref (h1#.../CVE-.../GHSA-.../submitted:f-XXXX) if any
  "novelty_reason":"", "dedup_coverage":"verified",                   // B3: reason + priorart coverage (verified|partial|unverifiable)
  "dedup_checked_ts":"ISO-8601",                                      // B3: when dedup was checked
  "payout_ready":true,                                               // B2: the SINGLE payable verdict = deterministic AND of the six sub-gates (impact-proven ∧ in-scope ∧ eligible ∧ paying-tier ∧ dedup-cleared ∧ report-ready). Computed by the synthesizer (tools/payout-gate.py), enforced at /triage. NEVER set by narration
  "payout_blockers":[],                                              // B2: the unmet sub-gates, each a structured string (e.g. "tier: P4 below pay floor P3", "dedup: could-not-verify — operator must confirm novelty")
  "payout_distance":"report-ready" }                                 // B2: the 8-rung ladder: signal -> reproduced -> impact-proven -> severity-graded -> dedup-cleared -> report-ready -> submitted -> paid. payout_ready ⟺ reached report-ready (submitted/paid are operator-attested, B6)
```

## state.json — world model (merged each run)
```json
{"hosts":[{"host":"","ip":"","os":"","services":[],"access":"","priority":""}],
 "services":[{"host":"","port":0,"service":"","version":""}],
 "creds":[{"principal":"","secret":"","source":"","works_on":[]}],
 "capabilities":[{"token":"session:host","acquired":true,"source":"f-0003 | session.env | creds","evidence":"raw/attack-h-authflow-01/","ts":"ISO-8601"}],
 "objective":{"mode":"impact|flag|bounty","status":"open|captured|payable|submitted|paid|rejected|dry|blocked","goal":"","flag":"",
              "evidence":"raw/attack-<h>/ (artifact the flag is re-derivable from)",
              "distance":"unauth|recon|foothold|file-read-or-rce|flag",   
              "blocked_reason":"","ts":"ISO-8601",
              "_bounty_only_fields":"all keys below are fix3 bounty-mode-only (synthesizer-only writer); absent in impact/flag",
              "payable_count":0,"best_tier":"","best_finding":"","dedup_cleared":false,"eligible_pending":0,
              "expected_value":{"currency":"USD","low":0,"high":0,"point":0,"unknown":false},"expected_value_total":0,
              "ev_ranked":[],
              "outcomes_summary":{"program":"","accepted":0,"triaged":0,"resolved":0,"paid":0,"duplicate":0,"not_applicable":0,"informative":0,"spam":0,"total":0,"realized_value":{"currency":"USD","sum":0},"ts":""},
              "acceptance_prior":{"value":0,"n":0,"unknown":true}},
 "classification":{"mode":"web","confidence":"high","signals":[],"ts":"ISO-8601"},
 "hypotheses":[{"id":"h-01","host":"","class":"","why":"","status":"open|proven|refuted|blocked",
                "stage":"foothold|post-foothold",
                "requires":["session:host"],   "provides":["session:host"],
                "seam":{"desync_variant":"","smuggle_evidence":"","unkeyed_input":"","cache_evidence":"","oasdiff_endpoint":"","endpoint_method":"","endpoint_evidence":"","vulnx_cve":"","cve_kev":false,"cve_epss":0,"cve_template":"","cve_refs":"","params":[],"sink":"","source":"","trace":"","note":""},
                "blocked_reason":"safeguard|missing_prereq|needs_session|policy"}],
 "leads":["open threads to pursue next"],
 "confirmed":["finding ids proven"], "refuted":["hypothesis ids killed"],
 "human_review":[{"id":"h-01","reason":"safeguard:cyber|died|needs-foothold|crown-jewel",
                  "what_it_attempted":"","evidence":"raw/attack-h-01/",
                  "options":["supply-session","manual-poc","decompose","skip","retry"],"routed_ts":"ISO-8601"}],
 "techniques":[{"class":"","what_worked":"","on":""}],
 "dead_paths":[{"id":"","goal":"","class":"","why":""}],
 "fingerprints":[{"host":"app.acme.com","tokens":["stack:nextjs@15.2","engine:jinja2","cloud:gcp"]}],
 "tried":[{"class":"","host":"","what":"","signal":"dead-end"}]}
```
`techniques` = what worked, replayed on similar future situations (technique reuse). `dead_paths` =
seeded targets/`/chain` attempts that didn't reproduce — future runs read these and don't re-tread them.

**`hypotheses[].seam` (gap C, OPTIONAL, additive — the recon→attack seam-seed).** A structured carrier for a
structural primitive recon-2 already PROVED, so the attack-operator weaponizes it instead of re-detecting it
from zero. The synthesizer populates it from deep-recon tool output (smugglex desync variant, cachex unkeyed
input, oasdiff added/authz-changed endpoint, vulnx stack-CVE map, param-mining, and the `deep-source-trace`
lens's verified client-side `source`/`sink`/`trace` chain — iteration 1), writing only keys it has
evidence for; `workflows/attack.mjs` renders a present `seam` as an explicit "do NOT re-detect, weaponize"
mission block. Absent ⇒ the attack mission is byte-identical to today. It is a RETRIEVAL/priming aid like
`fingerprints` — it NEVER enters the capability-token grammar and never relaxes the oracle.

**`sibling_hypotheses` (gap D, attack→recon feedback).** The attack return carries `sibling_hypotheses[]`
(adjacent exploitable surfaces operators surfaced while proving their own hypothesis) alongside
`composite_hypotheses[]`; the synthesizer merges both into `hypotheses[]` as new `status:open` rows so the
next round proves them — organic finding growth from the whole fleet, not only the chain-builder's top-down
composites. Same honesty rule: a sibling is a lead until its own oracle gate confirms it.

**`fingerprints` and `tried` (fix3, OPTIONAL, additive — absent on a run that never retrieves).**
- `fingerprints[]` — **PER-HOST** objects `{host, tokens:[...]}` (fix3 audit #3 — one owner shape, matching
  the synthesizer writer and the orchestrator's per-host retrieve `tools/retrieve.py --fingerprint <tokens
  for h.host>`). The `tokens` are the observed tech tokens (`stack:<fw>@<ver>`, `engine:<tmpl>`,
  `header:<name>`, `param:<name>`, `cloud:<provider>`, `response-shape:<x>`) a `fingerprint` recon step
  wrote; the synthesizer folds each `HYPO_RESULT.hypotheses[].fingerprint[]` into its host's `tokens`.
  `tools/retrieve.py` keys `(class × fingerprint-overlap)` on these (prefix-normalized to the bare value,
  so `framework:nextjs`~`stack:nextjs`~`nextjs` all match) to surface the right exemplars per host. They
  are a **SEPARATE namespace**: a fingerprint token NEVER enters the capability-token
  grammar (`requires`/`provides`) or `capabilities[]` — it gates retrieval only, never the oracle-honest
  scheduler.
- `tried[]` — a compressed per-target already-tried-and-failed facts list (Tier-1 negative memory,
  **synthesizer-written**, same single-writer invariant), injected back each round so no agent re-runs its
  own dead command (D7).

**Two-tier feedback.** Tier-1 (per-target, this block) = `techniques[]` / `dead_paths[]` / `tried[]`,
written by the synthesizer from the engagement's own outcomes. These feed the offline `corpus-curator`
(`.claude/agents/corpus-curator.md`), which promotes the **generalizable** subset into Tier-2 — the
cross-engagement `brain/corpus/` store (re-ranks `hit_rate`, promotes a reproducible win to a new
exemplar; `tools/retrieve.py`'s `hit_rate` bonus ranks a proven exemplar above an unproven one so a
never-reproducing exemplar sinks, and the curator may prune it). The fleet never writes either tier;
agents only return `used_exemplars[]` for the curator to reconcile.

`objective` (P1, OPTIONAL) and `classification` (P2, OPTIONAL) are additive and absent on a plain run.
- **`objective`** is written **only by the synthesizer** (same single-writer invariant as the rest of
  state.json — P1 adds no second writer). `distance` is the coarse progress ladder
  (`unauth→recon→foothold→file-read-or-rce→flag`) — the brain's "how close to the goal" signal, a
  read-only projection of the world model. The flag STRING is operator-facing proof (it IS the
  deliverable and is always re-derivable from `raw/`), distinct from `session.env` secrets; a flag
  enters `objective.flag` **only** when the `flag-capture` oracle is met — never a narrated/guessed
  value. A loot/internal-recon hypothesis (P4) that retrieves the objective artifact writes it as
  `execution_evidence`; the P1 objective oracle validates it against `flag_format`/`goal` and sets
  `objective.status:captured`. In flag mode a captured flag is TERMINAL.
  - **Bounty mode (fix3, additive on the same block — still synthesizer-only writer).** `status`
    semantics: `open` (hunting, no payable finding yet); `payable` (≥1 `payout_ready` finding — a
    recorded MILESTONE, the run KEEPS hunting like impact mode, NOT terminal); `submitted`/`paid`/
    `rejected` (B6 operator-attested lifecycle — a run with findings out for review is `submitted`,
    `paid` once any recorded paid, `rejected` when all submitted findings closed dup/N-A/informative);
    `dry` (the eligible-novel surface is exhausted — the TERMINAL/economic-exhaustion condition, the
    bounty analogue of impact-mode "iterate to dry"); `blocked` (stalled on a foothold/prereq no
    hypothesis can provide — the F1/F2 hand-off, exactly as flag mode). `captured` stays flag-mode-only.
    The run-level `distance` is a COARSE read-only projection of the per-finding B2 8-rung ladder (the
    best finding's rung): `signal→reproduced→impact-proven→severity-graded→dedup-cleared→report-ready`
    (+`submitted`/`paid` attested tail); the attack phase computes only the IMPACT-side rungs it can see
    (the eligible/payable/dedup rungs and `status:payable|dry` are SYNTHESIS-level verdicts — the
    synthesizer holds `program` + the dedup result, so the single-writer invariant and the
    "scheduler never sees economics" rule hold). `payable_count`/`best_tier`/`best_finding`/
    `expected_value`/`expected_value_total`/`ev_ranked`/`eligible_pending`/`dedup_cleared`/
    `outcomes_summary`/`acceptance_prior` are honest rollups (EV range summed over `payout_ready`
    findings; `unknown:true` if any payable tier lacks a table entry; `eligible_pending` = eligible ∧
    could-not-verify awaiting the operator; `acceptance_prior` = the HackerOne-Signal weighting over
    recorded outcomes, `unknown` at n=0 — never fabricated). **No new capability token** — the objective
    is terminal/standing in its own block, so nothing in the F4 graph depends on it (exactly as P1
    rejected a `flag:<host>` token and B1/B2/B6 add none).
- **`classification`** carries the committed engagement mode (P2) into state.json so re-runs and the
  final doc know the mode; hypotheses may optionally gain an additive `"mode"` tag for synthesizer
  grouping only (no scheduler behavior depends on it — F4 still runs off `requires`/`provides`).

### Capability tokens (the F4 dependency substrate)
A **capability** is a string `type:scope` — the typed "fact" a hypothesis needs (`requires`) or grants
(`provides`). The attack scheduler proves foothold-producers first and unlocks dependents only when
their required tokens are **acquired**. Small closed set:

| token | meaning | typical producer |
|---|---|---|
| `session:<host>` | an authenticated session on host (cookie / JWT / SSH) | auth-flow, otp-logic, login/SSH control-test |
| `creds:<principal>@<host>` | a working credential pair | cred control-test, secret-leak |
| `token:<name>` | a bearer / API / reset token held | OAuth, password-reset, leak |
| `foothold:<host>` | arbitrary authenticated read/write on host | any of the above, chained |
| `admin:<host>` | privileged / role-elevated access | priv-esc after foothold |
| `shell:<host>` | OS-level command execution on the host (interactive or single-shot) — strictly stronger than `session:<host>`/`foothold:<host>`, which may be app-level only (P4) | SSH/telnet/RDP cred control-test, proven RCE, uploaded webshell |
| `artifact:<name>@<chal>` | a CTF challenge artifact in hand **and characterised** (type/arch/format known) (P3) | operator drop in `artifacts/` (seeded), a forensics/stego carve |
| `key:<name>@<chal>` | a recovered secret: passphrase / private key / symmetric key / RSA factor / XOR key (P3) | rev, crypto, stego solve |
| `plaintext:<name>@<chal>` | recovered cleartext from a ciphertext (P3) | crypto solve |
| `source:<name>@<chal>` | recovered source / decompiled logic of a binary (P3) | rev solve |
| `flag:<chal>` | the flag for a (sub-)challenge captured (P3) — feeds P1's objective oracle | any terminal solve |

**Honesty rule (same discipline as the oracle gate):** a capability enters `capabilities[]` / the
scheduler's acquired set **only** when its producing hypothesis reaches `impact_proven`/`misconfig_proven`
AND the oracle met — or when the operator supplies it via `session.env`. Never on assumption. `requires`
is the *runtime gate* (what must be proven first); it is distinct from a finding's `combines`/lineage.

**Post-foothold stage (P4).** A hypothesis with `stage:"post-foothold"` that does inside-the-box work
(internal recon / privesc / loot / lateral) declares `requires:["shell:<host>"]` (OS work) or
`requires:["foothold:<host>"]` (authenticated app work). A foothold producer that grants OS command
execution — an SSH/telnet/RDP cred, a proven RCE, an uploaded webshell — MUST add `shell:<host>` to its
`provides`; a web-only login/BOLA session provides `session:`/`foothold:` but **NOT** `shell:`. Privesc
`provides:["admin:<host>"]`. The honesty rule is unchanged: `shell:`/`admin:` enter `capabilities[]`
**only** when oracle-proven (a demonstrated privileged action), never on an enumerator's suggestion.
Spider persistence posture is **scope-gated**, not globally denied (fix3-persistence, 2026-10-07). The engagement scope + operator attestation decides whether reboot-persist proof is in-bounds; `tools/leash-foothold.sh` reflects that decision in code via `LEASH_FOOTHOLD_ALLOW_PERSISTENCE` (default `0` — the historical no-persistence posture, byte-identical to today for every engagement whose `leash.env` leaves it unset). When the scope **requires** a persistence-proof milestone (e.g. Standoff 365 M100K user-session reboot-persist, M150K infra-node reboot-persist, M200K DA with a program-named user creation), the operator flips `leash.env`'s `LEASH_FOOTHOLD_ALLOW_PERSISTENCE=1` and the persistence group opens: `useradd/groupadd/usermod`, `passwd` for a NEW user, `authorized_keys` append, `crontab -e/add` (NOT `-r`), `systemctl enable/start/daemon-reload` (NOT `stop/disable/mask`), Windows `schtasks /create` (NOT `/delete`), writes to `/etc/cron.*//etc/systemd//etc/init.d//etc/rcN.d/`, registry `Run`/`RunOnce` keys. Even then the always-on denylist stays closed: destructive (`rm/rmdir/shred/dd/mkfs/wipefs/fdisk/chattr`), disruption of running services (`kill/pkill/killall/reboot/shutdown/halt/poweroff/systemctl stop|disable|mask/service X stop`), kernel-module (`insmod/rmmod/modprobe`), credential removal (`userdel`), log-wipe (`> /var/log/*`, `wevtutil cl`, `Clear-EventLog`, `auditpol /clear`), reverse-shell (`nc -e`, `ncat -e`), bulk-exfil (`tar -c`/`scp -r`/`rsync`/`zip -r`/`cp -r`), and ANY touch of the engagement's objective marker (e.g. `standoff365_hack_me`) — the final НС demonstration step is operator-manual, outside this wrapper. **No new capability token is introduced** — `requires`/`provides` stay the closed set in §Capability tokens; "persistence proven" is recorded as a finding's `execution_evidence`, not as a graph node. The brain **still** does not model implants/backdoors/C2 beacons autonomously — those are operator-manual tooling (operator holds C2 on an external VPS, operator attests persistence install under the engagement's blanket GO).

**CTF data-flow tokens (P3)** express a multi-stage CTF through the **existing** F4 graph, same honesty
rule: an `artifact:` from `targets/<t>/artifacts/` is *operator-supplied* (the file is on disk) and is
seeded into the scheduler's `acquired` set via `args.prior_capabilities`, exactly as `session.env` seeds
`session:`. A carve-produced `artifact:`, or any `key:`/`plaintext:`/`source:`/`flag:`, is granted
**only** when its solve hypothesis reaches `impact_proven` AND the oracle meets. `flag:<chal>` feeds P1's
objective oracle (the flag-behind-the-foothold).

**No new token for P1/P5/P6/P7 (closed-set discipline).** The objective is **terminal** — tracked in its
own `state.objective{}` block, so nothing depends on it and it needs no token (P1 rejects a `flag:<host>`
token). An interactive/pwn exploit (P5) and an OTP-logic door (P6) are **producers of the existing**
`session:<host>`/`foothold:<host>`/`admin:<host>` tokens, not new ones. Egress (P7) is a preflight GO-gate,
not a graph node — no token. The only grammar extension is `shell:<host>` (P4) + the 5 CTF tokens (P3);
there is deliberately **no** `objective:`/`interactive:`/`egress:`/`enum:` token.

## priorart.json — the prior-art / dedup index (fix3 B3, bounty mode; absent on a plain run)
Built EARLY by the reused `duplicate-scout` agent in **prior-art mode** (input: `scope.yaml` +
`state.json` recon surface/stack; output this file) and read UPSTREAM to orient the fleet + at the
`/report`+`/triage` gates. PASSIVE OSINT only (public disclosure indices + local files) — touches no
target, needs no leash. Matched by **ROOT CAUSE** (CWE+component+sink+authz-context, the Intigriti
"same-fix" test), not host+endpoint.
```json
{ "coverage":"verified|partial|unverifiable",   // the HONESTY switch: unverifiable (NO source resolved — private, no archive) => every verdict defaults to could-not-verify, NEVER novel
  "sources_checked":["hacktivity:acme","nvd:cpe:/a:acme:app:2.3","ghsa:npm/acme-sdk","changelog:...","submitted-archive","context-pack"],
  "disclosed":[ {"ref":"h1#1234567 | CVE-2025-1234 | GHSA-xxxx | submitted:f-0007",
                 "class":"IDOR","cwe":"CWE-639","host":"app.acme.com","component":"export-api",
                 "root_cause":"missing object-level authz on GET /export/{id}",
                 "disclosed_at":"2025-07-01","fixed":true,"fix_ref":"changelog#v2.4","source":"hacktivity"} ],
  "checked_ts":"ISO-8601" }
```
A disclosed-but-**fixed** item is a VARIANT/REGRESSION seed (re-test on the current build), not only a
filter. `state.json` carries a `priorart{coverage,ts}` summary mirror + `objective.dedup_cleared`;
hypotheses gain additive `novelty`/`novelty_ref`/`novelty_reason`/`dedup_source` (synthesizer-written).

## brain/corpus/ (fix3 senior-exemplar store)
The **cross-engagement** (Tier-2) generalization of the per-target `.claude/skills/context/<target>/SKILL.md`
pack: a precondition-keyed corpus of distilled senior exemplars the retriever surfaces against the live
world-model. It lives under `brain/` (NOT under `targets/<t>/` — it is shared across all engagements) and
is built OFFLINE, outside the GO-gated cycle. **Distilled only from PUBLICLY DISCLOSED material.** It
primes agents to find + PROVE faster; it is **never** a way to claim a finding without an oracle-proven
PoC — an exemplar's `proof_oracle` is a HINT for what to produce, FORBIDDEN as a citation of proof (the
oracle re-derives everything on the live target). The retrieval/injection path never touches the moat.

```
brain/corpus/
  exemplars.jsonl   # one senior exemplar per line (the decision-intelligence)
  payloads.jsonl    # one payload/command template per line (the executable primitive, by id)
  negative.jsonl    # one cross-engagement dead-end / clean-target fact per line
  index.json        # MACHINE-regenerated (tools/corpus_index.py); never hand-merged
```

**Record shapes (one JSON object per line):**
- `exemplars.jsonl`: `{id, class, source, target_fingerprint:{framework,version,header,param,response_shape},
  trigger_signal, decision_trace (string: "tried X (dead-end) -> pivot Y -> technique Z"), key_technique,
  payload_ref, proof_oracle (string naming the shape + the .claude/skills/proof/oracles/SKILL.md row),
  reusable_vs_instance:"reusable-technique|patched-instance|both", novelty:{vrt,patched_in},
  hit_rate:{tries,wins}, ts}`
- `payloads.jsonl`: `{id, class, requires_fingerprint:[tokens], template, note, payload (verbatim) OR
  status:"OMITTED" + resolve_from (exploit-db/nuclei-templates/PoC-repo keyed by the same fingerprint)}`
- `negative.jsonl`: `{id, scope:{class, fingerprint:[tokens]}, fact, consumed_by:["planner-skip","oracle-reject"]}`

**Invariants.**
- `class` ∈ the shipped `ATTACK_SKILLS` slug set (`workflows/attack.mjs:30`: artifact-analysis, auth-bypass,
  cors, cred-access, crypto, forensics, graphql, idor, interactive-exploit, internal-recon, jwt,
  keycloak-realm, lateral, loot, objective-capture, open-redirect, otp-logic, privesc, pwn,
  request-smuggling, rev, saml, sqli, ssrf, ssti, stego, takeover, upload, waf-body-bypass, xss, xxe), so
  corpus keys stay in lockstep with the skill packs (`tools/corpus_index.py` asserts this).
- **Single writer.** `brain/corpus/` has exactly ONE writer, `.claude/agents/corpus-curator.md` (mirrors
  `synthesizer.md`), active only in the OFFLINE enrichment phase. Fleet agents NEVER write the corpus —
  they return `used_exemplars[]` and the curator reconciles (the single-writer-of-canon invariant).
- **Fingerprint tokens are a SEPARATE namespace.** `target_fingerprint`/`requires_fingerprint` tokens
  (`stack:nextjs@15.2`, `engine:jinja2`, `cloud:gcp`, …) key retrieval/chaining ONLY. They NEVER enter the
  capability-token grammar (`requires`/`provides`) or `capabilities[]` — the F4 oracle-honest scheduler is
  untouched by the corpus.
- **The corpus `exemplars.jsonl.novelty` object is a SEPARATE namespace from the B3 finding-field `novelty`
  enum (fix3 audit #7 — explicit one-owner exemption).** Inside the corpus an exemplar carries
  `novelty:{vrt, patched_in}` (a disclosure descriptor: was this class patched upstream, seeding a
  variant/regression). On a FINDING / hypothesis, `novelty` is B3's string enum
  (`novel|likely-duplicate|could-not-verify`). They are different records in different files and NEVER
  co-occur in one object, so the single-owner rule is not violated; the `corpus-curator` reads a finding's
  B3 `novelty` enum and writes the exemplar's `novelty` object — do not conflate the two shapes.
- `index.json` is regenerated by `tools/corpus_index.py`, never hand-edited.

## Agent result additive fields (fix3, OPTIONAL — absent ⇒ byte-identical to today)
Agents still write evidence + a `result.json` into `raw/<agent>/`; these are additive leaf fields on the
existing result schemas, read by the feedback loop (never by the oracle):
- `CANDIDATE.used_exemplars[]` (attack) — the exemplar ids the agent was primed with for this hypothesis,
  returned so the `corpus-curator` can attribute outcomes and re-rank `hit_rate` (Tier-2 feedback). It is
  provenance for re-ranking, NEVER a proof citation.
- `HYPO_RESULT.hypotheses[].fingerprint[]` (recon-2) — the observed tech tokens a hypothesis saw, folded
  by the synthesizer into `state.json.fingerprints[]` so the retriever can key on them next round.

## Canonical field contract (fix3 §2 — one owner per field, no drift)
The bounty-mode fields above were proposed by several research points in parallel; the merge collapses
them to ONE grammar so future readers see the ownership (the consistency-gate lesson). Each per-finding
economic field is OPTIONAL (absent on an impact run); `scope.program{}` is ONE block (B1 economics ∪ B4
exclusions/vrt ∪ B5 reward_table); the objective mode enum is exactly `impact|flag|bounty`; no new
capability token is added.

| concept | canonical field(s) | owner |
|---|---|---|
| objective mode | `objective.mode` ∈ `impact\|flag\|bounty` | B1 |
| economics config | `scope.program{}` (ONE block) + `objective.min_payable_tier` + `objective.novelty{}` | B1 (program/objective), B4 (exclusions/vrt in program), B5 (`program.reward_table`), B3 (`objective.novelty`), B2 (`min_payable_tier`) |
| eligibility | `vrt`, `priority` (P1..P5\|varies), `eligibility` (payable\|excluded\|control-test-only\|unknown), `eligibility_reason` | B4 |
| severity→tier→EV | `cvss_vector`, `cvss_score`, `tier` (P1..P5 reward tier), `tier_reward`, `expected_value`, `ev_basis` | B5 |
| novelty/dedup | `novelty` (novel\|likely-duplicate\|could-not-verify), `novelty_ref`, `novelty_reason`, `dedup_coverage`, `dedup_checked_ts` | B3 |
| payout gate | `payout_ready` (bool), `payout_blockers` (string[]), `payout_distance` (8-rung enum) | B2 |
| effort floor | `program.min_pursue_priority` (distinct from the pay floor `objective.min_payable_tier`) | B4 |
| outcome record | `targets/<t>/submitted/<id>.json` (own schema) + additive `state.objective.status += submitted\|paid\|rejected` + additive `techniques[]`/`dead_paths[]` fields | B6 |

`priority` (VRT class baseline, B4) is distinct from `severity` (CVSS/impact band) and from `tier` (B5
evidence-derived reward tier); eligibility never changes severity; `could-not-verify` novelty is never
auto-promoted to novel; tier is never inflated to clear a pay floor; `submitted`/`paid` are
operator-attested. The schema additions are ALL optional (none in `finding.schema.json` `required`).

Agents never write `findings.jsonl` or `state.json` directly — they write evidence + a `result.json`
into `raw/<agent>/`. The **synthesizer** (clean context) reads the whole folder and writes the docs,
`findings.jsonl`, and merges `state.json`. One writer = no races.
