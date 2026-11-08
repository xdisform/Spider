export const meta = {
  name: 'spider-classify',
  description: 'Classify the engagement from scope + the one preflight liveness/egress fact + local artifact file-types, and propose an ordered cycle/lens plan. Preflight only — sends NO target packets.',
  phases: [{ title: 'Classify' }],
}

// --- args (from /spider preflight, see brain/mission.md + brain/spider.md §Mode router) ---
// { target, target_dir, scope, authorization, model_tier, skills_dir, preflight }
const a = args || {}
const skillsDir = a.skills_dir || 'C:/Spider/.claude/skills'
const modelFor = t => (t === 'fast' ? { model: 'claude-haiku-4-5' } : { model: 'claude-sonnet-4-6' })

// Closed vocabularies — brain/modes.md is the authoritative registry; keep these in sync with the
// `modes:` tags in recon-1.mjs/recon-2.mjs. LENS_MODES are the FINE tags the recon mode gate intersects
// (chosen_modes becomes args.modes); MODE_LABELS are the coarse human labels for the committed `mode`
// (they mirror scope.engagement.type). Coarse binary/file/ctf are EXPANDED to fine modes per modes.md.
const LENS_MODES = ['web', 'network', 'service', 'api', 'ctf-pwn', 'ctf-rev', 'ctf-crypto', 'ctf-forensics', 'ctf-stego']
const MODE_LABELS = ['web', 'network', 'service', 'api', 'binary', 'file', 'ctf', 'mixed']

// The schema the classifier returns — this return value IS the plan the operator approves at GO #1.
const PLAN = {
  type: 'object',
  properties: {
    mode: { type: 'string', enum: MODE_LABELS, description: 'the primary committed coarse mode (human label for the attack banner + state.json)' },
    chosen_modes: { type: 'array', items: { type: 'string', enum: LENS_MODES }, description: 'every applicable FINE lens-mode; this becomes args.modes and drives the recon mode gate. For a reachable web host, include the full web/network/service/api set (this is what keeps a normal run unchanged). Narrow to a non-web set ONLY for a pure artifact (no reachable host).' },
    confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
    signals: { type: 'array', items: { type: 'string' }, description: 'the concrete evidence for each mode: host:port + http status/title/server, an openapi/graphql path, or the `file` magic of an artifact' },
    proposed_phases: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          cycle: { type: 'string', description: 'classify | recon-1 | recon-2 | attack | chain | objective-check' },
          modes: { type: 'array', items: { type: 'string', enum: LENS_MODES } },
          why: { type: 'string' },
        },
        required: ['cycle'],
      },
      description: 'the ordered cycle plan, foothold-first (ATT&CK: access/credential before discovery/collection). A reachable host => [classify, recon-1, recon-2, attack, chain]; a pure artifact => [classify, attack, objective-check] (skip web recon).',
    },
    proposed_objective: {
      type: 'object',
      properties: {
        mode: { type: 'string', enum: ['impact', 'flag', 'bounty'] },
        why: { type: 'string' },
      },
      description: 'OPTIONAL (fix3 B7): the OBJECTIVE mode the router recommends (orthogonal to chosen_modes, the engagement shape). The operator approves/overrides at GO #1. Absent => the brain default (impact). A recommendation only — it sets no mode, relaxes no policy, grants no capability.',
    },
    proposed_ideas: { type: 'array', items: { type: 'string' }, description: 'OPTIONAL free-form suggestions the operator may fold in (the agent-proposes channel). Ignored if empty.' },
    note: { type: 'string' },
  },
  required: ['mode', 'chosen_modes', 'proposed_phases'],
}

phase('Classify')
const res = await agent(`${a.authorization || 'AUTHORIZED ENGAGEMENT.'}

You are Spider's engagement CLASSIFIER + PLANNER (the macro router). You send NO packets — you reason
ONLY over the FACTS below (scope.yaml + the single already-authorized liveness/egress probe step 1 ran +
the file-types of any local artifact the operator dropped under ${a.target_dir}/artifacts/). From them,
classify the engagement into the closed mode vocabulary and propose an ordered cycle/lens plan. You
CLASSIFY and SEQUENCE only — you do not hunt, scan, log in, or open any new connection.

FACTS (nothing else — do not infer a host you were not given):
  scope: ${JSON.stringify(a.scope || {}, null, 0)}
  preflight/liveness: ${JSON.stringify(a.preflight || {}, null, 0)}   // {host, port, http_status, server, title, egress verdict, reach_detail} from step 1
  artifacts: ${JSON.stringify((a.scope && a.scope.engagement && a.scope.engagement.artifacts) || [], null, 0)}

READ FIRST: ${a.target_dir}/scope.yaml (the authority), brain/modes.md (the mode registry — the
signal table, the coarse->fine expansion, the default cycle plans, and the two backward-compat locks),
and ${skillsDir}/recon/target-classify/SKILL.md (the read-only classification methodology for this phase).

VOCABULARY:
  mode (coarse, one label): ${JSON.stringify(MODE_LABELS)}
  chosen_modes (fine, the lens-driving set): ${JSON.stringify(LENS_MODES)}
  Expand coarse scope.engagement.type -> fine chosen_modes per brain/modes.md:
    binary -> [ctf-pwn, ctf-rev];  file -> [ctf-forensics, ctf-stego, ctf-crypto];
    ctf    -> the ctf-* modes implied by engagement.challenges[].category;  mixed -> the union.

RULES (the backward-compat contract — follow exactly):
1. READ SIGNALS: an HTTP status/title/server on the liveness fact => web; a raw service banner or a
   non-HTTP port in scope => network/service; an OpenAPI/Swagger/GraphQL path with little/no HTML => api;
   a local artifact's file-magic (ELF/PE => binary; document/image/pcap/ciphertext => file) => a ctf-*
   fine set. scope.objective.goal / where_hint biases the mode + the ordering (never authority or proof).
2. DEFAULT TO THE FULL WEB SET. If ANY host is reachable, chosen_modes MUST include every
   web/network/service/api mode that any signal supports — do NOT narrow below the full web set for a
   web-reachable target. That is what keeps a normal run byte-for-byte unchanged.
3. NARROW ONLY FOR A PURE ARTIFACT. Choose a ctf-*/binary/file-only chosen_modes set ONLY when there is
   NO reachable host at all (a provided puzzle). Then propose [classify, attack, objective-check] and
   skip the web recon cycles.
4. FAIL-OPEN. If you are NOT confident, or the shape is genuinely ambiguous and no operator hint pins it,
   return chosen_modes:['web','network'] with confidence:'low' (the standard flow). The default is always
   the thing that works today. (A single genuine api-vs-web ambiguity on confidence:'low' is for the
   brain to resolve with the operator at GO — you still return the safe default.)
5. ORDER FOOTHOLD-FIRST. proposed_phases is ATT&CK-ordered: a foothold cycle (Credential/Initial Access)
   precedes a post-foothold cycle (Discovery/Collection). A reachable host =>
   [classify, recon-1, recon-2, attack, chain]; a pure artifact => [classify, attack, objective-check].
6. PROPOSE AN OBJECTIVE MODE (fix3 B7). This is the objective axis (scope.objective.mode:
   impact|flag|bounty), ORTHOGONAL to chosen_modes (the engagement shape). If scope.objective.mode is
   already set, ECHO it. Else: a reachable web/api host with a BOUNTY SIGNAL — a scope.program{} block is
   present, OR scope.platform is a bug-bounty platform (HackerOne/Bugcrowd/Intigriti/YesWeHack/BI.ZONE/
   Standoff 365/private), AND there is no CTF/flag objective — => propose proposed_objective.mode:'bounty'
   with a one-line why (the economically-oriented default, the SOTA posture). A pure artifact / CTF with a
   flag_format/objective => propose 'flag'. Otherwise propose 'impact'. This is a RECOMMENDATION the operator
   approves at GO — it sets no mode, relaxes no policy, grants no capability.

RED LINE: classify only — NO packets, NO scan, NO login, NO new connection before GO. A mode is a
lens/cycle selection, never a capability or a policy relaxation. The operator approves your plan at GO.

Return the PLAN schema. Your return value IS the plan the operator will approve at GO #1.`,
  { label: 'classify', phase: 'Classify', agentType: 'recon-operator', schema: PLAN, ...modelFor(a.model_tier) })

// Fail-open locks (backward-compat): a null/empty classifier result => the full standard web playbook.
// ['web','network'] already lights every current non-CTF lens, so this is today's run. Order & shape are
// normalized here so the brain always gets a usable plan even if the agent died or under-returned.
const chosen_modes = (res && Array.isArray(res.chosen_modes) && res.chosen_modes.length)
  ? res.chosen_modes.filter(m => LENS_MODES.includes(m))
  : ['web', 'network']
const safe_modes = chosen_modes.length ? chosen_modes : ['web', 'network']
const proposed_phases = (res && Array.isArray(res.proposed_phases) && res.proposed_phases.length)
  ? res.proposed_phases
  : [{ cycle: 'recon-1', modes: safe_modes }, { cycle: 'recon-2', modes: safe_modes }, { cycle: 'attack', modes: safe_modes }, { cycle: 'chain' }]
const classification = {
  mode: (res && MODE_LABELS.includes(res.mode)) ? res.mode : 'web',
  confidence: (res && ['high', 'medium', 'low'].includes(res.confidence)) ? res.confidence : 'low',
  signals: (res && Array.isArray(res.signals)) ? res.signals : [],
  // NB: no `ts` here — workflow scripts cannot call `new Date()`/`Date.now()` (they throw, to keep
  // resume deterministic). The BRAIN stamps classification.ts when it writes run.json (same as every
  // other run.json timestamp).
}
// fix3 B7 — additive objective-mode proposal. Fail-open to {mode:'impact'} (today's default) so a
// null/invalid proposal never forces a mode; the brain acts on it only by SHOWING it at GO #1, and the
// objective mode is set only if the operator approves (writing scope.objective.mode). Absent approval,
// a.objective stays undefined/impact and every bounty block is '' — the run is byte-identical to today.
const proposed_objective = (res && res.proposed_objective && ['impact', 'flag', 'bounty'].includes(res.proposed_objective.mode))
  ? { mode: res.proposed_objective.mode, why: (typeof res.proposed_objective.why === 'string') ? res.proposed_objective.why : '' }
  : { mode: 'impact', why: '' }
log(`classify: mode=${classification.mode} confidence=${classification.confidence} chosen_modes=[${safe_modes.join(',')}] phases=[${proposed_phases.map(p => p.cycle).join(' -> ')}] objective=${proposed_objective.mode}`)

// The brain shows classification + proposed_phases on the GO #1 screen and, on GO, writes
// classification/chosen_modes/proposed_phases to run.json and passes args.modes = chosen_modes to each
// cycle. Absent/low-confidence => safe_modes = the standard flow.
return {
  phase: 'classify',
  target: a.target,
  classification,
  chosen_modes: safe_modes,
  confidence: classification.confidence,
  signals: classification.signals,
  proposed_phases,
  proposed_objective,
  proposed_ideas: (res && Array.isArray(res.proposed_ideas)) ? res.proposed_ideas : [],
  note: (res && res.note) || '',
}
