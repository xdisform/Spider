export const meta = {
  name: 'spider-triage',
  description: 'Pre-submission triage as a 3-stage skeptical veto funnel — Reproduce (class oracle) -> Impact (business + attacker impact) -> Severity (real CVSS via the FIRST calculator + eligibility/dedup/payout-gate). A finding is ruled SUBMIT only if it survives all three gates. Goal: zero false positives.',
  phases: [{ title: 'Reproduce' }, { title: 'Impact' }, { title: 'Severity' }],
}

// Spider /triage — the strictest pass before an operator submits. THREE hostile triagers, staged as a
// funnel; each is a VETO and a finding reaches SUBMIT only if it survives all three. The two decisive
// gates are DETERMINISTIC and re-derivable by someone who distrusts the model — the class oracle
// (.claude/skills/proof/oracles) in stage 1, and the FIRST CVSS calculator (tools/ev-score.py) plus the
// payout-gate (tools/payout-gate.py) in stage 3 — so nothing narrates its way to SUBMIT. That is the
// 0-false-positive contract: structural, not prompt-level. Spider RECORDS the rulings; the operator submits.

const a = args || {}
// Pinned fleet models: fast = sonnet-4-6, strong = opus-4-6. The last anti-false-positive gate is not the
// place to cheap out — the deterministic oracle/CVSS/payout tools carry the structural 0-FP work; the
// model re-runs the PoC, builds the honest vector, and judges real-world impact.
const modelFor = t => (t === 'fast' ? { model: 'claude-sonnet-4-6' } : { model: 'claude-opus-4-6' })
const findings = Array.isArray(a.findings) ? a.findings : []
const td = a.target_dir || `targets/${a.target || 't'}`
const binDir = a.bin_dir || 'bin'
const scopeJSON = JSON.stringify(a.scope || {}, null, 0)
// Bounty mode fires PER FINDING when economic fields are present (program/objective transcribed). Absent
// => impact mode: stage 3 still enforces HONEST CVSS severity truth (no inflation), it just skips the
// eligibility/dedup/payout-gate leg — byte-compatible with an impact-run finding carrying no economics.
const program = a.program || null
const minTier = (a.objective && a.objective.min_payable_tier) || (program && program.min_payable_tier) || null
const econOf = f => !!program || f.payout_ready !== undefined || !!f.eligibility || !!f.tier || !!f.novelty || !!f.cvss_vector

if (!findings.length) {
  log('triage: no findings passed — nothing to triage.')
  return {
    phase: 'triage', target: a.target, verdicts: [],
    summary: { total: 0, reproduced: 0, impactful: 0, submit: 0, fix: 0, drop: 0 }, note: 'no findings',
  }
}

// ---- per-stage schemas (each stage is a VETO gate) -----------------------------------------------
const ORACLE = {
  type: 'object',
  properties: {
    oracle_met: { type: 'boolean', description: 'the class oracle (proof/oracles) is objectively met with re-derivable evidence — NOT narration' },
    oracle_type: { type: 'string' },
    oracle_evidence: { type: 'string', description: 'the path/line under raw/ that proves it' },
    reproduced: { type: 'boolean' },
    severity: { type: 'string', enum: ['info', 'low', 'medium', 'high', 'critical'] },
    reason: { type: 'string' },
  },
  required: ['oracle_met', 'reason'],
}
const IMPACT = {
  type: 'object',
  properties: {
    refuted: { type: 'boolean', description: 'true if the claimed impact does NOT hold up (default to true)' },
    reproduced: { type: 'boolean' },
    proven_impact: { type: 'string', description: 'what was ACTUALLY achieved, empty if none' },
    business_impact: { type: 'string', description: 'what the asset owner loses — victim data/funds/accounts/integrity/availability. Empty if none' },
    attacker_impact: { type: 'string', description: 'what a REAL external attacker gains (crosses a boundary: another user/tenant, privilege, money, exec). Self-only or victim-impossible => empty' },
    severity: { type: 'string', enum: ['info', 'low', 'medium', 'high', 'critical'], description: 'severity justified by the proven impact only' },
    reason: { type: 'string' },
  },
  required: ['refuted', 'reason'],
}
const SEVERITY = {
  type: 'object',
  properties: {
    ruling: { type: 'string', enum: ['SUBMIT', 'FIX', 'DROP'] },
    cvss_vector: { type: 'string', description: 'CVSS 3.1 base vector built ONLY from proven impact' },
    cvss_score: { type: 'number', description: 'from tools/ev-score.py — the FIRST 3.1 formula, never hand-picked' },
    band: { type: 'string' },
    tier: { type: 'string', enum: ['P1', 'P2', 'P3', 'P4', 'P5'] },
    severity: { type: 'string', enum: ['info', 'low', 'medium', 'high', 'critical'] },
    inflated: { type: 'boolean', description: 'true if the claimed severity was higher than the proven CVSS supports' },
    corrected_from: { type: 'string', description: 'the claimed severity/tier if corrected down, else empty' },
    eligible: { type: 'boolean', description: 'bounty: class is payable under program/VRT' },
    eligibility: { type: 'string', description: 'payable | excluded | control-test-only | unknown' },
    likely_duplicate: { type: 'boolean', description: 'bounty: already disclosed/patched per priorart.json' },
    payout_ready: { type: 'boolean', description: 'bounty: the deterministic payout-gate composite (tools/payout-gate.py)' },
    payout_blockers: { type: 'array', items: { type: 'string' } },
    first_url: { type: 'string', description: 'the first.org/cvss/calculator link for this vector (from ev-score.py)' },
    missing: { type: 'string', description: 'what is missing to make it submittable (for FIX)' },
    reason: { type: 'string' },
  },
  required: ['ruling', 'reason'],
}

// ---- shared finding brief -------------------------------------------------------------------------
const brief = f => `FINDING ${f.id}: ${JSON.stringify({ type: f.type, title: f.title, claimed_severity: f.severity, detail: f.detail, evidence: f.evidence, execution_evidence: f.execution_evidence, poc_path: f.poc_path, repro: f.repro, target: f.target })}
TARGET DIR: ${td} (evidence + PoC under raw/). SCOPE: ${scopeJSON}
Arsenal in ${binDir}; re-run through the leash (tools/leashed.sh for HTTP, tools/leash-tcp.sh for raw TCP), IN SCOPE ONLY.`

// ---- stage missions -------------------------------------------------------------------------------
function reproMission(f) {
  return `You are the deterministic VALIDATOR — STAGE 1 of 3 (Reproduce) of pre-submission triage. You do
not debate; you RE-RUN the PoC with your own hands and produce the class oracle evidence. Read
.claude/skills/proof/oracles/SKILL.md for THIS finding's class oracle.
${brief(f)}

1. Read the PoC (poc_path) + the evidence under raw/.
2. Re-execute it yourself, in scope, through the leash — never trust the author's narration.
3. Produce the class ORACLE evidence and save it under raw/triage-${f.id}/ (OOB callback for a UNIQUE
   interactsh token whose src-IP is the target; a real DB banner; command output; account A reading
   account B's record with a differing owner-id; a credentialed cross-origin body read; a 3xx Location to
   the attacker host; a 401/403->200 privileged read; etc.).
ORIGIN-CHECK HARD VETO: a callback from 127.0.0.1 / our own egress, or a "service" that is really a local
proxy, is a FALSE POSITIVE -> oracle_met=false.
Set oracle_met=true ONLY with objective, re-derivable evidence. When in doubt, oracle_met=false — the
finding does NOT advance past this gate. Return the schema. Your return value IS data.`
}

function impactMission(f, s1) {
  return `You are a HOSTILE bug-bounty triager — STAGE 2 of 3 (Impact). Stage 1 already met the class oracle
(${s1.oracle_type || 'oracle'}: ${s1.oracle_evidence || 'see raw/'}). Your job now is to KILL anything whose
IMPACT does not really matter. Default to refuted=true; let the evidence change your mind.
${brief(f)}

Judge, from the REPRODUCED evidence only:
1. BUSINESS IMPACT — what does the asset owner actually lose (victim data / funds / account takeover /
   integrity / availability)? "Best-practice" or "an attacker could theoretically" is NOT impact.
2. ATTACKER IMPACT (decisive) — what does a REAL external attacker GAIN? It must cross a boundary: another
   user's data or tenant, a privilege, money, or code execution. A self-only effect (self-XSS, acting on
   your OWN account), an effect needing a victim action no real user performs, or an out-of-scope / own-
   egress target gains the attacker NOTHING: set attacker_impact="" and refuted=true.
3. SEVERITY SANITY — does the proven impact justify the claimed severity (${f.severity || 'n/a'}), or is it
   inflated? Record the evidence-justified severity.
Return the schema. If attacker_impact is empty you MUST set refuted=true. Be hostile — a finding that cannot
survive you will not survive the program's triager.`
}

function sevMission(f, s1, s2) {
  const econ = econOf(f)
  const scopePath = `${td}/scope.yaml`
  const econBlock = econ ? `
4. ELIGIBILITY (brain/vrt.md + the program's transcribed exclusions): map the class to its VRT row — is it
   payable, or excluded / a built-in P5 default / control-test-only? An excluded class is DROP (kept as a
   noted lead) UNLESS it chains into a payable impact (then the chain's end-impact is what pays). Set
   eligible + eligibility.
5. DEDUP: check ${td}/priorart.json if present — already disclosed/patched/known? likely-duplicate => DROP
   (or SUBMIT-as-regression ONLY if the current build contradicts the disclosed fix). could-not-verify is
   NEITHER novel NOR a duplicate — hand it to the operator. Set likely_duplicate.
6. PAYOUT-GATE (deterministic — you cannot narrate past it): write the finding with your corrected
   cvss_vector/tier/eligibility/novelty to a temp JSON and run
     python tools/payout-gate.py --finding <tmp.json> --scope ${scopePath} --explain
   Take payout_ready + payout_blockers VERBATIM. payout_ready=false => you CANNOT rule SUBMIT; rule FIX and
   copy the blockers into missing.${minTier ? ` Pay floor: min_payable_tier=${minTier}.` : ''}` : `
(impact mode — no program economics: skip eligibility/dedup/payout-gate; still enforce HONEST severity.)`
  return `You are the SEVERITY-TRUTH triager — STAGE 3 of 3 (Severity), the FINAL veto. Stages 1-2 proved the
impact: business="${(s2.business_impact || '').slice(0, 240)}"; attacker="${(s2.attacker_impact || '').slice(0, 240)}".
Your job: assign the HONEST CVSS and kill any inflation.
${brief(f)}

1. Build the CVSS 3.1 base vector from the PROVEN impact ONLY (stage-1 oracle + stage-2 attacker impact).
   AV/AC/PR/UI/S/C/I/A reflect what was actually demonstrated — never the tier you want.
2. SCORE IT WITH THE FIRST CALCULATOR — do not hand-pick a number. Run:
     python tools/ev-score.py --vector <your_vector>${econ ? ` --reward-table ${scopePath} --min-payable-tier ${minTier || 'P4'} --dedup <novelty> --eligibility <eligibility> --priority <vrt_priority>` : ''}
   Use its cvss_score / band / tier / first_url VERBATIM, and return first_url so the operator can re-verify
   on the official FIRST.org calculator. The vector is the evidence; the score is arithmetic.
3. INFLATION: if the claimed severity/tier was higher than the proven CVSS supports, set inflated=true and
   corrected_from=<claimed>, and use the honest value. Severity is evidence-bound — never upgraded for a
   bigger payout.${econBlock}

Rule: SUBMIT (proven + materially impactful + honestly scored${econ ? ' + payout_ready' : ''}), FIX (real but
incomplete — say exactly what is missing${econ ? ', incl. payout_blockers' : ''}), or DROP (inflated down to
nothing${econ ? ' / ineligible / duplicate / below the pay floor' : ''}). Return the schema. Be hostile.`
}

// ---- STAGE 1 — Reproduce (oracle veto) ------------------------------------------------------------
phase('Reproduce')
const r1 = await parallel(findings.map(f => () =>
  agent(reproMission(f), { label: `triage-reproduce:${f.id}`, phase: 'Reproduce', agentType: 'validator', schema: ORACLE, ...modelFor(a.model_tier) })
    .then(s1 => ({ f, s1: s1 || {} }))
))
const reproduced = r1.filter(x => x.s1.oracle_met === true)
log(`stage 1 Reproduce: ${reproduced.length}/${findings.length} met the class oracle`)

// ---- STAGE 2 — Impact (business + attacker-impact veto) -------------------------------------------
phase('Impact')
const r2 = await parallel(reproduced.map(x => () =>
  agent(impactMission(x.f, x.s1), { label: `triage-impact:${x.f.id}`, phase: 'Impact', agentType: 'verifier-skeptic', schema: IMPACT, ...modelFor(a.model_tier) })
    .then(s2 => ({ ...x, s2: s2 || {} }))
))
const impactful = r2.filter(x => x.s2.refuted === false)
log(`stage 2 Impact: ${impactful.length}/${reproduced.length} survived impact refutation`)

// ---- STAGE 3 — Severity (real CVSS via FIRST calc + eligibility/dedup/payout-gate veto) -----------
phase('Severity')
const r3 = await parallel(impactful.map(x => () =>
  agent(sevMission(x.f, x.s1, x.s2), { label: `triage-severity:${x.f.id}`, phase: 'Severity', agentType: 'triage-scorer', schema: SEVERITY, ...modelFor(a.model_tier) })
    .then(s3 => ({ ...x, s3: s3 || {} }))
))

// ---- assemble one verdict per ORIGINAL finding, recording the gate it died at ---------------------
const killedRepro = r1.filter(x => x.s1.oracle_met !== true).map(x => ({
  id: x.f.id, ruling: 'DROP', killed_at: 'reproduce', severity: 'info',
  reason: x.s1.reason || 'class oracle not met — not reproducible', stage1: x.s1,
}))
const killedImpact = r2.filter(x => x.s2.refuted !== false).map(x => ({
  id: x.f.id, ruling: 'DROP', killed_at: 'impact', severity: x.s2.severity || 'info',
  reason: x.s2.reason || 'no real attacker/business impact', stage1: x.s1, stage2: x.s2,
}))
const scored = r3.map(x => {
  const s3 = x.s3
  // Deterministic override mirroring the payout-gate red line: in bounty mode a payout_ready:false finding
  // can NEVER be ruled SUBMIT — the model cannot narrate past the gate.
  let ruling = s3.ruling || 'FIX'
  if (econOf(x.f) && s3.payout_ready === false && ruling === 'SUBMIT') ruling = 'FIX'
  return {
    id: x.f.id, ruling, killed_at: ruling === 'DROP' ? 'severity' : null,
    severity: s3.severity, cvss_vector: s3.cvss_vector, cvss_score: s3.cvss_score, tier: s3.tier,
    inflated: s3.inflated === true, corrected_from: s3.corrected_from || '',
    eligible: s3.eligible, likely_duplicate: s3.likely_duplicate,
    payout_ready: s3.payout_ready, payout_blockers: s3.payout_blockers || [],
    first_url: s3.first_url || '', missing: s3.missing || '', reason: s3.reason || '',
    stage1: x.s1, stage2: x.s2, stage3: s3,
  }
})

const verdicts = [...scored, ...killedImpact, ...killedRepro]
const submit = scored.filter(v => v.ruling === 'SUBMIT')
const fix = verdicts.filter(v => v.ruling === 'FIX')
const drop = verdicts.filter(v => v.ruling === 'DROP')
log(`triage done: ${submit.length} SUBMIT, ${fix.length} FIX, ${drop.length} DROP (of ${findings.length}) `
  + `— ${findings.length - reproduced.length} killed at Reproduce, ${reproduced.length - impactful.length} at Impact`)

return {
  phase: 'triage', target: a.target, verdicts,
  summary: { total: findings.length, reproduced: reproduced.length, impactful: impactful.length,
    submit: submit.length, fix: fix.length, drop: drop.length },
  funnel: {
    reproduce: { in: findings.length, out: reproduced.length },
    impact: { in: reproduced.length, out: impactful.length },
    severity: { in: impactful.length, out: submit.length },
  },
  note: 'Each stage is a veto; SUBMIT means reproduced (class oracle) + materially impactful (real attacker '
    + 'gain) + honestly scored' + (program ? ' + payout_ready (deterministic payout-gate)' : '')
    + '. The oracle and the CVSS/payout gates are deterministic — 0 false positives by construction.',
}
