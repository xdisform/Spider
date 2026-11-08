// Release guard: EXECUTE every workflow script end-to-end with mocked agents, so runtime control-flow bugs
// (undefined refs, throwing stages, broken .then chains, the reflect/rechain/per-hop loops) surface here —
// `node --check` only parses, it cannot catch a `CLIENT_SIDE is not defined` inside a function that never
// ran in a test. The agents are FAKE: this does not test agent behaviour, only that the orchestration code
// runs to completion and returns a sane shape over MANY random branches (proven/not, oracle met/not,
// reflect retry/exhausted, rechain, breadth-sweep). No target traffic. Run: tools/smoke-workflows.sh
import fs from 'node:fs'
import path from 'node:path'
import url from 'node:url'

const ROOT = path.resolve(path.dirname(url.fileURLToPath(import.meta.url)), '..')
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor
const RUNS = Number(process.env.RUNS || 6)

function mockAgent(prompt, opts = {}) {
  const at = opts.agentType || '', label = opts.label || '', r = Math.random()
  if (at === 'attack-operator' || /exploit|sweep|retry/.test(label)) {
    const proven = r < 0.45 ? 'impact_proven' : (r < 0.6 ? 'misconfig_proven' : 'not_reproduced')
    return Promise.resolve({ hypothesis_id: 'hX', proven_state: proven, type: 'rce', severity: 'high', title: 't', detail: 'd', evidence: 'raw/e', execution_evidence: proven === 'impact_proven' ? 'uid=0' : '', poc_path: proven !== 'not_reproduced' ? 'raw/poc' : '', repro: 's', sibling_hypotheses: [], used_exemplars: [], scaffold: 'baseline', hops: [], hops_reached: 0 })
  }
  if (at === 'validator') return Promise.resolve({ oracle_met: r < 0.6, oracle_type: 'oob', oracle_evidence: 'cb', reproduced: true, severity: 'high', reason: 'ok' })
  if (at === 'verifier-skeptic') return Promise.resolve({ refuted: r < 0.2, reproduced: true, proven_impact: 'x', business_impact: 'victim data', attacker_impact: r < 0.2 ? '' : 'cross-tenant read', severity: 'high', reason: 'ok' })
  if (at === 'triage-scorer') { const ready = r < 0.5; return Promise.resolve({ ruling: ready ? 'SUBMIT' : (r < 0.75 ? 'FIX' : 'DROP'), cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', cvss_score: 6.5, band: 'Medium', tier: ready ? 'P2' : 'P4', severity: 'high', inflated: r < 0.3, corrected_from: r < 0.3 ? 'critical' : '', eligible: true, eligibility: 'payable', likely_duplicate: r > 0.85, payout_ready: ready, payout_blockers: ready ? [] : ['tier: P4 below pay floor P3'], first_url: 'https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', missing: ready ? '' : 'raise proof', reason: 'ok' }) }
  if (at === 'advisor') return Promise.resolve({ verdict: r < 0.5 ? 'retry' : 'exhausted', failure_reason: 'WAF', sharpened_angle: 'mutate', how_to_prove: 'wafrift' })
  if (at === 'chain-builder') return Promise.resolve({ chains: [{ name: 'c', steps: ['a'], end_impact: 'ATO', severity: 'high', uses: [], status: 'needs_proof' }], composite_hypotheses: r < 0.5 ? [{ id: 'hc-1', class: 'idor', host: 'h', why: 'w', how_to_prove: 'p', requires: [], provides: [] }] : [], targets: [{ id: 'cx-1', goal: 'ATO', class: 'idor', host: 'h', seed: 's', how_to_prove: 'p', uses: [], priority: 'high' }], note: '' })
  return Promise.resolve({ targets: [], chains: [], composite_hypotheses: [], hypotheses: [], assets: [], proposed_modes: [], proposed_ideas: [] })
}
const mockParallel = (arr) => Promise.all((arr || []).map(f => (typeof f === 'function' ? f() : f)))
async function mockPipeline(items, f1, f2) { const out = []; for (const it of (items || [])) { const a = await f1(it); out.push(f2 ? await f2(a, it) : a) } return out }

const base = { target: 't', target_dir: 'targets/t', scope: { hosts: ['h'], policies: {} }, bin_dir: 'bin', skills_dir: '.claude/skills', model_tier: 'fast', fleet: 5 }
const ARGS = {
  'attack.mjs': { ...base, reflect_rounds: 2, reflect_max: 8, trajectories: 2, max_rechain_rounds: 2, objective: { mode: 'impact' }, hypotheses: [
    { id: 'h-1', class: 'sqli', host: 'h', why: 'p', how_to_prove: 'inject', requires: [], provides: ['session:h'] },
    { id: 'h-2', class: 'idor', host: 'h', why: 'r', how_to_prove: 'SSRF -> metadata -> creds -> data', requires: ['session:h'], provides: [] },
    { id: 'h-3', class: 'xss', host: 'h', why: 'x', how_to_prove: 'dom', requires: [], provides: [], seam: { source: 'location.hash', sink: 'app.js:10', trace: 'h->s' } },
    { id: 'h-4', class: 'escalation-ladder', host: 'h', why: 'f', how_to_prove: 'reuse', requires: ['session:h'], provides: ['admin:h'] } ] },
  'chain.mjs': { ...base, reflect_rounds: 2, reflect_max: 8, trajectories: 2, findings: { confirmed: [{ id: 'f1', type: 'idor', title: 'BOLA', severity: 'high', host: 'h' }], candidates: [{ id: 'c1', type: 'ssrf', title: 's', host: 'h' }], leads: [{ id: 'l1', class: 'xss', host: 'h', why: 'w' }] } },
  'recon-1.mjs': { ...base }, 'recon-2.mjs': { ...base }, 'classify.mjs': { ...base, preflight: {} },
  'triage.mjs': { ...base, program: { name: 'Acme', min_payable_tier: 'P3' }, objective: { mode: 'bounty', min_payable_tier: 'P3' }, findings: [
    { id: 'f-0001', type: 'idor', title: 'BOLA on /export/{id}', severity: 'high', detail: 'cross-account read', evidence: 'raw/e', execution_evidence: 'owner-id A!=B', poc_path: 'raw/poc.sh', repro: '1. GET /export/2 as A', target: 'app.acme.com', eligibility: 'payable', tier: 'P2', novelty: 'novel', cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N' },
    { id: 'f-0002', type: 'xss', title: 'self-XSS in profile', severity: 'low', detail: 'self only', evidence: 'raw/e2', target: 'app.acme.com' },
    { id: 'f-0003', type: 'ssrf', title: 'blind SSRF', severity: 'high', detail: 'oob', evidence: 'raw/e3', execution_evidence: 'interactsh hit', poc_path: 'raw/poc3', repro: '1. probe', target: 'api.acme.com', eligibility: 'payable', tier: 'P2', novelty: 'novel', cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N' },
  ] },
}

async function runOnce(file, args) {
  const body = fs.readFileSync(path.join(ROOT, 'workflows', file), 'utf8').replace(/^export\s+const\s+meta/m, 'const meta')
  const fn = new AsyncFunction('args', 'log', 'agent', 'parallel', 'pipeline', 'phase', body)
  return fn(args, () => {}, mockAgent, mockParallel, mockPipeline, () => {})
}

let fail = 0
for (const file of Object.keys(ARGS)) {
  const n = (file === 'attack.mjs' || file === 'chain.mjs' || file === 'triage.mjs') ? RUNS : 2
  let ok = 0, err = null
  for (let i = 0; i < n; i++) {
    try { const ret = await runOnce(file, ARGS[file]); if (ret && ret.phase) ok++; else throw new Error('no phase in return') }
    catch (e) { err = e; break }
  }
  if (ok === n) console.log(`  ok   ${file.padEnd(13)} ${n}/${n} runs`)
  else { console.log(`  FAIL ${file} (${ok}/${n})\n       ${(err && err.stack ? err.stack.split('\n').slice(0, 3).join('\n       ') : err)}`); fail = 1 }
}
console.log(fail ? 'SMOKE-WORKFLOWS: FAIL' : 'SMOKE-WORKFLOWS: PASS')
process.exit(fail)
