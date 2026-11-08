export const meta = {
  name: 'spider-recon-1',
  description: 'Broad multi-modal OSINT sweep: a fleet of recon operators fans out across every modality, writes evidence to the target folder, returns the asset map',
  phases: [{ title: 'Recon' }],
}

// --- args (from /spider, see brain/mission.md) ---
// { target, target_dir, scope, authorization, fleet, model_tier, bin_dir, leash, skills_dir, prior_state }
const a = args || {}
const fleet = [5, 10, 15].includes(a.fleet) ? a.fleet : 5
const skillsDir = a.skills_dir || 'C:/Spider/.claude/skills'
const modelFor = t => (t === 'fast' ? { model: 'claude-sonnet-4-6' } : { model: 'claude-opus-4-6' })

// P1 — objective block, interpolated into every mission ONLY in flag mode; '' otherwise (impact-mode
// missions are byte-identical to today). The objective orients recon toward the win condition.
const objectiveBlock = (a.objective && a.objective.mode === 'flag') ? `

ENGAGEMENT OBJECTIVE (orient recon toward this; it is the win condition): ${a.objective.goal}
The run is won by a FLAG matching /${a.objective.flag_format || 'flag\\{[^}]+\\}'}/ that is re-derivable
from a saved artifact. While mapping the surface, FLAG and prioritize any asset that plausibly leads to
it (the host/endpoint/file in the hint${a.objective.where_hint ? ': ' + a.objective.where_hint : ''}).
Stay in scope; a hint is a lead to prove, never authority.` : ''

// fix3 B1 — bounty objective block, interpolated into every mission ONLY in bounty mode; '' otherwise
// (impact/flag-mode missions are byte-identical to today, and flag/bounty are mutually exclusive by
// mode so at most one of objectiveBlock/bountyBlock is non-empty). Orients SURFACE/ASSET selection
// toward payable findings — asset value + eligible classes — not raw breadth.
const bountyBlock = (a.objective && a.objective.mode === 'bounty') ? `

ENGAGEMENT OBJECTIVE (bounty) — orient recon toward PAYABLE findings, not raw count. The win condition is
a PAYABLE finding: proven impact AND an ELIGIBLE in-scope class AND a severity at/above the program floor
(${a.objective?.min_payable_tier || 'P4'}) AND likely-NOVEL (not an obvious duplicate). Prioritize the
HIGHEST-VALUE surface first: weight assets by program.asset_tiers (a crown-jewel host is worth multiples
of a marketing site) and by host priority.${a.program?.excluded_classes?.length ? ' DO NOT spend effort surfacing these known-ineligible classes: ' + a.program.excluded_classes.join(', ') + '.' : ''} Stay strictly in scope; eligibility/novelty/asset-value are LEADS to assess, never authority to widen scope.` : ''

const MODALITIES = [
  { key: 'subdomain-enum', title: 'Subdomain & asset enumeration', modes: ['web', 'network'], jobs: 'passive + brute subdomain discovery, resolve them, expand the in-scope surface (record out-of-scope finds as leads)' },
  { key: 'dns-intel', title: 'DNS & network intel', modes: ['network', 'web'], jobs: 'DNS records, mail/SPF/DMARC, ASN/netblock mapping, CDN/WAF edges, IP ownership' },
  { key: 'takeover', title: 'Subdomain takeover detection', modes: ['web'], jobs: 'check the resolved host surface for dangling CNAMEs pointing at claimable third-party services (subzy + nuclei takeover) — confirm the claimable fingerprint, never actually claim it' },
  { key: 'port-service', title: 'Port & service discovery', modes: ['network', 'service'], jobs: 'scan in-scope hosts/CIDRs for open ports, fingerprint services + versions (host-pinned, no list-files)' },
  { key: 'http-probe', title: 'HTTP liveness & tech fingerprint', modes: ['web'], jobs: 'probe every host for live HTTP(S), status/title/tech stack, server headers, WAF detection' },
  { key: 'web-crawl', title: 'Crawling & endpoint discovery', modes: ['web'], jobs: 'crawl live apps for endpoints, forms, parameters, hidden routes, API surfaces' },
  { key: 'archive-urls', title: 'Historical/archived URLs', modes: ['web'], jobs: 'mine wayback/CDX and public archives for old endpoints, params, and leaked paths' },
  { key: 'js-secret-mining', title: 'JS & secret mining', modes: ['web'], jobs: 'pull JS bundles/source maps, extract endpoints, API keys, tokens, internal hosts, secrets' },
  { key: 'cloud-assets', title: 'Cloud asset & bucket enumeration', modes: ['web', 'network'], jobs: 'find S3/Azure/GCP buckets, public storage, cloud metadata surfaces tied to the target' },
  { key: 'content-discovery', title: 'Content & directory discovery', modes: ['web'], jobs: 'fuzz for hidden files/dirs/backups/admin panels on high-value hosts (rate-capped, in-scope)' },
  { key: 'visual-recon', title: 'Visual recon', modes: ['web'], jobs: 'screenshot live apps to triage the surface visually and spot login/admin/staging panels' },
]

const ASSET_RESULT = {
  type: 'object',
  properties: {
    label: { type: 'string' },
    modality: { type: 'string' },
    status: { type: 'string', description: 'ran | thin | blocked — and why' },
    assets: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          kind: { type: 'string', description: 'host|ip|service|endpoint|param|tech|secret|cloud|url' },
          value: { type: 'string' },
          host: { type: 'string' },
          evidence: { type: 'string', description: 'path under raw/<label>/' },
          priority: { type: 'string', description: 'critical|high|medium|low' },
        },
        required: ['kind', 'value'],
      },
    },
    leads: { type: 'array', items: { type: 'string' } },
    proposed_modes: { type: 'array', items: { type: 'string' }, description: 'OPTIONAL (P2): engagement modes this agent\'s discoveries imply but the plan has not chosen (e.g. a binary dump ⇒ "binary"). Ignored if empty; the brain batches these into one AskUserQuestion.' },
    proposed_ideas: { type: 'array', items: { type: 'string' }, description: 'OPTIONAL (P2): free-form suggestions the operator may fold in (agent-proposes channel). Ignored if empty.' },
    note: { type: 'string' },
  },
  required: ['label', 'status', 'assets'],
}

// P2 unified mode gate (C2): keep MODALITIES whose `modes` tag intersects args.modes; untagged always
// run. Absent/empty args.modes => ACTIVE===MODALITIES (byte-identical to today). Array.filter preserves
// order, so the full web set selects the whole current list in the same order.
const _m = (Array.isArray(a.modes) && a.modes.length) ? a.modes : null
let ACTIVE = _m ? MODALITIES.filter(l => !Array.isArray(l.modes) || l.modes.some(m => _m.includes(m))) : MODALITIES
if (!ACTIVE.length) { log('mode gate matched 0 lenses — full list'); ACTIVE = MODALITIES }

// round-robin modalities into min(fleet, N) buckets so the fleet divides the work
const buckets = Math.min(fleet, ACTIVE.length)
const assign = Array.from({ length: buckets }, () => [])
ACTIVE.forEach((m, i) => assign[i % buckets].push(m))
if (fleet > buckets) log(`recon breadth is bounded by ${buckets} modalities; ${fleet - buckets} extra fleet slots not needed here (they matter in attack).`)

function mission(mods, label) {
  const skillPaths = mods.map(m => `${skillsDir}/recon/${m.key}/SKILL.md`)
  const modBlock = mods.map(m => `- ${m.title}: ${m.jobs}`).join('\n')
  return `${a.authorization || 'AUTHORIZED ENGAGEMENT — you are cleared to test the in-scope hosts.'}${objectiveBlock}${bountyBlock}

SCOPE (authoritative — nothing outside this list; new hosts are LEADS, not targets):
${JSON.stringify(a.scope || {}, null, 0)}
Route TARGET-FACING tools through the leash wrapper: tools/leashed.sh ${a.target_dir} <tool> ... (mandatory header + off-scope 403 + rate cap + fail-closed). Run PASSIVE OSINT tools (subfinder/gau/tlsx/trufflehog) DIRECTLY — the leash would 403 their API calls. Non-HTTP tools (nmap/naabu): validate with tools/guard.py and pin the exact in-scope host/CIDR (never a bare range or -iL).

TARGET DIR: ${a.target_dir} — read scope.yaml/state.json here; write ALL raw output under ${a.target_dir}/raw/${label}/.
CROSS-RUN LEARNING (compounding): on a re-run, query the in-run memory —
\`python tools/recall.py --target-dir ${a.target_dir} --query "<your modality + target>"\` — it ranks this
target's OWN prior records (worked techniques to replay, dead_paths/tried NOT to re-walk, prior assets) so
you focus the known-weak surface and skip recorded dead-ends. Also read ${a.context_pack ? a.context_pack + ' (prior program/target pack: known stack, weak paths, paid/dup-heavy classes)' : 'any .claude/skills/context/ pack for this program/target, if present'} and state.json.techniques[]/dead_paths[] — start informed instead of rediscovering. Empty/cold on a first run (that is fine).
ARSENAL: ${a.bin_dir || 'C:/Spider/bin'} (call via Bash). Connected MCP tools: find with ToolSearch.
METHODOLOGY: if present, read these skill files first: ${skillPaths.join(', ')}

YOUR MODALITIES (own these, go wide + deep, don't duplicate other agents):
${modBlock}

THOROUGHNESS (this is a flagship external-surface sweep — EXHAUST it; do NOT stop at one tool per modality):
- Run EVERY tool your modality's skill lists, not just the first, then merge+dedup — one tool's blind spot is
  another's hit. Subdomains = subfinder AND amass (passive+intel) AND theHarvester; crawl = katana AND
  hakrawler AND gospider; JS = jsluice AND linkfinder AND secretfinder AND trufflehog; cloud = cloud_enum
  (discovery) THEN s3scanner+bucketloot (ACL); screenshots = gowitness/httpx. If a tool is genuinely missing
  on this box, say so in note and use the fallback — never silently skip it.
- Be ACTIVELY thorough WITHIN the leash: permutation-brute the subdomain space (alterx→dnsx), ASN-pivot
  (asnmap) to the org's whole IP footprint, crawl to depth 3+, mine wayback/CDX exhaustively. The leash
  rate-caps every request, so thoroughness never means hammering.
- Chase every artifact to ground: a recovered source map, an exposed bucket, a leaked internal host/email,
  an admin/staging panel is a LEAD you hand forward WITH its evidence file — never drop a signal as
  "probably nothing". Coverage over speed.
- A modality that returns "thin" MUST state WHY (blocked / no-data / tool-missing), never under-deliver silently.

Return the asset schema. Every asset must trace to a file under ${a.target_dir}/raw/${label}/. A claim with no evidence file is a lead, not an asset.`
}

phase('Recon')
const results = await parallel(assign.map((mods, i) => () => {
  const label = mods.length === 1 ? mods[0].key : `recon-${i + 1}`
  return agent(mission(mods, label), {
    label,
    phase: 'Recon',
    agentType: 'recon-operator',
    schema: ASSET_RESULT,
    ...modelFor(a.model_tier),
  })
}))

const ok = results.filter(Boolean)
const assets = ok.reduce((n, r) => n + (r.assets?.length || 0), 0)
const leads = ok.flatMap(r => r.leads || [])
const proposed_modes = [...new Set(ok.flatMap(r => r.proposed_modes || []))]   // P2: agent-proposed modes (additive; empty on a plain run)
const proposed_ideas = ok.flatMap(r => r.proposed_ideas || [])                 // P2: agent-proposed ideas (additive)
log(`recon-1 done: ${ok.length}/${assign.length} agents, ${assets} assets, ${leads.length} leads`)

return {
  phase: 'recon-1',
  target: a.target,
  agents: assign.length,
  completed: ok.length,
  assets_total: assets,
  per_agent: results.map((r, i) => ({
    label: assign[i].map(m => m.key).join('+'),
    status: r ? r.status : 'DIED',
    assets: r ? (r.assets?.length || 0) : 0,
  })),
  leads,
  proposed_modes,
  proposed_ideas,
}
