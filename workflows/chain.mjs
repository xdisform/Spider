export const meta = {
  name: 'spider-chain',
  description: 'Seeded/variant exploitation engine: agents receive ALL findings, a planner builds seeded exploitation targets (chains + CVE/finding seeds), heterogeneous independent trajectories actually exploit, and a deterministic PoC oracle validates (no oracle, no finding)',
  phases: [{ title: 'Plan' }, { title: 'Exploit' }, { title: 'Validate' }, { title: 'Reflect' }],
}

const a = args || {}
const modelFor = t => (t === 'fast' ? { model: 'claude-haiku-4-5' } : { model: 'claude-sonnet-4-6' })
const skillsDir = a.skills_dir || 'C:/Spider/.claude/skills'
const trajN = [1, 2, 3, 4, 5].includes(a.trajectories) ? a.trajectories : 3
const SEV = ['info', 'low', 'medium', 'high', 'critical']
const findings = a.findings || { confirmed: [], candidates: [], leads: [] }

// --- class -> shipped attack-skill resolver (see attack.mjs for rationale) ---
// Free-form seeded-target classes rarely equal a shipped skill slug verbatim;
// map them by keyword so the class methodology pack actually gets injected.
// SYNCED from workflows/attack.mjs (tools/smoke-resolver.sh enforces they stay identical). Do not edit here alone.
const ATTACK_SKILLS = ['adcs', 'ad-recon', 'artifact-analysis', 'auth-bypass', 'backup-pivot', 'cache-poisoning', 'cors', 'cred-access', 'crypto', 'deser', 'escalation-ladder', 'forensics', 'graphql', 'idor', 'info-disclosure', 'interactive-exploit', 'internal-recon', 'jwt', 'kerberos', 'keycloak-realm', 'lateral', 'loot', 'objective-capture', 'ognl', 'open-redirect', 'otp-logic', 'privesc', 'prototype-pollution', 'pwn', 'rce', 'relay', 'request-smuggling', 'rev', 'saml', 'sqli', 'ssrf', 'ssti', 'stego', 'takeover', 'upload', 'waf-body-bypass', 'xss', 'xxe']
const CLASS_ALIASES = [
  // non-HTTP / credential control-test (F3) — most-specific, placed ABOVE the web fallbacks so a
  // service class (ssh/ftp/...) never mis-routes into auth-bypass
  ['ssh', 'cred-access'], ['ftp', 'cred-access'], ['smb', 'cred-access'], ['rdp', 'cred-access'],
  ['mssql', 'cred-access'], ['mysql', 'cred-access'], ['redis', 'cred-access'], ['vnc', 'cred-access'],
  ['telnet', 'cred-access'], ['default-cred', 'cred-access'], ['weak-cred', 'cred-access'],
  ['cred-spray', 'cred-access'], ['password-spray', 'cred-access'],
  // 'anonymous' tightened to service forms (crit-roadmap #5): a bare 'anonymous' substring stole web
  // classes like 'jira-anonymous-info-disclosure' / 'user-enum-anonymous-jql'. FTP/SMB anon still route
  // via their own 'ftp'/'smb' keywords above, plus these explicit anon-login forms.
  ['anonymous-ftp', 'cred-access'], ['anonymous-smb', 'cred-access'], ['anonymous-login', 'cred-access'], ['anon-bind', 'cred-access'],
  // --- fix2 non-web / post-foothold / CTF / interactive / objective classes (C3 order: most-specific,
  // ABOVE the existing web specifics + fallbacks). Each keyword below is CTF/host/socket-exclusive and
  // (audited) not a substring of an existing web class that should route elsewhere. ---
  // OTP/2FA logic (P6) — a LEGITIMATE second foothold door; above the auth-bypass fallbacks so otp-* never mis-routes into 403-busting
  ['otp-logic', 'otp-logic'], ['otp', 'otp-logic'], ['2fa', 'otp-logic'], ['mfa', 'otp-logic'],
  ['two-factor', 'otp-logic'], ['totp', 'otp-logic'], ['hotp', 'otp-logic'], ['one-time', 'otp-logic'],
  // post-foothold / inside-the-box (P4) — host/OS classes resolve above the web fallbacks
  ['internal-recon', 'internal-recon'], ['host-recon', 'internal-recon'], ['post-foothold', 'internal-recon'],
  ['privesc', 'privesc'], ['priv-esc', 'privesc'], ['privilege-esc', 'privesc'], ['elevation', 'privesc'],
  ['gtfobins', 'privesc'], ['lolbas', 'privesc'], ['suid', 'privesc'], ['setuid', 'privesc'],
  ['sudo', 'privesc'], ['capability-abuse', 'privesc'], ['kernel-exploit', 'privesc'],
  ['loot', 'loot'], ['collection', 'loot'], ['secret-harvest', 'loot'], ['local-exfil', 'loot'],
  ['lateral', 'lateral'], ['pivot', 'lateral'], ['lateral-move', 'lateral'],
  // iteration 2 — escalation ladder (post-foothold planner) + credential reuse. escalation-ladder routes
  // post-exploitation/token/cloud/identity escalation (it delegates to privesc/lateral/loot/cred-access);
  // cred-reuse routes to the cred-access control-test pack. Keywords are escalation-exclusive (audited not
  // substrings of an earlier class) and placed above the web fallbacks.
  ['escalation-ladder', 'escalation-ladder'], ['post-exploitation', 'escalation-ladder'], ['token-escalation', 'escalation-ladder'], ['cloud-escalation', 'escalation-ladder'], ['identity-reuse', 'escalation-ladder'],
  ['cred-reuse', 'cred-access'], ['credential-reuse', 'cred-access'], ['password-reuse', 'cred-access'], ['cred-stuffing', 'cred-access'],
  // CTF non-web solve classes (P3) — CTF-exclusive keywords (bare 'rev'/'crypto'/'aes' deliberately avoided)
  ['pwn-', 'pwn'], ['pwn', 'pwn'], ['binexp', 'pwn'], ['ret2', 'pwn'], ['rop-chain', 'pwn'], ['heap-pwn', 'pwn'], ['fmt-string', 'pwn'],
  ['rev-', 'rev'], ['ctf-rev', 'rev'], ['reversing', 'rev'], ['crackme', 'rev'], ['decompile', 'rev'], ['angr-solve', 'rev'], ['keygen', 'rev'],
  ['crypto-', 'crypto'], ['ctf-crypto', 'crypto'], ['rsa-ctf', 'crypto'], ['classical-cipher', 'crypto'], ['xor-key', 'crypto'], ['lcg-prng', 'crypto'],
  ['forensics-', 'forensics'], ['forensics', 'forensics'], ['pcap', 'forensics'], ['memdump', 'forensics'], ['volatility', 'forensics'], ['disk-carve', 'forensics'],
  ['stego-', 'stego'], ['stego', 'stego'], ['lsb-stego', 'stego'], ['exif-hidden', 'stego'],
  // interactive-protocol / held-socket (P5) — bare 'pwn' DROPPED (remote-pwn routes to P3 pwn, which uses leash-sock at the tool level)
  ['interactive', 'interactive-exploit'], ['stateful', 'interactive-exploit'], ['nc-service', 'interactive-exploit'], ['tcp-protocol', 'interactive-exploit'],
  ['line-protocol', 'interactive-exploit'], ['binary-protocol', 'interactive-exploit'], ['socket', 'interactive-exploit'],
  ['websocket', 'interactive-exploit'], ['ws-logic', 'interactive-exploit'], ['repl', 'interactive-exploit'],
  ['format-string', 'interactive-exploit'], ['protocol-state', 'interactive-exploit'],
  // objective / flag capture (P1) — terminal last-mile producer
  ['objective-capture', 'objective-capture'], ['flag', 'objective-capture'], ['exfil-flag', 'objective-capture'], ['capture-flag', 'objective-capture'],
  // local artifact analysis (P2) — file/binary modes; stego/steg/exif stay with P3. NOTE: C3(b) listed a
  // bare 'metadata' keyword, but placing it above the web specifics (C3 order) steals ssrf-cloud-metadata /
  // saml-metadata / oauth-metadata from their web slugs (verified). The backward-compat GUARANTEE wins
  // (plan §5.4: "same slug for every existing web class"), so the generic keyword is qualified to
  // 'artifact-metadata'/'file-metadata' (non-colliding); the exact slug 'artifact-analysis' still resolves
  // via the ATTACK_SKILLS fast-path, and 'artifact'/'file-analysis' are collision-free.
  ['artifact', 'artifact-analysis'], ['file-analysis', 'artifact-analysis'], ['artifact-metadata', 'artifact-analysis'], ['file-metadata', 'artifact-analysis'],
  // --- crit-roadmap #5: high-severity server-side families that recon-2 emits but had NO skill pack
  // (deser/ognl/rce/info-disclosure) + routers for other unmapped recon-2 classes. Placed ABOVE the web
  // specifics; keywords are crit-exclusive and (audited) not substrings of an existing class that must
  // route elsewhere. NOTE: 'rce' is NOT a substring alias (it is inside 'source', and even 'rce-' hits
  // 'source-map') — the exact class 'rce' resolves via the ATTACK_SKILLS fast-path; free-form RCE routes via
  // command-inj / os-command / log4shell / jndi / code-exec keywords instead.
  ['deseri', 'deser'], ['serializ', 'deser'], ['unserialize', 'deser'], ['hessian', 'deser'], ['xmldecoder', 'deser'],
  ['jackson', 'deser'], ['fastjson', 'deser'], ['kryo', 'deser'], ['viewstate', 'deser'], ['pickle', 'deser'],
  ['ysoserial', 'deser'], ['gadget-chain', 'deser'], ['objectinputstream', 'deser'], ['binaryformatter', 'deser'],
  ['ognl', 'ognl'], ['spel', 'ognl'], ['struts', 'ognl'], ['mvel', 'ognl'],
  ['log4shell', 'rce'], ['log4j', 'rce'], ['jndi', 'rce'], ['command-inj', 'rce'], ['command-exec', 'rce'],
  ['command-dispatcher', 'rce'], ['os-command', 'rce'], ['cmd-inj', 'rce'], ['remote-code', 'rce'],
  ['code-execution', 'rce'], ['code-exec', 'rce'], ['arg-injection', 'rce'],
  ['actuator', 'info-disclosure'], ['heapdump', 'info-disclosure'], ['info-disc', 'info-disclosure'],
  ['stack-trace', 'info-disclosure'], ['stacktrace', 'info-disclosure'], ['error-leak', 'info-disclosure'],
  ['source-map', 'info-disclosure'], ['sourcemap', 'info-disclosure'], ['test-instance', 'info-disclosure'],
  ['env-exposure', 'info-disclosure'], ['debug-endpoint', 'info-disclosure'], ['verbose-error', 'info-disclosure'],
  // routers for other unmapped recon-2 classes -> nearest existing pack (not new packs)
  ['on-behalf', 'idor'], ['cross-service-user-content', 'idor'], ['cross-tenant-object', 'idor'],
  ['user-enum', 'auth-bypass'], ['anonymous-jql', 'auth-bypass'], ['auth-dto', 'auth-bypass'],
  ['multipart-boundary', 'waf-body-bypass'], ['boundary-abuse', 'waf-body-bypass'],
  ['upstream-routing', 'request-smuggling'], ['envoy', 'request-smuggling'],
  ['verify-token', 'otp-logic'],
  ['keycloak', 'keycloak-realm'],
  ['saml', 'saml'],
  ['ssrf', 'ssrf'],
  ['cors', 'cors'],
  ['jwt', 'jwt'], ['alg-confusion', 'jwt'], ['flask-session', 'jwt'], ['session-forgery', 'jwt'], ['token-forgery', 'jwt'],
  ['smuggl', 'request-smuggling'], ['desync', 'request-smuggling'],
  // web cache poisoning / deception — recon anomaly-hunt emits class:cache-poisoning and the attack/cache-poisoning
  // pack weaponizes it with wcvs. The exact slug resolves via the ATTACK_SKILLS fast-path above; these alias the
  // free-form variants. Keywords are cache-exclusive (no earlier class contains them), so first-match is safe.
  ['cache-poison', 'cache-poisoning'], ['web-cache', 'cache-poisoning'], ['cache-deception', 'cache-poisoning'], ['unkeyed-cache', 'cache-poisoning'],
  // client/server prototype pollution (deep-source-trace + js-sink-mining emit class:prototype-pollution).
  // Exact slug resolves via the fast-path; these alias the free-form variants. 'postmessage-xss' still
  // routes to xss via the 'xss' keyword below (postMessage DOM-XSS shares the xss playbook).
  ['prototype-pollution', 'prototype-pollution'], ['proto-pollution', 'prototype-pollution'], ['prototype-poison', 'prototype-pollution'],
  ['bola', 'idor'], ['idor', 'idor'], ['mass-assignment', 'idor'],
  ['sqli', 'sqli'], ['sql-inj', 'sqli'],
  ['ssti', 'ssti'], ['template-inj', 'ssti'],
  ['xxe', 'xxe'],
  ['xss', 'xss'],
  ['upload', 'upload'],
  ['takeover', 'takeover'],
  ['graphql', 'graphql'],
  ['waf', 'waf-body-bypass'],
  ['redirect', 'open-redirect'], ['oauth', 'open-redirect'], ['oidc', 'open-redirect'], ['dcr', 'open-redirect'],
  ['access-control', 'auth-bypass'], ['authbypass', 'auth-bypass'], ['auth-bypass', 'auth-bypass'], ['authz', 'auth-bypass'], ['regist', 'auth-bypass'], ['tenant', 'auth-bypass'], ['bypass', 'auth-bypass'],
]
function resolveAttackSkill(cls) {
  const c = (cls || '').toLowerCase()
  if (!c) return null
  if (ATTACK_SKILLS.includes(c)) return c
  for (const [kw, slug] of CLASS_ALIASES) if (c.includes(kw)) return slug
  return null
}

// --- heterogeneous scaffolds (diverse trajectories beat one "perfect" loop: CAI 57.6% > 45%) ---
const SCAFFOLDS = [
  { key: 'tool-first', hint: 'Lead with the arsenal: run the right bin/ tool for this class (nuclei/sqlmap/dalfox/ffuf/commix/jwt-hack/nomore403) and reason from its real output.' },
  { key: 'manual-first', hint: 'Lead with hand-crafted requests through the leash; read raw responses closely and craft bypasses by hand. No scanner — think like the author of the bug.' },
  { key: 'cve-seeded', hint: 'Seed from the KNOWN CVE/pattern for the detected stack+version (read the target context pack if present). Hunt the un-fixed variant and chain it — like variant analysis.' },
  { key: 'chain-first', hint: 'Start from the end impact and work backwards: which confirmed/lead findings combine to reach it? Prove the links in order.' },
  { key: 'auth-depth', hint: 'Attack the auth/authz/session/tenant boundary around the target: multi-account, token/alg, redirect_uri, forced browsing.' },
]

const CANDIDATE = {
  type: 'object',
  properties: {
    proven_state: { type: 'string', enum: ['impact_proven', 'misconfig_proven', 'not_reproduced'] },
    type: { type: 'string' }, severity: { type: 'string', enum: SEV },
    title: { type: 'string' }, detail: { type: 'string' },
    evidence: { type: 'string' }, execution_evidence: { type: 'string' },
    poc_path: { type: 'string' }, repro: { type: 'string' },
    scaffold: { type: 'string' },
    hops: { type: 'array', description: '#3 per-hop validation: the ordered chain hops and which are INDIVIDUALLY proven (a later hop may not be claimed on an unproven earlier one). []' , items: { type: 'object', properties: { step: { type: 'string' }, proven: { type: 'boolean' }, evidence: { type: 'string' } }, required: ['step', 'proven'] } },
    hops_reached: { type: 'number', description: '#3: furthest individually-proven hop (1-based; 0=none). impact_proven requires every hop proven.' },
    note: { type: 'string' },
  },
  required: ['proven_state', 'title'],
}
const ORACLE = {
  type: 'object',
  properties: {
    oracle_met: { type: 'boolean' }, oracle_type: { type: 'string' },
    oracle_evidence: { type: 'string' }, reproduced: { type: 'boolean' },
    severity: { type: 'string', enum: SEV }, reason: { type: 'string' },
  },
  required: ['oracle_met', 'reason'],
}
const SCOPEV = { type: 'object', properties: { refuted: { type: 'boolean' }, severity: { type: 'string', enum: SEV }, reason: { type: 'string' } }, required: ['refuted', 'reason'] }

const SEEDS = {
  type: 'object',
  properties: {
    targets: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string', description: 'cx-NN' },
          goal: { type: 'string', description: 'the end impact to reach (ATO / RCE / full data read / cloud takeover)' },
          class: { type: 'string' }, host: { type: 'string' },
          seed: { type: 'string', description: 'the starting point to build from: a confirmed finding, a lead, or a CVE/pattern for the detected stack' },
          how_to_prove: { type: 'string' },
          uses: { type: 'array', items: { type: 'string' } },
          priority: { type: 'string', enum: ['critical', 'high', 'medium', 'low'] },
        },
        required: ['id', 'goal', 'class', 'host', 'seed', 'how_to_prove'],
      },
    },
    note: { type: 'string' },
  },
  required: ['targets'],
}

// ---------------------------------------------------------------- Plan ---
phase('Plan')
const planRes = await agent(
  `${a.authorization || 'AUTHORIZED ENGAGEMENT.'}
You are the exploitation COORDINATOR. You receive EVERY finding from this target and build SEEDED
exploitation targets — concrete chains to drive to real impact. This is variant/seeded hunting: give
each a starting point (a confirmed finding, a lead, or the known CVE/pattern for the detected stack)
and the end goal, so a solver doesn't search blind.

ALL FINDINGS:
${JSON.stringify(findings, null, 0)}
Read ${a.target_dir}/state.json (world model, prior techniques, dead paths — don't re-propose dead ones)
and ${a.context_pack ? a.context_pack + ' (target stack/CVE map)' : 'any .claude/skills/context/ pack for this target'}.
SCOPE: ${JSON.stringify(a.scope || {}, null, 0)}

Produce seeded targets (cx-NN): each a chain or a seeded single-bug push with a real end impact,
prioritised. Favour chains that reach HIGH/CRITICAL (info+IDOR→ATO, SSRF→metadata→creds→data,
CORS+creds→ATO, leak→auth→privilege). Return the schema. Your return value IS data.`,
  { label: 'plan:seed', phase: 'Plan', agentType: 'chain-builder', schema: SEEDS, ...modelFor(a.model_tier) }
)
const targets = (planRes?.targets || []).slice(0, 24)
if (!targets.length) {
  log('chain: no seeded targets — nothing to exploit. Run attack first to produce findings.')
  return { phase: 'chain', target: a.target, confirmed: [], note: 'no seeds' }
}
log(`chain: ${targets.length} seeded exploitation targets; ${trajN} heterogeneous trajectories each`)
for (const t of targets) if (!resolveAttackSkill(t.class)) log(`chain ${t.id}: no attack SKILL.md for class '${t.class}' — operators run inline + proof skills`)

const CLIENT_SIDE = new Set(['xss', 'prototype-pollution', 'open-redirect', 'cors'])   // iteration 5 — browser-exec oracle
function exploitMission(t, s, reflectHint) {
  const slug = resolveAttackSkill(t.class)
  const classSkill = slug ? `${skillsDir}/attack/${slug}/SKILL.md` : null
  const WAF_PRONE = new Set(['sqli', 'xss', 'ssti', 'rce', 'ssrf', 'xxe', 'ognl', 'waf-body-bypass'])   // backlog #2 — evolutionary-bypass proof
  const proofs = [`${skillsDir}/proof/poc-standard/SKILL.md`, `${skillsDir}/proof/oracles/SKILL.md`, `${skillsDir}/proof/oob-interactsh/SKILL.md`,
    ...(CLIENT_SIDE.has(slug) ? [`${skillsDir}/proof/dynamic-validate/SKILL.md`] : []),
    ...(WAF_PRONE.has(slug) ? [`${skillsDir}/proof/waf-mutation/SKILL.md`] : [])]
  // Reflect loop (backlog #1) — a prior attempt on this seeded target did NOT confirm; the Advisor derived
  // WHY. Start from that, don't repeat the dead path. Additive: no reflectHint => '' => byte-identical.
  const reflectBlock = reflectHint ? `

REFLECTION — THIS IS A SHARPENED RETRY (the first attempt on this target did NOT confirm). An adversarial
Advisor reviewed your prior attempt artifacts and concluded:
${reflectHint}
Do NOT repeat the path that already failed. Act on the failure reason: a WAF/filter block => run the
evolutionary bypass loop (bin/wafrift, read proof/waf-mutation), NOT one more hand-guessed payload; a
missing precondition => acquire it first; a wrong param/sink => use the corrected one; a response that
LIES => treat as not-vulnerable. A sharper attempt, not a louder one.` : ''
  const escalationHint = slug === 'escalation-ladder' ? ' This is a POST-FOOTHOLD rung: reuse the held credential on other in-scope hosts (cred-access control-test, policy-gated) and climb to the highest eligible impact; read the escalation-ladder pack for the gates.' : ''
  const methodology = (classSkill ? [classSkill, ...proofs] : proofs).join(', ')
  return `${a.authorization || 'AUTHORIZED ENGAGEMENT — you are cleared to test the in-scope hosts.'}
You are an exploitation operator on trajectory "${s.key}". ACTUALLY EXPLOIT — produce a working PoC
and real impact, not a hypothesis. Working PoCs, not false positives.

SEEDED TARGET ${t.id}: goal=${t.goal}
  class=${t.class} host=${t.host}
  seed (start here): ${t.seed}
  how to prove: ${t.how_to_prove}
  combines: ${JSON.stringify(t.uses || [])}${escalationHint}${reflectBlock}

CROSS-RUN LEARNING (compounding): BEFORE you probe, run the in-run memory recall —
\`python tools/recall.py --target-dir ${a.target_dir} --class ${t.class} --host ${t.host}\` — it ranks this
target's OWN prior records (worked techniques to replay, dead_paths NOT to retry, related findings, raw/
notes from this run) so you don't repeat a sibling's failed payload or a recorded dead-end.

YOUR TRAJECTORY: ${s.hint}
Iterate — probe → read → refine → escalate; don't one-shot. Stop early if clearly flailing (real
exploits are found fast; long grinding = dead path — say so).
PER-HOP VALIDATION (a seeded target IS a chain): decompose the goal into ordered HOPS and prove each hop's
own mini-oracle with its own evidence BEFORE the next — a later hop may NOT be claimed on an unproven
earlier one (this stops a hallucinated end-to-end chain). Report hops[] {step,proven,evidence} +
hops_reached (furthest PROVEN hop); impact_proven needs EVERY hop proven, a real partial chain is honest
distance-to-impact, not a fabricated win.

SCOPE: ${JSON.stringify(a.scope || {}, null, 0)}
Honour safe-PoC limits. Target-facing tools via tools/leashed.sh ${a.target_dir} bin/<tool>; non-HTTP via tools/leash-tcp.sh; blind bugs via bin/interactsh-client with a UNIQUE token.
TARGET DIR: ${a.target_dir} — write all evidence + a runnable PoC under raw/chain-${t.id}-${s.key}/.
ARSENAL: ${a.bin_dir || 'C:/Spider/bin'} (Bash) + connected MCP via ToolSearch. For a client-side class
(xss/prototype-pollution/open-redirect/cors) PROVE real execution in the leashed Playwright MCP (load
proof/dynamic-validate) — the oracle is the execution signal, not a reflected string. METHODOLOGY: read ${methodology}.

Return the candidate. proven_state=impact_proven needs execution_evidence that MEETS THE CLASS ORACLE
(see proof/oracles) — an OOB callback / DB banner / command output / cross-account record / etc.
misconfig_proven needs a runnable PoC artifact. Else not_reproduced (a dead path). Be honest.`
}

function validateMission(c, t) {
  const dyn = CLIENT_SIDE.has(resolveAttackSkill(t.class)) ? ' This is a client-side class: re-execute the PoC in the LEASHED Playwright MCP (read proof/dynamic-validate) and capture the execution signal (the sentinel fired / final URL / framed render) — a reflected string or screenshot is NOT the oracle.' : ''
  return `Validate finding for seeded target ${t.id} (class ${t.class}). Read proof/oracles, then
RE-EXECUTE the PoC yourself and produce the class oracle evidence. Do not trust narration.${dyn}
CANDIDATE: ${JSON.stringify({ proven_state: c.proven_state, type: c.type, severity: c.severity, title: c.title, evidence: c.evidence, execution_evidence: c.execution_evidence, poc_path: c.poc_path, repro: c.repro })}
TARGET DIR: ${a.target_dir} (evidence under raw/). SCOPE: ${JSON.stringify(a.scope || {}, null, 0)}. Arsenal: ${a.bin_dir || 'C:/Spider/bin'}, through the leash, in scope.
oracle_met=true ONLY with objective, re-derivable oracle evidence. Save your re-run under raw/validate-${t.id}/.`
}

// ---------------------------------------------- Exploit -> Validate ---
phase('Exploit')
const rank = c => (c.proven_state === 'impact_proven' ? 2 : c.proven_state === 'misconfig_proven' ? 1 : 0)
const results = await pipeline(
  targets,
  (t) => parallel(SCAFFOLDS.slice(0, trajN).map(s => () =>
    agent(exploitMission(t, s), { label: `exploit:${t.id}:${s.key}`, phase: 'Exploit', agentType: 'attack-operator', schema: CANDIDATE, ...modelFor(a.model_tier) })
      .then(c => c ? { ...c, scaffold: s.key } : null)
  )).then(cands => {
    const live = cands.filter(Boolean)
    const proven = live.filter(c => c.proven_state && c.proven_state !== 'not_reproduced' && c.poc_path)
    const best = proven.sort((x, y) => rank(y) - rank(x))[0] || null
    return { target: t, candidates: live, best }
  }),
  (ex, t) => {
    if (!ex || !ex.best) return { target: t, status: 'dead', best: null, candidates: ex?.candidates || [] }
    return parallel([
      () => agent(validateMission(ex.best, t), { label: `validate:${t.id}`, phase: 'Validate', agentType: 'validator', schema: ORACLE, ...modelFor(a.model_tier) }),
      () => agent(`Scope/policy/severity check for ${t.id}. Is the affected host in scope.yaml and within policy? Is severity justified by the proven oracle, not inflated? CANDIDATE: ${JSON.stringify({ type: ex.best.type, severity: ex.best.severity, title: ex.best.title })}. SCOPE: ${JSON.stringify(a.scope || {}, null, 0)}. Default refuted=true if out-of-scope/over-policy.`,
        { label: `scope:${t.id}`, phase: 'Validate', agentType: 'verifier-skeptic', schema: SCOPEV, ...modelFor(a.model_tier) }),
    ]).then(([oracle, scope]) => {
      const confirmed = !!(oracle && oracle.oracle_met) && !(scope && scope.refuted)
      let severity = (oracle && oracle.severity) || ex.best.severity
      if (ex.best.proven_state === 'misconfig_proven' && SEV.indexOf(severity) < SEV.indexOf('low')) severity = 'low'
      return { target: t, best: ex.best, oracle, scope, severity, status: confirmed ? 'confirmed' : 'unconfirmed' }
    })
  }
)

// ===== REFLECT stage (backlog #1 — the Advisor loop, ported from attack.mjs to /chain + /again) =====
// A dead/unconfirmed seeded target is NOT dropped: the Advisor derives the failure reason from the attempt
// artifacts and either sharpens ONE retry (through the same oracle+scope gate) or calls it exhausted — the
// Execute->Reflect->re-Execute loop (~2x proven in the literature). Bounded by a.reflect_rounds (default 1;
// 0 => disabled => byte-identical) + a.reflect_max; can only UPGRADE a dead/unconfirmed target to confirmed.
const REFLECT = {
  type: 'object',
  properties: {
    verdict: { type: 'string', enum: ['retry', 'exhausted'] },
    failure_reason: { type: 'string' },
    sharpened_angle: { type: 'string' },
    how_to_prove: { type: 'string' },
  },
  required: ['verdict', 'failure_reason'],
}
function reflectMission(t, best, status, oracle, scope) {
  return `${a.authorization || 'AUTHORIZED ENGAGEMENT.'}
You are the ADVISOR — a senior exploitation strategist doing reflective verification. A seeded exploitation
target did NOT confirm (${status}${status === 'unconfirmed' ? `: oracle/scope said "${(oracle && oracle.reason) || (scope && scope.reason) || 'not met'}"` : ': no working PoC was produced'}). Decide the single next move — a sharpened retry or an honest exhausted. You do NOT attack.

SEEDED TARGET ${t.id}: goal=${t.goal} class=${t.class} host=${t.host}
  seed: ${t.seed}  how it was meant to be proven: ${t.how_to_prove}
${best ? `OPERATOR'S BEST CANDIDATE: ${JSON.stringify({ proven_state: best.proven_state, title: best.title, detail: (best.detail || '').slice(0, 500), note: best.note })}` : 'No candidate reached a provable state.'}
READ the real attempt artifacts under ${a.target_dir}/raw/chain-${t.id}-*/ (requests/responses, not a summary)
and run \`python tools/recall.py --target-dir ${a.target_dir} --class ${t.class} --host ${t.host}\`.
DERIVE THE FAILURE REASON (Evidence->Hypothesis->Verification, no blind guessing): WAF/filter block (=> wafrift
evolutionary bypass, proof/waf-mutation), wrong param/sink, missing precondition/auth, wrong encoding, a
response that LIES (honeypot/fabricated => not-vulnerable), or genuinely not present. Then verdict:'retry'
with ONE concrete sharpened_angle + how_to_prove, or verdict:'exhausted'. Never propose defeating a
safeguard. Return the schema; your return value IS data.`
}
async function validateBest(t, best) {
  const [oracle, scope] = await parallel([
    () => agent(validateMission(best, t), { label: `revalidate:${t.id}`, phase: 'Reflect', agentType: 'validator', schema: ORACLE, ...modelFor(a.model_tier) }),
    () => agent(`Scope/policy/severity check for ${t.id}. Is the affected host in scope.yaml and within policy? Is severity justified by the proven oracle, not inflated? CANDIDATE: ${JSON.stringify({ type: best.type, severity: best.severity, title: best.title })}. SCOPE: ${JSON.stringify(a.scope || {}, null, 0)}. Default refuted=true if out-of-scope/over-policy.`,
      { label: `rescope:${t.id}`, phase: 'Reflect', agentType: 'verifier-skeptic', schema: SCOPEV, ...modelFor(a.model_tier) }),
  ])
  const ok = !!(oracle && oracle.oracle_met) && !(scope && scope.refuted)
  let severity = (oracle && oracle.severity) || best.severity
  if (best.proven_state === 'misconfig_proven' && SEV.indexOf(severity) < SEV.indexOf('low')) severity = 'low'
  return { target: t, best, oracle, scope, severity, status: ok ? 'confirmed' : 'unconfirmed' }
}
let rows = results.filter(Boolean)
const reflectRounds = Number.isInteger(a.reflect_rounds) ? a.reflect_rounds : 1
const reflectMax = Number.isInteger(a.reflect_max) ? a.reflect_max : 16
let cReflected = 0, cReflectProven = 0
// #4 — ITERATIVE reflect rounds (mirror of attack.mjs): a retry that still fails gets a fresh Advisor read
// next round (on its new artifacts), up to reflect_rounds; 'exhausted' retires a target. Default 1 => one pass.
if (reflectRounds > 0) {
  for (let rRound = 1; rRound <= reflectRounds; rRound++) {
    const phaseName = reflectRounds > 1 ? `Reflect round ${rRound}` : 'Reflect'
    const toReflect = rows
      .filter(r => (r.status === 'dead' || r.status === 'unconfirmed') && !r.__reflectExhausted)
      .sort((x, y) => (SEV.indexOf((y.best && y.best.severity) || 'info') - SEV.indexOf((x.best && x.best.severity) || 'info')))
      .slice(0, reflectMax)
    if (!toReflect.length) break
    phase(phaseName)
    log(`chain reflect${reflectRounds > 1 ? ` round ${rRound}/${reflectRounds}` : ''}: ${toReflect.length} dead/unconfirmed targets get an Advisor pass (failure reason -> sharpened retry or exhausted)`)
    const rr = await pipeline(
      toReflect,
      (r) => agent(reflectMission(r.target, r.best, r.status, r.oracle, r.scope), { label: `reflect:${r.target.id}:r${rRound}`, phase: phaseName, agentType: 'advisor', schema: REFLECT, ...modelFor(a.model_tier) }),
      (adv, r) => {
        if (!adv || adv.verdict !== 'retry') { r.__reflectExhausted = true; return Promise.resolve({ row: r, retryRow: null }) }
        const hint = `failure reason: ${adv.failure_reason}${adv.sharpened_angle ? `\nsharper angle: ${adv.sharpened_angle}` : ''}${adv.how_to_prove ? `\nsharpened how-to-prove: ${adv.how_to_prove}` : ''}`
        return agent(exploitMission(r.target, SCAFFOLDS[0], hint), { label: `reflect-retry:${r.target.id}:r${rRound}`, phase: phaseName, agentType: 'attack-operator', schema: CANDIDATE, ...modelFor(a.model_tier) })
          .then(c => (c && c.proven_state && c.proven_state !== 'not_reproduced' && c.poc_path) ? validateBest(r.target, { ...c, scaffold: 'reflect' }) : null)
          .then(retryRow => ({ row: r, retryRow }))
      }
    )
    for (const x of (rr || []).filter(Boolean)) {
      cReflected++
      if (x.retryRow) {
        const idx = rows.indexOf(x.row); if (idx >= 0) rows[idx] = x.retryRow
        if (x.retryRow.status === 'confirmed') { cReflectProven++; log(`chain reflect: ${x.row.target.id} UPGRADED ${x.row.status}->confirmed after Advisor sharpening (round ${rRound})`) }
      }
    }
  }
  log(`chain reflect: ${cReflected} Advisor pass(es), ${cReflectProven} upgraded to confirmed (reflect_rounds=${reflectRounds}, cap=${reflectMax}/round)`)
}

const confirmed = rows.filter(r => r.status === 'confirmed').map(r => ({
  ...r.best, severity: r.severity, verified: true, refuted: false,
  oracle_type: r.oracle?.oracle_type, oracle_evidence: r.oracle?.oracle_evidence, chain_id: r.target.id, goal: r.target.goal,
}))
const unconfirmed = rows.filter(r => r.status === 'unconfirmed').map(r => ({ id: r.target.id, title: r.best?.title, why_unconfirmed: r.oracle?.reason || r.scope?.reason }))
const dead = rows.filter(r => r.status === 'dead').map(r => ({ id: r.target.id, goal: r.target.goal, class: r.target.class }))
log(`chain done: ${confirmed.length} confirmed (oracle-validated), ${unconfirmed.length} unconfirmed, ${dead.length} dead paths`)

return {
  phase: 'chain',
  target: a.target,
  seeded_targets: targets.length,
  confirmed,
  unconfirmed,
  dead_paths: dead,                 // brain merges into state.json so future runs don't re-tread
  reflect: { reflected: cReflected, reflect_proven: cReflectProven },   // Reflect stage: Advisor passes + dead/unconfirmed upgraded to confirmed
  per_target: rows.map(r => ({ id: r.target.id, goal: r.target.goal, status: r.status, oracle: r.oracle?.oracle_met })),
}
