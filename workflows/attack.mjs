export const meta = {
  name: 'spider-attack',
  description: 'Exploit each hypothesis to a reproducible PoC, then adversarially verify every claim from three distinct lenses — only proven impact survives. Repeatable.',
  phases: [{ title: 'Exploit' }, { title: 'Verify' }, { title: 'Reflect' }, { title: 'Chain' }],
}

const a = args || {}
const skillsDir = a.skills_dir || 'C:/Spider/.claude/skills'
const modelFor = t => (t === 'fast' ? { model: 'claude-sonnet-4-6' } : { model: 'claude-opus-4-6' })
const hypotheses = Array.isArray(a.hypotheses) ? a.hypotheses : []

// crit-roadmap #4 — heterogeneous exploit trajectories (diverse scaffolds beat one "perfect" loop:
// chain.mjs already ships this, citing CAI 57.6% > 45%). Each hypothesis is attacked from up to `trajN`
// angles in parallel; the BEST candidate (impact_proven > misconfig_proven > blocked > not_reproduced)
// feeds the UNCHANGED oracle/skeptic verify gate. The FIRST trajectory is the BASELINE (null scaffold =
// today's exact mission), so a.trajectories:1 is byte-identical to the pre-#4 single-shot wave. Default 2.
const SCAFFOLDS = [
  { key: 'tool-first', hint: 'Lead with the arsenal: run the right bin/ tool for this class (nuclei/sqlmap/dalfox/ffuf/commix/jwt-hack/nomore403) and reason from its real output.' },
  { key: 'manual-first', hint: 'Lead with hand-crafted requests through the leash; read raw responses closely and craft bypasses by hand. No scanner — think like the author of the bug.' },
  { key: 'cve-seeded', hint: 'Seed from the KNOWN CVE/pattern for the detected stack+version (read the target/program context pack if present). Hunt the un-fixed variant and chain it — like variant analysis.' },
  { key: 'chain-first', hint: 'Start from the end impact and work backwards: which acquired capabilities / confirmed findings combine to reach it? Prove the links in order.' },
  { key: 'auth-depth', hint: 'Attack the auth/authz/session/tenant boundary around the target: multi-account, token/alg, redirect_uri, forced browsing.' },
]
// baseline first (null = today's mission verbatim), then the diverse angles. trajN clamped to [1, 6].
const SC = [null, ...SCAFFOLDS]
const trajN = Math.max(1, Math.min(SC.length, Number.isInteger(a.trajectories) ? a.trajectories : 2))

// F4 dependency helpers — a hypothesis's preconditions (requires) and effects (provides), as capability tokens.
const reqs = h => Array.isArray(h.requires) ? h.requires : []
const prov = h => Array.isArray(h.provides) ? h.provides : []

// #3 per-hypothesis sub-tree — a hypothesis is MULTI-STEP when its own how_to_prove/why describes a chain
// (SSRF->metadata->creds->data, leak->auth->privilege). For those the operator decomposes into ordered hops
// and proves each before the next (per-hop validation), which stops a hallucinated end-to-end claim. The
// cross-hypothesis ordering is the requires/provides graph; this is the ordering WITHIN one hypothesis.
const CHAIN_MARKERS = /→|->|\bthen\b|\bchain\b|\bpivot\b|\bleads?\s+to\b|\bfollowed by\b|multi-?step/i
const isMultiStep = h => !!(h && (h.multi_step === true || CHAIN_MARKERS.test(`${h.how_to_prove || ''} ${h.why || ''}`)))

// gap B — derive capability tokens from what was ACTUALLY proven (gated on an oracle-CONFIRMED finding),
// in ADDITION to a hypothesis's static `provides`. A proven web RCE/SSTI/deser/cmd-inj mints shell:/foothold:
// so the post-foothold graph (internal-recon -> privesc -> loot -> lateral) actually unlocks — the web->infra
// bridge that static provides miss. ATO/auth-bypass/otp/session-forgery mints session:/foothold:; a proven
// privesc mints admin:. Additive + host-scoped: a minted token can only make MORE dependents `ready` (each
// still faces its OWN exploit + oracle gate), never gate or weaken anything. No host / no match => [] => the
// run is byte-identical to pre-B. The derivation is a lower bound; it never asserts impact the oracle didn't.
function derivedCaps(h, candidate, oracle) {
  const host = h && h.host ? String(h.host) : ''
  if (!host) return []
  const hay = `${candidate?.type || ''} ${candidate?.title || ''} ${oracle?.oracle_type || ''} ${(candidate?.detail || '').slice(0, 240)}`.toLowerCase()
  const out = []
  // OS command execution on the host => a shell foothold
  if (/\brce\b|remote[- ]?code|command[- ]?(exec|inj)|os[- ]?command|cmd[- ]?inj|web[- ]?shell|reverse shell|ssti[^.]*\b(rce|exec)|deseriali|ysoserial|\bognl\b|\bspel\b|log4|\bjndi\b|xp_cmdshell|stacked quer|into outfile|copy to program/.test(hay)) {
    out.push(`shell:${host}`, `foothold:${host}`)
  }
  // account/session takeover => a web session foothold
  if (/account[- ]?takeover|\bato\b|auth[- ]?bypass|authz bypass|session (forgery|fixation|hijack|takeover)|jwt[^.]*\b(forge|forged|confusion|none)|logged in as|authenticated as (another|victim)|otp|2fa|mfa bypass/.test(hay)) {
    out.push(`session:${host}`, `foothold:${host}`)
  }
  // privilege escalation on a held host => admin
  if (/priv(ilege)?[- ]?esc|elevation of privilege|uid=0|became root|\broot shell\b|domain admin|became admin|administrator access/.test(hay)) {
    out.push(`admin:${host}`)
  }
  // iteration 2 — a proven credential / secret / token leak mints a creds token so the cred-reuse +
  // identity-reuse composites (chain-builder) can fire against the rest of the in-scope estate. Additive +
  // host-scoped: a minted creds token only makes MORE dependents ready (each still oracle-gated), and the
  // actual reuse is a policy-gated cred-access control-test, never an unconditional login.
  if (/credential|creds?[- ]?(leak|disclos|exposed|found|valid)|password[- ]?(leak|disclos|found)|api[- ]?key|secret[- ]?(leak|exposed)|hardcoded[- ]?(secret|cred|key)|token[- ]?(leak|theft|captured|forged)|default[- ]?cred/.test(hay)) {
    out.push(`creds:${host}`)
  }
  return [...new Set(out)]
}

if (!hypotheses.length) {
  log('attack: no hypotheses passed — nothing to prove. Run recon-2 first.')
  return { phase: 'attack', target: a.target, confirmed: [], candidates: [], leads: [], note: 'no hypotheses' }
}

const SEV = ['info', 'low', 'medium', 'high', 'critical']
// client-side classes whose oracle is live browser execution (iteration 5) — MODULE scope so BOTH
// exploitMission (proof-skill injection) and validateMission (the validator re-runs in the browser) see it.
const CLIENT_SIDE = new Set(['xss', 'prototype-pollution', 'open-redirect', 'cors'])

// --- class -> shipped attack-skill resolver --------------------------------
// recon-2 emits granular, free-form hypothesis classes (jwt-alg-confusion,
// mass-idor, cors-reflection-with-credentials, saml-idp-broker-abuse, ...), but
// the arsenal ships 17 fixed attack skill packs. A verbatim ${class}/SKILL.md
// lookup therefore matched 0/39 real classes on the chd run, so the class
// methodology was never injected. Map the free-form class onto the right pack by
// keyword (first match wins; most specific first). null => no pack; caller logs it.
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

const CANDIDATE = {
  type: 'object',
  properties: {
    hypothesis_id: { type: 'string' },
    proven_state: { type: 'string', enum: ['impact_proven', 'misconfig_proven', 'not_reproduced', 'blocked'], description: 'impact_proven = chained to real impact (data read / RCE / ATO / OOB callback) WITH execution_evidence; misconfig_proven = the defect is reproduced with a RUNNABLE PoC artifact under raw/ (e.g. a CORS PoC HTML) even if full exfil was not chained; not_reproduced = could not reproduce (a lead); blocked = could NOT be attempted without crossing a red line (an Anthropic safeguard, or a policy-disabled control-test) — a HAND-OFF, never evidence the bug is absent. Set blocked_reason.' },
    blocked_reason: { type: 'string', enum: ['safeguard', 'missing_prereq', 'needs_session', 'policy'], description: 'ONLY when proven_state=blocked. safeguard = proving it would require defeating auth as an attack (do not evade); needs_session/missing_prereq = needs a capability not yet held; policy = a control-test the scope has not enabled' },
    type: { type: 'string' },
    severity: { type: 'string', enum: SEV },
    title: { type: 'string' },
    detail: { type: 'string' },
    evidence: { type: 'string', description: 'path under raw/ (requests/responses)' },
    execution_evidence: { type: 'string', description: 'the concrete proof: command output, leaked record, or OOB callback id. EMPTY if not proven' },
    poc_path: { type: 'string', description: 'path to a runnable PoC under raw/' },
    repro: { type: 'string', description: 'copy-paste reproduction steps' },
    note: { type: 'string' },
    used_exemplars: { type: 'array', items: { type: 'string' }, description: 'ids of retrieved exemplars that actually helped (for corpus hit-rate feedback). [] if none.' },
    scaffold: { type: 'string', description: 'crit-roadmap #4: which trajectory produced this candidate (baseline|tool-first|manual-first|cve-seeded|chain-first|auth-depth). Set by the workflow, not the agent.' },
    hops: { type: 'array', description: '#3 per-hop validation (multi-step hypotheses only): the ordered chain hops and which are INDIVIDUALLY proven. Stops a hallucinated end-to-end chain — a later hop may not be claimed on an unproven earlier one. [] for a single-step hypothesis.', items: { type: 'object', properties: { step: { type: 'string' }, proven: { type: 'boolean' }, evidence: { type: 'string', description: 'path/evidence proving THIS hop' } }, required: ['step', 'proven'] } },
    hops_reached: { type: 'number', description: '#3: the furthest INDIVIDUALLY-proven hop index (1-based; 0 = none). Honest distance-to-impact for a partial chain. impact_proven requires every hop proven.' },
    sibling_hypotheses: {
      type: 'array',
      description: 'gap D (attack->recon feedback): adjacent EXPLOITABLE surfaces you noticed while proving THIS hypothesis but did not chase (a second IDOR, an injectable sort/filter field, an open redirect in the same flow, a mis-authz endpoint). The planner re-attacks them as composites next round — organic finding growth. [] if none. NEVER a place to dump unproven speculation; only surfaces you actually saw behave suspiciously.',
      items: {
        type: 'object',
        properties: {
          class: { type: 'string', description: 'the vuln class (maps to an attack skill pack: sqli/idor/ssrf/open-redirect/...)' },
          host: { type: 'string' },
          why: { type: 'string', description: 'the concrete signal you saw (not a guess)' },
          how_to_prove: { type: 'string' },
          requires: { type: 'array', items: { type: 'string' }, description: 'capability tokens needed first (usually [])' },
          provides: { type: 'array', items: { type: 'string' } },
        },
        required: ['class', 'host', 'why'],
      },
    },
  },
  required: ['hypothesis_id', 'proven_state', 'title'],
}

const VERDICT = {
  type: 'object',
  properties: {
    refuted: { type: 'boolean' },
    reproduced: { type: 'boolean' },
    proven_impact: { type: 'string', description: 'what you actually achieved; empty if none' },
    severity: { type: 'string', enum: SEV, description: 'justified by proof only' },
    reason: { type: 'string' },
  },
  required: ['refuted', 'reason'],
}

function exploitMission(h, acquired, scaffold, reflectHint) {
  const slug = resolveAttackSkill(h.class)
  if (!slug) log(`attack ${h.id}: no attack SKILL.md for class '${h.class}' — operator runs inline + proof skills`)
  const classSkill = slug ? `${skillsDir}/attack/${slug}/SKILL.md` : null
  // iteration 5 — client-side classes reach impact_proven only on REAL browser execution, so inject the
  // dynamic-validate proof skill (leashed Playwright MCP) for them. postmessage-xss resolves to the xss slug.
  // backlog #2 — WAF-prone injection classes carry the evolutionary-bypass proof skill, so a WAF block
  // triggers wafrift's mutation search (then re-proves the class oracle) instead of a dead lead.
  const WAF_PRONE = new Set(['sqli', 'xss', 'ssti', 'rce', 'ssrf', 'xxe', 'ognl', 'waf-body-bypass'])
  const proofSkills = [`${skillsDir}/proof/poc-standard/SKILL.md`, `${skillsDir}/proof/oob-interactsh/SKILL.md`,
    ...(CLIENT_SIDE.has(slug) ? [`${skillsDir}/proof/dynamic-validate/SKILL.md`] : []),
    ...(WAF_PRONE.has(slug) ? [`${skillsDir}/proof/waf-mutation/SKILL.md`] : [])]
  const methodology = (classSkill ? [classSkill, ...proofSkills] : proofSkills).join(', ')
  const held = reqs(h).filter(t => (acquired instanceof Set ? acquired.has(t) : false))
  // F1 — a prerequisite capability is already held: the leash auto-injects the operator session, so
  // the operator exercises AUTHENTICATED surface; never log in / forge / crack / brute to obtain it.
  const sessionBlock = held.length ? `

ACQUIRED STATE YOU HOLD (this is why this hypothesis is now unlocked): ${held.join(', ')}
A valid operator session is ACTIVE and AUTO-INJECTED by the leash on every in-scope HTTP request. Do NOT
log in, handle, forge, crack, or brute credentials to get it — just exercise the AUTHENTICATED surface
and prove impact (e.g. cross-account object reads for BOLA/IDOR). For a non-HTTP service, load SSH/other
material from ${a.target_dir}/session.env through tools/leash-tcp.sh; never forge or crack it.` : ''
  // F3 — default-cred control-test: allowed ONLY if the scope policy enables it; spray-not-brute, capped.
  const credBlock = slug === 'cred-access' ? `

CRED-ACCESS IS A DEFAULT-CRED CONTROL-TEST — allowed ONLY if scope policies.default_cred_control_test.enabled.
If it is NOT enabled, STOP and return proven_state:'blocked', blocked_reason:'policy' (do not attempt a login).
If enabled: run every attempt through tools/leash-cred.sh (host-pinned + rate/lockout/attempt-capped),
SPRAY not brute (nuclei default-login pitchfork templates, or nxc --no-bruteforce), a SMALL curated set
≤ policy.max_pairs, stop_at_first, ONE attempt per principal. Pre-condition gate: only where the service
actually offers that auth (SSH offers password auth / FTP-SMB anon). On ANY lockout/throttle signal STOP
and return proven_state:'blocked', blocked_reason:'policy'. FORBIDDEN: cartesian brute, wordlist dumps,
--continue-on-success past a one-pass spray, OTP/2FA brute. The oracle is a REAL authenticated action with
the found cred (not the scanner's "[+]" line). A proven cred provides creds:<principal>@${h.host}.` : ''
  // F6/P6 — OTP/2FA logic: a LEGITIMATE non-brute foothold door. Observation + logic only.
  const otpBlock = slug === 'otp-logic' ? `

OTP/2FA IS A LOGIC PLAY — NEVER A BRUTE OF THE CODE SPACE. Prove ONE of these legitimate, safeguard-free
paths to a SERVER-VALID session, then STOP: (1) LEAK — the code or a pending/mfa/otp token is returned in
the pre-OTP response (body/headers/Set-Cookie) or a /resend|/me follow-up; submit it. (2) BINDING — the
verify request carries a client-controlled account/user/username/verify field; repoint it to the victim
and submit YOUR OWN delivered code (PortSwigger broken-logic). (3) PREDICTABLE/STATIC — derive the next
code from observed staticness/sequence and use it ONCE. (4) SIMPLE-BYPASS — reach a post-login resource
without submitting the code (step not enforced server-side). (5) REUSE — a used/expired code still
accepted. (6) LOOSE-COMPARE — a SINGLE well-formed probe per variant (int vs string, leading-zero, null,
[], "000000"). ORDERING RULE: if the session is a SERVER-SIGNED cookie (test: forge a bare value -> 401),
rank leak/binding/predictable ABOVE client-side response/status tampering — tampering a server-validated
flow fools only the SPA and mints NO server-valid session. HARD LIMITS: never brute the code space, never
flood, never touch a safeguard-flagged path (e.g. a register-crash), stop at the first valid session. The
ORACLE is a protected resource reached with a SERVER-VALID session (401/403 -> 200 w/ privileged content
that survives a fresh request), NOT "the SPA let me in". A proven session provides session:${h.host}.` : ''
  // P4 — post-foothold operation (inside an authorized host): non-destructive, scope-pinned, one-shot privesc.
  const POST_FOOTHOLD = new Set(['internal-recon', 'privesc', 'loot', 'lateral'])
  const postFootholdBlock = POST_FOOTHOLD.has(slug) ? `

POST-FOOTHOLD OPERATION (inside an authorized host) — NON-DESTRUCTIVE, SCOPE-PINNED, ONE-SHOT PRIVESC:
Run every on-host command through tools/leash-foothold.sh ${a.target_dir} ${h.host} <cmd> — it host-pins
the foothold channel and REFUSES destructive verbs. The foothold host is in scope; its neighbours are NOT
unless listed in scope.yaml.
- internal-recon (Discovery): enumerate READ-ONLY — linPEAS STEALTH profile (bin/.peass/linpeas.sh -s,
  NEVER -a), or manual (id; uname -a; sudo -l; find / -perm -4000 -type f 2>/dev/null; getcap -r / ;
  crontab -l; ls -la /etc/cron.*). winPEAS for Windows targets. Do NOT change anything. provides: nothing
  (knowledge); if you find a credential/key for an IN-SCOPE host, it provides creds:<p>@<that-host>.
- privesc (PrivEsc): take ONE deterministic single-step escalation from a CONCRETE enumeration finding,
  looked up in GTFOBins (bin/.gtfobins, for a SUID/sudo/caps binary) or LOLBAS (bin/.lolbas, Windows) or a
  single known-CVE public one-shot. The oracle is a DEMONSTRATED privileged action (id => uid=0, or
  reading a root-only file within safe-PoC policy) — NOT linPEAS's colour. FORBIDDEN: brute/crack of
  root's password, destructive or box-crashing kernel exploits (route those to human_review), any
  persistence/implant. provides:["admin:${h.host}"] only on oracle proof.
- loot (Collection): read OBJECTIVE-relevant files/creds/keys first (scope.objective.flag_format / scope.objective.goal —
  the flag usually lives behind the foothold). Bounded: no mass-exfil, no whole-filesystem copy, no
  destruction. A found objective artifact is your execution_evidence for the P1 objective oracle. A found
  in-scope credential provides creds:<p>@<host>.
- lateral (Lateral): enumerate neighbours reachable FROM this host, but PIVOT ONLY to a host already in
  scope.yaml (assert with tools/guard.py). A reachable host NOT in scope is a LEAD in state.json — never
  attack it. A working pivot cred for an in-scope host2 provides creds:<p>@<host2> (the scheduler unlocks
  host2's hypotheses next wave). No scanning/flooding of out-of-scope ranges.` : ''
  // iteration 2 — ESCALATION LADDER (post-foothold planner). Fires for class:escalation-ladder. It owns no
  // new exploit path: it decides the single highest-value next rung and routes it to the pack that owns the
  // technique (privesc/lateral/loot/cred-access/ssrf), all under the SAME scope + policy + oracle gates.
  const escalationBlock = slug === 'escalation-ladder' ? `

ESCALATION LADDER (post-foothold planner) — you HOLD a proven foothold${held.length ? ` (${held.join(', ')})` : ''}; the foothold is the START of the finding, not the end. Take the SINGLE highest-value next rung and prove it through the DESTINATION pack's oracle, then stop:
- REUSE the credential you hold: a proven creds:<p>@<hostA> is a lead that the SAME principal may auth on OTHER in-scope hosts — propose/prove a cred-access control-test on each (tools/leash-cred.sh, spray-not-brute, ONE pass, ONLY if policies.default_cred_control_test.enabled; otherwise return blocked:policy).
- CLIMB on the held host: route to privesc / internal-recon / loot per those packs (tools/leash-foothold.sh, READ-ONLY enumeration, ONE oracle-proven single-step privesc, non-destructive).
- FOLLOW the identity a stolen session/token trusts: prove ONE privileged action or authz boundary it crosses; a cloud cred found on the host is a lead for a single SCOPED cloud read (ssrf/loot). Read ${a.context_pack ? a.context_pack + ' + ' : ''}the target/program context pack for the stack-specific rung.
Pivot ONLY to scope.yaml hosts (tools/guard.py); an out-of-scope reachable host is a LEAD in state.json, never attacked. The ORACLE is the destination pack's (a real authenticated action with the reused cred / a demonstrated privileged action / a crossed authz boundary) — a plan or "could pivot" is NOT a finding. If a rung needs defeating an auth control AS AN ATTACK, return proven_state:'blocked', blocked_reason:'safeguard' (hand-off, never evade). Full gates in ${skillsDir}/attack/escalation-ladder/SKILL.md.` : ''
  // P3 — CTF solve: local/offline on a provided in-scope artifact; a pwn remote delivery is host-pinned.
  const CTF_SLUGS = new Set(['pwn', 'rev', 'crypto', 'forensics', 'stego'])
  const ctfBlock = CTF_SLUGS.has(slug) ? `

CTF SOLVE (${slug}) — the "target" is a PROVIDED, in-scope challenge artifact under ${a.target_dir}/artifacts/
(or raw/ if a prior stage carved it). Analyse it LOCALLY and OFFLINE: local artifact analysis touches no
network and needs NO leash. The only network is (i) a download, or (ii) a pwn/remote delivery to the
in-scope endpoint from engagement.challenges[].remote — pin that exact host:port via tools/guard.py and
tools/leash-tcp.sh; never a range. Many tools are Linux-native — if one is absent on this OS, run it under
WSL (see arsenal/manifest.json cross-OS notes). The ORACLE is the FLAG: your proof is a SAVED, re-runnable
solve artifact under raw/attack-${h.id}/ (exploit.py / solve.sage / solve-notes) that RE-DERIVES a string
matching scope.objective.flag_format. Put that flag in execution_evidence and the script in poc_path. If a
sub-result unlocks another challenge, set provides accordingly (artifact:/key:/plaintext:/flag: per
brain/schema.md). This is AUTHORISED solving of a provided puzzle you were given — NOT an attack on a third
party: no auth-crack of others, no DoS/flood, nothing destructive, and the Anthropic-safeguard red line is
unchanged.` : ''
  // P5 — interactive-protocol held-socket exploit (policy-gated; the socket wrapper is the audit choke point).
  const interactiveBlock = slug === 'interactive-exploit' ? `

INTERACTIVE-PROTOCOL EXPLOIT — allowed ONLY if scope policies.interactive_protocol.enabled.
If it is NOT enabled, STOP and return proven_state:'blocked', blocked_reason:'policy' (do not open a socket).
Hold the conversation through tools/leash-sock.py (the Remote tube: send/sendline/recvuntil/recvline),
NEVER raw netcat/curl (no audit, no scope-pin). It host-pins via guard.py, caps frames/bytes/session-time
(so a logic exploit can never become a flood), and writes a FULL TRANSCRIPT to raw/attack-${h.id}/sock-*.jsonl.
Iterate send->recv->branch: desync the state machine, vary one field's encoding, fuzz within caps, chase
every error leak. The oracle is the RE-DERIVABLE TRANSCRIPT showing the effect — command output over the
socket (id/whoami within the RCE safe-PoC policy), a leaked record, or a protocol state crossed (a
privileged verb accepted where it was denied). The scanner/narration is NOT proof. SAVE the driving
Remote-based exploit script next to the transcript so the foothold it provides is reproducible. A foothold
reachable only by defeating an auth control as an attack => proven_state:'blocked', blocked_reason:'safeguard'
(hand off, never evade). FORBIDDEN: auth brute/crack as evasion, flooding (caps enforce it), destructive
protocol actions. A proven interaction that grants access provides session:${h.host}/foothold:${h.host}.` : ''
  // P1 — objective/flag capture (mode-gated; orthogonal, may co-fire with any slug). '' in impact mode.
  const objectiveBlock = (a.objective && a.objective.mode === 'flag') ? `

ENGAGEMENT OBJECTIVE (the win condition): ${a.objective.goal}
If while proving this hypothesis you obtain a string matching /${a.objective.flag_format || 'flag\\{[^}]+\\}'}/, SAVE
the producing request/response/file/command output under raw/attack-${h.id}/ and report it as execution_evidence with
proven_state:'impact_proven' — the flag IS the impact. Never fabricate or guess a flag; one not traceable to a saved
artifact fails the oracle. Reach it ONLY by a legitimate, oracle-provable path — never evade a safeguard or crack auth to get it.` : ''
  // P2 — one-line engagement-mode banner (additive; '' for a plain web run). Orthogonal to the slug blocks.
  // Gated on a NON-web mode: the brain runs classify on every preflight and fail-opens to mode:'web', so
  // gating on mere truthiness would render on every plain run and break the byte-identical invariant
  // (schema.md: classification absent/web == a plain run). A non-web mode is the only case worth tailoring to.
  const classificationBanner = (a.classification && a.classification.mode && a.classification.mode !== 'web') ? `

ENGAGEMENT MODE: ${a.classification.mode}${(a.classification.signals && a.classification.signals.length) ? ` (signals: ${a.classification.signals.slice(0, 3).join('; ')})` : ''}. Tailor technique to this shape; the oracle and the scope rules are unchanged.` : ''
  // fix3 B1/B4/B5 — bounty exploit orientation (mode-gated; '' in impact/flag). Orthogonal to the slug
  // blocks; may co-fire with any. Submission-quality PoC, evidence-bound severity, no inflation.
  const bountyBlock = (a.objective && a.objective.mode === 'bounty') ? `

BOUNTY MODE — the win is a PAYABLE finding. Build the PoC to SUBMISSION quality (copy-paste repro,
execution_evidence, the mandatory header, synthetic accounts only) — report quality is a reward factor.
Reach impact ONLY by a legitimate, oracle-provable path; NEVER inflate severity to clear the program floor
(${a.objective?.min_payable_tier || 'P4'}), NEVER assume novelty. If this class is marked
eligibility:excluded / in program.excluded_classes, prove the MINIMAL misconfig and STOP (ineligible — do
not over-invest), returning proven_state:'misconfig_proven' or 'not_reproduced' with a note — it stays a
noted lead, it is never a reason to widen scope or bend a safeguard.` : ''
  // fix3 MVP — SENIOR EXEMPLAR priming (additive; '' when args.exemplars[h.id] is absent, so the mission
  // is byte-identical to today). Distilled from DISCLOSED reports: a HINT for what to try and what proof
  // SHAPE to produce — NEVER evidence. The oracle re-derives proof on THIS target; an exemplar is forbidden
  // as a citation of proof. KNOWN DEAD-ENDS (args.negatives[h.id]) are appended to save wasted turns.
  const exemplarBlock = (a.exemplars && Array.isArray(a.exemplars[h.id]) && a.exemplars[h.id].length) ? `

SENIOR EXEMPLARS retrieved for this class+fingerprint (distilled from DISCLOSED reports). These are HINTS
for what to try and what proof shape to PRODUCE — NOT evidence. You MUST re-derive proof on THIS target and
NEVER cite an exemplar as your result (the oracle re-runs your PoC):
${a.exemplars[h.id].map((e, i) => `  ${i + 1}. (id:${e.id || '?'}) [${e.class}] signal: ${e.trigger_signal}
       dead-end -> pivot: ${e.decision_trace}
       technique: ${e.key_technique}
       payload: ${e.payload ? e.payload : 'OMITTED — source the verbatim bytes from ' + (e.resolve_from || 'exploit-db / nuclei-templates / PoC repos') + ' keyed by the same fingerprint'}
       prove it like (produce THIS shape yourself): ${e.proof_oracle}`).join('\n')}
FEEDBACK (closes the corpus hit-rate loop): if an exemplar materially helped you reach proof, echo its id
(the id: tag above) in your result's used_exemplars[] — list ONLY ids that genuinely helped, [] otherwise.${(a.negatives && Array.isArray(a.negatives[h.id]) && a.negatives[h.id].length) ? '\nKNOWN DEAD-ENDS for this surface (do not waste turns; the oracle rejects these as false positives): ' + a.negatives[h.id].join(' | ') : ''}` : ''

  // crit-roadmap #4 — per-trajectory angle. null scaffold = BASELINE = today's mission verbatim (byte-identical).
  const scaffoldBlock = scaffold ? `

YOUR TRAJECTORY (${scaffold.key}): ${scaffold.hint}
Write THIS trajectory's evidence + runnable PoC under ${a.target_dir}/raw/attack-${h.id}-${scaffold.key}/ (your own subdir, so parallel trajectories never clobber each other). Same oracle, same scope, same safe-PoC limits.` : ''

  // Reflect loop (RefPentester/Red-MIRROR: an explicit failure-reason -> sharpened-retry step ~doubles
  // success). A prior attempt on THIS hypothesis did NOT reproduce; the Advisor derived WHY and a sharper
  // angle. Start from that, do NOT repeat the dead path. Additive: no reflectHint => '' => byte-identical.
  const reflectBlock = reflectHint ? `

REFLECTION — THIS IS A SHARPENED RETRY (the first attempt on this hypothesis did NOT reproduce). An
adversarial Advisor reviewed your prior attempt artifacts and concluded:
${reflectHint}
Do NOT repeat the exact path that already failed. Act on the failure reason: if a WAF/filter blocked you,
run the evolutionary bypass loop (bin/wafrift — grammar/encoding mutation ordered by block-confidence, its
gene-bank persists what lands) instead of hand-guessing; if a precondition/auth was missing, acquire it
first; if the param/sink was wrong, use the corrected one. Read the response to EVERY probe and adapt. Same
oracle, same scope, same safe-PoC limits — a sharper attempt, not a louder one.` : ''

  // #3 — per-hop validation for a MULTI-STEP hypothesis. Decompose the chain and prove each hop before the
  // next; a later hop can't be claimed on an unproven earlier one. Additive: single-step => '' => unchanged.
  const perHopBlock = isMultiStep(h) ? `

PER-HOP VALIDATION (this hypothesis is a MULTI-STEP chain — decompose it, prove each hop before the next):
Break the path into ordered HOPS (e.g. SSRF -> reach metadata -> read cloud creds -> use creds to read data).
Prove each hop's OWN mini-oracle with its OWN evidence BEFORE the next — a later hop may NOT be claimed on an
unproven earlier hop. This is what stops a hallucinated end-to-end chain. If a hop fails, STOP there and
report honestly: fill hops[] with each {step, proven, evidence} and set hops_reached to the furthest PROVEN
hop. impact_proven REQUIRES every hop proven; a real partial chain is misconfig_proven / a lead at the hop it
reached — an honest distance-to-impact, never a fabricated end-to-end success.` : ''

  // gap C — SEAM-SEED (recon->attack). recon-2 + the synthesizer already PROVED a structural seam (the exact
  // desync variant, the unkeyed cache input, the newly-exposed/authz-changed endpoint, the mapped stack-CVE,
  // the injectable params). Pre-fix those lived as free PROSE inside how_to_prove, so the operator re-detected
  // from zero. Now they arrive as STRUCTURED fields on h.seam and are rendered as an explicit "do NOT re-detect,
  // weaponize" block, so a senior starts at the proven primitive and spends the whole budget on IMPACT. Fully
  // additive: no h.seam (every run until the synthesizer writes it) => seamLines empty => '' => byte-identical.
  const seam = (h && h.seam && typeof h.seam === 'object') ? h.seam : null
  const seamLines = []
  if (seam) {
    const ev = x => x ? ` (evidence: ${x})` : ''
    if (seam.desync_variant || seam.smuggle) seamLines.push(`- request-smuggling/desync variant ALREADY DETECTED (smuggler/smugglex): ${seam.desync_variant || seam.smuggle}${ev(seam.smuggle_evidence)} — skip re-detection; weaponize it (cache poisoning of a victim response, request hijack/credential capture, front-end auth bypass) and prove the IMPACT.`)
    if (seam.unkeyed_input || seam.cache_input) seamLines.push(`- unkeyed cache input ALREADY FOUND: ${seam.unkeyed_input || seam.cache_input}${ev(seam.cache_evidence)} — weaponize with wcvs; prove a CLEAN second request re-fetches YOUR poisoned response (persistence oracle), not just a reflected header.`)
    if (seam.oasdiff_endpoint || seam.endpoint) seamLines.push(`- newly-added / authz-CHANGED endpoint (oasdiff) ALREADY MAPPED: ${seam.oasdiff_endpoint || seam.endpoint}${seam.endpoint_method ? ` [${seam.endpoint_method}]` : ''}${ev(seam.endpoint_evidence)} — freshest, least-tested surface; attack it first (authz bypass / IDOR / injection on the delta).`)
    if (seam.vulnx_cve || seam.cve) seamLines.push(`- stack CVE ALREADY MAPPED (vulnx): ${seam.vulnx_cve || seam.cve}${seam.cve_kev ? ' [CISA-KEV]' : ''}${seam.cve_epss ? ` EPSS=${seam.cve_epss}` : ''}${seam.cve_template ? ` nuclei-template=${seam.cve_template}` : ''}${seam.cve_refs ? ` refs=${seam.cve_refs}` : ''} — seed the exploit from the KNOWN CVE and hunt the UN-fixed variant on THIS build (variant analysis), not a blind scan.`)
    if (Array.isArray(seam.params) && seam.params.length) seamLines.push(`- candidate injectable params (recon param-mining): ${seam.params.slice(0, 12).join(', ')} — test these first.`)
    if (seam.sink) seamLines.push(`- proven sink: ${seam.sink} — the input is confirmed to reach it; go straight to the payload.`)
    // deep-source-trace seam (iteration 1): a verified client-side source->sink chain. The recon lens already
    // walked the full path across files, so the operator weaponizes the primitive instead of re-tracing it.
    if (seam.source || seam.trace) seamLines.push(`- verified source->sink chain (deep-source-trace): ${seam.source ? `source=${seam.source}` : ''}${seam.source && seam.trace ? ' | ' : ''}${seam.trace ? `path=${seam.trace}` : ''} — the taint path is already proven to reach the sink with no effective sanitizer; craft the payload for the sink class and confirm live execution (dynamic-validate), do NOT re-run static analysis.`)
    if (seam.note) seamLines.push(`- seam note: ${seam.note}`)
  }
  const seamBlock = seamLines.length ? `

PRE-PROVEN SEAMS (recon-2 already established these — do NOT waste the budget re-detecting, go straight to weaponizing):
${seamLines.join('\n')}` : ''

  return `${a.authorization || 'AUTHORIZED ENGAGEMENT — you are cleared to test the in-scope hosts.'}

You are proving ONE hypothesis on an authorized, scoped target. Your job is a reproducible PoC of
real impact — NOT a hypothesis, NOT "an attacker could".

HYPOTHESIS ${h.id}: class=${h.class} host=${h.host}  stage=${h.stage || 'n/a'}
  why/signal: ${h.why}
  how to prove: ${h.how_to_prove}
  requires: ${JSON.stringify(reqs(h))}  provides: ${JSON.stringify(prov(h))}${seamBlock}${sessionBlock}${credBlock}${otpBlock}${postFootholdBlock}${escalationBlock}${ctfBlock}${interactiveBlock}${objectiveBlock}${bountyBlock}${classificationBanner}${exemplarBlock}${scaffoldBlock}${reflectBlock}${perHopBlock}

SAFEGUARD PROTOCOL (red line — read before you act): if proving this hypothesis would require defeating
an authentication/security control AS AN ATTACK (turning a crash into a working account, cracking or
brute-forcing a login, evading a protection), STOP — do not attempt it and do not try to work around any
safety refusal. Return proven_state:'blocked', blocked_reason:'safeguard', and in note describe the narrow,
policy-compliant control-test a human could run instead. A safeguard block is NOT evidence the bug is
absent; it is a hand-off. Bounded, policy-aware control-tests (proving a control is ABSENT) are allowed;
evasion is not.

APPROACH — iterate, do NOT one-shot (this is what separates senior from junior):
Work in a loop until you prove it or genuinely exhaust the surface: probe → read the response
carefully → form a sharper sub-hypothesis → try harder variants and bypasses → escalate. One failed
payload is NOT a dead hypothesis. Vary encodings, headers, methods, auth states, parameter positions,
filter bypasses; combine techniques; chase every anomaly (odd status, timing, error leak, reflected
value). Use your full turn budget and persist intermediate notes/attempts under raw/attack-${h.id}/.
SELF-REFLECTION CHECKPOINT (don't grind the same wall): after ~3 consecutive failed variants on the SAME
sub-approach, STOP and reflect in-turn — name WHY it is failing from the responses (WAF/filter block ⇒
switch to bin/wafrift mutation; wrong param/sink; missing precondition/auth; wrong encoding; a response
that only echoes input / a suspiciously clean 200 ⇒ likely not vulnerable), then either pivot to a
genuinely DIFFERENT angle or conclude that approach is dead. Grinding one blocked path is junior behaviour.
Only conclude not_reproduced after you've tried the real senior repertoire for ${h.class}, not one curl.

SCOPE (authoritative): ${JSON.stringify(a.scope || {}, null, 0)}
Safe-PoC limits from scope policy MUST be honored (e.g. RCE = whoami/id/hostname only, SQLi =
database()/@@version only). No destructive, brute, or DoS actions. Route target-facing tools through the leash wrapper
(tools/leashed.sh ${a.target_dir} <tool>); non-HTTP tools validated with tools/guard.py and pinned to the exact in-scope host.

TARGET DIR: ${a.target_dir} — write every request/response and a runnable PoC under ${a.target_dir}/raw/attack-${h.id}/.
CROSS-RUN LEARNING (compounding): BEFORE you probe blind, run the in-run memory recall —
\`python tools/recall.py --target-dir ${a.target_dir} --class ${h.class} --host ${h.host}\` — it ranks this
target's OWN prior records (state.json techniques[] to REPLAY, dead_paths[]/tried[] NOT to retry, related
findings, AND raw/ notes other operators wrote THIS run) so you never repeat a sibling agent's failed
payload or a recorded dead-end. Also read ${a.context_pack ? a.context_pack + ' (prior program/target pack: stack/CVE map, paid classes)' : 'any .claude/skills/context/ pack for this program/target, if present'}. Empty/cold on a first run (that is fine).
ARSENAL: ${a.bin_dir || 'C:/Spider/bin'} via Bash; connected MCP via ToolSearch. For blind bugs, use the
interactsh client and capture the OOB callback as your execution_evidence. MCP phase-map (docs/mcp-integration.md):
a leashed browser (playwright) PROVES client-side bugs by real execution — for xss/prototype-pollution/
open-redirect/cors load proof/dynamic-validate and capture the execution signal, not a reflected string;
a leashed proxy (burp/caido) forges/replays stateful flows; bloodhound_mcp is LOCAL read-only post-foothold
AD-graph query (shortest path to DA from an owned principal). Target-facing MCP route through the leash; in-scope only.
METHODOLOGY: read if present: ${methodology}

SIBLING SURFACES (gap D — organic growth): if while probing you NOTICE a different exploitable-looking
surface that is NOT this hypothesis (a second IDOR on an adjacent object, an injectable sort/filter field,
an open redirect in the same flow, a mis-authz endpoint you passed through), do NOT chase it now — record it
in sibling_hypotheses[] ({class, host, why, how_to_prove, requires?, provides?}). The next round proves it.
This is how a senior turns one surfaced bug into five, instead of tunnel-visioning on the single assigned one.

Return the candidate schema with proven_state:
- impact_proven — you chained to real impact (data read / RCE / ATO / OOB callback). Fill
  execution_evidence + poc_path. high/critical REQUIRES this.
- misconfig_proven — the defect is reproduced with a RUNNABLE PoC ARTIFACT under raw/. For
  CORS/redirect/header/clickjacking classes you MUST BUILD the PoC artifact under raw/ (e.g. write a
  cors-poc.html that does a credentialed cross-origin fetch — see proof/cors-poc-html), not just read
  a response header. severity floor = low (may be
  medium/high if the class warrants).
- not_reproduced — could not reproduce; it's a lead.
Never claim high/critical without execution_evidence. A misconfig with a working PoC artifact is a
finding, not info — do not under-report it.`
}

const LENSES = [
  { key: 'reproduce', ask: 'Re-run the PoC yourself from the artifact. Does it reproduce the claimed effect with YOUR own hands, or only in the author\'s narration? If you cannot reproduce it, refuted=true.' },
  { key: 'impact', ask: 'Is the impact PROVEN, not assumed? Demand execution_evidence (command output, leaked record, OOB callback). A reflected value is not RCE; access to a page is not data theft. No hard proof => refuted=true. ALSO guard against DECEPTIVE evidence (ATOBench): a response that merely echoes the payload, a suspiciously clean 200, a generic "success" message, or a honeypot-style result is NOT proof — demand an effect the target cannot fabricate (an OOB callback to a UNIQUE token, a record only the real backend holds, a cross-account read). If the "proof" could be faked by the app, refuted=true.' },
  { key: 'scope-policy', ask: 'Is the affected host in scope.yaml AND within the program\'s safe-PoC policy? Is the claimed severity justified by the proven impact, or inflated? Out-of-scope/over-policy/over-graded => refuted=true (or corrected severity).' },
  { key: 'origin-check', ask: 'Confirm the target is the REAL remote in-scope host, not a local artifact or our own egress. Any OOB interactsh callback source-IP must NOT be 127.0.0.1 or this machine\'s own egress IP, and the responding service must be one of the target\'s origin IPs in state.json. If the "finding" is actually a local proxy/service (e.g. something on 127.0.0.1:PORT) or the callback returned to our own box, refuted=true. This is a hard veto.' },
]

function verifyMission(c, lens) {
  return `You are a hostile triager verifying a finding on axis: ${lens.key.toUpperCase()}. Default to
refuted=true and let evidence change your mind.

CANDIDATE: ${JSON.stringify({ proven_state: c.proven_state, type: c.type, severity: c.severity, title: c.title, detail: c.detail, evidence: c.evidence, execution_evidence: c.execution_evidence, poc_path: c.poc_path, repro: c.repro })}
Note: proven_state=misconfig_proven means the defect is reproduced with a PoC artifact — judge whether the PoC reproduces the DEFECT, not whether full data-exfil was chained. proven_state=impact_proven must show real impact (execution_evidence).
TARGET DIR: ${a.target_dir} (the evidence + PoC are under raw/). SCOPE: ${JSON.stringify(a.scope || {}, null, 0)}
Arsenal in ${a.bin_dir || 'C:/Spider/bin'}; all HTTP through the leash, in scope.

YOUR AXIS: ${lens.ask}

Return the verdict schema. Be hostile — a finding that can't survive you won't survive the program.`
}

// Deterministic PoC oracle — the hard gate (AI discovers, the oracle validates). No oracle, no finding.
const ORACLE = {
  type: 'object',
  properties: {
    oracle_met: { type: 'boolean' }, oracle_type: { type: 'string' },
    oracle_evidence: { type: 'string' }, reproduced: { type: 'boolean' },
    severity: { type: 'string', enum: SEV }, reason: { type: 'string' },
  },
  required: ['oracle_met', 'reason'],
}
function validateMission(c, h) {
  // iteration 5 — a client-side candidate's oracle is live browser execution, so the validator must re-run
  // it in the leashed Playwright MCP, not just read a response. Derived from the hypothesis class (fallback: the candidate type).
  const dyn = CLIENT_SIDE.has(resolveAttackSkill((h && h.class) || c.type)) ? `
This is a CLIENT-SIDE class: re-execute the PoC in the LEASHED Playwright MCP (read
.claude/skills/proof/dynamic-validate/SKILL.md) and capture the execution signal — the sentinel fired /
the final URL landed on the attacker host / the framed render — NOT a reflected string or a screenshot.` : ''
  return `Validate this finding deterministically. Read .claude/skills/proof/oracles/SKILL.md, then
RE-EXECUTE the PoC yourself (in scope, through the leash) and produce the class oracle evidence —
an OOB callback / DB banner / command output / cross-account record / cross-origin read / redirect
Location / etc. Do NOT trust narration.${dyn}
CANDIDATE: ${JSON.stringify({ proven_state: c.proven_state, type: c.type, severity: c.severity, title: c.title, evidence: c.evidence, execution_evidence: c.execution_evidence, poc_path: c.poc_path, repro: c.repro })}
TARGET DIR: ${a.target_dir} (evidence under raw/). SCOPE: ${JSON.stringify(a.scope || {}, null, 0)}. Arsenal: ${a.bin_dir || 'C:/Spider/bin'}.
oracle_met=true ONLY with objective, re-derivable evidence; save your re-run under raw/validate-${c.hypothesis_id || 'x'}/.`
}

// --- verify stage (lifted verbatim from the old pipeline; oracle gate + 4 skeptic lenses UNCHANGED) ---
function verifyStage(candidate, h, wave) {
  if (!candidate || candidate.proven_state === 'not_reproduced') {
    return { hypothesis: h, candidate, status: 'lead' }
  }
  if (candidate.proven_state === 'blocked') {           // F2 — operator self-reported a red-line block; a hand-off, not a lead
    return { hypothesis: h, candidate, status: 'blocked', blocked_reason: candidate.blocked_reason || 'policy' }
  }
  return parallel([
    // deterministic oracle (hard gate) runs alongside the adversarial skeptics
    () => agent(validateMission(candidate, h), { label: `validate:${h.id}`, phase: `Verify wave ${wave}`, agentType: 'validator', schema: ORACLE, ...modelFor(a.model_tier) }).then(o => ({ __oracle: o || null })),
    ...LENSES.map(lens => () =>
      agent(verifyMission(candidate, lens), { label: `verify:${h.id}:${lens.key}`, phase: `Verify wave ${wave}`, agentType: 'verifier-skeptic', schema: VERDICT, ...modelFor(a.model_tier) })
        .then(vd => vd ? { ...vd, lens: lens.key } : null)),
  ]).then(all => {
    const parts = all.filter(Boolean)
    const oracle = (parts.find(x => x.__oracle !== undefined) || {}).__oracle || null
    const v = parts.filter(x => x.__oracle === undefined)
    const originRefuted = v.some(x => x.lens === 'origin-check' && x.refuted)
    const core = v.filter(x => x.lens !== 'origin-check')
    const coreSurvived = core.filter(x => !x.refuted).length >= Math.ceil(core.length / 2)
    // the ORACLE is the hard gate: no deterministic oracle evidence => NOT confirmed
    const oracleOk = !!(oracle && oracle.oracle_met)
    const survived = oracleOk && !originRefuted && coreSurvived
    let severity = (oracleOk && oracle.severity) ? oracle.severity
      : (() => { const s = core.filter(x => !x.refuted && x.severity).map(x => SEV.indexOf(x.severity)).filter(i => i >= 0); return s.length ? SEV[Math.min(...s)] : candidate.severity })()
    if (candidate.proven_state === 'misconfig_proven' && SEV.indexOf(severity) < SEV.indexOf('low')) severity = 'low'
    return { hypothesis: h, candidate, oracle, verdicts: v, survived, severity, status: survived ? 'confirmed' : 'refuted' }
  })
}

// --- F4 foothold-first WAVE scheduler ---------------------------------------
// Prove foothold producers first; a dependent hypothesis fires only once every token in its
// `requires` is in the acquired set (seeded by the operator session + capabilities proven earlier).
// A confirmed/proven hypothesis's `provides` tokens unlock the next wave. Anything still unmet when the
// ready-set empties is reported blocked_on_prereq — never run as a dead PoC. The oracle gate is untouched.
const acquired = new Set([
  ...((a.session && Array.isArray(a.session.provides)) ? a.session.provides : []),  // F1: operator session.env descriptor (non-secret tokens)
  ...(Array.isArray(a.prior_capabilities) ? a.prior_capabilities : []),             // proven in earlier rounds (state.json.capabilities)
])
const ready = h => reqs(h).every(t => acquired.has(t))
const unlockScore = h => { const mine = new Set(prov(h)); let s = 0
  for (const g of hypotheses) if (g !== h && reqs(g).some(t => mine.has(t))) s++; return s }

// fix3 B4 — pure eligibility annotation (keyword match, mirrors resolveAttackSkill). The payout-POLICY
// verdict for a hypothesis class vs the program's exclusions/excluded_classes. It NEVER changes scope, a
// safeguard, or severity. program absent => 'unknown' with no action (no partition). Lower-cased
// substring, first-match-wins — one matching discipline, not two.
function eligibility(h, program) {
  if (!program) return { eligibility: 'unknown', action: '', reason: 'no program block' }
  const c = (h.class || '').toLowerCase()
  for (const ex of (Array.isArray(program.exclusions) ? program.exclusions : [])) {
    const kws = String(ex.match || '').toLowerCase().split('|').map(s => s.trim()).filter(Boolean)
    if (kws.some(kw => c.includes(kw)))
      return { eligibility: ex.action === 'control-test-only' ? 'control-test-only' : 'excluded',
               action: ex.action || 'note', reason: ex.reason || `matches exclusion ${ex.match}` }
  }
  if ((Array.isArray(program.excluded_classes) ? program.excluded_classes : []).some(k => k && c.includes(String(k).toLowerCase())))
    return { eligibility: 'excluded', action: 'note', reason: 'matches program.excluded_classes' }
  return { eligibility: 'payable', action: '', reason: '' }
}
// fix3 B4 — pre-schedule partition: in bounty mode with a program, an excluded class with action:'note' is
// a NOTED LEAD — never scheduled, never dropped. control-test-only / downrank stay scheduled. Backward
// compat: no bounty / no program => ineligible empty => scheduled === hypotheses (same reference) => the
// F4 wave loop is byte-identical.
const bounty = a.objective?.mode === 'bounty'
const ineligible_leads = (bounty && a.program)
  ? hypotheses.map(h => ({ h, e: eligibility(h, a.program) }))
      .filter(x => x.e.eligibility === 'excluded' && x.e.action === 'note')
      .map(x => ({ id: x.h.id, class: x.h.class, host: x.h.host, why: x.h.why, eligibility: 'excluded', eligibility_reason: x.e.reason }))
  : []
const _ineligibleIds = new Set(ineligible_leads.map(l => l.id))
const scheduled = _ineligibleIds.size ? hypotheses.filter(h => !_ineligibleIds.has(h.id)) : hypotheses
if (ineligible_leads.length) log(`eligibility: ${ineligible_leads.length} excluded-class hypotheses held as ineligible_leads (not scheduled, not dropped)`)

// fix3 B5/B3 (C6) — EV-aware SECONDARY sort key. 0 unless bounty mode, so the foothold-first unlockScore
// PRIMARY ordering is byte-identical in impact/flag (|| (0-0) collapses it away). A likely-duplicate LEAF
// (no novel/could-not-verify dependent needs its tokens) is EV~0 => sorts last (B3 dupPenalty folded in);
// a duplicate that is a PREREQUISITE for a novel dependent is dependency-safe (NOT penalized). could-not-
// verify always runs normally (fail-open to attacking — a missed novel bug costs more than a wasted wave).
const TIER_RANK = { P1: 4, P2: 3, P3: 2, P4: 1, P5: 0 }
const novelDependsOn = tok => hypotheses.some(g =>
  (g.novelty === 'novel' || g.novelty === 'could-not-verify') && reqs(g).includes(tok))
const projectedEv = h => Number.isFinite(h.projected_ev) ? h.projected_ev : (TIER_RANK[h.projected_tier] || 0)
const evOf = h => {
  if (!bounty) return 0
  if (h.novelty === 'likely-duplicate' && !prov(h).some(novelDependsOn)) return 0   // $0 duplicate leaf
  return projectedEv(h)
}

const done = new Set(); const allRows = []; let wave = 0

// gap D — SIBLING COLLECTION (attack->recon feedback). Operators surface adjacent exploitable surfaces they
// saw mid-proof in candidate.sibling_hypotheses[]. We fold them across every wave, give each a STABLE synthetic
// id (hs-N, deduped by class|host|why so the same sibling seen twice is one id and `done` prevents double-attack),
// and feed them to BOTH the chain-builder (as combinable leads) and the rechain layer (re-attacked as composites).
// This is organic finding growth from the whole fleet, not just the chain-builder's top-down composites.
const _siblingIds = new Map()
function collectSiblings() {
  const byId = new Map()
  for (const r of allRows.filter(Boolean)) {
    const sibs = (r.candidate && Array.isArray(r.candidate.sibling_hypotheses)) ? r.candidate.sibling_hypotheses : []
    for (const s of sibs) {
      if (!s || !s.class || !s.host) continue
      const key = `${s.class}|${s.host}|${(s.why || '').slice(0, 60)}`.toLowerCase()
      if (!_siblingIds.has(key)) _siblingIds.set(key, `hs-${_siblingIds.size + 1}`)
      const id = _siblingIds.get(key)
      if (byId.has(id)) continue
      byId.set(id, { id, class: s.class, host: s.host, why: s.why || '', how_to_prove: s.how_to_prove || s.why || '',
        requires: Array.isArray(s.requires) ? s.requires : [], provides: Array.isArray(s.provides) ? s.provides : [],
        stage: s.stage || 'foothold', combines: [r.hypothesis?.id].filter(Boolean), sibling_of: r.hypothesis?.id })
    }
  }
  return [...byId.values()]
}

// gap F — PARALLEL BREADTH-SWEEP (bounty mode only). A cheap FAST-tier, single-baseline wave over valid
// P4/P5 LEAF classes (open-redirect / CORS / subdomain-takeover / header-eligibility / info-disclosure) runs
// BEFORE the deep multi-trajectory chains, so a pile of payable lows is banked fast + in breadth instead of
// each one eating a strong multi-trajectory slot. Bounty rank = sum of accepted (every confirmed leaf counts).
// Fully gated on `bounty`: a non-bounty run never enters this block => byte-identical. a.breadth_sweep:false
// opts out even in bounty mode. Leaf classes rarely `provide` a token, so running them first never starves the
// foothold-first graph; any token they DO prove is added to `acquired` for the deep waves that follow.
const BREADTH_SLUGS = new Set(['open-redirect', 'cors', 'takeover', 'info-disclosure'])
const BREADTH_KW = /header|clickjack|spf|dmarc|dkim|\bcsp\b|hsts|cookie-flag|mixed-content|cache-control|eligible|open[- ]?redirect|subdomain[- ]?takeover|dangling/i
const isBreadth = h => { const s = resolveAttackSkill(h.class); return (s && BREADTH_SLUGS.has(s)) || BREADTH_KW.test(h.class || '') }
if (bounty && a.breadth_sweep !== false) {
  const sweep = scheduled.filter(h => !done.has(h.id) && ready(h) && isBreadth(h))
  if (sweep.length) {
    wave++
    phase('Breadth sweep (fast)')
    log(`breadth-sweep: ${sweep.length} valid-P4/P5 leaf hypotheses on FAST tier single-shot (bounty breadth; deep chains run after). breadth rank = sum accepted`)
    const sweepRows = await pipeline(
      sweep,
      (h) => agent(exploitMission(h, acquired), { label: `sweep:${h.id}`, phase: 'Breadth sweep (fast)', agentType: 'attack-operator', schema: CANDIDATE, ...modelFor('fast') }),
      (candidate, h) => verifyStage(candidate, h, wave)
    )
    sweep.forEach((h, i) => { if (!sweepRows[i]) sweepRows[i] = { hypothesis: h, candidate: null, status: 'blocked', blocked_reason: 'died' } })
    let banked = 0
    for (const r of sweepRows) {
      allRows.push(r); done.add(r.hypothesis.id)
      const won = r.status === 'confirmed' || (r.candidate && ['impact_proven', 'misconfig_proven'].includes(r.candidate.proven_state))
      if (won) prov(r.hypothesis).forEach(t => acquired.add(t))
      if (r.status === 'confirmed') { banked++; derivedCaps(r.hypothesis, r.candidate, r.oracle).forEach(t => { if (!acquired.has(t)) acquired.add(t) }) }
    }
    log(`breadth-sweep: ${banked}/${sweep.length} confirmed leaf findings banked before deep chains`)
  }
}

while (true) {
  const runnable = scheduled.filter(h => !done.has(h.id) && ready(h))
  if (!runnable.length) break                                   // converged; leftovers are blocked_on_prereq
  runnable.sort((x, y) => (unlockScore(y) - unlockScore(x)) || (evOf(y) - evOf(x)))   // foothold-first PRIMARY (unchanged); EV secondary (0 in non-bounty => identical ordering)
  wave++
  phase(`Exploit wave ${wave}`)
  log(`wave ${wave}: ${runnable.length} ready (${runnable.filter(h => unlockScore(h) > 0).length} unlockers); acquired={${[...acquired].join(',') || 'none'}}`)
  const waveRows = await pipeline(
    runnable,
    (h) => agent(exploitMission(h, acquired), { label: `exploit:${h.id}`, phase: `Exploit wave ${wave}`, agentType: 'attack-operator', schema: CANDIDATE, ...modelFor(a.model_tier) }),
    (candidate, h) => verifyStage(candidate, h, wave)
  )
  // a null return = terminal agent death (e.g. a safeguard refusal): NEVER filtered away — mark blocked:died (F2)
  runnable.forEach((h, i) => { if (!waveRows[i]) waveRows[i] = { hypothesis: h, candidate: null, status: 'blocked', blocked_reason: 'died' } })
  for (const r of waveRows) {
    allRows.push(r); done.add(r.hypothesis.id)
    const won = r.status === 'confirmed' ||
      (r.candidate && ['impact_proven', 'misconfig_proven'].includes(r.candidate.proven_state))
    if (won) prov(r.hypothesis).forEach(t => acquired.add(t))   // postconditions unlock the next wave
    // gap B — a CONFIRMED finding also mints the capability its proven impact implies (shell/session/admin),
    // so a web RCE/ATO in this wave unlocks the post-foothold/infra dependents in the SAME cascading loop.
    if (r.status === 'confirmed') derivedCaps(r.hypothesis, r.candidate, r.oracle).forEach(t => { if (!acquired.has(t)) { acquired.add(t); log(`derived capability ${t} from confirmed ${r.hypothesis.id} (${(r.candidate && r.candidate.type) || r.hypothesis.class})`) } })
  }
}
// ===== REFLECT stage (the missing Execute->Reflect->re-Execute loop) =========================
// Literature is blunt about this: an explicit Reflector that derives the FAILURE REASON and sharpens the
// next attempt roughly DOUBLES success (Red-MIRROR 33%->66%; RefPentester vuln-ID 87.5% vs 35.7%;
// CHYing's Advisor steps in "after consecutive failures"). We had Plan(chain-builder)->Execute(operator)->
// Verify(oracle) but NO reflect step: a not_reproduced hypothesis was just dropped to a lead. Now every
// ATTEMPTED-but-unproven lead gets ONE Advisor pass (clean context, reads the attempt artifacts) that
// either emits a SHARPENED retry or declares it genuinely exhausted; a sharpened retry runs ONE more
// attempt through the UNCHANGED oracle gate and can only UPGRADE a lead to confirmed, never downgrade.
// Bounded: a.reflect_rounds default 1 (0 => disabled => byte-identical); a.reflect_max caps fan-out.
const REFLECT = {
  type: 'object',
  properties: {
    verdict: { type: 'string', enum: ['retry', 'exhausted'], description: 'retry = a concrete sharper angle is worth one more oracle-gated shot; exhausted = the senior repertoire for this class is genuinely spent here' },
    failure_reason: { type: 'string', description: 'WHY the prior attempt did not reproduce — WAF/filter block, wrong param/sink, missing precondition/auth, wrong encoding, not actually vulnerable, deceptive/honeypot response, etc. Evidence-based, read from raw/attack-<id>/.' },
    sharpened_angle: { type: 'string', description: 'the ONE concrete different thing to try (new encoding/param-position/precondition/tool/chain). Empty if exhausted.' },
    how_to_prove: { type: 'string', description: 'the sharpened how-to-prove for the retry. Empty if exhausted.' },
  },
  required: ['verdict', 'failure_reason'],
}
function reflectMission(h, c) {
  return `${a.authorization || 'AUTHORIZED ENGAGEMENT.'}
You are the ADVISOR — a senior exploitation strategist doing REFLECTIVE VERIFICATION. An operator attempted
ONE hypothesis and did NOT reproduce it. Your job is NOT to attack; it is to read the attempt like a
tech-lead at a standup and decide the single highest-value next move: a sharper retry, or honestly dead.

HYPOTHESIS ${h.id}: class=${h.class} host=${h.host}
  why/signal: ${h.why}
  how it was meant to be proven: ${h.how_to_prove}
OPERATOR'S RESULT: ${JSON.stringify({ proven_state: c.proven_state, title: c.title, detail: (c.detail || '').slice(0, 600), note: c.note, evidence: c.evidence })}
READ the actual attempt artifacts under ${a.target_dir}/raw/attack-${h.id}/ (and any -<scaffold> subdirs) —
the real requests/responses, not the operator's summary. ${a.context_pack ? 'Also consult ' + a.context_pack + '.' : ''}
Run \`python tools/recall.py --target-dir ${a.target_dir} --class ${h.class} --host ${h.host}\` for what
already worked / already failed here, so you don't send the operator back down a recorded dead-end.

DERIVE THE FAILURE REASON from the evidence (Evidence -> Hypothesis -> Verification discipline — no blind
guessing): was it a WAF/filter block (-> wafrift evolutionary bypass), a wrong param/sink, a missing
precondition/auth (-> which capability to acquire first), a wrong encoding/content-type, a response that
LIES (honeypot/fabricated-success — treat as not-vulnerable), or is the class genuinely not present here?
Then decide: verdict:'retry' with ONE concrete sharpened_angle + how_to_prove, OR verdict:'exhausted' if
the senior repertoire for ${h.class} is truly spent. Do NOT propose defeating a safeguard. Be decisive:
a retry costs one more oracle-gated shot, so only propose it when the evidence points at a real different path.
Return the schema. Your return value IS data.`
}
const reflectRounds = Number.isInteger(a.reflect_rounds) ? a.reflect_rounds : 1
const reflectMax = Number.isInteger(a.reflect_max) ? a.reflect_max : 16
let reflected = 0, reflectProven = 0
// #4 — ITERATIVE reflect rounds (CHYing's "Advisor steps in again after consecutive failures"). The loop
// recomputes the not-reproduced lead set each round, so a sharpened retry that STILL fails gets a fresh
// Advisor read (on its new attempt artifacts) next round — up to reflect_rounds passes per lead. An
// Advisor 'exhausted' verdict retires a lead for good; an upgrade removes it from the pool. Default
// reflect_rounds=1 => exactly one pass => identical to the single-pass behaviour.
if (reflectRounds > 0) {
  for (let rRound = 1; rRound <= reflectRounds; rRound++) {
    const phaseName = reflectRounds > 1 ? `Reflect round ${rRound}` : 'Reflect'
    const leadsToReflect = allRows
      .filter(r => r.status === 'lead' && !r.__reflectExhausted && r.candidate && r.candidate.proven_state === 'not_reproduced')
      .sort((x, y) => (SEV.indexOf(y.candidate.severity || 'info') - SEV.indexOf(x.candidate.severity || 'info')) || (evOf(y.hypothesis) - evOf(x.hypothesis)))
      .slice(0, reflectMax)
    if (!leadsToReflect.length) break
    phase(phaseName)
    log(`reflect${reflectRounds > 1 ? ` round ${rRound}/${reflectRounds}` : ''}: ${leadsToReflect.length} attempted-but-unproven leads get an Advisor pass (failure reason -> sharpened retry or exhausted; ~2x proven in the literature)`)
    const reflectResults = await pipeline(
      leadsToReflect,
      (r) => agent(reflectMission(r.hypothesis, r.candidate), { label: `reflect:${r.hypothesis.id}:r${rRound}`, phase: phaseName, agentType: 'advisor', schema: REFLECT, ...modelFor(a.model_tier) }),
      (adv, r) => {
        if (!adv || adv.verdict !== 'retry') { r.__reflectExhausted = true; return Promise.resolve({ row: r, retryRow: null }) }
        const hint = `failure reason: ${adv.failure_reason}${adv.sharpened_angle ? `\nsharper angle: ${adv.sharpened_angle}` : ''}${adv.how_to_prove ? `\nsharpened how-to-prove: ${adv.how_to_prove}` : ''}`
        return agent(exploitMission(r.hypothesis, acquired, null, hint), { label: `reflect-retry:${r.hypothesis.id}:r${rRound}`, phase: phaseName, agentType: 'attack-operator', schema: CANDIDATE, ...modelFor(a.model_tier) })
          .then(cand => verifyStage(cand, r.hypothesis, wave))
          .then(retryRow => ({ row: r, retryRow }))
      }
    )
    for (const x of (reflectResults || []).filter(Boolean)) {
      reflected++
      if (x.retryRow && x.retryRow.status === 'confirmed') {
        const idx = allRows.indexOf(x.row)
        if (idx >= 0) allRows[idx] = x.retryRow; else allRows.push(x.retryRow)
        reflectProven++
        prov(x.retryRow.hypothesis).forEach(t => acquired.add(t))
        derivedCaps(x.retryRow.hypothesis, x.retryRow.candidate, x.retryRow.oracle).forEach(t => { if (!acquired.has(t)) acquired.add(t) })
        log(`reflect: ${x.row.hypothesis.id} UPGRADED lead->confirmed after Advisor sharpening (round ${rRound})`)
      } else if (x.retryRow && x.retryRow.status === 'refuted') {
        const idx = allRows.indexOf(x.row); if (idx >= 0) allRows[idx] = x.retryRow   // oracle/skeptic rejected the retry; it leaves the reflect pool
      }
      // else: retry still not_reproduced (status 'lead') — keep the original lead, re-reflectable next round
    }
  }
  log(`reflect: ${reflected} Advisor pass(es), ${reflectProven} upgraded lead->confirmed (reflect_rounds=${reflectRounds}, cap=${reflectMax}/round)`)
}

const blockedOnPrereq = scheduled.filter(h => !done.has(h.id))         // dependents whose prereq was never proven (over the scheduled set; ineligible_leads were never scheduled)
const stalledCaps = [...new Set(blockedOnPrereq.flatMap(reqs).filter(t => !acquired.has(t)))]

const rows = allRows.filter(Boolean)
const confirmed = rows.filter(r => r.status === 'confirmed').map(r => ({ ...r.candidate, severity: r.severity, verified: true, refuted: false, oracle_type: r.oracle?.oracle_type, oracle_evidence: r.oracle?.oracle_evidence }))
const candidates = rows.filter(r => r.status !== 'confirmed' && r.status !== 'blocked' && r.candidate && r.candidate.proven_state && !['not_reproduced', 'blocked'].includes(r.candidate.proven_state)).map(r => r.candidate)
const leads = rows.filter(r => r.status === 'lead').map(r => r.hypothesis)
const blockedRows = rows.filter(r => r.status === 'blocked')

// P1 — coarse distance-to-objective ladder + terminal flag state. Brain decides the next move; synthesizer persists.
const flagRe = a.objective?.flag_format ? new RegExp(a.objective.flag_format) : null
const flagHit = confirmed.find(c => c.oracle_type === 'flag-capture') ||
  (flagRe ? confirmed.find(c => flagRe.test(c.execution_evidence || '') || flagRe.test(c.detail || '')) : null)
const hasReadRce = confirmed.some(c => /rce|file[- ]?read|read-file|traversal|command|sqli/i.test(`${c.type} ${c.title}`))
const hasFoothold = [...acquired].some(t => /^(session|creds|foothold|admin):/.test(t))
const distance = flagHit ? 'flag' : hasReadRce ? 'file-read-or-rce' : hasFoothold ? 'foothold'
  : hypotheses.length ? 'recon' : 'unauth'
// fix3 B1 — bounty impact-side distance rung (the eligible/payable/dedup rungs + status payable|dry are
// SYNTHESIS-level verdicts; attack reports only the B2-ladder rungs it can prove this wave). `bounty` is
// defined above. flag and bounty are mutually exclusive by mode, so the flag/impact branch below is
// reached only when NOT bounty => byte-identical to today.
const bDistance = !bounty ? null
  : confirmed.length ? 'impact-proven'
  : candidates.length ? 'reproduced'
  : 'signal'   // fix3 audit #8: floor to the lowest B2 bounty-ladder rung ('unauth' is the impact/flag vocab)
const objective = bounty ? {
  mode: 'bounty',
  status: stalledCaps.length ? 'blocked' : 'open',   // payable/dry/submitted/paid are decided at synthesis
  distance: bDistance,
  blocked_reason: stalledCaps.length ? 'needs-foothold' : '',
} : (a.objective && a.objective.mode === 'flag') ? {
  // flag mode only. impact (the default) and an absent objective are EQUIVALENT (docs: absent === {mode:'impact'})
  // => objective stays undefined => the attack return + state.json.objective are byte-identical to pre-fix1 (fix3 audit #4).
  mode: 'flag',
  status: flagHit ? 'captured' : (stalledCaps.length ? 'blocked' : 'open'),
  flag: flagHit ? (flagRe ? (flagHit.execution_evidence || '').match(flagRe)?.[0] || '' : '') : '',
  evidence: flagHit ? (flagHit.oracle_evidence || flagHit.evidence || '') : '',
  distance,
  blocked_reason: (!flagHit && stalledCaps.length) ? 'needs-foothold' : '',
} : undefined
if (objective?.status === 'captured') log(`OBJECTIVE CAPTURED: flag re-derivable from ${objective.evidence} — terminal`)
else if (bounty) log(`bounty impact-side distance=${bDistance}; payable/dry decided at synthesis`)
else if (a.objective?.mode === 'flag') log(`objective distance=${distance}; status=${objective.status}`)

// F2 — a blocked/died attempt is a HAND-OFF, never a silent lead; every blocked path + every
// unmet-prereq dependent goes to the human-review queue the brain raises before final synthesis.
const human_review = [
  ...blockedRows.map(r => ({ id: r.hypothesis?.id, class: r.hypothesis?.class, reason: `blocked:${r.blocked_reason}`, what_it_attempted: r.hypothesis?.how_to_prove, evidence: `raw/attack-${r.hypothesis?.id}/` })),
  ...blockedOnPrereq.map(h => ({ id: h.id, class: h.class, reason: 'needs-foothold', what_it_attempted: h.how_to_prove, evidence: `raw/attack-${h.id}/` })),
]

log(`attack done: ${confirmed.length} confirmed, ${candidates.length} unconfirmed candidates, ${leads.length} leads, ${blockedRows.length} blocked, ${blockedOnPrereq.length} blocked_on_prereq (${hypotheses.length} hypotheses, ${wave} waves)`)
if (stalledCaps.length) log(`STALLED on capabilities no hypothesis could prove: ${stalledCaps.join(', ')} — operator session-inject (/spider resume-with-session) or manual-PoC may be needed`)

// --- Chain stage: combine findings into kill chains + propose composite hypotheses for the next round ---
const CHAINS = {
  type: 'object',
  properties: {
    chains: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          name: { type: 'string' },
          end_impact: { type: 'string', description: 'what the full chain achieves (ATO / RCE / full data read / cloud takeover)' },
          severity: { type: 'string', enum: SEV },
          steps: { type: 'array', items: { type: 'string' }, description: 'ordered links: entry -> escalation -> objective' },
          uses: { type: 'array', items: { type: 'string' }, description: 'finding/candidate/lead ids or asset refs this chain combines' },
          status: { type: 'string', enum: ['proven', 'needs_proof'] },
        },
        required: ['name', 'steps', 'end_impact'],
      },
    },
    composite_hypotheses: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string', description: 'hc-NN' },
          class: { type: 'string' },
          host: { type: 'string' },
          why: { type: 'string', description: 'which findings/signals combine, and the theory' },
          how_to_prove: { type: 'string' },
          combines: { type: 'array', items: { type: 'string' }, description: 'finding/candidate/lead ids this draws on (evidence lineage — distinct from requires)' },
          stage: { type: 'string', description: 'foothold | post-foothold' },
          requires: { type: 'array', items: { type: 'string' }, description: 'capability tokens the next round must PROVE before firing this (runtime gate; grammar in brain/schema.md)' },
          provides: { type: 'array', items: { type: 'string' }, description: 'capability tokens this grants if proven' },
          projected_tier: { type: 'string', description: 'fix3 B5 (OPTIONAL, bounty): the END-impact reward tier this composite would reach if proven (P1..P5)' },
          projected_ev: { type: 'number', description: 'fix3 B5 (OPTIONAL, bounty): the END-impact expected value; a composite is worth proposing only when chain-EV > sum of its legs EV' },
        },
        required: ['id', 'class', 'host', 'why', 'how_to_prove'],
      },
    },
    note: { type: 'string' },
  },
  required: ['chains'],
}
// fix3 B5 — payout-aware chain block (mode-gated; '' in impact/flag). Combine toward the highest-paying
// ELIGIBLE end-impact; a chain is paid at its END-impact tier, not the sum of legs.
const payoutChainBlock = (a.objective?.mode === 'bounty') ? `
BOUNTY MODE — combine toward the highest-paying ELIGIBLE end-impact. A chain is rated and paid at its
END-impact tier (Bugcrowd's "unusual/combined impact" rule), NOT the sum of its legs, so a chain of
mediums that reaches ATO/RCE is a top-tier payout. For each composite set projected_tier/projected_ev of
the END impact and ORDER composite_hypotheses by projected EV. Only propose a composite when its chain-EV
EXCEEDS the sum of its legs' EV (it is worth chaining). The tier is bound by the chain's PROVEN end impact
— never assert a tier to reach a payout, never inflate severity for a pay floor.
` : ''

phase('Chain')
// gap A — recomputed each chain round so iterative deepening sees the capabilities/confirmed that the
// previous re-attack round gained (not a stale first-round view). Reads the LIVE allRows/acquired/attempted.
function snapshot() {
  const rws = allRows.filter(Boolean)
  const bop = attempted.filter(h => !done.has(h.id))
  return {
    confirmed: rws.filter(r => r.status === 'confirmed').map(r => ({ id: r.candidate.hypothesis_id, type: r.candidate.type, severity: r.severity, title: r.candidate.title, detail: (r.candidate.detail || '').slice(0, 300) })),
    candidates: rws.filter(r => r.status !== 'confirmed' && r.status !== 'blocked' && r.candidate && r.candidate.proven_state && !['not_reproduced', 'blocked'].includes(r.candidate.proven_state)).map(r => ({ id: r.candidate.hypothesis_id, type: r.candidate.type, title: r.candidate.title, proven_state: r.candidate.proven_state })),
    leads: rws.filter(r => r.status === 'lead').map(r => ({ id: r.hypothesis.id, class: r.hypothesis.class, host: r.hypothesis.host, why: r.hypothesis.why })),
    acquired_capabilities: [...acquired],
    blocked_on_prereq: bop.map(h => ({ id: h.id, class: h.class, missing: reqs(h).filter(t => !acquired.has(t)) })),
    stalled_on: [...new Set(bop.flatMap(reqs).filter(t => !acquired.has(t)))],
    objective: a.objective || null,   // P1: in flag mode the composites aim at the objective
    program: a.program || null,       // fix3 B1: in bounty mode the composites aim at the highest-paying eligible end-impact
    // gap D — adjacent surfaces the fleet surfaced mid-proof; the chain-builder may combine them into a chain
    // or keep them as standalone composites. Conditionally included so the brief stays byte-identical when none.
    ...(siblings => siblings.length ? { sibling_hypotheses: siblings.map(s => ({ id: s.id, class: s.class, host: s.host, why: s.why, sibling_of: s.sibling_of })) } : {})(collectSiblings()),
  }
}
async function runChainBuilder(round) {
  const brief = snapshot()
  const res = await agent(
  `${a.authorization || 'AUTHORIZED ENGAGEMENT.'}
You are a senior exploitation lead (ROUND ${round}). Individually these findings may be medium/low — your job is to
combine them into CRITICAL kill chains and to propose COMPOSITE hypotheses worth a next attack round.
This is how seniors turn 5 mediums into one account-takeover / full-data-read.

FINDINGS THIS ROUND:
${JSON.stringify(brief, null, 0)}
Also read ${a.target_dir}/state.json (world model + all hypotheses) and skim ${a.target_dir}/raw/ for evidence.
SCOPE: ${JSON.stringify(a.scope || {}, null, 0)}

Think in real chains: info-disclosure+IDOR→ATO; SSRF→metadata→cloud creds→data; CORS+credentials→ATO;
subdomain-takeover→cookie/session; open-redirect→OAuth token theft; secret-leak→auth→privilege.
For each plausible chain give the ordered steps, which findings/leads it uses, the end impact and
severity, and whether it is already proven or needs one more proof step. Then emit composite
hypotheses (hc-NN) that the next attack round should try to prove — concrete, with how_to_prove,
and each carrying its stage/requires/provides (the dependency grammar in brain/schema.md).

DEPENDENCY-AWARE PRIORITY: brief.stalled_on lists capability tokens that NO hypothesis this round could
prove, which is why dependents (brief.blocked_on_prereq) never fired. Your highest-value move is to
propose a FOOTHOLD-PRODUCER composite (stage:"foothold", provides:[the stalled token]) that opens that
exact door by a LEGITIMATE path — never by evading a safeguard. If the only way to that token is an
auth-crack an operator must do by hand or a session they must supply, say so in note (do not propose the
crack). Composites that need a token still carry it in requires so the scheduler stages them correctly.
OBJECTIVE (P1): if brief.objective is set (flag mode), your highest-value composite is the one that reaches
objective.goal — make the last-mile capture explicit (a foothold:<host> that yields a readable artifact →
a class:objective-capture composite, stage:post-foothold, requires:["foothold:<host>"], that pulls and
extracts the flag locally). POST-FOOTHOLD (P4): if this round acquired a shell:<host>/foothold:<host>
token, your highest-value composites are the post-foothold chain on that host: internal-recon → privesc
(provides admin:<host>) → loot the objective (feeds the P1 objective oracle) → bounded lateral to in-scope
neighbours. Carry each one's stage/requires/provides so the scheduler stages them.
CRED-REUSE & ESCALATION (iteration 2 — don't stop at the first foothold): if this round acquired a
creds:<p>@<hostA> / session:<host> / token:<name> capability, your next-highest composites are (a) a
cred-reuse control-test of the SAME principal on every OTHER in-scope host that offers that auth
(class:cred-reuse, host:<hostB>, requires:["creds:<p>@<hostA>"], provides:["session:<hostB>"] — gated on
policies.default_cred_control_test; this is the lateral multiplier), and (b) a class:escalation-ladder
composite (requires:[the held token]) that climbs to the highest ELIGIBLE impact the identity/host unlocks
(ATO, privileged action, a single scoped cloud read). Propose these ONLY toward in-scope hosts; an
out-of-scope reachable host stays a lead. Never propose an auth-crack an operator must do by hand — say so
in note instead.${payoutChainBlock}
Return the schema. Your return value IS data.`,
  { label: round > 1 ? `chain-builder:r${round}` : 'chain-builder', phase: 'Chain', agentType: 'chain-builder', schema: CHAINS, ...modelFor(a.model_tier) }
  )
  return { chains: res?.chains || [], composite: res?.composite_hypotheses || [] }
}

// gap A — accumulate chains/composites across deepening layers for the return value.
const chains = []
let composite = []

// ===== fix(#2): bounded, CODE-FORCED composite RE-ATTACK loop ================================
// The chain stage already emits composite_hypotheses (how mediums join into a critical, and which
// foothold-producer composite opens a stalled door). Pre-fix, re-feeding them into another attack round
// was brain/spider.md PROSE only — and empirically never fired (ok.ru: 0 hc-* ever written back). This
// runs it IN-SCRIPT through the SAME wave scheduler + the UNCHANGED oracle/skeptic verify gate, so a
// medium+medium chain is actually proven to a crit inside one workflow. Default 1 bounded round;
// a.max_rechain_rounds:0 restores the pre-fix behaviour exactly. A composite only fires when its
// `requires` are already in `acquired` (never a dead PoC); the safeguard red line is untouched.
const unlockScoreIn = (h, universe) => { const mine = new Set(prov(h)); let s = 0
  for (const g of universe) if (g !== h && reqs(g).some(t => mine.has(t))) s++; return s }
// crit-roadmap #4 — pick the strongest candidate across a hypothesis's trajectories to feed the UNCHANGED
// verify gate: impact_proven > misconfig_proven > blocked(hand-off) > not_reproduced; ties by severity.
const _rank = c => (!c ? -1 : c.proven_state === 'impact_proven' ? 3 : c.proven_state === 'misconfig_proven' ? 2 : c.proven_state === 'blocked' ? 1 : 0)
function pickBest(cands) {
  const live = (cands || []).filter(Boolean)
  if (!live.length) return null
  const proven = live.filter(c => c.proven_state && !['not_reproduced', 'blocked'].includes(c.proven_state))
  const pool = proven.length ? proven : live
  pool.sort((x, y) => (_rank(y) - _rank(x)) || (SEV.indexOf(y.severity || 'info') - SEV.indexOf(x.severity || 'info')))
  return pool[0]
}
async function runWaveLoop(pool, universe, waveStart, phaseLabel) {
  let w = waveStart
  while (true) {
    const runnable = pool.filter(h => !done.has(h.id) && ready(h))
    if (!runnable.length) break
    runnable.sort((x, y) => (unlockScoreIn(y, universe) - unlockScoreIn(x, universe)) || (evOf(y) - evOf(x)))
    w++
    phase(`${phaseLabel} wave ${w}`)
    log(`${phaseLabel} wave ${w}: ${runnable.length} ready (${runnable.filter(h => unlockScoreIn(h, universe) > 0).length} unlockers); acquired={${[...acquired].join(',') || 'none'}}; trajN=${trajN}`)
    const waveRows = await pipeline(
      runnable,
      // crit-roadmap #4 — attack each hypothesis from up to trajN heterogeneous angles in parallel; the FIRST
      // is the baseline (null scaffold = today's mission). #6 tie-in: a known $0-duplicate leaf runs a single
      // baseline shot (don't spend diverse trajectories proving a duplicate). Then pick the strongest candidate.
      (h) => {
        const isDupLeaf = bounty && h.novelty === 'likely-duplicate' && evOf(h) === 0
        const lineup = isDupLeaf ? [null] : SC.slice(0, trajN)
        return parallel(lineup.map(s => () =>
          agent(exploitMission(h, acquired, s), { label: `exploit:${h.id}${s ? ':' + s.key : ''}`, phase: `${phaseLabel} wave ${w}`, agentType: 'attack-operator', schema: CANDIDATE, ...modelFor(a.model_tier) })
            .then(c => c ? { ...c, scaffold: s ? s.key : 'baseline' } : null)
        )).then(pickBest)
      },
      (candidate, h) => verifyStage(candidate, h, w)
    )
    runnable.forEach((h, i) => { if (!waveRows[i]) waveRows[i] = { hypothesis: h, candidate: null, status: 'blocked', blocked_reason: 'died' } })
    for (const r of waveRows) {
      allRows.push(r); done.add(r.hypothesis.id)
      const won = r.status === 'confirmed' || (r.candidate && ['impact_proven', 'misconfig_proven'].includes(r.candidate.proven_state))
      if (won) prov(r.hypothesis).forEach(t => acquired.add(t))
      if (r.status === 'confirmed') derivedCaps(r.hypothesis, r.candidate, r.oracle).forEach(t => { if (!acquired.has(t)) { acquired.add(t); log(`derived capability ${t} from confirmed ${r.hypothesis.id}`) } })
    }
  }
  return w
}
const maxRechain = Number.isInteger(a.max_rechain_rounds) ? a.max_rechain_rounds : 2   // gap A: default 2 = one iterative-deepening pass (re-attack -> re-chain on the new world -> re-attack). 1 = single round (pre-A behaviour). 0 = no re-attack. Early-stop guards cost: a round only deepens if it PROVED something.
const attempted = [...scheduled]                 // everything the scheduler was handed (grows with accepted composites)
let rechainRounds = 0
const composite_confirmed = []
{
  const first = await runChainBuilder(1)
  chains.push(...first.chains); composite.push(...first.composite)
  log(`chain-builder: ${first.chains.length} chains, ${first.composite.length} composite hypotheses for the next round`)
  if (maxRechain <= 0) {
    log(`rechain disabled (max_rechain_rounds=0) — ${composite.length} composites returned for the brain to re-feed via /chain`)
  } else {
    let layer = [...first.composite, ...collectSiblings()]   // chain-builder composites + gap D siblings; `done` + the requires-gate dedup/stage them
    for (let round = 1; round <= maxRechain; round++) {
      const pool = (layer || [])
        .filter(c => c && c.id && !done.has(c.id) && (Array.isArray(c.requires) ? c.requires : []).every(t => acquired.has(t)))
        .map(c => ({ id: c.id, class: c.class, host: c.host, why: c.why, how_to_prove: c.how_to_prove, stage: c.stage, requires: Array.isArray(c.requires) ? c.requires : [], provides: Array.isArray(c.provides) ? c.provides : [], projected_tier: c.projected_tier, projected_ev: c.projected_ev }))
      if (!pool.length) { log(round === 1 ? `rechain: no READY composite hypotheses to re-attack (each needs an unproven prereq, or none were produced) — the stalled door needs an operator foothold` : `rechain ${round}: no further ready composites — stop deepening`); break }
      pool.forEach(h => attempted.push(h))
      log(`rechain ${round}/${maxRechain}: re-attacking ${pool.length} ready composite hypotheses through the oracle gate (code-forced — this is how mediums become an oracle-proven critical)`)
      const before = allRows.filter(r => r.status === 'confirmed').length
      wave = await runWaveLoop(pool, [...hypotheses, ...attempted], wave, `Re-attack ${round}`)
      rechainRounds = round
      const proven = allRows.filter(r => r.status === 'confirmed').slice(before)
      proven.forEach(r => { if (r.hypothesis?.id) composite_confirmed.push(r.hypothesis.id) })
      if (!proven.length) { log(`rechain ${round}: no new oracle-proven composite — stop deepening`); break }   // gap A cost guard: deepen only when the round paid off
      if (round < maxRechain) {                   // gap A — re-chain on the UPDATED world (new caps + new confirmed) to propose the next layer
        const next = await runChainBuilder(round + 1)
        chains.push(...next.chains); composite.push(...next.composite); layer = [...next.composite, ...collectSiblings()]   // + any siblings surfaced during this round's re-attack
        log(`rechain ${round}: proved ${proven.length}; re-chained on the updated world -> ${next.composite.length} next-layer composite(s)`)
      }
    }
  }
}

// ===== FINAL aggregates (over the full allRows incl. any re-attack rounds) =====================
const rowsF = allRows.filter(Boolean)
const confirmedF = rowsF.filter(r => r.status === 'confirmed').map(r => ({ ...r.candidate, severity: r.severity, verified: true, refuted: false, oracle_type: r.oracle?.oracle_type, oracle_evidence: r.oracle?.oracle_evidence }))
const candidatesF = rowsF.filter(r => r.status !== 'confirmed' && r.status !== 'blocked' && r.candidate && r.candidate.proven_state && !['not_reproduced', 'blocked'].includes(r.candidate.proven_state)).map(r => r.candidate)
const leadsF = rowsF.filter(r => r.status === 'lead').map(r => r.hypothesis)
const blockedRowsF = rowsF.filter(r => r.status === 'blocked')
const blockedOnPrereqF = attempted.filter(h => !done.has(h.id))
const stalledCapsF = [...new Set(blockedOnPrereqF.flatMap(reqs).filter(t => !acquired.has(t)))]
// gap D — un-attacked siblings + un-attacked chain-builder composites both carry forward for the brain to
// re-feed next round (so a sibling the in-script rechain could not reach is still persisted as a hypothesis,
// not lost). Deduped by id; a sibling already attacked this run is in `done` and drops out.
const siblings_out = collectSiblings().filter(s => !done.has(s.id))
const composite_out = [...(composite || []), ...siblings_out].filter((c, i, arr) => c && c.id && !done.has(c.id) && arr.findIndex(x => x.id === c.id) === i)

// objective/distance recomputed over the post-rechain world (flag may have been captured in a re-attack round)
const flagReF = a.objective?.flag_format ? new RegExp(a.objective.flag_format) : null
const flagHitF = confirmedF.find(c => c.oracle_type === 'flag-capture') ||
  (flagReF ? confirmedF.find(c => flagReF.test(c.execution_evidence || '') || flagReF.test(c.detail || '')) : null)
const hasReadRceF = confirmedF.some(c => /rce|file[- ]?read|read-file|traversal|command|sqli/i.test(`${c.type} ${c.title}`))
const hasFootholdF = [...acquired].some(t => /^(session|creds|foothold|admin):/.test(t))
const distanceF = flagHitF ? 'flag' : hasReadRceF ? 'file-read-or-rce' : hasFootholdF ? 'foothold' : hypotheses.length ? 'recon' : 'unauth'
const bDistanceF = !bounty ? null : confirmedF.length ? 'impact-proven' : candidatesF.length ? 'reproduced' : 'signal'
const objectiveF = bounty ? {
  mode: 'bounty', status: stalledCapsF.length ? 'blocked' : 'open', distance: bDistanceF, blocked_reason: stalledCapsF.length ? 'needs-foothold' : '',
} : (a.objective && a.objective.mode === 'flag') ? {
  mode: 'flag', status: flagHitF ? 'captured' : (stalledCapsF.length ? 'blocked' : 'open'),
  flag: flagHitF ? (flagReF ? (flagHitF.execution_evidence || '').match(flagReF)?.[0] || '' : '') : '',
  evidence: flagHitF ? (flagHitF.oracle_evidence || flagHitF.evidence || '') : '', distance: distanceF,
  blocked_reason: (!flagHitF && stalledCapsF.length) ? 'needs-foothold' : '',
} : undefined
if (objectiveF?.status === 'captured') log(`OBJECTIVE CAPTURED (post-rechain): flag re-derivable from ${objectiveF.evidence} — terminal`)

const human_reviewF = [
  ...blockedRowsF.map(r => ({ id: r.hypothesis?.id, class: r.hypothesis?.class, reason: `blocked:${r.blocked_reason}`, what_it_attempted: r.hypothesis?.how_to_prove, evidence: `raw/attack-${r.hypothesis?.id}/` })),
  ...blockedOnPrereqF.map(h => ({ id: h.id, class: h.class, reason: 'needs-foothold', what_it_attempted: h.how_to_prove, evidence: `raw/attack-${h.id}/` })),
]

// fix(#3, sandbox-safe): LOUD priming status. The senior-exemplar primer (a.exemplars) was consumed with
// a silent '' fallback (exploitMission), so a run with ZERO corpus-priming was indistinguishable from a
// healthy one. Scripts can't touch disk (brain runs tools/retrieve.py|prime.py and passes a.exemplars),
// so the code CANNOT fetch — but it CAN refuse to be silent. A zero-priming run is now flagged, loudly.
const _primedIds = (a.exemplars && typeof a.exemplars === 'object') ? Object.keys(a.exemplars).filter(k => Array.isArray(a.exemplars[k]) && a.exemplars[k].length) : []
const priming = {
  exemplars_injected: _primedIds.length,
  negatives_injected: (a.negatives && typeof a.negatives === 'object') ? Object.keys(a.negatives).filter(k => Array.isArray(a.negatives[k]) && a.negatives[k].length).length : 0,
  context_pack: a.context_pack || null,
  corpus_primed: _primedIds.length > 0,
}
log(priming.corpus_primed
  ? `PRIMING: ${priming.exemplars_injected} hypotheses carry senior exemplars; context_pack=${priming.context_pack || 'none'}`
  : `PRIMING: ZERO senior exemplars injected — this run is NOT corpus-primed. If brain/corpus/ exists, the brain skipped the localhost retrieve/prime step; treat this as a DEGRADED run, not a clean one.`)
log(`attack(final): ${confirmedF.length} confirmed, ${candidatesF.length} candidates, ${leadsF.length} leads, ${blockedRowsF.length} blocked, ${blockedOnPrereqF.length} blocked_on_prereq; ${rechainRounds} rechain round(s), ${composite_confirmed.length} composite(s) oracle-proven`)

return {
  phase: 'attack',
  target: a.target,
  hypotheses: hypotheses.length,
  waves: wave,
  rechain_rounds: rechainRounds,
  confirmed: confirmedF,
  candidates: candidatesF,
  leads: leadsF,
  chains,
  composite_hypotheses: composite_out,
  sibling_hypotheses: siblings_out, // gap D: adjacent surfaces the fleet surfaced mid-proof, not yet attacked — the synthesizer persists them as next-round hypotheses (organic growth)
  composite_confirmed,              // fix(#2): ids of composite hypotheses the re-attack round(s) proved
  priming,                          // fix(#3): senior-priming status (loud; corpus_primed=false => degraded run)
  reflect: { reflected, reflect_proven: reflectProven },   // Reflect stage: Advisor passes run + leads upgraded to confirmed

  objective: objectiveF,
  ineligible_leads,                 // fix3 B4: excluded-class hypotheses held as noted leads (never scheduled, never dropped). [] in non-bounty / no-program
  capabilities: [...acquired],
  blocked_on_prereq: blockedOnPrereqF.map(h => ({ id: h.id, class: h.class, stage: h.stage, missing: reqs(h).filter(t => !acquired.has(t)) })),
  stalled_on: stalledCapsF,
  blocked: blockedRowsF.map(r => ({ id: r.hypothesis?.id, class: r.hypothesis?.class, reason: r.blocked_reason, candidate: r.candidate })),
  human_review: human_reviewF,
  per_hypothesis: rowsF.map(r => ({ id: r.hypothesis?.id, class: r.hypothesis?.class, status: r.status, survived: !!r.survived })),
}
