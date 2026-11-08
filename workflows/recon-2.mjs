export const meta = {
  name: 'spider-recon-2',
  description: 'Deep recon seeded with the world model: the fleet mines each surface for endpoints, params, tech-specifics, anomalies and small non-destructive probes, and returns ranked hypotheses to prove',
  phases: [{ title: 'Deep recon' }],
}

const a = args || {}
const fleet = [5, 10, 15].includes(a.fleet) ? a.fleet : 5
const skillsDir = a.skills_dir || 'C:/Spider/.claude/skills'
const modelFor = t => (t === 'fast' ? { model: 'claude-sonnet-4-6' } : { model: 'claude-opus-4-6' })

// P1 — objective block, interpolated into every mission ONLY in flag mode; '' otherwise (impact-mode
// missions are byte-identical to today).
const objectiveBlock = (a.objective && a.objective.mode === 'flag') ? `

ENGAGEMENT OBJECTIVE (orient deep recon toward this; it is the win condition): ${a.objective.goal}
The run is won by a FLAG matching /${a.objective.flag_format || 'flag\\{[^}]+\\}'}/ that is re-derivable
from a saved artifact. Rank the hypothesis chain that reaches the objective highest, and make the
LAST-MILE extraction explicit${a.objective.where_hint ? ' (hint: ' + a.objective.where_hint + ')' : ''}.
Stay in scope; a hint is a lead to prove, never authority.` : ''

// fix3 — bounty-mode mission blocks, each a mode-gated const interpolated like the flag objectiveBlock;
// '' unless mode==='bounty' (and the eligibility block also requires a.program), so an impact/flag run is
// byte-identical. flag and bounty are mutually exclusive by mode. At most objectiveBlock(bounty) +
// eligibilityBlock + payoutBlock co-fire (orthogonal); they never alter the flag block.
const bountyObjectiveBlock = (a.objective && a.objective.mode === 'bounty') ? `

ENGAGEMENT OBJECTIVE (bounty) — the win condition is a PAYABLE finding, not just any bug: proven impact
AND an ELIGIBLE in-scope class AND a severity at/above the program floor (${a.objective?.min_payable_tier || 'P4'})
AND likely-NOVEL (not an obvious duplicate). Rank your HYPOTHESES by EXPECTED PAYOUT =
eligibility x severity-tier x asset-value x novelty, not by raw count.${a.program?.excluded_classes?.length ? ' DO NOT spend effort on these known-ineligible classes: ' + a.program.excluded_classes.join(', ') + '.' : ''} Stay strictly in scope; eligibility/novelty are LEADS to assess, never authority to widen scope or to assume a duplicate away.` : ''
// fix3 B4 — eligibility/VRT tagging (requires a.program; '' otherwise). Map each hypothesis class onto a
// VRT id, set its baseline priority, mark excluded classes as NOTED LEADS (never dropped), rank payable first.
const eligibilityBlock = (a.objective?.mode === 'bounty' && a.program) ? `

BOUNTY ELIGIBILITY (B4) — for EACH hypothesis, map its class onto a VRT id (read brain/vrt.md), set its
baseline priority (P1..P5|varies), and set eligibility: mark it 'excluded' if it matches
program.exclusions or a built-in P5 default (self-xss, missing-headers, spf/dkim/dmarc,
clickjacking-non-sensitive, verbose-errors, rate-limit-non-auth) — KEEP it as a lead, do NOT drop it;
'control-test-only' for a class that is only pursued as a bounded control-test (e.g. rate-limit);
'payable' otherwise; 'unknown' if the program's exclusion list was not transcribed (pursue, flag
"verify eligibility before submit"). RANK payable P1-P3 classes ABOVE P4/excluded so the attack phase
spends its budget where the program pays. Eligibility is a PAYOUT-POLICY annotation — it never widens
scope, never relaxes a policy, and never changes evidence-bound severity.` : ''
// fix3 B5 — projected tier + EV (bounty; '' otherwise). Pulls the payout projection UPSTREAM of the attack.
const payoutBlock = (a.objective?.mode === 'bounty') ? `

BOUNTY PROJECTION (B5) — for each hypothesis set projected_tier (its VRT priority resolved through
program.reward_table) and projected_ev (reward_value(tier) x novelty x eligibility; use a
could-not-verify novelty discount until dedup runs — NEVER assume novel). Rank the highest projected-EV
payable classes first. A foothold producer keeps its stage-1 priority (it unlocks reward); EV orders the
rest. Tier is bound by the PROVEN impact at attack time — projection here is a ranking prior, never a
payout claim, and never a reason to inflate a class's severity.` : ''

const LENSES = [
  { key: 'param-mining', title: 'Parameter & input mining', modes: ['web'], jobs: 'discover hidden GET/POST/JSON params, injectable inputs, mass-assignment fields across the live endpoints in state.json' },
  { key: 'endpoint-deep', title: 'Endpoint & API deep-dive', modes: ['web', 'api'], jobs: 'enumerate API routes/versions, swagger/graphql schemas, undocumented actions, method/verb surface' },
  { key: 'api-discovery', title: 'API route discovery (kiterunner)', modes: ['api', 'web'], jobs: 'brute REST/API routes from Swagger/OpenAPI + kitebuilder wordlists with correct verbs/content-types (kiterunner `kr`); flag object-ref routes as IDOR/BOLA candidates — where the paid bugs live' },
  { key: 'graphql', title: 'GraphQL surface mapping', modes: ['api', 'web'], jobs: 'find GraphQL endpoints, fingerprint the engine (graphw00f), recover the schema even with introspection OFF (clairvoyance), and flag suspicious queries/mutations → emit class:graphql hypotheses' },
  { key: 'auth-flow', title: 'Auth & session mapping', modes: ['web', 'api'], jobs: 'map login/OAuth/JWT/session flows, roles, token shapes, password-reset and registration logic — where authz decisions live' },
  { key: 'otp-logic', title: 'OTP/2FA logic (non-brute foothold door)', jobs: 'when login gates behind an OTP/2FA step (e.g. a 409/200 -> POST /verify|/otp|/login2 flow), inspect the LOGIC, never the code space. (1) LEAK: read the pre-OTP response — body + headers + Set-Cookie — and any /resend|/me|/refresh follow-up for the code itself or a pending/mfa/otp_token the verify endpoint would accept. (2) BINDING: does the verify request carry a CLIENT-controlled account/user/username/verify field that can be repointed to a victim (PortSwigger broken-logic / WSTG "tied to the correct user account")? (3) PREDICTABLE/STATIC: request your OWN code twice (own account, within policy caps) and diff — identical, sequential, or constant-seeded = predictable. (4) ENFORCEMENT/simple-bypass: after the gate, request a post-login page directly — authed content without the code = step not enforced server-side. (5) REUSE: is a used/expired code still accepted. (6) LOOSE-COMPARE: note numeric-vs-string / leading-zero / null / [] / "000000" handling for a SINGLE well-formed probe each. Emit stage:"foothold", class:"otp-logic", provides:["session:<host>"] hypotheses — a FOOTHOLD PRODUCER for the attack dependency graph. ORDERING: when the session is a server-signed cookie, rank leak/binding/predictable ABOVE client-side response-tampering (which fools only the SPA). NEVER brute the code space, NEVER flood, NEVER touch a safeguard-flagged path (e.g. a register-crash) — observation + logic only, policy-gated.' },
  { key: 'access-control', title: 'Access-control surface', modes: ['web', 'api'], jobs: 'identify object refs (IDs, UUIDs), tenant boundaries, admin vs user endpoints — candidate IDOR/BOLA/privilege surfaces (probe read-only, no exploitation yet)' },
  { key: 'tech-specific', title: 'Tech-specific enumeration', modes: ['web', 'network'], jobs: 'for each detected stack (CMS, framework, cloud, edge), enumerate its known-weak surfaces, default paths, version-specific exposures' },
  { key: 'cve-intel', title: 'CVE intelligence (stack -> prioritized exploitable CVEs)', modes: ['web', 'network', 'service'], jobs: 'for EACH detected product+version in state.json (httpx -tech-detect / webanalyze / server headers / JS framework versions), map it to a PRIORITIZED exploitable-CVE list: run bin/vulnx <product> <version> (enriches each CVE with EPSS + CISA-KEV flag + nuclei-template availability + public-exploit/HackerOne refs) and, for RU-stack/RU targets, python tools/ru-cve-lookup.py --product "<product>" (BDU FSTEC / cert.gov.ru — advisories the NVD mirror lags). Rank CISA-KEV first, then high EPSS, then template/PoC-exists, then version-match. Keep a disclosed-but-FIXED CVE as a VARIANT/regression seed (re-test on this build), not just a filter. Optionally confirm reachability with a SINGLE detect-only leashed nuclei run of the mapped template IDs (tools/leashed.sh — NOT exploitation). Emit one hypothesis per high-priority CVE: class = the CVE underlying vuln class (rce/deser/ssrf/sqli/ognl/auth-bypass/info-disclosure...) so it routes to the right attack pack, confidence high only for CISA-KEV/public-PoC on a matched version, how_to_prove naming the exact CVE + matched version + known exploitation path, and a seam {vulnx_cve,cve_kev,cve_epss,cve_template,cve_refs,note} so the attack phase seeds from the KNOWN CVE and hunts the un-fixed variant (variant analysis) instead of a blind scan. requires:[] for an unauth CVE; the session/role token if reachable only authenticated. vulnx/ru-cve-lookup/NVD/EPSS/KEV are PASSIVE public indices (no leash); only the optional detect nuclei step is target-facing. A CVE match is a LEAD — the attack phase proves the variant with a working PoC + oracle. This is the producer side of the cve-seeded attack trajectory + the seam.vulnx_cve attack already renders.' },
  { key: 'anomaly-hunt', title: 'Anomaly & behavior hunting', modes: ['web'], jobs: 'send small, safe, differential probes; note error leaks, verbose responses, timing/behavior anomalies, reflected inputs — signals worth a hypothesis' },
  { key: 'js-sink-mining', title: 'JS sink & taint-flow mining', modes: ['web'], jobs: 'taint-flow SAST over the RESTORED client-side JS that recon-1 js-secret-mining already pulled — read the reconstructed source tree under ' + (a.target_dir || 'targets/<t>') + '/raw/js-secret-mining/ (sourcemapper srcmap/ + webcrack wc/ output); if it is empty fall back to the raw bundles there, and note the reduced signal. Run the sink-pattern passes + taint-trace from the js-sink-mining skill (DOM-XSS innerHTML/document.write/dangerouslySetInnerHTML, eval-family, prototype-pollution __proto__ gadgets, postMessage handlers with no origin check, insecure jwt decode/verify, client-side SSRF from fetch(user-controlled), open-redirect location= sinks). For each confirmed source->sink path with no sanitizer between, emit a hypothesis: class xss|prototype-pollution|postmessage-xss|jwt|ssrf|open-redirect, confidence high only when the full path is in-hand, with the sink file:line AND the source step in how_to_prove so the attack-operator reproduces it without re-doing the analysis. Mostly requires:[] (DOM/client-side fires unauth); a sink reachable only behind login requires:["session:<host>"]. ALL work is LOCAL on files from recon-1 — zero target traffic, no leash. A grep hit without a verified taint source is a LEAD, not a finding — the attack phase proves it with a working PoC.' },
  { key: 'deep-source-trace', title: 'Deep source->sink taint tracing (grey-box)', modes: ['web'], jobs: 'Vulnhuntr-style WHOLE-TREE source->sink tracing over the RESTORED client-side source js-secret-mining recovered (' + (a.target_dir || 'targets/<t>') + '/raw/js-secret-mining/srcmap/ + wc/). Run the deterministic skeleton builder: python -I tools/source-trace.py ' + (a.target_dir || 'targets/<t>') + '/raw/js-secret-mining --json --min-confidence medium — it ranks attacker-SOURCE -> dangerous-SINK candidates (innerHTML/eval/__proto__/postMessage/jwt/fetch/location=) with sink file:line, back-traced source, sanitizer flag and class. Then do the Vulnhuntr LLM loop PER high/medium candidate: open the sink file, follow the chain across files (find call sites of the sink function, confirm an attacker-controlled arg flows in, walk back frame by frame until the FULL path is in-hand), and confirm NO effective sanitizer on the path. Emit a hypothesis ONLY for a COMPLETE path: class xss|prototype-pollution|postmessage-xss|jwt|ssrf|open-redirect, confidence:high only with the full path + no sanitizer, how_to_prove naming the source entry AND the sink file:line, and a seam {source,sink,trace,params,note} so the attack-operator starts at the proven primitive. Mostly requires:[] (DOM/client-side fires unauth); a sink behind login requires:["session:<host>"]. ALL LOCAL on recovered files — zero target traffic, no leash. A path missing its source or with an un-bypassable sanitizer is a LEAD (confidence:low, no seam), not a finding — the attack phase + dynamic-validate prove DOM execution live.' },
  { key: 'exposed-datastores', title: 'Exposed backups & data stores', modes: ['web', 'network'], jobs: 'hunt exposed .git/.env/backup files/source-maps, open object storage, unauthenticated data stores (Elastic/Mongo/Redis/Kibana/Jenkins), DB/admin panels — a high-value class (backups/DB access). Prove ACCESS minimally, never mass-exfil' },
  { key: 'waf-body-encoding', title: 'WAF/edge body-encoding surface', modes: ['web'], jobs: 'map where the WAF and origin disagree on request-body parsing: chunked TE vs CL, charset/content-type tricks, multipart boundary, double-encoding — the bypass surface' },
  { key: 'oauth-pkce', title: 'OAuth/OIDC flow mapping', modes: ['web', 'api'], jobs: 'map auth-code+PKCE flows, redirect_uri handling, state/nonce, token endpoints, open-redirect→token-theft surface (read the flow, do not exploit)' },
  { key: 'session-fixation', title: 'Session & CSRF surface', modes: ['web'], jobs: 'cookie flags (HttpOnly/Secure/SameSite), Set-Cookie on auth boundary, session fixation/rotation, CSRF token presence/binding, logout invalidation' },
  { key: 'smtp-protocol', title: 'SMTP/mail semantics (gated)', modes: ['network', 'service'], jobs: 'ONLY if scope policies.smtp_semantics_probe.enabled — via tools/leash-tcp.sh: MAIL FROM sender-spoof (SPF), RCPT TO user-enum, STARTTLS downgrade. If not enabled, report gated and skip. Never flood' },
  { key: 'nonhttp-cred-surface', title: 'Non-HTTP service & credential surface', modes: ['network', 'service'], jobs: 'for every non-HTTP service in state.json (ssh/ftp/smb/rdp/mysql/mssql/redis/vnc/telnet): fingerprint version + auth methods READ-ONLY (SSH: does it offer password auth? FTP/SMB: anonymous allowed? banner/realm), identify the product so the right SMALL default set applies, and emit class:<svc>-default-cred hypotheses (stage:foothold, provides:["creds:<p>@<host>","session:<host>","foothold:<host>","shell:<host>"]) with a concrete how_to_prove. NOTE: only services that yield OS command execution (ssh/telnet/rdp) provide shell:<host>; an app/db-only cred (mysql/redis/vnc) provides creds:/session:/foothold: but NOT shell:. Use nuclei network/default-login templates in PRE-CONDITION/detect mode and tools/guard.py-pinned banner grabs via tools/leash-tcp.sh. Do NOT attempt logins here — recon is read-only; the control-test runs in attack ONLY if scope policies.default_cred_control_test.enabled. A reachable non-HTTP service is a FOOTHOLD PRODUCER for the attack dependency graph.' },
  { key: 'post-foothold-recon', title: 'Post-foothold operations planner (read-only)', jobs: 'for every host in state.json that has a CREDIBLE foothold surface — a non-HTTP service that can yield a shell (ssh/telnet/rdp), an RCE/SSTI/command-injection/file-upload hypothesis, or a proven/operator-supplied session — emit the LATENT post-foothold plan as stage:"post-foothold" hypotheses the scheduler will fire ONLY once the foothold token is proven: (1) class:internal-recon requires:["shell:<host>"] (whoami/id, OS/kernel, SUID/sudo/caps/cron, writable paths, interesting files — READ-ONLY, linPEAS stealth profile); (2) class:privesc requires:["shell:<host>"] provides:["admin:<host>"] (ONE oracle-proven single-step escalation from a GTFOBins/LOLBAS/known-CVE misconfig); (3) class:loot requires:["shell:<host>"] OR ["foothold:<host>"] (read objective-relevant files/creds/keys; the flag usually lives behind the foothold); (4) class:lateral requires:["shell:<host>"] (enumerate reachable neighbours — pivot ONLY to in-scope hosts, new hosts are LEADS); (5) class:cred-reuse requires:["creds:<p>@<hostA>"] provides:["session:<hostB>"] — for EACH in-scope host/service (ssh/smb/rdp/db/web-login) that the SAME principal might authenticate on, plan a cred-reuse control-test (the attack phase runs it via tools/leash-cred.sh, spray-not-brute, ONLY if policies.default_cred_control_test.enabled); this is the lateral-movement multiplier a senior always checks. Also emit ONE class:escalation-ladder requires:["session:<host>"] per held web session/token as the "do not stop at foothold" planner (it routes to privesc/loot/identity-reuse in attack). If NO host has a foothold surface, emit NOTHING (a plain web target is unaffected). This lens is READ-ONLY: it PLANS, it does not run anything.' },
  { key: 'ctf-pwn-triage', title: 'CTF pwn — binary triage', modes: ['ctf-pwn'], jobs: 'for each pwn artifact under targets/<t>/artifacts (ELF/PE): file + checksec (RELRO/canary/NX/PIE) + strings + a ROPgadget inventory + the provided libc version, READ-ONLY. Characterise the bug surface (stack overflow via gets/read, format string, UAF/heap, win-function) and emit class:pwn-<bug> hypotheses with host=<challenges[].remote or name>, stage:post-foothold, requires:["artifact:<bin>@<chal>"], provides:["flag:<chal>"], a concrete how_to_prove (the technique: ret2win/ret2libc/ROP/fmt), and evidence. The flag is the objective. Do NOT write the exploit here.' },
  { key: 'ctf-rev-triage', title: 'CTF rev — binary understanding', modes: ['ctf-rev'], jobs: 'for each rev artifact (native ELF/PE, .NET, JVM, .pyc, wasm, UPX-packed): file + strings | grep the flag_format FIRST (quick win), detect packer/language, then a ghidra analyzeHeadless or radare2 "aaa; afl; pdf @ main" static pass to recover the key-check/flag logic, READ-ONLY. Emit class:rev-<what> hypotheses, requires:["artifact:<bin>@<chal>"], provides:["key:<name>@<chal>"] or ["flag:<chal>"], naming the exact check to invert and the recommended engine (ghidra decompile / radare2 / angr+z3 symbolic). Dynamic/emulation only on the provided local in-scope artifact.' },
  { key: 'ctf-crypto-triage', title: 'CTF crypto — scheme identification', modes: ['ctf-crypto'], jobs: 'read the provided crypto challenge (source .py/.sage, public key, params, ciphertext) OFFLINE. Identify the primitive + the weakness (RSA small-e/Wiener/common-modulus/ROCA/close-primes, weak DH, ECB/CBC padding oracle, LCG/PRNG, repeated-key XOR, classical cipher). Parse key params (RsaCtfTool --dumpkey). Emit class:crypto-<weakness> hypotheses, requires:["artifact:<params>@<chal>"], provides:["key:<name>@<chal>","plaintext:<name>@<chal>","flag:<chal>"], naming the exact attack (RsaCtfTool --attack <x>, or a pycryptodome/sympy/sage script) and the oracle = recovered plaintext matching flag_format. factordb/online lookups are OPT-IN egress of public params only.' },
  { key: 'ctf-forensics-triage', title: 'CTF forensics — artifact characterisation', modes: ['ctf-forensics'], jobs: 'characterise the forensic artifact READ-ONLY: pcap/pcapng (tshark -q -z io,phs + protocol hierarchy), memory image (volatility3 windows.info/banners to ID the OS build), disk image (file/mmls), or a blob (binwalk --signature). Emit a carve plan. A carve that yields a NESTED artifact is a FOOTHOLD PRODUCER: class:forensics-carve, stage:foothold, requires:["artifact:<dump>@<chal>"], provides:["artifact:<carved>@<chal>"]. A directly-extractable flag: provides:["flag:<chal>"]. Name the exact plugin/filter (volatility3 windows.pslist|netscan|filescan|dumpfiles|cmdline, tshark -Y <filter> --export-objects, foremost -t, bulk_extractor) + evidence.' },
  { key: 'ctf-stego-triage', title: 'CTF stego — carrier triage', modes: ['ctf-stego'], jobs: 'for each stego carrier (image/audio) LOCAL/OFFLINE: exiftool -a -u -g1 (metadata + anomalies), binwalk (appended/embedded files), then carrier-specific READ-ONLY detection — PNG/BMP: zsteg -a; JPEG/WAV/BMP/AU: steghide info (is data embedded?); note spectrogram/bit-plane leads for audio/visual. Emit class:stego-<carrier> hypotheses, requires:["artifact:<carrier>@<chal>"], provides:["key:<name>@<chal>" (passphrase) | "artifact:<extracted>@<chal>" | "flag:<chal>"], naming the extractor and whether a steghide passphrase recovery (stegseek rockyou) applies.' },
]

const HYPO_RESULT = {
  type: 'object',
  properties: {
    label: { type: 'string' },
    lens: { type: 'string' },
    status: { type: 'string' },
    assets: {
      type: 'array',
      items: { type: 'object', properties: {
        kind: { type: 'string' }, value: { type: 'string' }, host: { type: 'string' }, evidence: { type: 'string' },
      }, required: ['kind', 'value'] },
    },
    hypotheses: {
      type: 'array',
      items: { type: 'object', properties: {
        id: { type: 'string', description: 'h-<lens>-NN' },
        host: { type: 'string' },
        class: { type: 'string', description: 'IDOR|SSRF|SQLi|auth-bypass|SSTI|... ' },
        why: { type: 'string', description: 'the signal/anomaly that suggests it' },
        how_to_prove: { type: 'string', description: 'the concrete PoC the attack phase should attempt' },
        confidence: { type: 'string', description: 'high|medium|low' },
        evidence: { type: 'string', description: 'path under raw/ backing the signal' },
        stage: { type: 'string', description: 'foothold | post-foothold — foothold producers (login/SSH-cred/otp/auth-bypass) run first and unlock dependents' },
        requires: { type: 'array', items: { type: 'string' }, description: 'capability tokens that must be PROVEN before this can fire (precondition). [] = independent. Grammar in brain/schema.md (session:<host>, creds:<p>@<host>, token:<name>, foothold:<host>, admin:<host>)' },
        provides: { type: 'array', items: { type: 'string' }, description: 'capability tokens granted IF this reaches a proven state (the unlock/effect). [] = grants nothing' },
        fingerprint: { type: 'array', items: { type: 'string' }, description: 'OPTIONAL: tech-fingerprint tokens observed (framework/version/header/param/response-shape) to sharpen corpus retrieval. [] if none.' },
        // fix3 bounty-mode-only, ALL OPTIONAL (additive; absent on impact/flag ⇒ ignored):
        vrt: { type: 'string', description: 'fix3 B4: dotted VRT class id for this hypothesis class' },
        priority: { type: 'string', description: 'fix3 B4: VRT baseline priority P1..P5|varies (the class baseline)' },
        eligibility: { type: 'string', description: 'fix3 B4: payable | excluded | control-test-only | unknown (vs program.eligible/excluded_classes). An excluded class stays a LEAD, never dropped' },
        eligibility_reason: { type: 'string', description: 'fix3 B4: why this eligibility' },
        projected_tier: { type: 'string', description: 'fix3 B5: pre-attack reward-tier projection (VRT priority resolved via program.reward_table)' },
        projected_ev: { type: 'number', description: 'fix3 B5: pre-attack expected-value projection = reward_value(tier) x novelty x eligibility — a ranking prior, never a payout claim' },
        novelty: { type: 'string', description: 'fix3 B3: novel | likely-duplicate | could-not-verify (root-cause match vs priorart.json; could-not-verify is NEVER promoted to novel)' },
        novelty_ref: { type: 'string', description: 'fix3 B3: the matching disclosed ref if any' },
        novelty_reason: { type: 'string', description: 'fix3 B3: reason for the verdict' },
        dedup_source: { type: 'string', description: 'fix3 B3: which source resolved the verdict (hacktivity|nvd|ghsa|changelog|submitted-archive|context-pack)' },
      }, required: ['id', 'host', 'class', 'why', 'how_to_prove'] },
    },
    novelty_index: { type: 'array', items: { type: 'object', properties: { class: { type: 'string' }, component: { type: 'string' }, host: { type: 'string' }, verdict: { type: 'string' }, ref: { type: 'string' }, reason: { type: 'string' }, source: { type: 'string' } } }, description: 'fix3 B3 (OPTIONAL): per-(class,component) novelty verdicts the novelty-scout lens emits; aggregated into the return. Empty/absent on a plain run.' },
    proposed_modes: { type: 'array', items: { type: 'string' }, description: 'OPTIONAL (P2): engagement modes this lens\'s discoveries imply but the plan has not chosen (e.g. ssh:22 with password auth ⇒ "service"). Ignored if empty.' },
    proposed_ideas: { type: 'array', items: { type: 'string' }, description: 'OPTIONAL (P2): free-form suggestions the operator may fold in. Ignored if empty.' },
    note: { type: 'string' },
  },
  required: ['label', 'status', 'hypotheses'],
}

// P5 — interactive-protocol recon surface (held-socket exploitation). Added ONLY when the operator opted
// into interactive work, so a plain web/network run's lens set + bucketing are byte-for-byte unchanged.
if (a.scope?.policies?.interactive_protocol?.enabled) LENSES.push({
  key: 'interactive-surface', title: 'Interactive / stateful-protocol surface',
  jobs: 'for every non-HTTP STATEFUL service in state.json (pwn nc listeners, custom line/binary protocols, telnet/console, redis-RESP/mqtt/amqp consoles, game servers) AND every WebSocket endpoint: grab the opening banner/frames READ-ONLY (one-shot via tools/leash-tcp.sh — NO held socket in recon), judge whether the protocol is conversational (prompt/menu/handshake/verb-set), and emit class:interactive-<proto> hypotheses with a concrete CONVERSATION SKETCH in how_to_prove (opening prompt, verbs to try, suspected logic flaw: protocol state-machine auth-bypass / missing-authz command / format-string/overflow in a field / race over the socket). A conversation that GRANTS access is stage:foothold, provides:["session:<host>","foothold:<host>"]; a logic bug inside a service you must already hold is stage:post-foothold, requires:["session:<host>"]. Do NOT hold a socket or exploit here — recon is read-only; the held-socket exploit runs in attack ONLY if scope policies.interactive_protocol.enabled. A reachable stateful service is a FOOTHOLD PRODUCER for the attack dependency graph.' })

// rate-limit / lockout control audit. Added ONLY when the scope policy enables it (zero roster change
// otherwise — same conditional-push pattern as interactive-surface above), so a plain run is
// byte-identical. It is a bounded CONTROL-TEST (prove the ABSENCE of a control), not a brute-force: own
// test account only, capped, through the leash. Mirrors the smtp-protocol gated-probe precedent.
if (a.scope?.policies?.rate_limit_test?.enabled) LENSES.push({
  key: 'rate-limit-audit', title: 'Rate-limit / lockout control audit (gated)', modes: ['web', 'api'],
  jobs: 'ONLY if scope policies.rate_limit_test.enabled — demonstrate that a sensitive endpoint ' +
    '(login/OTP/password-reset/token/API-key) enforces NO rate-limit or account-lockout, a frequently-' +
    'paid control defect. CONTROL-TEST, NOT a brute: use your OWN test account (wrong password) or your ' +
    'own identifier (OTP/reset) — NEVER guess another user. Run through the leash: python ' +
    'tools/rate-limit-probe.py --target-dir ' + (a.target_dir || 'targets/<t>') + ' --url https://<host>/' +
    '<auth-endpoint> --method POST --data \'{"username":"<own-test-acct>","password":"wrong"}\' --count ' +
    '<= policies.rate_limit_test.max_requests_per_endpoint. If N requests pass with no 429/419/lockout, ' +
    'emit class:rate-limit (eligibility:control-test-only) with the request count + evidence; stop at the ' +
    'first throttle/lockout signal. Respect own_accounts_only. If the policy is NOT enabled, report gated ' +
    'and skip. Never flood, never target a real account.' })

// fix3 B3 — novelty / prior-art lens. Added ONLY when the engagement has disclosure sources to check
// (a.novelty.sources_present), so a plain web/impact run's lens set + bucketing are byte-for-byte
// unchanged (the shipped P5 interactive-surface precedent — conditional LENSES.push, zero roster change
// when inactive). Reuses the duplicate-scout agent via the per-lens agentType override (below).
if (a.novelty?.sources_present) LENSES.push({
  key: 'novelty-scout', title: 'Novelty / prior-art mapping', agentType: 'duplicate-scout',
  jobs: 'build/refresh targets/<t>/priorart.json: pull the program disclosure history (hacktivity / ' +
    'operator submitted/ archive / context-pack disclosure section), the stack CVEs (NVD 2.0) and ' +
    'component advisories (GHSA), and the changelog. Index each as a ROOT-CAUSE fingerprint ' +
    '(class+cwe+component+root_cause+fixed). Emit a novelty_index keyed by (class, component) with ' +
    'verdict novel|likely-duplicate|could-not-verify + ref + reason. HONEST: if no source resolves, ' +
    'coverage:"unverifiable" and every verdict is could-not-verify (NEVER novel). A disclosed-but-FIXED ' +
    'item is a VARIANT/REGRESSION seed (re-test on the current build), not only a filter. Touch NO ' +
    'target; this is PASSIVE OSINT (public indices + local files), needs no leash. Do NOT exploit.' })

// P2 unified mode gate (C2): keep LENSES whose `modes` tag intersects args.modes; untagged lenses always
// run (web behavior unchanged). Absent/empty args.modes => ACTIVE===LENSES (byte-identical to today).
// Array.filter preserves order, so the full web set selects the whole current list in the same order.
const _m = (Array.isArray(a.modes) && a.modes.length) ? a.modes : null
let ACTIVE = _m ? LENSES.filter(l => !Array.isArray(l.modes) || l.modes.some(m => _m.includes(m))) : LENSES
if (!ACTIVE.length) { log('mode gate matched 0 lenses — full list'); ACTIVE = LENSES }

const buckets = Math.min(fleet, ACTIVE.length)
const assign = Array.from({ length: buckets }, () => [])
ACTIVE.forEach((l, i) => assign[i % buckets].push(l))

function mission(lenses, label) {
  const skillPaths = lenses.map(l => `${skillsDir}/recon/${l.key}/SKILL.md`)
  const block = lenses.map(l => `- ${l.title}: ${l.jobs}`).join('\n')
  // fix3 MVP — SENIOR REFLEX CARD priming (additive; '' when no retrieved reflex card matches a lens in
  // this bucket, so the mission is byte-identical to today). A signal->move checklist distilled from
  // DISCLOSED reports — a HINT to orient recon faster, never proof; the oracle is untouched downstream.
  const reflexCard = (a.reflex_cards && lenses.some(l => a.reflex_cards[l.key])) ? `

SENIOR REFLEX CARDS (signal -> move, distilled from disclosed reports; hints to orient recon, not proof):
${lenses.filter(l => a.reflex_cards[l.key]).map(l => `- ${l.key}: ${a.reflex_cards[l.key]}`).join('\n')}` : ''
  return `${a.authorization || 'AUTHORIZED ENGAGEMENT — you are cleared to test the in-scope hosts.'}${objectiveBlock}${bountyObjectiveBlock}${eligibilityBlock}${payoutBlock}

You are in DEEP recon. The broad surface is already mapped — read the world model at
${a.target_dir}/state.json and docs/01-recon-surface.md, then go deeper on YOUR lens.
CROSS-RUN LEARNING (compounding — read BEFORE you propose hypotheses): query the in-run memory with
\`python tools/recall.py --target-dir ${a.target_dir} --query "<your lens + top hosts>"\` to pull this
target's OWN prior records — state.json techniques[] (what WORKED — prefer these classes), dead_paths[]/
tried[] (do NOT re-propose a recorded dead-end — it wastes the run), related findings, and raw/ notes from
earlier this run — then read ${a.context_pack ? a.context_pack + ' (this program/target pack: paid + dup-heavy classes, realized pay bands, stack/CVE map)' : 'any .claude/skills/context/ pack for this program/target, if present'} so a NEW engagement starts already knowing what paid and what was a duplicate here. This is how each run leaves the next one stronger.

SCOPE (authoritative): ${JSON.stringify(a.scope || {}, null, 0)}
Target-facing tools via the leash wrapper (tools/leashed.sh ${a.target_dir} <tool>); passive OSINT direct; non-HTTP tools validated with tools/guard.py + pinned to the exact host/CIDR. Probes must be SMALL and NON-DESTRUCTIVE — this is recon, not exploitation.

TARGET DIR: ${a.target_dir} — write evidence under ${a.target_dir}/raw/${label}/.
ARSENAL: ${a.bin_dir || 'C:/Spider/bin'} via Bash; connected MCP via ToolSearch. MCP (docs/mcp-integration.md):
passive intel (osint/shodan) runs DIRECT; a leashed browser (playwright) crawls JS-heavy SPAs and reaches
auth-gated surface katana misses — route it through the leash, in-scope only.
METHODOLOGY: read if present: ${skillPaths.join(', ')}

YOUR LENS (own it, go deep):
${block}${reflexCard}

THOROUGHNESS (deep recon is where the PAID bugs are found — be exhaustive on YOUR lens, this is the
highest-impact phase):
- Do NOT stop at the first signal. Enumerate EVERY param (arjun AND x8 on every live endpoint), recover
  EVERY source map + unpack EVERY bundle and trace EVERY high-confidence sink (deep-source-trace), map EVERY
  API route/version/verb, fingerprint EVERY detected stack->CVE (cve-intel, KEV/EPSS-ranked). Breadth AND depth.
- Prefer MORE evidence-backed hypotheses over a tidy short list: every concrete, provable signal is a
  hypothesis with its evidence file and a honest confidence. The attack phase decides where to spend budget —
  your job is to miss nothing provable. A hunch with no evidence file stays a note, not a hypothesis.
- Cross-pollinate what other lenses surfaced (read state.json + docs/01-recon-surface.md): feed web-crawl/
  js endpoints into param-mining, stack fingerprints into cve-intel, the recovered JS tree into
  deep-source-trace, auth flows into otp-logic/oauth. A lens that ignores the others leaves bugs on the table.
- Every probe stays SMALL + NON-DESTRUCTIVE and in-scope through the leash — thoroughness is coverage, never a flood.

DEPENDENCY MODEL (the attack phase proves foothold FIRST, then unlocks dependents): for each
hypothesis declare its place in the graph using the closed capability-token grammar in brain/schema.md:
- requires: capability tokens a PRIOR step must PROVE before this can fire. A BOLA/IDOR on a protected
  object requires ["session:<host>"]; an admin-only action requires ["admin:<host>"]. A hypothesis that
  exploits AUTHENTICATED functionality MUST declare the session/cred it needs — do NOT assume access you
  have not modeled. Independent hypotheses have requires:[]. (The FULL closed token set — session/creds/
  token/foothold/admin + shell:<host> + the CTF tokens artifact:/key:/plaintext:/source:/flag: — is in
  brain/schema.md and the SHELL RULE / CTF TOKENS bullets below; use those for post-foothold & CTF hypotheses.)
- provides: capability tokens this grants IF proven. A login/auth-bypass/otp-logic/SSH-or-service-cred
  hypothesis provides ["session:<host>"] or ["creds:<p>@<host>"]; set stage:"foothold" for these.
Set stage:"post-foothold" for anything that needs a prior capability. This graph is what lets the attack
phase avoid building a PoC that can never fire (the BOLA-without-a-session failure it is fixing).
- FLAG MODE (P1): if an objective is declared, rank the hypothesis chain that reaches it HIGHEST and make
  the last-mile extraction explicit — a foothold:<host> that yields a readable artifact should emit a
  follow-on class:objective-capture hypothesis (stage:post-foothold, requires:["foothold:<host>"]) that
  pulls the artifact and extracts the flag LOCALLY.
- BOUNTY MODE (fix3): rank each hypothesis's confidence/order by EXPECTED PAYOUT (eligible class x est.
  tier x asset value x novelty prior x ACCEPTANCE_PRIOR — P(accepted) for this program+class from
  state.objective.acceptance_prior / the program context pack, i.e. hunt where the program ACTUALLY pays)
  and set vrt/priority/eligibility/projected_tier/projected_ev per the blocks above — but the F4
  requires/provides STAGING IS UNCHANGED. Economics bias WHAT you propose and in what order you LIST it,
  never the wave scheduler; a foothold producer still stages first.
- SHELL RULE (P4): a foothold that grants OS command execution (SSH/telnet/RDP cred, a proven
  RCE/SSTI/cmd-injection, an uploaded webshell) provides shell:<host> IN ADDITION to session:/foothold:.
  A web-only session provides session:/foothold: but NOT shell:. Inside-the-box hypotheses
  (internal-recon / privesc / loot / lateral) are stage:"post-foothold" and requires the shell:/foothold:
  token — they are LATENT until a producer proves it, letting Spider plan foothold → privesc → loot the
  flag up front without a step that fires before its prerequisite.
- CTF TOKENS (P3): for a provided artifact the tokens are artifact:<name>@<chal> (a characterised file in
  hand), key:/plaintext:/source: (recovered secrets/data), and flag:<chal> (the objective). A
  carve/extract that yields a nested artifact is stage:"foothold" providing the inner artifact: token.

Return the schema: enriched assets AND a ranked list of HYPOTHESES — each a concrete, provable
claim (id, host, class, why/signal, how-to-prove, confidence, stage, requires, provides) with an
evidence file under ${a.target_dir}/raw/${label}/.
A hypothesis is a lead for the attack phase; do NOT exploit it here.`
}

phase('Deep recon')
const results = await parallel(assign.map((lenses, i) => () => {
  const label = lenses.length === 1 ? lenses[0].key : `deep-${i + 1}`
  return agent(mission(lenses, label), {
    // fix3 B3 — per-lens agentType override so the novelty-scout lens reuses the duplicate-scout agent.
    // Every existing lens has no `agentType` => defaults to 'recon-operator' => byte-identical to today.
    label, phase: 'Deep recon', agentType: lenses[0].agentType || 'recon-operator', schema: HYPO_RESULT, ...modelFor(a.model_tier),
  })
}))

const ok = results.filter(Boolean)
const hypotheses = ok.flatMap(r => r.hypotheses || [])
const proposed_modes = [...new Set(ok.flatMap(r => r.proposed_modes || []))]   // P2: agent-proposed modes (additive; empty on a plain run)
const proposed_ideas = ok.flatMap(r => r.proposed_ideas || [])                 // P2: agent-proposed ideas (additive)
log(`recon-2 done: ${ok.length}/${assign.length} agents, ${hypotheses.length} hypotheses`)

// fix(#3, sandbox-safe): LOUD priming status — reflex cards / program context pack were consumed with a
// silent fallback, so a cold deep-recon was indistinguishable from a primed one. Scripts can't touch disk
// (the brain runs tools/prime.py|retrieve.py and passes a.reflex_cards / a.context_pack); the code can at
// least refuse to be silent about running cold.
const _reflexKeys = (a.reflex_cards && typeof a.reflex_cards === 'object') ? Object.keys(a.reflex_cards).length : 0
const priming = { reflex_cards: _reflexKeys, context_pack: a.context_pack || null, primed: !!(_reflexKeys || a.context_pack) }
log(priming.primed
  ? `recon-2 priming: ${_reflexKeys} reflex cards; context_pack=${a.context_pack || 'none'}`
  : `recon-2 priming: NONE (no reflex_cards, no context_pack) — deep recon ran COLD; if brain/corpus/ or a program pack exists the brain skipped the localhost retrieve/prime step`)

return {
  phase: 'recon-2',
  target: a.target,
  agents: assign.length,
  completed: ok.length,
  hypotheses_total: hypotheses.length,
  priming,
  hypotheses,
  per_agent: results.map((r, i) => ({ label: assign[i].map(l => l.key).join('+'), status: r ? r.status : 'DIED', hypotheses: r ? (r.hypotheses?.length || 0) : 0 })),
  proposed_modes,
  proposed_ideas,
}
