# Tool & skill distribution per workflow

What each workflow's agents get. Tools live in `bin/` (provisioned by `arsenal/`); skills in
`.claude/skills/` (agents `Read` the path for their surface, routed by `index.json`). The `phase`
field in `arsenal/manifest.json` is the tool→phase binding; the skill folder is the skill→surface
binding. Nothing is hardcoded into the fan-out — agents choose freely within their surface.

## Always-on (control plane, every live phase)
| Tool | Role |
|---|---|
| `mitmproxy` (mitmdump) | the **leash** — `tools/start-leash.sh`; agents route target HTTP via `tools/leashed.sh` |
| `interactsh-client` | OOB/OAST channel for proving blind bugs (also used in attack + triage) |

## recon-1.mjs — broad OSINT sweep (11 modalities)
| Modality (skill) | Primary tools |
|---|---|
| `recon/subdomain-enum` | subfinder, tlsx, dnsx, httpx, **alterx** (+**puredns**/massdns, optional) |
| `recon/dns-intel` | dnsx, tlsx |
| `recon/takeover` | **subzy**, dnsx, nuclei (takeover tags), httpx |
| `recon/port-service` | naabu (host-pinned via `guard.py`) |
| `recon/http-probe` | httpx, wafw00f |
| `recon/web-crawl` | katana |
| `recon/archive-urls` | gau, **uro** (dedupe), **gf** (pattern-tag) |
| `recon/js-secret-mining` | **jsluice** (AST parser), katana, gau, trufflehog |
| `recon/cloud-assets` | s3scanner |
| `recon/content-discovery` | **feroxbuster** (recursive), ffuf, SecLists wordlists |
| `recon/visual-recon` | httpx -screenshot |

## recon-2.mjs — deep recon → hypotheses (13 lenses)
| Lens (skill) | Primary tools |
|---|---|
| `recon/param-mining` | **x8**, arjun |
| `recon/endpoint-deep` | katana, httpx, nuclei (exposure tags) |
| `recon/api-discovery` | **kiterunner** (`kr` + kitebuilder wordlist), httpx, uro |
| `recon/graphql` | **graphw00f**, **clairvoyance** (schema w/o introspection), httpx, nuclei |
| `recon/auth-flow` | httpx, curl (map flows; no exploitation) |
| `recon/access-control` | httpx, arjun (read-only probing) |
| `recon/tech-specific` | nuclei (tag-scoped + **-dast fuzzing-templates** + **cent** community), httpx |
| `recon/anomaly-hunt` | httpx, curl (small differential probes) |

## attack.mjs — exploit → PoC → verify (per hypothesis class)
Class → `attack/<class>` skill + `proof/poc-standard` + `proof/oob-interactsh` (for blind).
| Class (skill) | Primary tools |
|---|---|
| `attack/ssrf` | interactsh-client, nuclei, httpx |
| `attack/idor` | hurl, httpx, ffuf, arjun |
| `attack/sqli` | sqlmap, arjun |
| `attack/xss` | dalfox, arjun, interactsh-client |
| `attack/jwt` | jwt-hack |
| `attack/xxe` | interactsh-client, curl |
| `attack/ssti` | sstimap |
| `attack/auth-bypass` | nomore403 |
| `attack/request-smuggling` | smuggler |
| `attack/open-redirect` | nuclei, ffuf |
| `attack/cors` | nuclei, curl |
| `attack/upload` | fuxploider |
| `attack/graphql` | clairvoyance, graphw00f, nuclei, hurl (BOLA/authz/injection/batching) |

Verification sub-stage uses the `verifier-skeptic` role (re-runs the PoC; no new tools).

## triage.mjs — adversarial pass over the report
Role `verifier-skeptic` + `proof/poc-standard`. Re-validation/replay tools:
| Job | Tool |
|---|---|
| deterministic replay / re-check a PoC | hurl |
| structural response diff (baseline vs attack) | difftastic |
| re-run a single detection | nuclei, httpx |
| OOB re-confirmation | interactsh-client |

**Routing rule (all phases):** target-facing tools → `tools/leashed.sh <target_dir> bin/<tool>`;
passive OSINT (subfinder/gau/tlsx/trufflehog) → direct; non-HTTP (naabu) → `tools/guard.py` +
exact host/CIDR pin; SMTP/non-HTTP protocol tools → `tools/leash-tcp.sh` (scope-audited). See `.claude/agents/*.md`.

## v2 additions (see CHANGELOG-v2.md)
- **recon-2 lenses (+5):** `exposed-datastores` (gitleaks/s3scanner/httpx/nuclei/ffuf),
  `waf-body-encoding` (httpx/curl), `oauth-pkce` (httpx/curl), `session-fixation` (httpx/curl),
  `smtp-protocol` (gated; leash-tcp + swaks/curl).
- **attack classes (+3):** `waf-body-bypass` (curl/nuclei/ffuf), `saml` (curl/xmlsec1·manual),
  `keycloak-realm` (jwt-hack/curl/httpx).
- **control-test:** `recon/rate-limit-audit` → `tools/rate-limit-probe.py` (through the leash).
- **proof:** `proof/cors-poc-html` (agent writes the PoC HTML directly, no helper script).
- **arsenal (+4):** gitleaks (recon/secrets), commix (attack/cmd-injection), flask-unsign (attack),
  testssl (recon/TLS; needs unix coreutils).
- **chain-builder** stage (attack) — no new tools; reads findings + state.json.
- **duplicate-scout** (pre-submit, in `/report`) — archive + public disclosure, best-effort.

## v3 additions — "break better" arsenal (13 tools + data)
Fills real class/quality gaps so the fleet reaches critical chains, not just noise. Each is bound to a
skill (so agents actually pick it) and provisioned by `arsenal/`.
- **New modality/lenses + classes:** `recon/takeover` (subzy), `recon/api-discovery` (kiterunner),
  `recon/graphql` (graphw00f + clairvoyance) → `attack/graphql`.
- **In-place upgrades:** jsluice (js-secret-mining, AST not regex), alterx[/puredns] (subdomain-enum,
  active brute), x8 (param-mining), feroxbuster (content-discovery, recursive), uro+gf (archive-urls,
  dedupe+tag), nuclei `-dast` + fuzzing-templates + cent (tech-specific, active param fuzzing).
- **Data (new `data` block in manifest, installer `data`):** `seclists-core` (curated wordlists, the
  fuel), `gf-patterns` (GF_PATH), `nuclei-fuzzing-templates` (-dast); `kitebuilder` wordlist is
  `optional` (large). Provision with `python arsenal/provision.py` (optional/heavy items need
  `--optional`). Probe shows them under their phase with `(optional)` marks.
- **Surface vs scope:** surface-expanders (alterx/puredns/subzy) feed **leads**, never auto-targets —
  the leash still gates every target packet.
- **Windows notes:** `kr` (kiterunner) has no Windows release (WSL/`go build`); `gf` needs the Go
  toolchain; `massdns` must be compiled (puredns heavy path) — the default alterx|dnsx brute needs
  neither; `clairvoyance` runs as `python -m clairvoyance`.
