# MCP integration

Spider's arsenal is CLI-first, run through the scope **leash** (`tools/leashed.sh` → mitmdump on
`127.0.0.1:8080`). MCP servers are added **only where a CLI cannot do the job** — API intel, a real
browser, or a graph query. The leash stays the single scope-enforcement point.

## The rule: what to adopt, what to refuse

- **Refuse CLI-wrapper MCP** (HexStrike, pentestMCP, cyproxio/mcp-for-security, …). They wrap
  nmap/nuclei/sqlmap/ffuf — tools Spider already runs under the leash. Adopting them duplicates the
  arsenal **and bypasses the leash**. Hard no.
- **Adopt only non-CLI capability:** passive intel APIs, a real browser, an AD graph query, a
  stateful proxy as the operator's channel.

## leash-as-proxy — the three routing classes

| Class | Servers | Routing |
|---|---|---|
| **Passive intel** | osint (passive tools), shodan, fofa, censys, virustotal | Run **direct** — they hit third-party APIs, exactly like `subfinder`/`gau`. No leash (the leash would 403 them as off-scope). |
| **Target-facing** | playwright (browser), caido/burp (proxy) | **Through the leash.** Point the client at `--proxy-server http://127.0.0.1:8080` + `--ignore-https-errors` (trust the mitm CA). Off-scope still 403s, the mandatory header is still injected, the rate cap still applies. Drive **in-scope hosts only** — a discovered host is a lead. |
| **Local analysis** | bloodhound_mcp | Talks to the **local** BloodHound instance (Neo4j/REST), never the target. No leash. Read-only, post-foothold only. |

`playwright` in `.mcp.json` is already pinned to the leash proxy. Start the leash first
(`tools/start-leash.sh targets/<t>/leash.env`), then the browser MCP routes through it.

**osint caveat:** osint-mcp is mostly passive, but `http_headers`, `tls_certificate`,
`investigate_site` and `recon_domain` (default) contact the target directly. For target-facing
checks prefer the leashed CLI, or call `recon_domain` with `include_active=false`.

## Mapping to the /spider phases

### recon-1 / recon-2 (recon-operator)
- **osint** (keyless) — WHOIS, DNS, CT subdomains, Wayback, ASN, Shodan InternetDB, email-sec.
- **shodan** / **fofa** / **censys** / **virustotal** (API key) — exposed-host + exposure intel,
  the passive force-multiplier Spider lacked.
- **playwright** (leashed) — crawl JS-heavy SPAs, capture XHR/GraphQL endpoints katana misses,
  reach auth-gated surface.
- Gap CLI tools (not MCP): `sourcemapper` (reconstruct source from `.map`), `wakaru` (unpack
  bundles/undo minify), `graphql-cop` (fast GraphQL misconfig audit). Extend `recon/js-secret-mining`.

### attack (attack-operator)
- **playwright** (leashed) — drive OAuth/SSO/MFA/OTP flows, DOM-XSS with real execution,
  CORS/clickjacking PoC in a real browser. Unlocks the auth-heavy targets the fleet stalls on.
- **caido** / **burp** (leashed) — stateful request forge/replay and auth-flow chaining a one-shot
  `curl` can't do. Operator's interactive channel.
- Gap method (not a tool): GraphQLer-style dependency-graph query/mutation fuzzing for BOLA/authz.

### post-foothold (internal-recon / privesc / loot / lateral)
- **bloodhound_mcp** — query the AD graph in the loop: shortest path to DA from an owned principal,
  DCSync rights, domain objects. Read-only, local. The query interface Spider's collection
  (bloodhound-python/sharphound) never had. The AD exploitation arsenal (impacket, certipy,
  bloodyAD, netexec, rubeus, mimikatz) is already complete.

## Enablement

1. Prereqs: `uv` (for `uvx` — osint, bloodhound) and Node 18+ (for `npx` — playwright). Shodan MCP
   needs a `git clone` + `npm install && npm run build`.
2. `cp .mcp.json.example .mcp.json` and fill the `REPLACE_*` values for the servers you want. The
   real `.mcp.json` is gitignored; the example stays tracked.
3. API keys live in the `env` block of `.mcp.json` (a local secret, like `session.env`) — never in
   args, prompts, or `state.json`.
4. `.claude/settings.json` allowlists the arsenal wrappers + these MCP servers so the fleet doesn't
   stall on permission prompts. Prefer moving it to `.claude/settings.local.json` if you don't want
   an offensive allowlist shipped in a public clone.

## Optional servers (verify the exact command from the repo before adding)

Not shipped in the example — community code that handles your keys; pin a commit and read the source.

- **fofa** — github.com/nn0nkey (FOFA + Shodan); env `FOFA_EMAIL`, `FOFA_KEY`.
- **virustotal** — github.com/BurtTheCoder/mcp-virustotal; env `VIRUSTOTAL_API_KEY`.
- **censys** — github.com/nickpending/mcp-censys (**author: demo-only, not production**); env
  `CENSYS_API_ID`, `CENSYS_API_SECRET`.
- **burp** (official PortSwigger) — a Burp extension exposing MCP at `127.0.0.1:9876`; connect as an
  HTTP/SSE server. Requires a running Burp.
- **caido** — github.com/FazcomIA/mcp-caido. **Not stdio** (local HTTP service), repo ownership is
  ambiguous, and its default `CAIDO_URL` port `8080` **collides with the leash** — remap one before
  use. Prefer Burp for the stateful-proxy slot.

## Caveats

- **Supply chain.** Most community MCP is unaudited third-party code holding your keys (tool-poisoning
  is a known MCP risk). Prefer official (Playwright/Microsoft, Burp/PortSwigger, BloodHound
  MCP/featured by SpecterOps); pin a commit for `uvx --from git+...`.
- **Token cost.** Playwright MCP is heavy (~114k tokens/task vs ~27k for the Playwright CLI). Don't
  run it always-on — gate it to recon-2/attack where a browser is actually needed.
