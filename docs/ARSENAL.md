# Arsenal — tools: where they live, how to add them

Spider's tools are **not committed**. They are downloaded onto each user's machine at install time
from their upstream releases, so the repo stays small and license-clean. This doc is the reference
for where they land and how to add, swap, or remove one.

## Where tools live

Everything lands in **`bin/`** (git-ignored). By channel:

| Channel | What lands in `bin/` | Extra |
|---|---|---|
| `github-release` | the binary, e.g. `bin/subfinder.exe` (or `bin/subfinder` on *nix) | — |
| `pip` | a shim `bin/<name>.cmd` (Win) / `bin/<name>` (*nix) | packages in the venv `bin/.pyenv/` |
| `git` | a python shim `bin/<name>.cmd` / `bin/<name>` | clone in `bin/.src/<name>/` |
| `go` | the binary (via `GOBIN`) | needs a Go toolchain |
| `npm` | a shim `bin/<name>` | package under `bin/.npm/` |
| `data` | a folder of files, not a binary — wordlists/templates under `bin/.wordlists/`, `bin/.gf`, `bin/.nuclei/` | from the `data[]` block; see below |

Agents call tools by `bin/<name>` through Bash. Everything under `bin/` is disposable — delete it
and re-run the provisioner to rebuild.

## Install / update

```bash
python arsenal/probe.py             # what's present now (per phase)
python arsenal/provision.py --check # dry run: resolve releases, show sizes, download nothing
python arsenal/provision.py         # install everything missing into bin/
python arsenal/provision.py --phase recon      # one phase only
python arsenal/provision.py --only nuclei      # one tool
python arsenal/provision.py --only nuclei --force  # reinstall
python arsenal/provision.py --optional          # ALSO install heavy/optional items (big wordlists, massdns, puredns)
python arsenal/provision.py --json  # machine-readable result (used by /doctor)
```

The default run installs the full tool set + the lightweight data assets (curated wordlists, gf
patterns, nuclei fuzzing-templates). **Heavy/optional** items (`optional: true` — the large
kitebuilder wordlist, `massdns`, `puredns`) are skipped unless you pass `--optional` or name them
with `--only <name>`. This keeps a first install lean and fast.

**Set `GITHUB_TOKEN`** before installing `github-release` tools — the unauthenticated GitHub API is
capped at 60 requests/hour and the resolver will 403 once it's hit:

```bash
export GITHUB_TOKEN=ghp_xxx        # Windows: setx GITHUB_TOKEN ghp_xxx  (new shell after)
```

## How the manifest describes a tool

`arsenal/manifest.json` → `tools[]`. Fields:

| Field | Meaning |
|---|---|
| `name` | canonical name + how agents call it (`bin/<name>`) |
| `phase` | `recon` \| `attack` \| `triage` \| `control` (binds the tool to a workflow phase) |
| `purpose` | one line |
| `install_method` | `github-release` \| `pip` \| `git` \| `go` \| `npm` \| `data` \| `manual` |
| `optional` | `true` = heavy item, skipped unless `--optional` or `--only <name>` |
| `repo` | `owner/repo` for github-release/go; reference for others |
| `package` | pip package name (pip only, if it differs from `repo`) |
| `git` + `entry` | clone URL + the script to run, e.g. `smuggler.py` (git only) |
| `bin_name` | the executable/command name if it differs from `name` (e.g. difftastic → `difft`) |
| `version_cmd` | flag for a health check, e.g. `-version` / `--version` |
| `license`, `platforms`, `json_output` | metadata (license also recorded in THIRD-PARTY-LICENSES) |
| `fallback` | note, e.g. `go install ...@latest` when no prebuilt binary |

The provisioner resolves the **right per-OS/arch asset live** from the GitHub release — you do NOT
hardcode a download URL. It matches the OS (`windows`/`linux`/`darwin`) and arch (`amd64`/`arm64`),
rejects other-OS/other-arch assets, and skips installers/checksums.

## Add a tool

1. Pick the channel (prefer `github-release` with a real prebuilt binary; else `pip`, then `git`).
2. Add one entry to `arsenal/manifest.json`:

   **github-release**
   ```json
   { "name": "gowitness", "phase": "recon", "purpose": "screenshot web apps",
     "install_method": "github-release", "repo": "sensepost/gowitness",
     "bin_name": "gowitness", "version_cmd": "version", "license": "GPL-3.0", "platforms": "windows,linux,darwin" }
   ```
   **pip**
   ```json
   { "name": "wafw00f", "phase": "recon", "purpose": "WAF fingerprint",
     "install_method": "pip", "repo": "EnableSecurity/wafw00f", "package": "wafw00f",
     "bin_name": "wafw00f", "version_cmd": "--version", "license": "BSD-3-Clause", "platforms": "any" }
   ```
   **git** (tool with no release/PyPI; a `.py` entrypoint)
   ```json
   { "name": "smuggler", "phase": "attack", "purpose": "request smuggling",
     "install_method": "git", "repo": "defparam/smuggler", "git": "https://github.com/defparam/smuggler",
     "bin_name": "smuggler", "entry": "smuggler.py", "version_cmd": "-h", "license": "MIT", "platforms": "any" }
   ```
3. `python arsenal/provision.py --only <name>` — confirm it installs and the version check runs.
4. If it's copyleft (GPL/AGPL), add a line to `THIRD-PARTY-LICENSES.md`.
5. Wire it into a workflow/skill so agents actually use it (see `docs/SKILLS.md` and `docs/TOOL-MAP.md`).

## Data assets (wordlists, templates, patterns)

Some capabilities are data, not binaries — fuzzers are only as good as their wordlists, and
`nuclei -dast` needs the fuzzing-templates. These live in a separate **`data[]`** block in
`arsenal/manifest.json` and install via `install_method: "data"` into `bin/` (never a binary on PATH).

Two shapes:
```json
// a shallow git clone (patterns / template repos)
{ "name": "nuclei-fuzzing-templates", "phase": "attack", "install_method": "data",
  "dest": ".nuclei/fuzzing-templates", "git": "https://github.com/projectdiscovery/fuzzing-templates" }

// a curated list of direct downloads (optionally extracted)
{ "name": "seclists-core", "phase": "recon", "install_method": "data", "dest": ".wordlists/seclists",
  "files": [ { "url": "https://raw.githubusercontent.com/.../raft-large-directories.txt", "as": "raft-large-directories.txt" } ] }
```
Fields: `dest` (folder under `bin/`), `git` **or** `files[]` (`{url, as, extract?}`), optional
`optional: true`. Skills reference the path directly (e.g. `bin/.wordlists/seclists/...`,
`GF_PATH=bin/.gf`, `nuclei -dast -t bin/.nuclei/fuzzing-templates`). `probe.py` reports a data asset
as present when its `dest` exists and is non-empty.

## Swap or remove a tool

- **Swap** (e.g. AGPL → permissive): change the entry's `repo`/`install_method`/`bin_name`, re-run
  `provision.py --only <name> --force`. Update the skills/TOOL-MAP that named the old tool.
- **Remove**: delete the manifest entry and `bin/<name>*`. Update any skill that referenced it.

## Optional heavy tool-servers (MCP)

The default arsenal is portable CLI. A heavier tool-server (a Kali-class MCP with 100+ tools) can be
attached as an **optional accelerator**: connect it as an MCP server for the session, and workflow
agents reach its tools via `ToolSearch`. Spider never assumes it — `/doctor` detects it, and the
cycle degrades to the `bin/` arsenal when it's absent.

## Troubleshooting

- **`GitHub API 403`** — rate limit; set `GITHUB_TOKEN` or wait an hour.
- **`WinError 216` / "not a valid Win32 application"** — wrong-OS asset was picked; the resolver now
  rejects other-OS assets, but if a new tool's naming is unusual, check its release asset names.
- **`no-asset`** — the release has no matching OS/arch archive; use the `go`/`git` fallback or a
  different tool.
- **`skipped: git/go not present`** — install git or a Go toolchain for those channels.
- Runtime notes: `naabu` SYN scan needs admin (auto-falls back to CONNECT); `katana -headless` and
  `httpx -screenshot` need Chrome/Chromium; `nuclei` pulls its templates on first run.
