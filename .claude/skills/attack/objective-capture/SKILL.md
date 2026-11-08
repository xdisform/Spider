---
name: attack-objective-capture
description: Last-mile flag/objective capture — given a LEGITIMATELY-acquired foothold, pull the objective artifact through the leash then extract the flag LOCALLY/OFFLINE (exiftool/strings/binwalk/identify) and validate it against scope.objective.flag_format. Terminal post-foothold producer; flag mode only. Never crack a door to reach the flag.
category: objective
tags: [objective, flag, exfil, post-foothold, local-analysis, terminal]
chains_with: [loot, internal-recon, artifact-analysis, stego, forensics]
tools: [exiftool, imagemagick, binwalk]
version: "1.0"
---

# Objective capture (last-mile flag extraction)

## Objective
Turn a **legitimately-acquired foothold** into the declared win condition: retrieve the objective
artifact and extract the **flag** from it. This is the engagement's **terminal** act in `flag` mode —
when its oracle meets, the run is won and routes to `/report`. It does the *last inch* only: it does
**not** obtain the foothold itself (a prior producer does) and it does **not** evade anything to reach
the artifact. The analysis is **local/offline** — only the *download* of an in-scope artifact crosses
the wire, through the leash.

## Gate (check BEFORE anything)
Act **only** when both hold, else STOP and hand off:
1. `scope.objective.mode == 'flag'` — in the default `impact` mode there is no flag to capture; this
   class is never emitted and this skill is a no-op.
2. You already **hold** a legitimately-acquired prerequisite — a `foothold:<host>` / `session:<host>` /
   `creds:<p>@<host>` token (oracle-proven earlier, or an operator-supplied `session.env`). The leash
   auto-injects that session on in-scope requests; you exercise the **authenticated** surface.

If the objective artifact sits behind a door you do **not** hold, return
`proven_state:'blocked', blocked_reason:'needs_session'` (or `'safeguard'` if reaching it would mean
defeating an auth/security control as an attack) and describe the hand-off in `note`. **Never** log in,
forge, crack, or brute to get there — the objective never licenses evasion.

## Dependency position (F4)
A **post-foothold producer**, wired in `workflows/attack.mjs` (spine), expressed through the existing
capability graph (`brain/schema.md`):
- `stage: "post-foothold"`, `requires: ["foothold:<host>"]` (or `session:`/`creds:`) — the scheduler
  only fires it once that token is in the acquired set, so the flag PoC never runs as a dead attempt
  before its foothold exists.
- `provides: []` — **terminal**. Nothing depends on the flag, so `unlockScore = 0` and it is correctly
  scheduled **last**. No new capability token is added; the objective is tracked in its own
  `state.objective{}` block, written only by the synthesizer.

## Methodology (local / offline extraction)
Work the hint (`scope.objective.where_hint`) as a lead, never as proof or authority.
1. **Pull the artifact through the leash (the only networked step).** Use the auto-injected session to
   read/download the in-scope object (the authenticated export, file-read response, command output, or
   the generated file). Save the raw producing request/response under `raw/attack-<id>/`. For a
   non-HTTP fetch, route via `tools/leash-tcp.sh <target_dir> <host> <cmd>`; nothing leaves scope.
2. **Flag already in the bytes?** If the artifact is text (a config, a file-read body, a command
   output), check it directly: the flag may be plaintext. Grep it against the format (step 5).
3. **Metadata.** `exiftool -a -u -g1 <file>` — all tags, unknown + duplicates, grouped. Flags hide in
   `Comment`/`UserComment`/`Artist`/`XMP`/custom tags. Secondary: `identify -verbose <file>`
   (ImageMagick) for comments, geometry, embedded profiles.
4. **Carve / strings.** `strings -a -n 6 <file>` (ASCII + wide: add `-el`), and `binwalk <file>` then
   `binwalk --dd='.*' <file>` to extract appended/embedded files (stego/appended data carrying a flag).
   For an image stego carrier, the `stego` class (P3) is the specialist — chain to it.
5. **Match against the format.** Check the recovered bytes against `scope.objective.flag_format`
   (default `flag\{[^}]+\}`). The matched substring is the flag.
6. **Deterministic cross-check (never a silent flag).** Run the always-on pre-filter
   `python tools/flag-scan.py --target-dir <target_dir>` — it greps **all** of `raw/` for the format
   and flags any match that was captured in evidence but never reported. If it surfaces a flag you
   missed, that is your candidate for the oracle below. It is read-only, offline, stdlib-only.

## What counts as a finding
- **Finding (`impact_proven`, the flag IS the impact):** a string that **matches
  `scope.objective.flag_format`** AND whose exact bytes are **re-derivable from a saved artifact under
  `raw/`** — the request/response, file read, command output, or local-tool output that produced it.
  Put the flag in `execution_evidence`, the producing artifact/command in `poc_path`/`evidence`. The
  oracle is `flag-capture` (`.claude/skills/proof/oracles/SKILL.md`) — a **double gate**: (a) format
  match, (b) **provenance** (an independent reader re-runs the PoC / re-reads the file / re-runs
  `exiftool -a -u -g1` and sees the same bytes).
- **Not a finding:** a flag typed from memory, guessed, or not traceable to a `raw/` artifact — it
  **fails** the oracle. Do not report it.
- **Blocked (hand-off, not a negative):** the artifact is behind a door you do not legitimately hold —
  `proven_state:'blocked'`, `blocked_reason:'needs_session'` (or `'safeguard'`). A flag behind a
  `[cyber]`-blocked door stays blocked and routes to the operator; it is never cracked.

## Evidence
Under `raw/attack-<id>/`: the producing request/response (or the leashed download), the local
extraction command and its output (`exiftool`/`strings`/`binwalk`), and the matched flag bytes. A
claim with no re-derivable artifact is not a finding. The synthesizer merges the proven flag into
`state.json.objective` (single writer); the flag string is operator-facing proof (it IS the
deliverable), distinct from `session.env` secrets, and is not injected into other agents' missions.

## Red line
- Local analysis touches **no network** — only the download is leashed and in-scope, so this class
  opens no new egress surface.
- **Never fabricate or guess** a flag; the provenance gate makes a remembered/plausible flag fail.
- Reach the flag **only by a legitimate, oracle-provable path**. A flag behind an auth-locked or
  `[cyber]`-blocked door => `blocked` + hand off (F1/F2) — never crack auth, never evade a safeguard,
  never work around a refusal. The objective is terminal, not a licence.
