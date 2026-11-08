# context/ — target knowledge packs

Per-target fingerprint packs that make the fleet act like it already knows the target's stack. Unlike
`recon/` and `attack/` skills (generic methodology), a context pack is **specific to one target or
tech family**: known stacks, typical paths, known-weak endpoints, public disclosure history, and
which nuclei/CVE templates apply. The brain passes `context/<target>/SKILL.md` into the mission when
it exists, so every agent starts with the map instead of rediscovering it.

Build one when you learn a target's stack (during recon-2 or from a prior run) — it compounds across
runs. Source real signal from `docs/SENIOR-METHODOLOGY.md` and the target's own recon.

Layout: `.claude/skills/context/<target-or-family>/SKILL.md`. Copy `_template/SKILL.md`.
