#!/usr/bin/env bash
# Offline regression for the attack class->skill resolver (workflows/attack.mjs). The resolver maps a
# recon-emitted free-form hypothesis class onto one of the shipped attack skill packs; a drift between the
# ATTACK_SKILLS array / CLASS_ALIASES and the attack/ skill dirs silently drops the class methodology (the
# cache-poisoning orphan + the artifact-analysis dangling path, 2026-11). This asserts the three invariants
# that catch that drift, plus a soft seam check that every literal class: hint written in the recon skills
# resolves to a real pack. Parses attack.mjs as the single source of truth. No target traffic. Run: tools/smoke-resolver.sh
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PYTHON:-python}"

ROOT="$ROOT" "$PY" - <<'PY'
import os, re, sys

root = os.environ["ROOT"]
mj = open(os.path.join(root, "workflows", "attack.mjs"), encoding="utf-8").read()
attack_dir = os.path.join(root, ".claude", "skills", "attack")
recon_dir = os.path.join(root, ".claude", "skills", "recon")

# --- parse the single source of truth out of attack.mjs ---------------------
ATTACK_SKILLS = re.findall(r"'([^']+)'", re.search(r"const ATTACK_SKILLS = \[(.*?)\]", mj, re.S).group(1))
ALIASES = re.findall(r"\['([^']+)',\s*'([^']+)'\]", re.search(r"const CLASS_ALIASES = \[(.*?)\n\]", mj, re.S).group(1))
on_disk = {d for d in os.listdir(attack_dir) if os.path.isdir(os.path.join(attack_dir, d))}
alias_slugs = {slug for _, slug in ALIASES}

def resolve(cls):
    """Byte-for-byte mirror of resolveAttackSkill() in attack.mjs (first-match-wins substring)."""
    c = (cls or "").lower()
    if not c:
        return None
    if c in ATTACK_SKILLS:
        return c
    for kw, slug in ALIASES:
        if kw in c:
            return slug
    return None

fail = 0

# A) every slug the resolver can RETURN names a pack that exists on disk ------
print("A) every ATTACK_SKILLS slug + every alias target has a pack on disk")
missing_arr = sorted(s for s in ATTACK_SKILLS if s not in on_disk)
missing_alias = sorted(s for s in alias_slugs if s not in on_disk)
if missing_arr:
    print(f"   FAIL: ATTACK_SKILLS slugs with no attack/<slug>/ dir: {missing_arr}"); fail = 1
if missing_alias:
    print(f"   FAIL: CLASS_ALIASES targets with no attack/<slug>/ dir: {missing_alias}"); fail = 1
if not missing_arr and not missing_alias:
    print(f"   ok ({len(set(ATTACK_SKILLS) | alias_slugs)} resolver targets, all present)")

# B) every pack on disk is REACHABLE (in the array or an alias target) -------
print("B) every attack/ pack on disk is reachable by the resolver")
reachable = set(ATTACK_SKILLS) | alias_slugs
orphans = sorted(d for d in on_disk if d not in reachable)
if orphans:
    print(f"   FAIL: orphan packs (on disk, resolver never returns them): {orphans}"); fail = 1
else:
    print(f"   ok ({len(on_disk)} packs, all reachable)")

# C) a sanity re-check that each pack ships a SKILL.md -----------------------
print("C) every reachable pack ships a SKILL.md")
no_skill = sorted(d for d in on_disk if not os.path.isfile(os.path.join(attack_dir, d, "SKILL.md")))
if no_skill:
    print(f"   FAIL: pack dirs with no SKILL.md: {no_skill}"); fail = 1
else:
    print(f"   ok")

# D) SEAM (soft): every literal class: hint in the recon skills resolves -----
# Recon prose writes `class:<name>` / `class:"name"` / `Emit class:name`. Placeholder segments (<svc>,
# <proto>, ...) are stripped; a token that is still all-placeholder is skipped. Unresolved literals are a
# WARNING, not a failure: recon also emits pure recon/novelty classes that intentionally have no attack
# pack. A regression like the cache-poisoning drop shows up here as a warning AND as a hard B) failure.
print("D) recon class: hints resolve to a pack (soft - warnings only)")
literal = set()
for base in (recon_dir,):
    for dp, _, fns in os.walk(base):
        for fn in fns:
            if fn != "SKILL.md":
                continue
            txt = open(os.path.join(dp, fn), encoding="utf-8").read()
            raw = []
            raw += re.findall(r"class:\s*[\"'`]?([A-Za-z0-9<>_|-]+)", txt)          # class:foo / class:foo|bar
            raw += re.findall(r"\bclass\s+`([A-Za-z0-9<>_-]+)`", txt)               # class `foo`
            raw += re.findall(r"\bclass\s+([a-z][a-z0-9<>_-]*(?:\|[a-z][a-z0-9<>_-]*)+)", txt)  # class foo|bar|baz
            for m in raw:
                for part in m.split("|"):   # split pipe-enumerations into individual classes
                    tok = re.sub(r"<[^>]*>", "", part).strip("-_").lower()
                    if len(tok) >= 3:   # drop prose noise ("class: an endpoint ...")
                        literal.add(tok)
unresolved = sorted(t for t in literal if resolve(t) is None)
if unresolved:
    print(f"   WARN: {len(unresolved)} literal recon class(es) resolve to NO attack pack: {unresolved}")
    print(f"         (ok if they are pure recon/novelty signals; a dropped attack class is a bug)")
else:
    print(f"   ok ({len(literal)} literal classes, all resolve)")

# E) chain.mjs resolver must stay identical to attack.mjs. The two are standalone workflow scripts (no
# shared imports), so they are synced by hand; this guard catches the drift that once left /chain + /again
# 22 packs and 113 aliases behind the main attack phase.
print("E) chain.mjs resolver is in sync with attack.mjs")
cj = open(os.path.join(root, "workflows", "chain.mjs"), encoding="utf-8").read()
c_arr = re.findall(r"'([^']+)'", re.search(r"const ATTACK_SKILLS = \[(.*?)\]", cj, re.S).group(1))
c_al = re.findall(r"\['([^']+)',\s*'([^']+)'\]", re.search(r"const CLASS_ALIASES = \[(.*?)\n\]", cj, re.S).group(1))
if set(c_arr) != set(ATTACK_SKILLS):
    print(f"   FAIL: ATTACK_SKILLS differ (symmetric diff): {sorted(set(ATTACK_SKILLS) ^ set(c_arr))}"); fail = 1
elif c_al != ALIASES:
    print(f"   FAIL: CLASS_ALIASES differ (attack={len(ALIASES)} aliases, chain={len(c_al)}) — re-sync chain.mjs from attack.mjs"); fail = 1
else:
    print(f"   ok (chain mirrors attack: {len(c_arr)} slugs, {len(c_al)} aliases)")

print()
if fail:
    print("SMOKE-RESOLVER: FAIL"); sys.exit(1)
print("SMOKE-RESOLVER: PASS")
PY
