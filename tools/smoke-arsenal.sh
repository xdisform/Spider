#!/usr/bin/env bash
# Release guard: every `bin/<tool>` a recon/attack SKILL.md tells an agent to run MUST exist in bin/
# (as a binary, a .exe, or a wrapper script). Catches the "wired but no binary/wrapper" class of bug
# where a skill's methodology references a tool that was installed as source-only with no bin/ entry, so
# the agent's command fails and it silently falls back — the installed arsenal becomes dead weight.
# No target traffic. Run: tools/smoke-arsenal.sh
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
FAIL=0

# Tools the skills reference as optional with a documented fallback (Go/Java builds that don't exist on
# a bare-Windows clone — the skill says "if provisioned / if absent use X"). Absent => WARN, not FAIL.
KNOWN_OPTIONAL=" jsluice ysoserial puredns massdns kiterunner kr "

# Collect unique top-level bin/<tool> refs. First strip shell PATHS (/usr/bin/find, /bin/sh) so GTFOBins /
# pwn examples don't masquerade as Spider arsenal refs; dotted helpers (bin/.pyenv/...) fail the alnum-first
# class and are excluded.
mapfile -t TOOLS < <(grep -rh '' .claude/skills/recon .claude/skills/attack .claude/skills/proof 2>/dev/null \
  | sed 's#/usr/bin/##g; s#/bin/##g' \
  | grep -oE 'bin/[A-Za-z0-9][A-Za-z0-9_-]*' \
  | sed 's#^bin/##' | sort -u)

echo "Checking ${#TOOLS[@]} distinct bin/<tool> references from recon+attack+proof skills..."
missing=(); optwarn=()
for t in "${TOOLS[@]}"; do
  if [ -e "bin/$t" ] || [ -e "bin/$t.exe" ] || [ -e "bin/$t.cmd" ] || [ -e "bin/$t.bat" ] \
     || [ -e "bin/.pyenv/Scripts/$t.exe" ]; then
    :
  elif [[ "$KNOWN_OPTIONAL" == *" $t "* ]]; then
    optwarn+=("$t")
  else
    missing+=("$t"); FAIL=1
  fi
done

if [ "${#missing[@]}" -gt 0 ]; then
  echo "  FAIL: skills reference these tools but bin/ has no binary/wrapper for them:"
  for m in "${missing[@]}"; do echo "    - bin/$m"; done
  echo "  -> install the tool and/or add a bin/ wrapper (see bin/.osint wrappers for the pattern)."
else
  echo "  ok: every required referenced tool resolves to a bin/ entry"
fi
[ "${#optwarn[@]}" -gt 0 ] && echo "  WARN (optional, documented fallback — ok if absent on this OS): ${optwarn[*]}"

# OSINT wrappers must actually launch (the 2026-11 gap: wrappers referenced but dep-less/absent)
echo "Smoke-launching the OSINT wrappers..."
for w in theHarvester maigret linkfinder secretfinder sf cloud_enum; do
  if [ -x "bin/$w" ] || [ -e "bin/$w" ]; then
    if bin/$w -h >/dev/null 2>&1 || bin/$w --help >/dev/null 2>&1 || bin/$w --version >/dev/null 2>&1; then
      echo "    ok   bin/$w launches"
    else
      echo "    WARN bin/$w exists but did not launch cleanly (deps?) — check bin/.pyenv"
    fi
  else
    echo "    FAIL bin/$w wrapper missing"; FAIL=1
  fi
done

echo
[ "$FAIL" -eq 0 ] && echo "SMOKE-ARSENAL: PASS" || { echo "SMOKE-ARSENAL: FAIL"; exit 1; }
