#!/usr/bin/env bash
# Scope + SAFETY enforcer for POST-FOOTHOLD on-host commands (P4). Sibling of leash-cred.sh/leash-tcp.sh.
# It makes "non-destructive, scope-pinned, bounded" STRUCTURAL (not just prompt-level) the same way
# leash-cred.sh made spray-not-brute structural — the safe path is the only path:
#   - fail-closed unless leash.env + LEASH_SCOPE are present
#   - host-pin the foothold host via guard.py (off-scope => refuse)
#   - a DESTRUCTIVE verb denylist (fail-closed) — enumeration/read/`id`/`sudo -l`/GTFOBins one-shots that
#     only read or spawn a proof shell pass; rm/dd/mkfs/kernel-module/kill/reboot/userdel/log-wipe refused
#   - a PERSISTENCE verb group (scope-gated by LEASH_FOOTHOLD_ALLOW_PERSISTENCE; DEFAULT 0 = refused as
#     before). When the operator's attested engagement scope PRE-APPROVES persistence proof as a milestone
#     (e.g. Standoff 365 M100K user-session reboot-persist, M150K infra-node reboot-persist, M200K DA
#     with 'standoff365'-user creation), leash.env sets LEASH_FOOTHOLD_ALLOW_PERSISTENCE=1 and the
#     persistence group opens for: useradd/groupadd/usermod/passwd (setting a NEW user), authorized_keys
#     append, crontab -e/add (NOT -r), systemctl enable/start (NOT stop/disable/mask of existing),
#     Windows schtasks /create (NOT /delete). Destructive, disruption of running services, log-wipe,
#     reverse-shell, bulk-exfil, kernel-module and marker-file touch REMAIN REFUSED even when enabled.
#   - a MARKER-FILE protection (always on): a command that references `standoff365_hack_me` is REFUSED
#     here — Spider never autonomously encrypts/touches the marker; the final НС demonstration step is
#     operator-manual (program-attested proof artifact), run outside this wrapper.
#   - bounded loot: refuse obvious bulk-copy (tar-create / scp -r / rsync / zip -r / cp -r of a tree) and
#     cap captured output at LEASH_FOOTHOLD_MAX_LOOT_BYTES (default 5 MB)
#   - every command ledgered to raw/foothold-ledger.jsonl BEFORE running (a crash can't hide it)
#
# Doctrine (fix3-persistence, 2026-10-07): Spider's persistence posture is scope-gated, not globally
# denied. The engagement scope + operator attestation decides whether reboot-persist proof is in-bounds;
# the leash reflects that decision in code (LEASH_FOOTHOLD_ALLOW_PERSISTENCE) rather than hard-coding one
# answer. Destructive and marker-file paths stay closed under either setting — that is the real red line.
#
# Usage: tools/leash-foothold.sh <target_dir> <host> <cmd> [args...]
#   e.g. tools/leash-foothold.sh targets/acme app.acme.com id
#        tools/leash-foothold.sh targets/acme app.acme.com bin/.peass/linpeas.sh -s
# Self-test (offline, no target): LEASH_FOOTHOLD_SELFTEST=1 tools/leash-foothold.sh <target_dir> <host> id
set -uo pipefail

TDIR="${1:?usage: leash-foothold.sh <target_dir> <host> <cmd> [args...]}"
HOST="${2:?dst host required}"; shift 2
[ "$#" -ge 1 ] || { echo "leash-foothold: no command given"; exit 2; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENVFILE="$TDIR/leash.env"
[ -f "$ENVFILE" ] || { echo "leash-foothold: no leash.env at $ENVFILE"; exit 2; }
set -a; . "$ENVFILE"; set +a
: "${LEASH_SCOPE:?leash-foothold: LEASH_SCOPE missing (fail-closed)}"

MAX_LOOT="${LEASH_FOOTHOLD_MAX_LOOT_BYTES:-5242880}"   # ~5 MB default output cap
ALLOW_PERSIST="${LEASH_FOOTHOLD_ALLOW_PERSISTENCE:-0}" # fix3-persistence: 0=today's doctrine, 1=scope-opt-in
LEDGER="$TDIR/raw/foothold-ledger.jsonl"; mkdir -p "$(dirname "$LEDGER")"
STAMP() { date -u +%Y-%m-%dT%H:%M:%SZ; }
CMD="$*"

# --- host-pin (skip only in offline self-test) -----------------------------------------------------
EXTRA=""; [ "${LEASH_EXACT:-1}" = "1" ] || EXTRA="--allow-subdomains"
if [ "${LEASH_FOOTHOLD_SELFTEST:-0}" != "1" ]; then
  if ! python "$ROOT/tools/guard.py" --scope "$LEASH_SCOPE" $EXTRA --check "$HOST" >/dev/null 2>&1; then
    echo "leash-foothold: $HOST is OUT OF SCOPE — refusing (fail-closed)"; exit 3
  fi
fi

# --- MARKER-FILE protection (ALWAYS on, both modes) ------------------------------------------------
# Spider never autonomously touches `standoff365_hack_me`. The final НС demonstration step (encrypting
# the marker on the backup disks) is operator-manual, outside this wrapper. Refuse any command that
# references the marker — case-insensitive substring is enough to catch cp/mv/encrypt/openssl paths.
if printf '%s' "$CMD" | grep -qiE 'standoff365_hack_me'; then
  printf '{"ts":"%s","host":"%s","cmd":"%s","event":"denied","why":"marker-file touch"}\n' \
    "$(STAMP)" "$HOST" "$CMD" "marker-file touch" >> "$LEDGER"
  echo "leash-foothold: REFUSED — command references the NS marker 'standoff365_hack_me'. Spider never autonomously touches it; the final NS demonstration step is operator-manual. (fail-closed)"
  exit 7
fi

# --- DESTRUCTIVE verb denylist (ALWAYS on, both modes) ---------------------------------------------
# True data destruction + system disruption + kernel-module + others-cred-change + bulk-exfil operators +
# reverse-shell operators + log-deletion outside own artifacts + marker-file paths.
# Command-name verbs are anchored to a command position ((^) | after a separator ; & | | after / in a
# path | after whitespace) so a READ of a colliding path is NOT blocked (e.g. `cat /etc/passwd` passes).
DESTRUCTIVE_VERB='(rm|rmdir|shred|dd|mkfs|mkfs\.[a-z0-9]+|fdisk|chattr|killall|kill|pkill|reboot|shutdown|halt|poweroff|init|telinit|insmod|rmmod|modprobe|mkswap|wipefs|userdel)'
DESTRUCTIVE_VERB_RE="(^|[;&|/]|[[:space:]])${DESTRUCTIVE_VERB}([[:space:]]|$)"
# non-command destructive / disruption / log-wipe patterns (always refused)
DESTRUCTIVE_MISC_RE=':\(\)[[:space:]]*\{|chmod[[:space:]]+-R|systemctl[[:space:]]+(stop|disable|mask)|service[[:space:]]+[^[:space:]]+[[:space:]]+stop|crontab[[:space:]]+-r|(^|[;&|/]|[[:space:]])nc[[:space:]]+-e|(^|[;&|/]|[[:space:]])ncat[[:space:]]+-e|logrotate[[:space:]]+-f|>[[:space:]]*/var/log/|truncate[[:space:]]+(-s[[:space:]]*0|--size=0)[[:space:]]+/var/log|wevtutil[[:space:]]+cl|Clear-EventLog|Remove-EventLog|auditpol[[:space:]]+/clear|schtasks[[:space:]]+/(delete|change)|net[[:space:]]+stop[[:space:]]'

DENY_HIT=""
printf '%s' "$CMD" | grep -qiE "$DESTRUCTIVE_VERB_RE" && DENY_HIT="destructive/disruption verb"
[ -z "$DENY_HIT" ] && printf '%s' "$CMD" | grep -qiE "$DESTRUCTIVE_MISC_RE" && DENY_HIT="destructive/disruption pattern"
if [ -n "$DENY_HIT" ]; then
  printf '{"ts":"%s","host":"%s","cmd":"%s","event":"denied","why":"%s"}\n' \
    "$(STAMP)" "$HOST" "$CMD" "$DENY_HIT" >> "$LEDGER"
  echo "leash-foothold: REFUSED — $DENY_HIT. Spider never destroys data, disrupts running services, kills processes, deletes users, wipes logs, or opens reverse shells. (fail-closed)"
  exit 5
fi

# --- PERSISTENCE verb group (scope-gated by LEASH_FOOTHOLD_ALLOW_PERSISTENCE) ----------------------
# When 0 (DEFAULT): refuse — Spider's historical no-persistence posture, byte-identical to today.
# When 1 (operator-attested per scope): PASS — milestones that require reboot-surviving proof (M100K
# user-session, M150K infra-node, M200K DA account creation) are legitimate finds under the engagement.
# Even when 1: destructive, log-wipe, service-kill, reverse-shell, marker-file touch ALL still refused.
PERSIST_VERB='(useradd|usermod|groupadd|visudo|iptables|nft|ufw)'
PERSIST_VERB_RE="(^|[;&|/]|[[:space:]])${PERSIST_VERB}([[:space:]]|$)"
PERSIST_PASSWD_RE="(^|[;&|][[:space:]]*|sudo[[:space:]]+)passwd([[:space:]]|$)"
PERSIST_MISC_RE='>[[:space:]]*/etc/(cron\.|systemd/|init\.d/|rc[0-9S]\.d/)|tee[[:space:]]+[^|;&]*/etc/(cron\.|systemd/|init\.d/|rc[0-9S]\.d/)|>>?[[:space:]]*[^|;&]*authorized_keys|tee[[:space:]]+[^|;&]*authorized_keys|(^|[;&|/]|[[:space:]])crontab[[:space:]]+(-e|-l|-u|<)|(^|[;&|/]|[[:space:]])systemctl[[:space:]]+(enable|start|daemon-reload|reload)|(^|[;&|/]|[[:space:]])schtasks[[:space:]]+/create|(^|[;&|/]|[[:space:]])at[[:space:]]+[0-9]|New-ScheduledTask|Register-ScheduledTask|Set-ItemProperty[[:space:]]+.*(Run|RunOnce)|reg[[:space:]]+add[[:space:]]+.*(Run|RunOnce)'

PERSIST_HIT=""
printf '%s' "$CMD" | grep -qiE "$PERSIST_VERB_RE"   && PERSIST_HIT="persistence verb (user/group/firewall mgmt)"
[ -z "$PERSIST_HIT" ] && printf '%s' "$CMD" | grep -qiE "$PERSIST_PASSWD_RE" && PERSIST_HIT="passwd (credential set for new user)"
[ -z "$PERSIST_HIT" ] && printf '%s' "$CMD" | grep -qiE "$PERSIST_MISC_RE"   && PERSIST_HIT="persistence pattern (cron/systemd/authorized_keys/scheduled-task/registry Run)"
if [ -n "$PERSIST_HIT" ]; then
  if [ "$ALLOW_PERSIST" = "1" ]; then
    # Scope opts in — allow + ledger explicitly (so the operator can audit every persistence step)
    printf '{"ts":"%s","host":"%s","cmd":"%s","event":"persistence-allowed","why":"%s","gate":"LEASH_FOOTHOLD_ALLOW_PERSISTENCE=1"}\n' \
      "$(STAMP)" "$HOST" "$CMD" "$PERSIST_HIT" >> "$LEDGER"
  else
    printf '{"ts":"%s","host":"%s","cmd":"%s","event":"denied","why":"persistence (LEASH_FOOTHOLD_ALLOW_PERSISTENCE=0)"}\n' \
      "$(STAMP)" "$HOST" "$CMD" >> "$LEDGER"
    echo "leash-foothold: REFUSED — $PERSIST_HIT. Persistence is scope-gated; this engagement's leash.env has LEASH_FOOTHOLD_ALLOW_PERSISTENCE=0. Operator attests persistence via scope.yaml + leash.env flip to 1. (fail-closed)"
    exit 8
  fi
fi

# --- bounded loot: refuse obvious bulk-copy / mass-exfil -------------------------------------------
BULK_RE='(^|[;&|/]|[[:space:]])tar[[:space:]]+-?[a-zA-Z]*c|(^|[;&|/]|[[:space:]])(rsync)([[:space:]]|$)|scp[[:space:]]+-r|zip[[:space:]]+-r|(^|[;&|/]|[[:space:]])cp[[:space:]]+-[a-zA-Z]*r'
if printf '%s' "$CMD" | grep -qiE "$BULK_RE"; then
  printf '{"ts":"%s","host":"%s","cmd":"%s","event":"denied","why":"bulk-copy/mass-exfil"}\n' \
    "$(STAMP)" "$HOST" "$CMD" >> "$LEDGER"
  echo "leash-foothold: REFUSED — bulk-copy/mass-exfil (tar-create/scp -r/rsync/zip -r/cp -r). Loot is objective-bounded. (fail-closed)"
  exit 6
fi

# --- ledger the command BEFORE running (a crash can't hide it) ------------------------------------
printf '{"ts":"%s","host":"%s","cmd":"%s","event":"run"}\n' "$(STAMP)" "$HOST" "$CMD" >> "$LEDGER"

# --- run, capture output, enforce the loot byte cap -----------------------------------------------
OUT="$(mktemp)"; trap 'rm -f "$OUT"' EXIT
"$@" > "$OUT" 2>&1; RC=$?
SZ=$(wc -c < "$OUT" 2>/dev/null | tr -d '[:space:]'); SZ="${SZ:-0}"
if [ "$SZ" -gt "$MAX_LOOT" ]; then
  head -c "$MAX_LOOT" "$OUT"
  echo
  echo "leash-foothold: OUTPUT TRUNCATED at ${MAX_LOOT} bytes (loot cap LEASH_FOOTHOLD_MAX_LOOT_BYTES; captured ${SZ}). No mass-exfil."
  printf '{"ts":"%s","host":"%s","cmd":"%s","event":"truncated","bytes":%s,"cap":%s}\n' \
    "$(STAMP)" "$HOST" "$CMD" "$SZ" "$MAX_LOOT" >> "$LEDGER"
else
  cat "$OUT"
fi
exit "$RC"
