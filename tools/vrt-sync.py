#!/usr/bin/env python3
"""
Spider VRT-sync — regenerate brain/vrt.md's class -> priority -> CVSS -> CWE map (fix3 B4, idea #1).

brain/vrt.md is DATA the brain and the fleet read to tag a hypothesis/finding's eligibility leg of
mode:bounty (vrt / priority / eligibility / eligibility_reason — the B4-owned canonical fields). The
class->VRT map inside it is GENERATED, not hand-edited — exactly like .claude/skills/index.json
(tools/skill_index.py) and brain/corpus/index.json (tools/corpus_index.py). This tool is that
generator: it renders the map between the <!-- VRT-SYNC:BEGIN/END --> markers from a single editorial
seed (which shipped attack-skill slug maps to which Bugcrowd VRT dotted id), pulling the authoritative
baseline priority / CVSS v3 vector / CWE from a PINNED Bugcrowd VRT JSON release when the operator
supplies one — so the map stays current without hand-editing and without silent drift.

    python tools/vrt-sync.py                       # regenerate brain/vrt.md's block from the embedded
                                                   #   VRT-1.9 reference seed (no external data needed)
    python tools/vrt-sync.py --vrt-json <dir>/vrt.json --mappings-dir <dir>/mappings
                                                   # overlay the AUTHORITATIVE priority/cvss/cwe from a
                                                   #   pinned Bugcrowd VRT checkout (records its version)
    python tools/vrt-sync.py --check               # lint: is the block in brain/vrt.md in sync? exit 1 if drift
    python tools/vrt-sync.py --emit-block          # print the generated block to stdout only
    python tools/vrt-sync.py --self-test           # offline self-check, no target / no network needed

HARD RED LINE: this is an OFFLINE, LOCAL generator. It touches NO network (the Bugcrowd VRT JSON is a
pinned file the operator checks out), reads no secret, issues no target traffic. It NEVER invents a
priority/CVSS/CWE: a slug with no VRT leaf is emitted honestly (vrt_id "", a doctrine note), never a
fabricated class. It NEVER inflates a baseline (the authoritative overlay only mirrors the pinned JSON).
Eligibility here is a payout-POLICY annotation only — it never changes scope, a safeguard, or `severity`.

stdlib-only, deterministic (fixed slug order, no clock, no randomness), cross-OS. Exit: 0 ok; 1 drift
(--check) / self-test fail / write error; 2 bad args.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "brain" / "vrt.md"
BEGIN = "<!-- VRT-SYNC:BEGIN"
END = "<!-- VRT-SYNC:END -->"
BLOCK_RE = re.compile(re.escape(BEGIN) + r".*?" + re.escape(END), re.S)

# The VRT snapshot the embedded reference seed was transcribed against (dossier cites Bugcrowd VRT 1.9).
# The authoritative overlay (--vrt-json) replaces this with the pinned release's own version string.
REFERENCE_VRT_VERSION = "1.9-reference"

# --- lockstep with workflows/attack.mjs line 30 (the 31 shipped attack-skill slugs) --------------------
# If attack.mjs's ATTACK_SKILLS changes, update SLUG_MAP (below) in lockstep; --self-test and --check
# assert the two sets are identical so the map can never key a class the oracle/skills do not know.
ATTACK_SKILLS = {
    "artifact-analysis", "auth-bypass", "cors", "cred-access", "crypto", "forensics", "graphql",
    "idor", "interactive-exploit", "internal-recon", "jwt", "keycloak-realm", "lateral", "loot",
    "objective-capture", "open-redirect", "otp-logic", "privesc", "pwn", "request-smuggling", "rev",
    "saml", "sqli", "ssrf", "ssti", "stego", "takeover", "upload", "waf-body-bypass", "xss", "xxe",
}

# --- the editorial seed: one row per shipped attack-skill slug ----------------------------------------
# (slug, vrt_id dotted, baseline_priority, cvss_v3_baseline, cwe, default_eligibility, note)
#   * baseline_priority is the VRT CLASS baseline (P1..P5|varies) — DISTINCT from a finding's evidence
#     `severity` and from B5's evidence-derived `tier`. "varies" = the VRT "null"/context rule: the
#     evidence + CVSS pick the band, never the desired tier.
#   * cvss_v3_baseline is the synthesizer's ANCHOR vector for the class (the reference it adjusts up/down
#     with the proven evidence) — it is NOT the per-finding `cvss_vector` (B5, evidence-derived).
#   * default_eligibility: payable | excluded | control-test-only | unknown. "unknown" is the honest
#     state for a surface/technique/CTF class that is not itself a payable web taxonomy entry — never
#     assumed payable (the same could-not-verify honesty the dedup point uses).
#   * vrt_id "" = no direct VRT leaf; the note says what it resolves to (the delivered/underlying class,
#     or the chain's end-impact, or "flag-mode only").
# Order mirrors attack.mjs ATTACK_SKILLS for readability; rendering is deterministic (no sort).
SLUG_MAP = [
    ("sqli", "server_side_injection.sql_injection", "P1",
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "CWE-89", "payable",
     "Server-side SQL injection; blind and in-band both P1."),
    ("ssrf", "server_side_injection.server_side_request_forgery_ssrf", "varies",
     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N", "CWE-918", "payable",
     "Internal/cloud-metadata SSRF is P2+; external/DNS-only is P4 — the evidence picks the band."),
    ("ssti", "server_side_injection.server_side_template_injection", "P1",
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "CWE-1336", "payable",
     "SSTI that reaches RCE is P1; a sandboxed/limited-eval SSTI grades lower on proof."),
    ("xxe", "server_side_injection.xml_external_entity_injection_xxe", "P2",
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", "CWE-611", "payable",
     "File-read / SSRF-via-XXE is P2; XXE chained to RCE is P1."),
    ("xss", "cross_site_scripting_xss.stored", "varies",
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "CWE-79", "payable",
     "Stored P2-P3, reflected P3, DOM P3, off-domain/non-persistent P4; self-XSS is P5 (see exclusions)."),
    ("idor", "broken_access_control.insecure_direct_object_references_idor", "varies",
     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "CWE-639", "payable",
     "IDOR/BOLA; P4->P1 by the function and data the object exposes — the evidence picks the band."),
    ("auth-bypass", "broken_authentication_and_session_management.authentication_bypass", "varies",
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "CWE-287", "payable",
     "Authn/authz bypass; tenant/role/boundary bypass is P1-P2 on proof."),
    ("jwt", "broken_authentication_and_session_management.authentication_bypass", "varies",
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "CWE-347", "payable",
     "JWT alg-confusion / alg:none / weak-secret is a signature-verification bypass -> authn bypass (CWE-347)."),
    ("saml", "broken_authentication_and_session_management.authentication_bypass", "varies",
     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", "CWE-347", "payable",
     "SAML signature-wrapping / unsigned-assertion -> authn bypass (CWE-347); resolve to the proven impact."),
    ("keycloak-realm", "broken_authentication_and_session_management.authentication_bypass", "varies",
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "CWE-287", "payable",
     "Keycloak/OIDC realm misconfig (public client, weak flows) -> authn bypass; grade on the proven impact."),
    ("cors", "broken_access_control.cross_origin_resource_sharing_misconfiguration", "varies",
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N", "CWE-942", "payable",
     "CORS with credentials + reflected/null origin reading authed data is P2-P3; CORS without creds/impact is P5."),
    ("open-redirect", "unvalidated_redirects_and_forwards.open_redirect", "P4",
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N", "CWE-601", "payable",
     "Open redirect P4; a GET-based redirect on a non-sensitive param can be P5 — pays when chained (OAuth token theft)."),
    ("request-smuggling", "server_security_misconfiguration.http_request_smuggling", "P2",
     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N", "CWE-444", "payable",
     "HTTP desync/smuggling P2; cache-poisoning / credential-capture chains rate higher at their end-impact."),
    ("upload", "server_security_misconfiguration.unrestricted_file_upload", "varies",
     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", "CWE-434", "payable",
     "Unrestricted upload that reaches RCE is P1; stored-XSS/path issues grade lower — bound to the proven exec."),
    ("takeover", "server_security_misconfiguration.misconfigured_dns.basic_subdomain_takeover", "varies",
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N", "CWE-284", "payable",
     "Subdomain takeover P3; takeover of a sensitive/auth host (cookie/session scope) is P1."),
    ("graphql", "", "varies",
     "", "", "unknown",
     "GraphQL is a SURFACE, not a class — resolve to the underlying payable class (idor/sqli/auth-bypass/dos); introspection-enabled alone is P5."),
    ("cred-access", "server_security_misconfiguration.using_default_credentials", "varies",
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "CWE-1392", "control-test-only",
     "Default/weak service credentials (CWE-1392/CWE-521) -> P1 if admin; pursued ONLY under policies.default_cred_control_test (spray-not-brute)."),
    ("waf-body-bypass", "", "varies",
     "", "", "unknown",
     "A DELIVERY technique, not a payable class — pays as the class it delivers (sqli/xss/ssti/xxe)."),
    ("interactive-exploit", "", "varies",
     "", "", "unknown",
     "A held-socket DELIVERY technique (policy-gated) — pays as the proven class (RCE / auth bypass / protocol-state crossed)."),
    ("pwn", "server_side_injection.remote_code_execution", "P1",
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "CWE-787", "unknown",
     "CTF memory-safety class (flag mode). In a bounty a memory-corruption RCE in an in-scope service maps to RCE (P1); otherwise n/a."),
    ("rev", "", "n/a", "", "", "unknown",
     "CTF reverse-engineering (flag mode) — not a web-bounty taxonomy class; eligibility n/a in bounty."),
    ("crypto", "", "n/a", "", "", "unknown",
     "CTF cryptography (flag mode) — a real crypto weakness pays as its impact class (e.g. broken auth); n/a in bounty on its own."),
    ("forensics", "", "n/a", "", "", "unknown",
     "CTF forensics (flag mode) — not a web-bounty taxonomy class; n/a in bounty."),
    ("stego", "", "n/a", "", "", "unknown",
     "CTF steganography (flag mode) — not a web-bounty taxonomy class; n/a in bounty."),
    ("artifact-analysis", "", "n/a", "", "CWE-200", "unknown",
     "Local artifact analysis (file/CTF mode) — a secret it surfaces pays as sensitive-data-exposure (CWE-200); the analysis itself is n/a in bounty."),
    ("internal-recon", "", "n/a", "", "", "unknown",
     "Post-foothold Discovery — pays on the IMPACT the chain proves (Bugcrowd combined-impact rule), never on its own."),
    ("privesc", "broken_access_control.privilege_escalation", "varies",
     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", "CWE-269", "payable",
     "Privilege escalation; vertical-to-admin is P1-P2 — bound to the demonstrated privileged action."),
    ("loot", "", "n/a", "", "CWE-200", "unknown",
     "Post-foothold Collection — pays on the data-exposure impact proven (CWE-200), never on its own."),
    ("lateral", "", "n/a", "", "", "unknown",
     "Post-foothold Lateral — pays on the in-scope impact proven; out-of-scope neighbours stay leads."),
    ("objective-capture", "", "n/a", "", "", "unknown",
     "Flag-mode terminal producer — n/a in bounty."),
    ("otp-logic", "broken_authentication_and_session_management.second_factor_authentication_2fa_bypass", "varies",
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "CWE-287", "payable",
     "2FA/OTP logic bypass (leaked/predictable/reused code, account-binding) P2; a legitimate logic play, never a brute."),
]

# --- built-in standard-exclusion defaults (the cross-platform P5 "won't pay" baseline) ----------------
# (match keyword(s) pipe-split, vrt_id, baseline_priority, cwe, action, default_eligibility, reason)
# These only DOWN-RANK (note / control-test-only), never hard-drop; the operator's scope.program always
# overrides. `match` is keyword-matched exactly as attack.mjs CLASS_ALIASES / eligibility() matches
# (lower-cased substring, pipe-split, first-match-wins) — one matching discipline, not two.
BUILTIN_EXCLUSIONS = [
    ("self-xss", "cross_site_scripting_xss.self_xss", "P5", "CWE-79",
     "note", "excluded", "Self-XSS: no cross-user vector."),
    ("missing-security-header|security-headers|hsts|csp-missing", "server_security_misconfiguration.security_headers",
     "P5", "CWE-16", "note", "excluded", "No-impact best-practice security headers."),
    ("spf|dkim|dmarc|email-spoof", "server_security_misconfiguration.mail_server_misconfiguration",
     "P5", "CWE-16", "note", "excluded", "SPF/DKIM/DMARC record issues / email spoofing to inbox."),
    ("clickjacking", "server_security_misconfiguration.clickjacking", "P5", "CWE-1021",
     "note", "excluded", "Clickjacking on non-sensitive actions."),
    ("descriptive-error|stack-trace|verbose-error|path-disclosure|debug-endpoint",
     "server_security_misconfiguration.information_disclosure", "P5", "CWE-209",
     "note", "excluded", "Descriptive/verbose errors, stack traces, path disclosure, debug endpoints."),
    ("version-banner|version-disclosure|software-version",
     "server_security_misconfiguration.server_software_version_disclosure", "P5", "CWE-200",
     "note", "excluded", "Software version / banner disclosure — best-practice only."),
    ("rate-limit|rate-limiting", "server_security_misconfiguration.no_rate_limiting_on_action", "P5", "CWE-799",
     "control-test-only", "control-test-only",
     "Rate-limiting as-is is excluded unless chained; pursue ONLY as a bounded control-test per policies.*."),
    ("best-practice|informational|no-security-impact", "other.no_security_impact", "P5", "",
     "note", "excluded", "Best-practice-only report / no demonstrated security impact."),
]

PRI = {1: "P1", 2: "P2", 3: "P3", 4: "P4", 5: "P5"}


def _priority_label(val) -> str:
    """VRT priority int 1..5 -> Pn; null -> 'varies' (the VRT context rule)."""
    if val is None:
        return "varies"
    if isinstance(val, bool):  # guard: bool is an int subclass
        return "varies"
    if isinstance(val, (int, float)) and int(val) in PRI:
        return PRI[int(val)]
    return "varies"


def _flatten(node_list, prefix: str, out: dict, value_key: str | None):
    """Walk a Bugcrowd-VRT-shaped tree into {dotted_id: value}. value_key None => record priority."""
    for node in node_list or []:
        if not isinstance(node, dict):
            continue
        nid = str(node.get("id", "")).strip()
        dotted = f"{prefix}.{nid}" if prefix and nid else (nid or prefix)
        if value_key is None:
            out[dotted] = _priority_label(node.get("priority"))
        else:
            v = node.get(value_key)
            if isinstance(v, list):
                v = ", ".join(str(x) for x in v)
            if v not in (None, ""):
                out[dotted] = str(v)
        _flatten(node.get("children"), dotted, out, value_key)


def _tree_root(doc):
    """Accept either {'content':[...]} (newer VRT) or a bare top-level list (older)."""
    if isinstance(doc, dict):
        return doc.get("content") or doc.get("categories") or []
    if isinstance(doc, list):
        return doc
    return []


def load_authoritative(vrt_json: pathlib.Path, mappings_dir: pathlib.Path | None):
    """Load a PINNED Bugcrowd VRT checkout from disk (no network). Returns (version, prio, cvss, cwe)."""
    doc = json.loads(vrt_json.read_text(encoding="utf-8"))
    version = ""
    if isinstance(doc, dict):
        meta = doc.get("metadata") or {}
        version = str(meta.get("release") or meta.get("version") or doc.get("release") or "").strip()
    prio: dict = {}
    _flatten(_tree_root(doc), "", prio, None)
    cvss: dict = {}
    cwe: dict = {}
    if mappings_dir:
        cvss_p = mappings_dir / "cvss_v3.json"
        cwe_p = mappings_dir / "cwe.json"
        if cvss_p.is_file():
            _flatten(_tree_root(json.loads(cvss_p.read_text(encoding="utf-8"))), "", cvss, "cvss_v3")
        if cwe_p.is_file():
            _flatten(_tree_root(json.loads(cwe_p.read_text(encoding="utf-8"))), "", cwe, "cwe")
    return version or "unknown", prio, cvss, cwe


def _overlay(prio: dict, cvss: dict, cwe: dict):
    """Build the slug/exclusion rows, overlaying authoritative values by vrt_id where the pin has them.
    Returns (slug_rows, excl_rows, drift[]). Drift notes where the seed and the pin disagree (honest)."""
    drift: list[str] = []

    def norm_cvss(v: str) -> str:
        v = (v or "").strip()
        if v and not v.upper().startswith("CVSS:"):
            v = "CVSS:3.1/" + v
        return v

    def apply(vid, seed_pri, seed_cvss, seed_cwe):
        p, c, w = seed_pri, seed_cvss, seed_cwe
        if vid and vid in prio:
            ap = prio[vid]
            if seed_pri not in ("n/a",) and ap != seed_pri:
                drift.append(f"priority {vid}: seed {seed_pri} != pin {ap} (using pin)")
            p = ap
        if vid and vid in cvss:
            ac = norm_cvss(cvss[vid])
            if seed_cvss and ac != seed_cvss:
                drift.append(f"cvss {vid}: seed differs from pin (using pin)")
            c = ac
        if vid and vid in cwe:
            w = cwe[vid]
        return p, c, w

    slug_rows = []
    for slug, vid, pri, cvssv, cwev, elig, note in SLUG_MAP:
        p, c, w = apply(vid, pri, cvssv, cwev)
        slug_rows.append((slug, vid, p, c, w, elig, note))
    excl_rows = []
    for match, vid, pri, cwev, action, elig, reason in BUILTIN_EXCLUSIONS:
        p, _c, w = apply(vid, pri, "", cwev)
        excl_rows.append((match, vid, p, w, action, elig, reason))
    return slug_rows, excl_rows, drift


def _cell(s: str) -> str:
    """Escape a table cell (pipes) and normalise empty to an em-dash placeholder."""
    s = (s or "").replace("|", "\\|").replace("\n", " ").strip()
    return s if s else "—"


def render_block(version: str, slug_rows, excl_rows) -> str:
    lines = [
        f"{BEGIN} — generated by tools/vrt-sync.py from VRT `{version}`; do NOT hand-edit this block "
        f"(edit the SLUG_MAP seed in the tool, or re-run with --vrt-json against a pinned release) -->",
        "",
        f"_VRT snapshot: `{version}` · generator: `tools/vrt-sync.py` · regenerate: `python tools/vrt-sync.py`_",
        "",
        "### Class -> VRT map (one row per shipped attack-skill slug)",
        "",
        "`cvss_v3_baseline` is the synthesizer's ANCHOR vector for the class (the reference it adjusts "
        "up/down with the PROVEN evidence) — it is NOT the per-finding `cvss_vector` (B5). `priority` is "
        "the VRT CLASS baseline (distinct from evidence `severity` and from B5 `tier`); `varies` means the "
        "evidence+CVSS pick the band, never the desired tier.",
        "",
        "| attack slug | vrt_id (dotted) | baseline `priority` | `cvss_v3_baseline` (anchor) | cwe | `default_eligibility` | note |",
        "|---|---|---|---|---|---|---|",
    ]
    for slug, vid, pri, cvssv, cwev, elig, note in slug_rows:
        lines.append(f"| {_cell(slug)} | {_cell(vid)} | {_cell(pri)} | {_cell(cvssv)} | "
                     f"{_cell(cwev)} | {_cell(elig)} | {_cell(note)} |")
    lines += [
        "",
        "### Built-in standard-exclusion defaults (the cross-platform P5 \"won't pay\" baseline)",
        "",
        "These only DOWN-RANK (`note` to a noted lead, or `control-test-only`) — they NEVER hard-drop a "
        "lead, and the operator's `scope.program.exclusions` always overrides. `match` is keyword-matched "
        "exactly as `attack.mjs` `eligibility()` matches (lower-cased substring, pipe-split, first-match-wins).",
        "",
        "| match (keyword, pipe-split) | vrt_id | baseline priority | cwe | `action` | `default_eligibility` | reason |",
        "|---|---|---|---|---|---|---|",
    ]
    for match, vid, pri, cwev, action, elig, reason in excl_rows:
        lines.append(f"| {_cell(match)} | {_cell(vid)} | {_cell(pri)} | {_cell(cwev)} | "
                     f"{_cell(action)} | {_cell(elig)} | {_cell(reason)} |")
    lines += ["", END]
    return "\n".join(lines)


def build_block(vrt_json=None, mappings_dir=None, version_override=None):
    """Return (block_text, version, drift[]). No args => embedded VRT-1.9 reference seed (no overlay)."""
    if vrt_json:
        version, prio, cvss, cwe = load_authoritative(pathlib.Path(vrt_json),
                                                      pathlib.Path(mappings_dir) if mappings_dir else None)
    else:
        version, prio, cvss, cwe = REFERENCE_VRT_VERSION, {}, {}, {}
    if version_override:
        version = version_override
    slug_rows, excl_rows, drift = _overlay(prio, cvss, cwe)
    return render_block(version, slug_rows, excl_rows), version, drift


def _extract_block(text: str) -> str | None:
    m = BLOCK_RE.search(text)
    return m.group(0) if m else None


def write_block(out: pathlib.Path, block: str) -> str:
    """Replace the block in `out` between the markers. Returns 'replaced' | 'created'. Refuses to clobber
    a file that exists but has no markers (it would destroy hand doctrine)."""
    if out.exists():
        text = out.read_text(encoding="utf-8")
        if not BLOCK_RE.search(text):
            raise ValueError(f"{out} exists but has no VRT-SYNC markers — refusing to overwrite hand doctrine")
        out.write_text(BLOCK_RE.sub(lambda _m: block, text, count=1), encoding="utf-8")
        return "replaced"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(block + "\n", encoding="utf-8")
    return "created"


def _attack_skills_from_source() -> set[str] | None:
    """Read ATTACK_SKILLS off workflows/attack.mjs so --check can assert lockstep. None if unreadable."""
    p = ROOT / "workflows" / "attack.mjs"
    if not p.is_file():
        return None
    m = re.search(r"const ATTACK_SKILLS\s*=\s*\[(.*?)\]", p.read_text(encoding="utf-8"), re.S)
    if not m:
        return None
    return set(re.findall(r"'([^']+)'", m.group(1)))


def _assert_lockstep() -> list[str]:
    """SLUG_MAP must cover EXACTLY the 31 ATTACK_SKILLS (no missing, no stray). Returns problems[]."""
    problems = []
    seed = [row[0] for row in SLUG_MAP]
    seed_set = set(seed)
    if len(seed) != len(seed_set):
        dupes = sorted({s for s in seed if seed.count(s) > 1})
        problems.append(f"SLUG_MAP has duplicate slugs: {', '.join(dupes)}")
    if seed_set != ATTACK_SKILLS:
        missing = ATTACK_SKILLS - seed_set
        stray = seed_set - ATTACK_SKILLS
        if missing:
            problems.append(f"SLUG_MAP missing shipped slugs: {', '.join(sorted(missing))}")
        if stray:
            problems.append(f"SLUG_MAP has slugs not in ATTACK_SKILLS: {', '.join(sorted(stray))}")
    return problems


def self_test() -> int:
    failures: list[str] = []

    # 1. lockstep: the seed covers exactly the 31 shipped slugs
    if len(ATTACK_SKILLS) != 31:
        failures.append(f"ATTACK_SKILLS has {len(ATTACK_SKILLS)} slugs, expected 31")
    failures += _assert_lockstep()

    # 2. honesty: every row's eligibility is in the closed set; a slug with no vrt_id is never 'payable'
    allowed_elig = {"payable", "excluded", "control-test-only", "unknown"}
    for slug, vid, pri, cvssv, cwev, elig, note in SLUG_MAP:
        if elig not in allowed_elig:
            failures.append(f"{slug}: eligibility '{elig}' not in {sorted(allowed_elig)}")
        if not vid and elig == "payable":
            failures.append(f"{slug}: marked payable but has no vrt_id (would be a fabricated class)")
        if vid and elig == "payable" and not cvssv:
            failures.append(f"{slug}: payable with a vrt_id must carry a cvss_v3_baseline anchor")
    # built-in exclusions must all down-rank, never pursue-normally
    for match, vid, pri, cwev, action, elig, reason in BUILTIN_EXCLUSIONS:
        if action not in ("note", "control-test-only"):
            failures.append(f"exclusion '{match}': action '{action}' must be note|control-test-only")
        if elig not in ("excluded", "control-test-only"):
            failures.append(f"exclusion '{match}': eligibility '{elig}' must be excluded|control-test-only")

    # 3. reference render is deterministic (idempotent) + carries the markers and a known row
    b1, v1, d1 = build_block()
    b2, _v2, _d2 = build_block()
    if b1 != b2:
        failures.append("reference render is not deterministic")
    if BEGIN not in b1 or END not in b1:
        failures.append("rendered block is missing its markers")
    if "server_side_injection.sql_injection" not in b1 or "self-xss" not in b1:
        failures.append("rendered block missing an expected row")
    if d1:
        failures.append(f"reference render reported drift against itself: {d1}")

    # 4. authoritative overlay from a SYNTHETIC pinned VRT (offline temp fixture) refreshes the anchor
    with tempfile.TemporaryDirectory() as td:
        t = pathlib.Path(td)
        maps = t / "mappings"
        maps.mkdir()
        # a tiny VRT where sql_injection is (deliberately) P2 so we can prove the pin WINS over the P1 seed
        vrt = {"metadata": {"release": "9.9-test"},
               "content": [{"id": "server_side_injection", "name": "SSI", "type": "category", "children": [
                   {"id": "sql_injection", "name": "SQLi", "type": "subcategory", "priority": 2}]}]}
        cvss = {"content": [{"id": "server_side_injection", "children": [
            {"id": "sql_injection", "cvss_v3": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}]}]}
        cwe = {"content": [{"id": "server_side_injection", "children": [
            {"id": "sql_injection", "cwe": ["CWE-9999"]}]}]}
        (t / "vrt.json").write_text(json.dumps(vrt), encoding="utf-8")
        (maps / "cvss_v3.json").write_text(json.dumps(cvss), encoding="utf-8")
        (maps / "cwe.json").write_text(json.dumps(cwe), encoding="utf-8")
        block, version, drift = build_block(vrt_json=t / "vrt.json", mappings_dir=maps)
        if version != "9.9-test":
            failures.append(f"authoritative version not picked up: {version!r}")
        if "CWE-9999" not in block:
            failures.append("authoritative CWE overlay not applied")
        if "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" not in block:
            failures.append("authoritative CVSS overlay not applied")
        if not any("sql_injection" in d and "seed P1 != pin P2" in d for d in drift):
            failures.append(f"drift detection failed (expected sql_injection P1!=P2): {drift}")
        # the sqli row in the overlaid block must now read P2 (pin), not P1 (seed)
        sqli_line = next((ln for ln in block.splitlines() if ln.startswith("| sqli ")), "")
        if "P2" not in sqli_line:
            failures.append(f"pin priority did not win over seed: {sqli_line!r}")

    # 5. write_block round-trip + marker-guard (never clobbers a marker-less file)
    with tempfile.TemporaryDirectory() as td:
        t = pathlib.Path(td)
        doc = t / "vrt.md"
        doc.write_text(f"# doctrine top\n\n{BEGIN} old -->\nstale\n{END}\n\n## doctrine tail\n", encoding="utf-8")
        write_block(doc, b1)
        after = doc.read_text(encoding="utf-8")
        if "stale" in after or "doctrine top" not in after or "doctrine tail" not in after:
            failures.append("write_block did not replace the block while preserving the surrounding doctrine")
        guard = t / "noblock.md"
        guard.write_text("# hand doctrine only, no markers\n", encoding="utf-8")
        try:
            write_block(guard, b1)
            failures.append("write_block clobbered a marker-less file (should refuse)")
        except ValueError:
            pass

    if failures:
        for f in failures:
            print("SELF-TEST FAIL:", f, file=sys.stderr)
        return 1
    print(f"vrt-sync self-test: OK ({len(SLUG_MAP)} slugs in lockstep; reference render deterministic; "
          f"authoritative overlay + drift + marker-guard verified)")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Regenerate brain/vrt.md's class->priority->CVSS->CWE map (offline).")
    ap.add_argument("--vrt-json", help="path to a PINNED Bugcrowd vrt.json (local checkout; no network)")
    ap.add_argument("--mappings-dir", help="dir holding cvss_v3.json + cwe.json from the same pinned release")
    ap.add_argument("--vrt-version", help="override the recorded VRT version string")
    ap.add_argument("--out", default=str(DEFAULT_OUT), help="markdown file to regenerate (default brain/vrt.md)")
    ap.add_argument("--check", action="store_true", help="lint: exit 1 if the block in --out drifts from a fresh render")
    ap.add_argument("--emit-block", action="store_true", help="print the generated block to stdout and exit")
    ap.add_argument("--self-test", action="store_true", help="run the offline self-test and exit")
    args = ap.parse_args(argv)

    if args.self_test:
        try:
            return self_test()
        except AssertionError as e:  # defensive — self_test uses explicit failures, not asserts
            print(f"vrt-sync self-test: FAIL — {e}", file=sys.stderr)
            return 1

    problems = _assert_lockstep()
    src = _attack_skills_from_source()
    if src is not None and src != {row[0] for row in SLUG_MAP}:
        miss = src - {row[0] for row in SLUG_MAP}
        stray = {row[0] for row in SLUG_MAP} - src
        if miss:
            problems.append(f"attack.mjs has slugs SLUG_MAP lacks: {', '.join(sorted(miss))}")
        if stray:
            problems.append(f"SLUG_MAP has slugs attack.mjs lacks: {', '.join(sorted(stray))}")
    if problems:
        for p in problems:
            print("LOCKSTEP:", p, file=sys.stderr)
        return 1

    if args.vrt_json and not pathlib.Path(args.vrt_json).is_file():
        print(f"vrt-sync: --vrt-json not found: {args.vrt_json} (it must be a PINNED local checkout — "
              f"this tool never fetches)", file=sys.stderr)
        return 2

    block, version, drift = build_block(args.vrt_json, args.mappings_dir, args.vrt_version)
    for d in drift:
        print("DRIFT:", d, file=sys.stderr)

    if args.emit_block:
        print(block)
        return 0

    out = pathlib.Path(args.out)
    if args.check:
        if not out.exists():
            print(f"vrt-sync --check: {out} does not exist", file=sys.stderr)
            return 1
        current = _extract_block(out.read_text(encoding="utf-8"))
        if current is None:
            print(f"vrt-sync --check: no VRT-SYNC block found in {out}", file=sys.stderr)
            return 1
        if current.strip() != block.strip():
            print(f"vrt-sync --check: {out} block is OUT OF SYNC — run: python tools/vrt-sync.py", file=sys.stderr)
            return 1
        print(f"vrt-sync --check: {out} block is in sync (VRT {version})")
        return 0

    try:
        status = write_block(out, block)
    except ValueError as e:
        print(f"vrt-sync: {e}", file=sys.stderr)
        return 1
    print(f"vrt-sync: {status} the class->VRT map in {out} "
          f"({len(SLUG_MAP)} slugs, {len(BUILTIN_EXCLUSIONS)} built-in exclusions, VRT {version})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
