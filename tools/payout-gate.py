#!/usr/bin/env python3
"""
Spider payout-gate — the deterministic PAYOUT-READINESS auditor (fix3 B2, bounty mode).

The economic analogue of the fix2 flag-capture oracle, computed in code so "payable" is
re-derivable by someone who distrusts the model (the oracle philosophy, applied to the submission
decision). This tool adds NO new verifier and NO capability token: it is a pure deterministic AND
over verdicts the cycle ALREADY produces, exactly like tools/flag-scan.py is a read-only projection
over raw/. The synthesizer runs it per finding as it writes findings.jsonl (single-writer invariant);
/triage enforces the result (a payout_ready:false finding cannot be ruled SUBMIT).

A finding `f` is `payout_ready:true` IFF all SIX sub-gates hold; each false term appends a structured
string to `payout_blockers` (no fabrication, no inflation — a missing CVSS vector is a blocker, not an
assumed tier; could-not-verify is NEVER promoted to cleared/novel):

  1 impact-proven  (EXISTING oracle) — f.verified && !f.refuted && f.oracle_type set
  2 in-scope/ROE   (EXISTING scope)  — f.target host in scope.yaml hosts/netblocks, not out_of_scope
  3 eligible class (B4)              — f.eligibility == 'payable' (not excluded / control-test-only / unknown)
  4 paying tier    (B5)              — f.cvss_vector + f.tier present, tier at/above objective.min_payable_tier
  5 dedup-cleared  (B3)             — f.novelty == 'novel' (could-not-verify is a blocker UNLESS waive_unverified)
  6 report-ready   (ISO-29147)      — f.repro + f.poc_path + f.detail + f.target + (f.cwe | f.remediation)

The 8-rung ladder (the brain's progress signal), each rung the max reached given the fields present:
  signal -> reproduced -> impact-proven -> severity-graded -> dedup-cleared -> report-ready -> submitted -> paid
`payout_ready` <=> the ladder reached `report-ready` (all six autonomous gates). `submitted`/`paid`
are OPERATOR-ATTESTED (B6) — Spider records, the operator submits; this tool never claims them.

CANONICAL FIELDS (fix3 §2 — one owner per field): this tool CONSUMES the frozen names
`eligibility` (B4), `cvss_vector`/`tier` (B5), `novelty` (B3) and OWNS `payout_ready`/`payout_blockers`/
`payout_distance` (B2). It invents no field name.

Read-only. No network. stdlib-only, cross-OS. PyYAML is used to read scope.yaml IF present, else a
small line-scan fallback reads the keys this gate needs; neither is required by --self-test.

    python tools/payout-gate.py --finding targets/acme/findings.jsonl --scope targets/acme/scope.yaml
    python tools/payout-gate.py --finding f.json --scope scope.yaml --explain
    python tools/payout-gate.py --self-test          # offline self-check, no target needed

Exit: 0 = gate computed (ready or not, both honest results); 2 = bad args / missing finding / bad JSON.
With --fail-unless-ready, exit 3 if ANY gated finding is not payout_ready (a submission guard for CI).
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

# P1 (highest / most severe) .. P5 (informational). A tier is "at/above the pay floor" when its rank
# is <= the floor's rank (P1 clears a P4 floor; P5 never clears a P4 floor). One vocabulary, shared
# with B5's reward tiers and the finding.schema `tier` enum — this gate defines no new tier vocabulary.
TIER_RANK = {"P1": 1, "P2": 2, "P3": 3, "P4": 4, "P5": 5}
DEFAULT_FLOOR = "P4"

# The 8-rung payout ladder (fix3 B2). `submitted`/`paid` are operator-attested (B6), never set here.
LADDER = ["signal", "reproduced", "impact-proven", "severity-graded",
          "dedup-cleared", "report-ready", "submitted", "paid"]
AUTONOMOUS_TOP = "report-ready"   # the highest rung this tool can reach on its own

# ISO/IEC 29147 report elements this gate lints (fix3 B2 red-line sub-check #6).
ISO_ELEMENTS = ("repro", "poc", "impact", "affected-host", "cwe-or-remediation")


# --- scope authority (reuse guard.py, the canonical scope check; never widen it) --------------------
def _in_scope(host: str, scope: dict) -> bool:
    """Host in scope.yaml hosts/IPs/netblocks AND not in out_of_scope. Prefers tools/guard.py:in_scope
    (the ONE scope authority the rest of Spider uses) so this gate consumes scope identically and never
    widens it; falls back to a conservative inline check if guard is unavailable (keeps --self-test
    self-contained)."""
    host = str(host or "").strip().lower().rsplit("/", 1)[0]
    if "://" in host:                       # a url target -> take the host[:port] authority
        host = host.split("://", 1)[1].split("/", 1)[0]
    host = host.rsplit(":", 1)[0] if host.count(":") == 1 else host  # strip a :port (not an IPv6 group)
    if not host:
        return False
    exact = bool(scope.get("scope_exact", True))
    entries = [str(x).strip().lower() for x in (scope.get("hosts", []) or [])]
    entries += [str(x).strip().lower() for x in (scope.get("netblocks", []) or [])]
    oos = {str(x).strip().lower() for x in (scope.get("out_of_scope", []) or [])}
    if host in oos:
        return False
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from guard import in_scope as _guard_in_scope  # type: ignore
        return bool(_guard_in_scope(host, entries, exact=exact))
    except Exception:                        # noqa: BLE001 — guard missing/parse error -> inline fallback
        import ipaddress
        hosts, nets = set(), []
        for s in entries:
            if "/" in s:
                try:
                    nets.append(ipaddress.ip_network(s, strict=False)); continue
                except ValueError:
                    pass
            hosts.add(s)
        try:
            ip = ipaddress.ip_address(host)
            if any(ip in n for n in nets):
                return True
        except ValueError:
            pass
        if exact:
            return host in hosts
        return any(host == h or host.endswith("." + h) for h in hosts)


def _present(v) -> bool:
    """A field is 'present' when it carries real content (non-empty string / non-empty list)."""
    if v is None:
        return False
    if isinstance(v, str):
        return bool(v.strip())
    if isinstance(v, (list, tuple, dict)):
        return len(v) > 0
    return bool(v)


# --- the six sub-gates -----------------------------------------------------------------------------
def _gate_impact(f: dict) -> tuple[bool, str]:
    ok = (f.get("verified") is True and f.get("refuted") is not True and _present(f.get("oracle_type")))
    return ok, "" if ok else "impact: not oracle-proven"


def _gate_scope(f: dict, scope: dict) -> tuple[bool, str]:
    host = f.get("target", "")
    if not scope:
        return False, "scope: no scope.yaml provided — cannot verify in-scope (fail-closed)"
    ok = _in_scope(host, scope)
    return ok, "" if ok else f"scope: host {host or '<none>'} not in scope.yaml / over-policy"


def _gate_eligible(f: dict) -> tuple[bool, str]:
    elig = str(f.get("eligibility", "") or "").strip().lower()
    if elig == "payable":
        return True, ""
    reason = str(f.get("eligibility_reason", "") or "").strip()
    if elig == "excluded":
        return False, f"eligibility: excluded — {reason or 'class not payable under the program'} (B4)"
    if elig == "control-test-only":
        return False, "eligibility: control-test-only — not a payable submission (B4)"
    return False, "eligibility: unknown — class not confirmed payable (B4)"


def _gate_tier(f: dict, scope: dict) -> tuple[bool, str]:
    if not _present(f.get("cvss_vector")):
        return False, "tier: no CVSS vector"
    tier = str(f.get("tier", "") or "").strip().upper()
    if tier not in TIER_RANK:
        return False, "tier: no reward tier assigned"
    floor = str(scope.get("min_payable_tier", DEFAULT_FLOOR) or DEFAULT_FLOOR).strip().upper()
    if floor not in TIER_RANK:
        floor = DEFAULT_FLOOR
    if TIER_RANK[tier] > TIER_RANK[floor]:    # higher rank number = less severe = below the floor
        return False, f"tier: {tier} below pay floor {floor}"
    return True, ""


def _gate_dedup(f: dict, scope: dict) -> tuple[bool, str]:
    nov = str(f.get("novelty", "") or "").strip().lower()
    if nov == "novel":
        return True, ""
    if nov == "likely-duplicate":
        ref = str(f.get("novelty_ref", "") or "").strip()
        return False, "dedup: likely-duplicate" + (f" (ref {ref})" if ref else "")
    if nov == "could-not-verify":
        # Honest dedup: could-not-verify is a BLOCKER (operator confirms novelty) UNLESS the operator
        # waived it in scope.objective.novelty.waive_unverified. The waiver CLEARS the rung by operator
        # attestation; it NEVER auto-promotes novelty to 'novel' (this tool mutates no field).
        if scope.get("waive_unverified"):
            return True, ""
        return False, "dedup: could-not-verify — operator must confirm novelty"
    return False, "dedup: not checked"


def _gate_report(f: dict) -> tuple[bool, list[str]]:
    missing = []
    if not _present(f.get("repro")):
        missing.append("repro")
    if not _present(f.get("poc_path")):
        missing.append("poc")
    if not _present(f.get("detail")):
        missing.append("impact")
    if not _present(f.get("target")):
        missing.append("affected-host")
    if not (_present(f.get("cwe")) or _present(f.get("remediation"))):
        missing.append("cwe-or-remediation")
    return (not missing), [f"report: missing {m}" for m in missing]


# --- the composite gate + the ladder ---------------------------------------------------------------
def payout_gate(finding: dict, scope: dict | None = None) -> dict:
    """Deterministic AND of the six sub-gates + the 8-rung distance ladder. Returns the B2 verdict
    (payout_ready / payout_blockers / payout_distance) plus a per-sub-gate audit trail. Pure: never
    mutates the finding, never touches the network, never calls the model."""
    f = finding or {}
    scope = scope or {}

    g1_ok, b1 = _gate_impact(f)
    g2_ok, b2 = _gate_scope(f, scope)
    g3_ok, b3 = _gate_eligible(f)
    g4_ok, b4 = _gate_tier(f, scope)
    g5_ok, b5 = _gate_dedup(f, scope)
    g6_ok, b6s = _gate_report(f)

    sub_gates = [
        {"gate": "impact-proven", "owner": "oracle", "ok": g1_ok, "blocker": b1},
        {"gate": "in-scope",      "owner": "scope",  "ok": g2_ok, "blocker": b2},
        {"gate": "eligible",      "owner": "B4",     "ok": g3_ok, "blocker": b3},
        {"gate": "paying-tier",   "owner": "B5",     "ok": g4_ok, "blocker": b4},
        {"gate": "dedup-cleared", "owner": "B3",     "ok": g5_ok, "blocker": b5},
        {"gate": "report-ready",  "owner": "ISO-29147", "ok": g6_ok, "blocker": "; ".join(b6s)},
    ]
    # report-ready may carry several missing elements -> expand them so each is its own blocker line.
    blockers = []
    for x, extra in zip(sub_gates, [[b1], [b2], [b3], [b4], [b5], b6s]):
        if not x["ok"]:
            blockers.extend([s for s in extra if s])

    payout_ready = len(blockers) == 0

    # The ladder: the highest rung whose predicate AND every lower rung's predicate hold. scope /
    # eligible / paying-tier are AND terms of the top rung (report-ready == payout_ready), so a finding
    # can be graded/dedup-cleared yet not report-ready (blocked on scope/eligibility/tier) — honest.
    reproduced = (str(f.get("proven_state", "")).lower() in ("misconfig_proven", "impact_proven")
                  or f.get("verified") is True or _present(f.get("execution_evidence")))
    graded = _present(f.get("cvss_vector")) and str(f.get("tier", "") or "").strip().upper() in TIER_RANK
    rung_preds = [
        True,          # signal        — a finding/candidate exists
        reproduced,    # reproduced    — the defect was reproduced (misconfig/impact proven)
        g1_ok,         # impact-proven — the existing oracle met
        graded,        # severity-graded — CVSS vector + reward tier assigned (not yet floor-checked)
        g5_ok,         # dedup-cleared — novelty cleared (or operator-waived could-not-verify)
        payout_ready,  # report-ready  — ALL SIX sub-gates (== payout_ready)
    ]
    distance = "signal"
    for i, ok in enumerate(rung_preds):
        if ok:
            distance = LADDER[i]
        else:
            break

    return {
        "id": f.get("id", ""),
        "payout_ready": payout_ready,
        "payout_blockers": blockers,
        "payout_distance": distance,
        "sub_gates": sub_gates,
        "note": "deterministic composition of existing honest verdicts (fix3 B2); no new verifier, no "
                "capability token. payout_ready <=> ladder reached report-ready. submitted/paid are "
                "operator-attested (B6). Severity/tier are evidence-bound — never inflated to clear a floor.",
    }


def explain(verdict: dict) -> str:
    """Human-readable ladder + per-sub-gate pass/fail + the exact blocker list (operator UX, B2 idea #4)."""
    lines = []
    lines.append(f"FINDING {verdict.get('id') or '<unnamed>'} — payout_ready: "
                 f"{'YES' if verdict['payout_ready'] else 'NO'}  (distance: {verdict['payout_distance']})")
    lines.append("  ladder:")
    reached_i = LADDER.index(verdict["payout_distance"]) if verdict["payout_distance"] in LADDER else 0
    for i, rung in enumerate(LADDER):
        if rung in ("submitted", "paid"):
            mark = "..."   # operator-attested tail — not computed by this tool
        else:
            mark = "[x]" if i <= reached_i else "[ ]"
        tail = "  <- operator-attested (B6)" if rung in ("submitted", "paid") else ""
        lines.append(f"    {mark} {rung}{tail}")
    lines.append("  sub-gates:")
    for g in verdict["sub_gates"]:
        mark = "PASS" if g["ok"] else "FAIL"
        reason = f" — {g['blocker']}" if (not g["ok"] and g["blocker"]) else ""
        lines.append(f"    [{mark}] {g['gate']} ({g['owner']}){reason}")
    if verdict["payout_blockers"]:
        lines.append("  blockers (what this finding still needs):")
        for b in verdict["payout_blockers"]:
            lines.append(f"    - {b}")
    else:
        lines.append("  blockers: none — report-ready; the operator submits (Spider records).")
    return "\n".join(lines)


# --- scope.yaml reading (PyYAML if present, else a targeted line-scan fallback) ---------------------
def read_scope(path: Path) -> dict:
    """Parse ONLY the keys this gate needs from scope.yaml: hosts (+ ips), netblocks, out_of_scope,
    scope_exact, objective.min_payable_tier, objective.novelty.waive_unverified. Returns the normalized
    scope dict payout_gate() expects. Never fatal — an unreadable scope yields an empty dict (fail-closed
    in _gate_scope)."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    try:
        import yaml  # optional; stdlib-first design, so we never require it
        doc = yaml.safe_load(text) or {}
        return _normalize_scope(doc)
    except Exception:  # noqa: BLE001 — missing PyYAML OR a parse error -> line-scan fallback
        return _scan_scope(text)


def _normalize_scope(doc: dict) -> dict:
    hosts = []
    for h in (doc.get("hosts") or []):
        if isinstance(h, dict):
            if h.get("host"):
                hosts.append(str(h["host"]))
            if h.get("ip"):
                hosts.append(str(h["ip"]))
        elif h:
            hosts.append(str(h))
    obj = doc.get("objective") or {}
    nov = (obj.get("novelty") or {}) if isinstance(obj, dict) else {}
    return {
        "hosts": hosts,
        "netblocks": [str(x) for x in (doc.get("netblocks") or [])],
        "out_of_scope": [str(x) for x in (doc.get("out_of_scope") or [])],
        "scope_exact": bool(doc.get("scope_exact", True)),
        "min_payable_tier": str(obj.get("min_payable_tier", DEFAULT_FLOOR) or DEFAULT_FLOOR)
        if isinstance(obj, dict) else DEFAULT_FLOOR,
        "waive_unverified": bool(nov.get("waive_unverified", False)) if isinstance(nov, dict) else False,
    }


def _flow_list(val: str) -> list[str]:
    """Parse an inline flow list `[a, b, c]` (or a bare scalar) into a list of trimmed tokens."""
    val = val.strip()
    if val.startswith("[") and val.endswith("]"):
        inner = val[1:-1].strip()
        return [t.strip().strip("'\"") for t in inner.split(",") if t.strip()] if inner else []
    return [val.strip("'\"")] if val else []


def _scan_scope(text: str) -> dict:
    """Indentation-aware fallback for the subset of scope.yaml this gate reads (no PyYAML)."""
    hosts: list[str] = []
    netblocks: list[str] = []
    out_of_scope: list[str] = []
    scope_exact = True
    min_payable_tier = DEFAULT_FLOOR
    waive_unverified = False
    in_hosts = in_objective = in_novelty = False

    def val_of(line: str) -> str:
        v = line.split(":", 1)[1].strip()
        cut = v.find(" #")
        return (v[:cut] if cut != -1 else v).strip()

    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        stripped = raw.strip()
        if indent == 0:
            in_hosts = stripped.startswith("hosts:")
            in_objective = stripped.startswith("objective:")
            in_novelty = False
            if stripped.startswith("netblocks:"):
                netblocks.extend(_flow_list(val_of(raw)))
            elif stripped.startswith("out_of_scope:"):
                out_of_scope.extend(_flow_list(val_of(raw)))
            elif stripped.startswith("scope_exact:"):
                scope_exact = val_of(raw).lower() not in ("false", "no", "0", "")
            continue
        if in_hosts:
            if stripped.startswith("- host:") or stripped.startswith("-host:"):
                hosts.append(val_of(stripped.lstrip("- ")))
            elif stripped.startswith("host:"):
                hosts.append(val_of(stripped))
            elif stripped.startswith("ip:"):
                hosts.append(val_of(stripped))
            elif stripped.startswith("- "):     # a bare "- app.acme.com" style host list
                hosts.append(stripped[2:].strip().strip("'\""))
        elif in_objective:
            if stripped.startswith("min_payable_tier:"):
                min_payable_tier = val_of(stripped) or DEFAULT_FLOOR
            elif stripped.startswith("novelty:"):
                in_novelty = True
            elif in_novelty and stripped.startswith("waive_unverified:"):
                waive_unverified = val_of(stripped).lower() in ("true", "yes", "1")
            elif indent <= 2 and not stripped.startswith(("min_payable_tier:", "novelty:", "mode:",
                                                          "goal:", "flag_format:", "where_hint:")):
                in_novelty = False
    return {
        "hosts": hosts, "netblocks": netblocks, "out_of_scope": out_of_scope,
        "scope_exact": scope_exact, "min_payable_tier": min_payable_tier,
        "waive_unverified": waive_unverified,
    }


# --- finding input ---------------------------------------------------------------------------------
def read_findings(src: str) -> list[dict]:
    """Read one finding JSON object, or a findings.jsonl (one object per line). `-` reads stdin."""
    if src == "-":
        text = sys.stdin.read()
    else:
        text = Path(src).read_text(encoding="utf-8", errors="replace")
    text = text.strip()
    if not text:
        return []
    try:                                   # a single JSON object/array?
        doc = json.loads(text)
        if isinstance(doc, list):
            return [d for d in doc if isinstance(d, dict)]
        if isinstance(doc, dict):
            return [doc]
    except json.JSONDecodeError:
        pass
    out = []                               # else JSONL: one object per line
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        out.append(json.loads(line))
    return out


# --- self-test (offline, no target, no PyYAML required) --------------------------------------------
def self_test() -> int:
    base = {
        "id": "f-0001", "target": "app.acme.com", "type": "IDOR",
        "verified": True, "refuted": False, "oracle_type": "idor-cross-account",
        "eligibility": "payable", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "tier": "P2", "novelty": "novel",
        "repro": "1. GET /export/2 as user A ...", "poc_path": "raw/attack-h-01/poc.sh",
        "detail": "cross-account object read on /export/{id}", "cwe": ["CWE-639"],
    }
    scope = {"hosts": ["app.acme.com"], "netblocks": [], "out_of_scope": ["status.acme.com"],
             "scope_exact": True, "min_payable_tier": "P4", "waive_unverified": False}

    def g(f, s=scope):
        return payout_gate(f, s)

    # 1) full pass -> payout_ready, distance report-ready
    v = g(base)
    assert v["payout_ready"] is True, f"full-pass should be payout_ready: {v['payout_blockers']}"
    assert v["payout_distance"] == "report-ready", v["payout_distance"]

    # 2) no CVSS vector -> blocked (tier), caps at impact-proven (not graded)
    v = g({**base, "cvss_vector": ""})
    assert v["payout_ready"] is False and any("no CVSS vector" in b for b in v["payout_blockers"])
    assert v["payout_distance"] == "impact-proven", v["payout_distance"]

    # 3) out-of-scope host -> NEVER payout_ready (scope is a hard AND term), but can still be graded/cleared
    v = g({**base, "target": "evil.example.com"})
    assert v["payout_ready"] is False and any(b.startswith("scope:") for b in v["payout_blockers"])
    # also an explicit out_of_scope host is blocked
    v = g({**base, "target": "status.acme.com"})
    assert v["payout_ready"] is False and any(b.startswith("scope:") for b in v["payout_blockers"])

    # 4) tier below the pay floor -> blocked, caps at dedup-cleared, tier NOT inflated
    v = g({**base, "tier": "P5"})
    assert v["payout_ready"] is False and any("below pay floor" in b for b in v["payout_blockers"])
    assert v["payout_distance"] == "dedup-cleared", v["payout_distance"]
    v = g({**base, "tier": "P4"}, {**scope, "min_payable_tier": "P3"})
    assert v["payout_ready"] is False and any("P4 below pay floor P3" in b for b in v["payout_blockers"])

    # 5) could-not-verify -> blocked, caps at severity-graded (never cleared/novel)
    v = g({**base, "novelty": "could-not-verify"})
    assert v["payout_ready"] is False and any("could-not-verify" in b for b in v["payout_blockers"])
    assert v["payout_distance"] == "severity-graded", v["payout_distance"]
    # waive_unverified CLEARS the rung by operator attestation (never auto-promoted)
    v = g({**base, "novelty": "could-not-verify"}, {**scope, "waive_unverified": True})
    assert v["payout_ready"] is True, f"waiver should clear dedup: {v['payout_blockers']}"
    assert v["payout_distance"] == "report-ready"

    # 6) likely-duplicate -> blocked dedup
    v = g({**base, "novelty": "likely-duplicate", "novelty_ref": "h1#1234567"})
    assert v["payout_ready"] is False and any("likely-duplicate" in b for b in v["payout_blockers"])
    assert "h1#1234567" in " ".join(v["payout_blockers"])

    # 7) not oracle-proven -> blocked impact, caps at reproduced/signal
    v = g({**base, "verified": False, "oracle_type": ""})
    assert v["payout_ready"] is False and any("not oracle-proven" in b for b in v["payout_blockers"])
    assert v["payout_distance"] in ("signal", "reproduced"), v["payout_distance"]
    v = g({**base, "verified": False, "oracle_type": "", "proven_state": "not_reproduced",
           "execution_evidence": ""})
    assert v["payout_distance"] == "signal", v["payout_distance"]

    # 8) excluded / control-test-only / unknown eligibility -> blocked
    for elig, needle in (("excluded", "excluded"), ("control-test-only", "control-test-only"),
                         ("unknown", "unknown")):
        v = g({**base, "eligibility": elig})
        assert v["payout_ready"] is False and any(b.startswith("eligibility:") and needle in b
                                                  for b in v["payout_blockers"]), (elig, v["payout_blockers"])

    # 9) missing report element -> blocked report (each element its own line)
    v = g({**base, "repro": "", "cwe": [], "remediation": ""})
    assert v["payout_ready"] is False
    assert any("missing repro" in b for b in v["payout_blockers"])
    assert any("missing cwe-or-remediation" in b for b in v["payout_blockers"])
    # remediation alone satisfies the cwe-or-remediation element
    v = g({**base, "cwe": [], "remediation": "add object-level authz on GET /export/{id}"})
    assert v["payout_ready"] is True, v["payout_blockers"]

    # 10) explain() renders without error and reflects the verdict
    txt = explain(g(base))
    assert "payout_ready: YES" in txt and "[x] report-ready" in txt

    # 11) file round-trip through the line-scan fallback (no PyYAML needed): write a scope.yaml + a
    #     findings.jsonl, read them back, and confirm the same verdict.
    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        (t / "scope.yaml").write_text(
            "target: acme\n"
            "scope_exact: true\n"
            "hosts:\n"
            "  - host: app.acme.com\n"
            "    ip: 203.0.113.10\n"
            "out_of_scope: [status.acme.com]\n"
            "objective:\n"
            "  mode: bounty\n"
            "  min_payable_tier: P3\n"
            "  novelty:\n"
            "    waive_unverified: false\n",
            encoding="utf-8")
        sc = _scan_scope((t / "scope.yaml").read_text(encoding="utf-8"))
        assert sc["min_payable_tier"] == "P3", sc
        assert sc["waive_unverified"] is False, sc
        assert "app.acme.com" in sc["hosts"] and "203.0.113.10" in sc["hosts"], sc
        assert "status.acme.com" in sc["out_of_scope"], sc
        # P4 finding now below the P3 floor read from the file
        v = payout_gate({**base, "tier": "P4"}, sc)
        assert v["payout_ready"] is False and any("below pay floor P3" in b for b in v["payout_blockers"])
        # an in-scope IP target resolves against the host ip
        v = payout_gate({**base, "target": "203.0.113.10", "tier": "P1"}, sc)
        assert v["payout_ready"] is True, v["payout_blockers"]
        # findings.jsonl round-trip
        (t / "findings.jsonl").write_text(
            json.dumps(base) + "\n" + json.dumps({**base, "id": "f-0002", "tier": "P5"}) + "\n",
            encoding="utf-8")
        fs = read_findings(str(t / "findings.jsonl"))
        assert len(fs) == 2 and fs[0]["id"] == "f-0001" and fs[1]["id"] == "f-0002"

    print("payout-gate self-test: OK (six sub-gates, 8-rung ladder, honest dedup, evidence-bound tier, "
          "scope-fidelity, fallback scope parse, jsonl round-trip)")
    return 0


# --- CLI -------------------------------------------------------------------------------------------
def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Deterministic payout-readiness gate over a finding (fix3 B2, bounty mode)")
    ap.add_argument("--finding", help="path to a finding JSON / findings.jsonl, or '-' for stdin")
    ap.add_argument("--scope", help="path to scope.yaml (reads hosts/netblocks/out_of_scope/"
                                    "objective.min_payable_tier/objective.novelty.waive_unverified)")
    ap.add_argument("--explain", action="store_true", help="print the ladder + each sub-gate pass/fail")
    ap.add_argument("--fail-unless-ready", action="store_true",
                    help="exit 3 if ANY gated finding is not payout_ready (submission guard)")
    ap.add_argument("--self-test", action="store_true", help="run the offline self-test and exit")
    args = ap.parse_args(argv)

    if args.self_test:
        try:
            return self_test()
        except AssertionError as e:
            print(f"payout-gate self-test: FAIL — {e}")
            return 1

    if not args.finding:
        print("payout-gate: --finding is required (or use --self-test)", file=sys.stderr)
        return 2

    scope = read_scope(Path(args.scope)) if args.scope else {}
    if not scope:
        print("payout-gate: no scope.yaml (or empty) — the in-scope sub-gate will fail closed",
              file=sys.stderr)

    try:
        findings = read_findings(args.finding)
    except (OSError, json.JSONDecodeError) as e:
        print(f"payout-gate: could not read finding(s) from {args.finding}: {e}", file=sys.stderr)
        return 2
    if not findings:
        print("payout-gate: no findings to gate", file=sys.stderr)
        return 2

    verdicts = [payout_gate(f, scope) for f in findings]
    if args.explain:
        print("\n\n".join(explain(v) for v in verdicts))
    else:
        out = verdicts[0] if len(verdicts) == 1 else verdicts
        print(json.dumps(out, indent=2, ensure_ascii=False))

    if args.fail_unless_ready and any(not v["payout_ready"] for v in verdicts):
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
