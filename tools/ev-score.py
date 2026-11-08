#!/usr/bin/env python3
"""
Spider ev-score — the deterministic SEVERITY -> TIER -> EXPECTED-VALUE engine (fix3 B5, bounty mode).

The economic analogue of the flag/payout oracle, computed in code so the *economic* layer is
re-derivable by someone who distrusts the model (the oracle philosophy applied to severity/payout). It
turns a finding's PROVEN-impact CVSS 3.1 vector into a deterministic `cvss_score` + band, maps the band
(cross-checked with the VRT class `priority`) to a program reward `tier` via `program.reward_table`, and
composes the ranking scalar `expected_value` = reward_value(tier) x novelty_confidence x
eligibility_confidence. It adds NO new verifier, NO capability token, and touches NO scheduler/oracle
path — it is a pure, read-only projection over verdicts the cycle already produced (the oracle's
`cvss_vector`/`execution_evidence`, B4's `priority`/`eligibility`, B3's `novelty`).

CANONICAL FIELDS (fix3 §2 — one owner per field): this tool OWNS `cvss_vector`/`cvss_score`/`tier`/
`tier_reward`/`expected_value`/`ev_basis` (B5). It CONSUMES `priority`/`eligibility` (B4), `novelty`
(B3), `program.reward_table` (B1/B5), and `objective.min_payable_tier` (B2). It invents no field name.

RED LINE (evidence-bound severity): the `cvss_vector` comes ONLY from the PROVEN impact; `cvss_score` is
the deterministic Roundup of that vector (self-tested against the FIRST.org reference vectors); `tier` is
a table lookup of that score. There is NO path by which this tool raises a tier to reach a pay floor: a
finding whose evidence supports only P4 under a P3 floor is honestly `expected_value:0`, NEVER bumped.
`could-not-verify` novelty contributes 0.5 and is NEVER promoted to novel. `expected_value` is a ranking
signal, NEVER a payout claim — `submitted`/`paid` stay operator-attested (B6). When the evidence-CVSS
band diverges >1 level from the VRT `priority`, the finding is flagged `needs_human_review` (the drift
guardrail — catches BOTH inflation and under-grading; the tier is still the evidence band, never priority).

The CVSS 3.1 base-score formula (FIRST.org spec, implemented verbatim):
  ISS           = 1 - [(1-C) x (1-I) x (1-A)]
  Impact (S:U)  = 6.42 x ISS
  Impact (S:C)  = 7.52 x (ISS - 0.029) - 3.25 x (ISS - 0.02)^15
  Exploitability= 8.22 x AV x AC x PR x UI
  Base          = 0 if Impact <= 0, else Roundup(min(Impact + Exploitability, 10))   [S:U]
                  Roundup(min(1.08 x (Impact + Exploitability), 10))                  [S:C]
  Roundup       = the smallest 1-decimal number >= the input (integer-arithmetic form).

The EV model (honest, auditable — a ranking scalar, never a payout claim):
  novelty_confidence     = { novel/cleared: 1.0, could-not-verify: 0.5, likely-duplicate: 0.1, <absent>: 0.5 }
  eligibility_confidence = { payable: 1.0, control-test-only: 0.3, unknown: 0.5, excluded: 0.0, <absent>: 1.0 }
  reward_value(tier):
      0                                   if tier == P5  OR  tier below min_payable_tier
      realized median $ for this (program,class)   if --realized-reward is given (REALIZED mode — what the
                                          program ACTUALLY paid this class in prior runs; the learning loop)
      midpoint (min+max)/2                if a reward_table is present AND lists the tier  (MONETARY mode)
      ordinal rank {P1:4,P2:3,P3:2,P4:1}  if no reward_table (ORDINAL mode), OR a payable tier the table
                                          omits (mode stays ordinal for THIS finding, `unknown:true` set)
  acceptance_factor      = acceptance_prior in [0,1] if given, else 1.0   (P(accepted) for this (program,class),
                                          the Signal-weighted prior the B6 outcome loop learns across runs)
  expected_value         = reward_value(tier) x novelty_confidence x eligibility_confidence x acceptance_factor

COMPOUNDING (fix3 B1/B6 learning loop — this is what makes each engagement raise the next one's ranking):
  `--acceptance-prior` and `--realized-reward` are the two channels the per-(program,class) outcome history
  feeds back in. The synthesizer passes them from `state.objective.acceptance_prior` + the program
  `outcomes.jsonl` realized-median so the NEXT run EV-ranks by what ACTUALLY paid/was-accepted, not only the
  nominal table. Both are OPTIONAL and default to the identity (prior 1.0, no realized override) => a first
  run with no history is byte-identical to the nominal model. They scale only the RANKING EV — NEVER the
  evidence-bound cvss_score/tier (no inflation path).

Read-only. No network. stdlib-only, cross-OS (Windows/Linux/macOS). PyYAML is used to read a scope.yaml
reward_table IF present, else a tiny line-scan fallback reads the inline-flow `tiers: { P1: [..], .. }`
form; neither is required (--reward-table also accepts inline JSON / a .json file), and --self-test needs
nothing on disk.

    python tools/ev-score.py --vector CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    python tools/ev-score.py --vector <v> --reward-table targets/acme/scope.yaml --dedup novel \
                             --eligibility payable --priority P1 --min-payable-tier P3
    python tools/ev-score.py --vector <v> --reward-table '{"tiers":{"P1":[5000,20000]}}' --explain
    python tools/ev-score.py --finding targets/acme/findings.jsonl --reward-table scope.yaml
    python tools/ev-score.py --self-test          # offline self-check vs FIRST.org vectors, no target

Exit: 0 = scored (any honest result); 2 = bad args / invalid/missing CVSS vector / missing finding.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
import tempfile
from pathlib import Path

# --- CVSS 3.1 base metric numerics (FIRST.org spec) ------------------------------------------------
AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
# PR is scope-dependent: Privileges Required is "easier to exploit" from a Changed scope.
PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
BASE_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
VALID = {"AV": set(AV), "AC": set(AC), "PR": {"N", "L", "H"}, "UI": set(UI),
         "S": {"U", "C"}, "C": set(CIA), "I": set(CIA), "A": set(CIA)}

# --- tier vocabulary (shared with B4 priority / B2 min_payable_tier / the finding.schema `tier` enum)
# P1 (most severe) .. P5 (informational). A tier is "at/above the pay floor" when its SEVERITY_RANK is
# <= the floor's (P1 clears a P4 floor; P5 clears nothing). This tool defines NO new tier vocabulary.
SEVERITY_RANK = {"P1": 1, "P2": 2, "P3": 3, "P4": 4, "P5": 5}
# The ORDINAL reward weight used when no monetary reward_table is transcribed (a valid payout-maximizing
# *order* without dollar figures). P5 = 0 (never payable); P1 is the top.
ORDINAL_WEIGHT = {"P1": 4, "P2": 3, "P3": 2, "P4": 1, "P5": 0}
# Default CVSS band -> reward tier (when the program does not override). Critical->P1 .. None->P5.
BAND_TIER = {"Critical": "P1", "High": "P2", "Medium": "P3", "Low": "P4", "None": "P5"}

# Honesty is structural: could-not-verify is 0.5 and is NEVER the 1.0 of a cleared/novel finding.
NOVELTY_CONF = {
    "novel": 1.0, "cleared": 1.0,
    "could-not-verify": 0.5, "could_not_verify": 0.5,
    "likely-duplicate": 0.1, "likely_duplicate": 0.1,
}
ELIGIBILITY_CONF = {
    "payable": 1.0, "control-test-only": 0.3, "control_test_only": 0.3,
    "unknown": 0.5, "excluded": 0.0,
}
NOVELTY_ABSENT = 0.5        # no dedup run yet => the could-not-verify discount (never assume novel)
ELIGIBILITY_ABSENT = 1.0   # no eligibility annotation (e.g. recon) => no payout-policy penalty for ranking


# --- CVSS 3.1 deterministic base score -------------------------------------------------------------
def roundup(x: float) -> float:
    """CVSS 3.1 Roundup: the smallest number to 1 decimal place >= x, via the spec's integer form
    (absorbs float error). Matches FIRST.org's reference implementation (half-up at 1e-5)."""
    i = int(math.floor(x * 100000 + 0.5))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def parse_vector(vector: str) -> dict:
    """Parse a CVSS 3.0/3.1 vector string into its BASE metrics. Temporal/environmental metrics are
    ignored (only the base score is derived). Raises ValueError on a missing/invalid base metric."""
    raw = str(vector or "").strip()
    if not raw:
        raise ValueError("empty CVSS vector")
    metrics: dict[str, str] = {}
    for part in raw.split("/"):
        part = part.strip()
        if not part or ":" not in part:
            continue
        key, val = part.split(":", 1)
        key, val = key.strip().upper(), val.strip().upper()
        if key == "CVSS":                 # the version prefix, e.g. CVSS:3.1 — base formula is 3.0/3.1 identical
            if val not in ("3.0", "3.1"):
                raise ValueError(f"unsupported CVSS version {val!r} (this engine implements 3.0/3.1 base)")
            continue
        metrics[key] = val
    missing = [k for k in BASE_METRICS if k not in metrics]
    if missing:
        raise ValueError(f"vector missing base metric(s): {', '.join(missing)}")
    bad = [f"{k}:{metrics[k]}" for k in BASE_METRICS if metrics[k] not in VALID[k]]
    if bad:
        raise ValueError(f"invalid base metric value(s): {', '.join(bad)}")
    return {k: metrics[k] for k in BASE_METRICS}


def base_score(metrics: dict) -> float:
    """The deterministic CVSS 3.1 base score from parsed base metrics."""
    scope_changed = metrics["S"] == "C"
    c, i, a = CIA[metrics["C"]], CIA[metrics["I"]], CIA[metrics["A"]]
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    pr_table = PR_CHANGED if scope_changed else PR_UNCHANGED
    exploitability = 8.22 * AV[metrics["AV"]] * AC[metrics["AC"]] * pr_table[metrics["PR"]] * UI[metrics["UI"]]
    if impact <= 0:
        return 0.0
    combined = impact + exploitability
    if scope_changed:
        combined *= 1.08
    return roundup(min(combined, 10.0))


def band_of(score: float) -> str:
    """CVSS qualitative band. None(0.0) / Low(0.1-3.9) / Medium(4.0-6.9) / High(7.0-8.9) / Critical(9.0-10.0)."""
    if score <= 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


# --- helpers ---------------------------------------------------------------------------------------
def _num(x):
    """Emit an integer when the value is whole (so 12500.0 -> 12500, matching the schema examples),
    else round to 2 decimals. Keeps the JSON clean and the ranking stable."""
    f = float(x)
    if f == int(f):
        return int(f)
    return round(f, 2)


def _norm_tier(t) -> str | None:
    t = str(t or "").strip().upper()
    return t if t in SEVERITY_RANK else None


def _below_floor(tier: str, floor: str | None) -> bool:
    """A tier is below the pay floor when it is LESS severe than the floor. Absent floor => no filtering
    (floor P5), so only the intrinsic P5 reward_value of 0 applies."""
    f = _norm_tier(floor) or "P5"
    return SEVERITY_RANK[tier] > SEVERITY_RANK[f]


# --- reward_table loading (inline JSON / JSON file / scope.yaml program.reward_table) --------------
def _extract_tiers(doc) -> tuple[str, dict] | None:
    """From a parsed JSON/YAML object pull (currency, {tier:[min,max]}). Accepts the reward_table at the
    top level ({tiers:{...}} or a bare {P1:[..],..}), under reward_table, or under program.reward_table."""
    if not isinstance(doc, dict):
        return None
    node = doc
    for key in ("program", "reward_table"):
        if isinstance(node, dict) and isinstance(node.get(key), dict):
            node = node[key]
    currency = "USD"
    tiers_src = None
    if isinstance(node, dict) and isinstance(node.get("tiers"), dict):
        currency = str(node.get("currency", "USD") or "USD")
        tiers_src = node["tiers"]
    elif isinstance(node, dict) and any(_norm_tier(k) for k in node):
        tiers_src = node
    if not isinstance(tiers_src, dict):
        return None
    tiers: dict[str, list] = {}
    for k, v in tiers_src.items():
        t = _norm_tier(k)
        if not t:
            continue
        if isinstance(v, (list, tuple)) and len(v) >= 2:
            try:
                lo, hi = float(v[0]), float(v[1])
            except (TypeError, ValueError):
                continue
            tiers[t] = [min(lo, hi), max(lo, hi)]
    return (currency, tiers) if tiers else None


def _scan_reward_table(text: str) -> tuple[str, dict] | None:
    """PyYAML-free fallback: find an inline-flow `tiers: { P1: [min,max], ... }` (the schema.md/
    scope.example form), optionally with a nearby `currency:`. Tolerant and never fatal."""
    import re
    currency = "USD"
    mc = re.search(r"(?m)^\s*currency:\s*([A-Za-z]{3})\b", text)
    if mc:
        currency = mc.group(1).upper()
    mt = re.search(r"tiers:\s*\{(.+?)\}", text, re.DOTALL)
    if not mt:
        return None
    tiers: dict[str, list] = {}
    for m in re.finditer(r"(P[1-5])\s*:\s*\[\s*([0-9]+(?:\.[0-9]+)?)\s*,\s*([0-9]+(?:\.[0-9]+)?)\s*\]",
                         mt.group(1)):
        lo, hi = float(m.group(2)), float(m.group(3))
        tiers[m.group(1)] = [min(lo, hi), max(lo, hi)]
    return (currency, tiers) if tiers else None


def load_reward_table(arg: str | None) -> tuple[str, dict] | None:
    """Resolve --reward-table into (currency, tiers) or None (=> ordinal EV). Accepts inline JSON, a
    .json file, or a scope.yaml (reads program.reward_table via PyYAML, else a line-scan). Never fatal:
    an unparseable source degrades to ordinal mode."""
    if not arg:
        return None
    s = arg.strip()
    if s.startswith("{"):
        try:
            return _extract_tiers(json.loads(s))
        except (json.JSONDecodeError, ValueError):
            return None
    p = Path(arg)
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    try:                                   # a JSON file?
        return _extract_tiers(json.loads(text))
    except (json.JSONDecodeError, ValueError):
        pass
    try:                                   # a YAML file, PyYAML present
        import yaml  # optional; stdlib-first design, so we never require it
        doc = yaml.safe_load(text) or {}
        t = _extract_tiers(doc)
        if t:
            return t
    except Exception:                      # noqa: BLE001 — missing PyYAML OR a parse error -> line-scan
        pass
    return _scan_reward_table(text)


# --- the economic grade ----------------------------------------------------------------------------
def reward_value(tier: str, table: tuple[str, dict] | None, floor: str | None,
                 realized: float | None = None):
    """Deterministic reward_value for a tier. Returns (value, mode, unknown, reward_range). P5 and any
    below-floor tier are honestly 0 (never payable / below the pay floor). When `realized` (the median $
    this (program,class) ACTUALLY paid in prior runs, from the B6 outcome loop) is given for a payable
    tier, it OVERRIDES the nominal table (REALIZED mode — rank by what really paid). Else a monetary table
    yields the tier's midpoint; absence of a table yields the ordinal rank; a payable tier a present table
    OMITS falls back to ordinal for this finding with unknown=True ('EV unknown, not 0')."""
    if tier == "P5":
        return 0, ("monetary" if table else "ordinal"), False, None
    if _below_floor(tier, floor):
        return 0, ("monetary" if table else "ordinal"), False, None
    # REALIZED override (learning loop): what this (program,class) actually paid > the nominal table.
    if realized is not None:
        try:
            rv = float(realized)
        except (TypeError, ValueError):
            rv = None
        if rv is not None and rv > 0:
            return _num(rv), "realized", False, None
    if table is not None:
        _currency, tiers = table
        rng = tiers.get(tier)
        if rng:
            lo, hi = rng
            return _num((lo + hi) / 2.0), "monetary", False, [_num(lo), _num(hi)]
        # payable tier at/above floor but not transcribed: unknown range -> ordinal proxy, flagged.
        return ORDINAL_WEIGHT[tier], "ordinal", True, None
    return ORDINAL_WEIGHT[tier], "ordinal", False, None


def _acceptance_factor(acceptance_prior) -> float:
    """Clamp an acceptance_prior to [0,1]; absent/invalid => 1.0 (no history yet => no penalty)."""
    if acceptance_prior is None:
        return 1.0
    try:
        p = float(acceptance_prior)
    except (TypeError, ValueError):
        return 1.0
    return min(1.0, max(0.0, p))


def ev_score(vector: str, *, priority: str | None = None, dedup: str | None = None,
             eligibility: str | None = None, reward_table: tuple[str, dict] | None = None,
             min_payable_tier: str | None = None, acceptance_prior=None, realized_reward=None) -> dict:
    """The full deterministic grade: CVSS score+band (from PROVEN impact) -> reward tier -> expected
    value. Pure: no network, no mutation, no model. The vector is the evidence; the tier is never
    inflated to the priority — a >1-band divergence only raises `needs_human_review`. `acceptance_prior`
    (P(accepted) for this program,class) and `realized_reward` (median $ it actually paid) are the B6
    learning-loop channels: both default to the identity so a first run is byte-identical, and both scale
    only the RANKING EV, never the evidence-bound score/tier."""
    metrics = parse_vector(vector)
    score = base_score(metrics)
    band = band_of(score)
    tier = BAND_TIER[band]              # evidence-derived; NEVER overridden by priority (no inflation)

    # drift guardrail (B5 owns the CVSS side): the evidence band vs the VRT class baseline priority.
    prio = _norm_tier(priority) if (priority and str(priority).strip().lower() != "varies") else None
    drift = abs(SEVERITY_RANK[tier] - SEVERITY_RANK[prio]) if prio else 0
    needs_human_review = bool(prio) and drift > 1

    # EV factors (honest discounts; could-not-verify is never 1.0).
    nov_key = str(dedup or "").strip().lower()
    novelty_confidence = NOVELTY_CONF.get(nov_key, NOVELTY_ABSENT) if nov_key else NOVELTY_ABSENT
    elig_key = str(eligibility or "").strip().lower()
    eligibility_confidence = ELIGIBILITY_CONF.get(elig_key, ELIGIBILITY_ABSENT) if elig_key else ELIGIBILITY_ABSENT
    acceptance_factor = _acceptance_factor(acceptance_prior)   # B6 learning: P(accepted) this program+class

    rv, mode, unknown, reward_range = reward_value(tier, reward_table, min_payable_tier, realized=realized_reward)
    expected_value = _num(rv * novelty_confidence * eligibility_confidence * acceptance_factor)

    norm_vector = f"CVSS:3.1/{'/'.join(f'{k}:{metrics[k]}' for k in BASE_METRICS)}"
    out = {
        "cvss_vector": norm_vector,
        "first_url": f"https://www.first.org/cvss/calculator/3.1#{norm_vector}",
        "cvss_score": score,
        "band": band,
        "tier": tier,
        "expected_value": expected_value,
        "ev_basis": {
            "reward_value": _num(rv),
            "novelty_confidence": novelty_confidence,
            "eligibility_confidence": eligibility_confidence,
            "acceptance_factor": acceptance_factor,
            "mode": mode,
        },
        "min_payable_tier": _norm_tier(min_payable_tier) or None,
        "below_pay_floor": (rv == 0 and tier != "P5" and _below_floor(tier, min_payable_tier)),
        "unknown_reward": unknown,
        "priority": prio,
        "cvss_vs_priority_drift": drift,
        "needs_human_review": needs_human_review,
        "note": "evidence-bound: cvss_vector is from PROVEN impact; cvss_score is the deterministic CVSS "
                "3.1 Roundup; tier is a reward_table lookup of the band, NEVER inflated to the priority or "
                "to clear a pay floor. expected_value is a RANKING signal, never a payout claim "
                "(submitted/paid are operator-attested, B6). could-not-verify novelty = 0.5, never promoted.",
    }
    if reward_range is not None:
        out["tier_reward"] = reward_range     # [min,max] from the table; omitted in ordinal mode
    if mode == "monetary" and reward_table is not None:
        out["currency"] = reward_table[0]
    return out


def explain(v: dict) -> str:
    """Human-readable grade: every term of the score, band, tier, and each EV factor (operator UX)."""
    b = v["ev_basis"]
    lines = [
        f"CVSS   {v['cvss_vector']}",
        f"       score {v['cvss_score']}  ->  band {v['band']}  ->  reward tier {v['tier']}",
        f"       verify {v['first_url']}",
    ]
    if v.get("priority"):
        drift = v["cvss_vs_priority_drift"]
        tag = "  <- DRIFT >1 band: needs_human_review" if v["needs_human_review"] else ""
        lines.append(f"       VRT priority {v['priority']} (class baseline); band-vs-priority drift {drift}{tag}")
    lines.append("EV     expected_value = reward_value x novelty_confidence x eligibility_confidence")
    rng = f"  range {v['tier_reward']} {v.get('currency','')}".rstrip() if "tier_reward" in v else ""
    unk = "  (UNKNOWN range — tier not in reward_table; ordinal proxy)" if v["unknown_reward"] else ""
    floor = f"  (below pay floor {v['min_payable_tier']})" if v["below_pay_floor"] else ""
    lines.append(f"       reward_value          = {b['reward_value']}   [{b['mode']} mode]{rng}{unk}{floor}")
    lines.append(f"       novelty_confidence    = {b['novelty_confidence']}")
    lines.append(f"       eligibility_confidence= {b['eligibility_confidence']}")
    lines.append(f"       -------------------------------------------------")
    lines.append(f"       expected_value        = {v['expected_value']}   (ranking signal, NOT a payout claim)")
    return "\n".join(lines)


# --- optional finding input (fills unset flags from a finding JSON, like payout-gate ergonomics) ---
def read_findings(src: str) -> list[dict]:
    """Read one finding JSON object, or a findings.jsonl (one object per line). `-` reads stdin."""
    text = sys.stdin.read() if src == "-" else Path(src).read_text(encoding="utf-8", errors="replace")
    text = text.strip()
    if not text:
        return []
    try:
        doc = json.loads(text)
        if isinstance(doc, list):
            return [d for d in doc if isinstance(d, dict)]
        if isinstance(doc, dict):
            return [doc]
    except json.JSONDecodeError:
        pass
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def grade_finding(f: dict, reward_table, min_payable_tier,
                  acceptance_prior=None, realized_reward=None) -> dict:
    """Grade one finding dict (a finding with no cvss_vector has no tier/EV — skipped honestly: EV is
    defined only over oracle-proven, CVSS-bearing findings). acceptance_prior/realized_reward (the B6
    learning channels) come from the caller, or per-finding fields if present."""
    vec = f.get("cvss_vector", "")
    if not str(vec or "").strip():
        return {"id": f.get("id", ""), "skipped": "no cvss_vector (not a graded/proven finding)"}
    v = ev_score(vec, priority=f.get("priority"), dedup=f.get("novelty"),
                 eligibility=f.get("eligibility"), reward_table=reward_table,
                 min_payable_tier=min_payable_tier,
                 acceptance_prior=f.get("acceptance_prior", acceptance_prior),
                 realized_reward=f.get("realized_reward", realized_reward))
    v["id"] = f.get("id", "")
    return v


# --- self-test (offline; pins the FIRST.org reference vectors + the honesty rules) -----------------
def self_test() -> int:
    # 1) CVSS engine pinned to FIRST.org / canonical reference vectors (proves determinism, not trust).
    refs = {
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,   # unauth RCE, scope changed -> capped 10
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,    # unauth full-impact, scope unchanged
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N": 5.4,    # low-priv partial C/I
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,    # reflected XSS reference
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H": 7.8,    # local, user-interaction
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H": 5.9,    # high AC, availability only
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N": 0.0,    # no impact -> 0.0
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N": 6.4,    # PR:L in a changed scope (0.68 branch)
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H": 7.2,    # PR:H unchanged (0.27 branch)
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": 1.8,    # a Low-band finding -> tier P4
    }
    for vec, expected in refs.items():
        got = base_score(parse_vector(vec))
        assert got == expected, f"CVSS score {got} != {expected} for {vec}"

    # band -> tier default map
    assert band_of(10.0) == "Critical" and BAND_TIER["Critical"] == "P1"
    assert band_of(1.8) == "Low" and BAND_TIER["Low"] == "P4"
    assert band_of(0.0) == "None" and BAND_TIER["None"] == "P5"

    # the official FIRST.org calculator link accompanies every grade (the "verify on the FIRST
    # calculator" cross-check that /triage stage 3 cites)
    _u = ev_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert _u["first_url"] == "https://www.first.org/cvss/calculator/3.1#" + _u["cvss_vector"], _u["first_url"]

    # roundup is the smallest 1-decimal >= input
    assert roundup(4.00) == 4.0 and roundup(4.01) == 4.1 and roundup(5.349327) == 5.4

    crit = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"   # 9.8 -> Critical -> P1
    low = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"    # 1.8 -> Low -> P4
    table = ("USD", {"P1": [5000, 20000], "P2": [2000, 5000], "P3": [500, 2000], "P4": [100, 500]})

    # 2) MONETARY midpoint + full-confidence EV
    v = ev_score(crit, dedup="novel", eligibility="payable", reward_table=table)
    assert v["tier"] == "P1" and v["cvss_score"] == 9.8, v
    assert v["ev_basis"]["mode"] == "monetary" and v["ev_basis"]["reward_value"] == 12500, v
    assert v["tier_reward"] == [5000, 20000], v
    assert v["expected_value"] == 12500, v   # 12500 x 1.0 x 1.0

    # 3) could-not-verify DISCOUNTS EV by 0.5 and is NEVER promoted to 1.0
    v = ev_score(crit, dedup="could-not-verify", eligibility="payable", reward_table=table)
    assert v["ev_basis"]["novelty_confidence"] == 0.5, v
    assert v["expected_value"] == 6250, v    # 12500 x 0.5
    assert v["ev_basis"]["novelty_confidence"] != 1.0
    # likely-duplicate -> 0.1
    v = ev_score(crit, dedup="likely-duplicate", eligibility="payable", reward_table=table)
    assert v["ev_basis"]["novelty_confidence"] == 0.1 and v["expected_value"] == 1250, v
    # absent dedup -> 0.5 (never assume novel)
    v = ev_score(crit, eligibility="payable", reward_table=table)
    assert v["ev_basis"]["novelty_confidence"] == 0.5, v

    # 4) eligibility:excluded -> EV 0 (recorded, deprioritized, never deleted); control-test-only -> 0.3
    v = ev_score(crit, dedup="novel", eligibility="excluded", reward_table=table)
    assert v["ev_basis"]["eligibility_confidence"] == 0.0 and v["expected_value"] == 0, v
    v = ev_score(crit, dedup="novel", eligibility="control-test-only", reward_table=table)
    assert v["ev_basis"]["eligibility_confidence"] == 0.3 and v["expected_value"] == 3750, v  # 12500x1.0x0.3
    v = ev_score(crit, dedup="novel", eligibility="unknown", reward_table=table)
    assert v["ev_basis"]["eligibility_confidence"] == 0.5, v
    # absent eligibility -> 1.0 (no payout-policy penalty for ranking)
    v = ev_score(crit, dedup="novel", reward_table=table)
    assert v["ev_basis"]["eligibility_confidence"] == 1.0, v

    # 5) TIER FLOOR — a P4 under a P3 floor is below the floor => EV 0, tier NOT inflated
    v = ev_score(low, dedup="novel", eligibility="payable", reward_table=table, min_payable_tier="P3")
    assert v["tier"] == "P4" and v["below_pay_floor"] is True and v["expected_value"] == 0, v
    assert v["ev_basis"]["reward_value"] == 0, v
    # the SAME P4 with no floor (floor defaults to P5) pays its P4 midpoint
    v = ev_score(low, dedup="novel", eligibility="payable", reward_table=table)
    assert v["below_pay_floor"] is False and v["ev_basis"]["reward_value"] == 300, v  # (100+500)/2
    assert v["expected_value"] == 300, v

    # 6) P5 is intrinsically non-payable (reward_value 0) even with a table and no floor
    v = ev_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N", dedup="novel", eligibility="payable",
                 reward_table=table)
    assert v["tier"] == "P5" and v["expected_value"] == 0, v

    # 7) ORDINAL fallback (no reward_table) still yields a valid payout-maximizing ORDER (P1 > P4 > P5)
    v1 = ev_score(crit, dedup="novel", eligibility="payable")
    v4 = ev_score(low, dedup="novel", eligibility="payable")
    assert v1["ev_basis"]["mode"] == "ordinal" and v1["expected_value"] == 4, v1
    assert v4["expected_value"] == 1, v4
    assert v1["expected_value"] > v4["expected_value"], "ordinal order must rank P1 above P4"
    assert "tier_reward" not in v1, "ordinal mode must omit tier_reward"

    # 8) a payable tier the table OMITS -> unknown range, ordinal proxy, EV not 0
    partial = ("USD", {"P2": [2000, 5000], "P3": [500, 2000]})   # P1/P4 omitted
    v = ev_score(crit, dedup="novel", eligibility="payable", reward_table=partial)
    assert v["tier"] == "P1" and v["unknown_reward"] is True, v
    assert v["ev_basis"]["mode"] == "ordinal" and v["expected_value"] == 4, v
    assert v["expected_value"] != 0, "an omitted payable tier is 'unknown', not 0"

    # 9) DRIFT guardrail — evidence band vs VRT priority deviates >1 band => needs_human_review; the tier
    #    is STILL the evidence band (never inflated to the priority).
    v = ev_score(crit, priority="P4", dedup="novel", eligibility="payable", reward_table=table)
    assert v["tier"] == "P1" and v["cvss_vs_priority_drift"] == 3 and v["needs_human_review"] is True, v
    v = ev_score(crit, priority="P2", dedup="novel", eligibility="payable", reward_table=table)
    assert v["needs_human_review"] is False and v["tier"] == "P1", v   # 1-band divergence is tolerated
    v = ev_score(crit, priority="varies", reward_table=table)
    assert v["needs_human_review"] is False, "a 'varies' priority cannot drift"

    # 10) invalid / incomplete vectors are rejected (fail-closed, not an assumed score)
    for bad in ("", "not-a-vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",   # missing A
                "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",                    # bad AV
                "CVSS:2.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"):                   # unsupported version
        try:
            ev_score(bad)
            assert False, f"expected ValueError for {bad!r}"
        except ValueError:
            pass

    # 11) reward_table loaders: inline JSON, a .json file, and a scope.yaml line-scan (no PyYAML needed)
    assert _extract_tiers({"tiers": {"P1": [1, 3]}}) == ("USD", {"P1": [1.0, 3.0]})
    assert _extract_tiers({"program": {"reward_table": {"currency": "EUR", "tiers": {"P2": [2, 4]}}}}) \
        == ("EUR", {"P2": [2.0, 4.0]})
    assert load_reward_table('{"tiers":{"P1":[5000,20000]}}') == ("USD", {"P1": [5000.0, 20000.0]})
    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        (t / "rt.json").write_text(json.dumps({"reward_table": {"tiers": {"P1": [5000, 20000]}}}),
                                   encoding="utf-8")
        assert load_reward_table(str(t / "rt.json")) == ("USD", {"P1": [5000.0, 20000.0]})
        (t / "scope.yaml").write_text(
            "target: acme\n"
            "program:\n"
            "  name: Acme\n"
            "  reward_table:\n"
            "    currency: USD\n"
            "    tiers: { P1: [5000, 20000], P2: [2000, 5000], P3: [500, 2000], P4: [100, 500] }\n"
            "objective:\n  mode: bounty\n  min_payable_tier: P3\n",
            encoding="utf-8")
        got = load_reward_table(str(t / "scope.yaml"))
        assert got is not None and got[1].get("P1") == [5000.0, 20000.0] and got[1].get("P4") == [100.0, 500.0], got
        # end-to-end through the file: a P1 finding reads its midpoint from the scanned table
        v = ev_score(crit, dedup="novel", eligibility="payable", reward_table=got, min_payable_tier="P3")
        assert v["expected_value"] == 12500 and v["ev_basis"]["mode"] == "monetary", v
        # findings.jsonl round-trip + grade_finding (a no-vector finding is skipped honestly)
        (t / "findings.jsonl").write_text(
            json.dumps({"id": "f-0001", "cvss_vector": crit, "novelty": "novel", "eligibility": "payable"})
            + "\n" + json.dumps({"id": "f-0002", "type": "lead"}) + "\n", encoding="utf-8")
        fs = read_findings(str(t / "findings.jsonl"))
        g0 = grade_finding(fs[0], got, "P3")
        g1 = grade_finding(fs[1], got, "P3")
        assert g0["tier"] == "P1" and g0["expected_value"] == 12500, g0
        assert g1.get("skipped"), "a finding with no cvss_vector must be skipped, not graded"

    # 12) explain() renders without error and reflects the grade
    txt = explain(ev_score(crit, priority="P1", dedup="novel", eligibility="payable", reward_table=table))
    assert "reward tier P1" in txt and "expected_value" in txt

    # 13) B6 LEARNING CHANNELS — acceptance_prior scales EV; realized_reward overrides the table; neither
    #     touches the evidence-bound score/tier; both default to the identity (first run == nominal model).
    base = ev_score(crit, dedup="novel", eligibility="payable", reward_table=table)     # EV 12500, no history
    assert base["ev_basis"]["acceptance_factor"] == 1.0 and base["expected_value"] == 12500, base
    half = ev_score(crit, dedup="novel", eligibility="payable", reward_table=table, acceptance_prior=0.5)
    assert half["ev_basis"]["acceptance_factor"] == 0.5 and half["expected_value"] == 6250, half  # 12500 x 0.5
    assert half["tier"] == "P1" and half["cvss_score"] == 9.8, "acceptance_prior must NOT change score/tier"
    # a program that historically pays this class ~2000 (realized) ranks it by 2000, not the 12500 midpoint
    real = ev_score(crit, dedup="novel", eligibility="payable", reward_table=table, realized_reward=2000)
    assert real["ev_basis"]["mode"] == "realized" and real["ev_basis"]["reward_value"] == 2000, real
    assert real["expected_value"] == 2000 and real["tier"] == "P1", real
    # realized + acceptance_prior compose; a below-floor finding stays 0 regardless of realized
    both = ev_score(crit, dedup="novel", eligibility="payable", reward_table=table,
                    realized_reward=2000, acceptance_prior=0.25)
    assert both["expected_value"] == 500, both                                          # 2000 x 1 x 1 x 0.25
    floored = ev_score(low, dedup="novel", eligibility="payable", reward_table=table,
                       realized_reward=9999, min_payable_tier="P3")
    assert floored["below_pay_floor"] is True and floored["expected_value"] == 0, "below-floor stays 0 even with realized"
    # an out-of-range prior is clamped to [0,1]; absent realized keeps nominal mode
    assert _acceptance_factor(5) == 1.0 and _acceptance_factor(-1) == 0.0 and _acceptance_factor(None) == 1.0
    assert ev_score(crit, eligibility="payable", reward_table=table)["ev_basis"]["mode"] == "monetary"

    print("ev-score self-test: OK (10 FIRST.org CVSS vectors; band->tier; monetary midpoint + ordinal "
          "fallback; honest novelty/eligibility discounts; evidence-bound tier floor; P5 non-payable; "
          "unknown-tier proxy; drift guardrail; invalid-vector rejection; table loaders + jsonl round-trip; "
          "B6 acceptance_prior + realized_reward learning channels)")
    return 0


# --- CLI -------------------------------------------------------------------------------------------
def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Deterministic CVSS 3.1 severity -> reward tier -> expected value (fix3 B5, bounty mode)")
    ap.add_argument("--vector", help="a CVSS 3.1 base vector built from PROVEN impact, e.g. "
                                     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    ap.add_argument("--finding", help="path to a finding JSON / findings.jsonl (or '-'); fills "
                                      "vector/priority/novelty/eligibility from each finding")
    ap.add_argument("--reward-table", dest="reward_table",
                    help="program.reward_table as inline JSON, a .json file, or a scope.yaml "
                         "(reads program.reward_table). Absent => ordinal EV")
    ap.add_argument("--priority", help="the VRT CLASS baseline priority P1..P5 (B4) — cross-check only; "
                                       ">1-band drift from the evidence tier flags needs_human_review")
    ap.add_argument("--dedup", help="B3 novelty: novel | could-not-verify | likely-duplicate (absent => 0.5)")
    ap.add_argument("--eligibility", help="B4 eligibility: payable | control-test-only | unknown | excluded "
                                          "(absent => 1.0)")
    ap.add_argument("--min-payable-tier", dest="min_payable_tier",
                    help="the program pay floor P1..P5 (B2); a tier below it is expected_value 0")
    ap.add_argument("--acceptance-prior", dest="acceptance_prior", type=float,
                    help="B6 learning: P(accepted) in [0,1] for this (program,class), from "
                         "state.objective.acceptance_prior. Scales the RANKING EV only. Absent => 1.0")
    ap.add_argument("--realized-reward", dest="realized_reward", type=float,
                    help="B6 learning: the median $ this (program,class) ACTUALLY paid in prior runs "
                         "(from the program outcomes.jsonl). Overrides the nominal table midpoint. Absent => table")
    ap.add_argument("--explain", action="store_true", help="print every term (score, band, tier, EV factors)")
    ap.add_argument("--self-test", action="store_true", help="run the offline self-test and exit")
    args = ap.parse_args(argv)

    if args.self_test:
        try:
            return self_test()
        except AssertionError as e:
            print(f"ev-score self-test: FAIL — {e}")
            return 1

    table = load_reward_table(args.reward_table)
    if args.reward_table and table is None:
        print("ev-score: could not parse --reward-table — falling back to ordinal EV", file=sys.stderr)

    # --finding: grade each finding in the file (vector/priority/novelty/eligibility come from it; an
    # explicit --vector/--priority/etc. is NOT applied in finding mode to keep per-finding grading honest).
    if args.finding and not args.vector:
        try:
            findings = read_findings(args.finding)
        except (OSError, json.JSONDecodeError) as e:
            print(f"ev-score: could not read finding(s) from {args.finding}: {e}", file=sys.stderr)
            return 2
        if not findings:
            print("ev-score: no findings to grade", file=sys.stderr)
            return 2
        graded = [grade_finding(f, table, args.min_payable_tier,
                                acceptance_prior=args.acceptance_prior,
                                realized_reward=args.realized_reward) for f in findings]
        if args.explain:
            print("\n\n".join(explain(g) if "cvss_score" in g else
                              f"FINDING {g.get('id') or '<unnamed>'} — {g.get('skipped')}" for g in graded))
        else:
            print(json.dumps(graded[0] if len(graded) == 1 else graded, indent=2, ensure_ascii=False))
        return 0

    if not args.vector:
        print("ev-score: --vector (or --finding, or --self-test) is required", file=sys.stderr)
        return 2
    try:
        result = ev_score(args.vector, priority=args.priority, dedup=args.dedup,
                          eligibility=args.eligibility, reward_table=table,
                          min_payable_tier=args.min_payable_tier,
                          acceptance_prior=args.acceptance_prior,
                          realized_reward=args.realized_reward)
    except ValueError as e:
        print(f"ev-score: {e} (fail-closed — no assumed score)", file=sys.stderr)
        return 2

    print(explain(result) if args.explain else json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
