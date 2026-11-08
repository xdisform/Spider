#!/usr/bin/env python3
r"""
Spider payout-calc — the deterministic, local/offline RUN-LEVEL bounty economics roll-up (fix3 B1).

The economic analogue of tools/flag-scan.py: determinism over an LLM's mental arithmetic, so the
expected-value a run reports is reproducible by anyone who distrusts the model. It is **bounty-mode only**
(scope.objective.mode:bounty); the synthesizer prefers it over hand arithmetic when it merges the bounty
objective into state.objective.

OWNERSHIP (the fix3 canonical field contract — one owner per field, no drift). payout-calc is B1-owned and
operates at the PROGRAM/OBJECTIVE level. It CONSUMES the per-finding verdicts the sibling tools already
wrote into findings.jsonl — `payout_ready` (B2), `tier`/`tier_reward`/`expected_value`/`payout_distance`
(B5/B2), `eligibility` (B4), `novelty` (B3) — and only AGGREGATES them into the B1-owned state.objective
economics. It computes NO per-finding verdict, emits NO per-finding canonical field, and is NOT a second
verifier: it never decides payability (that is B2's `payout_ready`), never grades severity, never fabricates
a number. A paying tier with no reward_table entry propagates as `unknown:true`, never a silent 0.

    # roll up a run's findings into the state.objective economics block
    python tools/payout-calc.py --rollup --findings targets/acme/findings.jsonl --min-payable-tier P4
    python tools/payout-calc.py --rollup --target-dir targets/acme          # reads findings.jsonl + scope.yaml
    # a deterministic reward-table lookup helper (raw range + asset-scaled range; no payable verdict)
    python tools/payout-calc.py --reward --tier P2 --reward-table '{"P1":[5000,20000],"P2":[2000,5000]}' --asset-multiplier 1.5
    python tools/payout-calc.py --self-test                                  # offline self-check, no target needed

Read-only. No network. stdlib-only, cross-OS (Windows/Linux/macOS). PyYAML is used to read
scope.objective.min_payable_tier / currency IF present, else a tiny line-scan fallback reads them; neither
is required because the values can be passed explicitly (the synthesizer knows them from args.objective).
No wall-clock / randomness is used anywhere (state.objective.ts is the synthesizer's to set).

Exit: 0 = computed (an honest zero roll-up is still success); 2 = bad args / missing input.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# The reward-tier vocabulary is the VRT priorities P1 (Critical) .. P5 (Informational). P5 is not payable
# (absent from a reward_table). A LOWER number is a HIGHER/better tier. "at or above the floor" == the
# tier's number <= the floor's number (doctrine: brain/bounty.md).
TIER_ORDER = ["P1", "P2", "P3", "P4", "P5"]
TIER_RANK = {t: i for i, t in enumerate(TIER_ORDER)}  # P1->0 (best) .. P5->4

# The B2 per-finding 8-rung payout ladder, lowest -> highest. The run-level distance is the coarse
# projection of the best finding's rung (the max reached across findings).
LADDER = ["signal", "reproduced", "impact-proven", "severity-graded",
          "dedup-cleared", "report-ready", "submitted", "paid"]
LADDER_RANK = {r: i for i, r in enumerate(LADDER)}

DEFAULT_MIN_PAYABLE_TIER = "P4"
DEFAULT_CURRENCY = "USD"


def tier_rank(tier: str) -> int | None:
    """Rank of a VRT tier (P1..P5); None if unknown. Lower = better/higher-paying."""
    return TIER_RANK.get(str(tier).strip().upper()) if tier else None


def meets_floor(tier: str, floor: str) -> bool:
    """True iff `tier` is at or above the pay floor (tier number <= floor number). Honest: an unknown
    tier or floor never 'meets' the floor."""
    tr, fr = tier_rank(tier), tier_rank(floor)
    return tr is not None and fr is not None and tr <= fr


def normalize_reward_table(rt) -> dict:
    """Accept either {"tiers": {P1:[min,max], ...}} (the scope.program.reward_table shape) or a bare
    {P1:[min,max], ...} map. Returns {TIER: [min,max]} with upper-cased keys; invalid rows dropped."""
    if isinstance(rt, dict) and isinstance(rt.get("tiers"), dict):
        rt = rt["tiers"]
    out: dict[str, list] = {}
    if isinstance(rt, dict):
        for k, v in rt.items():
            if isinstance(v, (list, tuple)) and len(v) == 2 and all(isinstance(x, (int, float)) for x in v):
                out[str(k).strip().upper()] = [v[0], v[1]]
    return out


def reward_range(reward_table: dict, tier: str, asset_multiplier: float = 1.0) -> dict:
    """Deterministic reward lookup for one tier. Returns the raw program range AND the asset-scaled range
    (program.asset_tiers is a B1 economic field). This is an economic magnitude ONLY — it emits no
    `payable`/`payout_ready`/`tier` verdict (those are B2/B5's)."""
    table = normalize_reward_table(reward_table)
    t = str(tier).strip().upper()
    rng = table.get(t)
    if rng is None:
        return {"tier": t, "reward_range": None, "asset_multiplier": asset_multiplier,
                "scaled_range": None, "unknown": True,
                "note": f"tier {t} has no reward_table entry -> reward unknown (never assumed 0)"}
    scaled = [round(rng[0] * asset_multiplier, 2), round(rng[1] * asset_multiplier, 2)]
    return {"tier": t, "reward_range": [rng[0], rng[1]], "asset_multiplier": asset_multiplier,
            "scaled_range": scaled, "unknown": False,
            "note": "raw program range + asset-scaled range; an economic magnitude, never a payout claim"}


def _num(x):
    return x if isinstance(x, (int, float)) and not isinstance(x, bool) else None


def _is_payout_ready(f: dict) -> bool:
    return f.get("payout_ready") is True


def rollup(findings: list[dict], min_payable_tier: str = DEFAULT_MIN_PAYABLE_TIER,
           currency: str = DEFAULT_CURRENCY, blocked: bool = False, dry: bool = False) -> dict:
    """Aggregate the per-finding economic verdicts into the B1-owned state.objective economics block.

    Consumes (never recomputes): payout_ready (B2), tier/tier_reward/expected_value/payout_distance
    (B5/B2), eligibility (B4), novelty (B3). `blocked`/`dry` are synthesizer-supplied (it alone sees the
    attack return / stall) and only affect `status` when there is no payable milestone. Precedence per
    brain/bounty.md: payable > blocked > dry > open (a payable finding is a milestone, not terminal)."""
    payable = [f for f in findings if _is_payout_ready(f)]

    # EV range: honest sum of tier_reward over payout_ready findings; unknown-propagation.
    low = high = 0
    unknown = False
    for f in payable:
        tr = f.get("tier_reward")
        if isinstance(tr, (list, tuple)) and len(tr) == 2 and all(_num(x) is not None for x in tr):
            low += tr[0]
            high += tr[1]
        else:
            # a payout_ready finding whose paying tier has no reward_table entry -> EV range unknown
            unknown = True
    point = round((low + high) / 2, 2) if (low or high) else 0
    ev_total = sum(_num(f.get("expected_value")) or 0 for f in payable)

    # best payable finding: best (lowest) tier rank, tie-break higher expected_value, then id.
    def _best_key(f):
        tr = tier_rank(f.get("tier"))
        return (tr if tr is not None else len(TIER_ORDER),
                -(_num(f.get("expected_value")) or 0),
                str(f.get("id", "")))
    best = min(payable, key=_best_key) if payable else None

    # ev_ranked: all findings carrying a numeric expected_value, descending (stable by id on ties).
    ev_candidates = [f for f in findings if _num(f.get("expected_value")) is not None]
    ev_ranked = [str(f.get("id", "")) for f in
                 sorted(ev_candidates, key=lambda f: (-(_num(f.get("expected_value")) or 0), str(f.get("id", ""))))]

    # eligible_pending: eligible (B4) AND could-not-verify (B3) AND not yet payable -> awaits operator novelty call.
    eligible_pending = sum(
        1 for f in findings
        if f.get("eligibility") == "payable" and f.get("novelty") == "could-not-verify" and not _is_payout_ready(f))

    dedup_cleared = any(f.get("novelty") == "novel" for f in findings)

    # distance: coarse projection = the highest B2 rung reached across findings.
    rungs = [LADDER_RANK[f["payout_distance"]] for f in findings
             if isinstance(f.get("payout_distance"), str) and f.get("payout_distance") in LADDER_RANK]
    distance = LADDER[max(rungs)] if rungs else ""

    status = "payable" if payable else ("blocked" if blocked else ("dry" if dry else "open"))

    return {
        "mode": "bounty",
        "status": status,
        "distance": distance,
        "payable_count": len(payable),
        "best_tier": (best.get("tier", "") if best else ""),
        "best_finding": (str(best.get("id", "")) if best else ""),
        "dedup_cleared": dedup_cleared,
        "eligible_pending": eligible_pending,
        "expected_value": {"currency": currency, "low": low, "high": high, "point": point, "unknown": unknown},
        "expected_value_total": ev_total,
        "ev_ranked": ev_ranked,
        "min_payable_tier": str(min_payable_tier).strip().upper(),
        "note": ("run-level roll-up of per-finding verdicts (payout_ready B2 / tier B5 / eligibility B4 / "
                 "novelty B3); an aggregate, never a per-finding verdict. unknown=true => a paying tier "
                 "lacks a reward_table entry (never a silent 0)."),
    }


def load_findings(path: Path) -> list[dict]:
    """Read findings.jsonl (one JSON object per line). Blank lines + comment lines skipped; a malformed
    line is skipped, not fatal (the synthesizer writes this file, so this is belt-and-suspenders)."""
    out: list[dict] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        try:
            obj = json.loads(s)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out


def read_objective_cfg(target_dir: Path) -> tuple[str, str]:
    """(min_payable_tier, currency) from scope.yaml via PyYAML if available, else a line-scan fallback.
    Defaults when absent. stdlib-first: PyYAML is never required."""
    scope = target_dir / "scope.yaml"
    if not scope.exists():
        return DEFAULT_MIN_PAYABLE_TIER, DEFAULT_CURRENCY
    text = scope.read_text(encoding="utf-8", errors="replace")
    try:
        import yaml  # optional dep; stdlib-first design, so we never require it
        doc = yaml.safe_load(text) or {}
        obj = doc.get("objective") or {}
        prog = doc.get("program")
        mpt = obj.get("min_payable_tier") or DEFAULT_MIN_PAYABLE_TIER
        cur = (prog.get("currency") if isinstance(prog, dict) else None) or DEFAULT_CURRENCY
        return str(mpt).strip().upper(), str(cur).strip()
    except Exception:  # noqa: BLE001  (missing PyYAML OR a parse error -> line-scan, never fatal)
        return _scan_objective_cfg(text)


def _scan_objective_cfg(text: str) -> tuple[str, str]:
    """Line-scan fallback: min_payable_tier under the top-level objective: block, currency under program:."""
    mpt, cur = DEFAULT_MIN_PAYABLE_TIER, DEFAULT_CURRENCY
    section = None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        stripped = raw.strip()
        if indent == 0:
            section = stripped.split(":", 1)[0] if ":" in stripped else None
            continue
        if section == "objective" and stripped.startswith("min_payable_tier:"):
            mpt = _scalar(stripped.split(":", 1)[1]) or mpt
        elif section == "program" and stripped.startswith("currency:"):
            cur = _scalar(stripped.split(":", 1)[1]) or cur
    return mpt.strip().upper(), cur.strip()


def _scalar(val: str) -> str:
    """Strip a trailing ' # comment' and surrounding quotes from a bare YAML scalar."""
    val = val.strip()
    if val and val[0] in "'\"":
        q = val[0]
        end = val.find(q, 1)
        if end != -1:
            return val[1:end]
    cut = val.find(" #")
    return (val[:cut] if cut != -1 else val).strip()


def self_test() -> int:
    """Offline end-to-end check: a mixed findings set exercising the roll-up + reward lookup + edges."""
    # tier ordering + floor arithmetic
    assert tier_rank("P1") < tier_rank("P5"), "P1 must outrank P5"
    assert meets_floor("P3", "P4") and meets_floor("P4", "P4"), "P3/P4 must clear a P4 floor"
    assert not meets_floor("P5", "P4"), "P5 must be below a P4 floor"
    assert not meets_floor("P2", "bogus"), "an unknown floor never 'meets'"

    # reward lookup: raw range + asset-scaled range + unknown propagation
    table = {"tiers": {"P1": [5000, 20000], "P2": [2000, 5000], "P3": [500, 2000], "P4": [100, 500]}}
    r = reward_range(table, "P2", 1.5)
    assert r["reward_range"] == [2000, 5000] and r["scaled_range"] == [3000.0, 7500.0], f"bad reward lookup: {r}"
    assert reward_range(table, "P5")["unknown"] is True, "P5 (not in table) must be unknown, not 0"

    # roll-up over a representative findings set
    findings = [
        # payable: proven P2, novel, report-ready
        {"id": "f-0001", "payout_ready": True, "tier": "P2", "tier_reward": [2000, 5000],
         "expected_value": 3500, "eligibility": "payable", "novelty": "novel", "payout_distance": "report-ready"},
        # below pay floor: P5, not payout_ready -> excluded from payable count + EV
        {"id": "f-0002", "payout_ready": False, "tier": "P5", "tier_reward": None,
         "expected_value": 0, "eligibility": "payable", "novelty": "novel", "payout_distance": "severity-graded"},
        # eligible but could-not-verify -> eligible_pending, not payable
        {"id": "f-0003", "payout_ready": False, "tier": "P3", "tier_reward": [500, 2000],
         "expected_value": 1200, "eligibility": "payable", "novelty": "could-not-verify",
         "payout_distance": "severity-graded"},
    ]
    res = rollup(findings, min_payable_tier="P4", currency="USD")
    assert res["payable_count"] == 1, f"payable_count: {res['payable_count']}"
    assert res["best_tier"] == "P2" and res["best_finding"] == "f-0001", f"best: {res}"
    assert res["expected_value"] == {"currency": "USD", "low": 2000, "high": 5000, "point": 3500, "unknown": False}, \
        f"EV range: {res['expected_value']}"
    assert res["expected_value_total"] == 3500, f"EV total: {res['expected_value_total']}"
    assert res["ev_ranked"] == ["f-0001", "f-0003", "f-0002"], f"ev_ranked: {res['ev_ranked']}"
    assert res["eligible_pending"] == 1, f"eligible_pending: {res['eligible_pending']}"
    assert res["dedup_cleared"] is True, "a novel finding must set dedup_cleared"
    assert res["status"] == "payable", f"status: {res['status']}"
    assert res["distance"] == "report-ready", f"distance: {res['distance']}"

    # unknown-propagation: a payout_ready finding with a missing tier_reward
    ures = rollup([{"id": "f-1", "payout_ready": True, "tier": "P1", "tier_reward": None,
                    "expected_value": 9000, "novelty": "novel", "payout_distance": "report-ready"}])
    assert ures["expected_value"]["unknown"] is True, "missing tier_reward must propagate unknown"

    # empty / impact-run (no economic fields) -> honest zeros, status open, no crash
    empty = rollup([])
    assert empty["payable_count"] == 0 and empty["best_tier"] == "" and empty["status"] == "open" \
        and empty["distance"] == "", f"empty roll-up not honest-zero: {empty}"
    impactish = rollup([{"id": "f-9", "severity": "high"}])  # a plain impact finding, no economic fields
    assert impactish["payable_count"] == 0 and impactish["ev_ranked"] == [], f"impact finding leaked econ: {impactish}"

    # synthesizer-supplied terminal states (only when no payable milestone)
    assert rollup([], dry=True)["status"] == "dry", "dry hint must surface when not payable"
    assert rollup([], blocked=True)["status"] == "blocked", "blocked hint must surface when not payable"
    assert rollup(findings, dry=True)["status"] == "payable", "a payable milestone outranks a dry hint"

    print("payout-calc self-test: OK (reward lookup, EV range + unknown-propagation, best/ranked, "
          "eligible_pending, honest-zero + impact no-op, status precedence)")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Deterministic run-level bounty economics roll-up (fix3 B1)")
    ap.add_argument("--rollup", action="store_true", help="aggregate findings.jsonl into the state.objective economics")
    ap.add_argument("--reward", action="store_true", help="deterministic reward_table lookup for one tier (helper)")
    ap.add_argument("--findings", default=None, help="path to findings.jsonl (roll-up mode)")
    ap.add_argument("--target-dir", default=None, help="targets/<t> (roll-up: reads findings.jsonl + scope.yaml)")
    ap.add_argument("--min-payable-tier", default=None, help="the pay floor P1..P5 (default: scope.objective or P4)")
    ap.add_argument("--currency", default=None, help="currency label for the EV range (default: scope.program or USD)")
    ap.add_argument("--blocked", action="store_true", help="synthesizer hint: stalled on a foothold/prereq")
    ap.add_argument("--dry", action="store_true", help="synthesizer hint: the eligible-novel surface is exhausted")
    ap.add_argument("--tier", default=None, help="reward mode: the tier to look up (P1..P5)")
    ap.add_argument("--reward-table", default=None, help="reward mode: JSON tier->[min,max] (or {\"tiers\":{...}})")
    ap.add_argument("--asset-multiplier", type=float, default=1.0, help="reward mode: program.asset_tiers multiplier")
    ap.add_argument("--out", default=None, help="write the JSON result here (default: stdout only)")
    ap.add_argument("--self-test", action="store_true", help="run the offline self-test and exit")
    args = ap.parse_args(argv)

    if args.self_test:
        try:
            return self_test()
        except AssertionError as e:
            print(f"payout-calc self-test: FAIL — {e}")
            return 1

    if args.reward:
        if not args.tier or not args.reward_table:
            print("payout-calc: --reward needs --tier and --reward-table", file=sys.stderr)
            return 2
        try:
            table = json.loads(args.reward_table)
        except json.JSONDecodeError as e:
            print(f"payout-calc: invalid --reward-table JSON: {e}", file=sys.stderr)
            return 2
        result = reward_range(table, args.tier, args.asset_multiplier)
        if args.currency:
            result["currency"] = args.currency
        _emit(result, args.out)
        return 0

    if args.rollup:
        findings_path = Path(args.findings) if args.findings else (
            Path(args.target_dir) / "findings.jsonl" if args.target_dir else None)
        if not findings_path:
            print("payout-calc: --rollup needs --findings or --target-dir", file=sys.stderr)
            return 2
        if not findings_path.is_file():
            # honest zero — a run with no findings file yet is not an error (never a silent crash)
            findings = []
        else:
            findings = load_findings(findings_path)
        mpt, cur = DEFAULT_MIN_PAYABLE_TIER, DEFAULT_CURRENCY
        if args.target_dir:
            mpt, cur = read_objective_cfg(Path(args.target_dir))
        if args.min_payable_tier:
            mpt = args.min_payable_tier.strip().upper()
        if args.currency:
            cur = args.currency.strip()
        result = rollup(findings, min_payable_tier=mpt, currency=cur, blocked=args.blocked, dry=args.dry)
        result["findings_scanned"] = len(findings)
        _emit(result, args.out)
        return 0

    print("payout-calc: pick a mode — --rollup, --reward, or --self-test", file=sys.stderr)
    return 2


def _emit(result: dict, out: str | None) -> None:
    text = json.dumps(result, indent=2, ensure_ascii=False)
    if out:
        p = Path(out)
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
            print(f"[payout-calc] result -> {p.as_posix()}")
        except OSError as e:
            print(f"payout-calc: could not write {out}: {e}", file=sys.stderr)
    print(text)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
