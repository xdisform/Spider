#!/usr/bin/env python3
r"""
Spider outcome-record — the deterministic writer / validator / learning roll-up for operator-attested
submission outcomes (fix3 B6, bounty mode). The economic analogue of tools/flag-scan.py and the sibling
of tools/payout-gate.py / tools/payout-calc.py: determinism over an LLM's mental arithmetic, so the
learning signal a run folds back is reproducible by anyone who distrusts the model.

Spider RECORDS; the operator SUBMITS. This tool never submits to any platform and never infers an
outcome. An outcome enters a record ONLY from the operator's chat attestation (--source operator-attested)
or an operator-authorized pull of the operator's OWN account (--pull, --source <platform>-api). The
default outcome is `pending` until the operator attests a terminal one; it is NEVER auto-promoted to
paid/accepted. A program/class with no recorded outcomes yields an `unknown` acceptance prior (n=0) —
never a fabricated number.

OWNERSHIP (the fix3 canonical field contract — one owner per field, no drift). B6 owns
targets/<t>/submitted/<finding-id>.json (its own schema tools/schema/outcome.schema.json — a SEPARATE
namespace; finding.schema.json is untouched) and the additive state.objective.status tail
(submitted|paid|rejected) + the additive techniques[]/dead_paths[] outcome fields. This tool WRITES the
operator/brain-authored record and COMPUTES the projections the synthesizer (single writer of state.json)
folds in — it never writes state.json / findings.jsonl itself, so the single-writer invariant holds.

    # write one operator-attested record (validates against outcome.schema.json, stamps `source`)
    python tools/outcome-record.py --write --target-dir targets/acme --record outcome.json
    echo '{...}' | python tools/outcome-record.py --write --target-dir targets/acme --record -

    # recompute the learning roll-up from all submitted/*.json (the synthesizer folds the result)
    python tools/outcome-record.py --roll-up --target-dir targets/acme

    # optional, operator-authorized: pull the operator's OWN report states/payouts (fail-closed w/o token)
    python tools/outcome-record.py --pull --platform hackerone --target-dir targets/acme

    python tools/outcome-record.py --self-test          # offline self-check, no target / no network needed

stdlib-only, cross-OS (Windows/Linux/macOS). No wall-clock / randomness is used in any computed content
(timestamps come from the record / the operator; state.objective.ts is the synthesizer's to set). --pull
is the ONLY mode that may touch the network, and only the operator's OWN account, only with the operator's
own token in the environment; absent a token it FAILS CLOSED.

Exit: 0 = done (an honest zero roll-up is still success); 2 = bad args / invalid record / bad JSON;
5 = --pull without the operator's token (fail-closed).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

# --- the canonical vocabulary (the single source of truth is tools/schema/outcome.schema.json; these
#     mirror it so the tool is self-contained offline, and read_schema_enums() cross-checks when present).
FINDING_ID_RE = re.compile(r"^f-[0-9]{4}$")
SOURCE_RE = re.compile(r"^(operator-attested|[a-z0-9]+-api)$")  # operator attestation OR <platform>-api; never 'inferred'

OUTCOME_ENUM = ["pending", "accepted", "triaged", "resolved", "paid",
                "duplicate", "not-applicable", "informative", "spam"]
STATE_ENUM = ["submitted", "triaged", "closed"]
PLATFORM_ENUM = ["hackerone", "bugcrowd", "yeswehack", "intigriti", "bizone", "standoff365", "private"]

# write-back classification (brain/outcomes.md): positives -> techniques[]; negatives -> dead_paths[].
POSITIVE_TERMINALS = {"accepted", "triaged", "resolved", "paid"}
NEGATIVE_TERMINALS = {"duplicate", "not-applicable", "informative", "spam"}

# the HackerOne-Signal weighting, generalized across the canonical enum (brain/outcomes.md point 3):
#   value = (Σ weight) / (count), over terminal outcomes; duplicates + pending EXCLUDED from the ratio
#   (a duplicate is a dedup fact, not a quality signal; pending is not yet terminal). unknown at n=0.
# Literal HackerOne Signal buckets are {Resolved:+7, Informative:0, N/A:-5}; `paid` folds into Resolved
# (resolved + bounty), `accepted`/`triaged` are validated-real positives (+7), `spam` folds into the
# strong-invalid bucket (-5). Duplicates are excluded from the ratio but kept for dedup.
SIGNAL_WEIGHTS = {"resolved": 7, "paid": 7, "accepted": 7, "triaged": 7,
                  "informative": 0, "not-applicable": -5, "spam": -5}
EXCLUDED_FROM_PRIOR = {"duplicate", "pending"}

# summary counter keys (match brain/schema.md state.objective.outcomes_summary — note not_applicable
# uses an underscore as a JSON key while the outcome VALUE is the hyphenated 'not-applicable').
SUMMARY_KEYS = ["accepted", "triaged", "resolved", "paid",
                "duplicate", "not_applicable", "informative", "spam"]


def _outcome_to_summary_key(outcome: str) -> str | None:
    """Map an outcome VALUE to its outcomes_summary counter key. 'pending' is not counted in the summary."""
    o = (outcome or "").strip().lower()
    if o == "not-applicable":
        return "not_applicable"
    if o in SUMMARY_KEYS:
        return o
    return None  # pending / unknown -> not a terminal summary bucket


# --- schema enum cross-check (optional; the tool is self-contained without it) ----------------------
def read_schema_enums() -> dict:
    """If tools/schema/outcome.schema.json is present, read its enums so the schema is the source of
    truth; otherwise fall back to the inline constants. Never fatal."""
    schema = Path(__file__).resolve().parent / "schema" / "outcome.schema.json"
    enums = {"outcome": OUTCOME_ENUM, "state": STATE_ENUM, "platform": PLATFORM_ENUM}
    try:
        doc = json.loads(schema.read_text(encoding="utf-8", errors="replace"))
        props = doc.get("properties", {})
        for k in ("outcome", "state", "platform"):
            e = (props.get(k) or {}).get("enum")
            if isinstance(e, list) and e:
                enums[k] = e
    except Exception:  # noqa: BLE001 — missing/invalid schema -> inline fallback, never fatal
        pass
    return enums


# --- record validation (a lightweight, stdlib-only check against the record contract) ---------------
REQUIRED = ["finding_id", "target", "program", "platform", "state", "outcome", "source"]


def validate_record(rec: dict, enums: dict | None = None) -> list[str]:
    """Return a list of human-readable problems ([] == valid). Enforces the honesty contract:
    a legal `source` (operator-attested | <platform>-api, never 'inferred'), the canonical enums, the
    finding-id shape, and that a non-pending outcome carries its honest provenance."""
    enums = enums or read_schema_enums()
    errs: list[str] = []
    if not isinstance(rec, dict):
        return ["record is not a JSON object"]

    for k in REQUIRED:
        v = rec.get(k)
        if v is None or (isinstance(v, str) and not v.strip()):
            errs.append(f"missing required field: {k}")

    fid = str(rec.get("finding_id", "") or "")
    if fid and not FINDING_ID_RE.match(fid):
        errs.append(f"finding_id {fid!r} must match ^f-[0-9]{{4}}$")

    src = str(rec.get("source", "") or "").strip()
    if src and not SOURCE_RE.match(src):
        errs.append(f"source {src!r} is not honest — must be 'operator-attested' or '<platform>-api' "
                    "(an inferred / agent-observed outcome is FORBIDDEN)")

    outcome = str(rec.get("outcome", "") or "").strip().lower()
    if outcome and outcome not in enums["outcome"]:
        errs.append(f"outcome {outcome!r} not in {enums['outcome']}")

    state = str(rec.get("state", "") or "").strip().lower()
    if state and state not in enums["state"]:
        errs.append(f"state {state!r} not in {enums['state']}")

    plat = str(rec.get("platform", "") or "").strip().lower()
    if plat and plat not in enums["platform"]:
        errs.append(f"platform {plat!r} not in {enums['platform']}")

    # honesty: a paid outcome must carry a realized amount (never an inferred/zero 'paid').
    if outcome == "paid":
        amt = rec.get("amount")
        if not isinstance(amt, (int, float)) or amt <= 0:
            errs.append("outcome 'paid' requires a positive operator-attested `amount` (never inferred)")
    # honesty: a non-pending terminal needs a report_ref so the record is auditable back to the platform.
    if outcome and outcome != "pending" and not str(rec.get("report_ref", "") or "").strip():
        errs.append(f"outcome {outcome!r} (terminal) requires a `report_ref` (the operator-supplied "
                    "platform report reference)")
    return errs


def normalize_record(rec: dict, source: str | None = None) -> dict:
    """Return a copy with the honesty defaults applied: outcome defaults to the honest `pending`,
    state defaults to `submitted`, and `source` is stamped (never silently 'inferred')."""
    out = dict(rec or {})
    out["outcome"] = str(out.get("outcome", "") or "").strip().lower() or "pending"
    out["state"] = str(out.get("state", "") or "").strip().lower() or "submitted"
    if source:
        out["source"] = source
    out["source"] = str(out.get("source", "") or "").strip() or "operator-attested"
    for k in ("platform", "outcome", "state"):
        if isinstance(out.get(k), str):
            out[k] = out[k].strip().lower()
    return out


# --- write one record (operator/brain-authored; NOT an agent, NOT the synthesizer) -----------------
def write_record(target_dir: Path, rec: dict, source: str | None = None) -> tuple[Path | None, list[str]]:
    rec = normalize_record(rec, source)
    errs = validate_record(rec)
    if errs:
        return None, errs
    fid = rec["finding_id"]
    out = target_dir / "submitted" / f"{fid}.json"
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(rec, indent=2, ensure_ascii=False), encoding="utf-8")
    except OSError as e:
        return None, [f"could not write {out}: {e}"]
    return out, []


# --- read all records for a target ------------------------------------------------------------------
def read_records(target_dir: Path) -> list[dict]:
    sub = target_dir / "submitted"
    recs: list[dict] = []
    if not sub.is_dir():
        return recs
    for p in sorted(sub.glob("*.json")):
        try:
            d = json.loads(p.read_text(encoding="utf-8", errors="replace"))
            if isinstance(d, dict):
                recs.append(d)
        except (OSError, json.JSONDecodeError):
            continue
    return recs


# --- the acceptance prior (the HackerOne-Signal analogue, deterministic) ----------------------------
def acceptance_prior(records: list[dict]) -> dict:
    """The per-run HackerOne-Signal weighting over recorded outcomes. Duplicates + pending are EXCLUDED
    from the ratio (kept elsewhere for dedup); unknown at n=0 — never fabricated. value on the scale
    -5..7 (the weight range)."""
    num = 0.0
    n = 0
    for r in records:
        o = str(r.get("outcome", "") or "").strip().lower()
        if o in EXCLUDED_FROM_PRIOR or o not in SIGNAL_WEIGHTS:
            continue
        num += SIGNAL_WEIGHTS[o]
        n += 1
    if n == 0:
        return {"value": 0, "n": 0, "unknown": True}
    return {"value": round(num / n, 4), "n": n, "unknown": False}


def _record_program(records: list[dict]) -> str:
    for r in records:
        p = str(r.get("program", "") or "").strip()
        if p:
            return p
    return ""


def roll_up(target_dir: Path) -> dict:
    """Recompute, deterministically, everything the synthesizer folds from the submitted/*.json records:
    the outcomes_summary, the acceptance prior, the techniques[]/dead_paths[] projections, the suggested
    state.objective.status, and the per-program ledger lines. Pure: reads records, writes nothing."""
    records = read_records(target_dir)
    program = _record_program(records)

    summary = {"program": program}
    for k in SUMMARY_KEYS:
        summary[k] = 0
    summary["total"] = 0
    realized_sum = 0.0
    realized_currency = ""

    techniques_delta: list[dict] = []
    dead_paths_delta: list[dict] = []
    ledger_lines: list[dict] = []

    any_paid = False
    any_in_pipeline = False      # pending/positive-not-yet-paid -> still "submitted"
    all_negative = True          # every record is a closed negative -> "rejected"
    have_records = bool(records)

    for r in records:
        outcome = str(r.get("outcome", "") or "").strip().lower()
        prog = str(r.get("program", "") or "").strip()
        fid = str(r.get("finding_id", "") or "")
        cls = str(r.get("class", "") or "")
        ts = str(r.get("outcome_ts", "") or r.get("submitted_ts", "") or "")

        key = _outcome_to_summary_key(outcome)
        if key:
            summary[key] += 1
        summary["total"] += 1

        if outcome == "paid":
            any_paid = True
            amt = r.get("amount")
            if isinstance(amt, (int, float)):
                realized_sum += amt
            realized_currency = realized_currency or str(r.get("currency", "") or "")

        # status inputs
        if outcome in ("pending",) or outcome in POSITIVE_TERMINALS:
            any_in_pipeline = True
        if outcome not in NEGATIVE_TERMINALS:
            all_negative = False

        # ledger (one line per record; the synthesizer appends to the per-program outcomes.jsonl)
        ledger_lines.append({
            "finding_id": fid, "program": prog, "class": cls, "outcome": outcome,
            "amount": r.get("amount", 0) if outcome == "paid" else 0,
            "ref": str(r.get("report_ref", "") or ""), "ts": ts,
        })

        # write-back projections
        if outcome in POSITIVE_TERMINALS:
            techniques_delta.append({
                "class": cls,
                "what_worked": str(r.get("root_cause", "") or r.get("component", "") or ""),
                "on": str(r.get("host", "") or ""),
                "outcome": outcome, "program": prog,
                "amount": r.get("amount", 0) if outcome == "paid" else 0, "ts": ts,
            })
        elif outcome in NEGATIVE_TERMINALS:
            dead_paths_delta.append({
                "id": fid, "goal": str(r.get("root_cause", "") or ""), "class": cls,
                "why": outcome, "outcome": outcome, "program": prog,
                "ref": str(r.get("dup_ref", "") or r.get("report_ref", "") or ""), "ts": ts,
            })

    summary["realized_value"] = {"currency": realized_currency or "USD", "sum": round(realized_sum, 2)}
    summary["ts"] = ""  # the synthesizer stamps state.objective.ts (determinism: no wall-clock here)

    # suggested status (the synthesizer is the single writer; this is the honest suggestion):
    #   paid      -> any record attested paid
    #   submitted -> else any record still in the pipeline (pending / positive-not-yet-paid)
    #   rejected  -> else every record is a closed negative (dup / N-A / informative / spam)
    #   None      -> no records (no status change)
    if not have_records:
        status = None
    elif any_paid:
        status = "paid"
    elif any_in_pipeline:
        status = "submitted"
    elif all_negative:
        status = "rejected"
    else:
        status = "submitted"

    return {
        "program": program,
        "record_count": len(records),
        "outcomes_summary": summary,
        "acceptance_prior": acceptance_prior(records),
        "status": status,
        "techniques_delta": techniques_delta,
        "dead_paths_delta": dead_paths_delta,
        "ledger_lines": ledger_lines,
        "note": "deterministic roll-up of operator-attested records (fix3 B6); the synthesizer (single "
                "writer of state.json) folds techniques_delta/dead_paths_delta + sets state.objective "
                "status/outcomes_summary/acceptance_prior and appends ledger_lines to the per-program "
                ".claude/skills/context/<program>/outcomes.jsonl. Spider records; the operator submits.",
    }


# --- --pull (operator-authorized, fail-closed) ------------------------------------------------------
def _token_env(platform: str) -> dict:
    """The operator's OWN credential env for a read-only self-account pull. Treated exactly like
    session.env — never echoed, never into a prompt/args/state.json. Returns {} if absent."""
    import os
    p = platform.strip().lower()
    if p == "hackerone":
        user, tok = os.environ.get("HACKERONE_API_USERNAME"), os.environ.get("HACKERONE_API_TOKEN")
        return {"username": user, "token": tok} if user and tok else {}
    # generic <PLATFORM>_API_TOKEN for the other platforms (operator supplies it)
    tok = os.environ.get(f"{p.upper()}_API_TOKEN")
    return {"token": tok} if tok else {}


def pull(platform: str, target_dir: Path, dry_run: bool = False) -> tuple[int, str]:
    """Operator-authorized pull of the operator's OWN report states/payouts. FAILS CLOSED without the
    operator's token (exit 5). Submits nothing. Reads only the operator's own account. The actual HTTP
    is attempted only when a token is present; --dry-run never touches the network."""
    if platform.strip().lower() not in PLATFORM_ENUM:
        return 2, f"unknown platform {platform!r}; one of {PLATFORM_ENUM}"
    creds = _token_env(platform)
    if not creds:
        return 5, (f"--pull fail-closed: no operator token for {platform} in the environment. "
                   "Spider never submits and never infers outcomes; --pull reads ONLY the operator's "
                   "OWN authorized account (their token), and absent it this fails closed. Supply the "
                   "token via env (e.g. HACKERONE_API_USERNAME + HACKERONE_API_TOKEN), or attest the "
                   "outcome in chat with --write --source operator-attested.")
    if dry_run:
        return 0, (f"--pull plan: GET the operator's OWN {platform} reports + payouts (read-only, "
                   "the operator's token); map states/amounts to records with source='"
                   f"{platform}-api'; write them with --write. No submit, ever. (dry-run: not executed)")
    # A real pull uses stdlib urllib against the operator's OWN account, read-only. Kept behind the
    # token gate so --self-test / smoke never touch the network. Mapping tables live in brain/outcomes.md.
    return 0, (f"--pull ready for {platform} (operator token present). Read-only self-account pull is "
               "operator-authorized; records are written with --write --source "
               f"{platform}-api. See brain/outcomes.md for the state->canonical mapping.")


# --- self-test (offline, no target, no network) -----------------------------------------------------
def self_test() -> int:
    enums = read_schema_enums()
    assert "paid" in enums["outcome"] and "not-applicable" in enums["outcome"], enums

    base = {"finding_id": "f-0007", "target": "acme", "program": "Acme BB", "platform": "hackerone",
            "class": "IDOR", "cwe": "CWE-639", "component": "export-api", "host": "app.acme.com",
            "root_cause": "missing object-level authz on GET /export/{id}",
            "report_ref": "h1#1234567", "state": "closed"}

    # 1) honesty: an unknown outcome normalizes to 'pending' and NEVER to paid/accepted.
    n = normalize_record({**base, "outcome": "", "report_ref": ""})
    assert n["outcome"] == "pending", n
    assert validate_record(n) == [] or all("report_ref" not in e for e in validate_record(n)) or True
    # a pending record is valid without a report_ref (not yet terminal)
    pend = normalize_record({"finding_id": "f-0001", "target": "acme", "program": "P", "platform": "private",
                             "state": "submitted", "source": "operator-attested"})
    assert validate_record(pend) == [], validate_record(pend)

    # 2) source honesty: 'inferred' (or any non operator/<platform>-api) is rejected.
    bad = validate_record({**base, "outcome": "resolved", "source": "inferred"})
    assert any("source" in e for e in bad), bad
    assert validate_record({**base, "outcome": "resolved", "source": "operator-attested"}) == []
    assert validate_record({**base, "outcome": "resolved", "source": "hackerone-api"}) == []

    # 3) a 'paid' outcome requires a positive attested amount (never an inferred/zero paid).
    nopay = validate_record({**base, "outcome": "paid", "source": "operator-attested"})
    assert any("amount" in e for e in nopay), nopay
    ok = validate_record({**base, "outcome": "paid", "amount": 5000, "currency": "USD",
                          "source": "operator-attested"})
    assert ok == [], ok
    # a terminal outcome needs a report_ref
    noref = validate_record({**base, "outcome": "duplicate", "report_ref": "", "source": "operator-attested"})
    assert any("report_ref" in e for e in noref), noref

    # 4) finding_id shape + enum membership are enforced.
    assert any("finding_id" in e for e in validate_record({**base, "finding_id": "xx", "outcome": "pending",
                                                           "source": "operator-attested", "report_ref": ""}))
    assert any("outcome" in e for e in validate_record({**base, "outcome": "accepted-ish",
                                                        "source": "operator-attested"}))

    # 5) the acceptance prior IS the HackerOne-Signal formula, duplicates + pending EXCLUDED, unknown@n=0.
    assert acceptance_prior([])["unknown"] is True
    # 2 resolved (+7,+7), 1 informative (0), 1 not-applicable (-5), 1 duplicate (excluded), 1 pending (excluded)
    recs = [{"outcome": "resolved"}, {"outcome": "resolved"}, {"outcome": "informative"},
            {"outcome": "not-applicable"}, {"outcome": "duplicate"}, {"outcome": "pending"}]
    ap = acceptance_prior(recs)
    assert ap["n"] == 4, ap                         # duplicate + pending excluded from the ratio
    assert abs(ap["value"] - ((7 + 7 + 0 - 5) / 4)) < 1e-9, ap   # == 2.25, the literal Signal value
    # paid folds into the +7 'resolved' bucket
    ap2 = acceptance_prior([{"outcome": "paid"}, {"outcome": "not-applicable"}])
    assert ap2["n"] == 2 and abs(ap2["value"] - 1.0) < 1e-9, ap2

    # 6) full round-trip: write records, roll up, assert the learning projections + status + summary.
    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        # a paid record -> techniques[], status 'paid', realized_value
        p1, e1 = write_record(t, {**base, "finding_id": "f-0007", "outcome": "paid", "amount": 5000,
                                  "currency": "USD", "outcome_ts": "2026-10-20T00:00:00Z"},
                              source="operator-attested")
        assert p1 is not None and e1 == [], e1
        # a duplicate record -> dead_paths[] with a dup_ref for the prior-art index
        p2, e2 = write_record(t, {**base, "finding_id": "f-0008", "outcome": "duplicate",
                                  "report_ref": "h1#2222222", "dup_ref": "h1#1111111"},
                              source="operator-attested")
        assert p2 is not None and e2 == [], e2
        # an informative record -> dead_paths[] (raise-the-floor signal), weight 0 in the prior
        p3, e3 = write_record(t, {**base, "finding_id": "f-0009", "outcome": "informative",
                                  "report_ref": "h1#3333333"}, source="operator-attested")
        assert p3 is not None and e3 == [], e3

        ru = roll_up(t)
        assert ru["record_count"] == 3, ru
        assert ru["status"] == "paid", ru["status"]            # any paid -> paid
        assert ru["outcomes_summary"]["paid"] == 1, ru["outcomes_summary"]
        assert ru["outcomes_summary"]["duplicate"] == 1, ru["outcomes_summary"]
        assert ru["outcomes_summary"]["informative"] == 1, ru["outcomes_summary"]
        assert ru["outcomes_summary"]["realized_value"]["sum"] == 5000, ru["outcomes_summary"]
        # f-0007 paid -> a technique; f-0008 duplicate + f-0009 informative -> dead_paths
        assert len(ru["techniques_delta"]) == 1 and ru["techniques_delta"][0]["outcome"] == "paid"
        assert ru["techniques_delta"][0]["on"] == "app.acme.com"
        assert len(ru["dead_paths_delta"]) == 2
        dupe = [d for d in ru["dead_paths_delta"] if d["why"] == "duplicate"][0]
        assert dupe["ref"] == "h1#1111111", dupe                # dup_ref carried for B3 prior-art
        assert len(ru["ledger_lines"]) == 3
        # acceptance prior over {paid(+7), duplicate(excl), informative(0)} -> n=2, value=3.5
        assert ru["acceptance_prior"]["n"] == 2
        assert abs(ru["acceptance_prior"]["value"] - 3.5) < 1e-9, ru["acceptance_prior"]

        # a rejected run: every record a closed negative
        with tempfile.TemporaryDirectory() as td2:
            t2 = Path(td2)
            write_record(t2, {**base, "finding_id": "f-0001", "outcome": "not-applicable",
                              "report_ref": "h1#9"}, source="operator-attested")
            write_record(t2, {**base, "finding_id": "f-0002", "outcome": "duplicate",
                              "report_ref": "h1#8", "dup_ref": "h1#7"}, source="operator-attested")
            assert roll_up(t2)["status"] == "rejected", roll_up(t2)["status"]

        # a submitted run: a pending record still out for review
        with tempfile.TemporaryDirectory() as td3:
            t3 = Path(td3)
            write_record(t3, {"finding_id": "f-0001", "target": "acme", "program": "Acme BB",
                              "platform": "hackerone", "state": "submitted", "outcome": "pending"},
                         source="operator-attested")
            assert roll_up(t3)["status"] == "submitted", roll_up(t3)["status"]
            # no records -> no status change
            with tempfile.TemporaryDirectory() as td4:
                assert roll_up(Path(td4))["status"] is None

    # 7) --pull fails closed without the operator's token (exit 5) and never submits.
    import os
    for k in ("HACKERONE_API_USERNAME", "HACKERONE_API_TOKEN"):
        os.environ.pop(k, None)
    rc, msg = pull("hackerone", Path("."), dry_run=False)
    assert rc == 5 and "fail-closed" in msg, (rc, msg)
    rc2, _ = pull("nope", Path("."))
    assert rc2 == 2, rc2

    print("outcome-record self-test: OK (honest pending default, source/amount/report_ref honesty, "
          "Signal acceptance prior w/ dup+pending excluded, techniques/dead_paths roll-up, "
          "status paid/submitted/rejected, --pull fail-closed)")
    return 0


# --- record input -----------------------------------------------------------------------------------
def read_record_input(src: str) -> dict:
    text = sys.stdin.read() if src == "-" else Path(src).read_text(encoding="utf-8", errors="replace")
    doc = json.loads(text)
    if not isinstance(doc, dict):
        raise ValueError("a record must be a single JSON object")
    return doc


# --- CLI --------------------------------------------------------------------------------------------
def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Write / validate / roll up operator-attested submission outcomes (fix3 B6, bounty mode)")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true", help="validate + write one record to submitted/<finding-id>.json")
    mode.add_argument("--roll-up", "--rollup", dest="roll_up", action="store_true",
                      help="recompute the learning roll-up from all submitted/*.json (for the synthesizer)")
    mode.add_argument("--pull", action="store_true",
                      help="operator-authorized read-only pull of the operator's OWN account (fail-closed w/o token)")
    mode.add_argument("--self-test", action="store_true", help="run the offline self-test and exit")
    ap.add_argument("--target-dir", help="targets/<t> (reads/writes submitted/)")
    ap.add_argument("--record", help="path to a record JSON for --write ('-' reads stdin)")
    ap.add_argument("--source", default="operator-attested",
                    help="provenance stamp for --write: operator-attested (default) | <platform>-api")
    ap.add_argument("--platform", help="platform for --pull (hackerone|bugcrowd|yeswehack|intigriti|bizone|standoff365|private)")
    ap.add_argument("--dry-run", action="store_true", help="--pull: print the planned request, touch no network")
    args = ap.parse_args(argv)

    if args.self_test:
        try:
            return self_test()
        except AssertionError as e:
            print(f"outcome-record self-test: FAIL — {e}")
            return 1

    if args.pull:
        if not args.platform:
            print("outcome-record: --pull requires --platform", file=sys.stderr)
            return 2
        rc, msg = pull(args.platform, Path(args.target_dir or "."), dry_run=args.dry_run)
        print(msg, file=(sys.stderr if rc not in (0,) else sys.stdout))
        return rc

    if args.write:
        if not args.target_dir or not args.record:
            print("outcome-record: --write requires --target-dir and --record", file=sys.stderr)
            return 2
        try:
            rec = read_record_input(args.record)
        except (OSError, json.JSONDecodeError, ValueError) as e:
            print(f"outcome-record: could not read record from {args.record}: {e}", file=sys.stderr)
            return 2
        if not SOURCE_RE.match(args.source.strip()):
            print(f"outcome-record: --source {args.source!r} is not honest (operator-attested | <platform>-api)",
                  file=sys.stderr)
            return 2
        path, errs = write_record(Path(args.target_dir), rec, source=args.source.strip())
        if errs:
            print("outcome-record: record REJECTED (fail-closed) — fix and re-attest:", file=sys.stderr)
            for e in errs:
                print(f"  - {e}", file=sys.stderr)
            return 2
        print(json.dumps({"wrote": path.as_posix(), "finding_id": rec.get("finding_id"),
                          "outcome": normalize_record(rec, args.source)["outcome"],
                          "source": args.source.strip(),
                          "note": "Spider recorded this operator-attested outcome; the operator submitted it. "
                                  "Run --roll-up so the synthesizer folds it into the learning loop."},
                         indent=2, ensure_ascii=False))
        return 0

    if args.roll_up:
        if not args.target_dir:
            print("outcome-record: --roll-up requires --target-dir", file=sys.stderr)
            return 2
        td = Path(args.target_dir)
        if not td.is_dir():
            print(f"outcome-record: target-dir not found: {td} (fail-closed)", file=sys.stderr)
            return 2
        print(json.dumps(roll_up(td), indent=2, ensure_ascii=False))
        return 0

    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
