#!/usr/bin/env python3
# fix3 senior-brain MVP — the retriever (G-tools).
# Scored tag-match over the distilled corpus: given a hypothesis class + the live fingerprint tokens,
# return the top-K REUSABLE senior exemplars shaped for args.exemplars[hid]. (SENIOR-BRAIN-DESIGN.md §3.2, D2, D4.)
#
# HARD RED LINE (never violated here): this is a localhost, ZERO-network, brain-side read of a local
# corpus. It NEVER touches the target, NEVER emits a secret, and it is strictly UPSTREAM of the oracle.
# The exemplar's proof_oracle is a HINT for what the agent must PRODUCE — it is FORBIDDEN as a citation
# of proof; validateMission() + the 4 skeptic lenses re-derive proof on the live target and never see
# this output. retrieve.py cannot and does not claim any finding.
#
# Python 3.9+, STDLIB ONLY.
import argparse
import json
import os
import sys

DEFAULT_CORPUS = "C:/Spider/brain/corpus"


def load_jsonl(path):
    """Load a JSONL file into a list of dicts. Missing file -> []. Blank/garbage lines are skipped."""
    out = []
    if not path or not os.path.isfile(path):
        return out
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict):
                out.append(rec)
    return out


def _norm_fp(t):
    """Normalize a fingerprint token for cross-vocabulary overlap (fix3 audit #6): lower-case and keep
    the MOST-SPECIFIC segment after the last ':' so the writer's prefix (framework:/stack:/engine:/sink:/
    response:/response-shape:/...) never blocks a match — `framework:nextjs` ~ `stack:nextjs` ~ `nextjs`
    all compare as `nextjs`. The ~80 ad-hoc corpus prefixes + the synthesizer's prefixes thus compose on
    the bare value. A prefix-less token is unchanged."""
    s = str(t or "").strip().lower()
    if not s:
        return ""
    return s.rsplit(":", 1)[-1].strip()


def _payload_tokens(rec):
    """requires_fingerprint tokens off a payload record (list of strings), prefix-normalized."""
    toks = rec.get("requires_fingerprint") if isinstance(rec, dict) else None
    if not isinstance(toks, list):
        return []
    return [_norm_fp(t) for t in toks if _norm_fp(t)]


def _exemplar_tokens(ex, payload):
    """
    The fingerprint token-set an exemplar is keyed by: the non-empty VALUES of its
    target_fingerprint{framework,version,header,param,response_shape} map, plus the linked
    payload's requires_fingerprint tokens. Lower-cased for case-insensitive overlap.
    """
    toks = set()
    fp = ex.get("target_fingerprint") if isinstance(ex, dict) else None
    if isinstance(fp, dict):
        for v in fp.values():
            v = _norm_fp(v)
            if v:
                toks.add(v)
    for t in _payload_tokens(payload):
        toks.add(t)
    return toks


def _hit_rate(ex):
    """A proven exemplar's success rate in [0,1] for the ranking bonus (fix3 audit #2B). Accepts a float
    `hit_rate`, or an object {wins,tries} / {hits,uses} the corpus-curator maintains. 0 when never tried
    (an unproven exemplar gets no bonus, so a proven one outranks it at equal fingerprint overlap)."""
    hr = ex.get("hit_rate") if isinstance(ex, dict) else None
    if isinstance(hr, (int, float)):
        return min(1.0, max(0.0, float(hr)))
    if isinstance(hr, dict):
        wins = hr.get("wins", hr.get("hits", 0)) or 0
        tries = hr.get("tries", hr.get("uses", 0)) or 0
        try:
            wins, tries = float(wins), float(tries)
        except (TypeError, ValueError):
            return 0.0
        if tries <= 0:
            return 0.0
        return min(1.0, max(0.0, wins / tries))
    return 0.0


def _is_omitted(payload):
    """A linked payload is OMITTED (nothing runnable) when it is missing, flagged status OMITTED,
    or carries no verbatim payload string."""
    if not isinstance(payload, dict):
        return True
    status = str(payload.get("status", "")).strip().upper()
    if status == "OMITTED":
        return True
    pv = payload.get("payload")
    if not (isinstance(pv, str) and pv.strip()):
        return True
    return False


def score_and_select(exemplars, payloads, cls, fingerprint, k):
    """
    Keep only records whose class == cls AND reusable_vs_instance != 'patched-instance' (D6 gate: a
    patched specific never primes). Score = (class exact match) + (fingerprint token overlap count)
    - (0.5 if the linked payload is OMITTED) [D4 down-weight so a runnable record always outranks an
    OMITTED one for equal overlap]. Return top-K shaped for args.exemplars[hid].
    """
    by_id = {}
    for p in payloads:
        pid = p.get("id")
        if pid is not None:
            by_id[pid] = p

    want = {_norm_fp(t) for t in fingerprint if _norm_fp(t)}
    scored = []
    for idx, ex in enumerate(exemplars):
        if ex.get("class") != cls:
            continue
        if ex.get("reusable_vs_instance") == "patched-instance":
            continue  # HARD gate: patched instances never prime (SENIOR-BRAIN-DESIGN.md req 6 / D6)
        payload = by_id.get(ex.get("payload_ref"))
        omitted = _is_omitted(payload)
        overlap = len(want & _exemplar_tokens(ex, payload))
        # score = class match (1) + fingerprint overlap - OMITTED down-weight + hit_rate bonus (fix3 #2B:
        # a PROVEN exemplar outranks an unproven one at equal overlap; bounded < a token match so it
        # tilts/breaks ties without overriding real fingerprint relevance).
        hit = _hit_rate(ex)
        score = 1.0 + float(overlap) - (0.5 if omitted else 0.0) + (0.75 * hit)
        verbatim = "" if omitted else str(payload.get("payload"))
        resolve_from = ""
        if isinstance(payload, dict):
            resolve_from = str(payload.get("resolve_from", "") or "")
        out = {
            "id": ex.get("id", ""),            # fix3 #2A: the agent echoes this in used_exemplars so the
                                               # corpus-curator can match it and increment hit_rate next run
            "class": ex.get("class", ""),
            "trigger_signal": ex.get("trigger_signal", ""),
            "decision_trace": ex.get("decision_trace", ""),
            "key_technique": ex.get("key_technique", ""),
            "payload": verbatim,
            "resolve_from": resolve_from,
            "proof_oracle": ex.get("proof_oracle", ""),
            "hit_rate": round(hit, 3),
        }
        # sort by score desc; break ties on original order for determinism (idx asc).
        scored.append((-score, idx, out))
    scored.sort(key=lambda t: (t[0], t[1]))
    return [t[2] for t in scored[: max(0, k)]]


def _self_test():
    # Tiny in-memory fixture — the corpus is written by a sibling agent this phase, so --self-test must
    # NOT assume brain/corpus exists. Three records, each with one linked payload:
    #   A: patched-instance        -> MUST be filtered out
    #   B: reusable + OMITTED       -> surfaced, but down-weighted
    #   C: reusable + full payload  -> equal fingerprint overlap with B, MUST outrank B
    exemplars = [
        {"id": "ex-a", "class": "ssrf", "reusable_vs_instance": "patched-instance",
         "payload_ref": "pl-a", "trigger_signal": "A", "decision_trace": "A", "key_technique": "A",
         "target_fingerprint": {"framework": "", "version": "", "header": "", "param": "", "response_shape": ""},
         "proof_oracle": "oob-callback | SSRF"},
        {"id": "ex-b", "class": "ssrf", "reusable_vs_instance": "reusable-technique",
         "payload_ref": "pl-b", "trigger_signal": "B", "decision_trace": "B", "key_technique": "B",
         "target_fingerprint": {"framework": "", "version": "", "header": "", "param": "", "response_shape": ""},
         "proof_oracle": "oob-callback | SSRF"},
        {"id": "ex-c", "class": "ssrf", "reusable_vs_instance": "reusable-technique",
         "payload_ref": "pl-c", "trigger_signal": "C", "decision_trace": "C", "key_technique": "C",
         "target_fingerprint": {"framework": "", "version": "", "header": "", "param": "", "response_shape": ""},
         "proof_oracle": "oob-callback | SSRF"},
    ]
    payloads = [
        {"id": "pl-a", "class": "ssrf", "requires_fingerprint": ["cloud:gcp"],
         "status": "present", "payload": "GET /?url=http://169.254.169.254/ (patched)"},
        {"id": "pl-b", "class": "ssrf", "requires_fingerprint": ["cloud:gcp"],
         "status": "OMITTED", "resolve_from": "nuclei-templates/http/ssrf"},
        {"id": "pl-c", "class": "ssrf", "requires_fingerprint": ["cloud:gcp"],
         "status": "present", "payload": "GET /?url=http://metadata.google.internal/..."},
    ]
    fp = ["cloud:gcp"]  # equal overlap (1) for B and C

    failures = []

    got = score_and_select(exemplars, payloads, "ssrf", fp, 3)
    techniques = [r["key_technique"] for r in got]

    # 1) patched-instance excluded
    if "A" in techniques:
        failures.append("patched-instance was not filtered out")

    # 2) full-payload record (C) outranks the OMITTED one (B) at equal fingerprint overlap
    if "C" in techniques and "B" in techniques:
        if techniques.index("C") > techniques.index("B"):
            failures.append("OMITTED record outranked the full-payload record")
    else:
        failures.append("expected both reusable records (B and C) to be returned")

    # 3) top-K length correct (2 reusable records survive the gate; asking for 3 yields 2, asking for 1 yields 1)
    if len(got) != 2:
        failures.append("top-K length wrong: expected 2 surviving records, got %d" % len(got))
    if len(score_and_select(exemplars, payloads, "ssrf", fp, 1)) != 1:
        failures.append("top-K cap of 1 not honored")

    # OMITTED record must carry no runnable payload but keep its resolve_from pointer
    for r in got:
        if r["key_technique"] == "B" and (r["payload"] != "" or not r["resolve_from"]):
            failures.append("OMITTED record payload/resolve_from handling wrong")

    # 4) the `id` is surfaced (fix3 #2A) so the agent can echo it into used_exemplars for hit-rate feedback
    for r in got:
        if "id" not in r or not r["id"]:
            failures.append("exemplar id not surfaced in output (corpus hit-rate loop cannot close)")
            break

    # 5) PREFIX-NORMALIZED overlap (fix3 #6): a PREFIXED fingerprint token (framework:gcp) must still match
    #    an exemplar keyed by a differently-prefixed value (cloud:gcp) — both normalize to `gcp`.
    pref = score_and_select(exemplars, payloads, "ssrf", ["framework:gcp"], 3)
    if len(pref) != 2:
        failures.append("prefix-normalized fingerprint overlap failed (framework:gcp should match cloud:gcp)")

    # 6) HIT-RATE bonus (fix3 #2B): at equal class+fingerprint overlap, a PROVEN exemplar outranks an
    #    unproven one. Two reusable full-payload records, identical overlap; H has hit_rate 1.0, U has none.
    hr_ex = [
        {"id": "ex-u", "class": "xss", "reusable_vs_instance": "reusable-technique", "payload_ref": "pl-u",
         "trigger_signal": "U", "decision_trace": "U", "key_technique": "U",
         "target_fingerprint": {"framework": "react"}, "proof_oracle": "alert"},
        {"id": "ex-h", "class": "xss", "reusable_vs_instance": "reusable-technique", "payload_ref": "pl-h",
         "trigger_signal": "H", "decision_trace": "H", "key_technique": "H", "hit_rate": {"wins": 3, "tries": 3},
         "target_fingerprint": {"framework": "react"}, "proof_oracle": "alert"},
    ]
    hr_pl = [
        {"id": "pl-u", "class": "xss", "requires_fingerprint": ["framework:react"], "status": "present", "payload": "<svg onload=1>"},
        {"id": "pl-h", "class": "xss", "requires_fingerprint": ["framework:react"], "status": "present", "payload": "<svg onload=2>"},
    ]
    hr = score_and_select(hr_ex, hr_pl, "xss", ["react"], 2)
    if not (len(hr) == 2 and hr[0]["id"] == "ex-h"):
        failures.append("hit-rate bonus failed: a proven exemplar must outrank an unproven one at equal overlap")

    if failures:
        for f in failures:
            print("SELF-TEST FAIL:", f, file=sys.stderr)
        return 1
    print("SELF-TEST OK")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="fix3 senior-brain retriever (localhost, zero-network).")
    ap.add_argument("--corpus", default=DEFAULT_CORPUS, help="corpus dir (default C:/Spider/brain/corpus)")
    ap.add_argument("--class", dest="cls", help="attack-skill class slug to retrieve for")
    ap.add_argument("--fingerprint", default="", help="comma-separated live fingerprint tokens")
    ap.add_argument("--k", type=int, default=3, help="top-K to return (default 3)")
    ap.add_argument("--self-test", action="store_true", help="run the in-memory self-test and exit")
    args = ap.parse_args(argv)

    # The brain consumes this stdout with encoding='utf-8'. On a non-UTF-8 console (e.g. cp1251 on
    # Windows) Python would otherwise encode the JSON to the console codepage, yielding bytes that fail a
    # strict UTF-8 decode (UnicodeDecodeError -> the brain gets ZERO exemplars). Force UTF-8 stdout so the
    # emitted JSON is always valid UTF-8 regardless of the console codepage. (fix3 YELLOW-blocker fix.)
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

    if args.self_test:
        return _self_test()

    if not args.cls:
        ap.error("--class is required (or use --self-test)")

    exemplars = load_jsonl(os.path.join(args.corpus, "exemplars.jsonl"))
    payloads = load_jsonl(os.path.join(args.corpus, "payloads.jsonl"))
    fingerprint = [t for t in args.fingerprint.split(",") if t.strip()]
    result = score_and_select(exemplars, payloads, args.cls, fingerprint, args.k)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
