#!/usr/bin/env python3
"""
Spider run-scoped recall — the in-run memory layer (iteration 3).

Between cycles the synthesizer merges the world model into state.json; WITHIN a long attack cycle (many
waves + rechain rounds) a later-wave operator cannot see the rich "I tried payload X, got WAF block Y"
that an earlier agent wrote — only the confirmed capability tokens carry forward. This tool gives every
agent a cheap, ranked lookup over the target's OWN accumulated memory so the fleet stops re-treading
dead-ends and replays what already worked on this host/stack. Agents call it via Bash during recon/attack
(the mission points them at it), exactly like source-trace.py — no brain step, used every cycle.

It indexes, for one target:
  - state.json  techniques[] (what WORKED here) + dead_paths[]/tried[] (what FAILED — do not retry)
  - findings.jsonl (confirmed/candidate findings: title/type/host/detail)
  - raw/**/notes*, *.md, sinks.txt, trace.json (agent working notes)
and ranks records by keyword/TF overlap with the query, tagging each worked | dead-end | finding | note.

Pure stdlib, local only — no network, no leash, no embeddings dependency (semantic embeddings via Mem0
are the documented ship-next upgrade; keyword recall is honest and cheap today). The raw/ tree is the
target's own evidence, not untrusted third-party input, but we still only READ it.

Usage:
  python tools/recall.py --target-dir targets/<t> --query "xss app.example.com innerHTML" [--k 8]
  python tools/recall.py --target-dir targets/<t> --class xss --host app.example.com [--k 8]
  python tools/recall.py --self-test
"""
import argparse
import json
import math
import os
import re
import sys

TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.:/-]{1,}")


def _tok(s):
    return [t for t in TOKEN_RE.findall((s or "").lower()) if len(t) > 1]


def _load_records(target_dir):
    recs = []  # {tag, host, text}
    # state.json: techniques (worked) + dead_paths/tried (dead-end)
    sp = os.path.join(target_dir, "state.json")
    if os.path.isfile(sp):
        try:
            st = json.load(open(sp, encoding="utf-8"))
        except Exception:
            st = {}
        for t in (st.get("techniques") or []):
            recs.append({"tag": "worked", "host": _s(t, "host"), "text": _flat(t)})
        for key in ("dead_paths", "tried"):
            for d in (st.get(key) or []):
                recs.append({"tag": "dead-end", "host": _s(d, "host"), "text": _flat(d)})
    # findings.jsonl
    fp = os.path.join(target_dir, "findings.jsonl")
    if os.path.isfile(fp):
        for line in open(fp, encoding="utf-8"):
            line = line.strip()
            if not line:
                continue
            try:
                f = json.loads(line)
            except Exception:
                continue
            recs.append({"tag": "finding", "host": _s(f, "host"),
                         "text": _flat({k: f.get(k) for k in ("type", "title", "severity", "class", "detail", "host")})})
    # raw working notes (bounded: only small text artifacts)
    raw = os.path.join(target_dir, "raw")
    if os.path.isdir(raw):
        for dp, _dirs, fns in os.walk(raw):
            for fn in fns:
                if not re.search(r"(notes|sinks|trace|repro|summary).*\.(txt|md|json|jsonl)$|\.md$", fn, re.I):
                    continue
                path = os.path.join(dp, fn)
                try:
                    if os.path.getsize(path) > 200_000:   # skip big dumps
                        continue
                    txt = open(path, encoding="utf-8", errors="replace").read()[:8000]
                except Exception:
                    continue
                label = os.path.relpath(dp, raw).replace("\\", "/")
                recs.append({"tag": "note", "host": label, "text": txt})
    return recs


def _s(d, k):
    v = d.get(k) if isinstance(d, dict) else None
    return str(v) if v else ""


def _flat(obj):
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        return " ".join(f"{k}={_flat(v)}" for k, v in obj.items() if v is not None)
    if isinstance(obj, (list, tuple)):
        return " ".join(_flat(x) for x in obj)
    return str(obj)


def recall(target_dir, query, host=None, k=8):
    recs = _load_records(target_dir)
    if not recs:
        return []
    # build df for idf weighting
    docs = [set(_tok(r["text"])) for r in recs]
    df = {}
    for ds in docs:
        for t in ds:
            df[t] = df.get(t, 0) + 1
    N = len(recs)
    qtok = _tok(query)
    scored = []
    for r, ds in zip(recs, docs):
        tf = _tok(r["text"])
        tfc = {}
        for t in tf:
            tfc[t] = tfc.get(t, 0) + 1
        score = 0.0
        for q in qtok:
            if q in tfc:
                idf = math.log((N + 1) / (df.get(q, 0) + 0.5))
                score += (1 + math.log(tfc[q])) * idf
        if host and r["host"] and host.lower() in r["host"].lower():
            score *= 1.5   # same-host records are more relevant
        # dead-ends are worth surfacing even on a weaker match (the point is to NOT retry them)
        if r["tag"] == "dead-end" and score > 0:
            score *= 1.2
        if score > 0:
            scored.append((score, r))
    scored.sort(key=lambda x: -x[0])
    return [r for _s0, r in scored[:k]]


def _self_test():
    import tempfile
    ok = True
    with tempfile.TemporaryDirectory() as d:
        json.dump({
            "techniques": [{"class": "sqli", "host": "api.ex.com", "note": "boolean-blind on id param worked"}],
            "dead_paths": [{"class": "xss", "host": "app.ex.com", "note": "reflected xss on q blocked by WAF, gave up"}],
        }, open(os.path.join(d, "state.json"), "w"))
        with open(os.path.join(d, "findings.jsonl"), "w") as f:
            f.write(json.dumps({"type": "idor", "title": "BOLA on /orders", "host": "api.ex.com", "severity": "high"}) + "\n")
        res = recall(d, "xss app.ex.com waf", host="app.ex.com", k=5)
        hit_dead = any(r["tag"] == "dead-end" and "waf" in r["text"].lower() for r in res)
        res2 = recall(d, "sqli id param", host="api.ex.com")
        hit_worked = any(r["tag"] == "worked" and "boolean-blind" in r["text"].lower() for r in res2)
        res3 = recall(d, "idor orders bola")
        hit_find = any(r["tag"] == "finding" and "bola" in r["text"].lower() for r in res3)
        for name, passed in [("recalls the WAF dead-end for xss", hit_dead),
                             ("recalls the working sqli technique", hit_worked),
                             ("recalls the BOLA finding", hit_find)]:
            print(f"  [{'ok' if passed else 'FAIL'}] {name}")
            ok = ok and passed
    print("SELF-TEST OK" if ok else "SELF-TEST FAIL")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description="Run-scoped recall over a target's own accumulated memory.")
    ap.add_argument("--target-dir")
    ap.add_argument("--query", default="")
    ap.add_argument("--class", dest="cls", default="")
    ap.add_argument("--host", default="")
    ap.add_argument("--k", type=int, default=8)
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return _self_test()
    if not a.target_dir or not os.path.isdir(a.target_dir):
        ap.error("--target-dir must be an existing target directory (or pass --self-test)")
    query = " ".join(x for x in (a.query, a.cls, a.host) if x).strip()
    if not query:
        ap.error("provide --query or --class/--host")
    res = recall(a.target_dir, query, host=(a.host or None), k=a.k)
    if not res:
        print("recall: nothing in this target's memory matches — cold on this surface (ok on a first run).")
        return 0
    print(f"recall: {len(res)} prior record(s) for '{query}':")
    for r in res:
        print(f"  [{r['tag']:8}] {r['host'] or '-'}: {r['text'][:220].strip()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
