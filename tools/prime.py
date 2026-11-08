#!/usr/bin/env python3
# crit-roadmap #3 — the priming BATCHER (brain-run, localhost, ZERO network).
#
# WHY THIS EXISTS: the senior-corpus primer (args.exemplars / args.negatives) is assembled by the BRAIN
# because a Workflow script cannot touch disk (require/process/fetch/import are all undefined in the
# sandbox — verified). Pre-fix that assembly was ~10 fuzzy prose steps in brain/spider.md that silently
# became a no-op whenever the brain skipped one, so brain/corpus/ never once primed a real run
# (hit_rate 0/0). This tool collapses those steps into ONE deterministic command with a checkable
# artifact: read brain/corpus/ + targets/<t>/state.json, score per hypothesis, and WRITE
# targets/<t>/priming.json = { exemplars:{<hid>:[...]}, negatives:{<hid>:[...]}, reflex_cards:{<lens>:...} }.
# The brain then loads priming.json and passes it as args.exemplars / args.negatives / args.reflex_cards.
#
# HARD RED LINE (inherited from retrieve.py): localhost-only, zero-network, strictly UPSTREAM of the
# oracle. An exemplar is a HINT for what to PRODUCE — NEVER a citation of proof. The oracle + 4 skeptic
# lenses re-derive everything on the live target and never see this output. This tool claims no finding.
#
# Python 3.9+, STDLIB ONLY. Reuses retrieve.py's scorer so there is ONE scoring discipline, not two.
import argparse
import io
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
import retrieve  # noqa: E402  (same dir; reuses load_jsonl / score_and_select / _norm_fp)

DEFAULT_CORPUS = "C:/Spider/brain/corpus"

# Condensed free-form-class -> canonical corpus-slug resolver, mirroring resolveAttackSkill() in
# workflows/attack.mjs (first substring match wins, most-specific first). The corpus keys its records by
# the canonical slug, while recon-2 emits granular classes (jwt-alg-confusion, mass-idor, ...), so without
# this a verbatim class== match misses almost everything. Kept deliberately small — the web families that
# actually have exemplars; a class that resolves to nothing simply gets no primer (honest empty, not error).
CLASS_ALIASES = [
    # crit-roadmap #5 — high-severity server-side families (mirror of workflows/attack.mjs). bare 'rce' is
    # NOT a substring alias (it is inside 'source'); exact 'rce' resolves via _CANON, free-form via '-rce'.
    ("deseri", "deser"), ("serializ", "deser"), ("unserialize", "deser"), ("hessian", "deser"),
    ("xmldecoder", "deser"), ("jackson", "deser"), ("fastjson", "deser"), ("kryo", "deser"),
    ("viewstate", "deser"), ("pickle", "deser"), ("ysoserial", "deser"), ("gadget-chain", "deser"),
    ("ognl", "ognl"), ("spel", "ognl"), ("struts", "ognl"), ("mvel", "ognl"),
    ("log4shell", "rce"), ("log4j", "rce"), ("jndi", "rce"), ("command-inj", "rce"),
    ("command-exec", "rce"), ("command-dispatcher", "rce"), ("os-command", "rce"), ("cmd-inj", "rce"),
    ("remote-code", "rce"), ("code-execution", "rce"), ("code-exec", "rce"),
    ("actuator", "info-disclosure"), ("heapdump", "info-disclosure"), ("info-disc", "info-disclosure"),
    ("stack-trace", "info-disclosure"), ("stacktrace", "info-disclosure"), ("error-leak", "info-disclosure"),
    ("source-map", "info-disclosure"), ("sourcemap", "info-disclosure"), ("test-instance", "info-disclosure"),
    ("env-exposure", "info-disclosure"), ("verbose-error", "info-disclosure"),
    ("on-behalf", "idor"), ("cross-service-user-content", "idor"), ("cross-tenant-object", "idor"),
    ("user-enum", "auth-bypass"), ("anonymous-jql", "auth-bypass"), ("auth-dto", "auth-bypass"),
    ("multipart-boundary", "waf-body-bypass"), ("boundary-abuse", "waf-body-bypass"),
    ("upstream-routing", "request-smuggling"), ("envoy", "request-smuggling"),
    ("verify-token", "otp-logic"),
    ("otp", "otp-logic"), ("2fa", "otp-logic"), ("mfa", "otp-logic"), ("totp", "otp-logic"),
    ("keycloak", "keycloak-realm"),
    ("saml", "saml"),
    ("ssrf", "ssrf"),
    ("cors", "cors"),
    ("alg-confusion", "jwt"), ("flask-session", "jwt"), ("session-forgery", "jwt"),
    ("token-forgery", "jwt"), ("jwt", "jwt"),
    ("smuggl", "request-smuggling"), ("desync", "request-smuggling"),
    ("bola", "idor"), ("idor", "idor"), ("mass-assignment", "idor"), ("mass-idor", "idor"),
    ("sql-inj", "sqli"), ("sqli", "sqli"),
    ("template-inj", "ssti"), ("ssti", "ssti"),
    ("xxe", "xxe"),
    ("xss", "xss"),
    ("upload", "upload"),
    ("takeover", "takeover"),
    ("graphql", "graphql"),
    ("waf", "waf-body-bypass"),
    ("redirect", "open-redirect"), ("oauth", "open-redirect"), ("oidc", "open-redirect"), ("dcr", "open-redirect"),
    ("access-control", "auth-bypass"), ("authbypass", "auth-bypass"), ("auth-bypass", "auth-bypass"),
    ("authz", "auth-bypass"), ("regist", "auth-bypass"), ("tenant", "auth-bypass"), ("bypass", "auth-bypass"),
]
_CANON = {slug for _, slug in CLASS_ALIASES}


def resolve_class(cls):
    c = (cls or "").strip().lower()
    if not c:
        return None
    if c in _CANON:
        return c
    for kw, slug in CLASS_ALIASES:
        if kw in c:
            return slug
    return None


def _fp_for_host(fingerprints, host):
    """Return the token list for the state.json.fingerprints[] entry whose host matches (exact, else
    the entry whose host is a suffix/prefix of the hypothesis host), else []. Mirrors spider.md's rule."""
    if not isinstance(fingerprints, list):
        return []
    host = (host or "").strip().lower()
    exact = None
    loose = None
    for fp in fingerprints:
        if not isinstance(fp, dict):
            continue
        fh = str(fp.get("host", "")).strip().lower()
        toks = fp.get("tokens") if isinstance(fp.get("tokens"), list) else []
        if fh and fh == host:
            exact = toks
            break
        if fh and host and (fh in host or host in fh):
            loose = toks
    return exact if exact is not None else (loose or [])


def _match_negatives(negatives, cls, fp_tokens, limit=4):
    """Reusable dead-ends for this class+fingerprint, as short strings. negative.jsonl records vary in
    shape; accept {class, fingerprint|requires_fingerprint, fact|dead_end|note|lesson, reusable}. A
    'clean-target'/'stop' rule with no class still applies broadly, so class-less reusable records match
    any class (they are base-rate STOP rules). Instance-specific (reusable:false / patched) are skipped."""
    want = {retrieve._norm_fp(t) for t in (fp_tokens or []) if retrieve._norm_fp(t)}
    out = []
    for rec in (negatives or []):
        if not isinstance(rec, dict):
            continue
        if rec.get("reusable") is False or rec.get("reusable_vs_instance") == "patched-instance":
            continue
        # negative.jsonl nests class/fingerprint under scope{} (e.g. ng-0001); accept both the nested and a
        # flat form. A record with no class is a BROAD base-rate STOP rule (applies to any class).
        scope = rec.get("scope") if isinstance(rec.get("scope"), dict) else {}
        rcls = str(scope.get("class", rec.get("class", "")) or "").strip().lower()
        if rcls and rcls != cls:
            continue  # class-specific record for another class
        rtoks = scope.get("fingerprint") or rec.get("fingerprint") or rec.get("requires_fingerprint") or []
        if isinstance(rtoks, list) and rtoks and want:
            if not (want & {retrieve._norm_fp(t) for t in rtoks if retrieve._norm_fp(t)}):
                continue  # has a fingerprint but none overlaps — not for this surface
        fact = rec.get("fact") or rec.get("dead_end") or rec.get("note") or rec.get("lesson") or rec.get("reason")
        if isinstance(fact, str) and fact.strip():
            out.append(fact.strip())
        if len(out) >= limit:
            break
    return out


def build(target_dir, corpus_dir, k):
    state_path = os.path.join(target_dir, "state.json")
    if not os.path.isfile(state_path):
        raise SystemExit("prime: no state.json at %s — run recon-2 + synthesis first" % state_path)
    with io.open(state_path, encoding="utf-8") as fh:
        state = json.load(fh)

    exemplars = retrieve.load_jsonl(os.path.join(corpus_dir, "exemplars.jsonl"))
    payloads = retrieve.load_jsonl(os.path.join(corpus_dir, "payloads.jsonl"))
    negatives = retrieve.load_jsonl(os.path.join(corpus_dir, "negative.jsonl"))

    hypotheses = state.get("hypotheses") if isinstance(state.get("hypotheses"), list) else []
    fingerprints = state.get("fingerprints") if isinstance(state.get("fingerprints"), list) else []

    out_ex, out_neg, reflex = {}, {}, {}
    stats = {"hypotheses": len(hypotheses), "primed": 0, "exemplars_total": 0, "negatives_total": 0,
             "unresolved_classes": []}
    for h in hypotheses:
        if not isinstance(h, dict):
            continue
        hid = h.get("id")
        if not hid:
            continue
        slug = resolve_class(h.get("class"))
        if not slug:
            cl = str(h.get("class", "")).strip().lower()
            if cl and cl not in stats["unresolved_classes"]:
                stats["unresolved_classes"].append(cl)
            continue
        fp = _fp_for_host(fingerprints, h.get("host"))
        ex = retrieve.score_and_select(exemplars, payloads, slug, fp, k)
        neg = _match_negatives(negatives, slug, fp)
        if ex:
            out_ex[hid] = ex
            stats["exemplars_total"] += len(ex)
            # a per-lens reflex card: the first exemplar's decision trace, keyed by the resolved class
            if slug not in reflex and ex[0].get("decision_trace"):
                reflex[slug] = ex[0]["decision_trace"]
        if neg:
            out_neg[hid] = neg
            stats["negatives_total"] += len(neg)
        if ex or neg:
            stats["primed"] += 1
    return {"exemplars": out_ex, "negatives": out_neg, "reflex_cards": reflex, "_stats": stats}


def _self_test():
    # In-memory: one ssrf hypothesis on a gcp host, one matching reusable exemplar, one reusable negative.
    import tempfile
    failures = []
    ex = [{"id": "ex-1", "class": "ssrf", "reusable_vs_instance": "reusable-technique", "payload_ref": "pl-1",
           "trigger_signal": "url param", "decision_trace": "blind -> oob", "key_technique": "metadata",
           "target_fingerprint": {"cloud": "gcp"}, "proof_oracle": "oob-callback"}]
    pl = [{"id": "pl-1", "class": "ssrf", "requires_fingerprint": ["cloud:gcp"], "status": "present",
           "payload": "GET /?url=http://metadata.google.internal/"}]
    neg = [{"class": "ssrf", "fingerprint": ["cloud:gcp"], "reusable": True, "fact": "169.254 is firewalled here"},
           {"class": "xss", "reusable": True, "fact": "unrelated"}]
    state = {"hypotheses": [{"id": "h-1", "class": "ssrf-blind-fetch", "host": "api.example.com"}],
             "fingerprints": [{"host": "api.example.com", "tokens": ["cloud:gcp", "framework:spring"]}]}
    d = tempfile.mkdtemp()
    cdir = os.path.join(d, "corpus")
    os.makedirs(cdir, exist_ok=True)
    with io.open(os.path.join(d, "state.json"), "w", encoding="utf-8") as fh:
        json.dump(state, fh)
    for name, rows in (("exemplars.jsonl", ex), ("payloads.jsonl", pl), ("negative.jsonl", neg)):
        with io.open(os.path.join(cdir, name), "w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")

    res = build(d, cdir, 5)
    # 1) the free-form class 'ssrf-blind-fetch' resolved to slug 'ssrf' and primed h-1
    if "h-1" not in res["exemplars"]:
        failures.append("hypothesis class was not resolved/primed (ssrf-blind-fetch -> ssrf)")
    elif res["exemplars"]["h-1"][0]["id"] != "ex-1":
        failures.append("wrong exemplar selected")
    # 2) the matching reusable negative for ssrf+gcp was attached; the xss one was NOT
    if "h-1" not in res["negatives"] or "169.254 is firewalled here" not in res["negatives"]["h-1"]:
        failures.append("matching reusable negative not attached")
    if "h-1" in res["negatives"] and "unrelated" in res["negatives"]["h-1"]:
        failures.append("a different-class negative leaked in")
    # 3) resolve_class basics (incl. crit-roadmap #5 families)
    if (resolve_class("mass-idor") != "idor"
            or resolve_class("unsafe-deserialization") != "deser"
            or resolve_class("ognl-injection-via-jira-plugin") != "ognl"
            or resolve_class("rce") != "rce"
            or resolve_class("actuator-exposure-port-regression") != "info-disclosure"
            or resolve_class("source-map-leak") != "info-disclosure"
            or resolve_class("totally-unknown-xyz") is not None):
        failures.append("resolve_class mapping wrong")

    if failures:
        for f in failures:
            print("SELF-TEST FAIL:", f, file=sys.stderr)
        return 1
    print("prime self-test: OK")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="crit-roadmap #3 priming batcher (localhost, zero-network).")
    ap.add_argument("target_dir", nargs="?", help="targets/<t> dir (contains state.json)")
    ap.add_argument("--corpus", default=DEFAULT_CORPUS, help="corpus dir (default C:/Spider/brain/corpus)")
    ap.add_argument("--k", type=int, default=5, help="top-K exemplars per hypothesis (default 5)")
    ap.add_argument("--out", default="", help="output path (default <target_dir>/priming.json)")
    ap.add_argument("--self-test", action="store_true", help="run the in-memory self-test and exit")
    args = ap.parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass
    if args.self_test:
        return _self_test()
    if not args.target_dir:
        ap.error("target_dir is required (or use --self-test)")

    res = build(args.target_dir, args.corpus, args.k)
    stats = res.pop("_stats")
    out_path = args.out or os.path.join(args.target_dir, "priming.json")
    with io.open(out_path, "w", encoding="utf-8") as fh:
        json.dump(res, fh, ensure_ascii=False, indent=2)
    print(json.dumps({"wrote": out_path, **stats}, ensure_ascii=False, indent=2))
    if stats["primed"] == 0:
        print("prime: WARNING — 0 hypotheses primed (no class resolved to a corpus slug, or corpus empty). "
              "The run will be a DEGRADED/cold run.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
