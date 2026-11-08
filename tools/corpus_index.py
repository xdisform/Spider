#!/usr/bin/env python3
# fix3 senior-brain MVP — the corpus validator/indexer (G-tools).
# Scans brain/corpus/*.jsonl, validates every record parses and carries the required keys for its file,
# ASSERTS every exemplar AND negative 'class' is a shipped attack-skill slug, and regenerates index.json (counts per
# class + totals). index.json is machine-regenerated, NEVER hand-merged (SENIOR-BRAIN-DESIGN.md §5).
#
# HARD RED LINE: read-only validation of a local corpus. Zero network, zero target traffic, no secrets.
# The class-domain assertion keeps the corpus keys in lockstep with the arsenal's skill packs so a
# retrieved exemplar can never route to a class the oracle/skills do not know.
#
# Python 3.9+, STDLIB ONLY.
import argparse
import json
import os
import sys
import tempfile

# Keep in sync with ATTACK_SKILLS in workflows/attack.mjs line 30 (the 31 shipped attack-skill slugs).
# If attack.mjs's list changes, update this set (and corpus records) in lockstep.
ATTACK_SKILLS = {
    "artifact-analysis", "auth-bypass", "cors", "cred-access", "crypto", "forensics", "graphql",
    "idor", "interactive-exploit", "internal-recon", "jwt", "keycloak-realm", "lateral", "loot",
    "objective-capture", "open-redirect", "otp-logic", "privesc", "pwn", "request-smuggling", "rev",
    "saml", "sqli", "ssrf", "ssti", "stego", "takeover", "upload", "waf-body-bypass", "xss", "xxe",
}

# Required keys per corpus file (one JSON object per line).
REQUIRED_KEYS = {
    "exemplars.jsonl": [
        "id", "class", "source", "target_fingerprint", "trigger_signal", "decision_trace",
        "key_technique", "payload_ref", "proof_oracle", "reusable_vs_instance", "novelty",
        "hit_rate", "ts",
    ],
    "payloads.jsonl": ["id", "class", "requires_fingerprint", "template", "note"],
    "negative.jsonl": ["id", "scope", "fact", "consumed_by"],
}


def _read_lines(path):
    """Yield (lineno, parsed-or-None, raw) for each non-blank line of a JSONL file."""
    with open(path, "r", encoding="utf-8") as fh:
        for i, line in enumerate(fh, 1):
            raw = line.strip()
            if not raw:
                continue
            try:
                yield i, json.loads(raw), raw
            except json.JSONDecodeError:
                yield i, None, raw


def validate_corpus(corpus_dir):
    """
    Validate the corpus under corpus_dir. Returns (index_dict, violations_list).
    index_dict follows the pinned index.json shape; violations is empty on a clean corpus.
    """
    violations = []
    counts = {}
    total_exemplars = 0
    omitted_payloads = 0
    n_payloads = 0
    n_negatives = 0

    # --- payloads.jsonl -> OMITTED tally + required keys
    ppath = os.path.join(corpus_dir, "payloads.jsonl")
    if os.path.isfile(ppath):
        for ln, rec, _raw in _read_lines(ppath):
            if rec is None:
                violations.append("payloads.jsonl:%d: invalid JSON" % ln)
                continue
            for key in REQUIRED_KEYS["payloads.jsonl"]:
                if key not in rec:
                    violations.append("payloads.jsonl:%d: missing key '%s'" % (ln, key))
            n_payloads += 1
            status = str(rec.get("status", "")).strip().upper()
            pv = rec.get("payload")
            if status == "OMITTED" or not (isinstance(pv, str) and pv.strip()):
                omitted_payloads += 1

    # --- negative.jsonl -> required keys
    npath = os.path.join(corpus_dir, "negative.jsonl")
    if os.path.isfile(npath):
        for ln, rec, _raw in _read_lines(npath):
            if rec is None:
                violations.append("negative.jsonl:%d: invalid JSON" % ln)
                continue
            for key in REQUIRED_KEYS["negative.jsonl"]:
                if key not in rec:
                    violations.append("negative.jsonl:%d: missing key '%s'" % (ln, key))
            # fix3 audit #4: scope.class MUST be an ATTACK_SKILLS slug too, else the negative can never
            # match a hypothesis and the dead-end is silently lost (dead_paths[].class is free-form upstream).
            scope = rec.get("scope")
            ncls = scope.get("class") if isinstance(scope, dict) else None
            if ncls is not None and ncls not in ATTACK_SKILLS:
                violations.append(
                    "negative.jsonl:%d: scope.class '%s' not in ATTACK_SKILLS (attack.mjs line 30) — "
                    "it would never match a hypothesis; map it to the closest slug or drop it" % (ln, ncls))
            n_negatives += 1

    # --- exemplars.jsonl -> required keys + class-domain assertion + per-class counts
    epath = os.path.join(corpus_dir, "exemplars.jsonl")
    if os.path.isfile(epath):
        for ln, rec, _raw in _read_lines(epath):
            if rec is None:
                violations.append("exemplars.jsonl:%d: invalid JSON" % ln)
                continue
            for key in REQUIRED_KEYS["exemplars.jsonl"]:
                if key not in rec:
                    violations.append("exemplars.jsonl:%d: missing key '%s'" % (ln, key))
            cls = rec.get("class")
            if cls not in ATTACK_SKILLS:
                violations.append(
                    "exemplars.jsonl:%d: class '%s' not in ATTACK_SKILLS (attack.mjs line 30)" % (ln, cls)
                )
            else:
                counts[cls] = counts.get(cls, 0) + 1
            total_exemplars += 1

    index = {
        "generated_from": "corpus_index.py",
        "counts": dict(sorted(counts.items())),
        "total_exemplars": total_exemplars,
        "payloads": n_payloads,
        "negatives": n_negatives,
        "omitted_payloads": omitted_payloads,
    }
    return index, violations


def _self_test():
    tmp = tempfile.mkdtemp(prefix="corpus-index-selftest-")
    failures = []
    try:
        with open(os.path.join(tmp, "exemplars.jsonl"), "w", encoding="utf-8") as fh:
            # one valid exemplar...
            fh.write(json.dumps({
                "id": "ex-ssrf-0001", "class": "ssrf", "source": "test",
                "target_fingerprint": {"framework": "", "version": "", "header": "", "param": "", "response_shape": ""},
                "trigger_signal": "t", "decision_trace": "t", "key_technique": "t",
                "payload_ref": "pl-ssrf-0001", "proof_oracle": "oob-callback | SSRF",
                "reusable_vs_instance": "reusable-technique", "novelty": {"vrt": "", "patched_in": ""},
                "hit_rate": {"tries": 0, "wins": 0}, "ts": "2026-10-04",
            }) + "\n")
            # ...and one with a BAD class that must be reported
            fh.write(json.dumps({
                "id": "ex-bad-0002", "class": "not-a-real-class", "source": "test",
                "target_fingerprint": {}, "trigger_signal": "t", "decision_trace": "t",
                "key_technique": "t", "payload_ref": "pl-x", "proof_oracle": "x",
                "reusable_vs_instance": "reusable-technique", "novelty": {}, "hit_rate": {}, "ts": "2026-10-04",
            }) + "\n")
        with open(os.path.join(tmp, "payloads.jsonl"), "w", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "id": "pl-ssrf-0001", "class": "ssrf", "requires_fingerprint": ["cloud:gcp"],
                "template": "GET /?url=...", "note": "n", "status": "OMITTED",
                "resolve_from": "nuclei-templates/http/ssrf",
            }) + "\n")
        with open(os.path.join(tmp, "negative.jsonl"), "w", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "id": "ng-0001", "scope": {"class": "ssti", "fingerprint": ["engine:twig"]},
                "fact": "twig autoescape blocks naive {{7*7}}", "consumed_by": ["planner-skip"],
            }) + "\n")
            # ...and one negative with a FREE-FORM (non-ATTACK_SKILLS) class that must be reported
            fh.write(json.dumps({
                "id": "ng-0002", "scope": {"class": "metadata-disclosure", "fingerprint": ["cloud:gcp"]},
                "fact": "a free-form class that never maps to a hypothesis", "consumed_by": ["planner-skip"],
            }) + "\n")

        index, violations = validate_corpus(tmp)

        # the bad class MUST be reported
        if not any("not-a-real-class" in v for v in violations):
            failures.append("bad class was not reported as a violation")
        # the free-form NEGATIVE class MUST be reported too (fix3 audit #4)
        if not any("metadata-disclosure" in v for v in violations):
            failures.append("free-form negative scope.class was not reported as a violation")
        # the good exemplar must be counted; the bad one must NOT inflate counts
        if index["counts"].get("ssrf") != 1:
            failures.append("ssrf count wrong: %r" % index["counts"])
        if index["total_exemplars"] != 2:
            failures.append("total_exemplars wrong: %r" % index["total_exemplars"])
        if index["omitted_payloads"] != 1:
            failures.append("omitted_payloads wrong: %r" % index["omitted_payloads"])
        if index["payloads"] != 1 or index["negatives"] != 2:
            failures.append("payloads/negatives count wrong: %r" % index)
    finally:
        for name in ("exemplars.jsonl", "payloads.jsonl", "negative.jsonl"):
            try:
                os.remove(os.path.join(tmp, name))
            except OSError:
                pass
        try:
            os.rmdir(tmp)
        except OSError:
            pass

    if failures:
        for f in failures:
            print("SELF-TEST FAIL:", f, file=sys.stderr)
        return 1
    print("SELF-TEST OK")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="fix3 senior-brain corpus validator/indexer.")
    ap.add_argument("--corpus", default="C:/Spider/brain/corpus",
                    help="corpus dir (default C:/Spider/brain/corpus)")
    ap.add_argument("--self-test", action="store_true", help="run the self-test on a temp fixture and exit")
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()

    if not os.path.isdir(args.corpus):
        print("corpus_index: corpus dir not found: %s" % args.corpus, file=sys.stderr)
        return 1

    index, violations = validate_corpus(args.corpus)
    if violations:
        for v in violations:
            print("VIOLATION:", v, file=sys.stderr)
        return 1

    out_path = os.path.join(args.corpus, "index.json")
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(index, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    print("wrote %s (%d exemplars, %d payloads [%d OMITTED], %d negatives)" % (
        out_path, index["total_exemplars"], index["payloads"],
        index["omitted_payloads"], index["negatives"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
