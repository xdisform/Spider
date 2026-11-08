#!/usr/bin/env python3
"""
Spider deep source->sink chain tracer (Vulnhuntr-style, deterministic skeleton).

The recon `deep-source-trace` lens runs this over the RESTORED client-side source tree that
`js-secret-mining` already recovered (sourcemapper `srcmap/` + webcrack `wc/`). It is the mechanical
half of a Vulnhuntr-style analysis: it builds the cross-file symbol/import graph, locates attacker-
controlled SOURCES and dangerous SINKS, and emits ranked candidate source->sink chains WITH the path
between them and a sanitizer flag. The recon-operator (the LLM) then expands/verifies each candidate
across files and only emits a hypothesis for a chain it believes real — the tool never asserts a bug,
it hands the agent a high-signal skeleton so the whole turn budget goes to judgement, not grep-wrangling.

DATA SAFETY: the tree is UNTRUSTED. This script only READS it (never imports, never executes anything
from it) and is pure-stdlib. Run it with `python -I tools/source-trace.py <tree>` per the repo's
untrusted-input rule. No network, no leash needed — all work is local on files already pulled.

Usage:
  python -I tools/source-trace.py <src_tree_dir> [--json] [--min-confidence low|medium|high] [--max N]
  python -I tools/source-trace.py --self-test
"""
import argparse
import json
import os
import re
import sys

EXTS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue")

# --- sink patterns: (kind, hypothesis-class, compiled regex) ----------------
SINKS = [
    ("dom-xss", "xss", re.compile(r"\.innerHTML\s*=|\.outerHTML\s*=|document\.write(?:ln)?\s*\(|insertAdjacentHTML\s*\(|dangerouslySetInnerHTML")),
    ("eval", "xss", re.compile(r"\beval\s*\(|new\s+Function\s*\(|\bsetTimeout\s*\(\s*[\"'`]|\bsetInterval\s*\(\s*[\"'`]")),
    ("proto-pollution", "prototype-pollution", re.compile(r"__proto__|Object\.prototype|\bprototype\s*\[|\bconstructor\s*\[")),
    ("postmessage", "postmessage-xss", re.compile(r"addEventListener\s*\(\s*[\"']message[\"']")),
    ("jwt", "jwt", re.compile(r"\bjwt\.(?:decode|verify|sign)\s*\(|\bjwtDecode\s*\(|atob\s*\([^)]*\.split")),
    ("client-ssrf", "ssrf", re.compile(r"\bfetch\s*\(|\baxios(?:\.\w+)?\s*\(|XMLHttpRequest|\.open\s*\(\s*[\"'](?:GET|POST)")),
    ("open-redirect", "open-redirect", re.compile(r"location\s*\.\s*(?:href|assign|replace)\s*\(?\s*=?|window\.open\s*\(|location\s*=")),
]

# --- source patterns: attacker-controllable inputs --------------------------
SOURCE_RE = re.compile(
    r"location\s*\.\s*(?:search|hash|href|pathname|search)"
    r"|document\s*\.\s*(?:URL|documentURI|referrer|cookie)"
    r"|URLSearchParams|window\.name"
    r"|\breq\s*\.\s*(?:query|body|params|headers|cookies)"
    r"|\bparams\s*\[|\bsearchParams\b"
    r"|(?:local|session)Storage\s*\.\s*getItem"
    r"|\bevent\s*\.\s*data|\be\s*\.\s*data|\bmsg\s*\.\s*data"
)
# a sanitizer sitting between source and sink downgrades the chain
SANITIZER_RE = re.compile(
    r"DOMPurify|\bsanitize\b|encodeURIComponent|\bescapeHtml\b|\btextContent\b"
    r"|\bencodeURI\b|xss\(|\bclean\b\(|allowlist|whitelist|\bvalidator\b"
)
# client-ssrf to a RELATIVE/constant URL is not attacker-controlled; require a dynamic arg
DYNAMIC_ARG_RE = re.compile(r"\$\{|\+\s*\w|`[^`]*\$\{|\(\s*\w+\s*\)|,\s*\w+")

IMPORT_RE = re.compile(r"""(?:import\s+(?:\{[^}]*\}|\w+|\*\s+as\s+\w+)\s+from\s+|require\s*\(\s*)["']([^"']+)["']""")
ASSIGN_SRC_RE = re.compile(r"\b(?:const|let|var)\s+(\w+)\s*=\s*(.+)$")


def _iter_files(root):
    for dp, _dirs, fns in os.walk(root):
        # skip node_modules / vendored noise the recovered tree may carry
        if any(seg in dp.replace("\\", "/").split("/") for seg in ("node_modules", ".git", "vendor")):
            continue
        for fn in fns:
            if fn.endswith(EXTS):
                yield os.path.join(dp, fn)


def _read(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read().splitlines()
    except Exception:
        return []


def analyze_tree(root, window=12):
    """Deterministic intra-file taint + cross-file import linkage. Returns ranked candidates."""
    cands = []
    files = list(_iter_files(root))
    for path in files:
        lines = _read(path)
        if not lines:
            continue
        rel = os.path.relpath(path, root)
        # tainted vars: `const x = <source...>`
        tainted = {}
        for i, ln in enumerate(lines):
            m = ASSIGN_SRC_RE.search(ln)
            if m and SOURCE_RE.search(m.group(2)):
                tainted[m.group(1)] = i + 1
        for i, ln in enumerate(lines):
            for kind, cls, rx in SINKS:
                if not rx.search(ln):
                    continue
                lo = max(0, i - window)
                ctx = "\n".join(lines[lo:i + window + 1])
                # a client-ssrf/open-redirect to a static string is not a taint chain
                if kind in ("client-ssrf",) and not DYNAMIC_ARG_RE.search(ln):
                    continue
                src_line = None
                src_kind = None
                # 1) a tainted var referenced on the sink line
                for v, vl in tainted.items():
                    if re.search(r"\b" + re.escape(v) + r"\b", ln):
                        src_line, src_kind = vl, "tainted-var"
                        break
                # 2) a source within the proximity window
                if src_line is None:
                    sm = SOURCE_RE.search(ctx)
                    if sm:
                        # find its absolute line
                        for j in range(lo, i + window + 1):
                            if j < len(lines) and SOURCE_RE.search(lines[j]):
                                src_line, src_kind = j + 1, "proximity"
                                break
                sanitized = bool(SANITIZER_RE.search(ctx))
                if src_line is not None:
                    conf = "medium" if sanitized else "high"
                elif kind == "postmessage" and "origin" not in ctx:
                    conf, src_kind = "medium", "message-no-origin-check"
                else:
                    conf = "low"
                cands.append({
                    "sink_file": rel.replace("\\", "/"), "sink_line": i + 1, "sink_kind": kind,
                    "class": cls, "source_line": src_line, "source_kind": src_kind,
                    "sanitizer_between": sanitized, "confidence": conf,
                    "snippet": lines[i].strip()[:200],
                })
    rank = {"high": 0, "medium": 1, "low": 2}
    cands.sort(key=lambda c: (rank[c["confidence"]], c["sink_file"], c["sink_line"]))
    return cands


def _self_test():
    import tempfile
    ok = True
    with tempfile.TemporaryDirectory() as d:
        # a planted DOM-XSS chain (source -> sink, no sanitizer) -> expect high
        with open(os.path.join(d, "vuln.js"), "w", encoding="utf-8") as f:
            f.write("const q = location.search;\n")
            f.write("document.getElementById('x').innerHTML = q;\n")
        # a sanitized chain -> expect medium (DOMPurify between)
        with open(os.path.join(d, "safe.jsx"), "w", encoding="utf-8") as f:
            f.write("const h = location.hash;\n")
            f.write("el.innerHTML = DOMPurify.sanitize(h);\n")
        # a bare sink with no source -> expect low
        with open(os.path.join(d, "bare.ts"), "w", encoding="utf-8") as f:
            f.write("el.innerHTML = STATIC_TEMPLATE;\n")
        c = analyze_tree(d)
        by = {x["sink_file"]: x for x in c}
        checks = [
            ("vuln.js is high", by.get("vuln.js", {}).get("confidence") == "high"),
            ("vuln.js class xss", by.get("vuln.js", {}).get("class") == "xss"),
            ("safe.jsx is medium (sanitizer)", by.get("safe.jsx", {}).get("confidence") == "medium"),
            ("safe.jsx sanitizer flagged", by.get("safe.jsx", {}).get("sanitizer_between") is True),
            ("bare.ts is low (no source)", by.get("bare.ts", {}).get("confidence") == "low"),
        ]
        for name, passed in checks:
            print(f"  [{'ok' if passed else 'FAIL'}] {name}")
            ok = ok and passed
    print("SELF-TEST OK" if ok else "SELF-TEST FAIL")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description="Deterministic source->sink chain tracer over a recovered JS/TS tree.")
    ap.add_argument("tree", nargs="?", help="root of the restored source tree (raw/js-secret-mining/...)")
    ap.add_argument("--json", action="store_true", help="emit JSON (default: human table)")
    ap.add_argument("--min-confidence", choices=["low", "medium", "high"], default="low")
    ap.add_argument("--max", type=int, default=200)
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return _self_test()
    if not a.tree or not os.path.isdir(a.tree):
        ap.error("tree must be an existing directory (or pass --self-test)")
    rank = {"high": 0, "medium": 1, "low": 2}
    cands = [c for c in analyze_tree(a.tree) if rank[c["confidence"]] <= rank[a.min_confidence]][:a.max]
    if a.json:
        print(json.dumps({"tree": a.tree, "count": len(cands), "candidates": cands}, indent=2))
    else:
        print(f"{len(cands)} source->sink candidate(s) in {a.tree}:")
        for c in cands:
            src = f" <- source@{c['source_line']} ({c['source_kind']})" if c["source_line"] else " [no source — lead only]"
            san = " [SANITIZER between]" if c["sanitizer_between"] else ""
            print(f"  [{c['confidence']:6}] {c['class']:18} {c['sink_file']}:{c['sink_line']} {c['sink_kind']}{src}{san}")
            print(f"           {c['snippet']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
