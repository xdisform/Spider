#!/usr/bin/env python3
"""
Spider flag-scan — an always-on, deterministic, local/offline flag pre-filter (P1 idea #1).

The synthesizer runs this every phase. It greps EVERY artifact under targets/<t>/raw/ for the
engagement's flag format (scope.objective.flag_format) and reports each match with its provenance
(file + line). If a flag was captured in some agent's evidence but was never REPORTED as a finding,
this catches it — the "never a silent zero" lesson applied to the objective. A surfaced match is a
CANDIDATE for the `flag-capture` oracle (.claude/skills/proof/oracles/SKILL.md); it is NOT a confirmed
flag — the oracle still validates format + re-derivable provenance.

Read-only. No network. stdlib-only, cross-OS (Windows/Linux/macOS). PyYAML is used to read
scope.objective.flag_format IF present, else a tiny line-scan fallback reads it; neither is required
because --flag-format can be passed explicitly (the synthesizer knows it from args.objective).

    python tools/flag-scan.py --target-dir targets/acme
    python tools/flag-scan.py --target-dir targets/acme --flag-format 'flag\\{[^}]{1,128}\\}'
    python tools/flag-scan.py --self-test          # offline self-check, no target needed

Exit: 0 = scan completed (matches or not, both honest results); 2 = bad args / invalid regex /
missing target-dir. With --fail-on-unreported, exit 3 if a format-matching flag exists in raw/ that is
absent from findings.jsonl / state.json (a SILENT flag the operator must look at).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

DEFAULT_FORMAT = r"flag\{[^}]+\}"
# per-file read cap so a huge memory/disk dump can't stall the scan (bytes). 64 MiB covers raw text
# evidence + modest binaries; larger binaries are the objective-capture skill's job (exiftool/binwalk).
MAX_BYTES = 64 * 1024 * 1024
# directories under raw/ that are our own audit trail, not target evidence — skipped to avoid echoing
# a flag we already recorded back as a "new" match.
SKIP_NAMES = {".git", "__pycache__", "node_modules"}


def read_flag_format(target_dir: Path) -> str:
    """scope.objective.flag_format, via PyYAML if available else a line-scan fallback; default if absent."""
    scope = target_dir / "scope.yaml"
    if not scope.exists():
        return DEFAULT_FORMAT
    text = scope.read_text(encoding="utf-8", errors="replace")
    try:
        import yaml  # optional dep; stdlib-first design, so we never require it
        doc = yaml.safe_load(text) or {}
        obj = doc.get("objective") or {}
        fmt = obj.get("flag_format")
        if isinstance(fmt, str) and fmt.strip():
            return fmt.strip()
        return DEFAULT_FORMAT
    except Exception:  # noqa: BLE001  (missing PyYAML OR a parse error -> fallback, never fatal)
        return _scan_flag_format(text)


def _scan_flag_format(text: str) -> str:
    """Line-scan fallback: find flag_format inside the top-level objective: block. Quote/comment-safe."""
    in_obj = False
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        stripped = raw.strip()
        if indent == 0:
            in_obj = stripped.rstrip().startswith("objective:")
            continue
        if in_obj and stripped.startswith("flag_format:"):
            val = stripped.split(":", 1)[1].strip()
            if val and val[0] in "'\"":           # quoted scalar -> take the quoted span verbatim
                q = val[0]
                end = val.find(q, 1)
                if end != -1:
                    return val[1:end]
            # bare scalar -> strip a trailing " # comment" (a regex flag_format carries no '#')
            cut = val.find(" #")
            return (val[:cut] if cut != -1 else val).strip()
    return DEFAULT_FORMAT


def _iter_files(raw: Path):
    for p in sorted(raw.rglob("*")):
        if any(part in SKIP_NAMES for part in p.parts):
            continue
        if p.is_file():
            yield p


def scan_file(path: Path, rx: re.Pattern) -> list[dict]:
    """Return match dicts {flag,line,offset} for a single file. latin-1 decode = byte-for-byte, never
    throws, so an ASCII flag embedded in an otherwise-binary artifact is still caught (strings-like)."""
    try:
        data = path.read_bytes()[:MAX_BYTES]
    except OSError:
        return []
    text = data.decode("latin-1", errors="replace")
    out = []
    for m in rx.finditer(text):
        start = m.start()
        line = text.count("\n", 0, start) + 1
        out.append({"flag": m.group(0), "line": line, "offset": start})
    return out


def _reported_blob(target_dir: Path) -> str:
    """Concatenate findings.jsonl + state.json so we can tell a reported flag from a silent one."""
    parts = []
    for name in ("findings.jsonl", "state.json"):
        p = target_dir / name
        if p.exists():
            parts.append(p.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(parts)


def run_scan(target_dir: Path, flag_format: str) -> dict:
    try:
        rx = re.compile(flag_format)
    except re.error as e:
        raise ValueError(f"invalid flag_format regex {flag_format!r}: {e}") from e

    raw = target_dir / "raw"
    matches: list[dict] = []
    scanned = 0
    if raw.is_dir():
        for p in _iter_files(raw):
            scanned += 1
            rel = p.relative_to(target_dir).as_posix()
            for hit in scan_file(p, rx):
                matches.append({"flag": hit["flag"], "file": rel, "line": hit["line"], "offset": hit["offset"]})

    reported = _reported_blob(target_dir)
    distinct = sorted({m["flag"] for m in matches})
    unreported = [f for f in distinct if f not in reported]
    for m in matches:
        m["reported"] = m["flag"] in reported

    if not distinct:
        verdict = f"no string matching /{flag_format}/ found in raw/ ({scanned} files scanned) — honest negative"
    elif unreported:
        verdict = (f"{len(unreported)} format-matching flag(s) present in raw/ but ABSENT from "
                   f"findings.jsonl/state.json -- SILENT FLAG, feed to the flag-capture oracle: "
                   + ", ".join(unreported))
    else:
        verdict = f"{len(distinct)} flag(s) found in raw/, all already reported — no silent flag"

    return {
        "target_dir": target_dir.as_posix(),
        "flag_format": flag_format,
        "scanned_files": scanned,
        "match_count": len(matches),
        "distinct_flags": distinct,
        "unreported_flags": unreported,
        "matches": matches,
        "verdict": verdict,
        "note": "read-only local pre-filter; a match is a CANDIDATE for the flag-capture oracle (format + "
                "re-derivable provenance), NOT a confirmed flag. No network touched.",
    }


def self_test() -> int:
    """Offline end-to-end check: plant a reported flag and a silent flag, assert both behaviours."""
    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        raw = t / "raw" / "attack-h-01"
        raw.mkdir(parents=True)
        (raw / "export-resp.txt").write_text("HTTP/1.1 200 OK\n\nhere is the flag{silent_in_evidence}\n",
                                             encoding="utf-8")
        (raw / "noise.txt").write_text("nothing here, flagformat but not a real flag\n", encoding="utf-8")
        # a binary-ish artifact with an ASCII flag embedded (strings-like path)
        (raw / "image.bin").write_bytes(b"\x89PNG\x00\x00tEXtflag{inside_binary}\x00\xff\xfe")
        # a second flag that IS reported as a finding
        (raw / "read-resp.txt").write_text("root:x:0:0\nflag{already_reported}\n", encoding="utf-8")
        (t / "findings.jsonl").write_text(
            json.dumps({"id": "f-0001", "execution_evidence": "flag{already_reported}"}) + "\n",
            encoding="utf-8")
        (t / "scope.yaml").write_text(
            "target: t\nobjective:\n  mode: flag\n  flag_format: 'flag\\{[^}]+\\}'  # inline\n",
            encoding="utf-8")

        fmt = read_flag_format(t)
        assert fmt == r"flag\{[^}]+\}", f"flag_format fallback parse failed: {fmt!r}"
        res = run_scan(t, fmt)
        found = set(res["distinct_flags"])
        assert "flag{silent_in_evidence}" in found, "missed a plaintext flag in evidence"
        assert "flag{inside_binary}" in found, "missed an ASCII flag embedded in a binary artifact"
        assert "flag{already_reported}" in found, "missed the reported flag"
        assert "flag{silent_in_evidence}" in res["unreported_flags"], "silent flag not flagged as unreported"
        assert "flag{inside_binary}" in res["unreported_flags"], "silent binary flag not flagged"
        assert "flag{already_reported}" not in res["unreported_flags"], "reported flag wrongly called silent"
        # the decoy ("flagformat") must NOT match the braced format
        assert all("flagformat" not in f for f in found), "decoy string wrongly matched"
    print("flag-scan self-test: OK (plaintext + embedded-ASCII caught; reported vs silent distinguished)")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Local/offline flag pre-filter over targets/<t>/raw/")
    ap.add_argument("--target-dir", help="targets/<t> (reads raw/, scope.yaml, findings.jsonl, state.json)")
    ap.add_argument("--flag-format", default=None,
                    help=r"regex to match (default: read scope.objective.flag_format, else flag\{[^}]+\})")
    ap.add_argument("--out", default=None, help="write JSON result here (default: <target-dir>/raw/flag-scan.json)")
    ap.add_argument("--fail-on-unreported", action="store_true",
                    help="exit 3 if a format-matching flag in raw/ is absent from findings.jsonl/state.json")
    ap.add_argument("--self-test", action="store_true", help="run the offline self-test and exit")
    args = ap.parse_args(argv)

    if args.self_test:
        try:
            return self_test()
        except AssertionError as e:
            print(f"flag-scan self-test: FAIL — {e}")
            return 1

    if not args.target_dir:
        print("flag-scan: --target-dir is required (or use --self-test)", file=sys.stderr)
        return 2
    target_dir = Path(args.target_dir)
    if not target_dir.is_dir():
        print(f"flag-scan: target-dir not found: {target_dir} (fail-closed)", file=sys.stderr)
        return 2

    fmt = args.flag_format or read_flag_format(target_dir)
    try:
        result = run_scan(target_dir, fmt)
    except ValueError as e:
        print(f"flag-scan: {e}", file=sys.stderr)
        return 2

    out = Path(args.out) if args.out else target_dir / "raw" / "flag-scan.json"
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    except OSError as e:
        print(f"flag-scan: could not write {out}: {e}", file=sys.stderr)

    summary = {k: result[k] for k in ("scanned_files", "match_count", "distinct_flags", "unreported_flags", "verdict")}
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f"[flag-scan] full result -> {out}")

    if args.fail_on_unreported and result["unreported_flags"]:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
