#!/usr/bin/env python3
r"""
Spider otp-logic-probe — a deterministic, local/offline OTP-logic checker (P6 idea #1).

Given one or more ALREADY-CAPTURED OTP-trigger responses (the pre-OTP / login / resend response the
operator saved under targets/<t>/raw/ with tools/leashed.sh), it machine-checks the two highest-value,
zero-risk OTP-logic surfaces so attack gets a concrete candidate instead of narrating past them:

  (a) LEAK  — grep each response (body + headers) for the OTP code itself, or for a
              pending / mfa / otp_token style accept-token the verify endpoint would take. A second
              factor returned to the client is no factor at all.
  (b) PREDICTABLE / STATIC — extract the labeled code from each response and diff them across
              captures: identical (static / reusable), a constant step (sequential counter), or a
              varying width / leading zero (loose-compare hint).

It issues **NO** target traffic — it only reads files already on disk — so it needs no leash and is
pure logic. A hit is a CANDIDATE for the `otp-logic-session` oracle (.claude/skills/proof/oracles/
SKILL.md) and for the `attack/otp-logic` class; it is NEVER a confirmed bypass, and this tool NEVER
brute-forces, floods, or touches a target. Read-only. stdlib-only. Cross-OS (Windows/Linux/macOS).

    # the deterministic path: point it at the two saved trigger responses (own-account captures)
    python tools/otp-logic-probe.py --resp raw/otp-logic/trigger-1.txt --resp raw/otp-logic/trigger-2.txt

    # convenience: auto-collect otp/verify/login2/resend responses under a target's raw/
    python tools/otp-logic-probe.py --target-dir targets/acme

    # custom code shape (tickytask ships a 9-digit code) + extra accept-token names
    python tools/otp-logic-probe.py --resp a.txt --resp b.txt --otp-format '\d{9}' --token-names pending,mfa,otp_token

    python tools/otp-logic-probe.py --self-test     # offline self-check, no target needed

Exit: 0 = probe completed (a leak/predictable candidate OR an honest negative — both are results);
2 = bad args / invalid regex / no readable input. With --fail-on-candidate, exit 3 when a leak or a
static/sequential/adjacent predictability candidate is found (handy for an offline assertion).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

# A bare OTP code: 4-10 digits by default (tickytask's is 9). Not anchored on \b so a code wrapped in
# quotes/punctuation ("otp":"123456") is still caught; the digit-neighbour guards avoid slicing a
# longer number. Override with --otp-format for an alnum / dashed code.
DEFAULT_OTP_FORMAT = r"(?<![0-9A-Za-z])[0-9]{4,10}(?![0-9A-Za-z])"
# JSON/header field NAMES whose presence-with-a-value in a PRE-OTP response is an accept-token leak.
DEFAULT_TOKEN_NAMES = [
    "otp", "otp_token", "otptoken", "pending", "pending_token", "mfa", "mfa_token",
    "code", "otp_code", "verification", "verification_code", "verify_token", "one_time",
    "one_time_code", "totp", "hotp", "challenge", "otp_secret",
]
# A number is LABELED "this is the OTP code" only when an OTP keyword sits immediately to its LEFT (a
# value follows its key: `"otp":"123456"`, `OTP code: 123456`), separated by at most a few quote/sep
# chars. Left-context only, so a Unix timestamp / content-length with an unrelated `otp` key to its
# RIGHT is NOT mislabeled (that was the self-test decoy). Case-insensitive.
LABEL_LEFT = re.compile(
    r"(otp|code|token|pin|verif|mfa|2fa|one[\s_\-]?time|passcode|auth[\s_\-]?code|challenge)"
    r"[\"'\s:=\-_]{0,8}$", re.I)
CODE_HINT_WINDOW = 40  # how many chars of left context to scan for the labeling keyword
# per-file read cap so a huge captured artifact can't stall the probe (bytes).
MAX_BYTES = 16 * 1024 * 1024
SKIP_NAMES = {".git", "__pycache__", "node_modules"}
# default filename hints when auto-collecting from a target's raw/ (no --resp given).
COLLECT_HINTS = ("otp", "verify", "login2", "resend", "mfa", "2fa", "challenge")


def _decode(path: Path) -> str | None:
    """latin-1 whole-file decode = byte-for-byte, never throws; an ASCII token in an otherwise-binary
    capture is still caught. Returns None only if the file cannot be read at all."""
    try:
        return path.read_bytes()[:MAX_BYTES].decode("latin-1", errors="replace")
    except OSError:
        return None


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _truncate(val: str, cap: int = 80) -> str:
    val = val.strip()
    return val if len(val) <= cap else val[:cap] + f"...(+{len(val) - cap})"


def find_token_fields(text: str, token_names: list[str]) -> list[dict]:
    """A `"<name>": "<value>"` JSON field or a `Name: value` header whose value is non-empty."""
    out: list[dict] = []
    seen: set[tuple[str, int]] = set()
    for name in token_names:
        # "name": "value"  |  "name": value  |  name=value  |  Header-Name: value
        rx = re.compile(
            r'(?i)["\']?\b' + re.escape(name) + r'\b["\']?\s*[:=]\s*["\']?([A-Za-z0-9._\-+/]{2,})["\']?'
        )
        for m in rx.finditer(text):
            value = m.group(1)
            # skip the obvious non-leaks: a boolean/null/empty "second-factor-required" flag is not a token
            if value.lower() in ("true", "false", "null", "none", "required", "pending", "sent", "ok"):
                continue
            key = (name, m.start(1))
            if key in seen:
                continue
            seen.add(key)
            out.append({"name": name, "value": _truncate(value), "line": _line_of(text, m.start())})
    return out


def find_codes(text: str, rx: re.Pattern) -> list[dict]:
    """Every otp-format match, flagged `labeled` when an OTP keyword sits immediately to its LEFT."""
    out: list[dict] = []
    for m in rx.finditer(text):
        s = m.start()
        left = text[max(0, s - CODE_HINT_WINDOW):s]
        labeled = bool(LABEL_LEFT.search(left))
        out.append({"code": m.group(0), "line": _line_of(text, s), "labeled": labeled})
    return out


def _primary_code(codes: list[dict]) -> str | None:
    """The code to use for the predictability diff: the first LABELED one (never a random long number)."""
    for c in codes:
        if c["labeled"]:
            return c["code"]
    return None


def classify_predictable(samples: list[dict]) -> dict:
    """Diff the per-capture primary codes: static / sequential / adjacent / inconclusive / not-predictable."""
    codes = [s["code"] for s in samples if s.get("code")]
    res: dict = {
        "samples": samples,
        "usable_samples": len(codes),
        "classification": "insufficient-samples",
        "step": None,
        "width_varies": False,
        "leading_zero": False,
        "summary": "",
    }
    if len(codes) < 2:
        res["summary"] = ("need >= 2 captures with a LABELED code for the predictability diff "
                          f"(have {len(codes)}); the leak check still applies to a single capture")
        return res

    res["leading_zero"] = any(c[0] == "0" and len(c) > 1 for c in codes)
    res["width_varies"] = len({len(c) for c in codes}) > 1

    if len(set(codes)) == 1:
        res["classification"] = "static"
        res["step"] = 0
        res["summary"] = (f"the SAME code ({codes[0]}) was returned on every capture — static/reusable; "
                          "attack should replay it (reuse path), no brute")
        return res

    # numeric sequence analysis (only when every code is all-digits)
    if all(c.isdigit() for c in codes):
        ints = [int(c) for c in codes]
        deltas = [b - a for a, b in zip(ints, ints[1:])]
        if len(codes) >= 3 and len(set(deltas)) == 1 and deltas[0] != 0:
            res["classification"] = "sequential"
            res["step"] = deltas[0]
            res["summary"] = (f"codes advance by a constant step {deltas[0]} across {len(codes)} captures "
                              "— a sequential/counter generator; the next code is derivable (use ONCE), no brute")
            return res
        if len(codes) == 2:
            d = deltas[0]
            res["step"] = d
            if abs(d) == 1:
                res["classification"] = "adjacent"
                res["summary"] = ("two captures differ by 1 — suggestive of a sequential counter; "
                                  "capture a THIRD own-account code to confirm before attack relies on it")
            else:
                res["classification"] = "inconclusive"
                res["summary"] = (f"two captures differ by {d}; two points cannot establish predictability "
                                  "— capture a third, or treat as not-predictable")
            return res
        res["classification"] = "not-predictable"
        res["summary"] = (f"{len(codes)} captures with non-constant deltas {deltas} — no obvious sequence "
                          "from these samples (not proof of secure generation; just not predictable here)")
        return res

    res["classification"] = "not-predictable"
    res["summary"] = (f"{len(codes)} non-numeric codes, all distinct — no static/sequence signal from "
                      "these samples")
    return res


def run_probe(resp_paths: list[Path], otp_format: str, token_names: list[str], root: Path | None = None) -> dict:
    try:
        rx = re.compile(otp_format)
    except re.error as e:
        raise ValueError(f"invalid --otp-format regex {otp_format!r}: {e}") from e

    per_file: list[dict] = []
    samples: list[dict] = []
    leak_candidate = False
    read_ok = 0

    for p in resp_paths:
        text = _decode(p)
        rel = p.as_posix()
        if root is not None:
            try:
                rel = p.relative_to(root).as_posix()
            except ValueError:
                rel = p.as_posix()
        if text is None:
            per_file.append({"file": rel, "error": "unreadable"})
            continue
        read_ok += 1
        token_fields = find_token_fields(text, token_names)
        codes = find_codes(text, rx)
        # a LABELED code (the value of an otp/code key) is a leak signal; a stray unlabeled number
        # (timestamp / content-length) is listed for transparency but does NOT by itself raise the flag.
        if token_fields or any(c["labeled"] for c in codes):
            leak_candidate = True
        per_file.append({
            "file": rel,
            "token_fields": token_fields,
            "bare_codes": codes,
            "labeled_code": _primary_code(codes),
        })
        samples.append({"file": rel, "code": _primary_code(codes)})

    predictable = classify_predictable(samples)

    if read_ok == 0:
        verdict = "no readable OTP-trigger response — pass --resp <file> (or --target-dir with captures under raw/)"
    elif leak_candidate:
        leaked = sorted({tf["name"] for f in per_file for tf in f.get("token_fields", [])})
        bits = []
        if leaked:
            bits.append("accept-token field(s) present in a pre-OTP response: " + ", ".join(leaked))
        if any(c["labeled"] for f in per_file for c in f.get("bare_codes", [])):
            bits.append("a labeled OTP code is present in a pre-OTP response")
        verdict = ("LEAK CANDIDATE -- " + "; ".join(bits) +
                   ". A second factor returned to the client is no factor: feed attack/otp-logic (LEAK path) "
                   "and the otp-logic-session oracle. Confirm it is the PRE-OTP/trigger response, not the "
                   "post-verify one.")
    elif predictable["classification"] in ("static", "sequential", "adjacent"):
        verdict = f"PREDICTABLE CANDIDATE ({predictable['classification']}) -- {predictable['summary']}"
    else:
        verdict = (f"no leak and no static/sequential signal from {read_ok} capture(s) — honest negative "
                   "(not proof the OTP logic is sound; binding / enforcement / reuse / loose-compare are "
                   "tested live in attack/otp-logic)")

    return {
        "inputs": [p.as_posix() for p in resp_paths],
        "readable": read_ok,
        "otp_format": otp_format,
        "token_names": token_names,
        "leak": {"candidate": leak_candidate, "per_file": per_file},
        "predictable": predictable,
        "verdict": verdict,
        "note": ("read-only local OTP-logic pre-filter; a hit is a CANDIDATE for the otp-logic-session "
                 "oracle (leak/predictable surfaces only), NOT a confirmed session. This tool issues NO "
                 "network traffic, never brutes the code space, and never touches a target."),
    }


def _collect_from_target(target_dir: Path, glob: str | None) -> list[Path]:
    raw = target_dir / "raw"
    if not raw.is_dir():
        return []
    out: list[Path] = []
    for p in sorted(raw.rglob(glob or "*")):
        if any(part in SKIP_NAMES for part in p.parts) or not p.is_file():
            continue
        name = p.name.lower()
        if glob or any(h in name for h in COLLECT_HINTS):
            out.append(p)
    return out


def self_test() -> int:
    """Offline end-to-end check: assert LEAK, STATIC, SEQUENTIAL, and a clean NEGATIVE each resolve right."""
    with tempfile.TemporaryDirectory() as td:
        t = Path(td)

        # 1) LEAK: a pre-OTP response that hands the client an accept-token AND the code itself.
        leak_a = t / "leak-a.txt"
        leak_a.write_text(
            'HTTP/1.1 200 OK\r\nSet-Cookie: pending=abc\r\n\r\n'
            '{"status":"otp_sent","otp_token":"eyJhbGciOi.PENDING.sig","otp":"483920"}\n',
            encoding="utf-8")
        r_leak = run_probe([leak_a], DEFAULT_OTP_FORMAT, DEFAULT_TOKEN_NAMES)
        assert r_leak["leak"]["candidate"] is True, "missed an accept-token leak"
        names = {tf["name"] for f in r_leak["leak"]["per_file"] for tf in f["token_fields"]}
        assert "otp_token" in names, f"otp_token field not detected: {names}"
        assert any(c["code"] == "483920" and c["labeled"] for f in r_leak["leak"]["per_file"] for c in f["bare_codes"]), \
            "labeled code 483920 not detected"

        # 2) STATIC: same labeled code returned twice (own account) => reusable/static.
        sa = t / "static-1.txt"; sb = t / "static-2.txt"
        sa.write_text('{"message":"code sent","otp":"100200"}', encoding="utf-8")
        sb.write_text('{"message":"code sent","otp":"100200"}', encoding="utf-8")
        r_static = run_probe([sa, sb], DEFAULT_OTP_FORMAT, DEFAULT_TOKEN_NAMES)
        assert r_static["predictable"]["classification"] == "static", r_static["predictable"]
        assert r_static["predictable"]["step"] == 0

        # 3) SEQUENTIAL: three captures advancing by a constant step, plus an UNLABELED timestamp decoy
        #    that must NOT be taken as the code.
        seq = []
        for i, code in enumerate(("100001", "100002", "100003")):
            p = t / f"seq-{i}.txt"
            p.write_text(f'{{"ts":1700000000,"otp":"{code}"}}', encoding="utf-8")
            seq.append(p)
        r_seq = run_probe(seq, DEFAULT_OTP_FORMAT, DEFAULT_TOKEN_NAMES)
        assert r_seq["predictable"]["classification"] == "sequential", r_seq["predictable"]
        assert r_seq["predictable"]["step"] == 1, r_seq["predictable"]
        # the 10-digit unlabeled timestamp must not have become the primary code
        assert all(s["code"] in ("100001", "100002", "100003") for s in r_seq["predictable"]["samples"]), \
            "unlabeled timestamp wrongly chosen as the OTP code"

        # 4) CLEAN NEGATIVE: no code, no accept-token, just a boolean flag (must not false-positive).
        clean = t / "clean.txt"
        clean.write_text('{"mfa_required":true,"message":"enter the code we sent you"}', encoding="utf-8")
        r_clean = run_probe([clean], DEFAULT_OTP_FORMAT, DEFAULT_TOKEN_NAMES)
        assert r_clean["leak"]["candidate"] is False, f"clean response false-positived: {r_clean['leak']}"
        assert r_clean["predictable"]["classification"] == "insufficient-samples"

        # 5) ADJACENT: exactly two captures differing by 1 => suggestive, not asserted sequential.
        aa = t / "adj-1.txt"; ab = t / "adj-2.txt"
        aa.write_text('{"otp":"555000"}', encoding="utf-8")
        ab.write_text('{"otp":"555001"}', encoding="utf-8")
        r_adj = run_probe([aa, ab], DEFAULT_OTP_FORMAT, DEFAULT_TOKEN_NAMES)
        assert r_adj["predictable"]["classification"] == "adjacent", r_adj["predictable"]

    print("otp-logic-probe self-test: OK (leak, static, sequential, adjacent, clean-negative all resolved; "
          "unlabeled timestamp decoy ignored)")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Local/offline OTP-logic pre-filter (leak + predictability) over captured responses")
    ap.add_argument("--resp", action="append", default=[], metavar="FILE",
                    help="a captured OTP-trigger response file; repeat for the predictability diff")
    ap.add_argument("--target-dir", help="targets/<t> — auto-collect otp/verify/login2/resend responses under raw/ when no --resp is given")
    ap.add_argument("--glob", default=None, help="override the raw/ collection glob (default: filename contains otp/verify/login2/resend/mfa/2fa/challenge)")
    ap.add_argument("--otp-format", default=DEFAULT_OTP_FORMAT, help=r"regex for the bare OTP code (default: 4-10 digits)")
    ap.add_argument("--token-names", default=None, help="comma-separated accept-token field names to grep for (default: a built-in list)")
    ap.add_argument("--out", default=None, help="write JSON result here (default: <target-dir>/raw/otp-logic-probe.json, else stdout only)")
    ap.add_argument("--fail-on-candidate", action="store_true", help="exit 3 if a leak or a static/sequential/adjacent predictability candidate is found")
    ap.add_argument("--self-test", action="store_true", help="run the offline self-test and exit")
    args = ap.parse_args(argv)

    if args.self_test:
        try:
            return self_test()
        except AssertionError as e:
            print(f"otp-logic-probe self-test: FAIL — {e}")
            return 1

    token_names = ([s.strip() for s in args.token_names.split(",") if s.strip()]
                   if args.token_names else list(DEFAULT_TOKEN_NAMES))

    root = None
    resp_paths: list[Path] = [Path(r) for r in args.resp]
    target_dir: Path | None = None
    if args.target_dir:
        target_dir = Path(args.target_dir)
        if not target_dir.is_dir():
            print(f"otp-logic-probe: target-dir not found: {target_dir} (fail-closed)", file=sys.stderr)
            return 2
        root = target_dir
        if not resp_paths:
            resp_paths = _collect_from_target(target_dir, args.glob)
            if not resp_paths:
                print(f"otp-logic-probe: no OTP-trigger responses found under {target_dir}/raw/ "
                      "— pass --resp <file> explicitly", file=sys.stderr)
                return 2

    if not resp_paths:
        print("otp-logic-probe: no input — pass --resp <file> (repeatable) or --target-dir (or --self-test)", file=sys.stderr)
        return 2

    missing = [p for p in resp_paths if not p.exists()]
    if missing and len(missing) == len(resp_paths):
        print(f"otp-logic-probe: no readable input (missing: {', '.join(m.as_posix() for m in missing)})", file=sys.stderr)
        return 2

    try:
        result = run_probe(resp_paths, args.otp_format, token_names, root=root)
    except ValueError as e:
        print(f"otp-logic-probe: {e}", file=sys.stderr)
        return 2

    out: Path | None = None
    if args.out:
        out = Path(args.out)
    elif target_dir is not None:
        out = target_dir / "raw" / "otp-logic-probe.json"
    if out is not None:
        try:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        except OSError as e:
            print(f"otp-logic-probe: could not write {out}: {e}", file=sys.stderr)
            out = None

    summary = {
        "readable": result["readable"],
        "leak_candidate": result["leak"]["candidate"],
        "predictable": result["predictable"]["classification"],
        "verdict": result["verdict"],
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    if out is not None:
        print(f"[otp-logic-probe] full result -> {out.as_posix()}")

    if args.fail_on_candidate and (result["leak"]["candidate"]
                                   or result["predictable"]["classification"] in ("static", "sequential", "adjacent")):
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
