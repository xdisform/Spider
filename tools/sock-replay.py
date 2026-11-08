#!/usr/bin/env python3
"""
Spider interactive replay (P5, optional) — the `hurl` of raw sockets.

An interactive exploit proves a `session:`/`foothold:` capability by holding a socket and driving a
conversation. Because agents are per-hypothesis and a live socket is never passed between waves, that
capability is only honest if the recipe is REPRODUCIBLE on demand. This tool re-runs the exact send
sequence of a saved transcript (raw/<label>/sock-*.jsonl) — or an expect/send `convo.expect` script —
back through tools/leash-sock.py (so the replay is itself scope-pinned, capped, and re-audited), then
asserts the effect reappears: either a caller-supplied `--expect <regex>` is seen in the replayed recv
stream, or (default) the replay's recv frames match the recorded ones well enough to confirm the effect.

This is the validator aid for the `interactive-transcript` oracle (proof/oracles/SKILL.md): a session is
only `confirmed` if replaying the saved script re-derives the effect frames. It sends the SAME bytes the
original exploit sent; it never brute-forces, never floods (leash-sock's caps still apply), and refuses
exactly as leash-sock does (policy off / off-scope / proto rejected).

    # replay a saved transcript, asserting the flag/marker reappears:
    python tools/sock-replay.py targets/ctf --transcript targets/ctf/raw/attack-h-07/sock-tcp-123.jsonl \
           --expect 'flag\\{'
    # replay an expect/send script against an explicit host:port:
    python tools/sock-replay.py targets/ctf --script raw/attack-h-07/convo.expect --host 10.0.0.9 --port 1337

Exit codes: 0 effect reproduced | 1 NOT reproduced / error | 2 usage | 3/4/5/7 leash-sock refusal (passthrough)
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path


def _load_leash_sock():
    """tools/leash-sock.py has a hyphen, so load it by path (not a plain `import`)."""
    here = Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location("leash_sock", here / "leash-sock.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _read_transcript(path: str):
    """Return (header|None, sends:list[bytes], recorded_recv:bytes) from a sock-*.jsonl transcript."""
    header = None
    sends = []
    recv = bytearray()
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        d = rec.get("dir")
        if d == "header":
            header = rec
        elif d == "send":
            sends.append(bytes.fromhex(rec.get("hex", "")))
        elif d == "recv":
            recv += bytes.fromhex(rec.get("hex", ""))
    return header, sends, bytes(recv)


def _replay_sends(io, sends, drain=0.3) -> bytes:
    """Send each recorded send frame, draining replies between them. Returns all recv bytes seen."""
    got = bytearray()
    got += io.clean(drain)  # opening banner
    for payload in sends:
        io.send(payload)
        got += io.clean(drain)
    got += io.recvall(timeout=1.0)
    return bytes(got)


def main(argv) -> int:
    ap = argparse.ArgumentParser(description="Deterministic interactive replay through tools/leash-sock.py")
    ap.add_argument("target_dir", help="targets/<t> (reads leash.env — the replay is re-leashed)")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--transcript", help="a saved raw/<label>/sock-*.jsonl to replay")
    src.add_argument("--script", help="an expect/send convo DSL file to replay")
    ap.add_argument("--host", help="override host (default: from the transcript header)")
    ap.add_argument("--port", type=int, help="override port (default: from the transcript header)")
    ap.add_argument("--proto", help="override proto (default: from the transcript header, else tcp)")
    ap.add_argument("--label", default="replay", help="raw/<label>/ dir for the replay transcript")
    ap.add_argument("--expect", default=None, help="regex the replayed recv stream MUST contain to pass")
    args = ap.parse_args(argv)

    leash_sock = _load_leash_sock()

    host, port, proto = args.host, args.port, args.proto
    recorded_recv = b""
    sends = []
    if args.transcript:
        header, sends, recorded_recv = _read_transcript(args.transcript)
        if header:
            host = host or header.get("host")
            port = port or header.get("port")
            proto = proto or header.get("proto")
    proto = proto or "tcp"
    if not host or not port:
        sys.stderr.write("sock-replay: need host+port (from --transcript header or --host/--port)\n")
        return 2

    try:
        io = leash_sock.Remote(args.target_dir, host, port, proto=proto, label=args.label)
    except leash_sock.SockLeashStop as e:
        sys.stderr.write(f"sock-replay: {e}\n")
        return e.code
    except OSError as e:
        sys.stderr.write(f"sock-replay: connect failed: {e}\n")
        return 1

    try:
        if args.script:
            leash_sock._run_script(io, args.script)
            replayed = io.recvall(timeout=1.0)
        else:
            replayed = _replay_sends(io, sends)
    except leash_sock.SockLeashStop as e:
        sys.stderr.write(f"sock-replay: STOP {e}\n")
        return e.code
    finally:
        try:
            io.close()
        except Exception:  # noqa: BLE001
            pass

    # verdict ----------------------------------------------------------------------------------------
    if args.expect:
        ok = re.search(args.expect.encode(), replayed) is not None
        why = f"--expect /{args.expect}/ {'found' if ok else 'NOT found'} in replayed recv"
    elif recorded_recv:
        # no explicit marker: require the replay to reproduce a non-trivial share of the recorded effect
        anchor = recorded_recv.strip()[-32:]
        ok = bool(anchor) and anchor in replayed
        why = f"recorded recv tail {'reproduced' if ok else 'NOT reproduced'} in replay"
    else:
        ok = len(replayed) > 0
        why = "no marker/recorded recv to compare — replay produced output" if ok else "replay produced nothing"

    print(json.dumps({
        "reproduced": ok, "why": why, "host": host, "port": port, "proto": proto,
        "sends_replayed": len(sends), "replay_transcript": io.log, "recv_bytes": len(replayed),
    }, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
