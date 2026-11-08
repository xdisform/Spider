#!/usr/bin/env python3
"""
Spider interactive-protocol leash (P5) — a held, scope-pinned, capped, AUDITED socket/REPL tube.

The HTTP leash (tools/leash.py, a mitmproxy addon whose only hook is `request`) is structurally blind to
raw TCP and to post-upgrade WebSocket frames, and tools/leash-tcp.sh is a ONE-SHOT exec (banner grab, one
nmap, one swaks) that cannot hold a conversation. A pwn `nc` logic bug, a stateful service REPL, or a
WebSocket command bug are exploited over a CONVERSATION (send -> recv -> branch across many frames on one
held connection). THIS wrapper is therefore the scope + audit choke point for that conversation, exactly
the role tools/leash-tcp.sh and tools/leash-cred.sh play for their one-shot / cred cases.

Core is pure Python stdlib (socket + ssl) so it runs on every OS with no third-party lib. pwntools /
pexpect / websocket-client are OPTIONAL enhancers used only when a proto needs them (ws/wss/pty).

Library (the agent's exploit drives a pwntools-shaped tube, but every frame is leashed + logged):
    # tools/leash-sock.py has a hyphen, so load it by path (see .claude/skills/attack/interactive-exploit):
    import importlib.util, pathlib
    spec = importlib.util.spec_from_file_location("leash_sock", pathlib.Path("tools/leash-sock.py"))
    leash_sock = importlib.util.module_from_spec(spec); spec.loader.exec_module(leash_sock)
    io = leash_sock.Remote("targets/ctf", "10.0.0.9", 1337, proto="tcp", label="attack-h-07")
    io.recvuntil(b"name? "); io.sendline(b"%p%p%p"); leak = io.recvline()
    io.sendlineafter(b"> ", b"redeem ADMIN"); print(io.recvall()); io.close()

CLI (expect-style runner for simple line protocols; drives the SAME leashed tube):
    python tools/leash-sock.py <target_dir> <host> <port> --proto tcp --script raw/attack-h-07/convo.expect
    python tools/leash-sock.py <target_dir> <host> <port> --proto tcp --recv-banner

Exit codes mirror tools/leash-cred.sh:
    0 ok | 2 usage | 3 off-scope (fail-closed) | 4 policy-disabled (fail-closed) | 5 proto/port rejected | 7 cap hit

Enforcement (all in this one file, same discipline as leash-cred.sh):
  1. fail-closed policy gate   — refuse unless LEASH_SOCK_ENABLED=1 (brain writes LEASH_SOCK_* into leash.env
                                 from policies.interactive_protocol, exactly as it writes LEASH_CRED_*).
  2. host-pin via guard.py     — imported, not edited; fail-closed if the host is not in LEASH_SCOPE.
  3. proto + optional port     — allow-lists from policy (LEASH_SOCK_PROTOS / LEASH_SOCK_PORTS).
  4. flood/DoS caps            — max_frames / max_bytes / max_session_s / idle_timeout_s; exceeding any closes
                                 the session with a `limit` event and a non-zero exit (a logic exploit is a
                                 handful of frames; a flood is structurally impossible). NO artificial pacing
                                 (unlike cred-spray) — a logic bug is not a spray.
  5. full transcript audit     — every frame -> raw/<label>/sock-<proto>-<ts>.jsonl (the re-derivable evidence
                                 the interactive oracle / tools/sock-replay.py replays; the HTTP leash is blind).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import ssl
import sys
import time
from pathlib import Path

DEFAULT_PROTOS = ("tcp", "tls", "ws", "wss", "pty")


class SockLeashStop(Exception):
    """A control refused — fail-closed. Carries the CLI exit code so caller and CLI agree."""

    def __init__(self, msg: str, code: int = 1):
        super().__init__(msg)
        self.code = code


def _stamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _b(x) -> bytes:
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    return str(x).encode()


def _csv(s) -> list:
    return [x.strip() for x in str(s or "").replace(";", ",").split(",") if x.strip()]


def _load_env(target_dir: str) -> dict:
    """Parse the flat KEY=VALUE leash.env (same shape leash-tcp.sh / rate-limit-probe.py read)."""
    env = {}
    p = Path(target_dir) / "leash.env"
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def _unescape(s: str) -> bytes:
    """Minimal DSL unescape for script lines: \\n \\r \\t \\0 \\\\ and \\xHH."""
    out = bytearray()
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            if n == "n":
                out.append(0x0A); i += 2; continue
            if n == "r":
                out.append(0x0D); i += 2; continue
            if n == "t":
                out.append(0x09); i += 2; continue
            if n == "0":
                out.append(0x00); i += 2; continue
            if n == "\\":
                out.append(0x5C); i += 2; continue
            if n == "x" and i + 3 < len(s) + 1 and re.match(r"[0-9a-fA-F]{2}", s[i + 2:i + 4]):
                out.append(int(s[i + 2:i + 4], 16)); i += 4; continue
        out.append(ord(c) & 0xFF)
        i += 1
    return bytes(out)


class Remote:
    """A held, leashed, audited tube. pwntools-shaped API (send/sendline/recv/recvuntil/recvline/
    recvregex/clean/interactive/close) so an ordinary pwntools-style exploit runs unchanged — but every
    frame is scope-checked, capped, and transcript-logged."""

    def __init__(self, target_dir, host, port, proto="tcp", label="interactive", env=None):
        self.target_dir = str(target_dir)
        self.env = env if env is not None else _load_env(target_dir)
        # 1. fail-closed policy gate (before anything else) ----------------------------------------
        if self.env.get("LEASH_SOCK_ENABLED") != "1":
            raise SockLeashStop("policies.interactive_protocol disabled — refusing (fail-closed)", 4)
        self.host = str(host)
        self.port = int(port)
        self.proto = str(proto).lower()
        # 2. proto allow-list (policy) --------------------------------------------------------------
        protos = _csv(self.env.get("LEASH_SOCK_PROTOS")) or list(DEFAULT_PROTOS)
        if self.proto not in protos:
            raise SockLeashStop(f"proto '{self.proto}' not in allow-list {protos} — refusing", 5)
        # 3. optional port allow-list (policy; [] => any in-scope port) -----------------------------
        ports = _csv(self.env.get("LEASH_SOCK_PORTS"))
        if ports and str(self.port) not in ports:
            raise SockLeashStop(f"port {self.port} not in allow-list {ports} — refusing", 5)
        # 4. host-pin via the SAME scope authority as every non-HTTP tool (guard.py) ----------------
        #    ALWAYS enforced (guard.in_scope is a pure, offline function) — fail-closed, never a range.
        self._host_pin()
        # caps (anti-flood; red line enforced in code) ----------------------------------------------
        self.max_frames = int(self.env.get("LEASH_SOCK_MAX_FRAMES", 500))
        self.max_bytes = int(self.env.get("LEASH_SOCK_MAX_BYTES", 1048576))
        self.max_sess = int(self.env.get("LEASH_SOCK_MAX_SESSION_S", 120))
        self.idle = float(self.env.get("LEASH_SOCK_IDLE_TIMEOUT_S", 10))
        self._frames = 0
        self._bytes = 0
        self._t0 = time.time()
        self._buf = b""
        self._closed = False
        self._kind = None
        label = re.sub(r"[^A-Za-z0-9._-]", "_", str(label)) or "interactive"
        self.log = os.path.join(self.target_dir, "raw", label,
                                f"sock-{self.proto}-{int(self._t0)}-{os.getpid()}.jsonl")
        os.makedirs(os.path.dirname(self.log), exist_ok=True)
        self._header()
        self._open()
        self._rec("open", b"")

    # --- gates --------------------------------------------------------------------------------------
    def _host_pin(self):
        scope = _csv(self.env.get("LEASH_SCOPE"))
        if not scope:
            raise SockLeashStop("LEASH_SCOPE missing — refusing (fail-closed)", 3)
        try:
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            from guard import in_scope  # imported, NOT edited — zero merge surface there
        except Exception as e:  # noqa: BLE001 — no guard => cannot verify scope => fail-closed
            raise SockLeashStop(f"scope guard unavailable ({e}) — refusing (fail-closed)", 3)
        exact = self.env.get("LEASH_EXACT", "1") == "1"
        if not in_scope(self.host, scope, exact=exact):
            raise SockLeashStop(f"{self.host} out of scope {scope} — refusing (fail-closed)", 3)

    # --- transport (tcp/tls via stdlib; ws/wss via websocket-client; pty via pexpect) ---------------
    def _open(self):
        if self.proto in ("tcp", "tls"):
            s = socket.create_connection((self.host, self.port), timeout=self.idle)
            if self.proto == "tls":
                ctx = ssl.create_default_context()
                # the target may ship a self-signed cert (same stance as start-leash.sh --ssl-insecure);
                # this tube proves a LOGIC bug, not TLS trust, so do not fail the hold on cert validation.
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=self.host)
            s.settimeout(self.idle)
            self._sock = s
            self._kind = "socket"
        elif self.proto in ("ws", "wss"):
            try:
                import websocket  # websocket-client (optional); pure Python, cross-OS
            except Exception as e:  # noqa: BLE001
                raise SockLeashStop(f"proto {self.proto} needs websocket-client "
                                    f"(pip install websocket-client): {e}", 5)
            path = self.env.get("LEASH_SOCK_WS_PATH", "/")
            url = f"{self.proto}://{self.host}:{self.port}{path}"
            self._ws = websocket.create_connection(url, timeout=self.idle)
            self._kind = "ws"
        elif self.proto in ("pty", "process"):
            try:
                import pexpect  # optional; spawn() needs a Unix pty (Linux/mac/WSL)
            except Exception as e:  # noqa: BLE001
                raise SockLeashStop(f"proto {self.proto} needs pexpect (pip install pexpect): {e}", 5)
            cmd = self.env.get("LEASH_SOCK_SPAWN")
            if not cmd:
                raise SockLeashStop("proto pty/process needs LEASH_SOCK_SPAWN=<client argv> in leash.env", 5)
            self._child = pexpect.spawn(cmd, timeout=self.idle, encoding=None)
            self._kind = "pty"
        else:
            raise SockLeashStop(f"unknown proto {self.proto}", 5)

    def _raw_send(self, data: bytes):
        if self._kind == "socket":
            self._sock.sendall(data)
        elif self._kind == "ws":
            self._ws.send_binary(data)
        elif self._kind == "pty":
            self._child.send(data)

    def _raw_recv(self, n: int) -> bytes:
        try:
            if self._kind == "socket":
                return self._sock.recv(n) or b""
            if self._kind == "ws":
                d = self._ws.recv()
                return d if isinstance(d, (bytes, bytearray)) else str(d).encode()
            if self._kind == "pty":
                return self._child.read_nonblocking(n, timeout=self.idle) or b""
        except (socket.timeout, TimeoutError):
            return b""
        except Exception:  # noqa: BLE001 — EOF / closed / ws timeout all mean "no more data now"
            return b""
        return b""

    # --- caps (checked at the START of every framed op; a flood can never leave this wrapper) -------
    def _check_limits(self):
        if time.time() - self._t0 > self.max_sess:
            self._rec("limit", b"max_session_s")
            self._fail("max_session_s cap hit", 7)
        if self._frames + 1 > self.max_frames:
            self._rec("limit", b"max_frames")
            self._fail("max_frames cap hit", 7)

    def _count_bytes(self, data: bytes):
        self._bytes += len(data)
        if self._bytes > self.max_bytes:
            self._rec("limit", b"max_bytes")
            self._fail("max_bytes cap hit", 7)

    def _fail(self, reason: str, code: int):
        self._raw_close()
        self._closed = True
        raise SockLeashStop(reason, code)

    # --- public pwntools-shaped API -----------------------------------------------------------------
    def send(self, data) -> int:
        data = _b(data)
        self._check_limits()
        self._frames += 1
        self._count_bytes(data)
        self._raw_send(data)
        self._rec("send", data)
        return len(data)

    def sendline(self, data=b"") -> int:
        data = _b(data)
        if not data.endswith(b"\n"):
            data = data + b"\n"
        return self.send(data)

    def sendafter(self, delim, data):
        self.recvuntil(delim)
        return self.send(data)

    def sendlineafter(self, delim, data):
        self.recvuntil(delim)
        return self.sendline(data)

    def _fill(self) -> int:
        """One framed raw read into the buffer; returns bytes read (0 = idle timeout or EOF)."""
        self._check_limits()
        self._frames += 1
        d = self._raw_recv(4096)
        self._count_bytes(d)
        self._rec("recv", d)
        self._buf += d
        return len(d)

    def recv(self, n: int = 4096) -> bytes:
        if not self._buf:
            self._fill()
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def recvuntil(self, delim, drop: bool = False) -> bytes:
        delim = _b(delim)
        while delim not in self._buf:
            if self._fill() == 0:
                break  # idle timeout / EOF — return what we have (honors idle/time/frame caps)
        i = self._buf.find(delim)
        if i < 0:
            out, self._buf = self._buf, b""
            return out
        end = i + len(delim)
        out, self._buf = self._buf[:end], self._buf[end:]
        return out[:i] if drop else out

    def recvline(self, drop: bool = False) -> bytes:
        return self.recvuntil(b"\n", drop=drop)

    def recvregex(self, rx, drop: bool = False) -> bytes:
        pat = re.compile(rx if isinstance(rx, (bytes, bytearray)) else str(rx).encode())
        while not pat.search(self._buf):
            if self._fill() == 0:
                break
        m = pat.search(self._buf)
        if not m:
            out, self._buf = self._buf, b""
            return out
        end = m.end()
        out, self._buf = self._buf[:end], self._buf[end:]
        return out[:m.start()] if drop else out

    def recvall(self, timeout: float = None) -> bytes:
        deadline = time.time() + (timeout if timeout is not None else self.max_sess)
        while time.time() < deadline:
            if self._fill() == 0:
                break
        out, self._buf = self._buf, b""
        return out

    def clean(self, timeout: float = 0.05) -> bytes:
        """Drain buffered/pending data without blocking the full idle timeout."""
        old = None
        if self._kind == "socket":
            old = self._sock.gettimeout()
            self._sock.settimeout(timeout)
        data = bytearray(self._buf)
        self._buf = b""
        try:
            while True:
                d = self._raw_recv(4096)
                if not d:
                    break
                data += d
        finally:
            if old is not None and self._kind == "socket":
                self._sock.settimeout(old)
        if data:
            self._count_bytes(bytes(data))
            self._rec("recv", bytes(data))
        return bytes(data)

    def interactive(self):
        """Hand the live (still-logged, still-capped) socket to a human. Gated by policy."""
        if self.env.get("LEASH_SOCK_ALLOW_PASSTHROUGH") != "1":
            raise SockLeashStop("Remote.interactive() needs allow_interactive_passthrough: true", 5)
        sys.stderr.write("[leash-sock] interactive passthrough (still audited). Ctrl-D to exit.\n")
        try:
            pending = self.clean(0.3)
            if pending:
                sys.stdout.buffer.write(pending)
                sys.stdout.flush()
            for line in sys.stdin.buffer:
                self.send(line)
                got = self.clean(0.3)
                if got:
                    sys.stdout.buffer.write(got)
                    sys.stdout.flush()
        except (EOFError, KeyboardInterrupt):
            pass

    # --- audit --------------------------------------------------------------------------------------
    def _write(self, rec: dict):
        try:
            with open(self.log, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, separators=(",", ":")) + "\n")  # compact JSONL, like the repo's other ledgers
        except OSError:
            pass

    def _header(self):
        self._write({
            "ts": _stamp(), "epoch": round(time.time(), 3), "dir": "header",
            "host": self.host, "port": self.port, "proto": self.proto,
            "scope": _csv(self.env.get("LEASH_SCOPE")),
            "exact": self.env.get("LEASH_EXACT", "1") == "1",
            "in_scope": True,  # guard.in_scope already verified above, else we never reach here
            "caps": {"max_frames": self.max_frames, "max_bytes": self.max_bytes,
                     "max_session_s": self.max_sess, "idle_timeout_s": self.idle},
            "fingerprint": self.env.get("LEASH_SOCK_FINGERPRINT", ""),  # recon banner / service version (idea #6)
        })

    def _rec(self, direction: str, data):
        data = _b(data)
        self._write({
            "ts": _stamp(), "epoch": round(time.time(), 3), "dir": direction,
            "host": self.host, "port": self.port, "proto": self.proto,
            "len": len(data), "hex": data.hex(), "printable": data.decode("latin-1", "replace"),
        })

    def _raw_close(self):
        try:
            if self._kind == "socket":
                self._sock.close()
            elif self._kind == "ws":
                self._ws.close()
            elif self._kind == "pty":
                self._child.close(force=True)
        except Exception:  # noqa: BLE001
            pass

    def close(self):
        if self._closed:
            return
        self._closed = True
        self._rec("close", b"")
        self._raw_close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# --- CLI: an expect-style runner over the SAME leashed tube ----------------------------------------
def _run_script(io: "Remote", path: str):
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        verb, _, rest = s.partition(" ")
        verb = verb.lower()
        if verb in ("send", "sendline"):
            io.sendline(_unescape(rest))
        elif verb == "sendraw":
            io.send(_unescape(rest))
        elif verb == "sendhex":
            io.send(bytes.fromhex(re.sub(r"\s+", "", rest)))
        elif verb == "recvline":
            io.recvline()
        elif verb == "recvuntil":
            io.recvuntil(_unescape(rest))
        elif verb == "recvregex":
            io.recvregex(rest.encode())
        elif verb == "recv":
            io.recv(int(rest) if rest.strip().isdigit() else 4096)
        elif verb == "clean":
            io.clean()
        elif verb == "sleep":
            time.sleep(float(rest or "0"))
        else:
            sys.stderr.write(f"[leash-sock] script: unknown verb '{verb}' (ignored)\n")


def main(argv) -> int:
    ap = argparse.ArgumentParser(description="Spider interactive-protocol leash (held, scope-pinned, "
                                             "capped, audited socket/REPL). Fail-closed.")
    ap.add_argument("target_dir", help="targets/<t> (reads leash.env: LEASH_SCOPE, LEASH_SOCK_*)")
    ap.add_argument("host", help="ONE in-scope destination host (never a range)")
    ap.add_argument("port", type=int)
    ap.add_argument("--proto", default="tcp", help="tcp|tls|ws|wss|pty (must be policy-allow-listed)")
    ap.add_argument("--label", default="interactive", help="raw/<label>/ transcript dir")
    ap.add_argument("--script", default=None, help="expect/send DSL file (one verb per line)")
    ap.add_argument("--recv-banner", action="store_true", help="just drain + print the opening banner")
    args = ap.parse_args(argv)

    try:
        io = Remote(args.target_dir, args.host, args.port, proto=args.proto, label=args.label)
    except SockLeashStop as e:
        sys.stderr.write(f"leash-sock: {e}\n")
        return e.code
    except OSError as e:
        sys.stderr.write(f"leash-sock: connect failed: {e}\n")
        return 1

    sys.stderr.write(f"leash-sock: held {args.proto}://{args.host}:{args.port} -> transcript {io.log}\n")
    try:
        if args.script:
            _run_script(io, args.script)
        elif args.recv_banner:
            sys.stdout.write(io.clean(0.3).decode("latin-1", "replace"))
        return 0
    except SockLeashStop as e:
        sys.stderr.write(f"leash-sock: STOP {e}\n")
        return e.code
    finally:
        try:
            io.close()
        except Exception:  # noqa: BLE001
            pass


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
