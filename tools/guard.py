#!/usr/bin/env python3
"""
Spider scope guard — for NON-HTTP tools (nmap, naabu, masscan...) that don't go through
the leash proxy. It checks that every host/IP a command would touch is in scope, and blocks
target-list-file flags that hide the real targets. Use it to pin a tool before it runs.

    python tools/guard.py --scope app.acme.com,203.0.113.0/24 --check "nmap -sV app.acme.com"
    -> exit 0 if in scope, exit 1 + reason otherwise

As a library:
    from guard import in_scope, guard_command
"""
from __future__ import annotations

import argparse
import ipaddress
import re
import sys

LIST_FLAGS = re.compile(r"(^|\s)(-iL|-l|-L|--list|--target-file|--hosts-file)(\s|=)")
HOSTISH = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b|\b\d{1,3}(?:\.\d{1,3}){3}\b", re.I)
# tokens that look host-ish but are code/paths, so we don't false-block
NON_HOST_TAILS = (".py", ".js", ".json", ".txt", ".html", ".sh", ".md", ".log", ".xml", ".yaml", ".yml")


def _parse_scope(scope: list[str]):
    hosts, nets = set(), []
    for s in scope:
        s = s.strip().lower()
        if not s:
            continue
        if "/" in s:
            try:
                nets.append(ipaddress.ip_network(s, strict=False))
                continue
            except ValueError:
                pass
        hosts.add(s)
    return hosts, nets


def in_scope(host: str, scope: list[str], exact: bool = True) -> bool:
    host = host.strip().lower().rsplit(":", 1)[0]
    hosts, nets = _parse_scope(scope)
    # IP against CIDRs
    try:
        ip = ipaddress.ip_address(host)
        if any(ip in n for n in nets):
            return True
    except ValueError:
        pass
    if exact:
        return host in hosts
    return any(host == h or host.endswith("." + h) for h in hosts)


def guard_command(cmd: str, scope: list[str], exact: bool = True) -> tuple[bool, str]:
    if LIST_FLAGS.search(cmd):
        return False, "target-list-file flag blocked (-iL/-l/--list): every target must be visible"
    tokens = [t for t in HOSTISH.findall(cmd) if not t.lower().endswith(NON_HOST_TAILS)]
    offenders = [t for t in tokens if not in_scope(t, scope, exact)]
    if offenders:
        return False, f"off-scope host(s): {', '.join(sorted(set(offenders)))}"
    if not tokens:
        return False, "no in-scope host found in command — pin the exact target"
    return True, "ok"


# --- credential control-test mode (F5) ------------------------------------------------------------
# A cred tool must run as a bounded SPRAY, never a cartesian brute, never a range. guard_cred_command
# rejects the shapes that turn a control-test into a brute-force. nuclei is gated by its templates
# (pre-condition + pitchfork + stop-at-first), so it is allowed through here.
CRED_TOOLS = re.compile(r"\b(nxc|netexec|crackmapexec|hydra|medusa|patator)\b", re.I)
PASS_FILE_FLAG = re.compile(r"(?:^|\s)(?:-p|-P|--password|--passwords)\s+(\S+)")
CIDR_TARGET = re.compile(r"/\d{1,2}\b")


def _file_line_count(path: str) -> int | None:
    import os
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return sum(1 for _ in f)
    except OSError:
        return None


def guard_cred_command(cmd: str, max_pairs: int = 20) -> tuple[bool, str]:
    low = cmd.lower()
    m = CRED_TOOLS.search(cmd)
    if not m:
        return True, "ok (no managed cred tool — nuclei is gated by its templates)"
    tool = m.group(1).lower()
    if tool in ("hydra", "medusa"):
        return False, f"{tool} forbidden for cred control-test (no lockout detection) — use nuclei default-logins or nxc --no-bruteforce"
    if tool in ("nxc", "netexec", "crackmapexec"):
        if "--no-bruteforce" not in low:
            return False, "netexec/nxc must carry --no-bruteforce (line-by-line spray, not cartesian brute)"
        if "--continue-on-success" in low:
            return False, "--continue-on-success past a one-pass spray is forbidden"
    if tool == "patator" and "--rate-limit" not in low and "rate_limit=" not in low:
        return False, "patator must carry --rate-limit"
    if CIDR_TARGET.search(cmd):
        return False, "range/CIDR target forbidden for cred tools — pin exactly one host"
    for mm in PASS_FILE_FLAG.finditer(cmd):
        n = _file_line_count(mm.group(1))
        if n is not None and n > max_pairs:
            return False, f"password set '{mm.group(1)}' has {n} > max_pairs={max_pairs} — curated small set only"
    return True, "ok"


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Spider scope guard for non-HTTP tools")
    ap.add_argument("--scope", required=True, help="comma-separated in-scope hosts/CIDRs")
    ap.add_argument("--check", required=True, help="the command line to validate")
    ap.add_argument("--allow-subdomains", action="store_true")
    ap.add_argument("--cred-mode", action="store_true", help="also enforce credential-control-test rules (spray-not-brute, no range, capped set)")
    ap.add_argument("--max-pairs", type=int, default=20, help="max credential pairs allowed in cred-mode (default 20)")
    args = ap.parse_args(argv)
    ok, reason = guard_command(args.check, args.scope.split(","), exact=not args.allow_subdomains)
    if ok and args.cred_mode:
        ok, reason = guard_cred_command(args.check, max_pairs=args.max_pairs)
    print(("OK: " if ok else "BLOCKED: ") + reason)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
