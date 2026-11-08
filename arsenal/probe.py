#!/usr/bin/env python3
"""
Spider arsenal probe.

Reports which arsenal tools are actually available right now (in ../bin/ or on
PATH) and their versions, so /doctor and workflow agents know the real capability
of the host before any live phase. Read-only: installs nothing.

Usage:
    python arsenal/probe.py            # human table
    python arsenal/probe.py --json     # machine-readable (for /doctor and agents)
    python arsenal/probe.py --phase recon
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from provision import present, verify, os_key, arch_tokens, data_dest, BIN, MANIFEST  # noqa: E402

PHASES = ["recon", "attack", "triage", "control", "data"]


def load() -> dict:
    if not MANIFEST.exists():
        return {"tools": []}
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def probe_tool(t: dict) -> dict:
    if t.get("install_method") == "data":
        dd = data_dest(t)
        has = dd.exists() and any(p.is_file() and p.stat().st_size > 0 for p in dd.rglob("*"))
        return {
            "name": t.get("name"), "phase": t.get("phase", "data"),
            "present": has, "path": str(dd) if has else None,
            "install_method": "data", "optional": bool(t.get("optional")),
            "version": "data dir" if has else None,
        }
    bin_name = t.get("bin_name", t.get("name"))
    p = present(bin_name)
    row = {
        "name": t.get("name"),
        "phase": t.get("phase"),
        "present": bool(p),
        "path": str(p) if p else None,
        "install_method": t.get("install_method"),
        "optional": bool(t.get("optional")),
        "version": verify(p, t.get("version_cmd", "")) if p else None,
    }
    return row


# --- F9 egress / VPN-conflict preflight (P7) --------------------------------------------------------
# Self-contained, STDLIB-ONLY (psutil used only if importable — the existing tool-table path is untouched
# and this block is reached only via the new --egress / --self-test flags). Read-only localhost diagnosis
# + (optionally) ONE in-scope TCP connect to the operator-named target (the sanctioned step-1 liveness
# connect). Default OOB-callback / local-proxy ports to flag: mihomo external-controller (9090) +
# mixed-port (7890) — a proxy LISTENING here can bounce an OOB callback back to THIS box (the h-41
# origin-check false-positive). Override with --oob-ports.
OOB_PROXY_PORTS = [9090, 7890]
# Interface name/description hints for KNOWN full-tunnel VPNs. OpenVPN tun/tap is listed only to recognise
# "another tunnel is up" (the blackholed engagement route) — it is NOT treated as a full-tunnel hijacker
# on its own (an OpenVPN engagement route is the EXPECTED path).
VPN_IFACE_HINTS = {
    "wireguard": ["wg", "wireguard"],
    "clash/mihomo": ["mihomo", "meta", "clash", "utun"],
}
OTHER_TUNNEL_HINTS = ["tun", "tap", "ovpn", "openvpn", "wg", "wireguard", "mihomo", "meta", "clash", "utun"]


def _run(cmd, timeout=6):
    """Run a localhost diagnostic read-only; (rc, text) or (None, '') if the tool is absent/fails."""
    try:
        if not (shutil.which(cmd[0]) or Path(cmd[0]).is_absolute()):
            return None, ""
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except Exception as e:  # noqa: BLE001
        return None, str(e)


def _egress_source_ip(dest):
    """Local IP the kernel would use to reach `dest` — WITHOUT sending a packet (a UDP connect only sets
    the route). Falls back to a public anchor when no target is given. Cross-OS."""
    for d in [x for x in (dest, "8.8.8.8") if x]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect((d, 80))
                return s.getsockname()[0]
            finally:
                s.close()
        except Exception:  # noqa: BLE001
            continue
    return None


def _iface_for_ip(ip):
    """Map a local IP to an interface name (psutil if present; else None)."""
    if not ip:
        return None
    try:
        import psutil  # optional
        for name, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if getattr(a, "address", None) == ip:
                    return name
    except Exception:  # noqa: BLE001
        pass
    return None


def _default_route(target_host):
    """(interface, interface_desc, gateway, source_ip, raw) for the active default route. Cross-OS,
    read-only: Get-NetRoute (Win) / ip route / route -n get default (mac) / /proc/net/route, plus the
    socket source-IP trick."""
    info = {"interface": None, "interface_desc": None, "gateway": None,
            "source_ip": _egress_source_ip(target_host), "raw": ""}
    if os.name == "nt":
        rc, out = _run(["powershell", "-NoProfile", "-Command",
            "Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Sort-Object RouteMetric | "
            "Select-Object -First 1 ifIndex,NextHop | ConvertTo-Json -Compress"])
        if rc == 0 and out.strip():
            try:
                j = json.loads(out)
                info["gateway"] = j.get("NextHop")
                info["raw"] = out.strip()
                rc2, out2 = _run(["powershell", "-NoProfile", "-Command",
                    f"Get-NetAdapter -IfIndex {j.get('ifIndex')} | "
                    "Select-Object Name,InterfaceDescription | ConvertTo-Json -Compress"])
                if rc2 == 0 and out2.strip():
                    a = json.loads(out2)
                    info["interface"] = a.get("Name")
                    info["interface_desc"] = a.get("InterfaceDescription")
            except Exception:  # noqa: BLE001
                pass
        if not info["interface"]:  # stdlib fallback
            rc, out = _run(["route", "print", "0.0.0.0"])
            info["raw"] = info["raw"] or out[-400:]
            for ln in out.splitlines():
                p = ln.split()
                if len(p) >= 5 and p[0] == "0.0.0.0" and p[1] == "0.0.0.0":
                    info["gateway"] = info["gateway"] or p[2]
                    break
    else:
        rc, out = _run(["ip", "route", "show", "default"])
        m = re.search(r"default\s+via\s+(\S+)\s+dev\s+(\S+)", out or "")
        if rc == 0 and m:
            info["gateway"], info["interface"], info["raw"] = m.group(1), m.group(2), out.strip()
        else:
            rc, out = _run(["route", "-n", "get", "default"])  # macOS
            if rc == 0 and out:
                gm = re.search(r"gateway:\s*(\S+)", out)
                im = re.search(r"interface:\s*(\S+)", out)
                info["gateway"] = gm.group(1) if gm else None
                info["interface"] = im.group(1) if im else None
                info["raw"] = out.strip()
            else:
                try:  # pure-stdlib Linux fallback
                    with open("/proc/net/route") as f:
                        for ln in f.readlines()[1:]:
                            p = ln.split()
                            if len(p) > 2 and p[1] == "00000000":
                                info["interface"] = p[0]
                                info["gateway"] = socket.inet_ntoa(int(p[2], 16).to_bytes(4, "little"))
                                break
                except Exception:  # noqa: BLE001
                    pass
    if not info["interface"]:
        info["interface"] = _iface_for_ip(info["source_ip"])
    return info


def _vpn_owns_default(route):
    """Does a KNOWN full-tunnel VPN own the default route? (bool, kind, evidence). WireGuard is also
    cross-checked via `wg show` (a peer advertising allowed-ips 0.0.0.0/0 == full-tunnel kill-switch)."""
    iface = (route.get("interface") or "").lower()
    desc = (route.get("interface_desc") or "").lower()
    for kind, hints in VPN_IFACE_HINTS.items():
        if any(h in iface or h in desc for h in hints):
            return True, kind, (f"default-route interface '{route.get('interface')}' "
                                f"({route.get('interface_desc') or 'n/a'}) matches {kind}")
    rc, out = _run(["wg", "show"])
    if rc == 0 and ("0.0.0.0/0" in out or "::/0" in out):
        return True, "wireguard", "wg show: a peer advertises allowed ips 0.0.0.0/0 (full-tunnel kill-switch)"
    return False, None, ""


def _other_tunnels_up(default_iface):
    """UP tunnel-ish interfaces besides the default-route one (e.g. an OpenVPN tun being blackholed by a
    WG kill-switch — the exact POSTMORTEM F9 shape)."""
    ups = set()
    try:
        import psutil  # optional
        for name, st in psutil.net_if_stats().items():
            if st.isup and name.lower() != (default_iface or "").lower() \
               and any(h in name.lower() for h in OTHER_TUNNEL_HINTS):
                ups.add(name)
    except Exception:  # noqa: BLE001
        if os.name == "nt":
            rc, out = _run(["powershell", "-NoProfile", "-Command",
                "Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -ExpandProperty Name"])
        else:
            rc, out = _run(["ip", "-o", "link", "show", "up"])
        for h in OTHER_TUNNEL_HINTS:
            if re.search(rf"\b{h}\w*\b", out or "", re.I):
                ups.add(h)
    return sorted(ups)


def _oob_proxy_listening(ports):
    """Local proxy LISTENING on a standard OOB-callback port on THIS box? Cross-OS, read-only — a TCP
    connect to 127.0.0.1:<port> that succeeds == something is listening."""
    hits = []
    for port in ports:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.4)
            s.close()
            hits.append({"port": port})
        except Exception:  # noqa: BLE001
            pass
    tools = [t for t in ("mihomo", "clash", "clash-meta", "wg") if shutil.which(t)]
    return hits, tools


def _target_reachable(host, port, timeout=3.0):
    """The ONE in-scope TCP connect (the sanctioned step-1 liveness connect). Read-only, no payload."""
    t0 = time.monotonic()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        local = s.getsockname()[0]
        s.close()
        return {"host": host, "port": port, "connected": True,
                "latency_ms": round((time.monotonic() - t0) * 1000), "via_source_ip": local}
    except Exception as e:  # noqa: BLE001
        return {"host": host, "port": port, "connected": False, "latency_ms": None,
                "error": f"{type(e).__name__}: {e}"}


def egress_check(target, localhost_only=False, oob_ports=None):
    host, _, port_s = (target or "").partition(":")
    port = int(port_s) if port_s.isdigit() else 443
    oob_ports = oob_ports or OOB_PROXY_PORTS
    route = _default_route(host or None)
    vpn_owns, vpn_kind, vpn_ev = _vpn_owns_default(route)
    others = _other_tunnels_up(route.get("interface"))
    oob_hits, vpn_tools = _oob_proxy_listening(oob_ports)
    reach = _target_reachable(host, port) if (host and not localhost_only) else None

    verdict, reason, advice = "egress_ok", "", ""
    if oob_hits:  # h-41 — warn: web findings valid, OOB/origin-check at risk
        verdict, reason = "warn", "oob-proxy-listening"
        advice = (f"Local proxy listening on {', '.join(str(h['port']) for h in oob_hits)} "
                  f"({', '.join(vpn_tools) or 'unknown'}). OOB callbacks may return to THIS box, not the "
                  "target (origin-check false-positive, h-41). Stop it or move it off the standard port "
                  "for the run. Non-OOB web findings are unaffected.")
    if reach is not None and not reach["connected"]:  # HARD — target unreachable
        if vpn_owns:
            verdict, reason = "conflict", "vpn-fulltunnel-killswitch"
            advice = (f"{vpn_kind} full-tunnel owns the default route ({route.get('interface')}) and "
                      f"{host}:{port} is unreachable"
                      + (f"; another tunnel is up ({', '.join(others)}) whose traffic the kill-switch "
                         "is blackholing" if others else "")
                      + ". Bring the engagement route up or disable the full-tunnel kill-switch, then re-run.")
        else:
            verdict, reason = "conflict", "target-unreachable"
            advice = (f"{host}:{port} unreachable over the current default route "
                      f"({route.get('interface')}). Check egress/VPN before GO.")
    egress_ok = verdict in ("egress_ok", "warn")  # warn does NOT block web GO; conflict does
    return {
        "mode": "egress", "target": (f"{host}:{port}" if host else None),
        "checked_localhost_only": bool(localhost_only or not host),
        "default_route": route,
        "vpn": {"full_tunnel_owns_default": vpn_owns, "kind": vpn_kind, "evidence": vpn_ev,
                "other_tunnels_up": others},
        "oob_proxy": {"listening": bool(oob_hits), "hits": oob_hits, "vpn_tools_on_path": vpn_tools},
        "target_reachable": (reach["connected"] if reach else None), "reach_detail": reach,
        "verdict": verdict, "verdict_reason": reason, "egress_ok": egress_ok, "advice": advice,
    }


def egress_self_test():
    """Offline proof the verdict table is correct — runs no network (smoke-egress.sh)."""
    def V(reach, vpn, oob):
        if oob:
            v, r = "warn", "oob-proxy-listening"
        else:
            v, r = "egress_ok", ""
        if reach is False:
            v, r = "conflict", ("vpn-fulltunnel-killswitch" if vpn else "target-unreachable")
        return v, r
    cases = [
        # (target_reachable, vpn_owns_default, oob_listening) -> (verdict, reason)
        ((True, False, False), ("egress_ok", "")),
        ((True, True, False), ("egress_ok", "")),               # VPN route is fine if target still answers
        ((False, True, False), ("conflict", "vpn-fulltunnel-killswitch")),
        ((False, False, False), ("conflict", "target-unreachable")),
        ((True, False, True), ("warn", "oob-proxy-listening")),
        ((False, True, True), ("conflict", "vpn-fulltunnel-killswitch")),  # unreachable dominates warn
    ]
    bad = 0
    for (reach, vpn, oob), want in cases:
        got = V(reach, vpn, oob)
        ok = got == want
        bad += not ok
        print(f"  {'OK ' if ok else 'FAIL'} reach={reach} vpn={vpn} oob={oob} -> {got} (want {want})")
    print(f"egress self-test: {'PASS' if not bad else f'{bad} FAIL'}")
    return 0 if not bad else 1


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Spider arsenal probe")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--phase")
    ap.add_argument("--egress", metavar="HOST[:PORT]", nargs="?", const="",
                    help="F9 egress/VPN-conflict preflight: default route + full-tunnel VPN ownership + "
                         "OOB-proxy port + (with a target) one in-scope TCP reachability connect")
    ap.add_argument("--oob-ports", help="comma-separated OOB-callback ports to flag (default 9090,7890)")
    ap.add_argument("--self-test", action="store_true", help="prove the egress verdict table offline")
    args = ap.parse_args(argv)

    # F9 egress paths short-circuit BEFORE the tool-table load — the existing probe path is untouched.
    if args.self_test:
        return egress_self_test()
    if args.egress is not None:
        ports = [int(x) for x in args.oob_ports.split(",")] if args.oob_ports else None
        res = egress_check(args.egress or None, localhost_only=(args.egress == ""), oob_ports=ports)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            v = res["verdict"].upper()
            print(f"egress: {v} ({res['verdict_reason'] or 'clean'})")
            r = res["default_route"]
            print(f"  default route: {r['interface']} via {r['gateway']} (src {r['source_ip']})")
            if res["vpn"]["full_tunnel_owns_default"]:
                print(f"  VPN: {res['vpn']['kind']} owns default — {res['vpn']['evidence']}")
            if res["oob_proxy"]["listening"]:
                print(f"  OOB proxy listening: {res['oob_proxy']['hits']} ({res['oob_proxy']['vpn_tools_on_path']})")
            if res["target"]:
                print(f"  target {res['target']} reachable: {res['target_reachable']}")
            if res["advice"]:
                print(f"  -> {res['advice']}")
        # non-zero exit on a hard conflict so a shell gate can branch on it
        return 2 if res["verdict"] == "conflict" else 0

    man = load()
    tools = man.get("tools", []) + [dict(d, phase=d.get("phase", "data")) for d in man.get("data", [])]
    if args.phase:
        tools = [t for t in tools if t.get("phase") == args.phase]
    rows = [probe_tool(t) for t in tools]

    if args.json:
        print(json.dumps({
            "host": f"{os_key()}/{arch_tokens()[0]}",
            "bin_dir": str(BIN),
            "manifest": MANIFEST.exists(),
            "present": sum(1 for r in rows if r["present"]),
            "total": len(rows),
            "tools": rows,
        }, indent=2))
        return 0

    print(f"host: {os_key()}/{arch_tokens()[0]}   bin: {BIN}")
    if not MANIFEST.exists():
        print("manifest: MISSING - run the arsenal research, then provision.py")
        return 0
    for ph in PHASES:
        prows = [r for r in rows if r["phase"] == ph]
        if not prows:
            continue
        print(f"\n[{ph}]")
        for r in prows:
            mark = "OK " if r["present"] else "-- "
            ver = f"  {r['version']}" if r["version"] else ""
            opt = " (optional)" if r.get("optional") else ""
            print(f"  {mark}{r['name']:<16}{ver}{opt}")
    ready = sum(1 for r in rows if r["present"])
    print(f"\nready: {ready}/{len(rows)}   (missing -> python arsenal/provision.py)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
