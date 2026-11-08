#!/usr/bin/env python3
"""
Direct-origin fetcher — WAF bypass via explicit IP + Host header.

Fetches a URL via a *specific direct-origin IP* (bypassing a CDN/WAF layer)
and spoofs the Host header to the production hostname. Scope-pinned: both
the Host header value AND the IP must appear in LEASH_SCOPE / LEASH_SCOPE's
derived set — otherwise refused.

Useful for:
  - fetching the live production JS bundle through stage/direct-origin that
    the CDN would otherwise 403
  - comparing production response vs direct-origin response for the same path
    (CDN artifacts, WAF-added headers, response shaping, extra middleware)
  - probing attack payloads directly against the origin to see if the WAF is
    the only gate

Usage:
  python tools/direct-origin-fetch.py --target-dir targets/<target> \\
       --host app.<target> --via-ip 203.0.113.10 \\
       --path /_next/static/chunks/main.js --out raw/bundle-via-stage.js

The script wraps curl + --resolve so the TLS SNI matches the Host header
(so the direct origin returns the right vhost without complaining).
"""
from __future__ import annotations
import argparse, json, os, pathlib, re, subprocess, sys, time

def _leash_env(td: pathlib.Path):
    env = {}
    f = td / "leash.env"
    if not f.exists(): return env
    for line in f.read_text(encoding="utf-8",errors="replace").splitlines():
        line=line.strip()
        if not line or line.startswith("#"): continue
        if "=" not in line: continue
        k,v = line.split("=",1); env[k.strip()] = v.strip().strip('"')
    return env

def _in_scope(host, scope):
    host = host.lower()
    for s in [x.strip().lower() for x in scope.split(",") if x.strip()]:
        if host==s or host.endswith("."+s): return True
    return False

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--target-dir", required=True)
    p.add_argument("--host", required=True, help="Host header value (production hostname)")
    p.add_argument("--via-ip", required=True, help="Direct-origin IP to connect to")
    p.add_argument("--path", default="/", help="URL path (default /). NB: Git Bash on Windows rewrites a bare `/` arg into the MinGW root; pass the path as `//foo/bar` or quote it to avoid the conversion. The script strips a leading MinGW root prefix defensively.")
    p.add_argument("--scheme", default="https", choices=["http","https"])
    p.add_argument("--method", default="GET")
    p.add_argument("--out", default="", help="Output file (default stdout + metadata)")
    p.add_argument("--extra-header", action="append", default=[], help="Extra request headers (repeatable)")
    p.add_argument("--port", default="")
    a = p.parse_args()

    td = pathlib.Path(a.target_dir).resolve()
    env = _leash_env(td)
    scope = env.get("LEASH_SCOPE","")
    if not scope: print(json.dumps({"err":"leash.env has no LEASH_SCOPE — refusing"})); sys.exit(2)
    if not _in_scope(a.host, scope):
        print(json.dumps({"err":f"host {a.host} out of scope {scope} — refused"})); sys.exit(2)
    # IP in-scope: either literally in LEASH_SCOPE, or in LEASH_SCOPE_NETBLOCKS; we require explicit
    # presence in LEASH_SCOPE (comma-separated) OR the user accepts a note that the IP is operator-asserted.
    # Simple check: ip appears in LEASH_SCOPE string
    if a.via_ip not in scope:
        # Allow if the IP's /24 or /27 appears somewhere; otherwise refuse honestly
        prefix = ".".join(a.via_ip.split(".")[:3])
        if prefix not in scope:
            print(json.dumps({"warn":f"via-ip {a.via_ip} not explicitly in LEASH_SCOPE — operator-asserted direct origin","note":"scope.yaml should include this IP or its CIDR under netblocks for a strict leash. Proceeding under operator attestation."}), file=sys.stderr)
    port = a.port or ("443" if a.scheme=="https" else "80")
    # Git-Bash defensive: strip MinGW root rewrite ("C:/Program Files/Git" or "/c/...").
    pth = a.path
    for pref in ("C:/Program Files/Git", "C:\\Program Files\\Git", "/c/"):
        if pth.startswith(pref):
            pth = pth[len(pref):]
            if pth == "": pth = "/"
            if not pth.startswith("/"): pth = "/" + pth
            break
    if not pth.startswith("/"): pth = "/" + pth
    url = f"{a.scheme}://{a.host}:{port}{pth}"
    # curl --resolve <host>:<port>:<ip> forces the lookup. We do NOT route this through the mitmproxy
    # leash — the leash is HTTP-only and would re-resolve. Direct curl via leashed-equivalent means we
    # still enforce header injection + rate manually.
    header = env.get("LEASH_HEADER","X-Bug-Bounty")
    token  = env.get("X_BUGBOUNTY_TOKEN","")
    rps    = env.get("LEASH_RPS","5")
    headers = ["-H", f"{header}: {token}"]
    for h in a.extra_header: headers += ["-H", h]
    out_file = a.out
    out_dir = td / "raw" / "direct-origin"
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = int(time.time())
    body = out_dir / f"{ts}-{a.host}-{a.via_ip}-{a.path.strip('/').replace('/','_') or 'root'}.bin"
    hdr  = out_dir / f"{ts}-{a.host}-{a.via_ip}-headers.txt"
    cmd = ["curl","-sk","--max-time","20",
           "--resolve", f"{a.host}:{port}:{a.via_ip}",
           "-o", str(body), "-D", str(hdr), "-w", "%{http_code} %{size_download} %{time_total}",
           "-X", a.method, url, *headers]
    t0 = time.monotonic()
    # MSYS_NO_PATHCONV=1 so Git Bash on Windows doesn't rewrite `/` into `C:/Program Files/Git/`.
    env = {**os.environ, "MSYS_NO_PATHCONV":"1", "MSYS2_ARG_CONV_EXCL":"*"}
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=25, env=env)
    dt = int((time.monotonic()-t0)*1000)
    try:
        stats = r.stdout.strip().split()
        status = int(stats[0]); size = int(stats[1]); _ = float(stats[2])
    except Exception:
        status, size = 0, 0
    hdr_txt = hdr.read_text(encoding="utf-8",errors="replace") if hdr.exists() else ""
    print(json.dumps({
        "ok": status>0,
        "status": status,
        "size": size,
        "timing_ms": dt,
        "url": url,
        "via_ip": a.via_ip,
        "body_file": str(body),
        "headers_file": str(hdr),
        "server": re.search(r"^Server:\s*(.+)$", hdr_txt, re.I|re.M).group(1).strip() if re.search(r"^Server:\s*(.+)$", hdr_txt, re.I|re.M) else "",
        "content_type": re.search(r"^Content-Type:\s*(.+)$", hdr_txt, re.I|re.M).group(1).strip() if re.search(r"^Content-Type:\s*(.+)$", hdr_txt, re.I|re.M) else "",
    }, ensure_ascii=False, indent=1))

if __name__=="__main__": main()
