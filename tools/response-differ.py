#!/usr/bin/env python3
"""
Response differ / anomaly detector.

Takes a baseline URL + list of mutation variants (via stdin JSON), fires each
through the leash, builds a response-vector per request (status, size, hash of
sorted-headers set, body-hash, timing-ms, Set-Cookie names), and flags variants
that deviate from the baseline median (status change, |size - median| > 2*MAD,
timing > 3*MAD, novel header/cookie, novel 2xx when baseline is 4xx, etc.).

Usage:
  cat <<'EOF' | python tools/response-differ.py --target-dir targets/<target>
  { "url":"https://api.<target>/some/endpoint",
    "method":"GET",
    "baseline_repeats":5,
    "variants":[
      {"name":"empty","query":""},
      {"name":"agw_https","query":"?agw=https://attacker.oast.pro/x"},
      {"name":"agw_localhost","query":"?agw=http://127.0.0.1:80/"},
      {"name":"xmlapi","query":"?xmlapi=1"}
    ]
  }
  EOF
Prints a JSON report; writes raw responses to <target-dir>/raw/differ/<ts>/.
Requires `tools/leashed.sh` to be functional (route through leash).
"""
from __future__ import annotations
import argparse, hashlib, json, os, pathlib, re, statistics, subprocess, sys, time

def _h(s): return hashlib.sha256(s.encode("utf-8","replace")).hexdigest()[:16]

def _mad(xs):
    if len(xs)<2: return 0
    m = statistics.median(xs); return statistics.median([abs(x-m) for x in xs]) or 0

def fire(url, method, target_dir, out_dir, idx, name, extra_headers=""):
    headers = []
    for h in extra_headers.split("|"):
        h = h.strip()
        if h: headers += ["-H", h]
    body_f = out_dir / f"{idx:03d}-{name}-body.bin"
    hdr_f  = out_dir / f"{idx:03d}-{name}-hdr.txt"
    t0 = time.monotonic()
    cmd = ["bash","tools/leashed.sh", target_dir, "curl","-sk","--max-time","20",
           "-o", str(body_f), "-D", str(hdr_f), "-w", "%{http_code}", "-X", method, url, *headers]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return {"name":name,"status":0,"size":0,"timing_ms":30000,"err":"timeout","hdr_hash":"","body_hash":"","set_cookies":[]}
    dt = int((time.monotonic()-t0)*1000)
    status = int(r.stdout.strip().split()[-1]) if r.stdout.strip() and r.stdout.strip().split()[-1].isdigit() else 0
    size = body_f.stat().st_size if body_f.exists() else 0
    hdr_txt = hdr_f.read_text(encoding="utf-8",errors="replace") if hdr_f.exists() else ""
    body_bytes = body_f.read_bytes() if body_f.exists() else b""
    cookies = re.findall(r"^set-cookie:\s*([^=;\r\n]+)", hdr_txt, re.I|re.M)
    hdr_names = sorted(set(re.findall(r"^([A-Za-z0-9\-]+):", hdr_txt, re.M)))
    return {"name":name, "status":status, "size":size, "timing_ms":dt,
            "hdr_hash":_h("|".join(hdr_names)), "body_hash":_h(body_bytes.decode("utf-8","replace")[:4096]),
            "set_cookies":cookies, "hdr_names":hdr_names}

def main():
    p = argparse.ArgumentParser(); p.add_argument("--target-dir", required=True)
    a = p.parse_args()
    td = pathlib.Path(a.target_dir).resolve()
    spec = json.loads(sys.stdin.read())
    url = spec["url"]; method = spec.get("method","GET")
    baseline_repeats = int(spec.get("baseline_repeats",5))
    ts = str(int(time.time()))
    out = td / "raw" / "differ" / ts; out.mkdir(parents=True, exist_ok=True)

    # Baseline — repeat the unmodified URL N times
    base = []
    for i in range(baseline_repeats):
        base.append(fire(url, method, str(td), out, i, "baseline"))

    sizes_b = [b["size"] for b in base if b["status"]>0]
    times_b = [b["timing_ms"] for b in base if b["status"]>0]
    stat_b  = [b["status"] for b in base if b["status"]>0]
    hdr_b   = set(h for b in base for h in b.get("hdr_names",[]))
    med_size = statistics.median(sizes_b) if sizes_b else 0
    med_time = statistics.median(times_b) if times_b else 0
    mad_size = _mad(sizes_b); mad_time = _mad(times_b)
    base_status = statistics.mode(stat_b) if stat_b else 0

    # Variants
    anomalies = []
    all_variants = []
    for i, v in enumerate(spec.get("variants", []), start=100):
        full_url = url + v.get("query","")
        r = fire(full_url, v.get("method",method), str(td), out, i, v["name"], v.get("headers",""))
        r["target_url"] = full_url
        all_variants.append(r)
        reasons = []
        if r["status"] != base_status and r["status"]>0:
            reasons.append(f"status {base_status}→{r['status']}")
        if sizes_b and abs(r["size"]-med_size) > max(2*mad_size, 32):
            reasons.append(f"size {med_size}±{mad_size} → {r['size']}")
        if times_b and r["timing_ms"] > med_time + 3*(mad_time or 50):
            reasons.append(f"timing {med_time}±{mad_time} → {r['timing_ms']}ms (possible blind delay)")
        novel_hdr = sorted(set(r.get("hdr_names",[])) - hdr_b)
        if novel_hdr: reasons.append(f"novel headers: {novel_hdr[:5]}")
        if r.get("set_cookies"): reasons.append(f"new cookies: {r['set_cookies'][:4]}")
        if reasons:
            anomalies.append({"name":v["name"],"url":full_url,"reasons":reasons,"vector":r})
    print(json.dumps({
        "baseline": {"status":base_status,"median_size":med_size,"median_timing_ms":med_time,"mad_size":mad_size,"mad_timing":mad_time,"samples":len(base)},
        "variants_fired": len(all_variants),
        "anomalies": anomalies,
        "all_variants": all_variants,
        "evidence_dir": str(out),
    }, ensure_ascii=False, indent=1))

if __name__=="__main__": main()
