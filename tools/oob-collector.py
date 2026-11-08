#!/usr/bin/env python3
"""
OOB collector v2 — webhook.site backend.

interactsh-client v1.4.0 shipped in this arsenal has a broken embedded DNS
resolver (reports 'no address found' even when getaddrinfo resolves fine).
Rather than ship an updated interactsh, this uses webhook.site — a free,
stable HTTP-callback endpoint. Target hosts can hit webhook.site/<uuid>
with any method/path and we poll /token/<uuid>/requests for interactions.

Limitations:
  - HTTP callbacks only (no raw DNS). The Юкки program excludes
    `ssrf-dns-only` as a payable class anyway — a payable SSRF must reach
    an HTTP endpoint. So this is sufficient for the paying subset.
  - Each token is public; do not route anything sensitive here.

Usage:
  oob-collector.py start                 # creates a token, prints {session, url}
  oob-collector.py poll  <session>       # returns the list of interactions seen
  oob-collector.py stop  <session>       # drops local state (no server call)
  oob-collector.py list                  # list active sessions

leash.env must list webhook.site in LEASH_PASSTHROUGH so our local poller
can talk to the webhook.site API through the leash. Target traffic (SSRF
callbacks from in-scope hosts) reaches webhook.site via the public Internet,
NOT via the leash — the leash just lets our poller fetch results.
"""
from __future__ import annotations
import argparse, json, pathlib, sys, time, urllib.request, uuid

ROOT = pathlib.Path(__file__).resolve().parent.parent
STATE = ROOT / ".oob"
STATE.mkdir(exist_ok=True)
API = "https://webhook.site"

def _state(sid): return STATE / f"{sid}.json"
def _active(): return sorted(p.stem for p in STATE.glob("*.json"))

def _api(path, method="GET", body=None, timeout=10):
    req = urllib.request.Request(API + path, method=method, headers={"User-Agent":"Spider-OOB/1","Accept":"application/json"})
    data = None
    if body is not None:
        data = json.dumps(body).encode(); req.add_header("Content-Type","application/json")
    r = urllib.request.urlopen(req, data=data, timeout=timeout)
    return r.status, json.loads(r.read())

def start():
    try:
        status, j = _api("/token", method="POST", body={"default_status":200,"default_content":"ok","default_content_type":"text/plain","timeout":0})
    except Exception as e:
        print(json.dumps({"err":f"webhook.site POST /token failed: {e}","hint":"leash.env must include webhook.site in LEASH_PASSTHROUGH; verify leash is up on 127.0.0.1:8080"}))
        return 2
    token = j.get("uuid") or j.get("id")
    if not token:
        print(json.dumps({"err":"webhook.site did not return a token","raw":j})); return 2
    url  = f"{API}/{token}"
    sid  = f"s{int(time.time())}"
    _state(sid).write_text(json.dumps({"token":token,"url":url,"started":int(time.time())}))
    # Also expose a short-form callback host for ssrf payloads
    callback_host = f"webhook.site"
    callback_path = f"/{token}"
    print(json.dumps({"session":sid,"token":token,"url":url,
                      "callback_host":callback_host,"callback_path":callback_path,
                      "poll_cmd":f"python tools/oob-collector.py poll {sid}",
                      "example_ssrf_payload":f"?agw={url}/x?mark={{HOST}}"}))

def poll(sid):
    sf = _state(sid)
    if not sf.exists(): print(json.dumps({"err":f"unknown session {sid}","active":_active()})); return 2
    meta = json.loads(sf.read_text())
    try:
        status, j = _api(f"/token/{meta['token']}/requests?sorting=newest&per_page=50")
    except Exception as e:
        print(json.dumps({"err":f"poll failed: {e}"})); return 2
    data = j.get("data") or []
    interactions = []
    for row in data:
        interactions.append({
            "ts": row.get("created_at",""),
            "ip": row.get("ip",""),
            "method": row.get("method",""),
            "url": row.get("url",""),
            "query": row.get("query",{}),
            "user_agent": row.get("user_agent",""),
            "size": row.get("size",0),
            "content_sample": (row.get("content","") or "")[:400],
        })
    print(json.dumps({"session":sid,"token":meta["token"],"url":meta["url"],
                      "count":len(interactions),"interactions":interactions}, ensure_ascii=False, indent=1))

def stop(sid):
    sf = _state(sid)
    if not sf.exists(): print(json.dumps({"err":f"unknown session {sid}"})); return 2
    sf.unlink()
    print(json.dumps({"stopped":sid}))

def lst(): print(json.dumps({"active":_active()}))

def main():
    p = argparse.ArgumentParser()
    p.add_argument("action", choices=["start","poll","stop","list"])
    p.add_argument("session", nargs="?")
    a = p.parse_args()
    if a.action=="start": sys.exit(start())
    if a.action=="poll":  sys.exit(poll(a.session or ""))
    if a.action=="stop":  sys.exit(stop(a.session or ""))
    if a.action=="list":  sys.exit(lst())

if __name__=="__main__": main()
