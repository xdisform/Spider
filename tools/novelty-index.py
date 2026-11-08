#!/usr/bin/env python3
r"""
Spider novelty-index — a deterministic, stdlib-only builder for the prior-art / dedup pack
targets/<t>/priorart.json (fix3 B3, bounty mode).

Bug bounty is a race-to-report-first TOURNAMENT: only the FIRST distinct submission is paid, a
duplicate valid report earns nothing. So the single highest-value lever in a bounty run is to learn
what is ALREADY KNOWN before spending fleet waves on $0 duplicates. This tool pulls the program's
disclosure history (HackerOne Hacktivity GraphQL), the stack's known CVEs (NVD 2.0) and component
advisories (GitHub Security Advisories / GHSA), the changelog, and — most reliable of all — the
operator's OWN submission archive (targets/<t>/submitted/), and indexes each disclosed item as a
ROOT-CAUSE fingerprint (class + cwe + component + root_cause + fixed). The reused duplicate-scout
agent (prior-art mode) / the novelty-scout recon-2 lens uses this pack to orient the fleet; the
single-writer synthesizer tags each hypothesis's `novelty`.

PASSIVE OSINT ONLY. Every source is a PUBLIC disclosure index or a LOCAL file — this tool touches NO
target, needs NO leash, and NEVER widens scope (same class as subfinder/gau). A host that appears in a
disclosed report but is NOT in scope.yaml stays a lead, never a target. NVD/GHSA/Hacktivity are not the
target, so requests go direct (not through tools/leashed.sh, which gates TARGET traffic only).

HONEST DEDUP (the red line, enforced in code not just prose):
  * coverage is the honesty switch. If NO source resolves (private program, no archive, no network) =>
    coverage:"unverifiable" => EVERY verdict defaults to `could-not-verify`, NEVER `novel`.
  * A `likely-duplicate` verdict requires a REAL root-cause match with a `ref`. Absent that, the honest
    default is `could-not-verify` (which fail-opens to attacking upstream — a missed novel bug costs
    more than a wasted wave).
  * A disclosed-but-FIXED match is a VARIANT/REGRESSION seed (re-test on the current build), NOT a flat
    duplicate => verdict `could-not-verify` + a regression reason, so it RUNS NORMALLY and is handed to
    the operator/gate (never buried, never auto-promoted to novel).
  * Novelty is ORTHOGONAL to severity — this tool never touches a CVSS/tier/severity. It orders work and
    gates submittability only. The verdict vocabulary is EXACTLY `novel | likely-duplicate |
    could-not-verify` (the canonical field contract — no new value).

Deterministic + offline-honest: the network fetchers are the only non-deterministic part and are gated
(--offline / --self-test never touch the network); the parsers + the "same-fix" matcher + the coverage
switch are pure and self-tested. disclosed[] and sources_checked[] are sorted for a stable pack.

    python tools/novelty-index.py --target-dir targets/acme --from-state \
        --hacktivity-handle acme --ghsa npm:acme-sdk --changelog-url https://acme.com/releases
    python tools/novelty-index.py --target-dir targets/acme --offline          # local-only (submitted/)
    python tools/novelty-index.py --target-dir targets/acme --match hypos.json  # also emit novelty_index
    python tools/novelty-index.py --self-test                                   # offline self-check

Optional env (operator's OWN keys, read-only, NEVER stored): NVD_API_KEY, GITHUB_TOKEN lift the public
rate ceilings. Exit: 0 = pack built (any coverage, all honest); 2 = bad args / missing target-dir.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# The canonical novelty verdict vocabulary (brain/schema.md — no new value may be emitted).
NOVEL = "novel"
DUP = "likely-duplicate"
CNV = "could-not-verify"

# A modest CWE -> class map so the "same-fix" match is CLASS-AWARE (the VRT shared-vocabulary anchor),
# not a fragile endpoint string compare. Classes use the shipped attack skill slugs where one exists.
CWE_CLASS = {
    "CWE-639": "idor", "CWE-566": "idor", "CWE-284": "auth-bypass", "CWE-285": "auth-bypass",
    "CWE-862": "auth-bypass", "CWE-863": "auth-bypass", "CWE-287": "auth-bypass", "CWE-306": "auth-bypass",
    "CWE-918": "ssrf", "CWE-78": "rce", "CWE-77": "rce", "CWE-94": "rce", "CWE-502": "rce",
    "CWE-89": "sqli", "CWE-79": "xss", "CWE-611": "xxe", "CWE-601": "open-redirect",
    "CWE-22": "file-read", "CWE-98": "file-read", "CWE-352": "csrf", "CWE-434": "upload",
    "CWE-1336": "ssti", "CWE-917": "ssti", "CWE-200": "info-leak", "CWE-522": "cred-access",
}
# Coarse class keyword -> normalized class token (for disclosure titles with no CWE).
CLASS_KEYWORDS = {
    "idor": "idor", "bola": "idor", "insecure direct object": "idor",
    "ssrf": "ssrf", "server-side request": "ssrf", "rce": "rce", "remote code": "rce",
    "command injection": "rce", "deserial": "rce", "sql injection": "sqli", "sqli": "sqli",
    "cross-site scripting": "xss", "xss": "xss", "xxe": "xxe", "xml external": "xxe",
    "open redirect": "open-redirect", "path traversal": "file-read", "directory traversal": "file-read",
    "lfi": "file-read", "file read": "file-read", "authentication bypass": "auth-bypass",
    "auth bypass": "auth-bypass", "broken access control": "auth-bypass", "privilege escalation": "privesc",
    "csrf": "csrf", "cross-site request": "csrf", "file upload": "upload", "ssti": "ssti",
    "template injection": "ssti", "information disclosure": "info-leak", "subdomain takeover": "takeover",
}

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GHSA_API = "https://api.github.com/advisories"
H1_GRAPHQL = "https://hackerone.com/graphql"
UA = "spider-novelty-index/1.0 (passive-osint; prior-art dedup)"


class SourceError(Exception):
    """A disclosure source could not be resolved — recorded as a failed source (never fatal, never faked)."""


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _norm(s) -> str:
    return re.sub(r"\s+", " ", str(s or "").strip().lower())


def _norm_cwe(s) -> str:
    m = re.search(r"cwe[-_\s]*(\d+)", str(s or ""), re.I)
    return f"CWE-{m.group(1)}" if m else ""


def _class_from(cwe: str, text: str) -> str:
    """Resolve a normalized class token from a CWE first, else from title/description keywords."""
    if cwe and cwe.upper() in CWE_CLASS:
        return CWE_CLASS[cwe.upper()]
    low = _norm(text)
    for kw, cls in CLASS_KEYWORDS.items():
        if kw in low:
            return cls
    return ""


def _entry(ref, cls, cwe, host, component, root_cause, disclosed_at, fixed, fix_ref, source) -> dict:
    """One disclosed[] record in the brain/schema.md shape (every key present; unknowns are empty)."""
    return {
        "ref": ref or "", "class": cls or "", "cwe": cwe or "", "host": host or "",
        "component": component or "", "root_cause": (root_cause or "")[:400],
        "disclosed_at": disclosed_at or "", "fixed": bool(fixed), "fix_ref": fix_ref or "",
        "source": source or "",
    }


# ─────────────────────────── network (gated; the only non-deterministic part) ───────────────────────────

def _http_json(url: str, *, data: bytes | None = None, headers: dict | None = None, timeout: float = 20.0):
    """Direct (NOT leashed — this is public OSINT, not target traffic) JSON GET/POST. Raises SourceError."""
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET")
    req.add_header("User-Agent", UA)
    req.add_header("Accept", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:   # noqa: S310 (fixed public hosts only)
            raw = r.read()
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, ValueError) as e:
        raise SourceError(f"{url}: {e}") from e
    try:
        return json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as e:
        raise SourceError(f"{url}: bad JSON ({e})") from e


def fetch_nvd(keyword: str | None, cpe: str | None, timeout: float, api_key: str | None):
    params = []
    if cpe:
        params.append(("cpeName", cpe))
    if keyword:
        params.append(("keywordSearch", keyword))
    if not params:
        raise SourceError("nvd: no keyword/cpe")
    q = "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in params)
    headers = {"apiKey": api_key} if api_key else {}
    return _http_json(f"{NVD_API}?{q}", headers=headers, timeout=timeout)


def fetch_ghsa(ecosystem: str, package: str, timeout: float, token: str | None):
    q = f"ecosystem={urllib.parse.quote(ecosystem)}&affects={urllib.parse.quote(package)}&per_page=50"
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return _http_json(f"{GHSA_API}?{q}", headers=headers, timeout=timeout)


def fetch_hacktivity(handle: str, timeout: float):
    # Public, unauthenticated Hacktivity GraphQL — disclosed reports for one program handle.
    query = {
        "operationName": "HacktivityPageQuery",
        "query": (
            "query HacktivityPageQuery($q: String!) { search(index: CompleteHacktivityReportIndex, "
            "query_string: $q, first: 50) { nodes { ... on HacktivityDocument { id url title "
            "severity_rating substate disclosed_at cwe { code } team { handle } } } } }"
        ),
        "variables": {"q": f'team:"{handle}" disclosed:true'},
    }
    body = json.dumps(query).encode("utf-8")
    return _http_json(H1_GRAPHQL, data=body, headers={"Content-Type": "application/json"}, timeout=timeout)


def fetch_text(url: str, timeout: float) -> str:
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", UA)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:   # noqa: S310
            return r.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, ValueError) as e:
        raise SourceError(f"{url}: {e}") from e


# ─────────────────────────────── parsers (pure, deterministic, self-tested) ───────────────────────────────

def parse_nvd(data: dict, component_hint: str = "") -> list[dict]:
    out = []
    for v in (data or {}).get("vulnerabilities", []):
        cve = (v or {}).get("cve", {}) or {}
        cid = cve.get("id", "")
        descs = cve.get("descriptions", []) or []
        desc = next((d.get("value", "") for d in descs if d.get("lang") == "en"), "")
        cwe = ""
        for w in cve.get("weaknesses", []) or []:
            for d in w.get("description", []) or []:
                cwe = _norm_cwe(d.get("value", "")) or cwe
                if cwe:
                    break
            if cwe:
                break
        # NVD does not carry a per-program "fixed" flag; references with a patch tag are a weak signal.
        fixed = any("patch" in (t.lower() for t in (ref.get("tags") or []))
                    for ref in cve.get("references", []) or [])
        out.append(_entry(cid, _class_from(cwe, desc), cwe, "", component_hint, desc,
                          cve.get("published", "")[:10], fixed, "", "nvd"))
    return out


def parse_ghsa(data, component_hint: str = "") -> list[dict]:
    out = []
    for adv in (data or []):
        if not isinstance(adv, dict):
            continue
        ref = adv.get("ghsa_id") or adv.get("cve_id") or ""
        cwe = ""
        cwes = (adv.get("cwes") or [])
        if cwes and isinstance(cwes[0], dict):
            cwe = _norm_cwe(cwes[0].get("cwe_id", ""))
        pkg = component_hint
        for vuln in adv.get("vulnerabilities", []) or []:
            p = (vuln.get("package") or {}).get("name")
            if p:
                pkg = p
                break
        summary = adv.get("summary", "") or adv.get("description", "")
        # A GHSA with a patched_versions range => the issue is fixed upstream (regression/variant signal).
        fixed = any((vuln.get("patched_versions") for vuln in adv.get("vulnerabilities", []) or []))
        out.append(_entry(ref, _class_from(cwe, summary), cwe, "", pkg, summary,
                          (adv.get("published_at") or "")[:10], fixed, "", "ghsa"))
    return out


def parse_hacktivity(data: dict, handle: str = "") -> list[dict]:
    out = []
    nodes = (((data or {}).get("data", {}) or {}).get("search", {}) or {}).get("nodes", []) or []
    for n in nodes:
        if not isinstance(n, dict):
            continue
        rid = n.get("id", "")
        title = n.get("title", "")
        cwe = _norm_cwe((n.get("cwe") or {}).get("code", "")) if isinstance(n.get("cwe"), dict) else ""
        team = (n.get("team") or {}).get("handle", "") if isinstance(n.get("team"), dict) else handle
        substate = _norm(n.get("substate", ""))
        fixed = substate in ("resolved", "duplicate")   # resolved on H1 => patched (regression candidate)
        ref = f"h1#{rid}" if rid else (n.get("url", "") or "")
        out.append(_entry(ref, _class_from(cwe, title), cwe, "", team, title,
                          (n.get("disclosed_at") or "")[:10], fixed, "", "hacktivity"))
    return out


def parse_submitted(records: list[dict]) -> list[dict]:
    """The operator's OWN archive — most reliable. A `paid`/`resolved` record => re-test for regression."""
    out = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        fid = rec.get("finding_id") or rec.get("id") or ""
        state = _norm(rec.get("state") or rec.get("outcome") or "")
        cwe = _norm_cwe(rec.get("cwe", ""))
        cls = _norm(rec.get("class") or _class_from(cwe, rec.get("title", "")))
        fixed = state in ("paid", "resolved", "duplicate")
        ref = rec.get("dup_ref") or (f"submitted:{fid}" if fid else "")
        out.append(_entry(ref, cls, cwe, rec.get("host", ""), rec.get("component", ""),
                          rec.get("root_cause") or rec.get("title", ""),
                          rec.get("submitted_at", ""), fixed, rec.get("fix_ref", ""), "submitted-archive"))
    return out


def read_submitted_archive(target_dir: Path) -> list[dict]:
    recs = []
    d = target_dir / "submitted"
    if d.is_dir():
        for p in sorted(d.glob("*.json")):
            try:
                recs.append(json.loads(p.read_text(encoding="utf-8", errors="replace")))
            except (json.JSONDecodeError, OSError):
                continue
    return recs


def read_state_fingerprints(target_dir: Path) -> list[str]:
    p = target_dir / "state.json"
    if not p.exists():
        return []
    try:
        doc = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return []
    return [str(f) for f in (doc.get("fingerprints") or []) if f]


# ─────────────────────────────── the "same-fix" matcher + coverage switch ───────────────────────────────

def _same_fix(hypo: dict, d: dict) -> bool:
    """Intigriti "same-fix" test: would the fix for the disclosed item fix this hypothesis too? Match on
    ROOT CAUSE (cwe OR class) AND component — conservative (requires BOTH), so a weak class-only overlap
    never raises a false duplicate that buries a real finding. Never an endpoint string compare."""
    h_cwe, d_cwe = _norm_cwe(hypo.get("cwe", "")), _norm_cwe(d.get("cwe", ""))
    h_cls = _norm(hypo.get("class", "")) or _class_from(h_cwe, hypo.get("title", ""))
    d_cls = _norm(d.get("class", ""))
    class_match = bool((h_cwe and h_cwe == d_cwe) or (h_cls and d_cls and h_cls == d_cls))
    if not class_match:
        return False
    h_comp, d_comp = _norm(hypo.get("component", "")), _norm(d.get("component", ""))
    if not h_comp or not d_comp:
        return False
    return h_comp == d_comp or h_comp in d_comp or d_comp in h_comp


def match_novelty(priorart: dict, hypotheses: list[dict]) -> list[dict]:
    """Per-hypothesis novelty_index (recon-2 shape {class,component,host,verdict,ref,reason,source}).
    The coverage switch is enforced HERE: unverifiable => every verdict could-not-verify, never novel."""
    coverage = (priorart or {}).get("coverage", "unverifiable")
    disclosed = (priorart or {}).get("disclosed", []) or []
    out = []
    for h in hypotheses:
        base = {"class": h.get("class", ""), "component": h.get("component", ""), "host": h.get("host", "")}
        if coverage == "unverifiable":
            out.append({**base, "verdict": CNV, "ref": "",
                        "reason": "no disclosure source resolved (coverage unverifiable) — operator must "
                                  "confirm novelty before submit", "source": ""})
            continue
        hit = next((d for d in disclosed if _same_fix(h, d)), None)
        if hit is None:
            out.append({**base, "verdict": NOVEL, "ref": "",
                        "reason": f"no disclosed root-cause match in {coverage} prior-art "
                                  f"({len(disclosed)} indexed)", "source": ""})
        elif hit.get("fixed"):
            out.append({**base, "verdict": CNV, "ref": hit.get("ref", ""),
                        "reason": "disclosed-but-FIXED root-cause match — REGRESSION/VARIANT candidate; "
                                  "re-test on the current build (runs normally, not a flat duplicate)",
                        "source": hit.get("source", "")})
        else:
            out.append({**base, "verdict": DUP, "ref": hit.get("ref", ""),
                        "reason": f"open disclosed root-cause match ({hit.get('class') or hit.get('cwe')} "
                                  f"on {hit.get('component') or 'component'})", "source": hit.get("source", "")})
    return out


def _coverage(resolved: int, failed: int) -> str:
    if resolved == 0:
        return "unverifiable"
    return "partial" if failed else "verified"


def build_priorart(target_dir: Path, *, offline: bool, timeout: float,
                   nvd_keywords: list[str], nvd_cpes: list[str], ghsa: list[str],
                   hacktivity_handle: str | None, changelog_urls: list[str], disclosure_urls: list[str],
                   use_submitted: bool, nvd_key: str | None, gh_token: str | None,
                   log=lambda *_: None) -> dict:
    """Try each requested source; on success index + mark checked, on failure mark it failed (never faked).
    Returns the priorart.json dict (coverage honestly derived from how many sources actually resolved)."""
    disclosed: list[dict] = []
    checked: list[str] = []
    failed: list[str] = []

    # 1. Operator submission archive — LOCAL, always offline-safe, most reliable for a private program.
    if use_submitted:
        recs = read_submitted_archive(target_dir)
        if recs or (target_dir / "submitted").is_dir():
            disclosed.extend(parse_submitted(recs))
            checked.append("submitted-archive")
            log(f"submitted-archive: {len(recs)} record(s)")

    def _net(label, fn):
        if offline:
            failed.append(f"{label}:offline")
            return
        try:
            n = fn()
            disclosed.extend(n)
            checked.append(label)
            log(f"{label}: {len(n)} disclosed")
        except SourceError as e:
            failed.append(label)
            log(f"{label}: unreachable ({e})")

    for kw in nvd_keywords:
        _net(f"nvd:kw:{kw}", lambda kw=kw: parse_nvd(fetch_nvd(kw, None, timeout, nvd_key), kw))
    for cpe in nvd_cpes:
        _net(f"nvd:cpe:{cpe}", lambda cpe=cpe: parse_nvd(fetch_nvd(None, cpe, timeout, nvd_key), cpe))
    for spec in ghsa:
        eco, _, pkg = spec.partition(":")
        if eco and pkg:
            _net(f"ghsa:{eco}/{pkg}",
                 lambda eco=eco, pkg=pkg: parse_ghsa(fetch_ghsa(eco, pkg, timeout, gh_token), pkg))
    if hacktivity_handle:
        _net(f"hacktivity:{hacktivity_handle}",
             lambda: parse_hacktivity(fetch_hacktivity(hacktivity_handle, timeout), hacktivity_handle))
    for url in changelog_urls:
        _net(f"changelog:{url}", lambda url=url: _parse_changelog(fetch_text(url, timeout), url))
    for url in disclosure_urls:
        # Non-H1 disclosure index: best-effort text fetch recorded as checked; structured extraction is
        # left to the agent (heuristic) — we honestly index only what we can parse, never invent matches.
        _net(f"disclosure:{url}", lambda url=url: _parse_changelog(fetch_text(url, timeout), url))

    disclosed.sort(key=lambda d: (d.get("source", ""), d.get("ref", ""), d.get("component", "")))
    return {
        "coverage": _coverage(len(checked), len(failed)),
        "sources_checked": sorted(set(checked)),
        "sources_failed": sorted(set(failed)),
        "disclosed": disclosed,
        "checked_ts": _now_iso(),
        "note": "PASSIVE OSINT prior-art index (public disclosure indices + local files) — no target "
                "traffic, no leash. coverage:unverifiable => every downstream verdict is could-not-verify, "
                "never novel. A disclosed-but-fixed item is a regression/variant seed, not a flat duplicate.",
    }


def _parse_changelog(text: str, url: str) -> list[dict]:
    """Heuristic: a changelog is mainly a 'what is already fixed' + narrow-fix VARIANT source. We index
    only lines that NAME a CVE/GHSA (a hard ref); free-form 'fixed a bug' lines are left to the agent so
    we never fabricate a root-cause match. Each indexed line is marked fixed:true (it is a changelog)."""
    out = []
    for m in re.finditer(r"(CVE-\d{4}-\d{3,7}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})", text or "", re.I):
        ref = m.group(1).upper() if m.group(1).upper().startswith("CVE") else m.group(1)
        line = text[max(0, m.start() - 80): m.start() + 80].replace("\n", " ")
        out.append(_entry(ref, _class_from("", line), "", "", "", line, "", True, url, "changelog"))
    return out


# ──────────────────────────────────────────── self-test ────────────────────────────────────────────

def self_test() -> int:
    """Offline, deterministic end-to-end: local submitted-archive build + fixture parsers + the matcher +
    the coverage honesty switch. No network touched."""
    # ---- parsers on canned fixtures (the real API/GraphQL shapes) ----
    nvd_fix = {"vulnerabilities": [{"cve": {
        "id": "CVE-2025-1234", "published": "2025-07-01T00:00:00",
        "descriptions": [{"lang": "en", "value": "SSRF in the export API allows internal requests"}],
        "weaknesses": [{"description": [{"value": "CWE-918"}]}],
        "references": [{"url": "https://x/patch", "tags": ["Patch"]}]}}]}
    nvd = parse_nvd(nvd_fix, "acme-app")
    assert len(nvd) == 1 and nvd[0]["ref"] == "CVE-2025-1234", "nvd parse: ref"
    assert nvd[0]["cwe"] == "CWE-918" and nvd[0]["class"] == "ssrf", f"nvd parse: class {nvd[0]}"
    assert nvd[0]["fixed"] is True, "nvd parse: patch tag => fixed"

    ghsa_fix = [{"ghsa_id": "GHSA-aaaa-bbbb-cccc", "cve_id": "CVE-2024-9", "summary": "SQL injection in query",
                 "published_at": "2024-02-02T00:00:00", "cwes": [{"cwe_id": "CWE-89"}],
                 "vulnerabilities": [{"package": {"name": "acme-sdk"}, "patched_versions": ">=2.0"}]}]
    ghsa = parse_ghsa(ghsa_fix, "acme-sdk")
    assert ghsa[0]["ref"] == "GHSA-aaaa-bbbb-cccc" and ghsa[0]["class"] == "sqli", f"ghsa parse {ghsa}"
    assert ghsa[0]["component"] == "acme-sdk" and ghsa[0]["fixed"] is True, "ghsa parse: patched => fixed"

    h1_fix = {"data": {"search": {"nodes": [
        {"id": "7654321", "title": "IDOR on export endpoint", "severity_rating": "high",
         "substate": "resolved", "disclosed_at": "2025-01-05T00:00:00",
         "cwe": {"code": "CWE-639"}, "team": {"handle": "acme"}}]}}}
    h1 = parse_hacktivity(h1_fix, "acme")
    assert h1[0]["ref"] == "h1#7654321" and h1[0]["class"] == "idor", f"h1 parse {h1}"
    assert h1[0]["fixed"] is True, "h1 parse: resolved => fixed (regression candidate)"

    # ---- a local submitted-archive build (offline, deterministic, coverage:verified) ----
    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        sub = t / "submitted"
        sub.mkdir(parents=True)
        (sub / "f-0007.json").write_text(json.dumps({
            "finding_id": "f-0007", "class": "idor", "cwe": "CWE-639", "component": "export-api",
            "host": "app.acme.com", "state": "triaged", "title": "IDOR on GET /export/{id}",
            "root_cause": "missing object-level authz on export"}), encoding="utf-8")
        (sub / "f-0009.json").write_text(json.dumps({
            "finding_id": "f-0009", "class": "ssrf", "cwe": "CWE-918", "component": "webhook",
            "host": "app.acme.com", "state": "paid", "title": "SSRF via webhook url"}), encoding="utf-8")
        (t / "state.json").write_text(json.dumps({"fingerprints": ["stack:nextjs@15.2", "engine:jinja2"]}),
                                      encoding="utf-8")

        pa = build_priorart(t, offline=True, timeout=5.0, nvd_keywords=[], nvd_cpes=[], ghsa=[],
                            hacktivity_handle=None, changelog_urls=[], disclosure_urls=[],
                            use_submitted=True, nvd_key=None, gh_token=None)
        assert pa["coverage"] == "verified", f"coverage: local archive should be verified, got {pa['coverage']}"
        assert "submitted-archive" in pa["sources_checked"], "submitted-archive not marked checked"
        assert len(pa["disclosed"]) == 2, f"archive index size {len(pa['disclosed'])}"
        refs = {d["ref"] for d in pa["disclosed"]}
        assert refs == {"submitted:f-0007", "submitted:f-0009"}, f"archive refs {refs}"
        # f-0009 is 'paid' => fixed:true (regression candidate); f-0007 'triaged' => open
        by_ref = {d["ref"]: d for d in pa["disclosed"]}
        assert by_ref["submitted:f-0009"]["fixed"] is True and by_ref["submitted:f-0007"]["fixed"] is False
        for d in pa["disclosed"]:
            assert set(d) >= {"ref", "class", "cwe", "host", "component", "root_cause",
                              "disclosed_at", "fixed", "fix_ref", "source"}, f"disclosed shape {d}"

        # ---- the matcher under coverage:verified ----
        hypos = [
            {"id": "h-01", "class": "idor", "cwe": "CWE-639", "component": "export-api"},   # open dup
            {"id": "h-02", "class": "ssrf", "cwe": "CWE-918", "component": "webhook"},      # fixed => regression
            {"id": "h-03", "class": "xss", "cwe": "CWE-79", "component": "comments"},       # novel
            {"id": "h-04", "class": "idor", "cwe": "CWE-639", "component": "billing"},      # class match, diff comp => novel
        ]
        idx = {m_["class"] + "/" + m_["component"]: m_ for m_ in match_novelty(pa, hypos)}
        assert idx["idor/export-api"]["verdict"] == DUP, f"h-01 should be likely-duplicate {idx['idor/export-api']}"
        assert idx["idor/export-api"]["ref"] == "submitted:f-0007", "h-01 ref"
        assert idx["ssrf/webhook"]["verdict"] == CNV and "REGRESSION" in idx["ssrf/webhook"]["reason"].upper(), \
            f"h-02 fixed match must be could-not-verify regression {idx['ssrf/webhook']}"
        assert idx["xss/comments"]["verdict"] == NOVEL, f"h-03 should be novel {idx['xss/comments']}"
        assert idx["idor/billing"]["verdict"] == NOVEL, \
            f"h-04 class-only (diff component) must NOT be a false duplicate {idx['idor/billing']}"

        # ---- the honesty switch: no source resolves => unverifiable => every verdict could-not-verify ----
        empty = t / "empty"
        empty.mkdir()
        pa0 = build_priorart(empty, offline=True, timeout=5.0, nvd_keywords=["acme"], nvd_cpes=[], ghsa=[],
                             hacktivity_handle="acme", changelog_urls=[], disclosure_urls=[],
                             use_submitted=True, nvd_key=None, gh_token=None)
        assert pa0["coverage"] == "unverifiable", f"no source => unverifiable, got {pa0['coverage']}"
        assert pa0["disclosed"] == [], "unverifiable must index nothing"
        v = match_novelty(pa0, hypos)
        assert all(m_["verdict"] == CNV for m_ in v), "unverifiable => every verdict could-not-verify"
        assert all(m_["verdict"] != NOVEL for m_ in v), "unverifiable must NEVER yield novel"

        # ---- partial coverage: one local source resolves, one network source offline-failed ----
        pa1 = build_priorart(t, offline=True, timeout=5.0, nvd_keywords=["acme-app"], nvd_cpes=[], ghsa=[],
                             hacktivity_handle=None, changelog_urls=[], disclosure_urls=[],
                             use_submitted=True, nvd_key=None, gh_token=None)
        assert pa1["coverage"] == "partial", f"local ok + nvd offline => partial, got {pa1['coverage']}"

    # ---- changelog hard-ref extraction (never fabricates a free-form match) ----
    cl = _parse_changelog("v2.4: fixed a thing (CVE-2023-4444). v2.3: internal cleanup, fixed a bug.", "u")
    assert len(cl) == 1 and cl[0]["ref"] == "CVE-2023-4444" and cl[0]["fixed"] is True, f"changelog {cl}"

    print("novelty-index self-test: OK (parsers NVD/GHSA/H1/archive; same-fix matcher; "
          "coverage honesty switch unverifiable=>could-not-verify-never-novel; fixed=>regression; "
          "conservative component match; partial coverage; changelog hard-ref only)")
    return 0


# ──────────────────────────────────────────────── main ────────────────────────────────────────────────

def main(argv: list[str]) -> int:
    import os
    ap = argparse.ArgumentParser(
        description="Build targets/<t>/priorart.json from PASSIVE public disclosure indices + local files "
                    "(fix3 B3, bounty mode). No target traffic, no leash. Honest coverage switch.")
    ap.add_argument("--target-dir", help="targets/<t> (reads submitted/, state.json; writes priorart.json)")
    ap.add_argument("--out", default=None, help="output path (default: <target-dir>/priorart.json)")
    ap.add_argument("--offline", action="store_true",
                    help="never touch the network — local sources only (submitted/); network sources are "
                         "recorded as failed so coverage is honest")
    ap.add_argument("--from-state", action="store_true",
                    help="derive NVD keywords from state.json fingerprints[] (stack:<fw>@<ver> => <fw>)")
    ap.add_argument("--nvd-keyword", action="append", default=[], help="NVD keywordSearch (repeatable)")
    ap.add_argument("--nvd-cpe", action="append", default=[], help="NVD cpeName (repeatable)")
    ap.add_argument("--ghsa", action="append", default=[], metavar="ECOSYSTEM:PACKAGE",
                    help="GHSA ecosystem:package, e.g. npm:acme-sdk (repeatable)")
    ap.add_argument("--hacktivity-handle", default=None, help="HackerOne program handle (public Hacktivity)")
    ap.add_argument("--changelog-url", action="append", default=[], help="changelog/release-notes URL (repeatable)")
    ap.add_argument("--disclosure-url", action="append", default=[],
                    help="non-H1 disclosure index URL the operator supplies (repeatable)")
    ap.add_argument("--no-submitted-archive", action="store_true",
                    help="do NOT read targets/<t>/submitted/ as a source")
    ap.add_argument("--match", default=None,
                    help="JSON file: a list of hypotheses [{class,component,host,cwe,title}] to also tag "
                         "with a novelty_index (candidate verdicts; the synthesizer is the single writer)")
    ap.add_argument("--timeout", type=float, default=20.0, help="per-request network timeout seconds")
    ap.add_argument("--self-test", action="store_true", help="run the offline self-test and exit")
    args = ap.parse_args(argv)

    if args.self_test:
        try:
            return self_test()
        except AssertionError as e:
            print(f"novelty-index self-test: FAIL — {e}", file=sys.stderr)
            return 1

    if not args.target_dir:
        print("novelty-index: --target-dir is required (or use --self-test)", file=sys.stderr)
        return 2
    target_dir = Path(args.target_dir)
    if not target_dir.is_dir():
        print(f"novelty-index: target-dir not found: {target_dir} (fail-closed)", file=sys.stderr)
        return 2

    nvd_keywords = list(args.nvd_keyword)
    if args.from_state:
        for fp in read_state_fingerprints(target_dir):
            m = re.match(r"stack:([^@]+)", fp)
            if m:
                kw = m.group(1).strip()
                if kw and kw not in nvd_keywords:
                    nvd_keywords.append(kw)

    priorart = build_priorart(
        target_dir, offline=args.offline, timeout=args.timeout,
        nvd_keywords=nvd_keywords, nvd_cpes=list(args.nvd_cpe), ghsa=list(args.ghsa),
        hacktivity_handle=args.hacktivity_handle, changelog_urls=list(args.changelog_url),
        disclosure_urls=list(args.disclosure_url), use_submitted=not args.no_submitted_archive,
        nvd_key=os.environ.get("NVD_API_KEY"), gh_token=os.environ.get("GITHUB_TOKEN"),
        log=lambda m: print(f"[novelty-index] {m}", file=sys.stderr))

    out = Path(args.out) if args.out else target_dir / "priorart.json"
    try:
        out.write_text(json.dumps(priorart, indent=2, ensure_ascii=False), encoding="utf-8")
    except OSError as e:
        print(f"novelty-index: could not write {out}: {e}", file=sys.stderr)
        return 2

    if args.match:
        try:
            hypos = json.loads(Path(args.match).read_text(encoding="utf-8"))
            if not isinstance(hypos, list):
                raise ValueError("--match file must be a JSON list")
        except (json.JSONDecodeError, OSError, ValueError) as e:
            print(f"novelty-index: bad --match file: {e}", file=sys.stderr)
            return 2
        idx = match_novelty(priorart, hypos)
        idx_out = out.parent / "novelty-index.json"
        try:
            idx_out.write_text(json.dumps(idx, indent=2, ensure_ascii=False), encoding="utf-8")
        except OSError as e:
            print(f"novelty-index: could not write {idx_out}: {e}", file=sys.stderr)
        print(json.dumps({"novelty_index": idx}, indent=2, ensure_ascii=False))
        print(f"[novelty-index] novelty_index -> {idx_out}", file=sys.stderr)

    summary = {k: priorart[k] for k in ("coverage", "sources_checked", "sources_failed")}
    summary["disclosed_count"] = len(priorart["disclosed"])
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f"[novelty-index] priorart -> {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
