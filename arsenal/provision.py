#!/usr/bin/env python3
"""
Spider arsenal provisioner.

Self-bootstraps the pentest arsenal for whoever clones the repo: reads
arsenal/manifest.json and installs each tool into ../bin/ on Windows, Linux or
macOS. Tools are DOWNLOADED at install time from their upstream releases (never
vendored into this repo), so there is nothing to redistribute and no license to
carry — third-party notices live in THIRD-PARTY-LICENSES.md.

Stdlib only (urllib/zipfile/tarfile/subprocess) so it runs on a bare Python 3.8+.

Usage:
    python arsenal/provision.py --check              # dry run: resolve + show what WOULD download, no writes
    python arsenal/provision.py                       # install everything missing
    python arsenal/provision.py --phase recon         # only one phase (recon|attack|triage|control)
    python arsenal/provision.py --only nuclei         # a single tool
    python arsenal/provision.py --force               # reinstall even if present
    python arsenal/provision.py --json                # machine-readable result (for /doctor)

Set GITHUB_TOKEN to raise the GitHub API rate limit (unauth = 60 req/hr).
"""
from __future__ import annotations

import argparse
import io
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import urllib.error
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin"
MANIFEST = ROOT / "arsenal" / "manifest.json"
PYENV = BIN / ".pyenv"

IS_WIN = os.name == "nt"
EXE = ".exe" if IS_WIN else ""


# ---------------------------------------------------------------- platform ---
def os_key() -> str:
    s = platform.system().lower()
    if s.startswith("win"):
        return "windows"
    if s == "darwin":
        return "darwin"
    return "linux"


def arch_tokens() -> list[str]:
    return ARCH_TOKENS.get(arch_key(), [platform.machine().lower()])


def arch_key() -> str:
    m = platform.machine().lower()
    if m in ("x86_64", "amd64", "x64"):
        return "amd64"
    if m in ("arm64", "aarch64"):
        return "arm64"
    if m in ("i386", "i686", "x86"):
        return "386"
    return "amd64"


# Precise OS tokens — NOT bare "win" (it is a substring of "darwin"!).
OS_TOKENS = {
    "windows": ["windows", "win64", "win32"],
    "linux": ["linux"],
    "darwin": ["darwin", "macos", "apple", "osx"],
}
ARCH_TOKENS = {
    "amd64": ["amd64", "x86_64", "x64", "64bit", "64-bit"],
    "arm64": ["arm64", "aarch64"],
    "386": ["386", "i386", "x86", "32bit"],
}
ARCHIVE_EXT = (".zip", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".gz")


# ------------------------------------------------------------------- utils ---
def log(msg: str) -> None:
    print(f"[arsenal] {msg}", file=sys.stderr)


def gh_api(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "spider-arsenal", "Accept": "application/vnd.github+json"})
    tok = os.environ.get("GITHUB_TOKEN")
    if tok:
        req.add_header("Authorization", f"Bearer {tok}")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode("utf-8"))


def gh_latest(repo: str) -> dict:
    return gh_api(f"https://api.github.com/repos/{repo}/releases/latest")


def score_asset(name: str, ok: str, akey: str) -> int:
    n = name.lower()
    if n.endswith((".sha256", ".sig", ".pem", ".txt", ".asc")) or "checksum" in n:
        return -1
    if "installer" in n or "setup" in n or n.endswith((".msi", ".deb", ".rpm", ".pkg", ".dmg", ".apk")):
        return -1  # we want the portable binary/archive, not an OS installer
    if not any(n.endswith(e) for e in ARCHIVE_EXT) and not (IS_WIN and n.endswith(".exe")):
        return -1
    # must match the target OS...
    if not any(t in n for t in OS_TOKENS[ok]):
        return -1
    # ...and must NOT match any other OS (kills darwin/linux for a windows target)
    for other, toks in OS_TOKENS.items():
        if other != ok and any(t in n for t in toks):
            return -1
    s = 10
    if any(t in n for t in ARCH_TOKENS[akey]):
        s += 10
    else:
        # reject a clearly-wrong arch; allow single-arch builds (no arch token at all)
        for ak, toks in ARCH_TOKENS.items():
            if ak != akey and any(t in n for t in toks):
                return -1
    if "musl" in n:
        s -= 2
    return s


def pick_asset(assets: list[dict], ok: str, akey: str, overrides: dict | None = None) -> dict | None:
    # Per-OS override for upstreams whose asset names the generic scorer can't match
    # (e.g. a typo'd 'windown', an unconventional arch token). overrides = {"windows": "windown"}.
    sub = (overrides or {}).get(ok)
    if sub:
        for a in assets:
            n = a.get("name", "").lower()
            if sub.lower() in n and (any(n.endswith(e) for e in ARCHIVE_EXT) or (IS_WIN and n.endswith(".exe"))):
                return a
    best, best_s = None, 0
    for a in assets:
        s = score_asset(a.get("name", ""), ok, akey)
        if s > best_s:
            best, best_s = a, s
    return best


def human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f}{unit}"
        n /= 1024
    return f"{n:.0f}TB"


def download(url: str, dest: Path, timeout: int = 120) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "spider-arsenal"})
    with urllib.request.urlopen(req, timeout=timeout) as r, open(dest, "wb") as f:
        shutil.copyfileobj(r, f)


def extract(archive: Path, into: Path) -> None:
    into.mkdir(parents=True, exist_ok=True)
    n = archive.name.lower()
    if n.endswith(".zip"):
        with zipfile.ZipFile(archive) as z:
            z.extractall(into)
    elif n.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")):
        with tarfile.open(archive) as t:
            t.extractall(into)
    elif n.endswith(".gz"):
        import gzip
        out = into / archive.stem
        with gzip.open(archive) as g, open(out, "wb") as f:
            shutil.copyfileobj(g, f)
    else:  # a bare binary (e.g. *.exe)
        shutil.copy2(archive, into / archive.name)


def find_binary(root: Path, bin_name: str) -> Path | None:
    wanted = {bin_name.lower(), (bin_name + EXE).lower(), bin_name.lower() + ".exe"}
    for p in root.rglob("*"):
        if p.is_file() and p.name.lower() in wanted:
            return p
    # fallback: first executable-looking file
    for p in root.rglob("*"):
        if p.is_file() and (p.suffix.lower() in ("", ".exe") and bin_name.lower() in p.name.lower()):
            return p
    return None


def make_executable(p: Path) -> None:
    if not IS_WIN:
        p.chmod(p.stat().st_mode | stat.S_IEXEC | stat.S_IRGRP | stat.S_IXGRP)


def verify(bin_path: Path, version_cmd: str) -> str:
    try:
        args = [str(bin_path)] + ([version_cmd] if version_cmd else [])
        out = subprocess.run(args, capture_output=True, text=True, timeout=30)
        blob = (out.stdout + out.stderr).strip().splitlines()
        return blob[0][:120] if blob else "(ran, no version output)"
    except Exception as e:  # noqa: BLE001
        return f"(verify failed: {e})"


def present(bin_name: str) -> Path | None:
    for cand in (bin_name + EXE, bin_name, bin_name + ".cmd", bin_name + ".sh"):
        p = BIN / cand
        if p.exists():
            return p
    onpath = shutil.which(bin_name)
    return Path(onpath) if onpath else None


# --------------------------------------------------------------- installers ---
def install_github_release(tool: dict, check: bool) -> dict:
    repo = tool["repo"]
    bin_name = tool.get("bin_name", tool["name"])
    ok, akey = os_key(), arch_key()
    try:
        rel = gh_latest(repo)
    except urllib.error.HTTPError as e:
        return {"name": tool["name"], "status": "error", "detail": f"GitHub API {e.code} for {repo}"}
    except Exception as e:  # noqa: BLE001
        return {"name": tool["name"], "status": "error", "detail": str(e)}
    asset = pick_asset(rel.get("assets", []), ok, akey, tool.get("asset_overrides"))
    if not asset:
        # No prebuilt asset for this OS/arch — try a Go build if the tool declares one.
        if tool.get("go_fallback") and not check and find_go():
            res = go_install(tool["go_fallback"], bin_name, tool.get("version_cmd", ""), tool.get("rename_from"))
            if res.get("status") == "installed":
                res["name"] = tool["name"]
                res["method"] = "go-fallback"
                return res
        hint = " (go_fallback available — install Go to build it)" if tool.get("go_fallback") else ""
        return {"name": tool["name"], "status": "no-asset",
                "detail": f"no {ok}/{akey} asset in {repo} {rel.get('tag_name','?')}{hint}"}
    size = asset.get("size", 0)
    if check:
        return {"name": tool["name"], "status": "would-install", "method": "github-release",
                "tag": rel.get("tag_name"), "asset": asset["name"], "size": human(size)}
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        arc = tdp / asset["name"]
        download(asset["browser_download_url"], arc)
        exdir = tdp / "x"
        extract(arc, exdir)
        found = find_binary(exdir, bin_name)
        if not found:
            return {"name": tool["name"], "status": "no-binary", "detail": f"{bin_name} not found in asset"}
        BIN.mkdir(parents=True, exist_ok=True)
        target = BIN / (bin_name + EXE)
        shutil.copy2(found, target)
        make_executable(target)
        return {"name": tool["name"], "status": "installed", "method": "github-release",
                "tag": rel.get("tag_name"), "path": str(target), "version": verify(target, tool.get("version_cmd", ""))}


def ensure_pyenv() -> Path:
    if not PYENV.exists():
        subprocess.run([sys.executable, "-m", "venv", str(PYENV)], check=True)
    return PYENV / ("Scripts" if IS_WIN else "bin") / ("python.exe" if IS_WIN else "python")


def shim(name: str, target: Path) -> Path:
    """Write a launcher in bin/ that calls a venv/console script, so it's uniformly on PATH."""
    BIN.mkdir(parents=True, exist_ok=True)
    if IS_WIN:
        s = BIN / f"{name}.cmd"
        s.write_text(f'@echo off\r\n"{target}" %*\r\n', encoding="utf-8")
    else:
        s = BIN / name
        s.write_text(f'#!/usr/bin/env sh\nexec "{target}" "$@"\n', encoding="utf-8")
        make_executable(s)
    return s


def install_pip(tool: dict, check: bool) -> dict:
    pkg = tool.get("package", tool["repo"])
    bin_name = tool.get("bin_name", tool["name"])
    if check:
        return {"name": tool["name"], "status": "would-install", "method": "pip", "package": pkg}
    py = ensure_pyenv()
    r = subprocess.run([str(py), "-m", "pip", "install", "--upgrade", pkg], capture_output=True, text=True)
    if r.returncode != 0:
        return {"name": tool["name"], "status": "error", "detail": r.stderr.strip().splitlines()[-1:] or "pip failed"}
    scripts = PYENV / ("Scripts" if IS_WIN else "bin")
    entry = scripts / (bin_name + (".exe" if IS_WIN else ""))
    if entry.exists():
        s = shim(bin_name, entry)
        return {"name": tool["name"], "status": "installed", "method": "pip", "path": str(s),
                "version": verify(s, tool.get("version_cmd", ""))}
    return {"name": tool["name"], "status": "installed", "method": "pip",
            "detail": f"installed into {PYENV}; call as module if no console script"}


def find_go() -> str | None:
    """Locate the Go toolchain even when it isn't on THIS shell's PATH — the common case
    right after a winget/installer run, where the machine PATH has it but an already-open
    shell doesn't. Checks PATH, GOROOT, and the standard install locations per OS."""
    g = shutil.which("go")
    if g:
        return g
    cands = []
    gr = os.environ.get("GOROOT")
    if gr:
        cands.append(str(Path(gr) / "bin" / ("go.exe" if IS_WIN else "go")))
    if IS_WIN:
        cands += [r"C:\Program Files\Go\bin\go.exe", r"C:\Go\bin\go.exe"]
        la = os.environ.get("LOCALAPPDATA")
        if la:
            cands.append(str(Path(la) / "Programs" / "Go" / "bin" / "go.exe"))
    else:
        cands += ["/usr/local/go/bin/go", "/usr/lib/go/bin/go", str(Path.home() / "go" / "bin" / "go")]
    for c in cands:
        if Path(c).exists():
            return c
    return None


def go_install(module: str, bin_name: str, version_cmd: str = "", rename_from: str | None = None) -> dict:
    """go install <module>@latest into bin/. go names the output after the module's last
    path segment; copy it to bin_name when they differ (e.g. kiterunner -> kr)."""
    go = find_go()
    if not go:
        return {"status": "skipped", "detail": "go toolchain not present (install Go, then re-run — a fresh shell is not required)"}
    env = dict(os.environ, GOBIN=str(BIN))
    env["PATH"] = str(Path(go).parent) + os.pathsep + env.get("PATH", "")
    r = subprocess.run([go, "install", f"{module}@latest"], capture_output=True, text=True, env=env)
    if r.returncode != 0:
        return {"status": "error", "detail": (r.stderr or "").strip()[-200:]}
    produced = rename_from or module.rstrip("/").split("/")[-1]
    src, dst = BIN / (produced + EXE), BIN / (bin_name + EXE)
    if produced != bin_name and src.exists() and not dst.exists():
        shutil.copy2(src, dst)
    p = present(bin_name)
    return {"status": "installed", "method": "go", "path": str(p) if p else str(BIN),
            "version": verify(p, version_cmd) if p else ""}


def install_go(tool: dict, check: bool) -> dict:
    if check:
        have = find_go()
        return {"name": tool["name"], "status": "would-install" if have else "skipped",
                "method": "go", "package": tool["repo"],
                "detail": None if have else "go toolchain not present"}
    res = go_install(tool["repo"], tool.get("bin_name", tool["name"]), tool.get("version_cmd", ""), tool.get("rename_from"))
    res["name"] = tool["name"]
    return res


def install_npm(tool: dict, check: bool) -> dict:
    if not shutil.which("npm"):
        return {"name": tool["name"], "status": "skipped", "detail": "npm not present"}
    if check:
        return {"name": tool["name"], "status": "would-install", "method": "npm", "package": tool["repo"]}
    prefix = BIN / ".npm"
    prefix.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(["npm", "i", "-g", "--prefix", str(prefix), tool["repo"]], capture_output=True, text=True, shell=IS_WIN)
    if r.returncode != 0:
        return {"name": tool["name"], "status": "error", "detail": (r.stderr or "").strip()[-200:]}
    entry = (prefix / (tool.get("bin_name", tool["name"]) + (".cmd" if IS_WIN else "")))
    if entry.exists():
        return {"name": tool["name"], "status": "installed", "method": "npm", "path": str(shim(tool.get("bin_name", tool["name"]), entry))}
    return {"name": tool["name"], "status": "installed", "method": "npm", "detail": f"installed under {prefix}"}


def _interp_for(entry: Path) -> str:
    """Pick the interpreter for a git-cloned script by its extension."""
    ext = entry.suffix.lower()
    if ext == ".py":
        py = PYENV / ("Scripts" if IS_WIN else "bin") / ("python.exe" if IS_WIN else "python")
        return str(py if PYENV.exists() else Path(sys.executable))
    return {".sh": "bash", ".pl": "perl", ".rb": "ruby", ".js": "node"}.get(ext, "")


def _pyshim(name: str, entry: Path) -> Path:
    """Launcher in bin/ that runs `<interpreter> <entry>` (for git-cloned script tools)."""
    interp = _interp_for(entry)
    BIN.mkdir(parents=True, exist_ok=True)
    call = f'"{interp}" "{entry}"' if interp else f'"{entry}"'
    if IS_WIN:
        s = BIN / f"{name}.cmd"
        s.write_text(f'@echo off\r\n{call} %*\r\n', encoding="utf-8")
    else:
        s = BIN / name
        s.write_text(f'#!/usr/bin/env sh\nexec {call} "$@"\n', encoding="utf-8")
        make_executable(s)
    return s


def install_git(tool: dict, check: bool) -> dict:
    name = tool["name"]
    if not shutil.which("git"):
        return {"name": name, "status": "skipped", "detail": "git not present"}
    url = tool.get("git") or f"https://github.com/{tool['repo']}"
    if check:
        return {"name": name, "status": "would-install", "method": "git", "repo": url}
    dest = BIN / ".src" / name
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        subprocess.run(["git", "-C", str(dest), "pull", "--ff-only"], capture_output=True, text=True)
    else:
        r = subprocess.run(["git", "clone", "--depth", "1", url, str(dest)], capture_output=True, text=True)
        if r.returncode != 0:
            return {"name": name, "status": "error", "detail": (r.stderr or "").strip()[-200:]}
    req = dest / "requirements.txt"
    if req.exists():
        py = ensure_pyenv()
        subprocess.run([str(py), "-m", "pip", "install", "-r", str(req)], capture_output=True, text=True)
    entry = dest / tool.get("entry", tool.get("bin_name", name))
    if not entry.exists():
        hits = list(dest.rglob(tool.get("entry", ""))) if tool.get("entry") else []
        entry = hits[0] if hits else entry
    if entry.exists():
        s = _pyshim(name, entry)
        return {"name": name, "status": "installed", "method": "git", "path": str(s), "version": verify(s, tool.get("version_cmd", ""))}
    return {"name": name, "status": "installed", "method": "git", "detail": f"cloned to {dest}; entry not found"}


def data_dest(tool: dict) -> Path:
    return BIN / tool.get("dest", f".data/{tool['name']}")


def install_data(tool: dict, check: bool) -> dict:
    """Fetch a data asset (wordlists, nuclei fuzzing-templates, gf patterns) into bin/.
    Two shapes: a shallow git clone (`git`) or a list of direct downloads (`files`)."""
    name = tool["name"]
    dest = data_dest(tool)
    if tool.get("git"):
        url = tool["git"]
        if check:
            return {"name": name, "status": "would-install", "method": "data(git)", "repo": url, "dest": str(dest)}
        if not shutil.which("git"):
            return {"name": name, "status": "skipped", "detail": "git not present"}
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists():
            subprocess.run(["git", "-C", str(dest), "pull", "--ff-only"], capture_output=True, text=True)
        else:
            r = subprocess.run(["git", "clone", "--depth", "1", url, str(dest)], capture_output=True, text=True)
            if r.returncode != 0:
                return {"name": name, "status": "error", "detail": (r.stderr or "").strip()[-200:]}
        return {"name": name, "status": "installed", "method": "data(git)", "path": str(dest)}
    files = tool.get("files", [])
    if check:
        return {"name": name, "status": "would-install", "method": "data", "files": len(files), "dest": str(dest)}
    dest.mkdir(parents=True, exist_ok=True)
    got = 0
    for f in files:
        try:
            out = dest / f.get("as", f["url"].rsplit("/", 1)[-1])
            download(f["url"], out, timeout=f.get("timeout", 600))  # data assets can be large/slow
            if out.stat().st_size == 0:
                out.unlink(missing_ok=True)
                raise ValueError("empty download (0 bytes)")
            if f.get("extract"):
                extract(out, dest)
            got += 1
        except Exception as e:  # noqa: BLE001
            log(f"  {name}: {f.get('url')} failed: {e}")
    if files and got == 0:
        return {"name": name, "status": "error", "detail": "no files downloaded"}
    return {"name": name, "status": "installed", "method": "data", "path": str(dest), "detail": f"{got}/{len(files)} files"}


INSTALLERS = {
    "github-release": install_github_release,
    "pip": install_pip,
    "go": install_go,
    "npm": install_npm,
    "git": install_git,
    "data": install_data,
}


# -------------------------------------------------------------------- main ---
def load_manifest() -> dict:
    if not MANIFEST.exists():
        log(f"no manifest at {MANIFEST} - run the arsenal research first")
        sys.exit(2)
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Spider arsenal provisioner")
    ap.add_argument("--check", action="store_true", help="dry run: resolve + show, no download")
    ap.add_argument("--phase", help="only this phase (recon|attack|triage|control)")
    ap.add_argument("--only", help="only this tool name")
    ap.add_argument("--force", action="store_true", help="reinstall even if present")
    ap.add_argument("--optional", action="store_true", help="also install heavy/optional items (big wordlists, massdns, puredns)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    man = load_manifest()
    tools = man.get("tools", []) + man.get("data", [])
    if args.phase:
        tools = [t for t in tools if t.get("phase") == args.phase]
    if args.only:
        wanted = {s.strip() for s in args.only.split(",") if s.strip()}
        tools = [t for t in tools if t.get("name") in wanted]
    # Heavy/optional items (large wordlists, source-build deps) are skipped unless asked for
    # explicitly (--optional) or by name (--only). Keeps the default provision lean and fast.
    elif not args.optional:
        tools = [t for t in tools if not t.get("optional")]

    log(f"host: {os_key()}/{arch_tokens()[0]}  tools: {len(tools)}  bin: {BIN}")
    results = []
    for t in tools:
        name, method = t.get("name"), t.get("install_method")
        if not args.check and not args.force:
            if method == "data":
                dd = data_dest(t)
                if dd.exists() and any(p.is_file() and p.stat().st_size > 0 for p in dd.rglob("*")):
                    results.append({"name": name, "status": "present", "path": str(dd)})
                    if not args.json:
                        log(f"  {name}: already present ({dd})")
                    continue
            else:
                p = present(t.get("bin_name", name))
                if p:
                    results.append({"name": name, "status": "present", "path": str(p)})
                    if not args.json:
                        log(f"  {name}: already present ({p})")
                    continue
        fn = INSTALLERS.get(method)
        if not fn:
            results.append({"name": name, "status": "manual", "detail": f"install_method={method}"})
            if not args.json:
                log(f"  {name}: manual ({method})")
            continue
        res = fn(t, args.check)
        results.append(res)
        if not args.json:
            extra = res.get("version") or res.get("asset") or res.get("detail") or res.get("path") or ""
            log(f"  {name}: {res['status']}  {extra}")

    if args.json:
        print(json.dumps({"host": f"{os_key()}/{arch_tokens()[0]}", "results": results}, indent=2))
    else:
        ok = sum(1 for r in results if r["status"] in ("installed", "present", "would-install"))
        log(f"done: {ok}/{len(results)} ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
