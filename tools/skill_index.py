#!/usr/bin/env python3
"""
Regenerate .claude/skills/index.json from every SKILL.md's frontmatter.
Run after adding or editing a skill:

    python tools/skill_index.py

Portable (resolves paths relative to the repo root); stdlib only.
"""
from __future__ import annotations

import json
import re
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
SKILLS = ROOT / ".claude" / "skills"


def frontmatter(text: str) -> str:
    m = re.search(r"^---\s*(.*?)\s*---", text, re.S | re.M)
    return m.group(1) if m else ""


def scalar(fm: str, key: str):
    m = re.search(rf"^{key}:\s*(.+)$", fm, re.M)
    return m.group(1).strip().strip('"') if m else None


def listval(fm: str, key: str):
    m = re.search(rf"^{key}:\s*\[(.*?)\]", fm, re.M)
    if not m:
        return []
    return [x.strip().strip('"').strip("'") for x in m.group(1).split(",") if x.strip()]


def main() -> int:
    skills = []
    for p in sorted(SKILLS.rglob("SKILL.md")):
        if "_template" in p.parts:
            continue
        fm = frontmatter(p.read_text(encoding="utf-8", errors="replace"))
        rel = p.relative_to(SKILLS).as_posix()
        cat = rel.split("/")[0]
        e = {"name": scalar(fm, "name") or p.parent.name, "path": rel, "category": cat}
        if cat == "attack":
            e["class"] = p.parent.name
        if listval(fm, "cwe_ids"):
            e["cwe_ids"] = listval(fm, "cwe_ids")
        if listval(fm, "tags"):
            e["tags"] = listval(fm, "tags")
        skills.append(e)
    out = {
        "version": 1,
        "note": "Skill router. The brain reads this to pick methodology by class/tags and passes the paths to workflow agents (agents Read them). Regenerate with: python tools/skill_index.py",
        "skills": skills,
    }
    (SKILLS / "index.json").write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8", newline="\n")
    by = {}
    for s in skills:
        by[s["category"]] = by.get(s["category"], 0) + 1
    print(f"indexed {len(skills)} skills: " + ", ".join(f"{v} {k}" for k, v in sorted(by.items())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
