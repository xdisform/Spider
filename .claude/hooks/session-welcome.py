#!/usr/bin/env python3
"""Spider first-launch greeting (SessionStart hook).

Shows the welcome exactly ONCE per device: on the first new session it prints the
language prompt and tells the assistant to run the two-step welcome flow, then drops
a marker in the user's home directory. Every later session finds the marker and stays
silent. A fresh clone on a NEW device has no marker, so the greeting shows again there.

Wired from .claude/settings.json as a SessionStart (matcher: startup) hook.
The marker lives OUTSIDE the repo (never committed), so it is per-device.
"""
import json
import os
import pathlib
import sys

MARKER = pathlib.Path(os.path.expanduser("~")) / ".spider" / "welcomed"

LANG_PROMPT = (
    "🕷️  Spider\n\n"
    "  Выберите язык  /  Choose your language\n\n"
    "    1 — Русский\n"
    "    2 — English\n\n"
    "  (ответьте 1 или 2  /  reply 1 or 2)"
)

DIRECTIVE = (
    "[Spider first-launch greeting — first session on this device; show only once]\n"
    "The operator has just been shown the language choice above "
    "(1 = Русский, 2 = English). When they reply 1 or 2, present the matching welcome "
    "section from WELCOME.md (ЧАСТЬ 2: «1 — Русский», or «If \"2 — English\"») verbatim, "
    "then continue normally. Do not repeat this greeting in later turns or sessions."
)


def already_shown():
    try:
        return MARKER.exists()
    except Exception:
        return False


def mark():
    try:
        MARKER.parent.mkdir(parents=True, exist_ok=True)
        MARKER.write_text("shown\n", encoding="utf-8")
    except Exception:
        pass  # if home is not writable the greeting may show again; better than never


def main():
    if already_shown():
        return  # silent on every later session on this device
    mark()
    out = {
        "systemMessage": LANG_PROMPT,
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": DIRECTIVE,
        },
    }
    # ensure_ascii keeps stdout pure ASCII (safe on any console codepage); the hook
    # runner parses the JSON and restores the Unicode.
    sys.stdout.write(json.dumps(out))


if __name__ == "__main__":
    main()
