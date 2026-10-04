"""Labelled examples from the test bed ("was this verdict right?"), stored locally as JSONL.

The text is stored (that's what makes it usable as an eval case); the file is created 0600 in a 0700
directory and never leaves this machine. Delete it any time.
"""
import json
import os
import time
from pathlib import Path

from . import __version__, config


def path():
    return Path(config.load("guard.json")["feedback_path"]).expanduser()


def append(boundary, text, got, expected, score=None, finding_ids=(), note=""):
    if expected not in ("allow", "review", "block"):
        raise ValueError("expected must be allow, review or block")
    p = path()
    p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "warden": __version__, "boundary": boundary, "text": text,
           "got": got, "expected": expected, "correct": got == expected, "score": score,
           "findings": list(finding_ids), "note": note[:500]}
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")       # ASCII escapes: lone surrogates and U+2028 survive the round trip
    return rec


def load():
    p = path()
    if not p.is_file():
        return []
    return [json.loads(l) for l in p.read_text(encoding="utf-8").split("\n") if l.strip()]  # not splitlines(): U+2028 etc. live inside JSON strings


def stats():
    rows = load()
    return {"path": str(path()), "total": len(rows), "correct": sum(r["correct"] for r in rows),
            "by_boundary": {b: sum(r["boundary"] == b for r in rows) for b in ("prompt", "content", "outbound")}}
