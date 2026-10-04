"""Labelled eval sets you build in the test bed (routing, escalation), stored locally as JSONL.

Append-only: re-labelling an item appends a new record and the latest one wins. Files are created 0600 in a
0700 directory next to the guard feedback file and never leave this machine. Delete them any time.

  routing     label = {"workflow": <router.json agent id> | null, "tier": local | frontier | blocked}
  escalation  label = {"escalate": true | false}
"""
import hashlib
import json
import os
import time
from pathlib import Path

from . import __version__, config

EVALS = Path(__file__).resolve().parent.parent / "evals"
TIERS = ("local", "frontier", "blocked")
KINDS = ("routing", "escalation")


def path(kind):
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {KINDS}")
    return Path(config.load("guard.json")["feedback_path"]).expanduser().parent / f"labels-{kind}.jsonl"


def seeds(kind):
    """The repo's seed items for a kind (evals/<kind>/seed.jsonl); [] in an installed copy without evals/."""
    p = EVALS / kind / "seed.jsonl"
    if kind not in KINDS or not p.is_file():
        return []
    return [json.loads(l) for l in p.read_text(encoding="utf-8").split("\n") if l.strip()]


def text_id(text):
    """Stable id for an item labelled from free text (not from a seed file)."""
    return "live-" + hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:12]


def split_of(item_id):
    """Deterministic 50/50 tune/test split for items without one (live labels)."""
    return "tune" if int(hashlib.sha256(item_id.encode()).hexdigest(), 16) % 2 == 0 else "test"


def validate(kind, label, m=None):
    if not isinstance(label, dict):
        raise ValueError("label must be an object")
    if kind == "routing":
        tier, wf = label.get("tier"), label.get("workflow")
        if tier not in TIERS:
            raise ValueError(f"tier must be one of {TIERS}")
        workflows = (m or config.load("router.json"))["agents"]
        if tier == "blocked":
            wf = None
        elif wf not in workflows:
            raise ValueError(f"workflow must be one of {tuple(workflows)}")
        return {"workflow": wf, "tier": tier, "unsure": bool(label.get("unsure"))}
    if kind == "escalation":
        if not isinstance(label.get("escalate"), bool):
            raise ValueError("escalate must be true or false")
        return {"escalate": label["escalate"], "unsure": bool(label.get("unsure"))}
    raise ValueError(f"kind must be one of {KINDS}")


def append(kind, item_id, text, label, source="seed", pred=None, note=""):
    if not isinstance(item_id, str) or not item_id or len(item_id) > 64:
        raise ValueError("id is required (max 64 chars)")
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "warden": __version__, "kind": kind, "id": item_id,
           "source": source, "text": text, "label": validate(kind, label), "pred": pred, "note": str(note)[:500]}
    p = path(kind)
    p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")       # ASCII escapes, as in feedback.jsonl
    return rec


def latest(kind):
    """{id: latest record}."""
    p = path(kind)
    if not p.is_file():
        return {}
    out = {}
    for line in p.read_text(encoding="utf-8").split("\n"):
        if line.strip():
            r = json.loads(line)
            out[r["id"]] = r
    return out
