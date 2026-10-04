"""What can actually run right now: local services, CLIs, and sign-ins. Local checks only.

HTTP checks go to loopback /health endpoints; nothing calls a paid or remote API. Auth checks look at whether a
sign-in exists on disk (file present; optionally a key or field present). They never return or log the values,
and can't tell whether a token has been revoked server-side.

Config: router.json "availability" (checks + ttl_s); models and executors list what they need in "needs".
"""
import json
import shutil
import threading
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from . import config

_cache, _lock = {}, threading.Lock()


def _http(c):
    if urlsplit(c["url"]).hostname not in ("127.0.0.1", "localhost", "::1"):
        return False, "refused: availability checks only call loopback addresses"
    try:
        with urllib.request.urlopen(c["url"], timeout=c.get("timeout_s", 2)) as r:
            body = json.load(r)
    except Exception as e:
        return False, f"down: {c['url']} ({type(e).__name__})"
    if body.get("status") != "ok":
        return False, f"unhealthy: {c['url']} status {body.get('status')!r}"
    return True, "up" + (" (busy)" if body.get("busy") else "")


def _auth(c):
    if c.get("bin") and not shutil.which(c["bin"]):
        return False, f"{c['bin']} not on PATH"
    p = Path(c["file"]).expanduser()
    try:
        if not p.is_file() or p.stat().st_size == 0:
            return False, f"not signed in ({c['file']} missing or empty)"
        if not (c.get("key") or c.get("field")):
            return True, "signed in"
        d = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False, f"unreadable sign-in file ({c['file']})"
    if not isinstance(d, dict):
        return False, f"unexpected sign-in file format ({c['file']})"
    if c.get("key") and c["key"] not in d:
        return False, f"no {c['key']} credentials in {c['file']}"
    if c.get("field") and not any(isinstance(v, dict) and v.get(c["field"]) for v in d.values()):
        return False, f"not signed in (no {c['field']} in {c['file']})"
    return True, "signed in"


def _bin(c):
    return (True, "installed") if shutil.which(c["bin"]) else (False, f"{c['bin']} not on PATH")


CHECKS = {"http": _http, "auth": _auth, "bin": _bin}


def check(m=None, force=False):
    """{name: {"up": bool, "why": str}} for every configured check, cached for ttl_s."""
    m = m or config.load("router.json")
    av = m.get("availability", {})
    now = time.monotonic()
    key = json.dumps(av, sort_keys=True)
    with _lock:
        hit = _cache.get(key)
        if hit and not force and now - hit[0] < av.get("ttl_s", 15):
            return hit[1]
    out = {}
    for name, c in av.get("checks", {}).items():
        fn = CHECKS.get(c.get("kind"))
        up, why = fn(c) if fn else (False, f"unknown check kind {c.get('kind')!r}")
        out[name] = {"up": up, "why": why, "label": c.get("label", name)}
    with _lock:
        _cache[key] = (now, out)
    return out


def needs(m, executor):
    """What an executor depends on: its model's needs plus the harness's own."""
    return list(dict.fromkeys(m["models"][executor["model"]].get("needs", []) + executor.get("needs", [])))


def missing(m, executor, status):
    """Human-readable reasons the executor can't run now ([] = available). Unknown checks count as available."""
    return [f"{status[n]['label']}: {status[n]['why']}" for n in needs(m, executor) if n in status and not status[n]["up"]]
