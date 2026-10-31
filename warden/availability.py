"""What can actually run right now: local services, CLIs, and sign-ins. Local checks only.

HTTP checks go to loopback /health endpoints; nothing calls a paid or remote API. Auth checks look at whether a
sign-in exists on disk (file present; optionally a key or field present) and, with "expires", whether it has
expired. They never return or log token values, and can't tell whether a token was revoked server-side.

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
    if c.get("expires"):
        when = _expiry(d, c["expires"])
        if when is None:
            return False, f"can't tell when the sign-in expires (no {c['expires']} in {c['file']})"
        left = when - time.time()
        if left > 0:
            return True, f"signed in (expires in {_ago(left)})"
        grace = c.get("stale_after_s")         # access tokens that the CLI refreshes on its own
        if grace is not None and -left < grace:
            return True, f"signed in (token refreshes on next use; last refreshed {_ago(-left)} ago)"
        return False, f"sign-in likely lapsed: last refreshed {_ago(-left)} ago (sign in again)"
    return True, "signed in"


def _expiry(d, key):
    """Epoch seconds from `key` anywhere in the sign-in file (top level or one level down). Accepts epoch seconds,
    epoch milliseconds, or an ISO-8601 time. Only the timestamp is read; tokens are never touched."""
    import datetime
    vals = [d.get(key)] + [v.get(key) for v in d.values() if isinstance(v, dict)]
    for v in vals:
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            return v / 1000 if v > 1e11 else float(v)
        if isinstance(v, str):
            try:
                return datetime.datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()
            except ValueError:
                continue
    return None


def _ago(secs):
    secs = int(secs)
    for unit, n in (("d", 86400), ("h", 3600), ("min", 60)):
        if secs >= n:
            return f"{secs // n} {unit}"
    return f"{secs} s"


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
