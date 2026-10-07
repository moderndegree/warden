"""Operational events: one JSON line per guard / decide / classify / escalate call, for log shippers and metrics.

    ~/.local/state/warden/events.jsonl      (guard.json "telemetry"; 0600, rotated by size)

Events carry outcomes and costs only: verdict, action, categories, finding ids, scores, lev calls and latency,
sizes. Never the text under inspection, the decide question or items, or the task. Every process that uses
warden (Hermes plugin, CLI, test bed) appends to the same file, so one tailer or `warden exporter` sees it all.

Each event also goes to the `warden` logger (INFO; WARNING when lev is down or a call fails). The library adds
only a NullHandler, so a host app decides whether that shows up anywhere.

Off switches: WARDEN_TELEMETRY=0 (tests and evals set it), or "telemetry": {"enabled": false}.
WARDEN_EVENTS_PATH overrides the path. WARDEN_SOURCE names the caller (default: the program name).
"""
import json
import logging
import os
import sys
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from . import __version__, config

log = logging.getLogger("warden")
DEFAULTS = {"enabled": True, "events_path": "~/.local/state/warden/events.jsonl", "max_bytes": 10 * 1024 * 1024,
            "keep": 3}
_lock = threading.Lock()
_source = None
_local = threading.local()


def settings():
    try:
        t = {**DEFAULTS, **config.load("guard.json").get("telemetry", {})}
    except (OSError, ValueError):
        t = dict(DEFAULTS)
    if os.environ.get("WARDEN_EVENTS_PATH"):
        t["events_path"] = os.environ["WARDEN_EVENTS_PATH"]
    if os.environ.get("WARDEN_TELEMETRY", "").lower() in ("0", "false", "off", "no"):
        t["enabled"] = False
    return t


def path():
    return Path(settings()["events_path"]).expanduser()


def set_source(name):
    """Label this process's events (e.g. "cli", "testbed", "hermes")."""
    global _source
    _source = name


def source():
    if _source or os.environ.get("WARDEN_SOURCE"):
        return _source or os.environ["WARDEN_SOURCE"]
    name = Path(sys.argv[0]).stem if sys.argv and sys.argv[0] not in ("", "-c", "-m") else ""
    return name if name and not name.startswith("-") else "python"


def _rotate(p, keep):
    for i in range(keep - 1, 0, -1):
        older = p.with_name(f"{p.name}.{i}")
        if older.exists():
            os.replace(older, p.with_name(f"{p.name}.{i + 1}"))
    os.replace(p, p.with_name(f"{p.name}.1"))


@contextmanager
def suppressed():
    """Don't record events from this thread inside the block (health self-tests)."""
    prev = getattr(_local, "off", False)
    _local.off = True
    try:
        yield
    finally:
        _local.off = prev


def record(op, level=logging.INFO, **fields):
    """Append one event. Never raises: telemetry must not break a scan."""
    if getattr(_local, "off", False):
        return None
    try:
        t = settings()
        ev = {"ts": datetime.now().astimezone().isoformat(timespec="milliseconds"), "op": op, "source": source(), "pid": os.getpid(), "warden": __version__,
              "level": logging.getLevelName(level).lower(), **fields}
        line = json.dumps(ev, default=str)        # ASCII escapes: one event is always one line
        log.log(level, "%s", line)
        if not t["enabled"]:
            return ev
        p = Path(t["events_path"]).expanduser()
        with _lock:
            p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            try:
                if p.stat().st_size >= t["max_bytes"]:
                    _rotate(p, max(1, t["keep"]))
            except FileNotFoundError:
                pass
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        return ev
    except Exception as e:                        # noqa: BLE001 - a full disk or bad config must not stop a scan
        log.warning("warden: could not record %s event: %s", op, e)
        return None


def guard_event(res, chars, ms=None):
    lvl = logging.WARNING if res.get("degraded") else logging.INFO
    return record("guard", lvl, boundary=res["boundary"], verdict=res["verdict"], action=res["action"],
                  stopped_at=res.get("stopped_at"), categories=res.get("categories", []),
                  findings=[f["id"] for f in res.get("findings", [])], score=res.get("score"),
                  rules_verdict=res.get("rules_verdict"), secrets=res.get("secrets"), pii=res.get("pii"),
                  redactions=sum((res.get("redactions") or {}).values()), hidden_text=bool(res.get("hidden_text")),
                  chars=chars, chunks=len(res.get("chunks") or []), degraded=res.get("degraded", False),
                  error=res.get("error"), cached=res.get("cached", False),
                  lev={"calls": 0, "ms": 0, "tokens": 0} if res.get("cached") else res.get("lev"), ms=res.get("ms") if ms is None else ms)
