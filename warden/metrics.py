"""Prometheus metrics, built by tailing the events log (telemetry.py) plus a live health check.

Every process that uses warden appends to one events file, so counting there covers the Hermes plugin, the CLI
and the test bed alike. Counters start from the current file when the exporter starts and stay monotonic while it
runs (a rotation is followed, not double-counted). Prometheus treats an exporter restart as a counter reset.

Labels stay low-cardinality: op, source, boundary, outcome, category. Never text, ids of findings, or errors.
"""
import json
import os
import threading
import time
from collections import defaultdict

from . import __version__, health, telemetry

BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30)
HELP = {
    "warden_build_info": ("gauge", "warden version"),
    "warden_up": ("gauge", "1 if warden can answer (health status ok or degraded)"),
    "warden_health_status": ("gauge", "1 for the current overall health status"),
    "warden_health_check": ("gauge", "1 if this health check passes"),
    "warden_health_check_seconds": ("gauge", "how long this health check took"),
    "warden_calls_total": ("counter", "guard/decide/classify/escalate calls, by outcome"),
    "warden_cached_total": ("counter", "guard calls answered from the in-process cache"),
    "warden_degraded_total": ("counter", "calls answered without lev (rules only or incomplete)"),
    "warden_errors_total": ("counter", "calls that recorded an error"),
    "warden_categories_total": ("counter", "guard calls flagged with a category (medium or worse)"),
    "warden_lev_calls_total": ("counter", "lev decision-model calls"),
    "warden_lev_seconds_total": ("counter", "time spent waiting on lev"),
    "warden_lev_tokens_total": ("counter", "input tokens sent to lev"),
    "warden_lev_down_total": ("counter", "times the lev circuit breaker tripped"),
    "warden_call_duration_seconds": ("histogram", "end-to-end call duration"),
    "warden_events_total": ("counter", "events read from the events log"),
    "warden_events_invalid_total": ("counter", "unparseable lines in the events log"),
    "warden_last_event_timestamp_seconds": ("gauge", "file mtime of the events log"),
    "warden_events_log_bytes": ("gauge", "size of the current events log"),
}


def outcome(ev):
    op = ev.get("op")
    if op == "guard":
        return ev.get("action") or "unknown"
    if op == "decide":
        return "complete" if ev.get("complete") else "incomplete"
    if op == "classify":
        return "stopped" if ev.get("stopped") else "error" if ev.get("error") else (ev.get("workflow") or "unknown")
    if op == "escalate":
        return "error" if ev.get("error") else "escalate" if ev.get("escalate") else "stay_local"
    return "unknown"


class Collector:
    def __init__(self, path=None):
        self.path = path
        self.lock = threading.Lock()
        self.c = defaultdict(float)                  # (name, labels tuple) -> value
        self.h = {}                                  # labels -> [bucket counts..., sum, count]
        self.inode, self.pos, self.partial = None, 0, b""
        self.health, self.health_at = None, 0.0

    def _path(self):
        return self.path or telemetry.path()

    def add(self, ev):
        op = ev.get("op")
        self.c[("warden_events_total", ())] += 1
        if op == "lev_down":
            self.c[("warden_lev_down_total", (("source", ev.get("source", "")),))] += 1
            return
        if op not in ("guard", "decide", "classify", "escalate"):
            return
        base = (("op", op), ("source", str(ev.get("source", ""))), ("boundary", str(ev.get("boundary") or "")))
        self.c[("warden_calls_total", base + (("outcome", outcome(ev)),))] += 1
        if ev.get("cached"):
            self.c[("warden_cached_total", base)] += 1
        if ev.get("degraded"):
            self.c[("warden_degraded_total", base)] += 1
        if ev.get("error"):
            self.c[("warden_errors_total", base)] += 1
        for cat in ev.get("categories") or []:
            self.c[("warden_categories_total", base[:1] + base[2:] + (("category", str(cat)),))] += 1
        lev = ev.get("lev") or {}
        opl = (("op", op),)
        self.c[("warden_lev_calls_total", opl)] += lev.get("calls", 0) or 0
        self.c[("warden_lev_seconds_total", opl)] += (lev.get("ms", 0) or 0) / 1000
        self.c[("warden_lev_tokens_total", opl)] += lev.get("tokens", 0) or 0
        if isinstance(ev.get("ms"), (int, float)):
            key = (("op", op), ("boundary", str(ev.get("boundary") or "")))
            h = self.h.setdefault(key, [0] * (len(BUCKETS) + 2))
            s = ev["ms"] / 1000
            for i, b in enumerate(BUCKETS):
                if s <= b:
                    h[i] += 1
            h[-2] += s
            h[-1] += 1

    def poll(self):
        """Read whatever was appended since the last poll; follow rotation."""
        p = self._path()
        try:
            st = os.stat(p)
        except FileNotFoundError:
            return
        with self.lock:
            if self.inode is not None and (st.st_ino != self.inode or st.st_size < self.pos):
                self.pos, self.partial = 0, b""      # rotated or truncated: the new file starts from zero
            self.inode = st.st_ino
            with open(p, "rb") as f:
                f.seek(self.pos)
                data = f.read()
                self.pos = f.tell()
            lines = (self.partial + data).split(b"\n")
            self.partial = lines.pop()               # an unfinished last line waits for the next poll
            for line in lines:
                if not line.strip():
                    continue
                try:
                    ev = json.loads(line)
                except ValueError:
                    self.c[("warden_events_invalid_total", ())] += 1
                    continue
                if isinstance(ev, dict):
                    self.add(ev)

    def check_health(self, ttl=10.0):
        if self.health is None or time.monotonic() - self.health_at > ttl:
            self.health, self.health_at = health.check(), time.monotonic()
        return self.health

    def render(self):
        self.poll()
        hc = self.check_health()
        g = defaultdict(float)
        g[("warden_build_info", (("version", __version__),))] = 1
        g[("warden_up", ())] = 1 if hc["status"] != "down" else 0
        for s in ("ok", "degraded", "down"):
            g[("warden_health_status", (("status", s),))] = 1 if hc["status"] == s else 0
        for name, c in hc["checks"].items():
            g[("warden_health_check", (("check", name),))] = 1 if c["ok"] else 0
            g[("warden_health_check_seconds", (("check", name),))] = c["ms"] / 1000
        try:
            st = os.stat(self._path())
            g[("warden_last_event_timestamp_seconds", ())] = st.st_mtime
            g[("warden_events_log_bytes", ())] = st.st_size
        except FileNotFoundError:
            pass
        with self.lock:
            series = {**g, **self.c}
            hists = {k: list(v) for k, v in self.h.items()}
        for name in ("warden_events_total", "warden_events_invalid_total"):
            series.setdefault((name, ()), 0)
        out, by_name = [], defaultdict(list)
        for (name, labels), v in series.items():
            by_name[name].append((labels, v))
        for name, (kind, text) in HELP.items():
            if name == "warden_call_duration_seconds":
                if not hists:
                    continue
                out += [f"# HELP {name} {text}", f"# TYPE {name} histogram"]
                for labels, h in sorted(hists.items()):
                    for i, b in enumerate(BUCKETS):
                        out.append(f"{name}_bucket{_fmt(labels + (('le', repr(float(b))),))} {h[i]}")
                    out.append(f"{name}_bucket{_fmt(labels + (('le', '+Inf'),))} {h[-1]}")
                    out.append(f"{name}_sum{_fmt(labels)} {h[-2]:.6f}")
                    out.append(f"{name}_count{_fmt(labels)} {h[-1]}")
                continue
            if name not in by_name:
                continue
            out += [f"# HELP {name} {text}", f"# TYPE {name} {kind}"]
            for labels, v in sorted(by_name[name]):
                out.append(f"{name}{_fmt(labels)} {_num(v)}")
        return "\n".join(out) + "\n"


def _esc(v):
    return str(v).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _fmt(labels):
    return "{" + ",".join(f'{k}="{_esc(v)}"' for k, v in labels) + "}" if labels else ""


def _num(v):
    return str(int(v)) if float(v).is_integer() else f"{v:.6f}"
