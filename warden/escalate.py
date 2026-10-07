"""Escalation check: given a task and a short summary of what a local agent tried, should it hand off to a
frontier model now?

    escalate("Fix the failing test in auth.py", "Edited auth.py 3 times, same AssertionError each run.")

One lev call (yes/no). Cheap rule signals in the summary then adjust it: clear success keeps the task local, and
"needs a person" (permissions, no network, waiting on the user) keeps it local because a bigger model can't help.
Config: router.json "escalation".
"""
import logging
import re
import time

from . import config, rules, telemetry
from .lev import Lev, DecisionError, frame


def _signals(tried, cfg):
    found = {}
    for name, pats in cfg["signals"].items():
        hits = [m.group(0) for p in pats for m in [re.search(p, tried, re.I)] if m]
        if hits:
            found[name] = hits[:3]
    return found


def state(task, tried, cfg):
    view = lambda s: rules.redact(rules.normalize(s))["text"]
    body = f"TASK:\n{view(task)}\n\nWHAT THE LOCAL AGENT TRIED:\n{view(tried)}"
    return frame(body, cfg["state_chars"], "escalation")


def decide(p, signals, cfg):
    """Policy over the lev score and the rule signals → (escalate, reasons)."""
    if "needs_person" in signals:
        return False, ["Blocked on something a bigger model can't fix (" + ", ".join(signals["needs_person"]) + "): ask the user."]
    if "done" in signals and "stuck" not in signals:
        return False, ["The summary reports success (" + ", ".join(signals["done"]) + ")."]
    if p is None:
        return False, ["Decision model unavailable; no lev score."]
    if p >= cfg["threshold"]:
        return True, [f"lev: hand off (p={p:.2f} ≥ {cfg['threshold']})"]
    return False, [f"lev: keep going locally (p={p:.2f} < {cfg['threshold']})"]


def escalate(task, tried, m=None, gcfg=None, lev=None):
    if not (task or "").strip() or not (tried or "").strip():
        raise ValueError("task and tried are both required")
    m = m or config.load("router.json")
    gcfg = gcfg or config.load("guard.json")
    cfg = m["escalation"]
    lev = lev or Lev(gcfg["decision_model"])
    t0 = time.monotonic()
    signals = _signals(rules.normalize(tried), cfg)
    p, error, st = None, None, {"calls": 0, "ms": 0, "tokens": 0}
    if not ("needs_person" in signals or ("done" in signals and "stuck" not in signals)):   # no call if rules decide
        try:
            a, ms, usage = lev.ask(state(task, tried, cfg), {"q": {"type": "noul", "instructions": cfg["question"]}})
            p = round(a["q"]["noul"], 4)
            st = {"calls": 1, "ms": ms, "tokens": usage.get("input_tokens", 0)}
        except DecisionError as e:
            error = str(e)
    esc, reasons = decide(p, signals, cfg)
    res = {"escalate": esc, "p": p, "signals": signals, "reasons": reasons, "error": error, "lev": st,
           "ms": round((time.monotonic() - t0) * 1000, 1)}
    telemetry.record("escalate", logging.WARNING if error else logging.INFO, escalate=esc, p=p,
                     signals=sorted(signals), degraded=error is not None, error=error, lev=st, ms=res["ms"])
    return res


def brief(r):
    p = f" p={r['p']:.2f}" if r["p"] is not None else ""
    return f"{'escalate' if r['escalate'] else 'stay local'}{p} · {r['reasons'][0]}" + (f" ERROR: {r['error']}" if r["error"] else "")
