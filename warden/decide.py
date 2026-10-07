"""lev as a cheap typed-decision engine: ask one question about each of many items.

    decide("Is this email an action item?", "yes_no", items=[...])
    decide("Which bucket?", "choice", items=[...], options={"bug": "a defect report", "feature": "a request"})
    decide("How urgent?", "score", items=[...], levels=["not urgent", "this week", "today", "now"])

Each item is one lev call (~90 ms for short items), framed as data. Secrets and high-risk PII are redacted
before lev sees an item. Good for triage, filtering and bucketing; not for final high-stakes calls.
"""
import logging
import time

from . import config, rules, telemetry
from .lev import Lev, DecisionError, fit, frame

KINDS = ("yes_no", "choice", "score")


def _question(question, kind, options, levels):
    if kind == "yes_no":
        return {"type": "noul", "instructions": question}
    if kind == "choice":
        if not options or len(options) < 2:
            raise ValueError("choice needs at least two options")
        crit = options if isinstance(options, dict) else {o: o for o in options}
        return {"type": "choice", "instructions": question, "criteria": crit}
    if kind == "score":
        if not levels or len(levels) < 2:
            raise ValueError("score needs at least two levels, lowest first")
        return {"type": "score", "instructions": question, "criteria": list(levels)}
    raise ValueError(f"kind must be one of {KINDS}")


def _answer(kind, a, threshold):
    if kind == "yes_no":
        return {"answer": a["noul"] >= threshold, "p": round(a["noul"], 4)}
    if kind == "choice":
        return {"answer": a["choice"], "p": round(a["probabilities"][a["choice"]], 4),
                "probabilities": {k: round(v, 4) for k, v in a["probabilities"].items()}}
    return {"answer": round(a["score"], 3), "level": min(len(a["probabilities"]) - 1, round(a["score"])),
            "probabilities": {k: round(v, 4) for k, v in a["probabilities"].items()}}


def decide(question, kind="yes_no", items=(), options=None, levels=None, context=None, cfg=None, lev=None):
    if not question or not question.strip():
        raise ValueError("question is required")
    items = list(items)
    if not items:
        raise ValueError("at least one item is required")
    cfg = cfg or config.load("guard.json")
    dc, dm = cfg["decide"], cfg["decision_model"]
    if len(items) > dc["max_items"]:
        raise ValueError(f"too many items ({len(items)} > {dc['max_items']})")
    q = {"q": _question(question, kind, options, levels)}
    lev = lev or Lev(dm)
    t0 = time.monotonic()
    out, calls, lev_ms, tokens, error = [], 0, 0, 0, None
    for i, item in enumerate(items):
        text = rules.redact(rules.normalize(str(item)))["text"]
        _, truncated = fit(text, dc["item_chars"])
        try:
            a, ms, usage = lev.ask(frame(text, dc["item_chars"], "item", context), q)
        except DecisionError as e:
            error = str(e)
            break
        calls, lev_ms, tokens = calls + 1, lev_ms + ms, tokens + usage.get("input_tokens", 0)
        out.append({"index": i, **_answer(kind, a["q"], dc["yes_threshold"]), "truncated": truncated})
    res = {"question": question, "kind": kind, "results": out, "complete": error is None and len(out) == len(items),
           "error": error, "lev": {"calls": calls, "ms": lev_ms, "tokens": tokens},
           "ms": round((time.monotonic() - t0) * 1000, 1)}
    telemetry.record("decide", logging.WARNING if error else logging.INFO, kind=kind, items=len(items),
                     answered=len(out), complete=res["complete"], degraded=error is not None, error=error,
                     lev=res["lev"], ms=res["ms"])
    return res
