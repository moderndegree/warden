"""EXPERIMENTAL: pick an agent and model for a prompt, after the guard has passed it.

Gates 0-1 are the guard's prompt boundary (warden.guard). Gate 2 asks lev only what can change the answer:
expert + mode -> agent; complexity -> model within the agent (skipped for one-model agents); sensitivity
only when the pick would leave this machine. Classifies only; never runs, answers, or forwards the prompt.
"""
import hashlib
import threading
import time
from collections import OrderedDict

from . import config
from .classify import choice_result as _choice, level_result as _level, state as classify_state
from .guard import guard_events
from .lev import Lev, DecisionError
from .router_logic import (agent_axis, choose_agent, decide_route, routing_questions, score_executors,
                           score_question)

_cache, _cache_lock = OrderedDict(), threading.Lock()


def _walk(text, m, gcfg, lev):
    t0 = time.monotonic()
    now = lambda: round((time.monotonic() - t0) * 1000, 1)
    res = {"chars": len(text), "est_prompt_tokens": int(len(text) / gcfg["chars_per_token"]), "hidden_text": None,
           "cached": False, "gates": [], "stopped_at": None, "security": None,
           "profile": {"expert": None, "mode": None, "complexity": None, "sensitivity": None, "skipped": {}},
           "agent": None, "routing": None, "timings": None, "error": None}
    st = {"calls": 0, "lev_ms": 0, "tokens": 0}

    def finish():
        res["timings"] = {"total_ms": round(now()), "lev_calls": st["calls"], "lev_ms": st["lev_ms"],
                          "lev_input_tokens": st["tokens"]}
        return {"type": "result", "t": now(), "result": res}

    # ---- Gates 0-1: the guard ---------------------------------------------------------------
    g = None
    for ev in guard_events(text, "prompt", gcfg, lev):
        if ev["type"] == "result":
            g = ev["result"]
        else:
            yield ev
    st.update(calls=g["lev"]["calls"], lev_ms=g["lev"]["ms"], tokens=g["lev"]["tokens"])
    res["gates"] = list(g["gates"])
    res["hidden_text"] = g["hidden_text"]
    sec = {"status": g["verdict"], "categories": g["categories"], "secrets": g["secrets"], "pii": g["pii"],
           "pii_any": g["pii_any"], "score": g["score"], "chunks": g["chunks"], "findings": g["findings"],
           "action": g["action"]}
    res["security"] = sec
    if g["degraded"]:
        res["error"] = g["error"]
    if sec["status"] in set(m["gates"]["stop_on"]) or g["degraded"]:
        res["stopped_at"] = g["stopped_at"] or ("security" if not g["degraded"] else None)
        why = (f"Security verdict {sec['status'].upper()}: not sent to any model, routing skipped." if not g["degraded"]
               else "Decision model unavailable; only the rules gate ran.")
        yield {"type": "gate_skipped", "gate": "routing", "reason": f"stopped at {res['stopped_at']}" if not g["degraded"] else "lev unavailable", "t": now()}
        res["routing"] = {"decision": "blocked" if not g["degraded"] else "unavailable", "agent": None, "model": None,
                          "route": None, "table": [], "reasons": [why]}
        yield {"type": "route", "routing": res["routing"], "t": now()}
        yield finish()
        return

    # ---- Gate 2: routing --------------------------------------------------------------------
    t_open, calls0 = now(), st["calls"]
    yield {"type": "gate", "gate": "routing", "t": now()}
    state = classify_state(text, m)
    prof = res["profile"]

    def ask(qs):
        a, ms, usage = lev.ask(state, qs)
        st["calls"] += 1
        st["lev_ms"] += ms
        st["tokens"] += usage.get("input_tokens", 0)
        return a, ms

    try:
        rq = routing_questions(m)
        for key, src in (("expert", m["experts"]), ("mode", m["modes"])):
            yield {"type": "ask", "key": key, "t": now()}
            a, ms = ask({key: rq[key]})
            prof[key] = _choice(src, a[key])
            yield {"type": "answer", "key": key, "answer": a[key], "ms": ms, "t": now()}

        agent_id, why = choose_agent(m, prof["expert"]["id"], prof["mode"]["id"])
        ag = m["agents"][agent_id]
        axis = agent_axis(m, agent_id, prof["expert"]["id"])
        res["agent"] = {"id": agent_id, "label": ag["label"], "harness": ag["harness"], "why": why, "axis": axis,
                        "executors": len(ag["executors"])}
        yield {"type": "agent", **res["agent"], "t": now()}

        asked, complexity = set(), None
        if len(ag["executors"]) == 1:
            prof["skipped"]["complexity"] = "agent has one executor"
            yield {"type": "skip", "key": "complexity", "reason": prof["skipped"]["complexity"], "t": now()}
        else:
            yield {"type": "ask", "key": "complexity", "t": now()}
            a, ms = ask(score_question(m, "complexity"))
            prof["complexity"] = _level(m, "complexity", a["complexity"])
            complexity = a["complexity"]["score"]
            asked.add("complexity")
            yield {"type": "answer", "key": "complexity", "answer": a["complexity"], "ms": ms, "t": now()}

        rows, ranked, force_local = score_executors(m, agent_id, axis, complexity, sec)
        yield {"type": "executors", "rows": rows, "phase": "fit", "t": now()}

        if ranked[0]["route"] == "local":
            prof["skipped"]["sensitivity"] = ("already local (rules found secrets/PII)" if force_local
                                              else "best pick is local; nothing leaves this machine")
            yield {"type": "skip", "key": "sensitivity", "reason": prof["skipped"]["sensitivity"], "t": now()}
        else:
            yield {"type": "ask", "key": "sensitivity", "t": now()}
            a, ms = ask(score_question(m, "sensitivity"))
            prof["sensitivity"] = _level(m, "sensitivity", a["sensitivity"])
            asked.add("sensitivity")
            yield {"type": "answer", "key": "sensitivity", "answer": a["sensitivity"], "ms": ms, "t": now()}
            rows, ranked, force_local = score_executors(m, agent_id, axis, complexity, sec, a["sensitivity"]["score"])
            yield {"type": "executors", "rows": rows, "phase": "privacy", "t": now()}

        res["routing"] = {**decide_route(m, agent_id, ranked, force_local, sec, asked), "table": rows}
        yield {"type": "route", "routing": res["routing"], "t": now()}
    except DecisionError as e:
        res["error"] = str(e)
        yield {"type": "error", "error": str(e), "t": now()}
        res["routing"] = {"decision": "unavailable", "agent": res["agent"] and res["agent"]["id"], "model": None,
                          "route": None, "table": [], "reasons": ["Decision model became unavailable during routing."]}
        yield {"type": "route", "routing": res["routing"], "t": now()}
    rec = {"gate": "routing", "status": res["routing"]["decision"], "stopped": False, "ms": round(now() - t_open, 1),
           "lev_calls": st["calls"] - calls0}
    res["gates"].append(rec)
    yield {"type": "gate_done", **rec, "t": now()}
    yield finish()


def route_events(text, m=None, gcfg=None, lev=None):
    """Yield walk events. Repeats (same text + same configs) replay from cache with zero model calls."""
    explicit = any(x is not None for x in (m, gcfg, lev))
    m = m or config.load("router.json")
    gcfg = gcfg or config.load("guard.json")
    lev = lev or Lev(gcfg["decision_model"])
    key = None
    if not explicit:
        key = (hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest(), config.mtime("router.json"),
               config.mtime("guard.json"))
        with _cache_lock:
            hit = _cache.get(key)
            if hit:
                _cache.move_to_end(key)
        if hit:
            for ev in hit:
                if ev["type"] == "start":
                    yield {**ev, "cached": True}
                elif ev["type"] == "result":
                    yield {**ev, "result": {**ev["result"], "cached": True}}
                else:
                    yield ev
            return
    events = []
    for ev in _walk(text, m, gcfg, lev):
        events.append(ev)
        # Store before yielding the final event: callers like route() stop reading at "result".
        if ev["type"] == "result" and key and not ev["result"]["error"]:
            with _cache_lock:
                _cache[key] = events
                while len(_cache) > gcfg.get("cache_size", 256):
                    _cache.popitem(last=False)
        yield ev


def route(text, m=None, gcfg=None, lev=None):
    for ev in route_events(text, m, gcfg, lev):
        if ev["type"] == "result":
            return ev["result"]
