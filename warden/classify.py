"""Standalone prompt classification: expert + mode (+ optional sensitivity), the router's lev questions.

    classify("Fix the failing test in auth.py")            # 2 lev calls
    classify(text, sensitivity=True)                       # +1
    classify(text, guard=True)                             # prompt guard first (+2); stops on block

Also reports the workflow the expert + mode map to (router.json "agents"; no extra call). Secrets and
high-risk PII are redacted before lev sees the text.
"""
import logging
import time

from . import config, rules, telemetry
from .lev import Lev, DecisionError, frame
from .router_logic import choose_agent, routing_questions, score_question


def choice_result(src, a):
    top = sorted(a["probabilities"].items(), key=lambda kv: -kv[1])[:4]
    return {"id": a["choice"], "label": src[a["choice"]]["label"], "p": a["probabilities"][a["choice"]],
            "probabilities": a["probabilities"],
            "alternatives": [{"id": k, "label": src[k]["label"], "p": p} for k, p in top]}


def level_result(m, key, a):
    lv = m[key]["levels"]
    i = min(len(lv) - 1, round(a["score"]))
    return {"label": m[key]["label"], "score": a["score"], "level": i, "level_text": lv[i],
            "probabilities": a["probabilities"], "max": len(lv) - 1}


def state(text, m):
    """The framed, redacted view of a prompt that every classification question reads."""
    return frame(rules.redact(rules.normalize(text))["text"], m["route_state_chars"], "prompt")


def classify(text, sensitivity=False, guard=False, m=None, gcfg=None, lev=None):
    m = m or config.load("router.json")
    gcfg = gcfg or config.load("guard.json")
    lev = lev or Lev(gcfg["decision_model"])
    t0 = time.monotonic()
    res = {"expert": None, "mode": None, "sensitivity": None, "workflow": None, "security": None,
           "stopped": False, "error": None}
    st = {"calls": 0, "ms": 0, "tokens": 0}

    def done():
        res["lev"] = st
        res["ms"] = round((time.monotonic() - t0) * 1000, 1)
        telemetry.record("classify", logging.WARNING if res["error"] else logging.INFO, chars=len(text),
                         expert=(res["expert"] or {}).get("id"), mode=(res["mode"] or {}).get("id"),
                         workflow=(res["workflow"] or {}).get("id"),
                         sensitivity=(res["sensitivity"] or {}).get("score"),
                         guard_verdict=(res["security"] or {}).get("verdict"), stopped=res["stopped"],
                         degraded=res["error"] is not None, error=res["error"], lev=st, ms=res["ms"])
        return res

    if guard:
        from .guard import inspect
        g = inspect(text, "prompt", gcfg, lev)
        st.update(calls=g["lev"]["calls"], ms=g["lev"]["ms"], tokens=g["lev"]["tokens"])
        res["security"] = {"verdict": g["verdict"], "action": g["action"], "score": g["score"],
                           "findings": [f["id"] for f in g["findings"]], "degraded": g["degraded"]}
        if g["verdict"] in m["gates"]["stop_on"]:
            res["stopped"] = True
            return done()

    s = state(text, m)
    qs = routing_questions(m)
    if sensitivity:
        qs.update(score_question(m, "sensitivity"))
    try:
        for key, q in qs.items():
            a, ms, usage = lev.ask(s, {key: q})
            st["calls"], st["ms"], st["tokens"] = st["calls"] + 1, st["ms"] + ms, st["tokens"] + usage.get("input_tokens", 0)
            res[key] = (level_result(m, key, a[key]) if key == "sensitivity"
                        else choice_result(m["experts" if key == "expert" else "modes"], a[key]))
    except DecisionError as e:
        res["error"] = str(e)
        return done()
    wid, why = choose_agent(m, res["expert"]["id"], res["mode"]["id"])
    res["workflow"] = {"id": wid, "label": m["agents"][wid]["label"], "why": why}
    return done()


def brief(r):
    """One line: [verdict ·] expert/mode → workflow  p=.. [· sensitivity]."""
    sec = f"{r['security']['verdict']} · " if r["security"] else ""
    if r["stopped"]:
        return f"{sec}stopped: not classified"
    if r["error"]:
        return f"{sec}error: {r['error']}"
    line = (f"{sec}{r['expert']['id']}/{r['mode']['id']} → {r['workflow']['id']}"
            f"  p={r['expert']['p']:.2f}/{r['mode']['p']:.2f}")
    if r["sensitivity"]:
        line += f" · sensitivity {r['sensitivity']['score']:.1f} ({r['sensitivity']['level_text']})"
    return line
