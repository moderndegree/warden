"""The guard: inspect text at a boundary and say what to do with it.

    inspect(text, boundary="prompt" | "content" | "outbound") -> result dict

Gate 0 (rules, ~1 ms, no model) runs first; a block stops there. Gate 1 asks lev one question, plus a chunk
sweep for long text that stops at the first high hit. The outbound boundary is rules + redaction only.
`guard_events` yields one event per step for the test bed's live view.
"""
import hashlib
import threading
import time
from collections import OrderedDict

from . import __version__, config, rules
from .lev import Lev, DecisionError, chunks, frame

BOUNDARIES = ("prompt", "content", "outbound")
_cache, _cache_lock = OrderedDict(), threading.Lock()


def _th(cfg, qid, level):
    return cfg["questions"][qid].get(level, cfg["thresholds"][level])


def security_finding(cfg, qid, p, medium_floor=0.0):
    """One lev question's score as a finding in the rule format, or None below its medium threshold.
    medium_floor raises the medium threshold (long text: more windows, more chances of a stray high score)."""
    q = cfg["questions"][qid]
    medium = max(_th(cfg, qid, "medium"), medium_floor)
    sev = "high" if p >= _th(cfg, qid, "high") else "medium" if p >= medium else None
    if not sev:
        return None
    return {"id": f"model.{qid}", "category": qid, "severity": sev, "title": q["label"],
            "detail": f"lev: p={p:.2f}", "evidence": "", "source": "lev"}


def verdict(findings):
    """block: high-confidence attack. review: suspicious. allow: no signal (not the same as safe)."""
    attack = [f for f in findings if f["category"] not in ("secret", "pii", "info")]
    worst = max((rules.SEV_RANK[f["severity"]] for f in attack), default=0)
    # lev alone never blocks: a high lev score needs a medium-or-worse rule hit to corroborate it.
    rule_worst = max((rules.SEV_RANK[f["severity"]] for f in attack if f["source"] == "rules"), default=0)
    lev_high = any(f["source"] == "lev" and f["severity"] == "high" for f in attack)
    if worst >= rules.SEV_RANK["critical"] or rule_worst >= rules.SEV_RANK["high"] or (
            lev_high and rule_worst >= rules.SEV_RANK["medium"]):
        status = "block"
    elif worst >= rules.SEV_RANK["medium"]:
        status = "review"
    else:
        status = "allow"
    return {"status": status,
            "categories": sorted({f["category"] for f in attack if rules.SEV_RANK[f["severity"]] >= rules.SEV_RANK["medium"]}),
            "secrets": any(f["category"] == "secret" for f in findings),
            "pii": any(f["category"] == "pii" and rules.SEV_RANK[f["severity"]] >= rules.SEV_RANK["high"] for f in findings),
            "pii_any": any(f["category"] == "pii" for f in findings)}


def guard_events(text, boundary="prompt", cfg=None, lev=None, use_lev=True, always_lev=False):
    """always_lev (analysis only): ask lev even when the rules already block, to measure lev on its own."""
    if boundary not in BOUNDARIES:
        raise ValueError(f"boundary must be one of {BOUNDARIES}")
    cfg = cfg or config.load("guard.json")
    b, dm = cfg["boundaries"][boundary], cfg["decision_model"]
    lev = lev or Lev(dm)
    t0 = time.monotonic()
    now = lambda: round((time.monotonic() - t0) * 1000, 1)
    st = {"calls": 0, "ms": 0, "tokens": 0}
    findings, chunk_rows, gates = [], [], []
    res = {"warden": __version__, "boundary": boundary, "verdict": None, "action": None, "stopped_at": None,
           "score": None, "categories": [], "secrets": False, "pii": False, "pii_any": False, "findings": [],
           "hidden_text": None, "redacted": None, "redactions": {}, "chunks": chunk_rows, "gates": gates,
           "degraded": False, "error": None, "lev": st, "ms": None, "cached": False, "rules_verdict": None,
           "scores": {}}

    def ask(state, qs):
        a, ms, usage = lev.ask(state, qs)
        st["calls"] += 1
        st["ms"] += ms
        st["tokens"] += usage.get("input_tokens", 0)
        return a, ms

    def close_gate(name, t_open, calls0, status, stopped):
        rec = {"gate": name, "status": status, "stopped": stopped, "ms": round(now() - t_open, 1),
               "lev_calls": st["calls"] - calls0}
        gates.append(rec)
        return {"type": "gate_done", **rec, "t": now()}

    def finish(sec, stopped=None):
        res.update(sec)
        res["verdict"] = sec["status"]
        res.pop("status", None)
        res["action"] = b["actions"][res["verdict"]]
        res["stopped_at"] = stopped
        res["findings"] = sorted(findings, key=lambda f: -rules.SEV_RANK[f["severity"]])
        res["ms"] = round(now(), 1)
        return [{"type": "verdict", "status": res["verdict"], "categories": sec["categories"], "secrets": sec["secrets"],
                 "pii": sec["pii"], "score": res["score"], "action": res["action"], "t": now()},
                {"type": "result", "result": res, "t": now()}]

    yield {"type": "start", "t": 0, "boundary": boundary, "chars": len(text),
           "est_prompt_tokens": int(len(text) / cfg["chars_per_token"])}

    # ---- Gate 0: rules ----------------------------------------------------------------------
    t_open = now()
    yield {"type": "gate", "gate": "rules", "t": now()}
    for family, fs in rules.scan_steps(text, cfg["chars_per_token"]):
        if family not in b["rules"]:
            continue
        findings.extend(fs)
        yield {"type": "rules", "family": family, "findings": fs, "t": now()}
    hidden = rules.decode_tag_chars(text)
    if hidden:
        res["hidden_text"] = hidden
        yield {"type": "hidden", "text": hidden, "t": now()}
    if b["redact"]:
        red = rules.redact(rules.strip_invisible(text))
        res["redacted"] = red["text"]
        res["redactions"] = red["counts"]
    sec = verdict(findings)
    if boundary == "outbound" and res["redactions"] and sec["status"] == "allow":
        sec["status"] = "review"                       # something had to be removed before sending
    res["rules_verdict"] = sec["status"]
    if (sec["status"] == "block" and not always_lev) or not (b["lev"] and use_lev):
        yield close_gate("rules", t_open, 0, sec["status"], sec["status"] == "block")
        if b["lev"] and use_lev:
            yield {"type": "gate_skipped", "gate": "security", "reason": "stopped at rules", "t": now()}
        yield from finish(sec, "rules" if sec["status"] == "block" else None)
        return
    yield close_gate("rules", t_open, 0, sec["status"], False)

    # ---- Gate 1: lev ------------------------------------------------------------------------
    # lev reads what a model would read: invisible chars stripped, NFKC, hidden tag text appended.
    # Secrets and high-risk PII are redacted first; they never leave the rules layer.
    view = rules.redact(rules.normalize(text) + (f"\n[hidden text: {hidden}]" if hidden else ""))["text"]
    t_open, calls0 = now(), st["calls"]
    yield {"type": "gate", "gate": "security", "t": now()}
    qids = b["questions"]
    scores = {}
    try:
        primary = qids[0]
        pq = lambda: {"q": {"type": "noul", "instructions": cfg["questions"][primary]["instructions"]}}
        hi = lambda qid: scores.get(qid, 0) >= _th(cfg, qid, "high")
        window = b.get("window_chars", dm["state_chars"])
        # 1. Primary question over the text. Long text is swept in windows (an attack diluted in a long document
        #    barely moves a whole-document score); stop at the first high window.
        if len(view) <= window:
            yield {"type": "ask", "key": "security", "q": primary, "label": cfg["questions"][primary]["label"], "t": now()}
            a, ms = ask(frame(view, window, b["frame"]), pq())
            scores[primary] = a["q"]["noul"]
            yield {"type": "answer", "key": "security", "q": primary, "label": cfg["questions"][primary]["label"],
                   "answer": a["q"], "ms": ms, "t": now()}
        else:
            parts = chunks(view, window, b.get("max_windows", dm["max_chunks"]))
            yield {"type": "chunks", "count": len(parts), "t": now()}
            scores[primary] = 0.0
            for i, c in enumerate(parts):
                yield {"type": "ask", "key": f"chunk_{i}", "t": now()}
                a, ms = ask(frame(c, window, b["frame"]), pq())
                p = a["q"]["noul"]
                chunk_rows.append({"chunk": i, "chars": len(c), "p": p})
                scores[primary] = max(scores[primary], p)
                yield {"type": "chunk", "chunk": i, "of": len(parts), "p": p, "ms": ms, "t": now()}
                if hi(primary):
                    if i + 1 < len(parts):
                        yield {"type": "skip", "key": "chunks",
                               "reason": f"hit in chunk {i + 1}; {len(parts) - i - 1} chunk(s) not needed", "t": now()}
                    break
        # 2. Hidden markup (comments, invisible elements, alt text) judged on its own: a person never sees it.
        if not hi(primary):
            for kind, seg in rules.hidden_markup(text)[:b.get("max_hidden", 3)]:
                seg = rules.redact(rules.normalize(seg))["text"]
                yield {"type": "ask", "key": "security", "q": primary, "label": f"{cfg['questions'][primary]['label']} ({kind})", "t": now()}
                a, ms = ask(frame(seg, window, b["frame"]), pq())
                scores[primary] = max(scores[primary], a["q"]["noul"])
                yield {"type": "answer", "key": "security", "q": primary, "label": f"{cfg['questions'][primary]['label']} ({kind})",
                       "answer": a["q"], "ms": ms, "t": now()}
                if hi(primary):
                    break
        # 3. Secondary questions once, on the head + tail.
        state = frame(view, dm["state_chars"], b["frame"])
        for qid in qids[1:]:
            if any(hi(k) for k in scores):
                break
            q = cfg["questions"][qid]
            yield {"type": "ask", "key": "security", "q": qid, "label": q["label"], "t": now()}
            a, ms = ask(state, {"q": {"type": "noul", "instructions": q["instructions"]}})
            scores[qid] = a["q"]["noul"]
            yield {"type": "answer", "key": "security", "q": qid, "label": q["label"], "answer": a["q"], "ms": ms, "t": now()}
    except DecisionError as e:
        res["degraded"], res["error"] = True, str(e)
        yield {"type": "error", "error": str(e), "t": now()}
    res["scores"] = scores
    res["score"] = max(scores.values()) if scores else None
    long_cfg = b.get("long_text")
    floor = long_cfg["medium"] if long_cfg and len(view) > long_cfg["over_chars"] else 0.0
    res["medium_floor"] = floor or None
    for qid, p in scores.items():
        f = security_finding(cfg, qid, p, floor)
        if f:
            findings.append(f)
    if res["degraded"] and b.get("on_lev_down") == "review":
        # Fail closed: without lev we can't vouch for this text, so at least ask for review.
        findings.append({"id": "guard.degraded", "category": "degraded", "severity": "medium",
                         "title": "Decision model unavailable", "detail": "rules only; this boundary fails closed to review",
                         "evidence": "", "source": "guard"})
    sec = verdict(findings)
    yield close_gate("security", t_open, calls0, sec["status"], sec["status"] == "block")
    yield from finish(sec, "security" if sec["status"] == "block" else None)


def inspect(text, boundary="prompt", cfg=None, lev=None, use_lev=True, always_lev=False):
    """Run the guard and return the result. Identical calls (text, boundary, config) hit an in-process cache."""
    explicit = cfg is not None or lev is not None
    key = None
    if not explicit:
        key = (boundary, use_lev, hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest(),
               config.mtime("guard.json"))
        with _cache_lock:
            if key in _cache:
                _cache.move_to_end(key)
                return {**_cache[key], "cached": True}
    res = None
    for ev in guard_events(text, boundary, cfg, lev, use_lev, always_lev):
        if ev["type"] == "result":
            res = ev["result"]
    if key and not res["degraded"]:
        with _cache_lock:
            _cache[key] = res
            while len(_cache) > (cfg or config.load("guard.json")).get("cache_size", 256):
                _cache.popitem(last=False)
    return res
