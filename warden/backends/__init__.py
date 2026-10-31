"""Decision backends: whatever answers warden's typed questions.

A backend has two methods:

    ask(state, questions) -> (answers, ms, usage)
    health() -> bool

`questions` maps a key to one of three shapes (the /v1/systemone shapes):

    {"type": "noul",   "instructions": "..."}                         -> {"noul": p_yes}
    {"type": "choice", "instructions": "...", "criteria": {id: desc}}  -> {"choice": id, "confidence": p,
                                                                          "probabilities": {id: p}}
    {"type": "score",  "instructions": "...", "criteria": [lowest, ..., highest]}
                                                                       -> {"score": float, "confidence": p,
                                                                          "probabilities": {"0": p, ...}}

`ask` raises DecisionError when it can't answer; every caller already degrades on that (prompt falls back to
rules, content fails closed to review, decide reports incomplete).

Pick one with `decision_model.backend` in guard.json:
    systemone      a /v1/systemone endpoint, e.g. lev on llama.cpp (the default)
    openai_compat  any OpenAI-compatible chat endpoint: Ollama, vLLM, LM Studio, llama.cpp server, OpenRouter...
    rules_only     no model; warden runs on rules alone and decisions go to a human
    module:Class   your own backend, constructed with the decision_model dict
"""
import importlib
import logging
import threading
import time


class DecisionError(RuntimeError):
    pass


class Breaker:
    """Circuit breaker: after a failure, calls fail fast for `cooldown_s`, so a dead model costs one timeout,
    not one per question. State is per backend class (shared by every instance in the process)."""
    _down_until = 0.0
    _lock = threading.Lock()

    def __init__(self, cfg):
        self.url = cfg.get("url", "")
        self.cooldown = cfg.get("cooldown_s", 15)

    def check(self):
        cls = type(self)
        if time.monotonic() < cls._down_until:
            raise DecisionError(f"decision model marked down (retry in {cls._down_until - time.monotonic():.0f}s)")

    def trip(self, e):
        cls = type(self)
        with cls._lock:
            tripped = time.monotonic() >= cls._down_until
            cls._down_until = time.monotonic() + self.cooldown
        if tripped:
            from .. import telemetry
            telemetry.record("lev_down", logging.WARNING, url=self.url, error=f"{type(e).__name__}: {e}"[:300],
                             cooldown_s=self.cooldown)
        return DecisionError(f"decision model unreachable at {self.url}: {e}")

    def reset(self):
        with type(self)._lock:
            type(self)._down_until = 0.0


BUILTIN = {
    "systemone": "warden.backends.systemone:SystemOne",
    "openai_compat": "warden.backends.openai_compat:OpenAICompat",
    "rules_only": "warden.backends.rules_only:RulesOnly",
}


def make(cfg):
    """Build the backend named by cfg["backend"] (default systemone)."""
    name = cfg.get("backend", "systemone")
    target = BUILTIN.get(name, name)
    if ":" not in target:
        raise ValueError(f"unknown decision backend {name!r}: use one of {sorted(BUILTIN)} or 'module:Class'")
    mod, cls = target.split(":", 1)
    return getattr(importlib.import_module(mod), cls)(cfg)


def describe(cfg):
    """One line for health output: which backend, where."""
    name = cfg.get("backend", "systemone")
    where = cfg.get("url") or "no model"
    return f"{name} at {where}" + (f" ({cfg['model']})" if cfg.get("model") else "")
