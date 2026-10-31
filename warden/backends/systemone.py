"""/v1/systemone backend: a typed-decision endpoint (e.g. lev on llama.cpp).

The endpoint returns probabilities, not text, so injected text can at most skew a score; it can't make warden
do anything. It re-reads `state` for every question (no prefix cache), so cost ≈ questions × state tokens:
ask only what you need, and keep `state` short.
"""
import json
import time
import urllib.error
import urllib.request

from . import Breaker, DecisionError


class SystemOne(Breaker):
    _down_until = 0.0

    def __init__(self, cfg):
        super().__init__(cfg)
        self.model = cfg.get("model", "")
        self.timeout = cfg.get("timeout_s", 8)

    def ask(self, state, questions):
        self.check()
        body = json.dumps({"model": self.model, "state": state, "questions": questions}).encode()
        req = urllib.request.Request(self.url, data=body, method="POST", headers={"Content-Type": "application/json"})
        t = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                data = json.load(r)
        except (urllib.error.URLError, TimeoutError, ConnectionError, json.JSONDecodeError) as e:
            raise self.trip(e) from e
        if "answers" not in data:
            raise DecisionError(f"no answers from {self.url}: {str(data)[:200]}")
        return data["answers"], round((time.monotonic() - t) * 1000), data.get("usage", {})

    def health(self):
        base = self.url.split("/v1/")[0]
        try:
            with urllib.request.urlopen(base + "/health", timeout=3) as r:
                ok = json.load(r).get("status") == "ok"
        except Exception:
            return False
        if ok:
            self.reset()
        return ok
