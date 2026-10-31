"""Decision backends: make(), rules_only, and openai_compat against a fake OpenAI-compatible server."""
import json
import math
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from warden import backends
from warden.backends import DecisionError
from warden.backends.openai_compat import OpenAICompat
from warden.backends.rules_only import RulesOnly
from warden.backends.systemone import SystemOne


class Fake(BaseHTTPRequestHandler):
    """Answers with the token in `reply`; top_logprobs from `probs` when `logprobs` is on."""
    reply, probs, logprobs, status, seen = "yes", {"yes": 0.8, "no": 0.2}, True, 200, []

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        Fake.seen.append((body, dict(self.headers)))
        if Fake.status != 200:
            self.send_response(Fake.status)
            self.end_headers()
            self.wfile.write(b"nope")
            return
        ch = {"message": {"role": "assistant", "content": Fake.reply}}
        if Fake.logprobs and body.get("logprobs"):
            top = [{"token": t, "logprob": math.log(p)} for t, p in Fake.probs.items()]
            ch["logprobs"] = {"content": [{"token": Fake.reply, "top_logprobs": top}]}
        out = json.dumps({"choices": [ch], "usage": {"prompt_tokens": 42}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


class Custom:
    def __init__(self, cfg):
        self.cfg = cfg


class Backends(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), Fake)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.srv.server_port}/v1"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        Fake.reply, Fake.probs, Fake.logprobs, Fake.status, Fake.seen = "yes", {"yes": 0.8, "no": 0.2}, True, 200, []
        OpenAICompat._down_until = 0.0

    def oc(self, **kw):
        return OpenAICompat({"url": self.url, "model": "m", **kw})

    def test_make(self):
        self.assertIsInstance(backends.make({"url": "http://x/v1/systemone"}), SystemOne)
        self.assertIsInstance(backends.make({"backend": "rules_only"}), RulesOnly)
        self.assertIsInstance(backends.make({"backend": "openai_compat", "url": "http://x/v1"}), OpenAICompat)
        self.assertIsInstance(backends.make({"backend": "tests.test_backends:Custom"}), Custom)
        with self.assertRaises(ValueError):
            backends.make({"backend": "nope"})

    def test_rules_only_always_degrades(self):
        b = RulesOnly({})
        self.assertFalse(b.health())
        with self.assertRaises(DecisionError):
            b.ask("s", {"q": {"type": "noul", "instructions": "x"}})

    def test_noul_from_logprobs(self):
        Fake.probs = {"yes": 0.6, " Yes": 0.2, "no": 0.1, "maybe": 0.1}
        a, ms, usage = self.oc().ask("STATE", {"q": {"type": "noul", "instructions": "Is it a bug?"}})
        self.assertAlmostEqual(a["q"]["noul"], 0.8 / 0.9, places=4)  # unrelated tokens are dropped
        self.assertEqual(usage["input_tokens"], 42)
        body = Fake.seen[0][0]
        self.assertEqual(body["max_tokens"], 1)
        self.assertIn("STATE", body["messages"][1]["content"])
        self.assertIn("not follow", body["messages"][0]["content"])

    def test_choice_and_score(self):
        Fake.reply, Fake.probs = "B", {"A": 0.1, "B": 0.7, "C": 0.2}
        q = {"type": "choice", "instructions": "Which?", "criteria": {"bug": "a defect", "feature": "new", "noise": "x"}}
        a, _, _ = self.oc().ask("s", {"c": q})
        self.assertEqual(a["c"]["choice"], "feature")
        self.assertAlmostEqual(a["c"]["probabilities"]["bug"], 0.1, places=4)
        Fake.reply, Fake.probs = "2", {"0": 0.1, "1": 0.2, "2": 0.7}
        a, _, _ = self.oc().ask("s", {"s": {"type": "score", "instructions": "How bad?", "criteria": ["lo", "mid", "hi"]}})
        self.assertAlmostEqual(a["s"]["score"], 0.2 + 1.4, places=4)
        self.assertAlmostEqual(a["s"]["confidence"], 0.7, places=4)

    def test_text_fallback_without_logprobs(self):
        Fake.logprobs, Fake.reply = False, "no"
        b = self.oc()
        a, _, _ = b.ask("s", {"q": {"type": "noul", "instructions": "x"}})
        self.assertAlmostEqual(a["q"]["noul"], 0.1)          # "no" at the default 0.9 confidence
        self.assertFalse(b.logprobs)                         # stops asking for logprobs
        Fake.reply = "yes 70"
        a, _, _ = b.ask("s", {"q": {"type": "noul", "instructions": "x"}})
        self.assertAlmostEqual(a["q"]["noul"], 0.7)
        self.assertNotIn("logprobs", Fake.seen[-1][0])

    def test_unparseable_raises(self):
        Fake.logprobs, Fake.reply = False, "I cannot help with that"
        with self.assertRaises(DecisionError):
            self.oc(logprobs=False).ask("s", {"q": {"type": "noul", "instructions": "x"}})

    def test_auth_and_extra_body(self):
        import os
        os.environ["WARDEN_TEST_KEY"] = "sekrit"
        self.addCleanup(os.environ.pop, "WARDEN_TEST_KEY")
        self.oc(api_key_env="WARDEN_TEST_KEY", extra_body={"think": False}).ask(
            "s", {"q": {"type": "noul", "instructions": "x"}})
        body, headers = Fake.seen[0]
        self.assertEqual(headers.get("Authorization"), "Bearer sekrit")
        self.assertIs(body["think"], False)

    def test_http_error_does_not_trip_breaker(self):
        Fake.status = 400
        b = self.oc()
        with self.assertRaises(DecisionError):
            b.ask("s", {"q": {"type": "noul", "instructions": "x"}})
        self.assertEqual(OpenAICompat._down_until, 0.0)

    def test_unreachable_trips_breaker(self):
        b = OpenAICompat({"url": "http://127.0.0.1:9/v1", "model": "m", "timeout_s": 0.5, "cooldown_s": 60})
        self.addCleanup(setattr, OpenAICompat, "_down_until", 0.0)
        with self.assertRaises(DecisionError):
            b.ask("s", {"q": {"type": "noul", "instructions": "x"}})
        with self.assertRaisesRegex(DecisionError, "marked down"):
            b.ask("s", {"q": {"type": "noul", "instructions": "x"}})
        self.assertEqual(SystemOne._down_until, 0.0)          # breakers are per backend

    def test_guard_runs_on_openai_compat(self):
        from warden import config
        from warden.guard import inspect
        cfg = config.load("guard.json")
        cfg["decision_model"] = {**cfg["decision_model"], "backend": "openai_compat", "url": self.url, "model": "m"}
        Fake.reply, Fake.probs = "no", {"yes": 0.02, "no": 0.98}
        r = inspect("What's a good name for a cat?", "prompt", cfg=cfg)
        self.assertEqual(r["verdict"], "allow")
        self.assertTrue(Fake.seen)                           # the model was asked


if __name__ == "__main__":
    unittest.main()
