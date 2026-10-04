"""Test bed API: request hygiene and the JSON routes (lev stubbed; server on an ephemeral port)."""
import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from unittest import mock

from warden import labels
from warden.testbed.server import Handler

from .stubs import StubLev
from .test_labels import TempLabels


class Testbed(TempLabels):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        super().setUp()
        self.lev = StubLev(expert="home", mode="act")
        p = mock.patch("warden.classify.Lev", return_value=self.lev)
        p.start()
        self.addCleanup(p.stop)

    def post(self, path, body, ctype="application/json"):
        req = urllib.request.Request(self.base + path, data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": ctype})
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            with e:
                return e.code, json.load(e)

    def test_classify(self):
        code, r = self.post("/api/classify", {"text": "turn off the lights", "sensitivity": True})
        self.assertEqual(code, 200)
        self.assertEqual((r["workflow"]["id"], self.lev.asked), ("voice_home", ["expert", "mode", "sensitivity"]))

    def test_classify_needs_text(self):
        self.assertEqual(self.post("/api/classify", {"text": "  "})[0], 400)

    def test_json_content_type_required(self):
        self.assertEqual(self.post("/api/classify", {"text": "x"}, ctype="text/plain")[0], 415)

    def get(self, path):
        with urllib.request.urlopen(self.base + path) as r:
            return json.load(r)

    def test_label_seed_item_uses_seed_text(self):
        code, r = self.post("/api/labels", {"kind": "routing", "id": "home-01", "text": "tampered",
                                            "label": {"tier": "local", "workflow": "voice_home"}})
        self.assertEqual((code, r["id"]), (200, "home-01"))
        got = self.get("/api/labels/routing")
        self.assertEqual(len(got["items"]), 100)
        self.assertEqual(got["labels"]["home-01"]["text"], "set a timer for twelve minutes")
        self.assertIn("voice_home", [w["id"] for w in got["workflows"]])

    def test_live_label_gets_text_id(self):
        code, r = self.post("/api/labels", {"kind": "routing", "id": "whatever", "text": "a new prompt",
                                            "label": {"tier": "blocked"}, "pred": {"tier": "local"}})
        self.assertEqual((code, r["id"]), (200, labels.text_id("a new prompt")))

    def test_bad_label_400(self):
        code, r = self.post("/api/labels", {"kind": "routing", "id": "home-01", "label": {"tier": "cloud"}})
        self.assertEqual(code, 400)
        self.assertEqual(self.post("/api/labels", {"kind": "nope", "text": "x", "label": {}})[0], 400)

    def test_classify_page_served(self):
        with urllib.request.urlopen(self.base + "/classify.html") as r:
            self.assertIn(b"classify.js", r.read())


if __name__ == "__main__":
    unittest.main()
