"""Test bed API: request hygiene and the JSON routes (lev stubbed; server on an ephemeral port)."""
import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from unittest import mock

from warden.testbed.server import Handler

from .stubs import StubLev


class Testbed(unittest.TestCase):
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
            return e.code, json.load(e)

    def test_classify(self):
        code, r = self.post("/api/classify", {"text": "turn off the lights", "sensitivity": True})
        self.assertEqual(code, 200)
        self.assertEqual((r["workflow"]["id"], self.lev.asked), ("voice_home", ["expert", "mode", "sensitivity"]))

    def test_classify_needs_text(self):
        self.assertEqual(self.post("/api/classify", {"text": "  "})[0], 400)

    def test_json_content_type_required(self):
        self.assertEqual(self.post("/api/classify", {"text": "x"}, ctype="text/plain")[0], 415)

    def test_classify_page_served(self):
        with urllib.request.urlopen(self.base + "/classify.html") as r:
            self.assertIn(b"classify.js", r.read())


if __name__ == "__main__":
    unittest.main()
