"""Availability checks: loopback-only HTTP, sign-in files (presence only), PATH."""
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from warden import availability as av


class Health(BaseHTTPRequestHandler):
    body = {"status": "ok"}

    def do_GET(self):
        data = json.dumps(self.body).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


class Checks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), Health)
        cls.url = f"http://127.0.0.1:{cls.srv.server_address[1]}/health"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.dir = Path(d.name)

    def test_http(self):
        self.assertEqual(av._http({"url": self.url}), (True, "up"))
        Health.body = {"status": "loading", "busy": True}
        self.addCleanup(setattr, Health, "body", {"status": "ok"})
        self.assertFalse(av._http({"url": self.url})[0])

    def test_http_down(self):
        self.srv2 = ThreadingHTTPServer(("127.0.0.1", 0), Health)
        port = self.srv2.server_address[1]
        self.srv2.server_close()                       # nothing listens there now
        up, why = av._http({"url": f"http://127.0.0.1:{port}/health", "timeout_s": 1})
        self.assertFalse(up)
        self.assertIn("down", why)

    def test_http_refuses_non_loopback(self):
        up, why = av._http({"url": "https://api.example.com/health"})
        self.assertFalse(up)
        self.assertIn("loopback", why)

    def test_auth_field_without_leaking(self):
        f = self.dir / "auth.json"
        c = {"file": str(f), "field": "refresh_token"}
        self.assertFalse(av._auth(c)[0])
        f.write_text(json.dumps({"https://auth::1": {"refresh_token": "", "email": "a@b"}}))
        self.assertFalse(av._auth(c)[0])
        f.write_text(json.dumps({"https://auth::1": {"refresh_token": "SECRET-VALUE"}}))
        up, why = av._auth(c)
        self.assertEqual((up, why), (True, "signed in"))

    def test_auth_key_and_presence(self):
        f = self.dir / "auth.json"
        f.write_text(json.dumps({"xai": {}}))
        self.assertFalse(av._auth({"file": str(f), "key": "openrouter"})[0])
        self.assertTrue(av._auth({"file": str(f), "key": "xai"})[0])
        self.assertTrue(av._auth({"file": str(f)})[0])             # presence only: never parsed
        f.write_text("not json")
        self.assertTrue(av._auth({"file": str(f)})[0])
        self.assertFalse(av._auth({"file": str(f), "key": "xai"})[0])
        self.assertFalse(av._auth({"file": str(f), "bin": "definitely-not-a-real-binary-xyz"})[0])

    def test_bin(self):
        self.assertTrue(av._bin({"bin": "python3"})[0])
        self.assertFalse(av._bin({"bin": "definitely-not-a-real-binary-xyz"})[0])

    def test_check_caches_and_missing(self):
        m = {"availability": {"ttl_s": 60, "checks": {
                "local": {"label": "Local", "kind": "http", "url": self.url},
                "cli": {"label": "CLI", "kind": "bin", "bin": "definitely-not-a-real-binary-xyz"}}},
             "models": {"a": {"needs": ["local"]}, "b": {"needs": ["cli"]}}}
        st = av.check(m, force=True)
        self.assertEqual((st["local"]["up"], st["cli"]["up"]), (True, False))
        self.assertIs(av.check(m), st)
        self.assertEqual(av.missing(m, {"model": "a"}, st), [])
        self.assertEqual(av.missing(m, {"model": "b", "needs": ["unknown"]}, st), ["CLI: definitely-not-a-real-binary-xyz not on PATH"])

    def test_default_config_names_real_checks(self):
        from warden import config
        m = config.load("router.json")
        names = set(m["availability"]["checks"])
        for mid, mod in m["models"].items():
            self.assertTrue(set(mod.get("needs", [])) <= names, mid)
        for a in m["agents"].values():
            for ex in a["executors"]:
                self.assertTrue(set(ex.get("needs", [])) <= names, ex["via"])
        for c in m["availability"]["checks"].values():
            if c["kind"] == "http":
                self.assertTrue(c["url"].startswith("http://127.0.0.1:"))


if __name__ == "__main__":
    unittest.main()
