"""warden test bed: local UI + JSON API for the guard, classify, decide, and the experimental router.

  warden testbed [--port 8740]        (or: python -m warden testbed)

Inspects and classifies only; nothing is executed or forwarded.
"""
import json
import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .. import __version__, config, feedback, labels
from ..classify import classify
from ..decide import decide
from ..guard import BOUNDARIES, guard_events, inspect
from ..lev import Lev
from ..router import route_events

STATIC = Path(__file__).resolve().parent / "static"
SAMPLES = Path(__file__).resolve().parents[2] / "evals" / "samples.json"
MAX_BODY = 512 * 1024          # bytes; larger bodies are rejected before parsing
HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
                               "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; "
                               "frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}
LOOPBACK = ("127.0.0.1", "localhost", "::1")


class Handler(BaseHTTPRequestHandler):
    server_version = "warden-testbed"
    sys_version = ""

    def log_message(self, fmt, *args):     # never log request bodies; method + path only
        print(f"{self.address_string()} {self.command} {self.path.split('?')[0]} {args[1] if len(args) > 1 else ''}")

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + ("; charset=utf-8" if ctype.startswith(("text/", "application/j")) else ""))
        self.send_header("Content-Length", str(len(data)))
        for k, v in HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _stream(self, events):
        """NDJSON: one event per line, flushed as it happens. HTTP/1.0 + close ends the body."""
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
        for k, v in HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        try:
            for ev in events:
                self.wfile.write(json.dumps(ev).encode() + b"\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass        # the page navigated away mid-walk

    def _host_ok(self):
        # DNS-rebinding guard: only answer requests addressed to this machine by a loopback name.
        return (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]") in LOOPBACK

    def _origin_ok(self):
        # CSRF guard: browsers send Origin on cross-site POSTs; accept only our own.
        origin = self.headers.get("Origin")
        return origin is None or origin == f"http://{self.headers.get('Host')}"

    def _body(self):
        """Validate a POST and return the JSON body, or send an error and return None."""
        if not self._host_ok() or not self._origin_ok():
            return self._send(403, {"error": "forbidden"})
        if not (self.headers.get("Content-Type") or "").startswith("application/json"):
            return self._send(415, {"error": "expected application/json"})
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self._send(400, {"error": "bad length"})
        if n > MAX_BODY:
            return self._send(413, {"error": f"body too large (max {MAX_BODY // 1024} KiB)"})
        try:
            body = json.loads(self.rfile.read(n))
            assert isinstance(body, dict)
            return body
        except (ValueError, AssertionError):
            return self._send(400, {"error": "body must be a JSON object"})

    def do_GET(self):
        if not self._host_ok():
            return self._send(403, {"error": "bad host"})
        path = self.path.split("?")[0]
        if path == "/api/health":
            g = config.load("guard.json")
            return self._send(200, {"warden": __version__, "config_dir": str(config.config_dir()),
                                    "decision_model": g["decision_model"]["model"],
                                    "decision_model_up": Lev(g["decision_model"]).health()})
        if path == "/api/guard/config":
            return self._send(200, config.load("guard.json"))
        if path == "/api/router/config":
            g = config.load("guard.json")
            return self._send(200, {**config.load("router.json"), "security": {"label": "Security check", **g["thresholds"]}})
        if path == "/api/samples":     # dev samples live in the repo; an installed copy may not have them
            return self._send(200, json.loads(SAMPLES.read_text()) if SAMPLES.is_file() else [])
        if path.startswith("/api/labels/"):
            kind = path.rsplit("/", 1)[1]
            if kind not in labels.KINDS:
                return self._send(404, {"error": "not found"})
            m = config.load("router.json")
            return self._send(200, {"items": labels.seeds(kind), "labels": labels.latest(kind),
                                    "path": str(labels.path(kind)), "tiers": labels.TIERS,
                                    "workflows": [{"id": k, "label": a["label"], "desc": a["desc"]}
                                                  for k, a in m["agents"].items()]})
        if path == "/api/feedback/stats":
            return self._send(200, feedback.stats())
        name = "index.html" if path == "/" else path.lstrip("/")
        f = (STATIC / name).resolve()
        if STATIC not in f.parents or not f.is_file():     # no path traversal
            return self._send(404, {"error": "not found"})
        self._send(200, f.read_bytes(), mimetypes.guess_type(f.name)[0] or "application/octet-stream")

    def do_POST(self):
        path = self.path.split("?")[0]
        routes = {"/api/guard", "/api/guard/stream", "/api/route/stream", "/api/classify", "/api/decide", "/api/feedback", "/api/labels"}
        if path not in routes:
            return self._send(404, {"error": "not found"})
        body = self._body()
        if body is None:
            return
        try:
            if path == "/api/classify":
                text = body.get("text")
                if not isinstance(text, str) or not text.strip():
                    return self._send(400, {"error": "text is required"})
                return self._send(200, classify(text, sensitivity=bool(body.get("sensitivity")),
                                                guard=bool(body.get("guard"))))
            if path in ("/api/guard", "/api/guard/stream", "/api/route/stream"):
                text = body.get("text")
                if not isinstance(text, str) or not text.strip():
                    return self._send(400, {"error": "text is required"})
                boundary = body.get("boundary", "prompt")
                if boundary not in BOUNDARIES:
                    return self._send(400, {"error": f"boundary must be one of {BOUNDARIES}"})
                if path == "/api/guard":
                    return self._send(200, inspect(text, boundary, use_lev=not body.get("no_lev")))
                if path == "/api/guard/stream":
                    return self._stream(guard_events(text, boundary, use_lev=not body.get("no_lev")))
                return self._stream(route_events(text))
            if path == "/api/decide":
                items = body.get("items")
                if not isinstance(items, list) or not all(isinstance(i, str) for i in items):
                    return self._send(400, {"error": "items must be a list of strings"})
                return self._send(200, decide(str(body.get("question", "")), body.get("kind", "yes_no"), items,
                                              options=body.get("options") or None, levels=body.get("levels") or None,
                                              context=body.get("context") or None))
            if path == "/api/labels":
                kind, item_id = body.get("kind"), body.get("id")
                seed = next((x for x in labels.seeds(kind) if x["id"] == item_id), None) if kind in labels.KINDS else None
                text = seed["text"] if seed else body.get("text")
                if seed is None:
                    if not isinstance(text, str) or not text.strip():
                        return self._send(400, {"error": "text is required"})
                    item_id = labels.text_id(text)
                rec = labels.append(kind, item_id, text, body.get("label"), "seed" if seed else "live",
                                    body.get("pred"), str(body.get("note", "")))
                return self._send(200, {"ok": True, "id": rec["id"], "label": rec["label"]})
            if path == "/api/feedback":
                rec = feedback.append(body.get("boundary", "prompt"), str(body.get("text", "")), body.get("got"),
                                      body.get("expected"), body.get("score"), body.get("findings") or [],
                                      str(body.get("note", "")))
                return self._send(200, {"ok": True, "correct": rec["correct"], "stats": feedback.stats()})
        except ValueError as e:
            return self._send(400, {"error": str(e)})


def serve(host="127.0.0.1", port=8740):
    if host not in LOOPBACK:
        raise SystemExit("refusing to bind a non-loopback address: the test bed has no authentication")
    srv = ThreadingHTTPServer((host, port), Handler)
    print(f"warden test bed on http://{host}:{port}  (config: {config.config_dir()})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
