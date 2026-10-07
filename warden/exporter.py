"""warden exporter: read-only HTTP endpoints for monitoring.

  warden exporter [--host 127.0.0.1] [--port 9740]

  GET /metrics   Prometheus text format (metrics.py)
  GET /healthz   health.check() as JSON; 200 when ok or degraded, 503 when down

Serves counts and health only (no text, no config, no POST), so it may bind a tailnet address for a remote
Prometheus. It still has no authentication: bind loopback or a private interface, never a public one.
"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import config, telemetry
from .metrics import Collector


def make_handler(collector):
    class Handler(BaseHTTPRequestHandler):
        server_version = "warden-exporter"
        sys_version = ""

        def log_message(self, fmt, *args):
            pass                                     # scrapes every 15 s would drown the journal

        def _send(self, code, data, ctype):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            path = self.path.split("?")[0]
            try:
                if path == "/metrics":
                    return self._send(200, collector.render().encode(), "text/plain; version=0.0.4; charset=utf-8")
                if path == "/healthz":
                    h = collector.check_health(ttl=2.0)
                    return self._send(503 if h["status"] == "down" else 200, json.dumps(h).encode(),
                                      "application/json")
                return self._send(404, b'{"error": "not found"}', "application/json")
            except Exception as e:                   # noqa: BLE001 - report, keep serving
                return self._send(500, json.dumps({"error": f"{type(e).__name__}: {e}"[:300]}).encode(),
                                  "application/json")

    return Handler


def serve(host="127.0.0.1", port=9740):
    collector = Collector()
    collector.poll()                                 # count what's already in the log before the first scrape
    srv = ThreadingHTTPServer((host, port), make_handler(collector))
    print(f"warden exporter on http://{host}:{port}/metrics  (events: {telemetry.path()}, config: {config.config_dir()})",
          flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
