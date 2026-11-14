"""
Real-time receiver for Wazuh (or any JSON alert source).

    python3 -m soar.webhook --port 8088

POST one alert (or a JSON list of alerts) to /alert and BlueShield writes a case for it.
GET /health returns {"status": "ok"}.

The receiver has no authentication, so it binds to 127.0.0.1 by default. Only use
--host 0.0.0.0 on an isolated lab network.
"""
from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from soar.engine import process_events, write_cases

MAX_BODY = 1_000_000  # 1 MB per request


def make_handler(intel_dir: Path, out_dir: Path):
    class AlertHandler(BaseHTTPRequestHandler):
        server_version = "BlueShield/1.0"

        def _reply(self, code: int, body: dict) -> None:
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):  # noqa: N802 (http.server naming)
            if self.path == "/health":
                self._reply(200, {"status": "ok"})
            else:
                self._reply(404, {"error": "not found"})

        def do_POST(self):  # noqa: N802
            if self.path != "/alert":
                return self._reply(404, {"error": "not found"})
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > MAX_BODY:
                return self._reply(413 if length > MAX_BODY else 400, {"error": "bad body size"})
            try:
                payload = json.loads(self.rfile.read(length))
            except json.JSONDecodeError:
                return self._reply(400, {"error": "invalid JSON"})
            events = payload if isinstance(payload, list) else [payload]
            if not all(isinstance(e, dict) for e in events):
                return self._reply(400, {"error": "expected a JSON object or a list of objects"})

            cases = process_events(events, intel_dir)
            write_cases(cases, out_dir)
            self._reply(200, {"cases": [{"case_id": c["case_id"], "priority": c["priority"],
                                         "score": c["score"], "summary": c["summary"]} for c in cases]})

        def log_message(self, fmt, *args):  # quieter default logging
            sys.stderr.write("[blueshield] " + (fmt % args) + "\n")

    return AlertHandler


def serve(host: str, port: int, intel_dir: Path, out_dir: Path) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), make_handler(intel_dir, out_dir))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="BlueShield real-time alert receiver")
    ap.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8088)
    ap.add_argument("--intel", type=Path, default=Path("intel"))
    ap.add_argument("--out", type=Path, default=Path("cases"))
    args = ap.parse_args(argv)

    httpd = serve(args.host, args.port, args.intel, args.out)
    print(f"BlueShield listening on http://{args.host}:{args.port}/alert (Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
