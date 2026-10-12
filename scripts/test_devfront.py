"""Tests of scripts/devfront.py: what it serves, what it forwards and what it adds."""
import http.client
import http.server
import threading
import unittest

import devfront


class FakeAPI(http.server.BaseHTTPRequestHandler):
    seen = []

    def log_message(self, *args):
        pass

    def respond(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        FakeAPI.seen.append((self.command, self.path, dict(self.headers.items()), body))
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", "a=1; Secure")
        self.send_header("Set-Cookie", "b=2; Secure")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    do_GET = do_POST = do_DELETE = respond


def serve(handler, **attrs):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    for key, value in attrs.items():
        setattr(handler, key, value)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class DevFrontTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = serve(FakeAPI)
        handler = type("Bound", (devfront.Handler,), {"api": ("127.0.0.1", cls.api.server_port)})
        cls.front = devfront.Server(("127.0.0.1", 0), handler)
        threading.Thread(target=cls.front.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.front.shutdown()
        cls.api.shutdown()

    def setUp(self):
        FakeAPI.seen.clear()

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.front.server_port, timeout=5)
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp, data

    def test_serves_the_page_and_its_script_and_nothing_else(self):
        for path, marker in (("/", b"<!doctype html>"), ("/index.html", b"<!doctype html>"),
                             ("/app.js", b"'use strict'"), ("/qrcodegen.js", b"Project Nayuki")):
            resp, data = self.request("GET", path)
            self.assertEqual(resp.status, 200, path)
            self.assertIn(marker, data, path)
            self.assertEqual(resp.getheader("Cache-Control"), "no-store")
        for path in ("/go.mod", "/README.md", "/../go.mod", "/metrics", "/.env", "/examples/browser/app.js"):
            resp, _ = self.request("GET", path)
            self.assertEqual(resp.status, 404, path)
        self.assertEqual(FakeAPI.seen, [], "a refused path reached the API")

    def test_the_page_cannot_be_written(self):
        resp, _ = self.request("POST", "/app.js", body=b"x")
        self.assertEqual(resp.status, 404)

    def test_forwards_the_api_routes_with_body_and_every_cookie(self):
        resp, data = self.request("POST", "/v1/auth/email/start?x=1", body=b'{"email":"a"}',
                                  headers={"Content-Type": "application/json", "Host": "id.example.test",
                                           "Cookie": "c=3", "X-Forwarded-For": "203.0.113.7", "Connection": "keep-alive"})
        self.assertEqual((resp.status, data), (201, b"{}"))
        self.assertEqual(resp.getheader("Set-Cookie"), "a=1; Secure, b=2; Secure")
        method, path, headers, body = FakeAPI.seen[0]
        self.assertEqual((method, path, body), ("POST", "/v1/auth/email/start?x=1", b'{"email":"a"}'))
        # The public host arrives as sent, so the API's own-origin check compares it.
        self.assertEqual(headers["Host"], "id.example.test")
        self.assertEqual(headers["Cookie"], "c=3")
        # The tunnel's client address is kept and the peer is added after it.
        self.assertEqual(headers["X-Forwarded-For"], "203.0.113.7, 127.0.0.1")

    def test_forwards_health_and_the_key_set_but_not_metrics(self):
        for path in ("/health/ready", "/.well-known/jwks.json", "/v1/native/me"):
            resp, _ = self.request("GET", path)
            self.assertEqual(resp.status, 201, path)
        resp, _ = self.request("GET", "/metrics")
        self.assertEqual(resp.status, 404)

    def test_an_unreachable_api_is_a_bad_gateway(self):
        handler = type("Dead", (devfront.Handler,), {"api": ("127.0.0.1", 1)})
        server = devfront.Server(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
            conn.request("GET", "/health/ready")
            self.assertEqual(conn.getresponse().status, 502)
        finally:
            server.shutdown()

    def test_refuses_to_listen_off_loopback(self):
        import subprocess
        import sys
        import os
        script = os.path.join(os.path.dirname(os.path.abspath(devfront.__file__)), "devfront.py")
        result = subprocess.run([sys.executable, script, "--listen", "0.0.0.0:0"], capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("loopback", result.stderr)


if __name__ == "__main__":
    unittest.main()
