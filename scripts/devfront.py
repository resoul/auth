#!/usr/bin/env python3
"""One origin in front of the browser example and the API, for real-device tests.

A passkey is bound to a host, and a browser sends the refresh cookie only to the origin that set
it, so the page and the API must answer on the same host. This server gives them one: the files
of examples/browser (index.html, app.js and qrcodegen.js, nothing else) and the routes of the API
(/v1/, /health/ and /.well-known/), which it forwards to the API on loopback. A tunnel such as
Cloudflare Tunnel points at this server and supplies the HTTPS host.

    devfront.py [--listen 127.0.0.1:5173] [--api 127.0.0.1:8080]

It adds the address of the peer to X-Forwarded-For, so the API (with this peer in
AIRLANCE_AUTH_TRUSTED_PROXIES) sees the client the tunnel reports. It forwards the Host header as it
arrived, so the API's own-origin check compares the public host. Only the standard library is used.
"""
import argparse
import http.client
import http.server
import os
import socketserver
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "examples", "browser")
FILES = {"/": ("index.html", "text/html; charset=utf-8"), "/index.html": ("index.html", "text/html; charset=utf-8"),
         "/app.js": ("app.js", "text/javascript; charset=utf-8"),
         "/qrcodegen.js": ("qrcodegen.js", "text/javascript; charset=utf-8")}
FORWARDED = ("/v1/", "/health/", "/.well-known/")
# Headers that belong to one connection, not to the message (RFC 9110, section 7.6.1).
HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer",
              "transfer-encoding", "upgrade"}


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    api = ("127.0.0.1", 8080)

    def log_message(self, fmt, *args):
        # Method and path only: a query or a header could carry a secret. A connection that sent no
        # request line has neither.
        if self.command is None:
            return
        sys.stderr.write("devfront: %s %s\n" % (self.command, self.path.split("?", 1)[0]))

    def do_GET(self):
        self.route()

    do_HEAD = do_POST = do_PATCH = do_DELETE = do_OPTIONS = do_GET

    def route(self):
        path = self.path.split("?", 1)[0]
        if path.startswith(FORWARDED):
            self.forward()
        elif path in FILES and self.command in ("GET", "HEAD"):
            self.static(*FILES[path])
        else:
            self.reply(404, b"not found\n", "text/plain; charset=utf-8")

    def reply(self, status, body, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def static(self, name, content_type):
        with open(os.path.join(ROOT, name), "rb") as f:
            self.reply(200, f.read(), content_type)

    def forward(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP_BY_HOP}
        peer = self.client_address[0]
        headers["X-Forwarded-For"] = ", ".join(filter(None, [self.headers.get("X-Forwarded-For"), peer]))
        conn = http.client.HTTPConnection(*self.api, timeout=30)
        try:
            conn.request(self.command, self.path, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
        except OSError:
            self.reply(502, b"the API is not reachable\n", "text/plain; charset=utf-8")
            return
        finally:
            conn.close()
        self.send_response(resp.status)
        for key, value in resp.getheaders():
            if key.lower() not in HOP_BY_HOP | {"content-length", "date", "server"}:
                self.send_header(key, value)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def hostport(text):
    host, _, port = text.rpartition(":")
    return host or "127.0.0.1", int(port)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--listen", default="127.0.0.1:5173")
    parser.add_argument("--api", default="127.0.0.1:8080")
    args = parser.parse_args()
    listen = hostport(args.listen)
    if listen[0] not in ("127.0.0.1", "::1", "localhost"):
        sys.exit("devfront listens on loopback only; the tunnel is what faces the network")
    Handler.api = hostport(args.api)
    print("devfront: http://%s:%d -> API %s:%d" % (listen + Handler.api), file=sys.stderr, flush=True)
    Server(listen, Handler).serve_forever()


if __name__ == "__main__":
    main()
