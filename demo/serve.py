import http.server, socketserver, urllib.request, urllib.error, os, functools
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "dashboard")
API = "http://127.0.0.1:8000"

class H(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=ROOT, **k)
    def _proxy(self, body=None):
        req = urllib.request.Request(API + self.path, data=body,
            headers={"Content-Type": self.headers.get("Content-Type", "application/json")},
            method=self.command)
        try:
            with urllib.request.urlopen(req, timeout=300) as r:
                data = r.read(); code = r.status
        except urllib.error.HTTPError as e:
            data = e.read(); code = e.code
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        if self.path.startswith("/api/"): return self._proxy()
        return super().do_GET()
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self._proxy(self.rfile.read(n))
    def log_message(self, *a): pass

socketserver.ThreadingTCPServer.allow_reuse_address = True
with socketserver.ThreadingTCPServer(("127.0.0.1", 8080), H) as s:
    s.serve_forever()
