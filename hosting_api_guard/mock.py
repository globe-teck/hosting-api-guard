"""Offline mock of a Module::function panel API server with example data (example.com, fake tokens)."""
import json, posixpath, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

FAKE_TOKEN = "EXAMPLE0FAKE0TOKEN0000000000TEST"
USER = "exampleuser"


class MockPanel:
    def __init__(self):
        root = "/home/%s/public_html" % USER
        self.files = {root + "/index.html": "<h1>example.com</h1>\n",
                      root + "/.htaccess": "# placeholder\n",
                      root + "/wp-config.php": "define('DB_PASSWORD','not-a-real-password');\n"}
        self.calls = []

    def __call__(self, func, params):
        self.calls.append(func)
        d, f = params.get("dir"), params.get("file")
        path = posixpath.join(d or "/home/%s/public_html" % USER, f or "")
        if func == "DomainInfo::list_domains":
            return {"status": 1, "data": {"main_domain": "example.com", "addon_domains": ["example.net"]}}
        if func == "Fileman::list_files":
            return {"status": 1, "data": [{"file": posixpath.basename(p)} for p in self.files]}
        if func == "Fileman::get_file_content":
            if path not in self.files:
                return {"status": 0, "errors": ["not found"], "data": None}
            return {"status": 1, "data": {"content": self.files[path]}}
        if func == "Fileman::save_file_content":
            self.files[path] = params.get("content", "")
            return {"status": 1, "data": {"path": path}}
        if func == "Boom::fetch":
            raise RuntimeError("upstream said: token=%s user %s" % (FAKE_TOKEN, USER))
        return {"status": 1, "data": {"func": func}}


def serve(panel, host="127.0.0.1", port=0):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.headers.get("Authorization") != "panel %s:%s" % (USER, FAKE_TOKEN):
                self.send_response(401); self.end_headers(); return
            u = urlparse(self.path)
            parts = u.path.strip("/").split("/")
            params = {k: v[0] for k, v in parse_qs(u.query).items()}
            body = json.dumps(panel("%s::%s" % (parts[1], parts[2]), params)).encode()
            self.send_response(200); self.end_headers(); self.wfile.write(body)

    srv = ThreadingHTTPServer((host, port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv
