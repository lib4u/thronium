"""Owned dashboard download transport; no route to public GitHub is required."""
import http.server
import io
import json
from pathlib import Path
import ssl
import zipfile
from warp_registration_fixture import Fixture as Transport


def archive(files):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', zipfile.ZIP_DEFLATED) as output:
        for name, content in files.items(): output.writestr(name, content)
    return stream.getvalue()


class Fixture(Transport):
    def __init__(self, directory, official_archive):
        super().__init__(directory, hosts=('github.com', 'codeload.github.com'))
        fixture = self
        official = Path(official_archive).read_bytes()
        updated = archive({'release/index.html': '<!doctype html><title>Owned update62</title><p>Owned updated dashboard</p>'})
        invalid = archive({'../escape': 'must never be written', 'index.html': 'bad'})

        class API(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def log_message(self, *_): pass
            def do_GET(self):
                with fixture.lock:
                    mode = fixture.state['mode']; fixture.state['active'] += 1
                    fixture.state['requests'].append({'path': self.path, 'host': self.headers.get('Host'), 'mode': mode})
                try:
                    if mode == 'hold': fixture.release.wait(20)
                    body = updated if mode == 'updated' else invalid if mode == 'traversal' else b'private-dashboard-response62' if mode == 'malformed' else official
                    code = 503 if mode == 'http-error' else 200
                    location = None
                    if self.headers.get('Host') == 'github.com' and mode in ('ok', 'updated'):
                        code = 302; location = 'https://codeload.github.com/SagerNet/sing-box-dashboard/zip/refs/heads/gh-pages'
                    if mode in ('foreign', 'downgrade'):
                        code = 302; location = 'https://untrusted.invalid/dashboard.zip' if mode == 'foreign' else 'http://github.com/dashboard.zip'
                    if location: body = b''
                    self.send_response(code); self.send_header('Connection', 'close')
                    if location: self.send_header('Location', location)
                    if mode == 'chunked':
                        self.send_header('Transfer-Encoding', 'chunked'); self.end_headers()
                        for _ in range(513):
                            chunk = b' ' * 65536; self.wfile.write(b'10000\r\n' + chunk + b'\r\n')
                        self.wfile.write(b'0\r\n\r\n')
                    else:
                        self.send_header('Content-Length', str(32 * 1024 * 1024 + 1 if mode == 'oversize' else len(body))); self.end_headers()
                        if mode != 'oversize': self.wfile.write(body)
                except (OSError, ssl.SSLError): pass
                finally:
                    with fixture.lock: fixture.state['active'] -= 1

        class Admin(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                with fixture.lock: body = json.dumps(fixture.state).encode()
                self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
            def do_POST(self):
                value = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))))
                with fixture.lock:
                    if 'mode' in value:
                        assert value['mode'] in ('ok', 'updated', 'traversal', 'hold', 'http-error', 'malformed', 'oversize', 'chunked', 'foreign', 'downgrade')
                        fixture.state['mode'] = value['mode']
                        if value['mode'] == 'hold': fixture.release.clear()
                        else: fixture.release.set()
                    if value.get('release'): fixture.release.set()
                self.do_GET()
        self.api.RequestHandlerClass = API; self.admin.RequestHandlerClass = Admin
