"""Owned IP2Location and Speedtest.net HTTPS services for isolated measurements.

Shared by the VPN and WireGuard diagnostics stands; each stand
adds the tunnel that makes the services reachable and its own admin cases.
"""
import http.server
import json

from speedtest_full_fixture import Fixture as SpeedFixture

HOSTS = ('api.ip2location.io', 'www.speedtest.net', 'speed.peer.test')
MODES = ('ok', 'ip-http', 'ip-invalid', 'ip-v6', 'ip-unknown',
         'api-http', 'api-invalid', 'api-empty', 'latency-http',
         'download-http', 'upload-http', 'download-empty', 'download-truncated',
         'hold-ip', 'hold-api', 'hold-download', 'hold-upload')


class Fixture(SpeedFixture):
    def __init__(self, directory, *, hosts=HOSTS):
        super().__init__(directory, hosts=hosts)
        owner = self
        speed_origin = self.api.RequestHandlerClass

        # A disposable tunnel may vanish while its TCP/TLS handshake is pending.
        # Handshake in the tracked request worker, not the sole accept loop.
        self.api.socket.do_handshake_on_connect = False

        class Origin(speed_origin):
            def setup(self):
                self.request.settimeout(3)
                super().setup()
            def do_GET(self):
                if self.headers.get('Host', '').split(':')[0] != hosts[0]:
                    return super().do_GET()
                mode, _ = self.start('ip')
                try:
                    body = json.dumps({'ip': '203.0.113.9', 'country_code': 'JP'}).encode()
                    if mode == 'ip-invalid': body = b'{owned invalid IP response'
                    if mode == 'ip-v6': body = b'{"ip":"2001:db8::9","country_code":"JP"}'
                    if mode == 'ip-unknown': body = b'{"ip":"203.0.113.9","country_code":"ZZ"}'
                    self.send(503 if mode == 'ip-http' else 200, body, 'application/json')
                except OSError:
                    pass
                finally:
                    self.end()

        class Admin(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                with owner.lock: body = json.dumps(owner.state).encode()
                self.send_response(200); self.send_header('Content-Length', str(len(body)))
                self.end_headers(); self.wfile.write(body)
            def do_POST(self):
                values = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))))
                with owner.lock:
                    if 'mode' in values:
                        mode = values['mode']
                        assert mode in MODES
                        owner.state['mode'] = mode
                        if mode.startswith('hold-'): owner.release.clear()
                        else: owner.release.set()
                    if values.get('release'): owner.release.set()
                    if values.get('clear'):
                        assert owner.state['active'] == 0
                        owner.state['requests'] = []; owner.state['dnsQueries'] = []
                        owner.state['downloadBytes'] = owner.state['uploadBytes'] = 0
                self.do_GET()

        self.api.RequestHandlerClass = self.http.RequestHandlerClass = Origin
        self.admin.RequestHandlerClass = Admin
