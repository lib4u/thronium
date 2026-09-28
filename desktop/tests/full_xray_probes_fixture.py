"""Owned HTTP/HTTPS and DNS servers for complete Xray client-policy probes."""
import http.server
import json
import socket
import socketserver
import struct
import threading
import time
from warp_registration_fixture import Fixture as Transport


class Fixture(Transport):
    def __init__(self, directory, *, hosts=('allowed.probe.test', 'blocked.probe.test', 'ipblocked.probe.test')):
        super().__init__(directory, hosts=hosts)
        fixture = self
        self.state['dnsQueries'] = []

        class Origin(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def log_message(self, *_): pass
            def do_GET(self):
                with fixture.lock:
                    mode = fixture.state['mode']
                    fixture.state['active'] += 1
                    fixture.state['requests'].append({'host': self.headers.get('Host'), 'path': self.path, 'mode': mode})
                try:
                    if mode == 'hold': fixture.release.wait(20)
                    time.sleep(.03)
                    self.send_response(503 if self.path == '/status' else 204)
                    self.send_header('Content-Length', '0')
                    self.send_header('Connection', 'close')
                    self.end_headers()
                except OSError:
                    pass
                finally:
                    with fixture.lock: fixture.state['active'] -= 1

        class DNS(socketserver.BaseRequestHandler):
            def handle(self):
                data, channel = self.request
                end = 12; labels = []
                while data[end]:
                    length = data[end]; assert length < 64
                    labels.append(data[end + 1:end + 1 + length].decode('ascii'))
                    end += 1 + length
                end += 1
                kind, cls = struct.unpack('!HH', data[end:end + 4]); assert kind in (1, 28) and cls == 1
                name = '.'.join(labels).lower()
                with fixture.lock:
                    fixture.state['dnsQueries'].append({'name': name, 'kind': kind})
                    failed = fixture.state['mode'] == 'dns-fail'
                answer = b''
                if kind == 1 and not failed:
                    address = '192.0.2.88' if name == 'ipblocked.probe.test' else '127.0.0.1'
                    answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 0, 4) + socket.inet_aton(address)
                response = data[:2] + (b'\x81\x82' if failed else b'\x81\x80') + struct.pack('!HHHH', 1, int(bool(answer)), 0, 0) + data[12:end + 4] + answer
                channel.sendto(response, self.client_address)

        class Admin(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                with fixture.lock: body = json.dumps(fixture.state).encode()
                self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
            def do_POST(self):
                value = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))))
                with fixture.lock:
                    if 'mode' in value:
                        assert value['mode'] in ('ok', 'hold', 'dns-fail')
                        fixture.state['mode'] = value['mode']
                        if value['mode'] == 'hold': fixture.release.clear()
                        else: fixture.release.set()
                    if value.get('release'): fixture.release.set()
                    if value.get('clear'):
                        fixture.state['requests'] = []
                        fixture.state['dnsQueries'] = []
                self.do_GET()

        self.api.RequestHandlerClass = Origin
        self.admin.RequestHandlerClass = Admin
        self.http = type(self.api)(('127.0.0.1', 0), Origin)
        self.dns = socketserver.UDPServer(('127.0.0.1', 0), DNS)
        for server in [self.http, self.dns]:
            self.servers.append(server)
            thread = threading.Thread(target=server.serve_forever)
            thread.start(); self.threads.append(thread)
        self.info.update(httpPort=self.http.server_port, dnsPort=self.dns.server_address[1])
        self.path.write_text(json.dumps(self.info))
