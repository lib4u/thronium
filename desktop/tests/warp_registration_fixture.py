"""Owned WARP HTTPS service and SOCKS hop; used only in a private network namespace."""
import base64
import contextlib
import http.server
import ipaddress
import json
import os
from pathlib import Path
import select
import socket
import socketserver
import ssl
import struct
import subprocess
import threading


class Fixture:
    def __init__(self, directory, *, hosts=('api.cloudflareclient.com',)):
        assert os.getpid() == 1 and os.geteuid() == 0
        assert os.readlink('/proc/self/ns/net') != os.environ['THRONIUM_TEST_ORIGINAL_NETNS']
        assert hosts and all(host.replace('.', '').isalnum() for host in hosts)
        subject = '/CN=' + hosts[0]; san = 'subjectAltName=' + ','.join('DNS:' + host for host in hosts)
        directory = Path(directory); directory.mkdir(parents=True, exist_ok=True)
        self.cert = directory / 'ca.pem'; ca_key = directory / 'ca.key'; key = directory / 'warp.key'; leaf = directory / 'warp.pem'; csr = directory / 'warp.csr'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(ca_key), '-out', str(self.cert), '-days', '1', '-subj', subject, '-addext', san, '-addext', 'basicConstraints=critical,CA:TRUE'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(csr), '-subj', subject], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        extensions = directory / 'leaf.ext'; extensions.write_text(san + '\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
        subprocess.run(['openssl', 'x509', '-req', '-in', str(csr), '-CA', str(self.cert), '-CAkey', str(ca_key), '-CAcreateserial', '-out', str(leaf), '-days', '1', '-extfile', str(extensions)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        key.chmod(0o600); ca_key.chmod(0o600)
        self.lock = threading.Lock(); self.release = threading.Event(); self.release.set()
        self.sockets = set(); self.threads = []; self.servers = []
        self.state = {'mode': 'ok', 'requests': [], 'active': 0, 'proxyConnections': []}
        self.response = {'id': 'private-account-canary61', 'token': 'private-token-canary61', 'config': {'client_id': base64.b64encode(bytes([0, 128, 255])).decode(), 'interface': {'addresses': {'v4': '172.16.0.2', 'v6': '2606:4700:110:8c5a::2'}}, 'peers': [{'public_key': base64.b64encode(bytes([3]) * 32).decode(), 'endpoint': {'host': 'engage.cloudflareclient.com:2408'}}]}}
        fixture = self

        class Server(http.server.ThreadingHTTPServer):
            daemon_threads = False
            def process_request_thread(self, request, address):
                with fixture.lock: fixture.sockets.add(request)
                try: super().process_request_thread(request, address)
                finally:
                    with fixture.lock: fixture.sockets.discard(request)

        class API(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            def log_message(self, *_): pass
            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get('Content-Length', 0)))
                value = json.loads(raw)
                with fixture.lock:
                    mode = fixture.state['mode']; fixture.state['active'] += 1
                    fixture.state['requests'].append({'path': self.path, 'body': value, 'userAgent': self.headers.get('User-Agent'), 'contentType': self.headers.get('Content-Type'), 'mode': mode})
                try:
                    if mode == 'hold': fixture.release.wait(15)
                    body = json.dumps(fixture.response).encode()
                    if mode == 'malformed': body = b'private-response-canary61: not JSON'
                    if mode in ('oversize', 'chunked'): body = b' ' * (256 * 1024 + 1)
                    code = 429 if mode == 'http-error' else 307 if mode == 'redirect' else 200
                    self.send_response(code)
                    self.send_header("Connection", "close")
                    if mode == 'redirect': self.send_header('Location', 'https://api.cloudflareclient.com/redirected')
                    if mode == 'chunked':
                        self.send_header('Transfer-Encoding', 'chunked'); self.end_headers()
                        for offset in range(0, len(body), 16384):
                            chunk = body[offset:offset + 16384]
                            self.wfile.write(('%x\r\n' % len(chunk)).encode() + chunk + b'\r\n')
                        self.wfile.write(b'0\r\n\r\n')
                    else:
                        self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError): pass
                finally:
                    with fixture.lock: fixture.state['active'] -= 1

        self.api = Server(('127.0.0.1', 443), API)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(leaf, key)
        self.api.socket = ctx.wrap_socket(self.api.socket, server_side=True); self.servers.append(self.api)

        class SocksServer(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = False

        class Socks(socketserver.BaseRequestHandler):
            def handle(self):
                incoming = self.request; upstream = None
                with fixture.lock: fixture.sockets.add(incoming)
                def read(count):
                    value = b''
                    while len(value) < count:
                        chunk = incoming.recv(count - len(value))
                        if not chunk: raise EOFError()
                        value += chunk
                    return value
                try:
                    incoming.settimeout(12)
                    version, count = read(2); assert version == 5
                    read(count); incoming.sendall(b'\x05\x00')
                    version, operation, _, kind = read(4); assert version == 5 and operation == 1
                    host = read(read(1)[0]).decode() if kind == 3 else str(ipaddress.ip_address(read(4 if kind == 1 else 16)))
                    port = struct.unpack('!H', read(2))[0]
                    with fixture.lock: fixture.state['proxyConnections'].append([host, port])
                    assert host in (*hosts, '127.0.0.1') and port == 443
                    upstream = socket.create_connection(('127.0.0.1', 443), timeout=12)
                    with fixture.lock: fixture.sockets.add(upstream)
                    incoming.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
                    while True:
                        ready, _, _ = select.select([incoming, upstream], [], [], 12)
                        if not ready: break
                        for source in ready:
                            value = source.recv(65536)
                            if not value: return
                            (upstream if source is incoming else incoming).sendall(value)
                except (OSError, EOFError, ValueError, AssertionError): pass
                finally:
                    if upstream: upstream.close()
                    with fixture.lock: fixture.sockets.discard(incoming); fixture.sockets.discard(upstream)

        self.socks = SocksServer(('127.0.0.1', 0), Socks); self.servers.append(self.socks)

        class Admin(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                with fixture.lock: body = json.dumps(fixture.state).encode()
                self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
            def do_POST(self):
                value = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))))
                with fixture.lock:
                    if 'mode' in value:
                        assert value['mode'] in ('ok', 'hold', 'http-error', 'malformed', 'oversize', 'chunked', 'redirect')
                        fixture.state['mode'] = value['mode']
                        if value['mode'] == 'hold': fixture.release.clear()
                        else: fixture.release.set()
                    if value.get('release'): fixture.release.set()
                self.do_GET()

        self.admin = Server(('127.0.0.1', 0), Admin); self.servers.append(self.admin)
        for server in self.servers:
            thread = threading.Thread(target=server.serve_forever); thread.start(); self.threads.append(thread)
        self.info = {'admin': 'http://127.0.0.1:%d/' % self.admin.server_port, 'socksPort': self.socks.server_address[1], 'peerPublicKey': self.response['config']['peers'][0]['public_key'], 'cert': str(self.cert)}
        self.path = directory / 'fixture.json'; self.path.write_text(json.dumps(self.info))

    def close(self):
        self.release.set()
        for server in self.servers: server.shutdown()
        with self.lock: sockets = list(self.sockets)
        for stream in sockets:
            with contextlib.suppress(OSError): stream.shutdown(socket.SHUT_RDWR)
            with contextlib.suppress(OSError): stream.close()
        for server in self.servers: server.server_close()
        for thread in self.threads: thread.join(timeout=3)
        return {'serviceThreadsReaped': all(not t.is_alive() for t in self.threads), 'serverSocketsClosed': all(s.socket.fileno() == -1 for s in self.servers), 'socketCount': len(self.sockets), 'active': self.state['active'], 'requests': self.state['requests'], 'proxyConnections': self.state['proxyConnections']}
