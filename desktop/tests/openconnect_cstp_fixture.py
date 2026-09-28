"""An actual OpenConnect server (ocserv) and the two services it stands in
front of: a file and a SOCKS hop. Used inside an owned user/network namespace,
so the server, the tunnel device it raises per client and everything it serves
belong to that namespace alone. Every remote address served is recorded: what
arrives from the tunnel network came through the tunnel."""
import http.server
import ipaddress
import json
import os
from pathlib import Path
from select import select as wait_ready
import socket
import socketserver
import struct
import subprocess
import threading
import time

USER = 'cstp-user'
PASSWORD = 'cstp-password'
DEVICE = 'oc-cstp'
NETWORK = '10.81.0.0/24'
SERVER_ADDRESS = '10.81.0.1'
PORT = 4443
HTTP_PORT = 8080
SOCKS_PORT = 1080
BODY = b'cstp-fixture-body' + bytes(4096)


class Fixture:
    """Starts ocserv and the services behind it; loopback and the tunnel
    network of this namespace are the only addresses in play."""

    def __init__(self, root, tools):
        self.root = Path(root)
        self.tools = Path(tools)
        self.root.mkdir(parents=True, exist_ok=True)
        self.environment = {**os.environ, 'LD_LIBRARY_PATH': str(self.tools / 'usr/lib64')}
        self.cert = self.root / 'cert.pem'
        self.key = self.root / 'key.pem'
        self.requests = []
        self.hops = []
        self.servers = []
        self.log = None
        self.server = None

    def certificate(self):
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(self.key), '-out', str(self.cert), '-days', '1',
                        '-subj', '/CN=vpn.cstp.invalid',
                        '-addext', 'subjectAltName=IP:127.0.0.1,DNS:vpn.cstp.invalid',
                        '-addext', 'basicConstraints=critical,CA:TRUE',
                        '-addext', 'keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign',
                        '-addext', 'extendedKeyUsage=serverAuth'],
                       check=True, capture_output=True, timeout=60)
        self.key.chmod(0o600)

    def start(self, socket_directory):
        """`socket_directory` is short on purpose: a unix socket path is bounded."""
        self.certificate()
        passwd = self.root / 'passwd'
        subprocess.run([str(self.tools / 'usr/bin/ocpasswd'), '-c', str(passwd), USER],
                       input=f'{PASSWORD}\n{PASSWORD}\n', text=True, check=True,
                       env=self.environment, capture_output=True, timeout=30)
        config = self.root / 'ocserv.conf'
        config.write_text('\n'.join([
            f'auth = "plain[passwd={passwd}]"',
            f'tcp-port = {PORT}', f'udp-port = {PORT}',
            # Inside this namespace the fixture is root and owns nothing else.
            'run-as-user = root', 'run-as-group = root',
            f'socket-file = {socket_directory}/s',
            f'server-cert = {self.cert}', f'server-key = {self.key}',
            'max-clients = 8', 'max-same-clients = 4',
            'try-mtu-discovery = false', f'device = {DEVICE}',
            f'ipv4-network = {NETWORK.split("/")[0]}', 'ipv4-netmask = 255.255.255.0',
            f'dns = {SERVER_ADDRESS}', f'route = {NETWORK}',
            'cisco-client-compat = true', 'dtls-legacy = true', 'isolate-workers = false',
        ]) + '\n')
        self.log = (self.root / 'ocserv.log').open('w')
        self.server = subprocess.Popen(
            [str(self.tools / 'usr/bin/ocserv'), '-f', '-c', str(config), '-d', '1'],
            env=self.environment, stdout=self.log, stderr=subprocess.STDOUT)
        # The tunnel device is raised per client; the listening port is what
        # tells us the server is up.
        until = time.monotonic() + 20
        while time.monotonic() < until:
            with socket.socket() as probe:
                probe.settimeout(1)
                if probe.connect_ex(('127.0.0.1', PORT)) == 0:
                    break
            assert self.server.poll() is None, 'ocserv exited before it listened'
            time.sleep(.2)
        else:
            raise AssertionError('ocserv never listened')
        self.serve()
        return self.ready()

    def serve(self):
        requests, hops = self.requests, self.hops

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def do_GET(self):
                requests.append({'path': self.path, 'remote': self.client_address[0]})
                self.send_response(200)
                # Whoever asked is told where the request came from, so the
                # window's own checks can state that it came through the tunnel.
                self.send_header('X-Fixture-Remote', self.client_address[0])
                self.send_header('Content-Length', str(len(BODY)))
                self.end_headers()
                self.wfile.write(BODY)

            def log_message(self, *_):
                pass

        class Hop(socketserver.BaseRequestHandler):
            """A SOCKS hop behind the tunnel, so an OpenConnect endpoint can be
            the node a chain passes through on its way to its exit."""

            def handle(self):
                incoming, upstream = self.request, None
                inside = ipaddress.ip_address(self.client_address[0]) in ipaddress.ip_network(NETWORK)
                hops.append({'remote': self.client_address[0], 'tunnelled': inside})
                # Only the tunnel reaches this hop: a chain that gets through
                # it went through the CSTP session and nowhere else.
                if not inside:
                    return

                def read(count):
                    data = b''
                    while len(data) < count:
                        chunk = incoming.recv(count - len(data))
                        if not chunk:
                            raise EOFError()
                        data += chunk
                    return data

                try:
                    incoming.settimeout(10)
                    version, count = read(2)
                    if version != 5:
                        raise ValueError('SOCKS version')
                    read(count)
                    incoming.sendall(b'\x05\x00')
                    version, operation, reserved, kind = read(4)
                    if operation != 1:
                        raise ValueError('SOCKS operation')
                    host = read(read(1)[0]).decode() if kind == 3 else str(
                        ipaddress.ip_address(read(4 if kind == 1 else 16)))
                    port = struct.unpack('!H', read(2))[0]
                    if port != HTTP_PORT:
                        incoming.sendall(b'\x05\x05\x00\x01' + b'\x00' * 6)
                        return
                    upstream = socket.create_connection((host, port), timeout=10)
                    incoming.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
                    while True:
                        ready, _, _ = wait_ready([incoming, upstream], [], [], 10)
                        if not ready:
                            return
                        for source in ready:
                            data = source.recv(65536)
                            if not data:
                                return
                            (upstream if source is incoming else incoming).sendall(data)
                except (OSError, EOFError, ValueError):
                    pass
                finally:
                    if upstream:
                        upstream.close()

        class Threading(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        # The tunnel address only exists while a client holds the tunnel, so
        # both services listen on every address of the namespace and the
        # remote address of each request is what states where it came from.
        http_server = http.server.ThreadingHTTPServer(('0.0.0.0', HTTP_PORT), Handler)
        http_server.daemon_threads = True
        self.servers.append(http_server)
        self.servers.append(Threading(('0.0.0.0', SOCKS_PORT), Hop))
        for server in self.servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()

    def ready(self):
        return {'server': f'https://127.0.0.1:{PORT}/', 'certificate': str(self.cert),
                'user': USER, 'password': PASSWORD, 'device': DEVICE,
                'serverAddress': SERVER_ADDRESS, 'network': NETWORK,
                'httpPort': HTTP_PORT, 'socksPort': SOCKS_PORT, 'body': len(BODY),
                # The server states its own version on its diagnostic stream.
                'version': subprocess.run([str(self.tools / 'usr/bin/ocserv'), '--version'],
                                          env=self.environment, stdout=subprocess.PIPE,
                                          stderr=subprocess.STDOUT,
                                          text=True).stdout.splitlines()[0]}

    def tunnelled(self):
        """Whether the tunnel is what carried the traffic: the hop was only ever
        reached from inside it, and a request arrived from it directly. What the
        hop itself fetches is dialled from this namespace, so it is not counted."""
        network = ipaddress.ip_network(NETWORK)
        inside = lambda row: ipaddress.ip_address(row['remote']) in network
        return (bool(self.requests) and any(inside(row) for row in self.requests)
                and bool(self.hops) and all(inside(row) for row in self.hops))

    def close(self):
        for server in self.servers:
            server.shutdown()
            server.server_close()
        if self.server:
            self.server.terminate()
            try:
                self.server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.server.kill()
                self.server.wait(timeout=5)
        if self.log:
            self.log.close()
        return {'requests': self.requests, 'hops': self.hops, 'tunnelled': self.tunnelled(),
                'deviceRemoved': DEVICE not in subprocess.run(
                    ['ip', '-br', 'link'], capture_output=True, text=True).stdout}

    def observations(self):
        return json.dumps({'requests': self.requests, 'hops': self.hops}, indent=2) + '\n'
