"""Two owned TLS IP services plus HTTP/stream targets for country selectors."""
import http.server
import json
from pathlib import Path
import threading
import time
from diagnostics_fixture import Fixture as BaseFixture


class Fixture:
    def __init__(self, directory):
        directory = Path(directory)
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.peers = []
        self.lock = threading.Lock()
        self.streams = 0
        try:
            for index in range(2):
                peer = BaseFixture(directory / str(index))
                self.peers.append(peer)
                peer.http.RequestHandlerClass = self.handler(index)
            # Both proxy exits may reach the two targets owned by this fixture.
            for peer in self.peers:
                peer.ports.extend(p.http.server_port for p in self.peers if p is not peer)
            self.cert = directory / 'country-ca.pem'
            self.cert.write_bytes(b'\n'.join(p.cert.read_bytes() for p in self.peers))
            servers = {s for p in self.peers for s in p.servers}
            self.threads = [t for t in threading.enumerate() if getattr(getattr(t, '_target', None), '__self__', None) in servers]
            assert len(self.threads) == len(servers)
            self.info = {
                'ports': [p.ports[2] for p in self.peers],
                'httpPorts': [p.http.server_port for p in self.peers],
                'admins': [p.info['admin'] for p in self.peers],
                'cert': str(self.cert),
            }
            self.path = directory / 'fixture.json'
            self.path.write_text(json.dumps(self.info))
        except BaseException:
            for peer in self.peers:
                peer.close()
            raise

    def handler(self, index):
        fixture = self

        class HTTP(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                stream = self.path == '/stream'
                body = b'' if self.path == '/health' else (b'ready' if stream else ('country45:' + str(index)).encode())
                self.send_response(204 if self.path == '/health' else 200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                self.wfile.flush()
                if not stream:
                    return
                self.connection.settimeout(10)
                with fixture.lock:
                    fixture.streams += 1
                try:
                    while True:
                        data = self.connection.recv(4096)
                        if not data:
                            break
                        self.connection.sendall(data)
                except OSError:
                    pass
                finally:
                    with fixture.lock:
                        fixture.streams -= 1

        return HTTP

    def close(self):
        for peer in self.peers:
            peer.close()
        for thread in self.threads:
            thread.join(5)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            active = []
            for peer in self.peers:
                with peer.lock:
                    active.append((len(peer.sockets), peer.state['active']))
            with self.lock:
                streams = self.streams
            if not streams and not any(s or a for s, a in active):
                break
            time.sleep(.03)
        return {
            'socketCount': sum(s for s, _ in active),
            'active': sum(a for _, a in active),
            'streamCount': streams,
            'serviceThreadsReaped': all(not t.is_alive() for t in self.threads),
            'serverSocketsClosed': all(s.socket.fileno() == -1 for p in self.peers for s in p.servers),
        }
