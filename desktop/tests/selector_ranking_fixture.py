"""Per-proxy HTTP delay/failure on owned SOCKS fixtures, without external traffic."""
import socket
import time
from selector_country_fixture import Fixture as CountryFixture


class Fixture(CountryFixture):
    def __init__(self, directory):
        super().__init__(directory)
        for peer in self.peers:
            peer.state['rankingRequests'] = 0
            server = next(s for s in peer.servers if getattr(s, 'index', None) == 2)
            server.RequestHandlerClass = self.delayed(server.RequestHandlerClass, peer)

    @staticmethod
    def delayed(original, peer):
        class DelayedSocket:
            def __init__(self, sock): self.sock = sock
            def __getattr__(self, name): return getattr(self.sock, name)
            def recv(self, size, *args):
                data = self.sock.recv(size, *args)
                # The base SOCKS handler uses small exact reads for its handshake
                # and 65536-byte reads for forwarded application traffic.
                if size == 65536:
                    while data in (b'G', b'GE', b'GET', b'H', b'HE', b'HEA', b'HEAD'):
                        more = self.sock.recv(1)
                        if not more: break
                        data += more
                    if data.startswith((b'GET ', b'HEAD ')):
                        with peer.lock:
                            peer.state['rankingRequests'] += 1
                            mode = peer.state['downloadMode']
                        if mode == 'slow': time.sleep(.25)
                        if mode == 'http-error':
                            self.sock.shutdown(socket.SHUT_RDWR)
                            return b''
                return data
        class Handler(original):
            def handle(self):
                self.request = DelayedSocket(self.request)
                super().handle()
        return Handler
