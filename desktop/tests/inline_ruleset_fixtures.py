"""Owned DNS packet fixtures; routing expectations come from the raw-core oracle."""
import contextlib
import ipaddress
import json
from pathlib import Path
import socket
import socketserver
import struct
import threading

DIRECTORY = Path(__file__).resolve().parents[1] / 'engine/tests/fixtures/inline-ruleset'
MATRIX = json.loads((DIRECTORY / 'oracle-contract.json').read_text())


def exact(sock, size):
    result = b''
    while len(result) < size:
        data = sock.recv(size - len(result))
        if not data:
            raise AssertionError('Owned SOCKS connection closed')
        result += data
    return result


def question(name, kind, transaction):
    assert name.endswith('.oracle.invalid') and kind in (1, 28)
    labels = b''.join(bytes([len(v)]) + v.encode() for v in name.split('.')) + b'\0'
    return struct.pack('!HHHHHH', transaction, 0x100, 1, 0, 0, 0) + labels + struct.pack('!HH', kind, 1)


def question_end(packet):
    offset = 12
    while packet[offset]:
        size = packet[offset]
        assert 0 < size < 64
        offset += size + 1
    return offset + 5


class DnsOrigins:
    def __init__(self):
        self.events = []; self.lock = threading.Lock(); self.servers = []
        self.addresses = {'MATCHED': {1: '192.0.2.71', 28: '2001:db8::71'}, 'FALLBACK': {1: '192.0.2.72', 28: '2001:db8::72'}}
        self.matched = self.start('MATCHED'); self.fallback = self.start('FALLBACK')

    def start(self, label):
        owner = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                query, channel = self.request
                end = question_end(query); kind = struct.unpack('!H', query[end - 4:end - 2])[0]
                assert kind in (1, 28)
                data = ipaddress.ip_address(owner.addresses[label][kind]).packed
                response = query[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0) + query[12:end]
                response += b'\xc0\x0c' + struct.pack('!HHIH', kind, 1, 0, len(data)) + data
                with owner.lock:
                    owner.events.append({'origin': label, 'type': kind, 'transaction': int.from_bytes(query[:2], 'big')})
                channel.sendto(response, self.client_address)

        class Server(socketserver.ThreadingUDPServer):
            daemon_threads = True

        server = Server(('127.0.0.1', 0), Handler)
        self.servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    def counts(self):
        with self.lock:
            return {name: sum(e['origin'] == name for e in self.events) for name in ['MATCHED', 'FALLBACK']}

    def close(self):
        for server in self.servers:
            server.shutdown(); server.server_close()


def dns_exchange(inbound, target, name, kind, transaction):
    """Real SOCKS5 UDP ASSOCIATE; every destination and relay is loopback."""
    with contextlib.ExitStack() as stack:
        control = stack.enter_context(socket.create_connection(('127.0.0.1', inbound), timeout=5))
        control.sendall(b'\x05\x01\x00'); assert exact(control, 2) == b'\x05\x00'
        control.sendall(b'\x05\x03\x00\x01' + b'\0' * 6)
        header = exact(control, 4); assert header[:3] == b'\x05\x00\x00'
        if header[3] == 1:
            address = ipaddress.ip_address(exact(control, 4))
        else:
            assert header[3] == 4; address = ipaddress.ip_address(exact(control, 16))
        assert address.is_unspecified or address.is_loopback
        relay_port = int.from_bytes(exact(control, 2), 'big'); assert relay_port
        channel = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        channel.bind(('127.0.0.1', 0)); channel.settimeout(5)
        prefix = b'\0\0\0\x01\x7f\0\0\x01' + target.to_bytes(2, 'big')
        channel.sendto(prefix + question(name, kind, transaction), ('127.0.0.1', relay_port))
        packet, peer = channel.recvfrom(65536); assert peer[0] == '127.0.0.1' and peer[1] == relay_port
        assert packet[:3] == b'\0\0\0'; atyp = packet[3]
        offset = 10 if atyp == 1 else 22 if atyp == 4 else 7 + packet[4]
        response = packet[offset:]
        assert int.from_bytes(response[:2], 'big') == transaction
        assert struct.unpack('!HHHHHH', response[:12])[1] & 0xF == 0
        assert struct.unpack('!HHHHHH', response[:12])[3] == 1
        end = question_end(response)
        while response[end] and response[end] & 0xC0 != 0xC0:
            assert response[end] < 64; end += response[end] + 1
        end += 2 if response[end] & 0xC0 == 0xC0 else 1
        rtype, rclass, _, size = struct.unpack('!HHIH', response[end:end + 10])
        assert rtype == kind and rclass == 1 and size == (4 if kind == 1 else 16)
        return str(ipaddress.ip_address(response[end + 10:end + 10 + size]))
