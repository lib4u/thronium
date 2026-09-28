"""Owned DNS upstream for the native TUN fixture; never used on the host network."""
import copy
import json
import os
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import threading
import time


class Fixture:
    def __init__(self, h, backend="resolved"):
        assert os.geteuid() == 0
        assert os.environ['THRONIUM_TEST_ORIGINAL_NETNS'] != os.readlink('/proc/self/ns/net')
        assert os.environ['DBUS_SYSTEM_BUS_ADDRESS'] == 'unix:path=/run/dbus/system_bus_socket'
        assert backend in ('resolved', 'resolvconf')
        self.backend = backend
        self.h = h
        self.routing = h['command']('routing')
        self.count = 0
        self.query_types = []
        self.query_number = 0
        self.expected_address = '198.18.0.80'
        self.server_counts = {}
        outer = self

        class DNS(socketserver.BaseRequestHandler):
            def handle(self):
                q, sock = self.request
                end = 12
                while q[end]:
                    assert q[end] < 64
                    end += 1 + q[end]
                end += 1
                kind, cls = struct.unpack('!HH', q[end:end + 4])
                assert cls == 1 and kind in (1, 28)
                source = self.server.server_address[0]
                answer = socket.inet_pton(socket.AF_INET, '198.18.0.81' if source == '198.51.100.53' else '198.18.0.80') if kind == 1 else socket.inet_pton(socket.AF_INET6, '2001:db8::80')
                outer.server_counts[source] = outer.server_counts.get(source, 0) + 1
                outer.query_types.append(kind)
                response = q[:2] + b'\x81\x80\0\1\0\1\0\0\0\0' + q[12:end + 4] + b'\xc0\x0c' + struct.pack('!HHIH', kind, 1, 0, len(answer)) + answer
                outer.count += 1
                sock.sendto(response, self.client_address)
        self.local_probe = backend == 'resolvconf' and os.environ.get('_THRONIUM_TUN_LOCAL_DNS_PROBE') == '1'
        if self.local_probe:
            from openresolv_fixture import call
            subprocess.run(['ip', 'addr', 'add', '192.0.2.53/24', 'dev', 'uplink'], check=True)
            call(['-a', 'eth0.dhcp'], 'search old.test\nnameserver 192.0.2.53\n')
        self.server = socketserver.UDPServer(('192.0.2.53', 53) if self.local_probe else ('127.0.0.1', 0), DNS)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.next_server = None
        self.next_thread = None
        if os.environ.get('_THRONIUM_TUN_NETWORK_DNS_PROBE') == '1':
            assert self.local_probe
            subprocess.run(['ip', 'addr', 'add', '198.51.100.53/24', 'dev', 'uplink'], check=True)
            self.next_server = socketserver.UDPServer(('198.51.100.53', 53), DNS)
            self.next_thread = threading.Thread(target=self.next_server.serve_forever)
            self.next_thread.start()
        route = copy.deepcopy(self.routing)
        active = next(p for p in route['profiles'] if p['id'] == route['active'])
        active['dns'] = {'servers': [{'type': 'udp', 'tag': 'dns-direct', 'server': '127.0.0.1', 'server_port': self.server.server_address[1]}], 'final': 'dns-direct'}
        if self.local_probe:
            active['dns'] = {'servers': [{'type': 'local', 'tag': 'dns-direct'}], 'final': 'dns-direct'}
        h['command']('saveRouting', route)
        self.physical = subprocess.check_output(['resolvectl', 'dns', 'uplink'], text=True) if backend == 'resolved' else None

    def query(self, label):
        if self.backend == 'resolvconf':
            from openresolv_fixture import call
            policy = Path('/etc/resolv.conf').read_text()
            assert 'nameserver 172.19.0.2' in policy
            keys = call(['-x']).split()
            assert len(keys) == 1 and keys[0].startswith('thronium-tun.thronium-')
            self.query_number += 1
            if self.local_probe:
                time.sleep(5.3)  # cross the actual upstream resolv.conf reload interval
            before = self.count
            try:
                addresses = socket.getaddrinfo('native-openresolv' + str(self.query_number) + '.test', 80, socket.AF_INET, socket.SOCK_STREAM)
            except OSError:
                (self.h['artifacts'] / 'openresolv-dns-failure.json').write_text(json.dumps({'upstreamCount': self.count, 'queryTypes': self.query_types, 'systemResolver': policy, 'logs': self.h['command']('getLogs')}, indent=2) + '\n')
                raise
            assert any(row[4][0] == self.expected_address for row in addresses) and self.count > before
            if not self.local_probe:
                call(['-a', 'eth0.dhcp'], 'search new.test\nnameserver 198.51.100.53\n')
            assert 'nameserver 172.19.0.2' in Path('/etc/resolv.conf').read_text()
            suffix = ': actual libc DNS follows the worker physical resolver after its reload interval' if self.local_probe else ': actual libc DNS follows client rules through openresolv and TUN despite a DHCP update'
            self.h['check'](True, label + suffix)
            return
        policy = subprocess.check_output(['resolvectl', 'dns', 'thronium-tun'], text=True)
        assert '172.19.0.2' in policy
        self.query_number += 1
        name = ('native' + str(self.query_number)).encode()
        q = struct.pack('!6H', 59, 0x100, 1, 0, 0, 0) + bytes([len(name)]) + name + b'\4test\0\0\1\0\1'
        before = self.count
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(5)
            sock.sendto(q, ('127.0.0.53', 53))
            response, _ = sock.recvfrom(4096)
        assert response[:2] == q[:2] and response[3] & 15 == 0 and b'\xc6\x12\0\x50' in response and self.count > before
        self.h['check'](True, label + ': actual system resolver uses the client DNS rules through TUN')

    def clean(self):
        assert not Path('/sys/class/net/thronium-tun').exists()
        if self.backend == 'resolvconf':
            from openresolv_fixture import call
            assert not any(key.startswith('thronium-tun.thronium-') for key in call(['-i']).split())
            body = Path('/etc/resolv.conf').read_text()
            assert ('192.0.2.53' in body if self.local_probe else '198.51.100.53' in body and 'search new.test' in body) and '172.19.0.2' not in body
        else:
            assert subprocess.check_output(['resolvectl', 'dns', 'uplink'], text=True) == self.physical
        self.h['check'](True, 'native cancellation removes its resolver link and preserves physical DNS')

    def close(self):
        try:
            self.h['command']('saveRouting', {**self.routing, 'revision': self.h['command']('routing')['revision']})
        finally:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=3)
            assert not self.thread.is_alive()
            if self.next_server:
                self.next_server.shutdown()
                self.next_server.server_close()
                self.next_thread.join(timeout=3)
                assert not self.next_thread.is_alive()
