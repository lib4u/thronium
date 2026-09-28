"""What a provider policy really does inside a tunnel: names it answers with
fake addresses, traffic that finds its way back to the name, and an OpenVPN
endpoint that runs beside the connection under its own gate. Loopback, the
private tunnel of this namespace and RFC 5737 addresses only."""
import contextlib
import ipaddress
import json
import os
from pathlib import Path
from select import select as wait_ready
import socket
import socketserver
import struct
import threading
import time
import uuid

from subscription_happ_fixture import Server as HappServer

BODY = b'fakeip-batch-body'
NAME = 'proxy.fixture.invalid'
# A resolver address nothing here owns: the tunnel is what answers it.
RESOLVER = '198.51.100.53'


def query(name):
    """One A question for `name`, as a client sends it."""
    header = struct.pack('!HHHHHH', 0x4242, 0x0100, 1, 0, 0, 0)
    labels = b''.join(bytes([len(part)]) + part.encode() for part in name.split('.')) + b'\0'
    return header + labels + struct.pack('!HH', 1, 1)


def answers(packet, name):
    """Every A address the answer carries, read without following pointers."""
    count = struct.unpack('!H', packet[6:8])[0]
    offset = 12
    while packet[offset]:
        offset += packet[offset] + 1
    # The question ends with its zero label, its type and its class.
    offset += 1 + 4
    result = []
    for _ in range(count):
        while True:
            length = packet[offset]
            if length == 0:
                offset += 1
                break
            if length & 0xC0:
                offset += 2
                break
            offset += length + 1
        kind, _, _, size = struct.unpack('!HHIH', packet[offset:offset + 10])
        offset += 10
        if kind == 1 and size == 4:
            result.append(str(ipaddress.ip_address(packet[offset:offset + 4])))
        offset += size
    return result


def run(h):
    command, check = h['command'], h['check']
    assert os.geteuid() == 0 and os.environ['THRONIUM_TEST_ORIGINAL_NETNS'] != os.readlink('/proc/self/ns/net')
    ready = json.loads(Path(os.environ['_THRONIUM_OPENVPN_PENDING_READY']).read_text())
    initial = command('snapshot')
    original_routing = command('routing')
    servers, groups, profiles, sockets = [], [], [], []
    hops = []

    class Fixture(socketserver.BaseRequestHandler):
        protocol = 'http'

        def handle(self):
            with contextlib.suppress(OSError):
                self.request.recv(4096)
                self.request.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: '
                                     + str(len(BODY)).encode() + b'\r\n\r\n' + BODY)

    class Hop(socketserver.BaseRequestHandler):
        """The member of the subscription: it is asked for a name, never for the
        fake address the tunnel handed the client."""

        def handle(self):
            incoming, upstream = self.request, None

            def exact(count):
                value = b''
                while len(value) < count:
                    part = incoming.recv(count - len(value))
                    if not part:
                        raise EOFError()
                    value += part
                return value

            try:
                incoming.settimeout(10)
                version, methods = exact(2)
                exact(methods)
                incoming.sendall(b'\x05\x00')
                version, kind, _, family = exact(4)
                if family == 3:
                    asked = exact(exact(1)[0]).decode()
                elif family == 1:
                    asked = str(ipaddress.ip_address(exact(4)))
                else:
                    return
                port = struct.unpack('!H', exact(2))[0]
                hops.append({'asked': asked, 'port': port})
                upstream = socket.create_connection(('127.0.0.1', http.server_address[1]), timeout=8)
                incoming.sendall(b'\x05\x00\x00\x01' + b'\0' * 6)
                while True:
                    readable, _, _ = wait_ready([incoming, upstream], [], [], 10)
                    for source in readable or []:
                        data = source.recv(8192)
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

    def serve(handler):
        server = Threading(('127.0.0.1', 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return server

    def until(accept, timeout=60, what='the connection'):
        end = time.monotonic() + timeout
        last = None
        while time.monotonic() < end:
            last = accept()
            if last:
                return last
            time.sleep(.3)
        raise AssertionError(what + ' never settled')

    attempts = []

    def resolve(name):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(8)
            try:
                client.sendto(query(name), (RESOLVER, 53))
                packet = client.recv(4096)
            except OSError as error:
                attempts.append({'error': type(error).__name__ + ': ' + str(error)})
                return []
            try:
                result = answers(packet, name)
            except Exception as error:  # the packet itself is the evidence
                attempts.append({'packet': packet.hex(), 'error': str(error)})
                return []
            attempts.append({'packet': packet.hex(), 'addresses': result})
            return result

    def diagnostics():
        import subprocess
        return {name: subprocess.run(command_line, capture_output=True, text=True).stdout
                for name, command_line in (
                    ('links', ['ip', '-br', 'addr']),
                    ('routes', ['ip', 'route', 'show', 'table', 'all']),
                    ('rules', ['ip', 'rule']))}

    try:
        http = serve(Fixture)
        hop = serve(Hop)
        happ = HappServer(hop.server_address[1])
        servers.append(type('Closer', (), {'shutdown': happ.close, 'server_close': lambda: None})())
        command('preferences', {**initial['preferences'], 'language': 'en'})
        group = command('saveGroup', {'name': 'Happ provider', 'subscription': {
            'url': happ.url, 'headers': {}, 'viaProxy': False, 'intervalMinutes': 0,
            'useProviderRouting': True, 'inheritDefaults': False}})['id']
        groups.append(group)
        response = command('fetchSubscription', {'id': group, 'requestId': str(uuid.uuid4())})
        command('previewSubscription', {'ticket': response['ticket'], 'profiles': [
            {'name': 'Happ member', 'groupId': group, 'kind': 'sing-box-outbound',
             'config': {'type': 'socks', 'server': '127.0.0.1', 'server_port': hop.server_address[1],
                        'version': '5'}}]})
        command('applySubscription', {'ticket': response['ticket'], 'useProviderRouting': True})
        member = next(p['id'] for p in command('snapshot')['profiles'] if p['groupId'] == group)
        check(response['providerRouting']['fakeDns'] is True,
              'the subscription asks for fake addresses in its own routing policy')

        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            inbound = reservation.getsockname()[1]
        command('connectionSettings', {'mode': 'tun', 'port': inbound})
        command('connect', {'id': member})
        until(lambda: command('snapshot')['running'] == member, what='the tunnel')
        try:
            addresses = until(lambda: resolve(NAME) or None, timeout=40, what='an answer from the tunnel')
        except AssertionError:
            (h['artifacts'] / 'fakeip-diagnostics.json').write_text(json.dumps(
                {'attempts': attempts[-3:], 'network': diagnostics(),
                 'log': [e.get('text') for e in command('getLogs', {})['entries'][-12:]],
                 'configuration': command('connectionConfiguration', {'id': member, 'active': True})},
                indent=2) + '\n')
            raise
        fake = ipaddress.ip_network('198.18.0.0/15')
        check(all(ipaddress.ip_address(a) in fake for a in addresses),
              'the tunnel answers the policy name with fake addresses: ' + json.dumps(addresses))

        with socket.create_connection((addresses[0], 80), timeout=10) as client:
            sockets.append(client)
            client.sendall(b'GET /policy HTTP/1.1\r\nHost: ' + NAME.encode() + b'\r\nConnection: close\r\n\r\n')
            received = b''
            while BODY not in received:
                part = client.recv(4096)
                if not part:
                    break
                received += part
        check(BODY in received, 'traffic to a fake address reaches the service the name stands for')
        check(any(entry['asked'] == NAME for entry in hops),
              'the member is asked for the name, never for the fake address: ' + json.dumps(hops))

        # The policy of a provider holds only while the person has written no
        # routing of their own; with a rule of their own it steps aside, and an
        # OpenVPN endpoint runs beside the connection under its own gate.
        auxiliary = command('saveProfile', {'name': 'Auxiliary OpenVPN', 'groupId': 'personal',
                                            'kind': 'sing-box-outbound',
                                            'config': {'type': 'openvpn-client', 'server': '127.0.0.1',
                                                       'server_port': ready['openvpnPort'], 'network': 'udp',
                                                       'system': False, 'username': ready['user'],
                                                       'password': ready['password'],
                                                       'tls': {'certificate_path': ready['certificate'],
                                                               'server_name': ready['serverName']}}})['id']
        profiles.append(auxiliary)
        ordinary = command('saveProfile', {'name': 'Own member', 'groupId': 'personal',
                                           'kind': 'sing-box-outbound',
                                           'config': {'type': 'socks', 'server': '127.0.0.1',
                                                      'server_port': hop.server_address[1], 'version': '5'}})['id']
        profiles.append(ordinary)
        routing = command('routing')
        active = next(p for p in routing['profiles'] if p['id'] == routing['active'])
        active['rules'] = list(active.get('rules') or []) + [
            {'id': 'auxiliary-gate', 'name': 'Auxiliary gate', 'enabled': True,
             'config': {'preferred_by': ['profile:' + auxiliary], 'action': 'route',
                        'outbound': 'profile:' + auxiliary}}]
        command('saveRouting', routing)
        command('connect', {'id': ordinary})
        until(lambda: command('snapshot')['running'] == ordinary, what='the connection of its own')
        endpoint = until(lambda: next((row for row in command('snapshot')['vpn']['endpoints']
                                       if row['state'] == 'connected'), None),
                         what='the auxiliary endpoint')
        check(endpoint['tag'] == 'thronium-route-' + auxiliary and endpoint['tunnel'] is not None,
              'the auxiliary endpoint runs beside the connection under its own tag: ' + json.dumps(endpoint['tag']))
        check(ipaddress.ip_network('10.79.8.0/24') == ipaddress.ip_network(endpoint['tunnel']['routes'][0]),
              'the endpoint carries only what it advertises: ' + json.dumps(endpoint['tunnel']['routes']))
        carried = len(hops)
        with socket.create_connection(('127.0.0.1', inbound), timeout=10) as client:
            sockets.append(client)
            target = '127.0.0.1:' + str(http.server_address[1])
            client.sendall(('CONNECT ' + target + ' HTTP/1.1\r\nHost: ' + target + '\r\n\r\n').encode())
            headers = b''
            while b'\r\n\r\n' not in headers:
                part = client.recv(4096)
                if not part:
                    break
                headers += part
            client.sendall(b'GET /own HTTP/1.1\r\nHost: own.fixture.invalid\r\nConnection: close\r\n\r\n')
            answer = b''
            while BODY not in answer:
                part = client.recv(4096)
                if not part:
                    break
                answer += part
        check(b' 200 ' in headers.split(b'\r\n', 1)[0] and BODY in answer and len(hops) > carried,
              'traffic keeps flowing through the connection while the endpoint stands beside it')
        (h['artifacts'] / 'fakeip-batch.json').write_text(json.dumps(
            {'openvpnVersion': ready['openvpnVersion'], 'addresses': addresses, 'hops': hops,
             'endpoint': {k: endpoint[k] for k in ('tag', 'protocol', 'state')}}, indent=2) + '\n')
    finally:
        with contextlib.suppress(Exception):
            command('disconnect')
        with contextlib.suppress(Exception):
            command('saveRouting', {**original_routing, 'revision': command('routing')['revision']})
        for identifier in profiles:
            with contextlib.suppress(Exception):
                command('deleteProfiles', {'ids': [identifier]})
        for identifier in groups:
            with contextlib.suppress(Exception):
                command('deleteGroup', {'id': identifier})
        for opened in sockets:
            with contextlib.suppress(Exception):
                opened.close()
        for server in servers:
            with contextlib.suppress(Exception):
                server.shutdown()
                server.server_close()
        with contextlib.suppress(Exception):
            command('preferences', initial['preferences'])
