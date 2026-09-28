"""Owned plain-password VPN servers for manual session-credential replacement.

Import-safe. CLI PRIVATE_ROOT requires an adjacent pinned Core and a copied
Python executable named Thronium; EOF closes only these owned fixture servers.
No OTP, static challenge, system TUN, trust-store or host routing operations.
"""
import copy
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import sys
import threading
import time
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

from vpn_auth_fixture import Rpc, field, parse
from vpn_otp_fixture import certificate_files

# Synthetic fixture values, including significant spaces. Never copy these
# values, raw config, HTTP bodies or server logs into evidence artifacts.
OLD_USERNAME = 'credentials-fixture-rejected-user'
OLD_PASSWORD = 'credentials-fixture-rejected-password'
NEW_USERNAME = ' credentials-fixture-new-user '
NEW_PASSWORD = ' credentials-fixture-new-password-31 '
VALID_USERNAME = NEW_USERNAME
VALID_PASSWORD = NEW_PASSWORD


class Events:
    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.Lock()
        self.rows = []
        self.counts = {}
        self.path.touch(mode=0o600, exist_ok=False)

    def add(self, protocol, event, **flags):
        # Hard evidence boundary: values only booleans or integers. Text is
        # confined to fixture-owned protocol/event enums below.
        assert protocol in ('openvpn', 'openconnect')
        assert event in ('authentication-rejected', 'authentication-accepted',
                         'initial-form', 'initial-lockout', 'credentials')
        assert all(type(value) in (bool, int) for value in flags.values())
        with self.lock:
            self.counts[protocol] = self.counts.get(protocol, 0) + 1
            row = dict(protocol=protocol, event=event,
                       attempt=self.counts[protocol], **flags)
            self.rows.append(row)
            with self.path.open('a') as output:
                output.write(json.dumps(row) + '\n')

    def observations(self, protocol=None):
        with self.lock:
            return [dict(row) for row in self.rows
                    if protocol is None or row['protocol'] == protocol]


def openvpn_server(certificate, key, port):
    return {'type': 'openvpn-server', 'tag': 'credentials-server',
            'listen': '127.0.0.1', 'listen_port': port,
            'network': 'udp', 'system': False,
            'address': ['10.79.0.1/24'], 'topology': 'subnet',
            'users': [{'username': NEW_USERNAME, 'password': NEW_PASSWORD}],
            'tls': {'certificate_path': str(certificate), 'key_path': str(key),
                    'verify_client_certificate': 'none'}}


def openvpn_outbound(certificate, port, username=OLD_USERNAME,
                     password=OLD_PASSWORD):
    return {'type': 'openvpn-client', 'tag': 'proxy',
            'server': '127.0.0.1', 'server_port': port, 'network': 'udp',
            'system': False, 'auth_retry': 'none',
            'username': username, 'password': password,
            'tls': {'certificate_path': str(certificate),
                    'server_name': 'vpn.fixture.invalid'}}


class CredentialsFormServer:
    """Two real rejection exchanges, then a separately verified login.

    An invalid submitted login receives HTTP 403. The next initialization also
    receives HTTP 403 (a one-initialization lockout). The first is retryable in
    this pinned client; the latter ends that attempt with terminal authFailed.
    A new explicit Start can log in. Valid credentials get an operator-only
    continuation. This proves auth exchange, not an established CSTP tunnel.
    """
    def __init__(self, certificate, key, events):
        self.certificate = str(certificate)
        self.events = events
        self.lock = threading.Lock()
        self.cases = {}
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *_):
                pass

            def do_POST(self):
                try:
                    size = int(self.headers.get('Content-Length', '0'))
                except ValueError:
                    size = -1
                if not 0 <= size <= 65536 or self.path not in owner.cases:
                    self.reply(400, b'')
                    return
                raw = self.rfile.read(size)
                try:
                    xml = ET.fromstring(raw)
                except ET.ParseError:
                    self.reply(400, b'')
                    return
                values = {node.tag: node.text or '' for node in xml.iter()
                          if len(node) == 0}
                initial = xml.attrib.get('type') == 'init'
                with owner.lock:
                    case = owner.cases[self.path]
                    if initial and case['lockout']:
                        case['lockout'] = False
                        owner.events.add('openconnect', 'initial-lockout',
                                         accepted=False, httpStatus=403)
                        status, data = 403, b''
                    elif initial:
                        owner.events.add('openconnect', 'initial-form')
                        status, data = 200, owner.form(self.path, False)
                    else:
                        old_exact = (values.get('username') == OLD_USERNAME and
                                     values.get('password') == OLD_PASSWORD)
                        new_exact = (values.get('username') == NEW_USERNAME and
                                     values.get('password') == NEW_PASSWORD)
                        owner.events.add('openconnect', 'credentials',
                                         oldExact=old_exact, newExact=new_exact,
                                         accepted=new_exact,
                                         httpStatus=200 if new_exact else 403)
                        if new_exact:
                            status, data = 200, owner.form(self.path, True)
                        else:
                            case['lockout'] = True
                            status, data = 403, b''
                self.reply(status, data)

            def reply(self, status, data):
                self.send_response(status)
                self.send_header('Content-Type', 'text/xml')
                self.send_header('Content-Length', str(len(data)))
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(data)

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def add_case(self, name, username=OLD_USERNAME, password=OLD_PASSWORD):
        assert name and len(name) <= 64 and all(c in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in name)
        path = '/credentials/' + name
        with self.lock:
            assert path not in self.cases
            self.cases[path] = {'lockout': False}
        return {'type': 'openconnect', 'tag': 'proxy',
                'server': f'https://127.0.0.1:{self.server.server_port}{path}',
                'flavor': 'anyconnect', 'system': False, 'no_udp': True,
                'username': username, 'password': password,
                'tls': {'certificate_authority_path': self.certificate}}

    @staticmethod
    def form(path, accepted):
        fields = ('<input type="text" name="operator_note" label="Operator note"/>'
                  if accepted else
                  '<input type="text" name="username" label="Username"/>'
                  '<input type="password" name="password" label="Password"/>')
        return ('<config-auth><auth id="' + ('operator' if accepted else 'login') +
                '"><message>Owned credential verifier</message>'
                '<form method="POST" action="' + escape(path, {'"': '&quot;'}) +
                '">' + fields + '</form></auth></config-auth>').encode()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


def load(rpc, endpoint, logging=False):
    config = {'log': {'disabled': not logging, 'level': 'info', 'timestamp': False},
              'endpoints': [endpoint],
              'outbounds': [{'type': 'direct', 'tag': 'direct'}],
              'route': {'final': 'direct'}}
    payload = field(1, json.dumps(config)) + field(2, 1) + field(9, 0)
    rpc.call('CheckConfig', payload)
    rpc.call('Start', payload)


def status(rpc):
    response = rpc.call('QueryVPNStatus', field(1, 'proxy'), error_response=False)
    endpoint = parse(response[1][0])
    challenge = parse(endpoint[16][0]) if endpoint.get(16) else None
    return endpoint, challenge


def wait_state(rpc, expected, timeout=12):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        endpoint, challenge = status(rpc)
        if endpoint.get(2) == [expected.encode()]:
            return endpoint, challenge
        time.sleep(.03)
    # Intentionally omit the arbitrary endpoint error and challenge details.
    raise AssertionError('credentials_fixture_state_timeout_' + expected)


class CredentialsFixture:
    def __init__(self, root):
        self.root = Path(root).resolve()
        assert Path(sys.executable).resolve() == self.root / 'Thronium', 'credentials_fixture_parent_identity_required'
        assert self.root.stat().st_uid == os.getuid() and self.root.stat().st_mode & 0o077 == 0
        self.rpc = self.web = None
        self.stopping = threading.Event()
        self.log_thread = None

    def __enter__(self):
        try:
            certificate, key = certificate_files(self.root)
            self.events = Events(self.root / 'events.jsonl')
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
                reservation.bind(('127.0.0.1', 0))
                port = reservation.getsockname()[1]
            self.rpc = Rpc(self.root, 'credentials-server')
            self.log_thread = threading.Thread(target=self.watch_server_log, daemon=True)
            self.log_thread.start()
            load(self.rpc, openvpn_server(certificate, key, port), logging=True)
            self.web = CredentialsFormServer(certificate, key, self.events)
            self.ready = {'openvpn': openvpn_outbound(certificate, port),
                          'openconnect': self.web.add_case('main'),
                          'certificate': str(certificate),
                          'events': str(self.events.path),
                          'serverCorePid': self.rpc.process.pid,
                          'openconnectSuccessBoundary': 'accepted-credentials-operator-form',
                          'systemTun': False}
            return self
        except BaseException:
            self.close()
            raise

    def watch_server_log(self):
        # Core's immutable built-in server is the authenticator. Its successful
        # log plus the singleton users map implies exact password acceptance;
        # this is distinct from observing the decoded password directly.
        with (self.root / 'credentials-server-core.log').open() as source:
            while not self.stopping.is_set():
                line = source.readline()
                if not line:
                    self.stopping.wait(.02)
                    continue
                if 'authentication rejected for peer ' in line:
                    self.events.add('openvpn', 'authentication-rejected', accepted=False)
                elif 'peer connected: ' in line:
                    self.events.add('openvpn', 'authentication-accepted', accepted=True,
                                    singletonCredentialsAccepted=True,
                                    usernameExact=json.dumps(NEW_USERNAME) in line)

    def outbound(self, protocol, username=OLD_USERNAME, password=OLD_PASSWORD):
        value = copy.deepcopy(self.ready[protocol])
        value.update(username=username, password=password)
        return value

    def close(self):
        if self.web:
            self.web.close()
            self.web = None
        if self.rpc:
            self.rpc.close()
            self.rpc = None
        self.stopping.set()
        if self.log_thread:
            self.log_thread.join(timeout=3)

    def __exit__(self, *_):
        self.close()


def self_check(root, fixture):
    """Actual Core fixture readiness only; no Engine31/UI acceptance claim."""
    result = {'fixtureOnly': True, 'app31Tested': False, 'otpTested': False,
              'systemTun': False, 'openvpnPayloadTested': False,
              'openconnectCstpConnected': False}
    rpc = Rpc(root, 'credentials-client')
    try:
        load(rpc, fixture.outbound('openvpn'))
        endpoint, challenge = wait_state(rpc, 'error')
        assert endpoint.get(17) == [1] and challenge is None
        assert endpoint.get(4, [0]) == [0]
        result['openvpnTerminalAuthFailed'] = True
        for _ in range(10):
            endpoint, challenge = status(rpc)
            assert endpoint.get(2) == [b'error'] and endpoint.get(17) == [1] and challenge is None
            time.sleep(.05)
        rpc.call('Stop')
        load(rpc, fixture.outbound('openvpn', NEW_USERNAME, NEW_PASSWORD))
        endpoint, challenge = wait_state(rpc, 'connected')
        assert endpoint.get(4) == [1] and challenge is None
        result['openvpnPlainPasswordConnected'] = True
        rpc.call('Stop')

        load(rpc, fixture.outbound('openconnect'))
        endpoint, challenge = wait_state(rpc, 'error')
        assert endpoint.get(17) == [1] and challenge is None
        result['openconnectTerminalAuthFailed'] = True
        before = len(fixture.events.observations('openconnect'))
        for _ in range(10):
            endpoint, challenge = status(rpc)
            assert endpoint.get(2) == [b'error'] and endpoint.get(17) == [1] and challenge is None
            time.sleep(.05)
        assert len(fixture.events.observations('openconnect')) == before
        result['openconnectTerminalQuietPolls'] = 10
        rpc.call('Stop')
        load(rpc, fixture.outbound('openconnect', NEW_USERNAME, NEW_PASSWORD))
        endpoint, challenge = wait_state(rpc, 'auth-pending')
        assert challenge and len(challenge[11]) == 1
        assert parse(challenge[11][0])[2] == [b'operator_note']
        result['openconnectNewCredentialsAccepted'] = True
        result['openconnectSuccessBoundary'] = 'operator-form-after-exact-login'
        rpc.call('Stop')
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            vpn_rows = fixture.events.observations('openvpn')
            if any(row['event'] == 'authentication-accepted' for row in vpn_rows):
                break
            time.sleep(.03)
        assert any(row['event'] == 'authentication-accepted' and row['usernameExact'] for row in vpn_rows)
        oc_rows = fixture.events.observations('openconnect')
        assert any(row.get('oldExact') and not row['accepted'] for row in oc_rows)
        assert any(row.get('newExact') and row['accepted'] for row in oc_rows)
        result['observations'] = fixture.events.observations()
        return result
    finally:
        rpc.close()


def serve(root):
    with CredentialsFixture(root) as fixture:
        print(json.dumps(fixture.ready), flush=True)
        if '--self-check' in sys.argv:
            print(json.dumps(self_check(Path(root), fixture)), flush=True)
        else:
            sys.stdin.buffer.read()


if __name__ == '__main__':
    serve(Path(sys.argv[1]))
