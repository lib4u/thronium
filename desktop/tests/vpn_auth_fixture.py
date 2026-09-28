"""Owned userspace OpenVPN server and HTTPS OpenConnect authentication fixture.

Run through the native wrapper's private Python executable named Thronium.
Only ready metadata and redacted observations are written; answers stay in memory.
"""
import base64
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

USER = 'auth-native-user'
PASSWORD = 'auth-native-password-7dc24'
ANSWER = 'auth-native-answer-429871'
FORM_USER = 'auth-native-form-user'
FORM_PASSWORD = 'auth-native-form-password-e8421'
FORM_ANSWER = 'auth-native-form-otp-193528'


def varint(number):
    data = bytearray()
    while number > 127:
        data.append((number & 127) | 128)
        number >>= 7
    data.append(number)
    return bytes(data)


def field(number, value):
    if isinstance(value, int):
        return varint(number << 3) + varint(value)
    if isinstance(value, str):
        value = value.encode()
    return varint((number << 3) | 2) + varint(len(value)) + value


def read_varint(data, offset):
    value = shift = 0
    while True:
        if offset >= len(data) or shift >= 70:
            raise ValueError('fixture_invalid_protobuf')
        byte = data[offset]
        offset += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, offset
        shift += 7


def parse(data):
    result = {}
    offset = 0
    while offset < len(data):
        key, offset = read_varint(data, offset)
        if key & 7 == 0:
            value, offset = read_varint(data, offset)
        elif key & 7 == 2:
            length, offset = read_varint(data, offset)
            if length > len(data) - offset:
                raise ValueError('fixture_invalid_protobuf')
            value = data[offset:offset + length]
            offset += length
        else:
            raise ValueError('fixture_invalid_protobuf')
        result.setdefault(key >> 3, []).append(value)
    return result


class Rpc:
    # `prefix` launches the Core through a namespace entry helper, which execs
    # it in place, so the peer credentials below still name this very process.
    def __init__(self, root, name='server', prefix=()):
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(str(root / (name + '-core.sock')))
        self.listener.listen()
        self.listener.settimeout(8)
        self.log = (root / (name + '-core.log')).open('w')
        self.process = subprocess.Popen(
            [*prefix, str(root / 'ThroniumCore')], cwd=root,
            env={**os.environ, 'THRONE_CORE_SOCKET': str(root / (name + '-core.sock'))},
            stdin=subprocess.DEVNULL, stdout=self.log, stderr=self.log)
        self.socket, _ = self.listener.accept()
        self.socket.settimeout(8)
        pid, uid, _ = struct.unpack('3i', self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if pid != self.process.pid or uid != os.getuid():
            raise RuntimeError('fixture_wrong_core_owner')
        self.identity = 0

    def read(self, length):
        result = b''
        while len(result) < length:
            part = self.socket.recv(length - len(result))
            if not part:
                raise RuntimeError('fixture_core_eof')
            result += part
        return result

    def call(self, method, payload=b'', error_response=True):
        self.identity += 1
        name = method.encode()
        self.socket.sendall(struct.pack('<IH', self.identity, len(name)) + name + struct.pack('<I', len(payload)) + payload)
        identity, status, size = struct.unpack('<IBI', self.read(9))
        if identity != self.identity or size > 16 * 1024 * 1024:
            raise RuntimeError('fixture_rpc_invalid_frame')
        result = parse(self.read(size))
        if status or (error_response and result.get(1, [b''])[0]):
            raise RuntimeError('fixture_rpc_rejected')
        return result

    def close(self):
        try:
            self.call('Stop')
        finally:
            self.socket.close()
            self.listener.close()
            try:
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                self.process.wait(timeout=5)
            self.log.close()


def self_check(root, ready):
    """Real second core checks both fixture protocols; no GUI claim."""
    client = Rpc(root, 'client')
    def config(endpoint):
        value = {'log': {'disabled': True}, 'endpoints': [endpoint],
            'outbounds': [{'type': 'direct', 'tag': 'direct'}], 'route': {'final': 'direct'}}
        payload = field(1, json.dumps(value)) + field(2, 1) + field(9, 0)
        client.call('CheckConfig', payload)
        client.call('Start', payload)
    def status():
        response = client.call('QueryVPNStatus', field(1, 'proxy'), error_response=False)
        value = parse(response[1][0])
        challenge = parse(value[16][0]) if value.get(16) else None
        return value, challenge
    def wait(state, old=None):
        until = time.monotonic() + 10
        while time.monotonic() < until:
            value, challenge = status()
            if value.get(2) == [state.encode()] and (old is None or challenge and challenge[2][0] != old):
                return value, challenge
            time.sleep(.03)
        raise AssertionError('fixture_client_state_timeout')
    try:
        config({'type': 'openvpn-client', 'tag': 'proxy', 'server': '127.0.0.1',
            'server_port': ready['openvpnPort'], 'network': 'udp', 'system': False,
            'static_challenge': 'Synthetic answer', 'tls': {'certificate_path': ready['certificate'], 'server_name': ready['serverName']}})
        _, challenge = wait('auth-pending')
        assert challenge[3] == [b'credentials'], 'fixture_credentials_missing'
        client.call('SubmitVPNChallenge', field(1, 'proxy') + field(2, challenge[2][0]) + field(3, USER) + field(4, PASSWORD) + field(5, ANSWER))
        state, challenge = wait('connected')
        assert state[4] == [1] and not challenge, 'fixture_openvpn_not_connected'
        client.call('Stop')
        config({'type': 'openconnect', 'tag': 'proxy',
            'server': 'https://127.0.0.1:' + str(ready['openconnectPort']) + '/form/selfcheck',
            'flavor': 'anyconnect', 'system': False, 'no_udp': True,
            'tls': {'certificate_authority_path': ready['certificate']}})
        _, challenge = wait('auth-pending')
        assert challenge[3] == [b'form'], 'fixture_form_missing'
        old = challenge[2][0]
        answers = {'username': FORM_USER, 'password': FORM_PASSWORD, 'realm': 'two'}
        payload = field(1, 'proxy') + field(2, old)
        kinds = set()
        for encoded in challenge[11]:
            item = parse(encoded)
            kinds.add(item[4][0].decode())
            payload += field(6, field(1, item[1][0]) + field(2, answers[item[2][0].decode()]))
        assert kinds == {'text', 'password', 'select'}, 'fixture_form_kinds_invalid'
        client.call('SubmitVPNChallenge', payload)
        _, challenge = wait('auth-pending', old)
        entries = [json.loads(line) for line in Path(ready['events']).read_text().splitlines()]
        assert any(row['formExact'] for row in entries), 'fixture_form_values_mismatch'
        assert challenge[2][0] != old, 'fixture_otp_identity_unchanged'
        old = challenge[2][0]
        otp_field = parse(challenge[11][0])
        assert len(challenge[11]) == 1 and otp_field[2] == [b'answer'], 'fixture_otp_field_invalid'
        client.call('SubmitVPNChallenge', field(1, 'proxy') + field(2, old) + field(6, field(1, otp_field[1][0]) + field(2, FORM_ANSWER)))
        wait('auth-pending', old)
        entries = [json.loads(line) for line in Path(ready['events']).read_text().splitlines()]
        assert any(row['otpExact'] for row in entries), 'fixture_otp_value_mismatch'
        return {'openvpnConnected': True, 'openconnectFormToOtp': True,
            'fieldKinds': sorted(kinds), 'formValuesExact': True, 'otpValueExact': True, 'certificateVerified': True,
            'systemTun': False, 'cancelTerminalChecked': False}
    finally:
        client.close()


def serve(root):
    root = root.resolve()
    if Path(sys.executable).resolve() != root / 'Thronium':
        raise RuntimeError('fixture_parent_identity_required')
    certificate = root / 'certificate.pem'
    key = root / 'private-key.pem'
    with (root / 'certificate-generation.log').open('w') as log:
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
            '-keyout', str(key), '-out', str(certificate), '-days', '1',
            '-subj', '/CN=vpn.fixture.invalid',
            '-addext', 'subjectAltName=IP:127.0.0.1,DNS:vpn.fixture.invalid',
            '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'authorityKeyIdentifier=keyid:always',
            '-addext', 'keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign',
            '-addext', 'extendedKeyUsage=serverAuth'], stdout=log, stderr=subprocess.STDOUT, check=True)
    key.chmod(0o600)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(('127.0.0.1', 0))
        vpn_port = reservation.getsockname()[1]
    packed = 'SCRV1:' + base64.b64encode(PASSWORD.encode()).decode() + ':' + base64.b64encode(ANSWER.encode()).decode()
    server = {'type': 'openvpn-server', 'tag': 'fixture-server', 'listen': '127.0.0.1',
        'listen_port': vpn_port, 'network': 'udp', 'system': False,
        'address': ['10.77.0.1/24'], 'topology': 'subnet',
        'users': [{'username': USER, 'password': packed}],
        'tls': {'certificate_path': str(certificate), 'key_path': str(key), 'verify_client_certificate': 'none'}}
    rpc = Rpc(root)
    config = {'log': {'disabled': True}, 'endpoints': [server],
        'outbounds': [{'type': 'direct', 'tag': 'direct'}], 'route': {'final': 'direct'}}
    payload = field(1, json.dumps(config)) + field(2, 1) + field(9, 0)
    rpc.call('CheckConfig', payload)
    rpc.call('Start', payload)
    counts = {}
    lock = threading.Lock()
    events_path = root / 'events.jsonl'

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, *_):
            pass

        def do_POST(self):
            try:
                length = int(self.headers.get('Content-Length', '0'))
            except ValueError:
                self.send_error(400)
                return
            if length < 0 or length > 65536 or not self.path.startswith('/form/'):
                self.send_error(400)
                return
            body = self.rfile.read(length)
            try:
                xml = ET.fromstring(body)
                values = {node.tag: node.text or '' for node in xml.iter() if len(node) == 0}
            except ET.ParseError:
                values = {}
            with lock:
                index = counts.get(self.path, 0) + 1
                counts[self.path] = index
                event = {'path': self.path, 'request': index, 'tls': True,
                    'formExact': values.get('username') == FORM_USER and values.get('password') == FORM_PASSWORD and values.get('realm') == 'two',
                    # AnyConnect xmlpost_append_form_opts explicitly maps
                    # answer/whichpin/new_password to the wire tag password.
                    'otpExact': index >= 3 and values.get('password') == FORM_ANSWER}
                with events_path.open('a') as out:
                    out.write(json.dumps(event) + '\n')
            action = escape(self.path, {'"': '&quot;'})
            if index == 1:
                reply = ('<config-auth><auth id="login"><banner>Synthetic VPN &lt;b&gt;plain text&lt;/b&gt;</banner>'
                    '<message>Answer local form</message><form method="POST" action="' + action + '">'
                    '<input type="text" name="username" label="User"/>'
                    '<input type="password" name="password" label="Password"/>'
                    '<select name="realm" label="Realm"><option value="one">First realm label</option>'
                    '<option value="two">Second realm label</option></select></form></auth></config-auth>')
            else:
                reply = ('<config-auth><auth id="challenge"><message>Synthetic OTP</message>'
                    '<form method="POST" action="' + action + '"><input type="password" name="answer" '
                    'label="One-time code"/></form></auth></config-auth>')
            data = reply.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/xml')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    webserver = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    webserver.daemon_threads = True
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    webserver.socket = context.wrap_socket(webserver.socket, server_side=True)
    thread = threading.Thread(target=webserver.serve_forever, daemon=True)
    thread.start()
    ready = {'openvpnPort': vpn_port, 'openconnectPort': webserver.server_port,
        'certificate': str(certificate), 'serverName': 'vpn.fixture.invalid',
        'events': str(events_path), 'serverCorePid': rpc.process.pid}
    print(json.dumps(ready), flush=True)
    try:
        if '--self-check' in sys.argv:
            print(json.dumps(self_check(root, ready)), flush=True)
        else:
            sys.stdin.buffer.read()
    finally:
        webserver.shutdown()
        webserver.server_close()
        thread.join(timeout=3)
        rpc.close()


if __name__ == '__main__':
    serve(Path(sys.argv[1]))
