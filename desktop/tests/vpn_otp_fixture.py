"""Private VPN OTP verifier: real HTTPS forms, generated TOTP/HOTP and safe audit.

This module never writes request bodies, codes, or secrets. RFC test keys are
synthetic. A successful OpenConnect code leads to a manual form, not a claimed
CSTP tunnel. OpenVPN connected is verified separately through a real server.
"""
import base64
from dataclasses import dataclass, field as datafield
import hashlib
import hmac
import http.server
import json
import os
from pathlib import Path
import re
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

from vpn_auth_fixture import FORM_USER, FORM_PASSWORD, USER, PASSWORD, Rpc, field, parse

SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'


def code_at(counter, secret=SECRET, algorithm='SHA1', digits=6):
    """Independent standard-library HMAC verifier, checked against RFC vectors."""
    assert 0 <= counter <= (1 << 63) - 1 and 4 <= digits <= 10
    digest = hmac.new(base64.b32decode(secret), struct.pack('>Q', counter),
                      {'SHA1': hashlib.sha1, 'SHA256': hashlib.sha256,
                       'SHA512': hashlib.sha512}[algorithm]).digest()
    offset = digest[-1] & 15
    number = int.from_bytes(digest[offset:offset + 4], 'big') & 0x7fffffff
    return str(number % (10 ** digits)).zfill(digits)


def verify_vectors():
    expected = ['755224', '287082', '359152', '969429', '338314',
                '254676', '287922', '162583', '399871', '520489']
    assert all(code_at(index) == value for index, value in enumerate(expected))
    assert code_at(59 // 30, digits=8) == '94287082'
    return 11


@dataclass
class Case:
    kind: str = 'hotp'
    counter: int = 0
    period: int = 8
    algorithm: str = 'SHA1'
    digits: int = 6
    secret: str = SECRET
    shape: str = 'otp'  # otp, login, template, unknown
    steps: int = 1
    reject_valid: int = 0
    always_reject: bool = False
    drop_after_valid: bool = False
    template: str = 'prefix-{otp}-suffix-{otp}'
    stage: str = 'new'
    requests: int = 0
    attempts: int = 0
    verified: int = 0
    rejected: int = 0
    seen: set = datafield(default_factory=set, repr=False)


class OtpFormServer:
    """One path per scenario; register before Start, inspect only safe events.

    add_case returns an endpoint config. All state transitions are serialized
    with the request audit. The HTTPS server binds exclusively to loopback.
    """
    def __init__(self, certificate, key, events=None):
        self.certificate = str(certificate)
        self.events_path = Path(events) if events else None
        self.events = []
        self.cases = {}
        self.lock = threading.Lock()
        owner = self

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
                if not 0 <= length <= 65536 or self.path not in owner.cases:
                    self.send_error(400)
                    return
                body = self.rfile.read(length)
                try:
                    document = ET.fromstring(body)
                    auth = document.find('auth')
                    values = {} if auth is None else {node.tag: node.text or '' for node in auth if len(node) == 0}
                    duplicate = auth is not None and len(values) != len(list(auth))
                except ET.ParseError:
                    self.send_error(400)
                    return
                with owner.lock:
                    case = owner.cases[self.path]
                    case.requests += 1
                    response = auth is not None and bool(values)
                    if response:
                        case.attempts += 1
                    owner.record({'case': self.path, 'event': 'received',
                                  'request': case.requests, 'attempt': case.attempts,
                                  'response': response, 'tls': True})
                    error = False
                    if not response:
                        case.stage = 'login' if case.shape == 'login' else 'otp'
                    elif case.stage == 'login':
                        exact = not duplicate and values == {'username': FORM_USER, 'password': FORM_PASSWORD, 'realm': 'two'}
                        owner.record({'case': self.path, 'event': 'validated',
                                      'attempt': case.attempts, 'formExact': exact})
                        case.stage = 'otp' if exact else 'login'
                        error = not exact
                    elif case.stage == 'otp':
                        # Count before validating: a failed durable save must
                        # yield no response event at all, not just no valid code.
                        step = case.counter + 1 if case.kind == 'hotp' else int(time.time()) // case.period
                        candidates = [step] if case.kind == 'hotp' else [step, step - 1]
                        field_name = 'custom_challenge' if case.shape == 'template' else 'password'
                        submitted = values.get(field_name, '')
                        matched = None
                        for candidate in candidates:
                            generated = code_at(candidate, case.secret, case.algorithm, case.digits)
                            wanted = case.template.replace('{otp}', generated) if case.shape == 'template' else generated
                            if hmac.compare_digest(submitted, wanted):
                                matched = candidate
                                break
                        exact = not duplicate and set(values) == {field_name} and matched is not None
                        repeated = submitted in case.seen
                        case.seen.add(submitted)
                        if exact:
                            case.verified += 1
                            if case.kind == 'hotp':
                                case.counter = matched
                        reject = not exact or case.always_reject or case.rejected < case.reject_valid
                        if exact and reject:
                            case.rejected += 1
                        owner.record({'case': self.path, 'event': 'validated',
                                      'attempt': case.attempts, 'otpExact': exact,
                                      'codeRepeated': repeated, 'rejected': reject,
                                      'counter': str(matched) if exact and case.kind == 'hotp' else None,
                                      'timeStep': matched if exact and case.kind == 'totp' else None,
                                      'previousTimeStep': exact and case.kind == 'totp' and matched != step})
                        if exact and case.drop_after_valid:
                            self.close_connection = True
                            self.connection.shutdown(socket.SHUT_RDWR)
                            return
                        error = reject
                        case.stage = 'otp' if reject or case.verified < case.steps else 'manual'
                    else:
                        owner.record({'case': self.path, 'event': 'validated',
                                      'attempt': case.attempts, 'manualResponse': True})
                    data = owner.form(self.path, case, error).encode()
                self.send_response(200)
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

    def record(self, event):
        self.events.append(event)
        if self.events_path:
            with self.events_path.open('a') as output:
                output.write(json.dumps(event) + '\n')

    def add_case(self, name, **options):
        assert re.fullmatch('[a-z0-9-]{1,64}', name)
        path = '/otp/' + name
        with self.lock:
            assert path not in self.cases
            case = Case(**options)
            assert case.kind in ('hotp', 'totp') and case.shape in ('otp', 'login', 'template', 'unknown')
            assert 1 <= case.period <= 3600 and 1 <= case.steps <= 8
            self.cases[path] = case
        return {'type': 'openconnect', 'tag': 'proxy',
                'server': f'https://127.0.0.1:{self.server.server_port}{path}',
                'flavor': 'anyconnect', 'system': False, 'no_udp': True,
                'tls': {'certificate_authority_path': self.certificate}}

    @staticmethod
    def form(path, case, error):
        if case.stage == 'login':
            fields = ('<input type="text" name="username" label="User"/>'
                      '<input type="password" name="password" label="Password"/>'
                      '<select name="realm" label="Realm"><option value="one">One</option>'
                      '<option value="two">Two</option></select>')
        elif case.stage == 'manual' or case.shape == 'unknown':
            fields = '<input type="text" name="operator_note" label="Operator note"/>'
        elif case.shape == 'template':
            fields = '<input type="password" name="custom_challenge" label="Private field"/>'
        else:
            fields = '<input type="password" name="answer" label="One-time code"/>'
        reason = '<error>Owned verifier rejected this response</error>' if error else ''
        return ('<config-auth><auth id="' + case.stage + '">' + reason +
                '<message>Owned generated-code verification</message>'
                '<form method="POST" action="' + escape(path, {'"': '&quot;'}) + '">' +
                fields + '</form></auth></config-auth>')

    def observations(self, name):
        with self.lock:
            return [dict(event) for event in self.events if event['case'] == '/otp/' + name]

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


def openvpn_server(certificate, key, port, counter=1, tag='otp-server'):
    packed = 'SCRV1:' + base64.b64encode(PASSWORD.encode()).decode() + ':' + base64.b64encode(code_at(counter).encode()).decode()
    return {'type': 'openvpn-server', 'tag': tag, 'listen': '127.0.0.1',
            'listen_port': port, 'network': 'udp', 'system': False,
            'address': ['10.77.0.1/24'], 'topology': 'subnet',
            'users': [{'username': USER, 'password': packed}],
            'tls': {'certificate_path': str(certificate), 'key_path': str(key),
                    'verify_client_certificate': 'none'}}


def openvpn_start_server(certificate, key, port, counter=1, tag='otp-start-server'):
    """Accepts one before-Start code shape per user: a plain code as the password,
    or Qt's SCRV1 packing of a substituted password plus the code."""
    code = code_at(counter)
    packed = 'SCRV1:' + base64.b64encode((PASSWORD + '-' + code).encode()).decode() + ':' + base64.b64encode(code.encode()).decode()
    return {'type': 'openvpn-server', 'tag': tag, 'listen': '127.0.0.1',
            'listen_port': port, 'network': 'udp', 'system': False,
            'address': ['10.78.0.1/24'], 'topology': 'subnet',
            'users': [{'username': USER, 'password': code},
                      {'username': USER + '-scrv1', 'password': packed}],
            'tls': {'certificate_path': str(certificate), 'key_path': str(key),
                    'verify_client_certificate': 'none'}}


def certificate_files(root):
    certificate, key = root / 'certificate.pem', root / 'private-key.pem'
    with (root / 'certificate-generation.log').open('w') as output:
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
            '-keyout', str(key), '-out', str(certificate), '-days', '1',
            '-subj', '/CN=vpn.fixture.invalid',
            '-addext', 'subjectAltName=IP:127.0.0.1,DNS:vpn.fixture.invalid',
            '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'authorityKeyIdentifier=keyid:always',
            '-addext', 'keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign',
            '-addext', 'extendedKeyUsage=serverAuth'], check=True,
            stdout=output, stderr=subprocess.STDOUT)
    key.chmod(0o600)
    return certificate, key


def load(rpc, endpoints):
    config = {'log': {'disabled': True}, 'endpoints': endpoints,
              'outbounds': [{'type': 'direct', 'tag': 'direct'}], 'route': {'final': 'direct'}}
    payload = field(1, json.dumps(config)) + field(2, 1) + field(9, 0)
    rpc.call('CheckConfig', payload)
    rpc.call('Start', payload)


def wait_challenge(rpc, state='auth-pending', previous=None):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        response = rpc.call('QueryVPNStatus', field(1, 'proxy'), error_response=False)
        value = parse(response[1][0])
        challenge = parse(value[16][0]) if value.get(16) else None
        if value.get(2) == [state.encode()] and (previous is None or challenge and challenge[2][0] != previous):
            return value, challenge
        time.sleep(.03)
    raise AssertionError('otp_fixture_state_timeout')


def submit_fields(rpc, challenge, answers):
    payload = field(1, 'proxy') + field(2, challenge[2][0])
    for raw in challenge[11]:
        item = parse(raw)
        name = item[2][0].decode()
        assert name in answers, 'otp_fixture_unexpected_field'
        payload += field(6, field(1, item[1][0]) + field(2, answers[name]))
    rpc.call('SubmitVPNChallenge', payload)


def self_check(root, server, ready):
    """Actual Core, manual generated answers only; no auto-binding claim."""
    result = {'rfcVectors': verify_vectors(), 'manualCoreFixtureOnly': True,
              'automaticBindingTested': False, 'cstpConnectedClaimed': False}
    rpc = Rpc(root, 'client')
    try:
        endpoint = dict(ready['openvpn'])
        load(rpc, [endpoint])
        _, challenge = wait_challenge(rpc)
        assert challenge[3] == [b'credentials']
        rpc.call('SubmitVPNChallenge', field(1, 'proxy') + field(2, challenge[2][0]) +
                 field(3, USER) + field(4, PASSWORD) + field(5, code_at(1)))
        value, challenge = wait_challenge(rpc, 'connected')
        assert value[4] == [1] and challenge is None
        result['openvpnGeneratedHotpConnected'] = True
        rpc.call('Stop')

        load(rpc, [ready['endpoints']['hotp-two']])
        _, challenge = wait_challenge(rpc)
        for counter in [1, 2]:
            previous = challenge[2][0]
            submit_fields(rpc, challenge, {'answer': code_at(counter)})
            _, challenge = wait_challenge(rpc, previous=previous)
        assert parse(challenge[11][0])[2] == [b'operator_note']
        rows = [row for row in server.observations('hotp-two') if row.get('otpExact')]
        assert [row['counter'] for row in rows] == ['1', '2']
        result['hotpStepsExact'] = 2
        rpc.call('Stop')

        load(rpc, [ready['endpoints']['totp-login']])
        _, challenge = wait_challenge(rpc)
        previous = challenge[2][0]
        submit_fields(rpc, challenge, {'username': FORM_USER, 'password': FORM_PASSWORD, 'realm': 'two'})
        _, challenge = wait_challenge(rpc, previous=previous)
        previous = challenge[2][0]
        submit_fields(rpc, challenge, {'answer': code_at(int(time.time()) // 8)})
        _, challenge = wait_challenge(rpc, previous=previous)
        rows = server.observations('totp-login')
        assert any(row.get('formExact') for row in rows) and any(row.get('otpExact') for row in rows)
        result['totpFormAndCodeExact'] = True
        rpc.call('Stop')

        load(rpc, [ready['endpoints']['hotp-login']])
        _, challenge = wait_challenge(rpc)
        previous = challenge[2][0]
        submit_fields(rpc, challenge, {'username': FORM_USER, 'password': FORM_PASSWORD, 'realm': 'two'})
        _, challenge = wait_challenge(rpc, previous=previous)
        previous = challenge[2][0]
        submit_fields(rpc, challenge, {'answer': code_at(1)})
        _, challenge = wait_challenge(rpc, previous=previous)
        rows = server.observations('hotp-login')
        assert len([row for row in rows if row.get('formExact')]) == 1
        assert [row['counter'] for row in rows if row.get('otpExact')] == ['1']
        result['hotpLoginThenC1Exact'] = True
        rpc.call('Stop')

        load(rpc, [ready['endpoints']['hotp-template']])
        _, challenge = wait_challenge(rpc)
        previous = challenge[2][0]
        submit_fields(rpc, challenge, {'custom_challenge': Case().template.replace('{otp}', code_at(1))})
        _, challenge = wait_challenge(rpc, previous=previous)
        assert any(row.get('otpExact') for row in server.observations('hotp-template'))
        result['repeatedPlaceholderExact'] = True
        rpc.call('Stop')

        load(rpc, [ready['endpoints']['totp-reject']])
        _, challenge = wait_challenge(rpc)
        while time.time() % 8 > 5:
            time.sleep(.05)
        answer = code_at(int(time.time()) // 8)
        for _ in range(2):
            previous = challenge[2][0]
            submit_fields(rpc, challenge, {'answer': answer})
            _, challenge = wait_challenge(rpc, previous=previous)
            assert challenge.get(7), 'otp_fixture_missing_rejection_error'
        rows = [row for row in server.observations('totp-reject') if row.get('otpExact')]
        assert len(rows) == 2 and rows[-1]['codeRepeated'] and all(row['rejected'] for row in rows)
        result['repeatedRejectedTotpObservable'] = True
        rpc.call('CancelVPNChallenge', field(1, 'proxy') + field(2, challenge[2][0]))
        rpc.call('Stop')
        result['httpsRequests'] = len([row for row in server.events if row['event'] == 'received'])
        result['authResponses'] = len([row for row in server.events if row['event'] == 'received' and row['response']])
        return result
    finally:
        rpc.close()


def serve(root):
    root = root.resolve()
    assert Path(sys.executable).resolve() == root / 'Thronium', 'otp_fixture_parent_identity_required'
    assert root.stat().st_uid == os.getuid() and root.stat().st_mode & 0o077 == 0
    verify_vectors()
    certificate, key = certificate_files(root)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(('127.0.0.1', 0))
        start_port = reservation.getsockname()[1]
    rpc = Rpc(root)
    server = None
    try:
        load(rpc, [openvpn_server(certificate, key, port), openvpn_start_server(certificate, key, start_port)])
        server = OtpFormServer(certificate, key, root / 'events.jsonl')
        endpoints = {
            'hotp-two': server.add_case('hotp-two', steps=2),
            'hotp-one': server.add_case('hotp-one'),
            'hotp-login': server.add_case('hotp-login', shape='login'),
            'hotp-reject': server.add_case('hotp-reject', always_reject=True),
            'hotp-drop': server.add_case('hotp-drop', drop_after_valid=True),
            'hotp-template': server.add_case('hotp-template', shape='template'),
            'hotp-unknown': server.add_case('hotp-unknown', shape='unknown'),
            'totp-one': server.add_case('totp-one', kind='totp'),
            'totp-login': server.add_case('totp-login', kind='totp', shape='login'),
            'totp-reject': server.add_case('totp-reject', kind='totp', always_reject=True),
        }
        ready = {'endpoints': endpoints, 'certificate': str(certificate),
                 'events': str(root / 'events.jsonl'), 'serverCorePid': rpc.process.pid,
                 'totpPeriod': 8,
                 'openvpn': {'type': 'openvpn-client', 'tag': 'proxy',
                    'server': '127.0.0.1', 'server_port': port, 'network': 'udp',
                    'system': False, 'static_challenge': 'Owned generated HOTP',
                    'tls': {'certificate_path': str(certificate), 'server_name': 'vpn.fixture.invalid'}},
                 'openvpnStart': {'type': 'openvpn-client', 'tag': 'proxy',
                    'server': '127.0.0.1', 'server_port': start_port, 'network': 'udp',
                    'system': False,
                    'tls': {'certificate_path': str(certificate), 'server_name': 'vpn.fixture.invalid'}}}
        print(json.dumps(ready), flush=True)
        if '--self-check' in sys.argv:
            print(json.dumps(self_check(root, server, ready)), flush=True)
        else:
            sys.stdin.buffer.read()
    finally:
        if server:
            server.close()
        rpc.close()


if __name__ == '__main__':
    serve(Path(sys.argv[1]))
