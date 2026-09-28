#!/usr/bin/env python3
"""Actual core before/after cancellation, owned HTTPS forms, no system tunnel."""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

REPOSITORY = Path(__file__).resolve().parents[2]

def varint(n):
    out = bytearray()
    while n > 127:
        out.append((n & 127) | 128)
        n >>= 7
    out.append(n)
    return bytes(out)

def field(n, value):
    if isinstance(value, int):
        return varint(n << 3) + varint(value)
    if isinstance(value, str):
        value = value.encode()
    return varint((n << 3) | 2) + varint(len(value)) + value

def unvar(data, i):
    n = shift = 0
    while True:
        value = data[i]
        i += 1
        n |= (value & 127) << shift
        if value < 128:
            return n, i
        shift += 7
        assert shift < 70

def parse(data):
    out, i = {}, 0
    while i < len(data):
        key, i = unvar(data, i)
        if key & 7 == 0:
            value, i = unvar(data, i)
        elif key & 7 == 2:
            size, i = unvar(data, i)
            value, i = data[i:i + size], i + size
            assert len(value) == size
        else:
            raise AssertionError('unexpected wire type')
        out.setdefault(key >> 3, []).append(value)
    return out

def value(data, key, default=b''):
    return data.get(key, [default])[0]

def text(data, key):
    return value(data, key).decode()

class Rpc:
    def __init__(self, root):
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(str(root / 'core.sock'))
        self.listener.listen()
        self.listener.settimeout(8)
        self.log = (root / 'core.log').open('w')
        self.process = subprocess.Popen([str(root / 'ThroniumCore')], cwd=root,
            env={**os.environ, 'THRONE_CORE_SOCKET': str(root / 'core.sock')},
            stdin=subprocess.DEVNULL, stdout=self.log, stderr=self.log)
        self.socket, _ = self.listener.accept()
        self.socket.settimeout(8)
        pid, uid, _ = struct.unpack('3i', self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        assert pid == self.process.pid and uid == os.getuid()
        self.sequence = 0

    def read(self, size):
        data = b''
        while len(data) < size:
            part = self.socket.recv(size - len(data))
            assert part
            data += part
        return data

    def call(self, method, payload=b''):
        self.sequence += 1
        name = method.encode()
        self.socket.sendall(struct.pack('<IH', self.sequence, len(name)) + name + struct.pack('<I', len(payload)) + payload)
        sequence, status, size = struct.unpack('<IBI', self.read(9))
        assert sequence == self.sequence and size <= 16 * 1024 * 1024
        reply = self.read(size)
        assert status == 0, reply
        return parse(reply)

    def status(self, tag):
        reply = self.call('QueryVPNStatus', field(1, tag))
        status = parse(value(reply, 1))
        challenge = parse(value(status, 16)) if value(status, 16) else None
        return status, challenge

    def wait(self, tag, state, timeout=5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status, challenge = self.status(tag)
            if text(status, 2) == state:
                return status, challenge
            time.sleep(.02)
        raise AssertionError((tag, state, text(status, 2), text(status, 3)))

    def challenge(self, tag):
        status, challenge = self.wait(tag, 'auth-pending')
        assert challenge is not None and text(challenge, 3) == 'form'
        return challenge

    def cancel(self, tag, challenge_id):
        return text(self.call('CancelVPNChallenge', field(1, tag) + field(2, challenge_id)), 1)

    def submit(self, tag, challenge):
        payload = field(1, tag) + field(2, text(challenge, 2))
        values = {'username': 'fixture-user', 'password': 'fixture-password', 'realm': 'two', 'answer': 'synthetic-otp'}
        for raw in challenge[11]:
            item = parse(raw)
            payload += field(6, field(1, text(item, 1)) + field(2, values[text(item, 2)]))
        assert not text(self.call('SubmitVPNChallenge', payload), 1)

    def stop(self):
        assert not text(self.call('Stop'), 1)

    def close(self):
        self.socket.close()
        self.listener.close()
        assert self.process.wait(timeout=8) == 0
        self.log.close()

class FormServer:
    def __init__(self, cert, key):
        self.events = []
        self.lock = threading.Lock()
        owner = self
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def log_message(self, *args): pass
            def do_POST(self):
                size = int(self.headers.get('Content-Length', '0'))
                assert size <= 65536
                body = self.rfile.read(size)
                with owner.lock:
                    owner.events.append(body.decode())
                    first = len(owner.events) == 1
                if first:
                    xml = b'<config-auth><auth id="login"><message>Owned authentication fixture</message><form method="POST" action="/"><input type="text" name="username" label="User"/><input type="password" name="password" label="Password"/><select name="realm" label="Realm"><option value="one">One</option><option value="two">Two</option></select></form></auth></config-auth>'
                else:
                    xml = b'<config-auth><auth id="challenge"><message>Owned OTP fixture</message><form method="POST" action="/"><input type="password" name="answer" label="One-time code"/></form></auth></config-auth>'
                self.send_response(200)
                self.send_header('Content-Type', 'text/xml')
                self.send_header('Content-Length', str(len(xml)))
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(xml)
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def count(self):
        with self.lock: return len(self.events)

    def endpoint(self, tag, cert):
        return {'type': 'openconnect', 'tag': tag, 'server': f'https://127.0.0.1:{self.server.server_port}/',
                'flavor': 'anyconnect', 'system': False, 'no_udp': True,
                'tls': {'certificate_authority_path': str(cert)}}

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

def get(proxy_port, origin_port):
    with socket.create_connection(('127.0.0.1', proxy_port), timeout=5) as connection:
        connection.sendall(f'GET http://127.0.0.1:{origin_port}/owned HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nConnection: close\r\n\r\n'.encode())
        response = b''
        while True:
            part = connection.recv(4096)
            if not part: break
            response += part
        assert response.startswith(b'HTTP/1.1 200') and response.endswith(b'owned-cancel-control'), response

def child(args):
    root = Path(sys.executable).parent
    output = args.artifacts.resolve()
    cert, key = root / 'cert.pem', root / 'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=vpn.fixture.invalid', '-addext', 'subjectAltName=IP:127.0.0.1,DNS:vpn.fixture.invalid', '-addext', 'keyUsage=digitalSignature,keyEncipherment,keyCertSign', '-addext', 'extendedKeyUsage=serverAuth'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    a, b = FormServer(cert, key), FormServer(cert, key)
    class Origin(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self, *args): pass
        def do_GET(self):
            body = b'owned-cancel-control'
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(body)
    origin = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Origin)
    origin.daemon_threads = True
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        proxy_port = reservation.getsockname()[1]
    config = {'log': {'level': 'debug'}, 'inbounds': [{'type': 'mixed', 'tag': 'owned-in', 'listen': '127.0.0.1', 'listen_port': proxy_port}],
              'endpoints': [a.endpoint('alpha', cert), b.endpoint('beta', cert)],
              'outbounds': [{'type': 'direct', 'tag': 'control', 'udp_fragment': True}], 'route': {'final': 'control'}}
    payload = field(1, json.dumps(config)) + field(2, 1) + field(9, 0)
    before_routes = Path('/proc/net/route').read_text()
    before_interfaces = sorted(os.listdir('/sys/class/net'))
    rpc = Rpc(root)
    observations = {}
    try:
        assert not text(rpc.call('CheckConfig', payload), 1)
        assert (a.count(), b.count()) == (0, 0)
        assert not text(rpc.call('Start', payload), 1)
        first_a, first_b = rpc.challenge('alpha'), rpc.challenge('beta')
        assert text(first_a, 2) != text(first_b, 2)
        get(proxy_port, origin.server_port)
        assert rpc.cancel('alpha', text(first_b, 2))
        assert rpc.cancel('unknown-tag', text(first_a, 2))
        assert text(rpc.challenge('alpha'), 2) == text(first_a, 2)
        assert text(rpc.challenge('beta'), 2) == text(first_b, 2)
        rpc.submit('alpha', first_a)
        deadline = time.monotonic() + 5
        while True:
            second_a = rpc.challenge('alpha')
            if text(second_a, 2) != text(first_a, 2): break
            assert time.monotonic() < deadline
        assert all(token in a.events[1] for token in ['fixture-user', 'fixture-password', 'two'])
        assert rpc.cancel('alpha', text(first_a, 2))
        assert text(rpc.challenge('alpha'), 2) == text(second_a, 2)
        counts = (a.count(), b.count())
        assert not rpc.cancel('alpha', text(second_a, 2))
        assert rpc.cancel('alpha', text(second_a, 2))
        if args.expect == 'before':
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                status, repeated = rpc.status('alpha')
                if repeated is not None and text(repeated, 2) != text(second_a, 2): break
                time.sleep(.02)
            else: raise AssertionError('expected old-core cancellation re-prompt not observed')
            assert a.count() > counts[0]
            assert rpc.cancel('alpha', text(second_a, 2))
            assert text(rpc.challenge('alpha'), 2) == text(repeated, 2)
            observations['expectedRegression'] = 'Cancel acknowledged, then a new HTTPS request and new auth challenge'
        else:
            status, pending = rpc.wait('alpha', 'error')
            assert pending is None and 'authentication challenge canceled' in text(status, 3)
            assert value(status, 4, 0) == 0 and value(status, 17, 0) == 0
            deadline = time.monotonic() + 2.25
            polls = 0
            while time.monotonic() < deadline:
                status, pending = rpc.status('alpha')
                assert text(status, 2) == 'error' and pending is None
                assert 'authentication challenge canceled' in text(status, 3)
                assert value(status, 17, 0) == 0
                assert (a.count(), b.count()) == counts
                assert text(rpc.challenge('beta'), 2) == text(first_b, 2)
                polls += 1
                time.sleep(.04)
            observations.update(terminalPolls=polls, minimumQuietMs=2250, authFailed=False)
        get(proxy_port, origin.server_port)
        assert text(rpc.challenge('beta'), 2) == text(first_b, 2)
        rpc.submit('beta', first_b)
        deadline = time.monotonic() + 5
        while True:
            second_b = rpc.challenge('beta')
            if text(second_b, 2) != text(first_b, 2): break
            assert time.monotonic() < deadline
        assert b.count() == 2 and all(token in b.events[1] for token in ['fixture-user', 'fixture-password', 'two'])
        assert not rpc.cancel('beta', text(second_b, 2))
        if args.expect == 'after':
            status, pending = rpc.wait('beta', 'error')
            assert pending is None and value(status, 17, 0) == 0
        rpc.stop()
        rpc.stop()
        assert not rpc.call('QueryVPNStatus').get(1)
        if args.expect == 'after':
            assert not text(rpc.call('Start', payload), 1)
            current_a, current_b = rpc.challenge('alpha'), rpc.challenge('beta')
            assert text(current_a, 2) != text(second_a, 2) and text(current_b, 2) != text(second_b, 2)
            assert rpc.cancel('alpha', text(second_a, 2))
            assert text(rpc.challenge('alpha'), 2) == text(current_a, 2)
            assert not rpc.cancel('alpha', text(current_a, 2))
            assert not rpc.cancel('beta', text(current_b, 2))
            for tag in ['alpha', 'beta']:
                status, pending = rpc.wait(tag, 'error')
                assert pending is None and value(status, 17, 0) == 0
            counts = (a.count(), b.count())
            time.sleep(1.25)
            assert (a.count(), b.count()) == counts
            get(proxy_port, origin.server_port)
            rpc.stop()
        observations.update(staleAndCrossEndpointRefused=True, repeatedCancelNoSideEffect=True, otherEndpointSubmitted=True, directHttpResponses=3 if args.expect == 'after' else 2, stopIdempotent=True, manualRestart=args.expect == 'after', requests={'alpha': a.count(), 'beta': b.count()})
    finally:
        rpc.stop()
        rpc.close()
        a.close()
        b.close()
        origin.shutdown()
        origin.server_close()
        shutil.copy2(root / 'core.log', output / 'core.log')
        (output / 'https-events.json').write_text(json.dumps({'alpha': a.events, 'beta': b.events}, indent=2) + '\n')
    assert Path('/proc/net/route').read_text() == before_routes
    assert sorted(os.listdir('/sys/class/net')) == before_interfaces
    with socket.socket() as released:
        released.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        released.bind(('127.0.0.1', proxy_port))
        released.listen()
    report = {'passed': True, 'expectation': args.expect, 'terminalCancellationSupported': args.expect == 'after', 'coreSha256': hashlib.sha256((root / 'ThroniumCore').read_bytes()).hexdigest(), 'observations': observations, 'hostRoutesAndInterfacesUnchanged': True, 'systemTun': False, 'browserSso': False}
    (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report), flush=True)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--core', type=Path, required=True)
    parser.add_argument('--core-sha256', required=True)
    parser.add_argument('--expect', choices=['before', 'after'], required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get('THRONIUM_CANCEL_FIXTURE_CHILD'):
        child(args)
        return
    core = args.core.resolve()
    assert hashlib.sha256(core.read_bytes()).hexdigest() == args.core_sha256
    output = args.artifacts.resolve()
    output.mkdir(parents=True, exist_ok=False)
    shutil.copy2(Path(__file__), output / 'source.py')
    with tempfile.TemporaryDirectory(prefix='thronium-openconnect-cancel-') as directory:
        root = Path(directory)
        shutil.copy2(Path(sys.executable).resolve(), root / 'Thronium')
        shutil.copy2(core, root / 'ThroniumCore')
        environment = {**os.environ, 'PYTHONHOME': sys.prefix, 'THRONIUM_CANCEL_FIXTURE_CHILD': '1'}
        for name in ['http_proxy', 'https_proxy', 'all_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY']:
            environment.pop(name, None)
        for name in ['XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'XDG_STATE_HOME', 'XDG_RUNTIME_DIR']:
            path = root / name.lower()
            path.mkdir(mode=0o700)
            environment[name] = str(path)
        command = [str(root / 'Thronium'), str(Path(__file__).resolve()), '--core', str(core), '--core-sha256', args.core_sha256, '--expect', args.expect, '--artifacts', str(output)]
        result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=45)
        (output / 'run.log').write_text(result.stdout + result.stderr)
        (output / 'command.json').write_text(json.dumps(command, indent=2) + '\n')
        print(result.stdout, end='')
        print(result.stderr, end='')
        result.check_returncode()

if __name__ == '__main__':
    main()
