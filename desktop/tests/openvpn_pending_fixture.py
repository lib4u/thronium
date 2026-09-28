"""An actual OpenVPN 2.7 server that asks the client to finish signing in.

Every flow of `client-pending-auth` is scripted from the management interface:
a text challenge, a notice with nothing to answer, a link to open, a challenge
that is never answered before its own deadline, and the dynamic CRV1 challenge
an AUTH_FAILED carries. Only loopback is used and no answer is ever written to
a file; the fixture reports what it saw, never what it was told.
"""
import base64
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time

USER = 'pending-user'
RELOGIN_USER = 'relogin-user'
PASSWORD = 'pending-password'
ANSWER = 'pending-answer'
CRV1_STATE = 'state-42'
CRV1_TEXT = 'Enter the code from your token'
TEXT_CHALLENGE = 'Enter the code shown on your phone'
NOTICE = 'Your session will be recorded'
OPEN_URL = 'https://sign-in.fixture.invalid/continue'
# Short enough for a test to watch it lapse, long enough not to race the core.
EXPIRY_SECONDS = 4


def certificate(root):
    """A self-signed certificate of this run; it is its own authority."""
    key, cert = root / 'server.key', root / 'server.crt'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-keyout', str(key), '-out', str(cert), '-days', '1',
                    '-subj', '/CN=openvpn.fixture.invalid',
                    '-addext', 'subjectAltName=IP:127.0.0.1,DNS:openvpn.fixture.invalid',
                    '-addext', 'basicConstraints=critical,CA:TRUE',
                    '-addext', 'authorityKeyIdentifier=keyid:always',
                    '-addext', 'keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign',
                    '-addext', 'extendedKeyUsage=serverAuth'],
                   check=True, capture_output=True, timeout=60)
    key.chmod(0o600)
    return key, cert


class Management(threading.Thread):
    """Answers every connecting client the way the chosen case asks for."""

    def __init__(self, port, state, lock):
        super().__init__(daemon=True)
        self.port = port
        self.state = state
        self.lock = lock
        self.socket = None
        self.stopping = threading.Event()

    def send(self, line):
        with self.lock:
            self.state['sent'].append(line.split(' ')[0])
        try:
            self.socket.sendall((line + '\n').encode())
        except OSError:
            pass

    def decide(self, cid, kid, environment):
        with self.lock:
            case = self.state['case']
            pending = self.state['pending'].get(cid)
            self.state['seen'].append({'case': case, 'username': bool(environment.get('username')),
                                       'answered': bool(pending)})
        password = environment.get('password', '')
        if case == 'restart':
            # The server refuses the first codes and accepts a later one, so the
            # client must come back with digits it has not used yet.
            with self.lock:
                seen = [entry for entry in self.state['seen'] if entry['case'] == 'restart']
                used = self.state.setdefault('codes', [])
                if password:
                    used.append(password)
            if len(seen) <= 2:
                return self.send(f'client-deny {cid} {kid} "stale code" "stale code"')
            return self.send(f'client-auth-nt {cid} {kid}')
        if case == 'relogin':
            # Only the person's new user is let in, whatever the profile holds.
            if environment.get('username') == RELOGIN_USER:
                return self.send(f'client-auth-nt {cid} {kid}')
            return self.send(f'client-deny {cid} {kid} "wrong user" "wrong user"')
        if case == 'crv1':
            # The dynamic challenge travels in the reason of a refusal; the
            # answer comes back packed into the password field.
            if password.startswith('CRV1::' + CRV1_STATE + '::'):
                if password.split('::')[-1] == ANSWER:
                    return self.send(f'client-auth-nt {cid} {kid}')
                return self.send(f'client-deny {cid} {kid} "wrong answer" "wrong answer"')
            user = environment.get('username', '')
            packed = base64.b64encode(user.encode()).decode()
            return self.send(
                f'client-deny {cid} {kid} "challenge" "CRV1:R,E:{CRV1_STATE}:{packed}:{CRV1_TEXT}"')
        if pending:
            # A notice has nothing to answer, so the client is let in as soon as
            # it acknowledges by asking again.
            with self.lock:
                self.state['pending'].pop(cid, None)
            if case in ('notice', 'url'):
                return self.send(f'client-auth-nt {cid} {kid}')
            return self.send(f'client-deny {cid} {kid} "no answer" "no answer"')
        extra = {
            'text': f'CR_TEXT:E,R:{TEXT_CHALLENGE}',
            'expired': f'CR_TEXT:E,R:{TEXT_CHALLENGE}',
            'notice': f'CR_TEXT:E,:{NOTICE}',
            'url': f'OPEN_URL:{OPEN_URL}',
        }.get(case)
        if extra is None:
            return self.send(f'client-auth-nt {cid} {kid}')
        with self.lock:
            self.state['pending'][cid] = case
        timeout = EXPIRY_SECONDS if case == 'expired' else 60
        self.send(f'client-pending-auth {cid} {kid} "{extra}" {timeout}')
        if case in ('notice', 'url'):
            # Nothing comes back from the client for these: a notice is only
            # read, and a link is followed outside the tunnel. The server makes
            # up its own mind shortly afterwards, as a real one would.
            timer = threading.Timer(1.5, lambda: self.send(f'client-auth-nt {cid} {kid}'))
            timer.daemon = True
            timer.start()
        return None

    def answered(self, cid, kid, encoded):
        """`>CLIENT:CR_RESPONSE` carries the answer to a pending challenge."""
        try:
            answer = base64.b64decode(encoded, validate=True).decode('utf-8', 'replace')
        except ValueError:
            answer = ''
        with self.lock:
            case = self.state['case']
            self.state['pending'].pop(cid, None)
            self.state['seen'].append({'case': case, 'crResponse': True,
                                       'accepted': answer == ANSWER})
        if answer == ANSWER:
            return self.send(f'client-auth-nt {cid} {kid}')
        return self.send(f'client-deny {cid} {kid} "wrong answer" "wrong answer"')

    def run(self):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                self.socket = socket.create_connection(('127.0.0.1', self.port), timeout=5)
                break
            except OSError:
                time.sleep(.1)
        else:
            return
        self.socket.settimeout(1)
        buffered, cid, kid, environment = '', None, None, {}
        while not self.stopping.is_set():
            try:
                chunk = self.socket.recv(65536).decode('utf-8', 'replace')
            except socket.timeout:
                continue
            except OSError:
                return
            if not chunk:
                return
            buffered += chunk
            while '\n' in buffered:
                line, buffered = buffered.split('\n', 1)
                line = line.strip()
                if line.startswith('>CLIENT:CR_RESPONSE'):
                    parts = line.split(',')
                    if len(parts) >= 4:
                        self.answered(parts[1], parts[2], parts[3])
                    cid, environment = None, {}
                elif line.startswith('>CLIENT:CONNECT') or line.startswith('>CLIENT:REAUTH'):
                    parts = line.split(',')
                    cid, kid, environment = parts[1], parts[2], {}
                elif line.startswith('>CLIENT:ENV,') and cid is not None:
                    value = line[len('>CLIENT:ENV,'):]
                    if value == 'END':
                        self.decide(cid, kid, environment)
                        cid, environment = None, {}
                    elif '=' in value:
                        name, _, content = value.partition('=')
                        environment[name] = content


def main(root):
    root = Path(root)
    key, cert = certificate(root)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserved:
        reserved.bind(('127.0.0.1', 0))
        vpn_port = reserved.getsockname()[1]
    with socket.socket() as reserved:
        reserved.bind(('127.0.0.1', 0))
        management_port = reserved.getsockname()[1]
    config = root / 'server.conf'
    config.write_text('\n'.join([
        'mode server', 'tls-server', 'dev null', 'proto udp',
        'local 127.0.0.1', f'lport {vpn_port}',
        'server 10.79.9.0 255.255.255.0',
        f'ca {cert}', f'cert {cert}', f'key {key}', 'dh none',
        'verify-client-cert none', 'username-as-common-name',
        f'management 127.0.0.1 {management_port}', 'management-client-auth',
        'push "dhcp-option DNS 10.79.9.1"', 'push "route 10.79.8.0 255.255.255.0"',
        'keepalive 10 60', 'verb 3',
    ]) + '\n')
    state = {'case': 'accept', 'pending': {}, 'seen': [], 'sent': [], 'codes': []}
    lock = threading.Lock()
    log = (root / 'openvpn.log').open('w')
    server = subprocess.Popen(['openvpn', '--config', str(config)], cwd=root,
                              stdout=log, stderr=subprocess.STDOUT)
    management = Management(management_port, state, lock)
    management.start()

    class Admin(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, *_):
            pass

        def respond(self, body):
            payload = json.dumps(body).encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            with lock:
                self.respond({'case': state['case'], 'seen': list(state['seen']),
                              'sent': list(state['sent']),
                              'distinctCodes': len(set(state['codes'])),
                              'codeCount': len(state['codes'])})

        def do_POST(self):
            values = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))) or b'{}')
            with lock:
                if 'case' in values:
                    state['case'] = values['case']
                if values.get('clear'):
                    state['seen'].clear()
                    state['sent'].clear()
                    state['pending'].clear()
                    state['codes'].clear()
                self.respond({'case': state['case']})

    admin = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Admin)
    admin.daemon_threads = True
    threading.Thread(target=admin.serve_forever, daemon=True).start()
    ready = {'openvpnPort': vpn_port, 'certificate': str(cert),
             'serverName': 'openvpn.fixture.invalid',
             'admin': f'http://127.0.0.1:{admin.server_address[1]}/',
             'user': USER, 'password': PASSWORD, 'answer': ANSWER,
             'reloginUser': RELOGIN_USER,
             'textChallenge': TEXT_CHALLENGE, 'notice': NOTICE, 'openUrl': OPEN_URL,
             'crv1Text': CRV1_TEXT, 'expirySeconds': EXPIRY_SECONDS,
             'openvpnVersion': subprocess.run(['openvpn', '--version'], capture_output=True,
                                              text=True).stdout.splitlines()[0]}
    print(json.dumps(ready), flush=True)
    try:
        sys.stdin.read()
    finally:
        management.stopping.set()
        if management.socket:
            management.socket.close()
        admin.shutdown()
        admin.server_close()
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)
        log.close()
        with lock:
            (root / 'observations.json').write_text(
                json.dumps({'seen': state['seen'], 'sent': state['sent']}, indent=2) + '\n')


if __name__ == '__main__':
    assert os.name == 'posix'
    main(sys.argv[1])
