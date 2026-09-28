"""Real Linux WireGuard server; invoked only in an owned user/network namespace."""
import base64
import http.client
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time

from vpn_auth_fixture import Rpc, field


def run(root, wg):
    assert os.readlink('/proc/self/ns/net') != os.environ['THRONIUM_TEST_ORIGINAL_NETNS']
    assert Path(sys.executable).resolve() == root / 'Thronium'
    checks, requests, servers, threads = [], [], [], []
    rpc = None

    def check(value, name):
        assert value, name
        checks.append(name)
        print('PASS ' + name, flush=True)

    def ip(*args):
        subprocess.run(['ip', *args], check=True, stdout=subprocess.DEVNULL)

    def wire(*args, input=None):
        return subprocess.check_output([str(wg), *args], input=input, text=True).strip()

    def stats():
        return {'handshake': int(wire('show', 'wg78', 'latest-handshakes').split()[1]),
                'transfer': [int(v) for v in wire('show', 'wg78', 'transfer').split()[1:]],
                'endpoint': wire('show', 'wg78', 'endpoints').split()[1]}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append({'path': self.path, 'remote': self.client_address[0]})
            body = b'kernel-wg78:' + self.path.encode() + bytes(65536)
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    class V6(http.server.ThreadingHTTPServer):
        address_family = socket.AF_INET6

    try:
        ip('link', 'set', 'lo', 'up')
        ip('link', 'add', 'wg78', 'type', 'wireguard')
        server_key, client_key, psk = wire('genkey'), wire('genkey'), wire('genpsk')
        server_public, client_public = wire('pubkey', input=server_key), wire('pubkey', input=client_key)
        for name, key in [('server.key', server_key), ('psk.key', psk)]:
            path = root / name
            path.write_text(key + '\n')
            path.chmod(0o600)
        wire('set', 'wg78', 'private-key', str(root / 'server.key'), 'listen-port', '0',
             'peer', client_public, 'preshared-key', str(root / 'psk.key'),
             'allowed-ips', '10.178.78.2/32,fd00:78::2/128')
        ip('address', 'add', '10.178.78.1/24', 'dev', 'wg78')
        ip('-6', 'address', 'add', 'fd00:78::1/64', 'dev', 'wg78', 'nodad')
        ip('link', 'set', 'wg78', 'mtu', '1420', 'up')
        link = json.loads(subprocess.check_output(['ip', '-d', '-j', 'link', 'show', 'wg78']))[0]
        check(link['linkinfo']['info_kind'] == 'wireguard', 'the independent server is a real Linux kernel WireGuard interface')
        for cls, address in [(http.server.ThreadingHTTPServer, '10.178.78.1'), (V6, 'fd00:78::1')]:
            server = cls((address, 18080), Handler)
            server.daemon_threads = True
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            servers.append(server)
            threads.append(thread)
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        endpoint = {'type': 'wireguard', 'tag': 'proxy', 'system': False, 'mtu': 1420,
                    'private_key': client_key, 'address': ['10.178.78.2/32', 'fd00:78::2/128'],
                    'peers': [{'address': '127.0.0.1', 'port': int(wire('show', 'wg78', 'listen-port')),
                               'public_key': server_public, 'pre_shared_key': psk,
                               'allowed_ips': ['10.178.78.1/32', 'fd00:78::1/128']}]}
        rpc = Rpc(root, 'kernel')

        def start(profile):
            config = {'log': {'level': 'error'}, 'endpoints': [profile],
                      'inbounds': [{'type': 'mixed', 'tag': 'mixed', 'listen': '127.0.0.1', 'listen_port': port}],
                      'route': {'final': 'proxy'}}
            payload = field(1, json.dumps(config)) + field(2, 1) + field(9, 0)
            rpc.call('CheckConfig', payload)
            rpc.call('Start', payload)

        def request(host, path, timeout=8):
            client = http.client.HTTPConnection('127.0.0.1', port, timeout=timeout)
            try:
                client.request('GET', 'http://' + host + ':18080' + path)
                response = client.getresponse()
                body = response.read()
                return response.status == 200 and body == b'kernel-wg78:' + path.encode() + bytes(65536)
            finally:
                client.close()

        for cycle in ['initial', 'reconnect']:
            before = stats()
            start(endpoint)
            for host, remote in [('10.178.78.1', '10.178.78.2'), ('[fd00:78::1]', 'fd00:78::2')]:
                path = '/' + cycle + '-' + remote
                check(request(host, path) and {'path': path, 'remote': remote} in requests,
                      cycle + ': 64 KiB HTTP crosses the kernel tunnel from ' + remote)
            after = stats()
            check(after['handshake'] > 0 and all(a > b for a, b in zip(after['transfer'], before['transfer'])),
                  cycle + ': kernel handshake and both traffic counters confirm the exchange')
            rpc.call('Stop')
            time.sleep(1.1)
        for name, key in [('wrong-public-key', 'public_key'), ('wrong-psk', 'pre_shared_key')]:
            invalid = json.loads(json.dumps(endpoint))
            invalid['peers'][0][key] = base64.b64encode(os.urandom(32)).decode()
            count = len(requests)
            start(invalid)
            try:
                success = request('10.178.78.1', '/' + name, timeout=3)
            except (TimeoutError, ConnectionError, http.client.HTTPException):
                success = False
            check(not success and len(requests) == count, name + ': kernel server receives no plaintext request')
            rpc.call('Stop')
        start(endpoint)
        check(request('10.178.78.1', '/after-negatives'), 'valid keys reconnect after both rejected peers')
        rpc.close()
        core_pid = rpc.process.pid
        rpc = None
        check(not Path('/proc', str(core_pid)).exists(), 'owned Core process is reaped')
        ip('link', 'del', 'wg78')
        check(not any(i['ifname'] == 'wg78' for i in json.loads(subprocess.check_output(['ip', '-j', 'link']))),
              'kernel fixture removes its WireGuard interface')
        return {'passed': True, 'checks': checks, 'requests': requests, 'kernel': os.uname().release,
                'networkNamespace': os.readlink('/proc/self/ns/net'), 'wireguardTools': wire('--version')}
    finally:
        if rpc:
            rpc.close()
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=3)


if __name__ == '__main__':
    root = Path(sys.argv[1]).resolve()
    result = run(root, Path(sys.argv[2]).resolve())
    Path(sys.argv[3]).write_text(json.dumps(result, indent=2) + '\n')
