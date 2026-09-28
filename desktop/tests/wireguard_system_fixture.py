"""A WireGuard endpoint that owns a system interface instead of a userspace
stack. The independent Linux kernel server and the Core live in two network
namespaces joined by one link, so the tunnel the Core builds is the only path
to the server's addresses. Invoked only inside an owned user namespace."""
import http.client
import http.server
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time

from vpn_auth_fixture import Rpc, field

SERVER = 'wg79'
LINK = ('wg79-server', 'wg79-client')
# Documentation addresses for the link, tunnel addresses for the WireGuard pair.
SERVER_LINK, CLIENT_LINK = '192.0.2.1', '192.0.2.2'
SERVER_TUNNEL, CLIENT_TUNNEL = '10.179.79.1', '10.179.79.2'
SERVER_TUNNEL6, CLIENT_TUNNEL6 = 'fd00:79::1', 'fd00:79::2'
PORT = 19080


def run(root, wg):
    assert os.readlink('/proc/self/ns/net') != os.environ['THRONIUM_TEST_ORIGINAL_NETNS']
    assert Path(sys.executable).resolve() == root / 'Thronium'
    checks, requests, servers, threads = [], [], [], []
    rpc, holder = None, None

    def check(value, name):
        assert value, name
        checks.append(name)
        print('PASS ' + name, flush=True)

    def ip(*args):
        subprocess.run(['ip', *args], check=True, stdout=subprocess.DEVNULL)

    def wire(*args, input=None):
        return subprocess.check_output([str(wg), *args], input=input, text=True).strip()

    def links(inside=None):
        command = ['ip', '-d', '-j', 'link'] if inside is None else \
            ['nsenter', '-t', str(inside), '-n', 'ip', '-d', '-j', 'link']
        return json.loads(subprocess.check_output(command))

    def names(inside=None, known=()):
        return sorted(link['ifname'] for link in links(inside) if link['ifname'] not in known)

    def client_side(*args, check_output=False):
        command = ['nsenter', '-t', str(holder.pid), '-n', *args]
        if check_output:
            return subprocess.check_output(command, text=True)
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL)
        return None

    def client_addresses(device):
        shown = json.loads(client_side('ip', '-j', 'address', 'show', 'dev', device, check_output=True))[0]
        return sorted(entry['local'] for entry in shown.get('addr_info', []))

    def stats():
        return {'handshake': int(wire('show', SERVER, 'latest-handshakes').split()[1]),
                'transfer': [int(v) for v in wire('show', SERVER, 'transfer').split()[1:]]}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append({'path': self.path, 'remote': self.client_address[0]})
            body = b'system-wg79:' + self.path.encode() + bytes(65536)
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    class V6(http.server.ThreadingHTTPServer):
        address_family = socket.AF_INET6

    try:
        # The Core's namespace is held open by a child; the link's client end is
        # moved into it, so nothing the Core creates can appear on this side.
        holder = subprocess.Popen(['unshare', '-n', 'sleep', '600'])
        time.sleep(.3)
        ip('link', 'set', 'lo', 'up')
        ip('link', 'add', LINK[0], 'type', 'veth', 'peer', 'name', LINK[1])
        ip('link', 'set', LINK[1], 'netns', str(holder.pid))
        ip('address', 'add', SERVER_LINK + '/24', 'dev', LINK[0])
        ip('link', 'set', LINK[0], 'up')
        client_side('ip', 'link', 'set', 'lo', 'up')
        client_side('ip', 'address', 'add', CLIENT_LINK + '/24', 'dev', LINK[1])
        client_side('ip', 'link', 'set', LINK[1], 'up')
        # sing-box looks up a default interface before it binds an endpoint.
        client_side('ip', 'route', 'add', 'default', 'via', SERVER_LINK, 'dev', LINK[1])

        ip('link', 'add', SERVER, 'type', 'wireguard')
        server_key, client_key, psk = wire('genkey'), wire('genkey'), wire('genpsk')
        server_public, client_public = wire('pubkey', input=server_key), wire('pubkey', input=client_key)
        for name, key in [('server.key', server_key), ('psk.key', psk)]:
            path = root / name
            path.write_text(key + '\n')
            path.chmod(0o600)
        wire('set', SERVER, 'private-key', str(root / 'server.key'), 'listen-port', '0',
             'peer', client_public, 'preshared-key', str(root / 'psk.key'),
             'allowed-ips', CLIENT_TUNNEL + '/32,' + CLIENT_TUNNEL6 + '/128')
        ip('address', 'add', SERVER_TUNNEL + '/24', 'dev', SERVER)
        ip('-6', 'address', 'add', SERVER_TUNNEL6 + '/64', 'dev', SERVER, 'nodad')
        ip('link', 'set', SERVER, 'mtu', '1420', 'up')
        link = json.loads(subprocess.check_output(['ip', '-d', '-j', 'link', 'show', SERVER]))[0]
        check(link['linkinfo']['info_kind'] == 'wireguard',
              'the independent server is a real Linux kernel WireGuard interface')
        check(names(holder.pid, ('lo', LINK[1])) == [],
              'the Core namespace holds only its link before the Core starts')
        for cls, address in [(http.server.ThreadingHTTPServer, SERVER_TUNNEL), (V6, SERVER_TUNNEL6)]:
            server = cls((address, PORT), Handler)
            server.daemon_threads = True
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            servers.append(server)
            threads.append(thread)
        with socket.socket() as probe:
            probe.bind((SERVER_LINK, 0))
            port = probe.getsockname()[1]
        endpoint = {'type': 'wireguard', 'tag': 'proxy', 'system': True, 'mtu': 1420,
                    'private_key': client_key,
                    'address': [CLIENT_TUNNEL + '/32', CLIENT_TUNNEL6 + '/128'],
                    'peers': [{'address': SERVER_LINK, 'port': int(wire('show', SERVER, 'listen-port')),
                               'public_key': server_public, 'pre_shared_key': psk,
                               'allowed_ips': [SERVER_TUNNEL + '/32', SERVER_TUNNEL6 + '/128']}]}
        rpc = Rpc(root, 'system', prefix=['nsenter', '-t', str(holder.pid), '-n'])

        def start(profile):
            config = {'log': {'level': 'error'}, 'endpoints': [profile],
                      'inbounds': [{'type': 'mixed', 'tag': 'mixed', 'listen': CLIENT_LINK, 'listen_port': port}],
                      'route': {'final': 'proxy'}}
            payload = field(1, json.dumps(config)) + field(2, 1) + field(9, 0)
            rpc.call('CheckConfig', payload)
            rpc.call('Start', payload)

        def created(timeout=15):
            """The interface the Core owns appears when its endpoint first dials."""
            until = time.monotonic() + timeout
            while time.monotonic() < until:
                owned = names(holder.pid, ('lo', LINK[1]))
                if owned and client_addresses(owned[0]):
                    return owned
                time.sleep(.1)
            return names(holder.pid, ('lo', LINK[1]))

        def request(host, path, timeout=15):
            client = http.client.HTTPConnection(CLIENT_LINK, port, timeout=timeout)
            try:
                client.request('GET', 'http://' + host + ':' + str(PORT) + path)
                response = client.getresponse()
                body = response.read()
                return response.status == 200 and body == b'system-wg79:' + path.encode() + bytes(65536)
            finally:
                client.close()

        owned_interfaces = []
        for cycle in ['initial', 'reconnect']:
            before = stats()
            start(endpoint)
            for host, remote in [(SERVER_TUNNEL, CLIENT_TUNNEL), ('[' + SERVER_TUNNEL6 + ']', CLIENT_TUNNEL6)]:
                path = '/' + cycle + '-' + remote
                check(request(host, path) and {'path': path, 'remote': remote} in requests,
                      cycle + ': 64 KiB HTTP crosses the system interface from ' + remote)
            owned = created()
            owned_interfaces.append(owned)
            check(len(owned) == 1, cycle + ': the Core owns exactly one interface of its own')
            device = owned[0]
            check({CLIENT_TUNNEL, CLIENT_TUNNEL6} <= set(client_addresses(device)),
                  cycle + ': the endpoint addresses live on that kernel interface, not in a userspace stack')
            table = client_side('ip', 'route', 'show', 'table', 'all', check_output=True).splitlines()
            check(any(device in line and SERVER_TUNNEL in line for line in table),
                  cycle + ': the kernel routes the peer through the interface the Core created')
            check(names(known=('lo', LINK[0], SERVER)) == [],
                  cycle + ': the server namespace gains no interface of the Core')
            after = stats()
            check(after['handshake'] > 0 and all(a > b for a, b in zip(after['transfer'], before['transfer'])),
                  cycle + ': the independent kernel server confirms the handshake and both traffic counters')
            rpc.call('Stop')
            until = time.monotonic() + 10
            while time.monotonic() < until and names(holder.pid, ('lo', LINK[1])):
                time.sleep(.1)
            check(not names(holder.pid, ('lo', LINK[1])),
                  cycle + ': stopping removes the interface the Core created')
            time.sleep(1.1)
        rpc.close()
        core_pid = rpc.process.pid
        rpc = None
        check(not Path('/proc', str(core_pid)).exists(), 'owned Core process is reaped')
        check(not names(holder.pid, ('lo', LINK[1])), 'a reaped Core leaves no interface behind')
        ip('link', 'del', SERVER)
        ip('link', 'del', LINK[0])
        check(names(known=('lo',)) == [], 'the fixture removes its own WireGuard interface and link')
        return {'passed': True, 'checks': checks, 'requests': requests,
                'coreInterfaces': owned_interfaces, 'kernel': os.uname().release,
                'networkNamespace': os.readlink('/proc/self/ns/net'), 'wireguardTools': wire('--version')}
    finally:
        if rpc:
            rpc.close()
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=3)
        if holder:
            holder.send_signal(signal.SIGKILL)
            holder.wait(timeout=5)


if __name__ == '__main__':
    root = Path(sys.argv[1]).resolve()
    result = run(root, Path(sys.argv[2]).resolve())
    Path(sys.argv[3]).write_text(json.dumps(result, indent=2) + '\n')
