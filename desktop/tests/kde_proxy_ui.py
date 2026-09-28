"""Real KConfig/libproxy on private XDG paths; only owned App/Core processes are signalled."""
import http.client
import http.server
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import threading
import time
from urllib.parse import urlsplit

from external_core_fixture import identity
from native_processes import core_pids
from system_proxy_guardian_fixture import Guardians
from window_ui import primary


def until(predicate, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(.1)
    raise AssertionError('private KDE proxy did not settle')


def run(h):
    command, check = h['command'], h['check']
    config = Path(os.environ['XDG_CONFIG_HOME'])
    defaults = Path(os.environ['XDG_CONFIG_DIRS'])
    assert 'thronium-native-test-' in str(config) and defaults.parent == config.parent
    assert os.environ['XDG_CURRENT_DESKTOP'] == 'KDE'
    config.mkdir(exist_ok=True)
    file = config / 'kioslaverc'
    journal = config / 'thronium-system-proxy-kde/recovery.json'
    guards = Guardians(h['args'].application, config, h['artifacts'] / 'kde-guardians.json', 'thronium-system-proxy-kde')
    initial = command('snapshot')
    audit = {'traffic': [], 'cleanupErrors': []}
    original = '# Keep this comment\n[Proxy Settings]\nhttpProxy=http://previous.invalid 3128\nhttpsProxy[$d]\nftpProxy=\nsocksProxy[$e]=socks://$SYNTHETIC_KDE_PROXY 1080\nReversedException=true\nProxyType=2\nNoProxyFor=intranet.invalid\nProxy Config Script=http://previous.invalid/proxy.pac\n[Other]\nvalue=unchanged\n'
    file.write_text(original)
    file.chmod(0o600)
    requests = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            body = b'kde-system-proxy'
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    server = http.server.ThreadingHTTPServer(('127.0.0.2', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    profile = command('saveProfile', {'name': 'Owned KDE proxy', 'groupId': 'personal', 'kind': 'sing-box-outbound', 'config': {'type': 'direct'}})['id']

    def owner():
        connection, _, pid = primary()
        connection.close()
        return identity(pid)

    def start():
        command('connect', {'id': profile})
        node = owner()
        guard = guards.one(node['pid'])
        check(command('snapshot')['systemProxy']['active'] and json.loads(journal.read_text())['backend'] == 'kde',
              'KDE connection owns its typed recovery journal and authenticated guardian')
        return node, guard

    def traffic(label):
        url = f'http://127.0.0.2:{server.server_port}/{label}'
        # A fresh libproxy factory chooses the system adapter itself. Environment
        # proxy overrides are removed only in this test child.
        code = '''import ctypes,ctypes.util,json,sys
p=ctypes.CDLL(ctypes.util.find_library('proxy'))
p.px_proxy_factory_new.restype=ctypes.c_void_p
p.px_proxy_factory_get_proxies.argtypes=[ctypes.c_void_p,ctypes.c_char_p]
p.px_proxy_factory_get_proxies.restype=ctypes.POINTER(ctypes.c_char_p)
p.px_proxy_factory_free.argtypes=[ctypes.c_void_p]
p.px_proxy_factory_free_proxies.argtypes=[ctypes.POINTER(ctypes.c_char_p)]
f=p.px_proxy_factory_new();v=p.px_proxy_factory_get_proxies(f,sys.argv[1].encode());r=[];i=0
while v[i]:r.append(v[i].decode());i+=1
p.px_proxy_factory_free_proxies(v);p.px_proxy_factory_free(f);print(json.dumps(r))
'''
        env = {key: value for key, value in os.environ.items() if key.lower() not in ['http_proxy', 'https_proxy', 'all_proxy', 'no_proxy', 'ftp_proxy']}
        proxies = json.loads(subprocess.check_output(['python3', '-c', code, url], env=env, text=True, timeout=10))
        expected = f'http://127.0.0.1:{port}'
        assert proxies and proxies[0].rstrip('/') == expected, proxies
        proxy = urlsplit(proxies[0])
        client = http.client.HTTPConnection(proxy.hostname, proxy.port, timeout=5)
        try:
            client.request('GET', url)
            response = client.getresponse()
            assert response.status == 200 and response.read() == b'kde-system-proxy'
        finally:
            client.close()
        check('/' + label in requests, label + ': libproxy discovers KDE settings and actual HTTP crosses the running Core')
        audit['traffic'].append({'label': label, 'proxies': proxies})

    try:
        check(initial['systemProxy']['available'] and not initial['systemProxy']['active'], 'KDE capability is available before a lease is acquired')
        command('preferences', {**initial['preferences'], 'language': 'en', 'connectionMode': 'system-proxy', 'inboundPort': port})
        check(file.read_text() == original and not journal.exists(), 'saving connection settings leaves KDE configuration untouched')
        node, guard = start()
        traffic('initial')
        command('disconnect')
        check(file.read_text() == original and not journal.exists() and guards.gone(guard),
              'Disconnect restores raw expansion/deletion markers, comments, PAC, bypass and unrelated settings')

        # Inherited entries must return to inheritance, not a local deletion mask.
        inherited = original.replace('httpProxy=http://previous.invalid 3128\n', '')
        (defaults / 'kioslaverc').write_text('[Proxy Settings]\nhttpProxy=http://inherited.invalid 8080\n')
        file.write_text(inherited)
        start()
        traffic('inherited')
        command('disconnect')
        effective = subprocess.check_output(['kreadconfig6', '--file', 'kioslaverc', '--group', 'Proxy Settings', '--key', 'httpProxy'], text=True).strip()
        check(file.read_text() == inherited and effective == 'http://inherited.invalid 8080',
              'Disconnect restores an absent local key and the real KConfig system default')

        file.write_text(original.replace('ProxyType=2', 'ProxyType[$i]=2'))
        locked = file.read_text()
        try:
            command('connect', {'id': profile})
            raise AssertionError('immutable KDE setting was accepted')
        except RuntimeError as error:
            check('system_proxy_not_writable' in str(error) and file.read_text() == locked and not journal.exists(),
                  'KConfig immutable proxy settings are refused before any system write')
        file.write_text(original)
        start()
        external = file.read_text().replace(f'httpProxy=http://127.0.0.1 {port}', 'httpProxy=http://external.invalid 9090')
        file.write_text(external)
        until(lambda: command('snapshot')['systemProxy']['error'] == 'system_proxy_changed')
        command('disconnect')
        check(file.read_text() == external and not journal.exists(), 'external KDE proxy changes relinquish the entire lease and survive Disconnect')
        command('restoreSystemProxy')
        file.write_text(original)

        node, guard = start()
        cores = core_pids(node['pid'])
        assert len(cores) == 1
        old = int(cores[0])
        lease = journal.read_bytes()
        core = identity(old)
        assert core['ppid'] == node['pid'] and Path('/proc', str(old), 'exe').resolve() == guards.app.with_name('ThroniumCore')
        fd = os.pidfd_open(old)
        try:
            assert identity(old)['starttime'] == core['starttime']
            signal.pidfd_send_signal(fd, signal.SIGKILL, None, 0)
        finally:
            os.close(fd)
        until(lambda: command('snapshot')['phase'] == 'connected' and core_pids(node['pid']) and str(old) not in core_pids(node['pid']))
        check(journal.read_bytes() == lease and guards.one(node['pid'])['pid'] == guard['pid'], 'Core recovery retains the same KDE lease and guardian')
        traffic('after-core-recovery')
        command('disconnect')
        check(file.read_text() == original, 'Disconnect after Core recovery restores original KDE settings')

        node, guard = start()
        h['closed_session'] = True
        guards.send(node, signal.SIGKILL)
        until(lambda: not journal.exists() and guards.gone(guard) and file.read_text() == original)
        check(True, 'SIGKILL of the real GUI restores original KDE settings and removes the guardian before any restart')
    finally:
        if not h['closed_session']:
            for step, action in [('disconnect', lambda: command('disconnect')), ('preferences', lambda: command('preferences', initial['preferences'])), ('profile', lambda: command('deleteProfiles', {'ids': [profile]}))]:
                try:
                    action()
                except Exception as error:
                    audit['cleanupErrors'].append({'step': step, 'error': str(error)})
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        guards.finish()
        (h['artifacts'] / 'kde-proxy-audit.json').write_text(json.dumps(audit, indent=2) + '\n')
        assert not audit['cleanupErrors'], audit['cleanupErrors']
