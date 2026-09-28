"""Actual native TUN, recovery status, HTTP and cancellation in a private network."""
import http.client
import base64
import os
from pathlib import Path
import signal
import socket
import socketserver
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from gi.repository import Gio, GLib


def run(h):
    command, click, wait_for, js, check = (h[k] for k in ('command', 'click', 'wait_for', 'js', 'check'))
    namespace = os.readlink('/proc/self/ns/net')
    assert os.environ.get('THRONIUM_TEST_ORIGINAL_NETNS') not in (None, namespace)
    assert os.environ.get('THRONIUM_TEST_ORIGINAL_MNTNS') not in (None, os.readlink('/proc/self/ns/mnt'))
    assert os.geteuid() == 0
    def ip(*args): return subprocess.check_output(['ip', *args], text=True)
    ip('link', 'add', 'uplink', 'type', 'dummy')
    ip('addr', 'add', '192.0.2.2/24', 'dev', 'uplink')
    ip('link', 'set', 'uplink', 'up')
    ip('route', 'add', 'default', 'via', '192.0.2.1', 'dev', 'uplink')
    baseline = (ip('-4', '-j', 'rule'), ip('-6', '-j', 'rule'))

    class Socks(socketserver.BaseRequestHandler):
        def handle(self):
            def read(n):
                data = b''
                while len(data) < n:
                    part = self.request.recv(n - len(data))
                    if not part: raise EOFError()
                    data += part
                return data
            try:
                self.request.settimeout(10)
                version, n = read(2); assert version == 5
                read(n); self.request.sendall(b'\x05\x00')
                version, method, _, kind = read(4); assert version == 5 and method == 1
                read(4 if kind == 1 else 16 if kind == 4 else read(1)[0]); read(2)
                self.request.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50')
                request = b''
                while b'\r\n\r\n' not in request: request += read(1)
                self.request.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\nreconnect-native')
            except (OSError, EOFError): pass

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True
    server = Server(('127.0.0.1', 0), Socks)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    with socket.socket() as free:
        free.bind(('127.0.0.1', 0)); port = free.getsockname()[1]
    initial = command('snapshot')
    pid = None
    occupied = None
    dns = None
    def forward_http():
        client = http.client.HTTPConnection('198.18.0.80', 80, timeout=5)
        try:
            client.request('GET', '/')
            response = client.getresponse()
            assert response.status == 200 and response.read() == b'reconnect-native'
        finally: client.close()
    def children(parent):
        result = set()
        for task in Path('/proc', str(parent), 'task').glob('*/children'):
            try: result.update(int(pid) for pid in task.read_text().split())
            except OSError: pass
        return sorted(result)
    def current_worker(helper):
        expected = os.readlink(f'/proc/{helper}/exe')
        workers = []
        for candidate in children(helper):
            try:
                if os.readlink(f'/proc/{candidate}/exe') == expected:
                    workers.append(candidate)
            except OSError:
                pass
        worker, = workers
        assert os.readlink(f'/proc/{worker}/ns/net') == namespace
        return worker
    def kill_worker(helper):
        worker = current_worker(helper)
        os.kill(worker, signal.SIGKILL)
    def reserve_port():
        # Wait for the killed process to release the listener before forcing a
        # failed retry. The helper's backoff keeps the native state observable.
        for _ in range(50):
            listener = socket.socket()
            try:
                listener.bind(('127.0.0.1', port)); listener.listen(); return listener
            except OSError: listener.close(); time.sleep(.01)
        raise AssertionError('Dead worker retained its listener')
    def tray_layout_reader(app_pid):
        bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        def call(service, path, interface, method, signature, args):
            return bus.call_sync(service, path, interface, method, GLib.Variant(signature, args), None, Gio.DBusCallFlags.NONE, 2000, None).unpack()
        names = call('org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'ListNames', '()', ())[0]
        for name in names:
            if not name.startswith(':'): continue
            try:
                pid = call('org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'GetConnectionUnixProcessID', '(s)', (name,))[0]
            except GLib.Error: continue
            if pid != app_pid: continue
            paths = ['/']
            for path in paths:
                try:
                    node = ET.fromstring(call(name, path, 'org.freedesktop.DBus.Introspectable', 'Introspect', '()', ())[0])
                except GLib.Error: continue
                if any(i.attrib['name'] == 'com.canonical.dbusmenu' for i in node.findall('interface')):
                    return lambda: [row[1] for row in call(name, path, 'com.canonical.dbusmenu', 'GetLayout', '(iias)', (0, -1, []))[1][2]]
                paths.extend(path.rstrip('/') + '/' + n.attrib['name'] for n in node.findall('node'))
        raise AssertionError('The disposable native application has no DBusMenu')
    def wait_tray(status, disconnect):
        for _ in range(30):
            rows = tray_layout()
            if any(row.get('label') == status and not row.get('enabled', True) for row in rows) and any(row.get('label') == disconnect and row.get('enabled', True) for row in rows):
                return
            time.sleep(.1)
        raise AssertionError('Tray recovery status or Disconnect is missing')
    try:
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark',
            'connectionMode': 'tun', 'inboundPort': port, 'tun': {**initial['preferences']['tun'], 'autoReconnect': True, 'systemDns': os.environ.get('_THRONIUM_TUN_DNS_BACKEND', 'resolved') if os.environ.get('_THRONIUM_TUN_SYSTEM_DNS') == '1' else initial['preferences']['tun']['systemDns']}})
        draft = {'name': 'TUN recovery fixture', 'groupId': 'personal', 'kind': 'sing-box-outbound',
            'config': {'type': 'socks', 'server': '127.0.0.1', 'server_port': server.server_address[1], 'version': '5'}}
        if os.environ.get('_THRONIUM_TUN_XRAY_LOCAL_DNS') == '1':
            draft = {'name': 'Full Xray localhost DNS fixture', 'groupId': 'personal', 'kind': 'xray-config',
                'config': {'dns': {'servers': ['localhost'], 'queryStrategy': 'UseIPv4'},
                    'outbounds': [{'protocol': 'socks', 'tag': 'proxy', 'settings': {'servers': [{'address': '127.0.0.1', 'port': server.server_address[1]}]}}]}}
        pid = command('saveProfile', draft)['id']
        if os.environ.get('_THRONIUM_TUN_SYSTEM_DNS') == '1':
            from tun_system_dns_fixture import Fixture
            dns = Fixture(h, os.environ.get('_THRONIUM_TUN_DNS_BACKEND', 'resolved'))
        command('select', {'id': pid})
        wait_for('return document.documentElement.lang==="en" && !document.querySelector(".power-button").disabled')
        click('.power-button')
        wait_for('return document.querySelector(".live-indicator").textContent.includes("Active")')
        forward_http()
        if dns: dns.query('Native connection')
        from window_ui import primary
        from native_processes import core_pids
        connection, _, app_pid = primary(); connection.close()
        helper, = map(int, core_pids(app_pid))
        tray_layout = tray_layout_reader(app_pid)
        check(True, 'the native TUN window forwards real HTTP inside the isolated network')

        if dns and os.environ.get('_THRONIUM_TUN_NETWORK_DNS_PROBE') == '1':
            from tun_network_dns_fixture import run as network_dns
            network_dns(h, dns, lambda: current_worker(helper), forward_http)

        kill_worker(helper); occupied = reserve_port()
        wait_for('return document.querySelector(".session-overline").textContent.includes("Restoring connection") && document.body.classList.contains("reconnecting")')
        state = command('snapshot')
        check(state['phase'] == 'reconnecting' and state['running'] == pid and not state['trafficAvailable'], 'recovery keeps the intended profile and removes stale traffic status')
        check(js('return !document.querySelector(".power-button").disabled && document.querySelector(".power-button").textContent.includes("Disconnect")'), 'the reconnecting window keeps Disconnect available')
        wait_tray('Reconnecting…', 'Disconnect')
        check(True, 'the actual English DBusMenu reports recovery and allows Disconnect')
        snapshot = h['request']('GET', h['base'] + '/screenshot')
        (h['artifacts'] / 'tun-reconnecting-en.png').write_bytes(base64.b64decode(snapshot))
        occupied.close(); occupied = None
        wait_for('return !document.body.classList.contains("reconnecting") && document.querySelector(".session-overline").textContent.includes("Active")')
        forward_http()
        if dns: dns.query('Native connection')
        check(list(map(int, core_pids(app_pid))) == [helper], 'automatic reconnect restores HTTP without replacing the authorized supervisor')

        preferences = command('snapshot')['preferences']
        command('preferences', {**preferences, 'language': 'ru', 'theme': 'light'})
        kill_worker(helper); occupied = reserve_port()
        wait_for('return document.querySelector(".session-overline").textContent.includes("Восстанавливаем соединение")')
        check(js('return document.querySelector(".power-button").textContent.includes("Отключить")'), 'Russian recovery status and cancellation are shown in the live window')
        wait_tray('Восстанавливаем соединение…', 'Отключить')
        check(True, 'the actual Russian DBusMenu reports recovery and allows Disconnect')
        click('.power-button')
        wait_for('return document.querySelector(".session-overline").textContent.includes("Не подключено")')
        occupied.close(); occupied = None
        time.sleep(2.2)
        state = command('snapshot')
        check(state['running'] is None and not Path('/sys/class/net/thronium-tun').exists() and children(helper) == [], 'Disconnect cancels pending retries and no worker or TUN reappears')
        check((ip('-4', '-j', 'rule'), ip('-6', '-j', 'rule')) == baseline, 'native recovery and cancellation restore the original policy rules')
        if dns: dns.clean()
    finally:
        if occupied: occupied.close()
        command('disconnect')
        if dns: dns.close()
        command('preferences', initial['preferences'])
        if pid: command('delete', {'id': pid})
        server.shutdown(); server.server_close()
