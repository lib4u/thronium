"""Read and activate the real DBusMenu, scoped to the disposable app PID."""
import http.client
import http.server
import pathlib
import os
import socket
import threading
import time
import xml.etree.ElementTree as ET
from gi.repository import Gio, GLib


def wait(predicate, title, timeout=12):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value: return value
        time.sleep(.1)
    raise AssertionError('Timed out: ' + title)


def run(h, quitting=False):
    command, check = h['command'], h['check']
    bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
    def call(service, path, interface, method, signature, args):
        return bus.call_sync(service, path, interface, method, GLib.Variant(signature, args), None, Gio.DBusCallFlags.NONE, 2000, None).unpack()
    def isolated(pid):
        proc = pathlib.Path('/proc', str(pid))
        try:
            return proc.joinpath('comm').read_text().strip() == 'Thronium' and any(v == b'XDG_DATA_HOME=' + os.environ['XDG_DATA_HOME'].encode() and b'thronium-native-test-' in v for v in proc.joinpath('environ').read_bytes().split(b'\0'))
        except OSError: return False
    def find_menu():
        names = call('org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'ListNames', '()', ())[0]
        for name in names:
            if not name.startswith(':'): continue
            try:
                pid = call('org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'GetConnectionUnixProcessID', '(s)', (name,))[0]
                if not isolated(pid): continue
                paths = ['/']
                for path in paths:
                    xml = call(name, path, 'org.freedesktop.DBus.Introspectable', 'Introspect', '()', ())[0]
                    node = ET.fromstring(xml)
                    if any(i.attrib['name'] == 'com.canonical.dbusmenu' for i in node.findall('interface')): return name, path, pid
                    paths.extend(path.rstrip('/') + '/' + n.attrib['name'] for n in node.findall('node'))
            except GLib.Error: continue
        return None
    service, path, pid = wait(find_menu, 'native tray menu registration')
    def layout():
        root = call(service, path, 'com.canonical.dbusmenu', 'GetLayout', '(iias)', (0, -1, []))[1]
        return [(row[0], row[1]) for row in root[2] if row[1].get('type') != 'separator']
    def item(prefix):
        rows = layout()
        return next((row for row in rows if row[1].get('label') == prefix), None) or next((row for row in rows if row[1].get('label', '').startswith(prefix)), None)
    def menu_ready(prefix, enabled=True): return wait(lambda: (row := item(prefix)) and row[1].get('enabled', True) == enabled and row, prefix)
    def event(prefix):
        row = item(prefix)
        if row is None: raise AssertionError('Tray item is missing: ' + prefix)
        call(service, path, 'com.canonical.dbusmenu', 'Event', '(isvu)', (row[0], 'clicked', GLib.Variant('s', ''), 0))
    initial = command('snapshot'); added = []
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = b'thronium-tray-loopback'; self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
        def log_message(self, *args): pass
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        command('disconnect'); command('preferences', {**initial['preferences'], 'language': 'en', 'inboundPort': port})
        menu_ready('Open Thronium'); menu_ready('Disconnect', False)
        check(item('Connect')[1].get('enabled', True) == bool(initial['selected']), 'tray availability matches the current selection and disconnected engine')
        check(all(label in [r[1].get('label') for r in layout()] for label in ['Open Thronium', 'Disconnect', 'Quit']), 'real native tray exposes open, connection and quit actions in English')
        good = command('saveProfile', {'name': 'Tray direct 🦊', 'groupId': 'personal', 'kind': 'sing-box-outbound', 'config': {'type': 'direct'}})['id']; added.append(good)
        bad = command('saveProfile', {'name': 'Tray invalid', 'groupId': 'personal', 'kind': 'sing-box-outbound', 'config': {'type': 'vless', 'server': '127.0.0.1', 'server_port': 9, 'uuid': 'private-tray-invalid-secret', 'transport': {'type': 'not-a-real-transport'}}})['id']; added.append(bad)
        command('select', {'id': good}); menu_ready('Connect: Tray direct')
        event('Connect:'); wait(lambda: command('snapshot')['running'] == good, 'tray connection start')
        menu_ready('Connected: Tray direct', False); menu_ready('Connect', False); menu_ready('Disconnect')
        check(True, 'activating the native Connect item starts the selected profile and updates menu state')
        client = http.client.HTTPConnection('127.0.0.1', port, timeout=4)
        client.request('GET', f'http://127.0.0.1:{server.server_port}/tray')
        response = client.getresponse(); body = response.read(); client.close()
        check(response.status == 200 and body == b'thronium-tray-loopback', 'a connection started by the tray carries actual HTTP through the bundled core')
        since = command('snapshot')['since']; event('Connect'); time.sleep(.25)
        check(command('snapshot')['since'] == since, 'repeated Connect events cannot restart an already running connection')
        command('select', {'id': bad}); time.sleep(1.2)
        check(command('snapshot')['running'] == good and item('Connected: Tray direct') is not None, 'changing selection preserves the running VPN and the tray names the active profile')
        command('preferences', {**command('snapshot')['preferences'], 'language': 'ru'})
        menu_ready('Открыть Thronium'); menu_ready('Отключить'); menu_ready('Выйти')
        check(item('Подключено: Tray direct') is not None, 'tray labels and connection status update to Russian without a restart')
        event('Отключить'); wait(lambda: command('snapshot')['running'] is None, 'tray disconnect'); menu_ready('Отключить', False)
        with socket.socket() as s: closed = s.connect_ex(('127.0.0.1', port)) != 0
        check(closed, 'native Disconnect stops the VPN and closes its local proxy port')
        command('preferences', {**command('snapshot')['preferences'], 'language': 'en'})
        menu_ready('Connect: Tray invalid'); event('Connect:')
        import pyatspi
        def error_dialog():
            for app in pyatspi.Registry.getDesktop(0):
                if app.get_process_id() == pid:
                    return pyatspi.findDescendant(app, lambda n: n.getRole() in (pyatspi.ROLE_DIALOG, pyatspi.ROLE_ALERT) and n.name == 'Thronium')
        dialog = wait(error_dialog, 'native tray error dialog')
        labels = pyatspi.findAllDescendants(dialog, lambda n: n.getRole() == pyatspi.ROLE_LABEL)
        check(any('Could not change' in n.name for n in labels) and all('private-tray-invalid-secret' not in n.name for n in labels), 'failed tray connection shows a useful native error without exposing configuration secrets')
        pyatspi.findDescendant(dialog, lambda n: n.getRole() == pyatspi.ROLE_PUSH_BUTTON and n.name in ('OK', 'Ok')).queryAction().doAction(0)
        menu_ready('Connect: Tray invalid'); check(command('snapshot')['running'] is None and 'private-tray-invalid-secret' not in str(layout()), 'failed tray start leaves the engine disconnected and the menu ready to retry')
        from native_screenshot import connect
        from Xlib import X, Xutil, protocol, error
        connection = connect()
        try:
            clients = connection.screen().root.get_full_property(connection.intern_atom('_NET_CLIENT_LIST'), X.AnyPropertyType)
            windows = []
            for wid in clients.value:
                try:
                    window = connection.create_resource_object('window', int(wid))
                    owner = window.get_full_property(connection.intern_atom('_NET_WM_PID'), X.AnyPropertyType)
                    if owner is not None and int(owner.value[0]) == pid and window.get_wm_transient_for() is None: windows.append(window)
                except error.BadWindow:
                    # The just-dismissed error dialog may still be in the WM list.
                    continue
            if len(windows) != 1: raise AssertionError('Expected one disposable main window')
            window = windows[0]
            connection.screen().root.send_event(protocol.event.ClientMessage(window=window, client_type=connection.intern_atom('WM_CHANGE_STATE'), data=(32, [Xutil.IconicState, 0, 0, 0, 0])), event_mask=X.SubstructureRedirectMask | X.SubstructureNotifyMask)
            connection.sync()
            def minimized():
                state = window.get_full_property(connection.intern_atom('_NET_WM_STATE'), X.AnyPropertyType)
                return state is not None and connection.intern_atom('_NET_WM_STATE_HIDDEN') in state.value
            wait(minimized, 'minimized test window')
            try:
                event('Open Thronium'); wait(lambda: not minimized(), 'restored test window')
            finally:
                if minimized():
                    connection.screen().root.send_event(protocol.event.ClientMessage(window=window, client_type=connection.intern_atom('_NET_ACTIVE_WINDOW'), data=(32, [2, X.CurrentTime, 0, 0, 0])), event_mask=X.SubstructureRedirectMask | X.SubstructureNotifyMask)
                    connection.sync()
            check(True, 'Open Thronium from the native tray restores the minimized main window')
        finally: connection.close()
        command('select', {'id': good}); menu_ready('Connect: Tray direct'); event('Connect:'); wait(lambda: command('snapshot')['running'] == good, 'reconnect after error')
        check(True, 'a corrected selection reconnects successfully through the tray after an error')
        from tray_extended_ui import run as extended
        extended(h, call, service, path, event, good, bad, port, server)
        menu_ready('Open Thronium'); menu_ready('Disconnect')
        if quitting:
            command('saveWindowSettings', {'closeBehavior': 'background'})
            from native_processes import core_pids as owned_core_pids
            core_pids = owned_core_pids(pid)
            if len(core_pids) != 1: raise AssertionError('The tray connection must own exactly one core')
            quit_item = menu_ready('Quit')
            for _ in range(2):
                try:
                    call(service, path, 'com.canonical.dbusmenu', 'Event', '(isvu)', (quit_item[0], 'clicked', GLib.Variant('s', ''), 0))
                except GLib.Error as error:
                    # Shutdown may finish before the Event reply or second
                    # click. PID/core/listener checks below still require exit.
                    if not any(code in str(error) for code in ('NoReply', 'NameHasNoOwner', 'ServiceUnknown')):
                        raise
            wait(lambda: not pathlib.Path('/proc', str(pid)).exists(), 'tray exit', timeout=15)
            h['closed_session'] = True
            with socket.socket() as s: closed = s.connect_ex(('127.0.0.1', port)) != 0
            check(closed and all(not pathlib.Path('/proc', p).exists() for p in core_pids), 'repeated Quit bypasses background mode and leaves no owned core or listening proxy')
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)
        if not h['closed_session']:
            command('disconnect')
            if initial['selected']: command('select', {'id': initial['selected']})
            for profile in added: command('delete', {'id': profile})
            command('preferences', initial['preferences'])
