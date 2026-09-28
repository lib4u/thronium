"""Real private-bus routing menu with loopback traffic and saved/applied states."""
import base64
import copy
import http.client
import http.server
import json
import os
import pathlib
import socket
import threading
import time
import uuid
import urllib.parse
import xml.etree.ElementTree as ET
from gi.repository import Gio, GLib
from diagnostics_fixture import Fixture
from native_processes import core_pids
from tray_ui import wait


def run(h):
    command, check = h['command'], h['check']
    if not os.environ.get('_THRONIUM_TEST_BUS'):
        raise AssertionError('Tray routing tests require --private-tray-bus')
    bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)

    def call(service, path, interface, method, signature, args):
        return bus.call_sync(service, path, interface, method, GLib.Variant(signature, args), None, Gio.DBusCallFlags.NONE, 2000, None).unpack()

    def isolated(pid):
        proc = pathlib.Path('/proc', str(pid))
        try:
            return proc.joinpath('comm').read_text().strip() == 'Thronium' and any(v == b'XDG_DATA_HOME=' + os.environ['XDG_DATA_HOME'].encode() and b'thronium-native-test-' in v for v in proc.joinpath('environ').read_bytes().split(b'\0'))
        except OSError:
            return False

    def find_menu():
        names = call('org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'ListNames', '()', ())[0]
        for service in names:
            if not service.startswith(':'):
                continue
            try:
                pid = call('org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'GetConnectionUnixProcessID', '(s)', (service,))[0]
                if not isolated(pid):
                    continue
                paths = ['/']
                for path in paths:
                    node = ET.fromstring(call(service, path, 'org.freedesktop.DBus.Introspectable', 'Introspect', '()', ())[0])
                    if any(i.attrib['name'] == 'com.canonical.dbusmenu' for i in node.findall('interface')):
                        return service, path, pid
                    paths.extend(path.rstrip('/') + '/' + n.attrib['name'] for n in node.findall('node'))
            except GLib.Error:
                continue
        return None

    service, path, pid = wait(find_menu, 'private native routing menu')

    def tree():
        return call(service, path, 'com.canonical.dbusmenu', 'GetLayout', '(iias)', (0, -1, []))[1]

    def walk(node):
        yield node
        for child in node[2]:
            yield from walk(child)

    def find(label):
        return next((node for node in walk(tree()) if node[1].get('label') == label), None)

    def ready(label, enabled=None):
        try:
            return wait(lambda: (node := find(label)) and (enabled is None or node[1].get('enabled', True) == enabled) and node, 'routing tray ' + label)
        except AssertionError:
            pathlib.Path(h['args'].artifacts, 'tray-routing-failure-menu.json').write_text(json.dumps(tree(), ensure_ascii=False, indent=2))
            raise

    def activate(node):
        try:
            call(service, path, 'com.canonical.dbusmenu', 'Event', '(isvu)', (node[0], 'clicked', GLib.Variant('s', ''), 0))
        except GLib.Error as error:
            if 'does not refer to a menu item' not in str(error):
                raise

    def checked(label):
        node = find(label)
        return node is not None and node[1].get('toggle-state') == 1

    def save(routing):
        return command('saveRouting', {**routing, 'revision': command('routing')['revision']})

    def settled(mode=None, active=None):
        def done():
            state = command('snapshot')['routing']
            return not state['pending'] and (mode is None or state['mode'] == mode) and (active is None or state['active'] == active)
        wait(done, 'applied routing')
        ready('Saved routing is applied')
        routing = command('routing')
        profile = next(p for p in routing['profiles'] if p['id'] == routing['active'])
        mode_label = {'rules': 'Rules', 'all': 'All traffic through proxy', 'direct': 'Direct connection'}[profile['mode']]
        ready('Saved: ' + profile['name'] + ' · ' + mode_label)
        wait(lambda: checked(profile['name']) and checked(mode_label), 'applied native checkmarks')

    def seen(clear=False):
        with fixture.lock:
            result = copy.deepcopy(fixture.state['seen'])
            if clear:
                fixture.state['seen'] = []
            return result

    def traffic():
        client = http.client.HTTPConnection('127.0.0.1', port, timeout=4)
        try:
            client.request('GET', fixture.info['download'])
            response = client.getresponse()
            return response.status == 200 and response.read() == b'x' * 245760
        except (OSError, http.client.HTTPException):
            return False
        finally:
            client.close()

    def tunnel():
        destination = urllib.parse.urlsplit(fixture.info['download'])
        connection = socket.create_connection(('127.0.0.1', port), timeout=4)
        connection.sendall(f'CONNECT {destination.netloc} HTTP/1.1\r\nHost: {destination.netloc}\r\n\r\n'.encode())
        headers = b''
        while b'\r\n\r\n' not in headers:
            data = connection.recv(4096)
            assert data, 'CONNECT closed before response headers'
            headers += data
        assert b' 200 ' in headers.split(b'\r\n', 1)[0]
        return connection

    def use_tunnel(connection):
        destination = urllib.parse.urlsplit(fixture.info['download'])
        connection.sendall(f'GET {destination.path} HTTP/1.0\r\nHost: {destination.netloc}\r\n\r\n'.encode())
        response = b''
        while True:
            data = connection.recv(65536)
            if not data:
                break
            response += data
        headers, body = response.split(b'\r\n\r\n', 1)
        return b' 200 ' in headers.split(b'\r\n', 1)[0] and body == b'x' * 245760

    def dismiss_error():
        import pyatspi
        def dialog():
            for app in pyatspi.Registry.getDesktop(0):
                if app.get_process_id() == pid:
                    return pyatspi.findDescendant(app, lambda n: n.getRole() in (pyatspi.ROLE_DIALOG, pyatspi.ROLE_ALERT) and pyatspi.findDescendant(n, lambda label: label.getRole() == pyatspi.ROLE_LABEL and 'Routing was saved, but could not be applied.' in label.name))
        try:
            node = wait(dialog, 'routing failure dialog')
        except AssertionError:
            def describe(node, depth=0):
                try:
                    value={'name':node.name,'role':node.getRoleName(),'pid':node.get_process_id()}
                    if depth<4:value['children']=[describe(child,depth+1) for child in node]
                    return value
                except Exception as error:return {'error':str(error)}
            pathlib.Path(h['args'].artifacts,'tray-routing-accessibility.json').write_text(json.dumps({'ownedPid':pid,'tree':describe(pyatspi.Registry.getDesktop(0))},ensure_ascii=False,indent=2))
            # GTK's accessible alert name can be Information, independently of
            # its Thronium window title. The tree is scoped to this owned PID.
            raise
        labels = [n.name for n in pyatspi.findAllDescendants(node, lambda n: n.getRole() == pyatspi.ROLE_LABEL)]
        pyatspi.findDescendant(node, lambda n: n.getRole() == pyatspi.ROLE_PUSH_BUTTON and n.name in ('OK', 'Ok')).queryAction().doAction(0)
        return labels

    initial = command('snapshot')
    initial_routing = command('routing')
    fixture = Fixture(pathlib.Path(h['args'].artifacts) / 'routing-loopback')
    added, groups = [], []
    provider_server = None
    existing_tunnel = None
    default = {'id': 'default', 'name': 'Tray route default', 'mode': 'rules', 'rules': [], 'route': {'final': 'proxy', 'auto_detect_interface': True, 'find_process': True, 'default_domain_resolver': 'dns-direct'}, 'dns': {'servers': [{'type': 'local', 'tag': 'dns-direct'}], 'final': 'dns-direct'}}
    blocked = {**copy.deepcopy(default), 'id': 'tray-blocked', 'name': 'Tray route block', 'rules': [{'id': 'loopback', 'name': 'Block fixture', 'enabled': True, 'config': {'ip_cidr': ['127.0.0.0/8'], 'action': 'reject'}}]}
    broken = {**copy.deepcopy(default), 'id': 'tray-broken', 'name': 'Tray route invalid', 'rules': [{'id': 'invalid', 'name': 'Invalid', 'enabled': True, 'config': {'action': 'private-tray-routing-secret'}}]}
    second = {**copy.deepcopy(default), 'id': 'tray-second', 'name': 'Tray route second', 'mode': 'direct'}
    routing = {'active': 'default', 'profiles': [default, blocked, broken, second]}
    try:
        command('disconnect')
        with socket.socket() as available:
            available.bind(('127.0.0.1', 0))
            port = available.getsockname()[1]
        command('preferences', {**initial['preferences'], 'language': 'en', 'inboundPort': port})
        command('connectionSettings', {'mode': 'local', 'port': port})
        main = command('saveProfile', {'name': 'Tray routing loopback', 'groupId': 'personal', 'kind': 'sing-box-outbound', 'config': {'type': 'socks', 'server': '127.0.0.1', 'server_port': fixture.ports[0], 'version': '5'}})['id']
        added.append(main)
        command('select', {'id': main})
        save(routing)
        ready('Routing'); ready('Connect to server'); ready('Saved for next connection'); ready('Saved profile', True); ready('Saved mode', True)
        check(checked('Tray route default') and checked('Rules') and find('Apply saved changes')[1].get('enabled') is False, 'native Routing menu shows the saved profile and mode without claiming they are applied')
        processes = core_pids(pid)
        activate(ready('Tray route second'))
        wait(lambda: command('routing')['active'] == 'tray-second', 'disconnected routing profile save')
        wait(lambda: checked('Tray route second') and checked('Direct connection'), 'selected routing profile checkmarks')
        ready('All traffic through proxy'); activate(ready('All traffic through proxy'))
        wait(lambda: command('snapshot')['routing']['mode'] == 'all', 'disconnected mode save')
        wait(lambda: checked('Tray route second') and checked('All traffic through proxy'), 'disconnected checkmarks')
        check(command('snapshot')['running'] is None and core_pids(pid) == processes, 'disconnected tray routing selections save without launching or checking a core')
        current = command('routing')
        check(current['profiles'][0] == default and current['profiles'][1] == blocked, 'changing the selected routing mode preserves rules and other profiles')
        revision = current['revision']
        activate(ready('All traffic through proxy'))
        wait(lambda: command('routing')['revision'] != revision or checked('All traffic through proxy'), 'restored checkmark after mode no-op')
        check(command('routing')['revision'] == revision and checked('All traffic through proxy'), 'reselecting the saved mode is a no-op and restores its native checkmark')
        stale = ready('Tray route default')
        current['profiles'][0]['name'] = 'Tray route renamed'
        save(current)
        revision = command('routing')['revision']
        activate(stale)
        time.sleep(1.3)
        check(command('routing')['revision'] == revision and command('routing')['active'] == 'tray-second', 'queued menu events cannot overwrite a newer routing revision before or after menu refresh')
        save(routing)
        ready('Tray route default'); ready('Rules')
        command('connect', {'id': main}); settled('rules', 'default')
        seen(True)
        check(traffic() and len(seen()) == 1 and seen()[0][0] == 0, 'an applied rules profile carries HTTP through the chosen loopback SOCKS server')
        revision = command('routing')['revision']
        direct = ready('Direct connection')
        activate(direct); activate(direct)
        settled('direct')
        seen(True)
        check(traffic() and not seen() and command('routing')['revision'] == revision + 1, 'duplicate Direct events apply once and actual traffic bypasses the SOCKS server')
        activate(ready('All traffic through proxy')); settled('all')
        seen(True)
        check(traffic() and len(seen()) == 1, 'All traffic mode reconnects the same server and restores proxy routing')
        activate(ready('Tray route block')); settled('rules', 'tray-blocked')
        seen(True)
        check(not traffic() and not seen(), 'choosing a routing profile from the native tray applies its reject rule to real traffic')
        activate(ready('Tray route default')); settled('all', 'default')
        seen(True)
        check(traffic() and len(seen()) == 1, 'switching back restores the previous saved mode of that routing profile')
        full_config = {'inbounds': [{'type': 'mixed', 'listen': '127.0.0.1', 'listen_port': port}], 'outbounds': [{'type': 'direct', 'tag': 'direct'}], 'route': {'final': 'direct'}}
        full = command('saveProfile', {'name': 'Tray full JSON', 'groupId': 'personal', 'kind': 'sing-box-config', 'config': full_config})['id']
        added.append(full)
        command('select', {'id': full})
        time.sleep(1.3)
        check(find('Saved mode')[1].get('enabled', True) and command('snapshot')['running'] == main, 'routing ownership follows the running connection even if a full configuration is selected in the library')
        current = command('routing')
        next(p for p in current['profiles'] if p['id'] == current['active'])['mode'] = 'direct'
        save(current)
        ready('Saved changes are not applied'); ready('Apply saved changes', True)
        seen(True)
        check(traffic() and len(seen()) == 1 and checked('Direct connection'), 'saved pending mode has a checkmark but the tray explicitly reports that live traffic still uses the older policy')
        activate(ready('Apply saved changes')); settled('direct')
        seen(True)
        check(traffic() and not seen(), 'Apply saved changes activates pending routing against the running server')
        before = command('snapshot'); processes = core_pids(pid)
        existing_tunnel = tunnel()
        activate(ready('Apply saved changes', False))
        time.sleep(1.3)
        check(command('snapshot')['since'] == before['since'] and core_pids(pid) == processes, 'disabled Apply events cannot restart an already applied connection')
        activate(ready('Tray route invalid'))
        labels = dismiss_error()
        ready('Saved changes are not applied'); ready('Apply saved changes', True)
        check(any('saved, but could not be applied' in label for label in labels) and all('private-tray-routing-secret' not in label for label in labels), 'invalid routing gives a native saved-but-not-applied error without exposing raw configuration')
        after = command('snapshot')
        seen(True)
        check(after['running'] == main and after['since'] == before['since'] and core_pids(pid) == processes and traffic() and not seen(), 'core validation failure preserves the existing connection and its working routing')
        check(use_tunnel(existing_tunnel), 'an already-open CONNECT tunnel survives both disabled Apply and invalid routing validation')
        existing_tunnel.close(); existing_tunnel = None
        check(checked('Tray route invalid') and 'private-tray-routing-secret' not in str(tree()), 'failed selection remains visibly saved and pending without leaking rule contents into DBusMenu')
        activate(ready('Tray route default')); settled('direct', 'default')
        check(traffic(), 'a valid tray selection recovers after invalid routing without manual disconnect')
        stale = ready('All traffic through proxy')
        command('disconnect'); command('select', {'id': full})
        ready('Full configuration controls routing'); ready('Saved mode', False); ready('Saved profile', False)
        revision = command('routing')['revision']; processes = core_pids(pid)
        activate(stale); activate(ready('All traffic through proxy', False))
        time.sleep(1.3)
        check(command('routing')['revision'] == revision and core_pids(pid) == processes and command('snapshot')['running'] is None, 'full JSON disables disconnected routing changes and rejects stale or forged disabled menu events')
        command('connect', {'id': full})
        ready('Full configuration controls routing'); ready('Saved mode', False)
        before = command('snapshot'); processes = core_pids(pid)
        activate(ready('Tray route block', False))
        time.sleep(1.3)
        check(command('snapshot')['since'] == before['since'] and core_pids(pid) == processes and traffic(), 'routing selections cannot mutate or reconnect an active full JSON configuration')
        command('disconnect')
        xray = command('saveProfile', {'name': 'Tray full Xray', 'groupId': 'personal', 'kind': 'xray-config', 'config': {'outbounds': [{'protocol': 'freedom', 'tag': 'direct'}]}})['id']
        added.append(xray); command('select', {'id': xray})
        ready('Full configuration controls routing'); ready('Saved mode', False)
        check(command('snapshot')['routing']['profileOwned'], 'full Xray configurations have the same explicit routing-ownership guard')
        # Provider policy is downloaded only from this loopback subscription. It
        # contains no geodata, remote DNS, or startup probes that access internet.
        policy = 'happ://routing/add/' + base64.b64encode(json.dumps({'GlobalProxy': True, 'DomesticDNSType': 'DoU', 'DomesticDNSIP': '127.0.0.1', 'RemoteDNSType': 'DoU', 'RemoteDNSIP': '127.0.0.1'}).encode()).decode()
        class Subscription(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                body = f'socks://127.0.0.1:{fixture.ports[0]}#Tray%20provider'.encode()
                self.send_response(200); self.send_header('Content-Length', str(len(body))); self.send_header('Routing', policy); self.end_headers(); self.wfile.write(body)
        provider_server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Subscription)
        threading.Thread(target=provider_server.serve_forever, daemon=True).start()
        save({'active': 'default', 'profiles': [default]})
        group = command('saveGroup', {'name': 'Tray provider policy', 'subscription': {'url': f'http://127.0.0.1:{provider_server.server_port}/subscription', 'headers': {}, 'viaProxy': False, 'intervalMinutes': 0, 'useProviderRouting': True, 'inheritDefaults': False}})['id']
        groups.append(group)
        response = command('fetchSubscription', {'id': group, 'requestId': str(uuid.uuid4())})
        command('previewSubscription', {'ticket': response['ticket'], 'profiles': [{'name': 'Tray provider', 'groupId': group, 'kind': 'sing-box-outbound', 'config': {'type': 'socks', 'server': '127.0.0.1', 'server_port': fixture.ports[0], 'version': '5'}}]})
        command('applySubscription', {'ticket': response['ticket'], 'useProviderRouting': True})
        provider = next(p['id'] for p in command('snapshot')['profiles'] if p['groupId'] == group)
        command('select', {'id': main}); ready('Saved mode', True)
        stale = ready('Direct connection')
        command('select', {'id': provider})
        ready('Subscription controls routing'); ready('Saved profile', False); ready('Saved mode', False)
        revision = command('routing')['revision']; processes = core_pids(pid)
        activate(stale); activate(ready('Direct connection', False))
        time.sleep(1.3)
        check(command('routing')['revision'] == revision and core_pids(pid) == processes and command('snapshot')['routing']['providerOwned'], 'subscription-owned routing is explained and disabled without silently replacing provider DNS or policy')
        command('preferences', {**command('snapshot')['preferences'], 'language': 'ru'})
        ready('Маршрутизация'); ready('Подключиться к серверу'); ready('Маршрутизацией управляет подписка'); ready('Сохранённый режим', False)
        check(find('Измените политику в разделе маршрутизации') is not None, 'Russian ownership status directs users to the routing settings')
        command('select', {'id': main})
        ready('Сохранено для следующего подключения'); ready('Сохранённый режим', True)
        activate(ready('Прямое подключение'))
        wait(lambda: command('snapshot')['routing']['mode'] == 'direct', 'Russian mode selection')
        wait(lambda: checked('Прямое подключение'), 'Russian saved mode marker')
        check(command('snapshot')['running'] is None and checked('Прямое подключение'), 'Russian native routing choices save correctly while disconnected')
        command('preferences', {**command('snapshot')['preferences'], 'language': 'en'})
        paged = {'active': 'default', 'profiles': [copy.deepcopy(default)] + [{**copy.deepcopy(default), 'id': f'route-{i}', 'name': f'Paged route {i:02}'} for i in range(50)]}
        save(paged)
        ready('Saved profile', True); ready('1–50'); ready('51–51')
        # The native subtree is replaced during refresh. Read one complete
        # snapshot rather than dereferencing a second lookup between updates.
        menu = wait(lambda: (node := find('Saved profile')) and len([item for item in walk(node) if item[1].get('toggle-type')]) == 51 and node, 'complete paginated routing profile menu')
        check(len([node for node in walk(menu) if node[1].get('toggle-type')]) == 51, 'large routing libraries paginate without losing any saved profile')
        stale = ready('Paged route 49')
        paged['profiles'].pop(); save(paged)
        wait(lambda: find('Paged route 49') is None, 'deleted routing profile removed')
        revision = command('routing')['revision']; activate(stale); time.sleep(.3)
        check(command('routing')['revision'] == revision and command('routing')['active'] == 'default', 'events from a deleted routing-profile menu cannot select a different row')
        pathlib.Path(h['args'].artifacts, 'tray-routing-menu.json').write_text(json.dumps(tree(), ensure_ascii=False, indent=2))
    except BaseException:
        pathlib.Path(h['args'].artifacts, 'tray-routing-failure-state.json').write_text(json.dumps({'snapshot': command('snapshot'), 'routing': command('routing'), 'menu': tree()}, ensure_ascii=False, indent=2))
        raise
    finally:
        if existing_tunnel:
            existing_tunnel.close()
        command('disconnect')
        save(initial_routing)
        if initial['selected']:
            command('select', {'id': initial['selected']})
        for profile in added:
            command('delete', {'id': profile})
        for group in groups:
            command('deleteGroup', {'id': group, 'deleteProfiles': True})
        command('preferences', initial['preferences'])
        if provider_server:
            provider_server.shutdown(); provider_server.server_close()
        fixture.close()
