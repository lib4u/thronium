"""Actual Qt DoQ import, native scopes/undo and DNS packets through the app."""
import contextlib
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import socketserver
import struct
import threading
import time

from inline_ruleset_fixtures import exact, question_end
from native_dialogs import file_dialog


def dns_exchange(inbound, target, name, kind, transaction):
    assert name.endswith('.fixture.invalid') and kind in (1, 28)
    question = struct.pack('!HHHHHH', transaction, 0x100, 1, 0, 0, 0)
    question += b''.join(bytes([len(label)]) + label.encode() for label in name.split('.'))
    question += b'\0' + struct.pack('!HH', kind, 1)
    with contextlib.ExitStack() as stack:
        control = stack.enter_context(socket.create_connection(('127.0.0.1', inbound), timeout=5))
        control.sendall(b'\x05\x01\0')
        assert exact(control, 2) == b'\x05\0'
        control.sendall(b'\x05\x03\0\x01' + b'\0' * 6)
        header = exact(control, 4)
        assert header[:3] == b'\x05\0\0' and header[3] in (1, 4)
        address = ipaddress.ip_address(exact(control, 4 if header[3] == 1 else 16))
        assert address.is_loopback or address.is_unspecified
        port = int.from_bytes(exact(control, 2), 'big')
        assert port > 0
        channel = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        channel.bind(('127.0.0.1', 0))
        channel.settimeout(6)
        channel.sendto(b'\0\0\0\x01\x7f\0\0\x01' + target.to_bytes(2, 'big') + question,
                       ('127.0.0.1', port))
        packet, peer = channel.recvfrom(65536)
        assert peer == ('127.0.0.1', port) and packet[:3] == b'\0\0\0'
        atyp = packet[3]
        offset = 10 if atyp == 1 else 22 if atyp == 4 else 7 + packet[4]
        response = packet[offset:]
        fields = struct.unpack('!HHHHHH', response[:12])
        assert fields[0] == transaction and fields[1] & 0xF == 0 and fields[3] == 1
        cursor = question_end(response)
        while response[cursor] and response[cursor] & 0xC0 != 0xC0:
            assert response[cursor] < 64
            cursor += response[cursor] + 1
        cursor += 2 if response[cursor] & 0xC0 == 0xC0 else 1
        rtype, rclass, _, size = struct.unpack('!HHIH', response[cursor:cursor + 10])
        assert rtype == kind and rclass == 1 and size == (4 if kind == 1 else 16)
        return str(ipaddress.ip_address(response[cursor + 10:cursor + 10 + size]))


def run(h):
    command, click, select, wait_for, js, check, screenshot = (
        h[key] for key in ('command', 'click', 'select', 'wait_for', 'js', 'check', 'screenshot'))
    artifacts = Path(h['args'].artifacts)
    info = json.loads(Path(os.environ['THRONIUM_LEGACY_QUIC_NATIVE_INFO']).read_text())
    archives = Path(os.environ['THRONIUM_LEGACY_QUIC_NATIVE_ARCHIVES'])
    manifest = json.loads((archives / 'manifest.json').read_text())
    cases = {case['name']: case for case in manifest['cases']}
    assert os.environ['SSL_CERT_FILE'] == info['ca'] and Path(info['ca']).is_file()
    for case in cases.values():
        assert hashlib.sha256((archives / (case['name'] + '.thrbackup')).read_bytes()).hexdigest() == case['sha256']
    initial = command('snapshot')
    geometry = h['request']('GET', h['base'] + '/window/rect')
    routes_before = Path('/proc/net/route').read_bytes()
    interfaces_before = sorted(p.name for p in Path('/sys/class/net').iterdir())
    connections = []
    dns_rows = []
    completed = False

    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            with contextlib.suppress(OSError):
                while data := self.request.recv(65536):
                    self.request.sendall(data)

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    server = Server(('127.0.0.1', 0), Echo)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    guard = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    guard.bind(('127.0.0.1', 0))
    with socket.socket() as available:
        available.bind(('127.0.0.1', 0))
        inbound = available.getsockname()[1]

    def state():
        root = Path(os.environ['XDG_DATA_HOME'])
        assert 'thronium-native-test-' in str(root)
        return json.loads((root / 'io.thronium.desktop/library.json').read_text())

    def events():
        # Ignore an unfinished final line if the independent fixture is writing.
        return [json.loads(line) for line in Path(info['events']).read_text().splitlines()
                if line.endswith('}')]

    def settings():
        click('.primary-nav button:nth-child(5)')
        wait_for('return !!document.querySelector("[data-settings-section=backup]")')
        click('[data-settings-section=backup]')
        wait_for('return !!document.querySelector("#backup-open")')

    def page():
        click('.primary-nav button:first-child')
        click('.primary-nav button:nth-child(2)')
        wait_for('return !!document.querySelector("#route-profile-select")')

    def previews():
        return js('return window.__doqNativeAudit.previews')

    def latest():
        return previews()[-1]

    def language():
        return command('snapshot')['preferences']['language']

    def open_file(path=None):
        count = len(previews())
        click('#backup-open')
        file_dialog('Открыть резервную копию' if language() == 'ru' else 'Open backup', path, opening=True)
        wait_for('return !document.querySelector("#backup-open").disabled', timeout=30)
        if path is not None:
            wait_for('return window.__doqNativeAudit.previews.length > ' + str(count), timeout=30)
            wait_for('return !!document.querySelector("#backup-confirm")')
            return latest()

    def scope(name, value):
        selector = '#legacy-scope-' + name
        if js('return document.querySelector(arguments[0]).checked', selector) != value:
            count = len(previews())
            click(selector)
            wait_for('return window.__doqNativeAudit.previews.length > ' + str(count))
            wait_for('return !document.querySelector("#backup-refresh").disabled')
        return latest()

    def routes_only(name):
        open_file(archives / (name + '.thrbackup'))
        scope('profiles', False)
        return scope('routes', True)

    def refresh():
        count = len(previews())
        click('#backup-refresh')
        wait_for('return window.__doqNativeAudit.previews.length > ' + str(count))
        wait_for('return !document.querySelector("#backup-refresh").disabled')
        return latest()

    def close():
        click('#main-modal > .modal-head > button')
        wait_for('return !document.querySelector("dialog[open]")')

    def apply():
        click('#backup-acknowledge')
        click('#backup-confirm')
        wait_for('return !document.querySelector("dialog[open]")', timeout=30)

    def reject(name, payload, code):
        try:
            command(name, payload)
        except RuntimeError as error:
            assert code in str(error), str(error)
        else:
            raise AssertionError(name + ' unexpectedly succeeded')

    def follow(enabled):
        previous = command('settings')['dns']
        command('saveSettings', {'section': 'dns', 'previous': previous,
                                'values': {**previous, 'enable_dns_routing': enabled}})

    def hold():
        connection = socket.create_connection(('127.0.0.1', inbound), timeout=5)
        target = '127.0.0.1:' + str(server.server_address[1])
        connection.sendall(f'CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n'.encode())
        headers = b''
        while b'\r\n\r\n' not in headers:
            part = connection.recv(4096)
            assert part
            headers += part
        assert b' 200 ' in headers.split(b'\r\n', 1)[0]
        connections.append(connection)
        return connection

    def echo(connection, label):
        data = ('native-doq-' + label).encode()
        connection.sendall(data)
        return exact(connection, len(data)) == data

    def stopped():
        for connection in connections:
            connection.close()
        connections.clear()
        command('disconnect')

    def choose(preset):
        page()
        before = js('return window.__doqNativeAudit.checks.length')
        select('#route-profile-select', preset['id'])
        wait_for('return !document.querySelector("#route-profile-select").disabled')
        assert command('routing')['active'] == preset['id']
        assert js('return window.__doqNativeAudit.checks.length') > before

    def imported(name, before):
        added = [p for p in command('routing')['profiles']
                 if p['id'] not in {p['id'] for p in before['routing']['profiles']}]
        assert len(added) == 1
        preset = added[0]
        assert preset['name'] == 'DoQ imported ' + name
        assert preset['dns'] == cases[name]['expectedDNS']
        assert preset['legacyConstraints'] == {'version': 4 if name in ['remote-udp', 'remote-quic'] else 2, 'xrayDnsStrategy': 'UseIP'}
        return preset

    def network(name, preset, selected):
        choose(preset)
        command('connect', {'id': selected})
        held = hold()
        config = command('connectionConfiguration', {'id': selected, 'active': True})
        actual = next(part['config'] for part in config['parts'] if part['name'] == 'sing-box')
        check(actual['dns'] == cases[name]['expectedDNS'] and echo(held, name),
              name + ' active configuration retains exact Qt DNS without TLS or detour overrides')
        (artifacts / (name + '-active-config.json')).write_text(json.dumps(config, indent=2) + '\n')
        for kind in (1, 28):
            label = f'native-{name}-{kind}.fixture.invalid'
            answer = dns_exchange(inbound, guard.getsockname()[1], label, kind, len(dns_rows) + 100)
            expected = ('192.0.2.22' if kind == 1 else '2001:db8::16') if name == 'bootstrap' else ('192.0.2.11' if kind == 1 else '2001:db8::b')
            transport = 'tcp' if name == 'bootstrap' else 'direct'
            rows = [e for e in events() if e.get('event') == 'query' and e.get('name') == label + '.' and e.get('type') == kind]
            assert rows and all(e['transport'] == transport for e in rows)
            if transport == 'direct':
                assert all(e['wireID'] == 0 for e in rows)
            check(answer == expected, name + ' returns a real ' + ('A' if kind == 1 else 'AAAA') + ' answer from the intended DNS transport')
            dns_rows.append({'case': name, 'type': kind, 'name': label, 'answer': answer, 'events': rows})
        tls_transport = 'bootstrap' if name == 'bootstrap' else 'direct'
        seen = events()
        assert any(e.get('event') == 'connection' and e.get('transport') == tls_transport and e.get('alpn') == 'doq' for e in seen)
        if name == 'bootstrap':
            assert any(e.get('event') == 'query' and e.get('transport') == 'bootstrap'
                       and e.get('name') == 'resolver.fixture.invalid.' and e.get('type') == 1 and e.get('wireID') == 0 for e in seen)
        check(echo(held, name + '-after-dns'), name + ' keeps the original CONNECT alive after verified QUIC DNS exchanges')
        return held

    try:
        command('disconnect')
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark'})
        wait_for('return document.documentElement.lang==="en"')
        settings()
        js('''window.__doqNativeAudit={fetch:window.fetch,previews:[],checks:[]};window.fetch=function(input,options){let body;try{body=JSON.parse(options?.body)}catch{};const out=window.__doqNativeAudit.fetch.apply(this,arguments);if(String(input).includes('/app_command')){if(body?.name==='checkRouting')window.__doqNativeAudit.checks.push(body.payload);if(['readBackup','legacyBackupScopes','refreshBackupPreview','previewPreviousBackup'].includes(body?.name))out.then(r=>r.clone().json()).then(v=>{const p=v?.preview||v;if(p?.token&&p?.incoming&&p?.current)window.__doqNativeAudit.previews.push(p);}).catch(()=>{});}return out;};''')
        baseline = state()
        baseline_path = artifacts / 'baseline.json'
        click('#backup-save')
        file_dialog('Save backup', baseline_path)
        wait_for('return !document.querySelector("#backup-save").disabled')
        assert json.loads(baseline_path.read_text())['library'] == baseline
        command('connectionSettings', {'mode': 'local', 'port': inbound})
        selected = command('saveProfile', {'name': 'DoQ current direct', 'groupId': 'personal',
                           'kind': 'sing-box-outbound', 'config': {'type': 'direct', 'udp_fragment': True}})['id']
        command('select', {'id': selected})
        routing = command('routing')
        original_active = routing['active']
        for preset in routing['profiles']:
            if preset['id'] == original_active:
                preset['mode'] = 'direct'
        command('saveRouting', routing)
        follow(False)
        before = state()
        open_file()
        check(state() == before and not js('return !!document.querySelector("dialog[open]")'), 'cancelled native backup chooser leaves the full library unchanged')
        preview = open_file(archives / 'direct.thrbackup')
        check(preview['legacy']['scopes']['profiles'] and not preview['legacy']['scopes']['routes'], 'real Qt DoQ archive defaults to profiles without enabling DNS route import')
        scope('profiles', False)
        preview = scope('routes', True)
        check(preview['legacy']['canApply'] and preview['legacy']['routeCount'] == 1
              and preview['incoming']['profiles'] == preview['current']['profiles'], 'route scope alone imports one generated DoQ preset with no source profiles')
        check('inactive-fixture-secret' not in json.dumps(preview) and 'inactive-fixture-secret' not in js('return document.body.textContent'), 'public DoQ review does not expose inactive DNS JSON or settings values')
        h['request']('POST', h['base'] + '/window/rect', {'width': 390, 'height': 844})
        check(js('return document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth+1'), 'English DoQ scope review fits the 390-pixel native window')
        screenshot('legacy-doq-en-390')
        command('preferences', {**command('snapshot')['preferences'], 'language': 'ru'})
        wait_for('return document.documentElement.lang==="ru"')
        preview = refresh()
        check('Пресеты маршрутизации' in js('return document.querySelector("#legacy-import-review").textContent')
              and js('return document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth+1'), 'Russian DoQ review stays localized and usable at 390 pixels')
        screenshot('legacy-doq-ru-390')
        command('preferences', {**command('snapshot')['preferences'], 'language': 'en'})
        wait_for('return document.documentElement.lang==="en"')
        old_token = preview['token']
        preview = refresh()
        reject('restoreBackup', {'token': old_token}, 'backup_preview_expired')
        check(not js('return document.querySelector("#backup-acknowledge").checked'), 'refresh expires the previous DoQ token and clears acknowledgement')
        h['request']('POST', h['base'] + '/window/rect', {'width': 1280, 'height': 860})
        close()
        check(state() == before, 'closing DoQ scope review adds nothing to the library')

        preview = routes_only('direct')
        command('saveProfile', {'name': 'Concurrent DoQ record', 'groupId': 'personal',
                              'kind': 'sing-box-outbound', 'config': {'type': 'direct'}})
        before_import = state()
        click('#backup-acknowledge')
        click('#backup-confirm')
        wait_for('return document.querySelector("dialog .desktop-inline-error")?.textContent.includes("changed")')
        updated = refresh()
        check(updated['token'] != preview['token'] and updated['current']['profiles'] == preview['current']['profiles'] + 1
              and updated['legacy']['scopes']['routes'] and not updated['legacy']['scopes']['profiles'], 'stale DoQ review refuses commit and refresh retains scope and the concurrent record')
        apply()
        direct = imported('direct', before_import)
        after = state()
        check(all(after[k] == before_import[k] for k in ['profiles', 'groups', 'preferences', 'settings'])
              and after['routing']['active'] == before_import['routing']['active'], 'DoQ import adds exact Qt DNS while retaining current settings profiles and active routing')
        click('#backup-undo')
        wait_for('return !!document.querySelector("#backup-confirm")')
        apply()
        check(state() == before_import, 'native Previous library exactly reverses the DoQ import')
        routes_only('direct')
        apply()
        previous_id = direct['id']
        direct = imported('direct', before_import)
        check(direct['id'] != previous_id, 'reimport after undo creates a fresh routing UUID instead of reusing the discarded plan')

        follow(True)
        command('connect', {'id': selected})
        held = hold()
        page()
        select('#route-profile-select', direct['id'])
        wait_for('return !!document.querySelector(".desktop-inline-error") && !document.querySelector("#route-profile-select").disabled')
        reject('checkRouting', direct, 'legacy_routing_dns_follow_conflict')
        check(command('routing')['active'] == original_active and echo(held, 'conflict'), 'UI and backend reject conflicting DoQ selection before disrupting the active CONNECT')
        stopped()
        follow(False)
        held = network('direct', direct, selected)
        stable = state()
        settings()
        for name in ['bootstrap-hostname']:
            preview = routes_only(name)
            check(not preview['legacy']['canApply'] and cases[name]['expectedError'] in {i['code'] for i in preview['legacy']['issues']}
                  and js('return document.querySelector("#backup-confirm").disabled') and echo(held, name), name + ' remains a visible import blocker while the original CONNECT stays open')
            close()
            assert state() == stable
        preview = routes_only('both')
        reject('restoreBackup', {'token': preview['token']}, 'backup_disconnect_first')
        check(js('return document.querySelector("#backup-confirm").disabled') and echo(held, 'valid-import-while-running'), 'valid DoQ import also respects the disconnect guard and leaves active traffic intact')
        close()
        stopped()

        for name in ['bootstrap', 'both', 'remote-quic', 'direct-hostname']:
            settings()
            before_import = state()
            routes_only(name)
            apply()
            preset = imported(name, before_import)
            check(state()['routing']['active'] == before_import['routing']['active'], name + ' import retains the previously selected preset until explicit choice')
            network(name, preset, selected)
            stopped()
        settings()
        before_import = state()
        routes_only('default-port')
        apply()
        preset = imported('default-port', before_import)
        command('checkRouting', preset)
        check(all('server_port' not in server for server in preset['dns']['servers'] if server['type'] == 'quic'), 'default DoQ port remains absent in imported JSON and passes the real core check')
        for name in ['no-settings', 'no-routes']:
            before_case = state()
            open_file(archives / (name + '.thrbackup'))
            if name == 'no-settings':
                preview = scope('routes', True)
                check(not preview['legacy']['canApply'] and 'legacy_route_parts_required' in {i['code'] for i in preview['legacy']['issues']}, 'missing Settings part blocks generated DoQ without dropping the DNS dependency')
            else:
                check(js('return document.querySelector("#legacy-scope-routes").disabled'), 'missing Routes part cannot import retained source routing rows')
            close()
            assert state() == before_case
        guard.settimeout(.1)
        try:
            guard.recvfrom(4096)
        except socket.timeout:
            pass
        else:
            raise AssertionError('DNS capture forwarded a packet to the placeholder destination')
        check(Path('/proc/net/route').read_bytes() == routes_before and sorted(p.name for p in Path('/sys/class/net').iterdir()) == interfaces_before, 'native DoQ traffic leaves host routes and network interfaces unchanged')
        open_file(baseline_path)
        apply()
        check(state() == baseline, 'native baseline restore removes every test addition exactly')
        check(all(hashlib.sha256((archives / (name + '.thrbackup')).read_bytes()).hexdigest() == case['sha256'] for name, case in cases.items()), 'all original Qt archive bytes remain unchanged after preview import refresh and undo')
        completed = True
    finally:
        with contextlib.suppress(Exception):
            (artifacts / 'legacy-quic-dns-review.json').write_text(json.dumps({
                'passed': completed, 'dnsAnswers': dns_rows, 'events': events(),
                'previews': previews(), 'sourceHashes': {name: case['sha256'] for name, case in cases.items()},
                'trust': 'Private SSL_CERT_FILE, unmodified imported DNS JSON',
            }, ensure_ascii=False, indent=2) + '\n')
        for connection in connections:
            connection.close()
        with contextlib.suppress(Exception):
            if js('return !!document.querySelector("dialog[open]")'):
                close()
            command('disconnect')
            command('preferences', initial['preferences'])
            js('if(window.__doqNativeAudit){window.fetch=window.__doqNativeAudit.fetch;delete window.__doqNativeAudit;}')
            h['request']('POST', h['base'] + '/window/rect', geometry)
        guard.close()
        server.shutdown()
        server.server_close()
