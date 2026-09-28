"""Measured-country selection through real private TLS services and a held stream."""
import contextlib
import copy
import json
import os
from pathlib import Path
import socket
import threading
import time
import urllib.request


def run(h):
    command, click, fill, select, wait_for, js, check, screenshot = (h[k] for k in ('command', 'click', 'fill', 'select', 'wait_for', 'js', 'check', 'screenshot'))
    fixture = json.loads(Path(os.environ['_THRONIUM_DIAGNOSTICS_FIXTURE']).read_text())
    initial = command('snapshot')
    original_route = command('routing')
    geometry = h['request']('GET', h['base'] + '/window/rect')
    groups = []
    held = None
    heartbeat = None
    stop = threading.Event()
    beats = []
    errors = []
    pending = set()

    def admin(index, **values):
        req = urllib.request.Request(fixture['admins'][index], data=json.dumps(values).encode() if values else None, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=3) as response:
            return json.load(response)

    def group(name):
        result = command('saveGroup', {'name': name})['id']; groups.append(result); return result

    def add(gid, name, port):
        return command('saveProfile', {'name': name, 'groupId': gid, 'kind': 'sing-box-outbound', 'config': {'type': 'socks', 'server': '127.0.0.1', 'server_port': port}})['id']

    def close():
        click('#main-modal > .modal-head > button')
        if js('return !!document.querySelector(".editor-discard")'): click('.editor-discard [data-confirm-accept]')
        wait_for('return !document.querySelector("dialog[open]")')

    def preview(ids):
        wait_for('return !document.querySelector("#selector-preview-loading") && JSON.stringify([...document.querySelectorAll("[data-selector-preview-member]")].map(e=>e.dataset.selectorPreviewMember))===' + json.dumps(json.dumps(ids, separators=(',', ':'))))

    def edit(pid):
        click('.primary-nav button:first-child'); select('.group-strip select', 'all'); fill('#client-search', '')
        click('[data-profile-menu="' + pid + '"]'); click('#menu-edit-profile')
        wait_for('return !!document.querySelector("#selector-country-filter")')

    def begin(pid, token):
        pending.add(token)
        js('''window.__country45 ??= {};const token=arguments[1];window.__country45[token]={done:false};
window.__TAURI_INTERNALS__.invoke('app_command',{name:'testIp',payload:{id:arguments[0],requestId:token}})
.then(value=>window.__country45[token]={done:true,ok:true,value})
.catch(error=>window.__country45[token]={done:true,ok:false,error});''', pid, token)

    def finish(token):
        wait_for('return window.__country45?.[' + json.dumps(token) + ']?.done', 15)
        result = json.loads(js('return JSON.stringify(window.__country45[arguments[0]])', token))
        pending.remove(token)
        return result

    def measured(pid, index, mode, code):
        admin(index, clear=True, ipMode=mode)
        result = command('testIp', {'id': pid, 'requestId': 'country45-' + str(time.monotonic_ns())})['result']
        assert result['countryCode'] == code and any(row[0] == 2 and row[2] == 443 for row in admin(index)['seen'])
        return result

    def ui_measure(pid, index, mode, label):
        click('.primary-nav button:first-child'); command('select', {'id': pid}); select('.group-strip select', 'all')
        click('[data-profile-menu="' + pid + '"]'); click('#diagnostics-one')
        admin(index, clear=True, ipMode=mode)
        click('#diagnostics-ip')
        wait_for('return !document.querySelector("#diagnostics-progress") && !!document.querySelector("#settings-test-result,.settings-test-actions [role=alert]")', 15)
        check(js('return document.querySelector("#diagnostics-country")?.textContent===arguments[0]', label)
              and any(row[0] == 2 and row[2] == 443 for row in admin(index)['seen']),
              'native IP action validates TLS through owned proxy ' + str(index) + ' and displays ' + label)
        close()

    def pool(ids):
        end = time.monotonic() + 12
        while time.monotonic() < end:
            status = command('getAutoSelectors')
            if status and status[0]['membersAlive'] == len(ids) and [m['profileId'] for m in status[0]['members']] == ids:
                return status[0]
            time.sleep(.1)
        raise AssertionError('Country runtime membership did not become ' + repr(ids))

    def connect_http(path):
        sock = socket.create_connection(('127.0.0.1', local_port), timeout=4)
        try:
            authority = '127.0.0.1:' + str(fixture['httpPorts'][0])
            sock.sendall(('CONNECT ' + authority + ' HTTP/1.1\r\nHost: ' + authority + '\r\n\r\n').encode())
            def headers():
                result = b''
                while b'\r\n\r\n' not in result:
                    chunk = sock.recv(1); assert chunk; result += chunk
                assert b' 200 ' in result.split(b'\r\n', 1)[0]
                return result
            headers()
            sock.sendall(('GET ' + path + ' HTTP/1.0\r\nHost: ' + authority + '\r\n\r\n').encode())
            head = headers()
            length = int(next(line.split(b':', 1)[1] for line in head.split(b'\r\n') if line.lower().startswith(b'content-length:')))
            body = b''
            while len(body) < length:
                chunk = sock.recv(length - len(body)); assert chunk; body += chunk
            return sock, body
        except BaseException:
            sock.close(); raise

    def pulse():
        try:
            while not stop.is_set():
                message = ('country45-heartbeat-' + str(len(beats))).encode()
                held.sendall(message)
                reply = b''
                while len(reply) < len(message):
                    chunk = held.recv(len(message) - len(reply)); assert chunk; reply += chunk
                assert reply == message
                beats.append(time.monotonic())
                stop.wait(.2)
        except BaseException as error:
            errors.append(repr(error))

    def rejected(name, payload, code):
        try: command(name, payload)
        except RuntimeError as error: return code in str(error)
        return False

    try:
        command('disconnect')
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0)); local_port = listener.getsockname()[1]
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark', 'connectionMode': 'local', 'inboundPort': local_port,
                                'ping': {**initial['preferences']['ping'], 'timeoutMs': 3000}})
        # Explicitly send the owned loopback target to the selected proxy.
        route = copy.deepcopy(original_route)
        current = next(p for p in route['profiles'] if p['id'] == route['active'])
        current['rules'] = [{'id': 'country45-local-proxy', 'name': 'Owned fixture through selected proxy', 'enabled': True, 'config': {'ip_cidr': ['127.0.0.1/32'], 'outbound': 'proxy'}}]
        command('saveRouting', route)
        source, owner = group('Country measurements'), group('Country pools')
        a = add(source, 'Germany flag — measured elsewhere', fixture['ports'][0])
        b = add(source, 'Japan flag — measured elsewhere', fixture['ports'][1])
        unknown = add(source, 'JP unmeasured', fixture['ports'][0])
        wait_for('return document.documentElement.lang==="en"')
        data_root = Path(os.environ['XDG_DATA_HOME']).resolve()
        assert data_root.parent.name.startswith('thronium-native-test-') and data_root.name == 'data'
        library_paths = list(data_root.rglob('library.json')); assert len(library_paths) == 1
        library_path = library_paths[0]
        # UI selection writes the library; compare the cache-only API separately below.
        ui_measure(a, 0, 'ok', 'Japan (JP)')
        ui_measure(b, 1, 'ipv6', 'Germany (DE)')
        cache_path = library_path.with_name('exit-countries-v1.json')
        before = library_path.read_bytes(); revision = command('snapshot')['libraryRevision']
        measured(a, 0, 'ok', 'JP')
        cache = cache_path.read_text()
        check(library_path.read_bytes() == before and command('snapshot')['libraryRevision'] > revision
              and (cache_path.stat().st_mode & 0o777) == 0o600 and '203.0.113.9' not in cache and '2001:db8::9' not in cache,
              'successful measurement updates a private derived cache and revision without rewriting the portable library or storing exit IPs')
        cfg = {'type': 'auto-selector', 'member_source': {'group_id': source, 'country_filter': ' jp, JP '},
               'url': 'http://127.0.0.1:' + str(fixture['httpPorts'][0]) + '/health', 'interval': '1s', 'bench_interval': '2s',
               'watch_interval': '500ms', 'timeout': '800ms', 'sampling': 2, 'expected': 2, 'active_size': 5}
        pid = command('saveProfile', {'name': 'Measured country pool', 'groupId': owner, 'kind': 'auto-selector', 'config': cfg})['id']
        edit(pid); preview([a])
        check(js('return document.querySelector("#selector-preview-unknown").textContent.endsWith(": 1") && document.querySelector("[data-selector-preview-member] small").textContent==="JP"'),
              'country preview normalizes duplicate codes, uses measurements instead of names, and counts unmeasured servers')
        fill('#selector-country-filter', 'DE'); preview([b])
        check(True, 'changing the country filter selects the other measured exit')
        fill('#selector-country-filter', ''); preview([a, b, unknown])
        check(not js('return !!document.querySelector("#selector-preview-unknown")'), 'empty country filter includes servers without IP measurements')
        fill('#selector-country-filter', 'DE;JP'); wait_for('return !!document.querySelector("#selector-preview-error")')
        original = command('profile', {'id': pid})
        invalid = copy.deepcopy(original); invalid['config']['member_source']['country_filter'] = 'DE;JP'
        check(rejected('saveProfile', {k: invalid[k] for k in ('id', 'name', 'groupId', 'kind', 'config')}, 'selector_invalid_country_filter')
              and command('profile', {'id': pid}) == original
              and not js('return document.querySelector("#selector-preview-error").textContent.includes("selector_invalid_country_filter")'),
              'invalid country input clears the preview, localizes its error, and cannot overwrite the saved pool')
        fill('#selector-country-filter', 'JP'); preview([a])
        # An actual backend measurement while the editor stays open must refresh
        # through the snapshot revision, without clicking Refresh preview.
        measured(unknown, 0, 'ok', 'JP'); preview([a, unknown])
        measured(unknown, 0, 'unknown', None); preview([a])
        check(True, 'open editor follows new cache revisions and unknown results remove previous country eligibility')
        for lang, theme in [('ru', 'light'), ('en', 'dark')]:
            command('preferences', {**command('snapshot')['preferences'], 'language': lang, 'theme': theme})
            wait_for('return document.documentElement.lang===' + json.dumps(lang)); preview([a])
            h['request']('POST', h['base'] + '/window/rect', {'width': 390, 'height': 844})
            js('document.querySelector("#selector-country-filter").scrollIntoView({block:"start"})')
            check(js('return document.documentElement.scrollWidth<=innerWidth && document.querySelector(".selector-fields").scrollWidth<=document.querySelector(".selector-fields").clientWidth && !!document.querySelector("#selector-country-hint")'),
                  lang + ' country editor and measurement explanation fit a 390-pixel native window')
            screenshot('selector-country-' + lang + '-390')
        h['request']('POST', h['base'] + '/window/rect', {'width': 1280, 'height': 860})
        click('button[form="profile-editor"]'); wait_for('return !document.querySelector("dialog[open]")')
        check(command('profile', {'id': pid})['config']['member_source']['country_filter'] == 'JP',
              'native Save persists the edited country filter without replacing the dynamic source')
        # A pool using other group hops cannot borrow an unrelated country.
        command('saveGroup', {'id': owner, 'name': 'Country pools', 'proxyChain': {'landing': b}})
        edit(pid); preview([])
        check(js('return document.querySelector("#selector-preview-unknown").textContent.endsWith(": 3")'), 'pool group proxy mismatch excludes individually measured countries')
        close(); command('saveGroup', {'id': owner, 'name': 'Country pools', 'proxyChain': {}})
        command('connect', {'id': pid}); pool([a])
        active = command('connectionConfiguration', {'id': pid, 'active': True})
        since = command('snapshot')['since']
        held, body = connect_http('/stream'); assert body == b'ready'
        heartbeat = threading.Thread(target=pulse, name='country45-owned-heartbeat'); heartbeat.start()
        time.sleep(.5)
        check(len(beats) >= 2 and not errors and any(row[2] == fixture['httpPorts'][0] for row in admin(0)['seen']), 'country-selected pool carries an actual CONNECT stream through its measured proxy')
        measured(a, 0, 'ipv6', 'DE'); measured(b, 1, 'ok', 'JP')
        edit(pid); preview([b]); count = len(beats)
        time.sleep(.5)
        check(len(beats) > count and not errors and command('snapshot')['since'] == since
              and command('connectionConfiguration', {'id': pid, 'active': True}) == active
              and [m['profileId'] for m in command('getAutoSelectors')[0]['members']] == [a],
              'new country measurements refresh the draft while preserving active Core configuration, membership and the held stream')
        close(); stop.set(); heartbeat.join(5); assert not heartbeat.is_alive(); held.close(); held = None
        command('disconnect'); admin(1, clear=True)
        command('connect', {'id': pid}); pool([b])
        conn, body = connect_http('/body'); conn.close()
        check(body == b'country45:0' and any(row[2] == fixture['httpPorts'][0] for row in admin(1)['seen']), 'next connection rebuilds the country pool and forwards a complete HTTP response through the newly eligible proxy')
        command('disconnect')
        # Cancellation and stale configuration must not publish delayed success.
        before = cache_path.read_bytes(); admin(1, clear=True, ipMode='slow'); token = 'country45-cancel'; begin(b, token)
        deadline = time.monotonic() + 4
        while not admin(1)['seen'] and time.monotonic() < deadline: time.sleep(.02)
        assert admin(1)['seen']; command('cancelSettingsTest', {'requestId': token}); result = finish(token)
        check(not result['ok'] and result['error'] == 'probe_cancelled' and cache_path.read_bytes() == before, 'cancelled real IP request leaves the previous country cache untouched')
        admin(1, clear=True, ipMode='slow'); token = 'country45-stale'; begin(b, token)
        deadline = time.monotonic() + 4
        while not admin(1)['seen'] and time.monotonic() < deadline: time.sleep(.02)
        assert admin(1)['seen']
        saved = command('profile', {'id': b}); changed = copy.deepcopy(saved); changed['config']['server_port'] = fixture['ports'][0]
        command('saveProfile', {k: changed[k] for k in ('id', 'name', 'groupId', 'kind', 'config')}); result = finish(token)
        check(not result['ok'] and result['error'] == 'probe_stale' and cache_path.read_bytes() == before, 'late response for edited server settings is rejected without overwriting the cache')
        edit(pid); preview([])
        check(js('return document.querySelector("#selector-preview-unknown").textContent.endsWith(": 2")'), 'edited connection settings invalidate old measurements until an explicit new IP check')
        close()
        check(rejected('connect', {'id': pid}, 'selector_empty_pool') and command('snapshot')['running'] is None, 'country pool with no applicable measurements refuses connection before starting Core')
        Path(h['artifacts']).joinpath('country-network-audit.json').write_text(json.dumps({'heartbeats': len(beats), 'heartbeatErrors': errors, 'privateTlsProxies': 2, 'firstMember': a, 'nextMember': b, 'cacheFields': list(json.loads(cache)['entries'][a]), 'externalRequests': False}, indent=2) + '\n')
    finally:
        for token in list(pending):
            with contextlib.suppress(Exception): command('cancelSettingsTest', {'requestId': token})
        stop.set()
        if heartbeat:
            heartbeat.join(5)
        if held:
            with contextlib.suppress(OSError): held.shutdown(socket.SHUT_RDWR)
            held.close()
        if heartbeat: assert not heartbeat.is_alive(), 'Owned heartbeat thread did not exit'
        command('disconnect')
        for gid in reversed(groups):
            command('deleteGroup', {'id': gid, 'deleteProfiles': True})
        command('saveRouting', {**original_route, 'revision': command('routing')['revision']})
        command('preferences', initial['preferences'])
        if initial['selected']: command('select', {'id': initial['selected']})
        h['request']('POST', h['base'] + '/window/rect', {'width': geometry['width'], 'height': geometry['height']})
