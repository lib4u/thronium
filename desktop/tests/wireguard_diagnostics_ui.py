"""Native IP/speed/HTTP measurements through an independent userspace WireGuard peer."""
import contextlib
import copy
import json
import os
from pathlib import Path
import socket
import time
import urllib.request


def run(h):
    command, check, js, wait_for = (h[k] for k in ('command', 'check', 'js', 'wait_for'))
    fixture = json.loads(Path(os.environ['_THRONIUM_WG_DIAGNOSTICS_FIXTURE']).read_text())
    initial = command('snapshot'); assert not initial['profiles']
    sockets, tokens = [], []
    audit = {'results': [], 'tunnel': fixture['tunnel']}
    def admin(**values):
        request = urllib.request.Request(fixture['admin'], data=json.dumps(values).encode() if values else None,
                                         headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=3) as response: return json.load(response)
    def peer(): return json.loads(Path(fixture['peerStats']).read_text())
    def poll(predicate, timeout=8):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if predicate(): return
            time.sleep(.05)
        raise AssertionError('WireGuard diagnostics fixture did not reach expected state')
    def setting(mode='simple'):
        old = command('settings')['testing']
        command('saveSettings', {'section': 'testing', 'previous': old, 'values': {
            **old, 'speed_test_mode': mode, 'speed_test_timeout_ms': 1000, 'simple_dl_url': fixture['simpleUrl']}})
    def add(name, config, group='personal'):
        return command('saveProfile', {'name': name, 'kind': 'sing-box-outbound', 'groupId': group, 'config': config})['id']
    def begin(kind, identifier):
        token = 'wg-diagnostics81-' + str(len(tokens) + 1); tokens.append(token)
        js('''const token=arguments[2];window.__wg81??={};window.__wg81[token]={done:false};
            window.__TAURI_INTERNALS__.invoke('app_command',{name:arguments[0],payload:{id:arguments[1],requestId:token}})
            .then(value=>window.__wg81[token]={done:true,ok:true,value})
            .catch(error=>window.__wg81[token]={done:true,ok:false,error});''', kind, identifier, token)
        return token
    def finish(token, release=False):
        wait_for('return window.__wg81?.[' + json.dumps(token) + ']?.done', 35)
        if release: admin(mode='ok', release=True)
        row = json.loads(js('return JSON.stringify(window.__wg81[arguments[0]])', token))
        poll(lambda: admin()['active'] == 0)
        audit['results'].append({'result': row, 'fixture': admin(), 'peer': peer()})
        return row
    def phase_started(token, phase):
        poll(lambda: any(r['phase'] == phase for r in admin()['requests']) or js('return window.__wg81[arguments[0]].done', token), 15)
        if not any(r['phase'] == phase for r in admin()['requests']):
            row = finish(token)
            raise AssertionError('WireGuard measurement ended before phase ' + phase + ': ' + json.dumps(row))
    def code_of(row):
        error = row.get('error')
        return error.get('code') if isinstance(error, dict) else error
    def failed(row, code=None):
        return not row['ok'] and 'value' not in row and (code is None or code_of(row) == code)
    def measured(row, kind):
        value = row['value']['result']
        return row['ok'] and value['kind'] == kind and value['transport'] == 'wireguard-endpoint' and value['profileName']
    try:
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0)); port = reservation.getsockname()[1]
        preferences = {**initial['preferences'], 'language': 'en', 'connectionMode': 'local', 'inboundPort': port}
        preferences['ping'] = {**preferences['ping'], 'timeoutMs': 2500, 'url': 'https://api.ip2location.io/'}
        command('preferences', preferences)
        direct = add('Owned primary direct', {'type': 'direct'})
        wg = add('WireGuard diagnostics81', fixture['wireguard'])
        awg = add('AmneziaWG diagnostics81', {**copy.deepcopy(fixture['wireguard']), 'amnezia_wg': {'rekey_after_time': 120}})
        command('connect', {'id': direct}); before = command('snapshot')
        listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen(); sockets.append(listener)
        client = socket.create_connection(('127.0.0.1', port), timeout=3); sockets.append(client)
        authority = '127.0.0.1:' + str(listener.getsockname()[1])
        client.sendall(('CONNECT ' + authority + ' HTTP/1.1\r\nHost: ' + authority + '\r\n\r\n').encode())
        upstream, _ = listener.accept(); upstream.settimeout(3); sockets.append(upstream)
        assert b'200' in client.recv(1024)
        from window_ui import primary
        from native_processes import core_pids
        connection, _, app_pid = primary(); connection.close(); main_pids = core_pids(app_pid)
        def preserved():
            poll(lambda: core_pids(app_pid) == main_pids)
            current = command('snapshot')
            assert current['running'] == direct and current['since'] == before['since']
            client.sendall(b'preserved81'); assert upstream.recv(11) == b'preserved81'
        setting()
        for kind in ('testIp', 'testSpeed'):
            admin(mode='ok', clear=True); row = finish(begin(kind, direct))
            check(failed(row) and not admin()['requests'], kind + ' cannot reach the owned service without the tunnel')
            preserved()
        profiles = {p['id']: p for p in command('snapshot')['profiles']}
        check(profiles[wg]['ipSpeedSupported'] and profiles[awg]['ipSpeedSupported'], 'single userspace WireGuard and AmneziaWG profiles advertise IP/speed support')
        forwarded = peer().get('forwarded', {}).get('443', 0)
        admin(mode='ok', clear=True); row = finish(begin('testIp', wg))
        check(measured(row, 'ip') and row['value']['result']['ip'] == '203.0.113.9' and row['value']['result']['countryCode'] == 'JP',
              'WireGuard measures the owned TLS exit IP/country through its own disposable endpoint')
        stats = peer()
        check(len(admin()['requests']) == 1 and admin()['requests'][0]['phase'] == 'ip' and stats['forwarded']['443'] > forwarded
              and all(remote.startswith('10.177.43.2:') for remote in stats['forwardedFrom']) and stats['metrics']['last_handshake_time_sec'] > 0,
              'the IP request reaches the service exactly once from inside the independent peer tunnel')
        cache = Path(command('storageLocation')['directory']) / 'exit-countries-v1.json'
        cached = cache.read_text()
        check(json.loads(cached)['entries'][wg]['countryCode'] == 'JP' and fixture['wireguard']['private_key'] not in cached
              and fixture['wireguard']['peers'][0]['pre_shared_key'] not in cached, 'WireGuard country is persisted without any key material')
        preserved()
        admin(mode='ok', clear=True); row = finish(begin('testIp', awg))
        check(measured(row, 'ip') and row['value']['result']['countryCode'] == 'JP', 'AmneziaWG-typed profile with standard-wire timers measures IP through the same endpoint path')
        preserved()
        for mode in ('simple', 'download', 'upload', 'full'):
            setting(mode); admin(mode='ok', clear=True); before_peer = peer(); row = finish(begin('testSpeed', wg)); state = admin()
            check(measured(row, 'speed'), 'WireGuard completes real ' + mode + ' speed measurement')
            result = row['value']['result']
            check((result['downloadBytes'] > 0) == (mode != 'upload') and (result['uploadBytes'] > 0) == (mode in ('full', 'upload'))
                  and (state['downloadBytes'] > 0) == (mode != 'upload') and (state['uploadBytes'] > 0) == (mode in ('full', 'upload'))
                  and peer()['receivedWirePacketTypes'].get('4', 0) > before_peer['receivedWirePacketTypes'].get('4', 0),
                  'WireGuard ' + mode + ' credits actual bytes in the requested directions through the tunnel')
            preserved()
        for kind, mode, failure in [('testIp', 'simple', 'ip-http'), ('testIp', 'simple', 'ip-invalid'),
                                    ('testSpeed', 'download', 'download-http'), ('testSpeed', 'upload', 'upload-http'),
                                    ('testSpeed', 'download', 'download-empty')]:
            # A truncated body is not asserted here: through the fast loopback tunnel a
            # timed sample ends at its deadline with bytes already counted, and the simple
            # path counts a cleanly closed short body; the ordinary stands keep that case.
            setting(mode); admin(mode=failure, clear=True); row = finish(begin(kind, wg))
            check(failed(row) and code_of(row) in ('probe_failed', 'probe_timeout'), 'WireGuard with ' + failure + ' reports a failed measurement without inventing a value')
            preserved()
        for kind, mode, phase in [('testIp', 'simple', 'ip'), ('testSpeed', 'download', 'download'), ('testSpeed', 'upload', 'upload')]:
            setting(mode); admin(mode='hold-' + phase, clear=True); token = begin(kind, wg)
            phase_started(token, phase)
            started = time.monotonic(); command('cancelSettingsTest', {'requestId': token}); row = finish(token, release=True)
            check(failed(row, 'probe_cancelled') and time.monotonic() - started < 5, 'WireGuard cancellation during ' + phase + ' rejects late results promptly')
            preserved()
        for field in ('private_key', 'peer'):
            admin(mode='hold-ip', clear=True); token = begin('testIp', wg)
            phase_started(token, 'ip')
            original = command('profile', {'id': wg}); changed = copy.deepcopy(original)
            if field == 'private_key': changed['config']['private_key'] = fixture['wireguard']['peers'][0]['public_key']
            else: changed['config']['peers'][0]['port'] += 1
            command('saveProfile', changed); admin(mode='ok', release=True); row = finish(token)
            check(failed(row, 'probe_stale'), 'WireGuard ' + field + ' edit rejects a pending measurement')
            command('saveProfile', {**original, 'expectedRevision': command('profile', {'id': wg})['expectedRevision']}); preserved()
        for change in ({'system': True}, {'name': 'owned-wg81'}, {'detour': 'other'}):
            config = {**copy.deepcopy(fixture['wireguard']), **change}; identifier = add('Unsupported WG context81', config)
            profile = next(p for p in command('snapshot')['profiles'] if p['id'] == identifier)
            check(not profile['ipSpeedSupported'], 'unsupported WireGuard context disables IP/speed capability: ' + next(iter(change)))
            row = finish(begin('testIp', identifier)); check(failed(row, 'probe_unsupported'), 'unsupported context refuses execution before any core starts')
            preserved()
        wrapped_group = command('saveGroup', {'name': 'Wrapped WG81', 'subscription': None, 'proxyChain': {'front': direct, 'landing': None}})['id']
        wrapped = add('Wrapped WG81', copy.deepcopy(fixture['wireguard']), wrapped_group)
        check(not next(p for p in command('snapshot')['profiles'] if p['id'] == wrapped)['ipSpeedSupported'], 'group proxies around an endpoint keep IP/speed unavailable')
        setting('simple'); admin(mode='ok', clear=True)
        run = command('startPing', {'ids': [wg]})
        poll(lambda: command('snapshot')['urlTests'] is not None and all(e['status'] not in ('queued', 'testing') for e in command('snapshot')['urlTests']['entries']), 20)
        entry = next(e for e in command('snapshot')['urlTests']['entries'] if e['profileId'] == wg)
        check(entry['status'] == 'ok' and entry['effectiveMethod'] == 'http' and entry['latencyMs'] >= 0 and any(r['phase'] == 'ip' for r in admin()['requests']),
              'Auto latency test reaches the owned service over HTTP through the WireGuard endpoint before any fallback')
        preserved()
        for language, width in [('en', 1280), ('ru', 390)]:
            command('preferences', {**command('snapshot')['preferences'], 'language': language}); command('select', {'id': wg})
            h['request']('POST', h['base'] + '/window/rect', {'width': width, 'height': 900})
            wait_for('return document.documentElement.lang===' + json.dumps(language) + ' && innerWidth===' + str(width))
            h['click']('.primary-nav button:last-child'); h['click']('[data-settings-section=testing]')
            wait_for('return document.querySelector("#diagnostics-profile")?.textContent.includes("WireGuard diagnostics81") && !document.querySelector("#diagnostics-ip").disabled')
            admin(mode='ok', clear=True)
            js('document.querySelector("#diagnostics-ip").scrollIntoView({block:"center",behavior:"instant"})')
            h['click']('#diagnostics-ip'); wait_for('return document.querySelector("#diagnostics-exit-ip")?.textContent==="203.0.113.9"', 25)
            context = js('return document.querySelector("#diagnostics-context").textContent')
            check('JP' in js('return document.querySelector("#diagnostics-country").textContent') and ('WireGuard endpoint' in context),
                  'native WireGuard IP button displays the measured country and the endpoint transport in ' + language)
            js('document.querySelector("#settings-test-result").scrollIntoView({block:"center",behavior:"instant"})')
            check(js('return document.documentElement.scrollWidth<=innerWidth+1'), 'WireGuard diagnostics fit ' + language + ' ' + str(width) + 'px')
            h['screenshot']('wg-ip-' + language + '-' + str(width)); preserved()
        # Bulk IP and speed through the shared queue: the same isolated tests per row.
        def batch_done(timeout=40):
            poll(lambda: command('snapshot')['urlTests'] is not None and all(e['status'] not in ('queued', 'testing') for e in command('snapshot')['urlTests']['entries']), timeout)
            return command('snapshot')['urlTests']
        unsupported = add('Unsupported WG bulk81', {**copy.deepcopy(fixture['wireguard']), 'system': True})
        setting('simple'); admin(mode='ok', clear=True); before_peer = peer()
        command('startIpTests', {'ids': [wg, awg, direct, unsupported]})
        batch = batch_done(); rows = {e['profileId']: e for e in batch['entries']}
        check(batch['kind'] == 'ip' and all(e['kind'] == 'ip' for e in batch['entries']), 'a bulk IP batch is published with its kind on every entry')
        check(all(rows[i]['status'] == 'ok' and rows[i]['ip'] == '203.0.113.9' and rows[i]['countryCode'] == 'JP' and rows[i]['transport'] == 'wireguard-endpoint' for i in (wg, awg)),
              'bulk IP measures both endpoint profiles through their own disposable cores')
        check(rows[direct]['status'] == 'error' and rows[direct]['ip'] is None and rows[unsupported]['status'] == 'unsupported' and rows[unsupported]['error'] == 'probe_unsupported',
              'bulk IP reports the unreachable direct route as an error and the system endpoint as unsupported without inventing values')
        check(sum(1 for r in admin()['requests'] if r['phase'] == 'ip') == 2 and peer()['forwarded']['443'] >= before_peer['forwarded']['443'] + 2,
              'bulk IP reaches the owned service once per endpoint from inside the tunnel')
        check(json.loads(cache.read_text())['entries'][awg]['countryCode'] == 'JP', 'bulk IP persists the country for every measured profile')
        preserved()
        admin(mode='ok', clear=True); command('startSpeedTests', {'ids': [wg, awg]})
        overlap = 0
        end = time.monotonic() + 40
        while time.monotonic() < end:
            current = command('snapshot')['urlTests']['entries']
            overlap = max(overlap, sum(1 for e in current if e['status'] == 'testing'))
            if all(e['status'] not in ('queued', 'testing') for e in current): break
            time.sleep(.05)
        batch = command('snapshot')['urlTests']; rows = {e['profileId']: e for e in batch['entries']}
        check(batch['kind'] == 'speed' and overlap <= 1 and all(rows[i]['status'] == 'ok' and rows[i]['downloadBytes'] > 0 and rows[i]['download'] for i in (wg, awg)),
              'bulk speed measures one endpoint at a time and records real download bytes for each')
        preserved()
        admin(mode='hold-ip', clear=True); command('startIpTests', {'ids': [wg]})
        poll(lambda: any(r['phase'] == 'ip' for r in admin()['requests']), 15)
        started = time.monotonic(); command('cancelUrlTests'); batch = batch_done(10); admin(mode='ok', release=True)
        check(batch['entries'][0]['status'] == 'cancelled' and time.monotonic() - started < 5, 'cancelling a bulk IP batch rejects the pending isolated test promptly')
        poll(lambda: admin()['active'] == 0)
        preserved()
        admin(mode='ok', clear=True); command('startIpTests', {'ids': [wg]}); batch_done()
        h['click']('.primary-nav button:first-child'); command('select', {'id': wg})
        wait_for('return document.querySelector(' + json.dumps('[data-profile-latency="' + wg + '"]') + ')?.textContent.includes("JP · 203.0.113.9")')
        check(js('return document.querySelector("#ping-status").textContent').count('203.0.113.9') == 0 and 'IP' in js('return document.querySelector("#ping-status").textContent'),
              'library rows show the bulk IP result and the batch status names the measurement kind')
        command('clearUrlTests')
        audit['primaryPreserved'] = True
        check(True, 'all WireGuard diagnostics preserve the primary Core PID, connection age and held TCP stream')
    except BaseException:
        import traceback
        audit['failure'] = traceback.format_exc()
        raise
    finally:
        for token in tokens:
            with contextlib.suppress(Exception): command('cancelSettingsTest', {'requestId': token})
        with contextlib.suppress(Exception): admin(mode='ok', release=True)
        for stream in sockets:
            with contextlib.suppress(OSError): stream.close()
        with contextlib.suppress(Exception): audit['pendingResults'] = json.loads(js('return JSON.stringify(window.__wg81)'))
        with contextlib.suppress(Exception): audit['lastLogs'] = command('getLogs')
        (h['artifacts'] / 'wireguard-diagnostics-audit.json').write_text(json.dumps(audit, indent=2) + '\n')
        with contextlib.suppress(Exception): command('disconnect')
