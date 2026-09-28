"""Native IP/speed measurements through a real userspace OpenVPN peer."""
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
    fixture = json.loads(Path(os.environ['_THRONIUM_VPN_DIAGNOSTICS_FIXTURE']).read_text())
    initial = command('snapshot'); assert not initial['profiles']
    sockets, tokens = [], []
    audit = {'results': [], 'openconnectBoundary': fixture['openconnectBoundary']}
    def admin(**values):
        request = urllib.request.Request(fixture['admin'], data=json.dumps(values).encode() if values else None,
                                         headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=3) as response: return json.load(response)
    def poll(predicate, timeout=8):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if predicate(): return
            time.sleep(.05)
        raise AssertionError('VPN diagnostics fixture did not reach expected state')
    def setting(mode='simple'):
        old = command('settings')['testing']
        command('saveSettings', {'section': 'testing', 'previous': old, 'values': {
            **old, 'speed_test_mode': mode, 'speed_test_timeout_ms': 1000, 'simple_dl_url': fixture['simpleUrl']}})
    def add(name, config):
        return command('saveProfile', {'name': name, 'kind': 'sing-box-outbound', 'groupId': 'personal', 'config': config})['id']
    def begin(kind, identifier):
        token = 'vpn-diagnostics72-' + str(len(tokens) + 1); tokens.append(token)
        js('''const token=arguments[2];window.__vpn72??={};window.__vpn72[token]={done:false};
            window.__TAURI_INTERNALS__.invoke('app_command',{name:arguments[0],payload:{id:arguments[1],requestId:token}})
            .then(value=>window.__vpn72[token]={done:true,ok:true,value})
            .catch(error=>window.__vpn72[token]={done:true,ok:false,error});''', kind, identifier, token)
        return token
    def finish(token, release=False):
        wait_for('return window.__vpn72?.[' + json.dumps(token) + ']?.done', 35)
        if release: admin(mode='ok', release=True)
        row = json.loads(js('return JSON.stringify(window.__vpn72[arguments[0]])', token))
        poll(lambda: admin()['active'] == 0)
        audit['results'].append({'result': row, 'fixture': admin()})
        return row
    def phase_started(token, phase):
        poll(lambda: any(r['phase'] == phase for r in admin()['requests']) or js('return window.__vpn72[arguments[0]].done', token), 15)
        if not any(r['phase'] == phase for r in admin()['requests']):
            row = finish(token)
            raise AssertionError('VPN measurement ended before phase ' + phase + ': ' + json.dumps(row))
    def failed(row, code=None):
        # Command errors arrive as structured {code} objects since the S2 contracts.
        error = row.get('error')
        actual = error.get('code') if isinstance(error, dict) else error
        return not row['ok'] and 'value' not in row and (code is None or actual == code)
    try:
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0)); port = reservation.getsockname()[1]
        preferences = {**initial['preferences'], 'language': 'en', 'connectionMode': 'local', 'inboundPort': port}
        preferences['ping'] = {**preferences['ping'], 'timeoutMs': 1500}
        command('preferences', preferences)
        direct = add('Owned primary direct', {'type': 'direct'})
        good = add('OpenVPN diagnostics72', fixture['openvpn'])
        rejected = add('OpenVPN rejected72', fixture['openvpnRejected'])
        form = add('OpenConnect form72', fixture['openconnectForm'])
        oc_rejected = add('OpenConnect rejected72', fixture['openconnectRejected'])
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
            client.sendall(b'preserved72'); assert upstream.recv(11) == b'preserved72'
        setting()
        for kind in ('testIp', 'testSpeed'):
            admin(mode='ok', clear=True); row = finish(begin(kind, direct))
            check(failed(row) and not admin()['requests'], kind + ' cannot reach the owned service without a VPN route')
            preserved()
        admin(mode='ok', clear=True); row = finish(begin('testIp', good))
        check(row['ok'] and row['value']['result']['ip'] == '203.0.113.9' and row['value']['result']['countryCode'] == 'JP',
              'OpenVPN waits for the real tunnel and measures the owned TLS exit IP/country')
        check(len(admin()['requests']) == 1 and admin()['requests'][0]['phase'] == 'ip',
              'VPN IP measurement reaches the isolated service exactly once')
        cache = Path(command('storageLocation')['directory']) / 'exit-countries-v1.json'
        check(json.loads(cache.read_text())['entries'][good]['countryCode'] == 'JP', 'VPN country is persisted only after a successful measurement')
        preserved()
        for mode in ('simple', 'download', 'upload', 'full'):
            setting(mode); admin(mode='ok', clear=True); row = finish(begin('testSpeed', good)); state = admin()
            check(row['ok'], 'OpenVPN completes real ' + mode + ' speed measurement')
            result = row['value']['result']
            check((result['downloadBytes'] > 0) == (mode != 'upload') and (result['uploadBytes'] > 0) == (mode in ('full', 'upload'))
                  and (state['downloadBytes'] > 0) == (mode != 'upload') and (state['uploadBytes'] > 0) == (mode in ('full', 'upload')),
                  'OpenVPN ' + mode + ' credits actual bytes in the requested directions')
            preserved()
        for identifier, name in ((rejected, 'OpenVPN rejected'), (form, 'OpenConnect continuation'), (oc_rejected, 'OpenConnect rejected')):
            for kind in ('testIp', 'testSpeed'):
                admin(mode='ok', clear=True); row = finish(begin(kind, identifier))
                check(failed(row, 'probe_vpn_auth_required') and not admin()['requests'], name + ' ' + kind + ' reports authentication and never claims a measurement')
                preserved()
        for kind, mode, failure in [('testIp', 'simple', 'ip-http'), ('testIp', 'simple', 'ip-invalid'),
                                    ('testSpeed', 'download', 'download-http'), ('testSpeed', 'upload', 'upload-http'),
                                    ('testSpeed', 'download', 'download-empty'), ('testSpeed', 'download', 'download-truncated')]:
            setting(mode); admin(mode=failure, clear=True); row = finish(begin(kind, good))
            check(failed(row, 'probe_vpn_diagnostic_failed'), 'connected VPN with ' + failure + ' reports a failed measurement')
            preserved()
        for kind, mode, phase in [('testIp', 'simple', 'ip'), ('testSpeed', 'download', 'download'), ('testSpeed', 'upload', 'upload')]:
            setting(mode); admin(mode='hold-' + phase, clear=True); token = begin(kind, good)
            phase_started(token, phase)
            started = time.monotonic(); command('cancelSettingsTest', {'requestId': token}); row = finish(token, release=True)
            check(failed(row, 'probe_cancelled') and time.monotonic() - started < 5, 'VPN cancellation during ' + phase + ' rejects late results promptly')
            preserved()
        # An owned UDP socket silently receives handshakes, so readiness cannot finish.
        silent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); silent.bind(('127.0.0.1', 0)); sockets.append(silent)
        pending_config = copy.deepcopy(fixture['openvpn']); pending_config['server_port'] = silent.getsockname()[1]
        pending = add('OpenVPN pending72', pending_config)
        for kind in ('testIp', 'testSpeed'):
            silent.setblocking(False)
            with contextlib.suppress(BlockingIOError):
                while True: silent.recvfrom(65536)
            admin(mode='ok', clear=True); token = begin(kind, pending)
            silent.settimeout(4); silent.recvfrom(65536)
            command('cancelSettingsTest', {'requestId': token}); row = finish(token)
            check(failed(row, 'probe_cancelled') and not admin()['requests'], kind + ' cancellation during VPN readiness never starts HTTP')
            preserved()
        for field in ('password', 'policy'):
            admin(mode='hold-ip', clear=True); token = begin('testIp', good)
            phase_started(token, 'ip')
            original = command('profile', {'id': good}); changed = copy.deepcopy(original)
            if field == 'password': changed['config']['password'] += '-changed'
            else: changed['vpnPolicy'] = {'onlyAdvertisedRoutes': False, 'useTunnelDns': False, 'blockOutsideDns': False}
            command('saveProfile', changed); admin(mode='ok', release=True); row = finish(token)
            check(failed(row, 'probe_stale'), 'VPN ' + field + ' edit rejects a pending measurement')
            # Restoring after the edit needs the current revision under the S2 contracts.
            original['vpnPolicy'] = original.get('vpnPolicy')
            command('saveProfile', {**original, 'expectedRevision': command('profile', {'id': good})['expectedRevision']}); preserved()
        for change in ({'system': True}, {'name': 'owned-vpn72'}, {'detour': 'other'}):
            config = {**fixture['openvpn'], **change}; identifier = add('Unsupported VPN context72', config)
            profile = next(p for p in command('snapshot')['profiles'] if p['id'] == identifier)
            check(not profile['ipSpeedSupported'], 'unsupported VPN context disables IP/speed capability: ' + next(iter(change)))
            row = finish(begin('testIp', identifier)); check(failed(row, 'probe_unsupported'), 'unsupported context refuses execution before Core startup')
            preserved()
        setting('simple'); admin(mode='ok', clear=True)
        for language, width in [('en', 1280), ('ru', 390)]:
            command('preferences', {**command('snapshot')['preferences'], 'language': language}); command('select', {'id': good})
            h['request']('POST', h['base'] + '/window/rect', {'width': width, 'height': 900})
            wait_for('return document.documentElement.lang===' + json.dumps(language) + ' && innerWidth===' + str(width))
            h['click']('.primary-nav button:last-child'); h['click']('[data-settings-section=testing]')
            wait_for('return document.querySelector("#diagnostics-profile")?.textContent.includes("OpenVPN diagnostics72") && !document.querySelector("#diagnostics-ip").disabled')
            js('document.querySelector("#diagnostics-ip").scrollIntoView({block:"center",behavior:"instant"})')
            h['click']('#diagnostics-ip'); wait_for('return document.querySelector("#diagnostics-exit-ip")?.textContent==="203.0.113.9"', 25)
            check('JP' in js('return document.querySelector("#diagnostics-country").textContent'), 'native VPN IP button displays the measured country in ' + language)
            js('document.querySelector("#settings-test-result").scrollIntoView({block:"center",behavior:"instant"})')
            check(js('return document.documentElement.scrollWidth<=innerWidth+1'), 'VPN diagnostics fit ' + language + ' ' + str(width) + 'px')
            h['screenshot']('vpn-ip-' + language + '-' + str(width)); preserved()
            admin(mode='ip-http', clear=True); js('document.querySelector("#diagnostics-ip").scrollIntoView({block:"center",behavior:"instant"})'); h['click']('#diagnostics-ip')
            wait_for('return !!document.querySelector(".settings-test-actions .desktop-inline-error")', 25)
            message = js('return document.querySelector(".settings-test-actions .desktop-inline-error").textContent')
            check(('VPN подключён' if language == 'ru' else 'VPN is connected') in message, 'native VPN measurement failure is explained in ' + language)
            h['screenshot']('vpn-failure-' + language + '-' + str(width)); admin(mode='ok'); preserved()
        audit['primaryPreserved'] = True
        check(True, 'all VPN diagnostics preserve the primary Core PID, connection age and held TCP stream')
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
        with contextlib.suppress(Exception): audit['pendingResults'] = json.loads(js('return JSON.stringify(window.__vpn72)'))
        with contextlib.suppress(Exception): audit['lastLogs'] = command('getLogs')
        (h['artifacts'] / 'vpn-diagnostics-audit.json').write_text(json.dumps(audit, indent=2) + '\n')
        with contextlib.suppress(Exception): command('disconnect')
