"""Native diagnostics with loopback SOCKS hops and a private TLS IP service.

The fixture is created by test_native.py; no request may leave loopback.
"""
import contextlib
import json
import os
import pathlib
import re
import socket
import time
import urllib.parse
import urllib.request


def run(h):
    command, click, select, wait_for, js, check, screenshot = (
        h[k] for k in ('command', 'click', 'select', 'wait_for', 'js', 'check', 'screenshot')
    )
    fixture = json.loads(pathlib.Path(os.environ['_THRONIUM_DIAGNOSTICS_FIXTURE']).read_text())
    request, base = h['request'], h['base']
    initial = command('snapshot')
    old_testing = command('settings')['testing']
    geometry = request('GET', base + '/window/rect')
    groups = []

    def admin(**values):
        req = urllib.request.Request(fixture['admin'], data=json.dumps(values).encode() if values else None,
                                     headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=3) as response:
            return json.load(response)

    def settings(**values):
        old = command('settings')['testing']
        return command('saveSettings', {'section': 'testing', 'previous': old, 'values': {**old, **values}})

    def add(group, name, kind, config):
        return command('saveProfile', {'name': name, 'groupId': group, 'kind': kind, 'config': config})['id']

    def open_diagnostics(profile):
        click('.primary-nav button:first-child')
        command('select', {'id': profile})
        select('.group-strip select', 'all')
        selector = '[data-profile-menu="' + profile + '"]'
        wait_for('return !!document.querySelector(' + json.dumps(selector) + ')')
        js('document.querySelector(arguments[0]).scrollIntoView({block:"center"})', selector)
        wait_for('const r=document.querySelector(' + json.dumps(selector) + ').getBoundingClientRect();return r.top>=0 && r.bottom<=innerHeight')
        # Dropdowns deliberately dismiss on scroll. Let the browser deliver the
        # scroll event requested above before opening the menu.
        request('POST',base+'/execute/async',{'script':'const done=arguments[arguments.length-1];requestAnimationFrame(()=>requestAnimationFrame(()=>done(true)));','args':[]})
        click(selector)
        try:
            click('#diagnostics-one')
        except Exception:
            screenshot('diagnostics-menu-failure')
            raise
        wait_for('return !!document.querySelector("#diagnostics-ip")')

    def close():
        click('#main-modal > .modal-head > button')
        wait_for('return !document.querySelector("dialog[open]")')

    def done():
        wait_for('return !document.querySelector("#diagnostics-progress") && !!document.querySelector("#settings-test-result,.settings-test-actions [role=alert]")', 15)

    def alert():
        return js('return document.querySelector(".settings-test-actions [role=alert]")?.textContent || ""')

    def result():
        return js('return document.querySelector("#settings-test-result")?.textContent || ""')

    def begin(name, profile, token):
        js('''window.__diagnosticsNative ??= {}; window.__diagnosticsNative[arguments[2]]={done:false};
const token=arguments[2];window.__TAURI_INTERNALS__.invoke('app_command',
{name:arguments[0],payload:{id:arguments[1],requestId:token}})
.then(value=>window.__diagnosticsNative[token]={done:true,ok:true,value})
.catch(error=>window.__diagnosticsNative[token]={done:true,ok:false,error});''', name, profile, token)

    def finish(token):
        wait_for('return window.__diagnosticsNative?.[' + json.dumps(token) + ']?.done', 15)
        # The shared WebDriver helper treats a top-level `error` as transport
        # failure; keep the app's expected error reply inside a JSON string.
        return json.loads(js('return JSON.stringify(window.__diagnosticsNative[arguments[0]])', token))

    def wait_hops():
        end = time.monotonic() + 5
        while time.monotonic() < end:
            seen = admin()['seen']
            if len(seen) >= 3:
                return seen
            time.sleep(.03)
        raise AssertionError('Diagnostic request did not traverse all three local proxy hops')

    def wait_inactive(timeout=.9):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if admin()['active'] == 0:
                return True
            time.sleep(.025)
        return False

    def correct_order(port):
        seen = admin()['seen']
        return len(seen) >= 3 and [row[0] for row in seen[:3]] == [0, 1, 2] and \
            [row[2] for row in seen[:3]] == [fixture['ports'][1], fixture['ports'][2], port]

    def rejected(name, payload, code):
        try:
            command(name, payload)
        except RuntimeError as error:
            return code in str(error)
        return False

    def connect_tunnel():
        destination = urllib.parse.urlsplit(fixture['download'])
        conn = socket.create_connection(('127.0.0.1', local_port), timeout=3)
        authority = destination.netloc
        conn.sendall(('CONNECT ' + authority + ' HTTP/1.1\r\nHost: ' + authority + '\r\n\r\n').encode())
        headers = b''
        while b'\r\n\r\n' not in headers:
            chunk = conn.recv(4096)
            assert chunk, 'Active proxy closed the CONNECT tunnel before response headers'
            headers += chunk
        assert b' 200 ' in headers.split(b'\r\n', 1)[0], headers
        return conn, destination

    def use_tunnel(conn, destination):
        conn.sendall(('GET ' + destination.path + ' HTTP/1.0\r\nHost: ' + destination.netloc + '\r\n\r\n').encode())
        response = b''
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            response += chunk
        headers, body = response.split(b'\r\n\r\n', 1)
        return b' 200 ' in headers.split(b'\r\n', 1)[0] and body == b'x' * 245760

    try:
        command('disconnect')
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            local_port = listener.getsockname()[1]
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark',
                                'inboundPort': local_port,
                                'ping': {**initial['preferences']['ping'], 'timeoutMs': 2000}})
        settings(speed_test_mode='simple', simple_dl_url=fixture['download'],
                 speed_test_timeout_ms=2000, direct_test_url=fixture['download'])
        source = command('saveGroup', {'name': 'Diagnostics proxy fixtures'})['id']
        groups.append(source)
        target = command('saveGroup', {'name': 'Diagnostic wrapped servers'})['id']
        groups.append(target)
        front = add(source, 'Entry Xray', 'xray-outbound',
                    {'protocol': 'socks', 'settings': {'address': '127.0.0.1', 'port': fixture['ports'][0]}})
        landing = add(source, 'Exit sing-box', 'sing-box-outbound',
                      {'type': 'socks', 'server': '127.0.0.1', 'server_port': fixture['ports'][2]})
        server = add(target, 'Measured server', 'sing-box-outbound',
                     {'type': 'socks', 'server': '127.0.0.1', 'server_port': fixture['ports'][1]})
        command('saveGroup', {'id': target, 'name': 'Diagnostic wrapped servers',
                              'proxyChain': {'front': front, 'landing': landing}})
        # Qt measures a complete client whose listeners the check replaces; only what the
        # disposable core cannot own itself, such as an unowned rule-set file, stays refused.
        full = add(source, 'Complete JSON with external rule-set', 'sing-box-config',
                   {'outbounds': [{'type': 'direct'}],
                    'route': {'rule_set': [{'type':'remote','tag':'unowned','format':'binary','url':'https://unowned.test/file.srs'}]}})
        full_tun = add(source, 'Complete JSON with TUN', 'sing-box-config', {'inbounds':[{'type':'tun'}], 'outbounds': [{'type': 'direct'}]})
        endpoint = add(source, 'VPN endpoint', 'sing-box-outbound', {'type': 'wireguard'})
        pool = add(source, 'Automatic pool', 'auto-selector', {'type': 'auto-selector', 'members': [front, landing], 'pinned_profile': landing})
        extra = add(source, 'External core', 'external-core', {'type':'extracore','socks_address':'127.0.0.1','socks_port':32124,'extra_core_path':'/nonexistent-diagnostics55-core','extra_core_args':'','extra_core_conf':'{}','no_logs':True})
        openvpn = add(source, 'OpenVPN diagnostics', 'sing-box-outbound', {'type':'openvpn-client','server':'127.0.0.1','server_port':1194,'username':'synthetic','password':'synthetic'})
        openconnect = add(source, 'OpenConnect diagnostics', 'sing-box-outbound', {'type':'openconnect','server':'https://127.0.0.1:4443','flavor':'anyconnect','username':'synthetic','password':'synthetic'})
        full_xray = add(source, 'Full Xray with API', 'xray-config', {'api': {'tag':'api','services':[]}, 'outbounds':[{'protocol':'freedom'}]})
        chain = add(source, 'Explicit chain', 'chain', {'type':'chain','hops':[front,landing]})
        wait_for('return document.documentElement.lang==="en"')
        open_diagnostics(server)
        check(js('return document.querySelector("#main-modal .modal-head").textContent.includes("Server diagnostics") && !document.querySelector("#diagnostics-internet") && document.querySelector("#diagnostics-profile").textContent.includes("Measured server")'),
              'server menu opens diagnostics for that server with distinct proxy tests')

        admin(clear=True, ipMode='ok')
        click('#diagnostics-ip'); done()
        check(js('return document.querySelector("#diagnostics-exit-ip")?.textContent==="203.0.113.9" && document.querySelector("#diagnostics-country")?.textContent==="Japan (JP)"'),
              'native IP test displays the validated exit IP and localized country')
        check(correct_order(443), 'IP test traverses Xray entry, selected server and sing-box exit in order')
        check('Measured server' in result(), 'IP result identifies the measured server and completion time')
        screenshot('diagnostics-ip-en')

        admin(ipMode='ipv6')
        click('#diagnostics-ip'); done()
        check(js('return document.querySelector("#diagnostics-exit-ip")?.textContent==="2001:db8::9" && document.querySelector("#diagnostics-country")?.textContent==="Germany (DE)"'),
              'IPv6 exit addresses are shown without IPv4 assumptions')
        admin(ipMode='unknown')
        click('#diagnostics-ip'); done()
        check(js('return document.querySelector("#diagnostics-country")?.textContent==="Unknown"'),
              'missing country is displayed as unknown without guessing from the profile name')
        for mode in ['invalid', 'oversize', 'http-error']:
            admin(ipMode=mode)
            click('#diagnostics-ip'); done()
            check(bool(alert()) and not result(), mode + ' IP response is rejected without displaying the previous success')
        admin(ipMode='ok')
        click('#diagnostics-ip'); done()
        check(not alert() and '203.0.113.9' in result(), 'retry clears the previous diagnostic error after a successful response')

        admin(clear=True, downloadMode='ok')
        measured = command('testSpeed', {'id': server, 'requestId': 'native-speed-bytes'})['result']
        check(measured['downloadBytes'] == 245760 and measured['profileId'] == server and measured['testedAt'] > 0,
              'speed API reports transferred bytes and the saved measured profile')
        check(correct_order(urllib.parse.urlsplit(fixture['download']).port),
              'speed download uses every configured group proxy in order')
        click('#diagnostics-speed'); done()
        check(not alert() and '↓ ' in result() and '0 B/s' not in result(), 'native speed action displays a measured download rate')
        screenshot('diagnostics-speed-en')
        for mode in ['http-error', 'truncated', 'empty']:
            admin(downloadMode=mode)
            click('#diagnostics-speed'); done()
            check(bool(alert()) and not result(), mode + ' speed response is rejected instead of publishing partial success')

        admin(clear=True, downloadMode='slow')
        click('#diagnostics-speed')
        wait_for('return !!document.querySelector("#diagnostics-progress")')
        wait_hops()
        check(js('return document.querySelector("#diagnostics-ip").disabled && document.querySelector("#diagnostics-speed").disabled && !!document.querySelector("#diagnostics-cancel")'),
              'in-flight diagnostics disable duplicate starts and expose cancellation')
        click('#diagnostics-cancel'); done()
        check('cancelled' in alert().lower() and not result(),
              'Stop cancels the current measurement and explains cancellation without publishing bytes')

        admin(clear=True)
        command('cancelSettingsTest', {'requestId': 'native-cancel-before-start'})
        check(rejected('testSpeed', {'id': server, 'requestId': 'native-cancel-before-start'}, 'probe_cancelled')
              and not admin()['seen'],
              'cancellation received before the matching start prevents the measurement from dialing')

        admin(clear=True, downloadMode='slow')
        begin('testSpeed', server, 'native-owned-test')
        wait_hops()
        command('cancelSettingsTest', {'requestId': 'another-view'})
        check(rejected('testIp', {'id': server, 'requestId': 'native-second-test'}, 'probe_busy'),
              'a concurrent diagnostic is rejected while the existing test keeps its ownership')
        owned = finish('native-owned-test')
        check(owned['ok'] and owned['value']['result']['downloadBytes'] == 245760,
              'a foreign cancellation token does not cancel another view’s measurement')

        admin(clear=True, downloadMode='slow')
        begin('testSpeed', server, 'native-external-owner')
        wait_hops(); close()
        owned = finish('native-external-owner')
        check(owned['ok'] and owned['value']['result']['downloadBytes'] == 245760,
              'closing an idle diagnostic view leaves an externally owned measurement running')
        open_diagnostics(server)

        admin(clear=True, downloadMode='slow')
        click('#diagnostics-speed'); wait_hops(); close()
        check(wait_inactive(), 'closing a busy diagnostic view promptly closes its isolated proxy sockets')
        admin(downloadMode='ok')
        retried = None
        for _ in range(30):
            try:
                retried = command('testSpeed', {'id': server, 'requestId': 'native-after-close'})
                break
            except RuntimeError as error:
                if 'probe_busy' not in str(error):
                    raise
                time.sleep(.05)
        check(retried is not None and retried['result']['downloadBytes'] == 245760,
              'closing diagnostics cancels its task and releases the slot for a new measurement')
        open_diagnostics(server)
        check(not result() and not alert(), 'reopening diagnostics does not publish results from a closed view')

        admin(clear=True, downloadMode='slow')
        click('#diagnostics-speed'); wait_hops()
        settings(speed_test_timeout_ms=2500)
        done()
        check('changed' in alert().lower() and not result(),
              'changing saved test settings discards an in-flight result with a readable stale message')
        screenshot('diagnostics-stale-en')
        settings(speed_test_timeout_ms=2000)

        admin(clear=True, downloadMode='slow')
        begin('testSpeed', server, 'native-hop-stale')
        wait_hops()
        saved_landing = command('profile', {'id': landing})
        command('saveProfile', {**saved_landing, 'config': {**saved_landing['config'], 'server_port': 9}})
        changed = finish('native-hop-stale')
        # Restoring after the edit needs the current revision under the S2 contracts.
        command('saveProfile', {**saved_landing, 'expectedRevision': command('profile', {'id': saved_landing['id']})['expectedRevision']})
        # Command errors arrive as structured {code} objects since the S2 contracts.
        stale = changed.get('error'); stale = stale.get('code') if isinstance(stale, dict) else stale
        check(not changed['ok'] and stale == 'probe_stale' and 'value' not in changed,
              'editing a group proxy while measuring discards the old route’s result at the native API')

        command('connect', {'id': server})
        active_before = command('snapshot')
        admin(downloadMode='ok', ipMode='slow')
        tunnel, destination = connect_tunnel()
        try:
            click('#diagnostics-ip'); done()
            check(not alert() and command('snapshot')['running'] == active_before['running'] == server,
                  'IP diagnostics preserve the active connection')
            check(use_tunnel(tunnel, destination), 'a TCP CONNECT tunnel established before diagnostics remains usable afterward')
        finally:
            tunnel.close()
        admin(downloadMode='slow')
        tunnel, destination = connect_tunnel()
        try:
            admin(clear=True)
            click('#diagnostics-speed'); wait_hops(); click('#diagnostics-cancel'); done()
            admin(downloadMode='ok')
            check(command('snapshot')['running'] == server and use_tunnel(tunnel, destination),
                  'cancelling a speed test preserves active proxy traffic and its existing TCP tunnel')
        finally:
            tunnel.close()
        command('disconnect')
        close()

        before_refusals = admin()['seen']
        open_diagnostics(full_tun)
        check(js('return !document.querySelector("#diagnostics-ip").disabled && !document.querySelector("#diagnostics-speed").disabled'),
              'a complete client with its own TUN listener is offered diagnostics, as Qt offers them')
        close()
        for profile, label in [(full, 'complete JSON'), (full_xray, 'full Xray JSON'), (endpoint, 'VPN endpoint'), (extra, 'external core')]:
            open_diagnostics(profile)
            check(js('return document.querySelector("#diagnostics-ip").disabled && document.querySelector("#diagnostics-speed").disabled && document.querySelector(".settings-test-actions").textContent.includes("not supported yet")'),
                  label + ' diagnostics explain the limitation and disable unsupported actions')
            check(rejected('testIp', {'id': profile, 'requestId': 'native-unsupported'}, 'probe_unsupported') and
                  rejected('testSpeed', {'id': profile, 'requestId': 'native-unsupported'}, 'probe_unsupported'),
                  label + ' API refuses unsupported diagnostics')
            close()

        for profile, label in [(openvpn, 'OpenVPN'), (openconnect, 'OpenConnect')]:
            open_diagnostics(profile)
            check(js('return !document.querySelector("#diagnostics-ip").disabled && !document.querySelector("#diagnostics-speed").disabled && !document.querySelector("#diagnostics-unsupported")'),
                  label + ' primary diagnostics are enabled after VPN readiness support')
            cancelled = []
            for name in ['testIp', 'testSpeed']:
                token = 'native-vpn-precancel-' + label.lower() + '-' + name.lower()
                command('cancelSettingsTest', {'requestId': token})
                cancelled.append(rejected(name, {'id': profile, 'requestId': token}, 'probe_cancelled'))
            check(all(cancelled), label + ' precancelled measurements stop before opening the VPN or HTTP')
            close()

        check(admin()['seen'] == before_refusals, 'unsupported IP and speed requests do not dial any diagnostic proxy')
        caps = {p['id']: p['ipSpeedSupported'] for p in command('snapshot')['profiles']}
        check(all(caps[p] for p in [server, front, landing, chain, openvpn, openconnect, pool, full_tun]) and all(not caps[p] for p in [full, full_xray, endpoint, extra]), 'native snapshot exposes the same capability for supported chains, pools, adapted complete clients and all unsupported kinds')
        # A pool is measured through one member and the result names it.
        open_diagnostics(pool)
        check(js('return !document.querySelector("#diagnostics-ip").disabled && !document.querySelector("#diagnostics-speed").disabled && !document.querySelector("#diagnostics-unsupported")'),
              'pool diagnostics are enabled through its measured member')
        admin(clear=True, ipMode='ok')
        click('#diagnostics-ip'); done()
        check('203.0.113.9' in result() and 'Measured member: Exit sing-box' in js('return document.querySelector("#diagnostics-context")?.textContent||""'),
              'pool IP result names the pinned member instead of presenting the exit as the pool\'s (alert: ' + alert() + ')')
        close()
        measured = command('testIp', {'id': pool, 'requestId': 'native-pool-member'})['result']
        check(measured['memberId'] == landing and measured['memberName'] == 'Exit sing-box' and measured['profileId'] == pool and measured['memberOrigin'] == 'pinned',
              'pool API result carries the measured member identity and says the pin chose it')
        direct = {}
        for member, label in [(front, 'entry'), (landing, 'exit')]:
            try:
                direct[label] = command('testIp', {'id': member, 'requestId': 'native-member-' + label})['result'].get('ip')
            except RuntimeError as error:
                direct[label] = str(error)
        # The fixture's entry hop only forwards to the next chain port, so a lone entry member cannot reach the IP service.
        check(direct['exit'] == '203.0.113.9' and 'probe_failed' in direct['entry'], 'members are measured on their own: the exit reaches the service, the entry-only hop fails honestly: ' + json.dumps(direct))
        # Singles and batches share one diagnostic slot.
        admin(clear=True, downloadMode='slow')
        begin('testSpeed', server, 'native-single-slot'); wait_hops()
        check(rejected('startIpTests', {'ids': [server, front]}, 'probe_busy') and rejected('startSpeedTests', {'ids': [server]}, 'probe_busy'),
              'a running single measurement blocks bulk IP and speed batches')
        single = finish('native-single-slot')
        check(single['ok'] and single['value']['result']['downloadBytes'] == 245760, 'the single measurement completes after the refused batches')
        admin(clear=True, downloadMode='slow')
        command('startSpeedTests', {'ids': [server]}); wait_hops()
        check(rejected('testIp', {'id': server, 'requestId': 'native-batch-slot'}, 'probe_busy') and rejected('testSpeed', {'id': front, 'requestId': 'native-batch-slot-2'}, 'probe_busy'),
              'a running batch blocks single IP and speed measurements')
        end = time.monotonic() + 20
        while time.monotonic() < end and any(e['status'] in ('queued', 'testing') for e in (command('snapshot').get('urlTests') or {'entries': []})['entries']):
            time.sleep(.1)
        admin(downloadMode='ok')
        after = command('testIp', {'id': server, 'requestId': 'native-after-batch'})['result']
        check(after['ip'] == '203.0.113.9' and 'memberId' not in after, 'the slot is free again once the batch finishes and plain profiles carry no member')
        open_diagnostics(chain)
        check(js('return !document.querySelector("#diagnostics-ip").disabled && !document.querySelector("#diagnostics-speed").disabled && !document.querySelector("#diagnostics-unsupported")'), 'explicit chain diagnostics remain available')
        close()
        for language in ['ru', 'en']:
            command('preferences', {**command('snapshot')['preferences'], 'language':language})
            wait_for('return document.documentElement.lang===' + json.dumps(language))
            request('POST', base + '/window/rect', {'width':390,'height':800})
            open_diagnostics(extra)
            expected = 'внешние ядра' if language == 'ru' else 'external cores'
            check(expected in js('return document.querySelector("#diagnostics-unsupported").textContent') and js('const b=document.querySelector("#main-modal .modal-body");return b.scrollWidth<=b.clientWidth+1'), language + ' unsupported diagnostics explain external cores in a narrow native window')
            screenshot('diagnostics-unsupported-' + language + '-390')
            close()
        request('POST', base + '/window/rect', geometry)
        command('select', {'id': server})
        admin(ipMode='ok', downloadMode='ok', clear=True)
        click('.primary-nav button:last-child')
        click('[data-settings-section=testing]')
        # Backend selection reaches this view on the next snapshot poll.
        # Starting before it arrives would correctly cancel on selection change.
        wait_for('return document.querySelector("#diagnostics-profile")?.textContent.includes("Measured server") && !document.querySelector("#diagnostics-ip").disabled')
        click('#diagnostics-internet'); done()
        check('Internet available' in result() and not admin()['seen'],
              'settings internet check uses its configured direct URL without traversing proxy hops')
        click('#diagnostics-ip'); done()
        check('203.0.113.9' in result() and correct_order(443),
              'settings IP action measures the selected server through the same group chain')
        admin(clear=True, ipMode='slow')
        click('#diagnostics-ip'); wait_hops()
        command('select', {'id': endpoint})
        wait_for('return document.querySelector("#diagnostics-ip").disabled && !document.querySelector("#diagnostics-progress")')
        check(wait_inactive() and not result() and not alert(),
              'changing the selected server cancels settings diagnostics and clears the old server result')
        command('select', {'id': server})
        admin(ipMode='ok')
        click('#diagnostics-ip'); done()
        for language, theme in [('en', 'light'), ('ru', 'dark')]:
            command('preferences', {**command('snapshot')['preferences'], 'language': language, 'theme': theme})
            wait_for('return document.documentElement.lang===' + json.dumps(language))
            request('POST', base + '/window/rect', {'width': 390, 'height': 800})
            check(js('return document.documentElement.scrollWidth<=innerWidth+1'),
                  'diagnostics settings fit a 390px window in ' + language)
            js('document.querySelector(".settings-test-actions").scrollIntoView({block:"start"})')
            screenshot('diagnostics-settings-' + language + '-390')
            open_diagnostics(server)
            click('#diagnostics-ip'); done()
            expected = 'Япония (JP)' if language == 'ru' else 'Japan (JP)'
            check(js('return document.querySelector("#diagnostics-country")?.textContent') == expected and
                  js('const d=document.querySelector("#main-modal"),b=d.querySelector(".modal-body");return b.scrollWidth<=b.clientWidth+1&&d.getBoundingClientRect().bottom<=innerHeight+1'),
                  'localized IP result and modal fit a 390px window in ' + language)
            screenshot('diagnostics-modal-' + language + '-390')
            if language == 'ru':
                admin(downloadMode='http-error')
                click('#diagnostics-speed'); done()
                check('Не удалось' in alert() and not result(),
                      'Russian diagnostic errors are readable and clear the previous IP result')
                screenshot('diagnostics-error-ru-390')
            close()
            click('.primary-nav button:last-child')
            click('[data-settings-section=testing]')
        # Every finished measurement lands in the bounded journal with codes only.
        journal = command('getMeasurementJournal')
        rows = journal['entries']
        by_profile = lambda pid, **f: [r for r in rows if r['profileId'] == pid and all(r.get(k) == v for k, v in f.items())]
        check(journal['limit'] == 500 and journal['retentionDays'] == 7 and journal['total'] == len(rows) and rows == sorted(rows, key=lambda r: -r['id']),
              'the journal reports its bounds and lists newest entries first')
        check(by_profile(pool, kind='ip', source='single', status='ok', memberId=landing, memberName='Exit sing-box'),
              'a pool measurement is journaled with the member it was measured through')
        check(by_profile(server, kind='speed', source='batch', status='ok') and by_profile('direct', kind='internet', status='ok', transport='direct'),
              'batch rows and the direct internet check are journaled with their own source and transport')
        errors = [r for r in rows if r['status'] == 'error']
        check(errors and all(re.fullmatch(r'[a-z_-]+', r.get('error', '')) for r in errors) and any(r['status'] == 'cancelled' for r in rows),
              'failed and cancelled runs are journaled as codes without free text: ' + json.dumps([r.get('error') for r in errors]))
        check(not any('203.0.113' in json.dumps(r) for r in rows if r['status'] != 'ok'), 'error rows carry no measured values')
        request('POST', base + '/window/rect', geometry)
        command('preferences', {**command('snapshot')['preferences'], 'language': 'en', 'theme': 'light'})
        wait_for('return document.documentElement.lang==="en"')
        click('.primary-nav button:nth-child(3)')
        wait_for('return document.querySelectorAll("[data-journal-entry]").length>0')
        js('document.querySelector("#measurement-journal").scrollIntoView({block:"start"})')
        shown = js('return [...document.querySelectorAll("[data-journal-entry]")].map(r=>[...r.cells].map(c=>c.textContent))')
        headers = js('return [...document.querySelectorAll("#measurement-journal-table thead th")].map(h=>h.textContent)')
        internet = [r for r in shown if r[1] == 'Internet without proxy']
        check(len(shown) == len(rows) and any(r[2].startswith('Automatic pool · Exit sing-box') for r in shown) and any(r[5] == 'Bulk test' for r in shown) and
              internet and all(r[2] == 'without proxy' for r in internet) and not any('probe_' in c for r in shown for c in r) and
              headers == ['Time', 'Check', 'Server', 'Status', 'Result', 'Source'],
              'the journal panel lists every entry under labelled columns with labels instead of codes: ' + json.dumps([headers] + shown[:2]))
        screenshot('measurement-journal')
        revision = command('snapshot')['libraryRevision']
        command('testInternet', {'requestId': 'native-journal-visible-r0'})
        wait_for('return document.querySelectorAll("[data-journal-entry]").length===' + str(len(rows) + 1), 6)
        check(command('snapshot')['libraryRevision'] == revision, 'the open journal refreshes after a new measurement without a library revision or page remount')
        command('preferences', {**command('snapshot')['preferences'], 'language': 'ru', 'theme': 'dark'})
        wait_for('return document.documentElement.lang==="ru"')
        request('POST', base + '/window/rect', {'width': 390, 'height': 800})
        wait_for('return document.querySelectorAll("[data-journal-entry]").length>0 && document.querySelector("#measurement-journal-table thead th").textContent==="Время"')
        check(js('return document.documentElement.scrollWidth<=innerWidth+1') and js('const w=document.querySelector(".measurement-journal-entries");return w.scrollWidth>w.clientWidth && w.getBoundingClientRect().right<=innerWidth+1') and
              any('Массовый тест' in t for t in js('return [...document.querySelectorAll("[data-journal-entry]")].map(r=>r.textContent)')),
              'the Russian journal fits a 390px window and scrolls its table inside the panel')
        js('document.querySelector("#measurement-journal").scrollIntoView({block:"start"})')
        screenshot('measurement-journal-ru-390')
        request('POST', base + '/window/rect', geometry)
        command('preferences', {**command('snapshot')['preferences'], 'language': 'en', 'theme': 'light'})
        wait_for('return document.documentElement.lang==="en"')
        click('#measurement-journal-clear')
        wait_for('return !!document.querySelector("#measurement-journal-keep")')
        click('#measurement-journal-keep')
        check(js('return !document.querySelector("#measurement-journal-keep") && document.querySelectorAll("[data-journal-entry]").length>0'),
              'declining the confirmation keeps the journal')
        root = pathlib.Path(os.environ['XDG_DATA_HOME']).resolve()
        assert root.name == 'data' and root.parent.name.startswith('thronium-native-test-')
        logs = list(root.rglob('measurement-journal-v1.json'))
        assert len(logs) == 1
        log = logs[0]
        saved = log.read_bytes()
        before_clear = command('getMeasurementJournal')
        log.unlink(); log.mkdir()
        try:
            click('#measurement-journal-clear'); click('#measurement-journal-clear')
            wait_for('return !!document.querySelector("#measurement-journal-error")')
            check(command('getMeasurementJournal') == before_clear and js('return document.querySelectorAll("[data-journal-entry]").length') == before_clear['total'],
                  'a failed journal write preserves the engine and visible rows')
        finally:
            log.rmdir(); log.write_bytes(saved); log.chmod(0o600)
        click('#measurement-journal-clear')
        wait_for('return !!document.querySelector("#measurement-journal-empty")')
        check(command('getMeasurementJournal')['total'] == 0, 'clearing the journal after confirmation empties it in the engine')
        command('testIp', {'id': server, 'requestId': 'native-journal-after-clear'})
        wait_for('return document.querySelectorAll("[data-journal-entry]").length===1', 6)
        check(command('getMeasurementJournal')['entries'][0]['profileId'] == server, 'the journal records and refreshes the open panel again after it was cleared')
        click('.primary-nav button:last-child')
        # Opt-in periodic checks of favourite servers: nothing runs
        # until enabled, the first run waits one interval, only favourites are
        # measured, rows are journaled as periodic and disabling stops them.
        command('favorite', {'id': server})
        check(next(p for p in command('snapshot')['profiles'] if p['id'] == server)['favorite'], 'the measured server is marked favourite for the periodic schedule')
        settings(periodic_tests_enabled=True, periodic_tests_interval_min=1, periodic_tests_kind='ip')
        # The settings page keeps its draft; reopen it so the saved values are shown.
        click('.primary-nav button:first-child'); click('.primary-nav button:last-child')
        click('[data-settings-section=testing]')
        wait_for('return !!document.querySelector("#setting-periodic_tests_enabled")')
        shown = js('return {checked: document.querySelector("#setting-periodic_tests_enabled").checked, kind: document.querySelector("#setting-periodic_tests_kind").value, options: [...document.querySelectorAll("#setting-periodic_tests_kind option")].map(o=>o.textContent), interval: document.querySelector("#setting-periodic_tests_interval_min").value}')
        # Connection speed is the third periodic kind.
        check(shown == {'checked': True, 'kind': 'ip', 'options': ['Latency', 'Exit IP and country', 'Connection speed'], 'interval': '1'},
              'the testing section shows the periodic switch, interval and labelled kinds: ' + json.dumps(shown))
        enabled_at = time.monotonic()
        periodic = None
        while time.monotonic() - enabled_at < 110:
            batch = command('snapshot').get('urlTests')
            if batch and batch.get('source') == 'periodic':
                periodic = batch
                break
            time.sleep(1)
        check(periodic is not None and periodic['kind'] == 'ip' and [e['profileId'] for e in periodic['entries']] == [server] and 45 <= time.monotonic() - enabled_at <= 110,
              'a periodic exit-IP batch of the favourite server alone starts one interval after enabling: ' + json.dumps({'after': round(time.monotonic() - enabled_at), 'batch': periodic and [e['profileId'] for e in periodic['entries']]}))
        click('.primary-nav button:first-child')
        wait_for('return !!document.querySelector("#ping-status")')
        # The window shows the batch from its next one-second snapshot poll.
        wait_for('return document.querySelector("#ping-status").textContent.includes("Periodic check")', 5)
        check('Periodic check' in js('return document.querySelector("#ping-status").textContent'), 'the library batch header names the periodic run')
        end = time.monotonic() + 30
        while time.monotonic() < end and any(e['status'] in ('queued', 'testing') for e in command('snapshot')['urlTests']['entries']):
            time.sleep(.2)
        rows = command('getMeasurementJournal')['entries']
        check(rows and rows[0]['source'] == 'periodic' and rows[0]['profileId'] == server and rows[0]['kind'] == 'ip' and rows[0]['status'] == 'ok' and rows[0]['ip'] == '203.0.113.9',
              'the finished periodic row is journaled with its own source: ' + json.dumps(rows[0] if rows else None))
        settings(periodic_tests_enabled=False)
        command('favorite', {'id': server})
        check(not next(p for p in command('snapshot')['profiles'] if p['id'] == server)['favorite'], 'the favourite mark is released again')
        click('.primary-nav button:last-child')
        click('[data-settings-section=testing]')
    finally:
        with contextlib.suppress(Exception):
            command('cancelSettingsTest')
        with contextlib.suppress(Exception):
            command('disconnect')
        for group in reversed(groups):
            with contextlib.suppress(Exception):
                command('deleteGroup', {'id': group, 'deleteProfiles': True})
        with contextlib.suppress(Exception):
            command('saveSettings', {'section': 'testing', 'previous': command('settings')['testing'], 'values': old_testing})
        with contextlib.suppress(Exception):
            command('preferences', initial['preferences'])
        with contextlib.suppress(Exception):
            request('POST', base + '/window/rect', geometry)
