"""Real URL probes, isolated cores, cancellation and stale-result protection."""
import collections
import http.server
import json
import socket
import threading
import time


def run(h):
    command, click, fill, select, wait_for, js, check, screenshot = (h[k] for k in ('command', 'click', 'fill', 'select', 'wait_for', 'js', 'check', 'screenshot'))
    request, base = h['request'], h['base']
    calls = collections.Counter()
    started, release = threading.Event(), threading.Event()

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_GET(self):
            calls[self.path] += 1
            if self.path == '/slow':
                started.set()
                release.wait(15)
            else:
                time.sleep(.035)
            self.send_response(503 if self.path == '/status' else 204)
            self.send_header('Content-Length', '0')
            self.end_headers()

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = f'http://127.0.0.1:{server.server_port}'
    initial = command('snapshot')
    ids, sockets = [], []

    def add(name, kind, config):
        pid = command('saveProfile', {'name': 'URL fixture ' + name, 'groupId': 'personal', 'kind': kind, 'config': config})['id']
        ids.append(pid)
        return pid

    def batch(): return command('snapshot')['urlTests']
    def start(chosen, path='/ok', timeout=1000):
        return command('startUrlTests', {'ids': chosen, 'url': origin + path, 'timeoutMs': timeout})['id']
    def done(timeout=15):
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            b = batch()
            if b and all(e['status'] not in ('queued', 'testing') for e in b['entries']): return b
            time.sleep(.1)
        raise AssertionError('URL tests did not complete')
    def close():
        click('.modal-head .icon-button')
        wait_for('return !document.querySelector("dialog")')

    try:
        with socket.socket() as available:
            available.bind(('127.0.0.1', 0)); port = available.getsockname()[1]
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark', 'inboundPort': port})
        a = add('sing-box', 'sing-box-outbound', {'type': 'direct'})
        b = add('Xray', 'xray-outbound', {'protocol': 'freedom', 'settings': {}})
        c = add('unreachable', 'sing-box-outbound', {'type': 'socks', 'server': '127.0.0.1', 'server_port': port + 1, 'password': 'probe-private-credential'})
        # Reserve then close a port to avoid assuming any particular local service is absent.
        with socket.socket() as unused:
            unused.bind(('127.0.0.1', 0)); unreachable_port = unused.getsockname()[1]
        cp = command('profile', {'id': c}); cp['config']['server_port'] = unreachable_port; command('saveProfile', cp)
        d = add('full JSON', 'sing-box-config', {'inbounds': [{'type': 'tun'}], 'outbounds': [{'type': 'direct'}]})
        command('connect', {'id': a})
        before = command('snapshot')
        listener = socket.socket(); sockets.append(listener); listener.settimeout(3)
        listener.bind(('127.0.0.1', 0)); listener.listen()
        client = socket.create_connection(('127.0.0.1', port), timeout=3); sockets.append(client)
        addr = f'127.0.0.1:{listener.getsockname()[1]}'
        client.sendall(f'CONNECT {addr} HTTP/1.1\r\nHost: {addr}\r\n\r\n'.encode())
        upstream, _ = listener.accept(); sockets.append(upstream); upstream.settimeout(3)
        assert b'200' in client.recv(1024)
        wait_for('return document.documentElement.lang==="en"')
        click('.primary-nav button:nth-child(5)'); click('[data-settings-section=testing]')
        wait_for('return !!document.querySelector("#settings-form")')
        check(js('return document.querySelector(".settings-category h2").textContent==="Tests" && document.querySelector(".feature-panel-head p").textContent.includes("HTTP(S)") && document.querySelector("[data-setting=ping_method]").options.length===4'), 'Ping settings expose Auto, HTTP(S), TCP and ICMP in the existing category')
        check(js('return document.querySelector("#setting-ping_method").value==="auto" && document.querySelector("#setting-ping_method").selectedOptions[0].textContent==="Auto · HTTP(S) → TCP → ICMP"'), 'Auto is selected by default for a new native library')
        select('#setting-ping_method', 'http')
        fill('#probe-url', 'ftp://example.test/check'); click('#settings-save')
        wait_for('return !!document.querySelector("#settings-form [role=alert]")')
        check(command('snapshot')['preferences']['ping'] == initial['preferences']['ping'], 'invalid Ping URL reports an inline error and leaves saved settings intact')
        fill('#probe-url', origin + '/ok'); fill('#probe-timeout', '99')
        check(not js('return document.querySelector("#probe-timeout").checkValidity()'), 'Ping timeout field rejects values outside the supported range')
        fill('#probe-timeout', '1000')
        time.sleep(1.1)
        check(js('return document.querySelector("#probe-url").value') == origin + '/ok', 'background snapshot polling preserves unsaved Ping settings')
        click('#settings-save')
        wait_for('return !!document.querySelector("#settings-form [role=status]")')
        check(command('snapshot')['preferences']['ping'] == {'method': 'http', 'url': origin + '/ok', 'timeoutMs': 1000}, 'Ping settings save the URL and timeout in the native library')
        screenshot('ping-settings-dark-en')
        request('POST', base + '/refresh', {})
        wait_for('return !!document.querySelector("#open-probes")')
        check(command('snapshot')['preferences']['ping']['url'] == origin + '/ok', 'saved Ping defaults survive webview reload')
        fill('#client-search', 'URL fixture')
        wait_for('return document.querySelectorAll(".connection-row").length===4')
        click('#open-probes')
        wait_for('return !!document.querySelector("#ping-status")')
        check(not js('return !!document.querySelector("dialog")'), 'toolbar Ping starts immediately without opening a dialog')
        result = done()
        check(result['url'] == origin + '/ok' and result['timeoutMs'] == 1000, 'one-click Ping uses saved native defaults')
        check([e['profileId'] for e in result['entries']] == ids, 'native URL queue preserves order and completes every selected profile')
        check([e['status'] for e in result['entries']] == ['ok', 'ok', 'error', 'ok'], 'real sing-box, Xray and complete-client probes succeed while the unreachable server reports its own failure')
        check(all(e['latencyMs'] >= 30 for e in result['entries'] if e['status'] == 'ok'), 'displayed latency comes from the delayed HTTP origin through the real cores')
        check(calls['/ok'] == 6, 'every successful URL probe performs a warmup and a measured request')
        snap = command('snapshot')
        check(snap['running'] == a and snap['since'] == before['since'], 'URL tests keep the active core and connection start time')
        client.sendall(b'probe-preserved'); check(upstream.recv(15) == b'probe-preserved', 'an already open tunnel still transfers data after isolated URL probes')
        check('probe-private-credential' not in json.dumps(snap), 'probe snapshots never expose profile credentials or raw core errors')
        wait_for('return document.querySelectorAll("[data-probe-status=ok]").length===3')
        screenshot('url-probes-dark-en')
        wait_for('return Array.from(document.querySelectorAll("[data-profile-latency]")).filter(e=>e.textContent.includes("ms")).length===3')
        check(True, 'library rows show actual cached latency in milliseconds')
        command('favorite', {'id': b})
        check(next(p for p in command('snapshot')['profiles'] if p['id'] == b)['measurement']['status'] == 'ok', 'changing favorites keeps the measurement of an unchanged configuration')

        start([a], '/status'); result = done()
        check(result['entries'][0]['status'] == 'ok', 'an HTTP error status counts only as reachability, matching the documented core contract')
        start([a], '/slow', 100); result = done()
        check(result['entries'][0]['error'] == 'probe_timeout' and result['entries'][0]['latencyMs'] is None, 'timeout reports failure without inventing a latency value')
        release.set(); time.sleep(.1); release.clear(); started.clear()
        start([a, b], '/slow', 5000)
        assert started.wait(5)
        wait_for('return !!document.querySelector("#probe-cancel")')
        check(js('return [...document.querySelectorAll("[data-group-probe]")].every(e=>e.disabled)'), 'group Ping buttons prevent duplicate runs while the queue is active')
        check(js('return !!document.querySelector("[data-group-probe-status]") && !document.querySelector("dialog")'), 'group progress appears inline while the test runs')
        screenshot('ping-progress-dark-en')
        fill('#client-search', 'no matching ping servers')
        check(js('return !document.querySelector("#open-probes").disabled && document.querySelector("#open-probes").getAttribute("aria-label")=="Stop testing"'), 'toolbar still offers Stop when filters hide every tested profile')
        click('#probe-cancel')
        result = done()
        check(all(e['status'] == 'cancelled' for e in result['entries']), 'cancel stops the in-flight probe and the rest of its native queue')
        release.set(); time.sleep(.15)
        check(all(e['status'] == 'cancelled' for e in batch()['entries']), 'late HTTP responses cannot overwrite cancelled results')

        release.clear(); started.clear(); start([b], '/slow', 5000); assert started.wait(5)
        request('POST', base + '/refresh', {})
        wait_for('return !!document.querySelector("#open-probes")')
        check(batch()['entries'][0]['status'] == 'testing', 'native URL testing continues through a webview reload')
        release.set(); result = done()
        check(result['entries'][0]['status'] == 'ok', 'a probe started before reload publishes its result to the restored window')

        release.clear(); started.clear(); start([b], '/slow', 5000); assert started.wait(5)
        bp = command('profile', {'id': b}); bp['config']['settings']['domainStrategy'] = 'UseIPv4'; command('saveProfile', bp)
        release.set(); result = done()
        check(result['entries'][0]['status'] == 'stale' and next(p for p in command('snapshot')['profiles'] if p['id'] == b)['measurement'] is None, 'editing a profile discards the result of its older configuration')
        # Wait for the in-flight native request to finish even if the snapshot already marks it stale.
        command('cancelUrlTests')
        fill('#client-search', 'URL fixture Xray'); wait_for('return document.querySelectorAll(".connection-row").length===1')
        previous = batch()['id']
        wait_for('return !document.querySelector("#open-probes").disabled')
        click('.row-more'); click('#probe-one')
        wait_for('return !document.querySelector("dialog") && document.querySelector("#ping-status").dataset.pingBatch !== ' + json.dumps(previous))
        result = done()
        check(result['id'] != previous and [e['profileId'] for e in result['entries']] == [b] and result['entries'][0]['status'] == 'ok', 'profile context menu closes and immediately tests only that profile using saved defaults')
        command('preferences', {**command('snapshot')['preferences'], 'language': 'ru', 'theme': 'light'})
        wait_for('return document.documentElement.lang==="ru"')
        click('#ping-open-settings')
        wait_for('return document.activeElement.id==="setting-ping_method"')
        check(js('return document.querySelector(".settings-category h2").textContent==="Проверки"'), 'library settings link navigates to the Ping section, focuses the method selector and uses Russian labels')
        request('POST', base + '/window/rect', {'width': 390, 'height': 844})
        js('document.querySelector("#settings-form").scrollIntoView({block:"center"})')
        check(js('return document.querySelector("#settings-form").scrollWidth<=document.querySelector("#settings-form").clientWidth && document.documentElement.scrollWidth<=innerWidth'), 'Ping settings fit a narrow native window')
        screenshot('ping-settings-narrow-ru')
        click('.primary-nav button:first-child')
        wait_for('return !!document.querySelector("#ping-status")')
        js('document.querySelector("#ping-status").scrollIntoView({block:"center"})')
        check(js('return document.querySelector("#ping-status").scrollWidth<=document.querySelector("#ping-status").clientWidth && !document.querySelector("dialog")'), 'inline Ping results and actions wrap within a narrow library')
        screenshot('url-probes-narrow-ru')
        click('#probe-clear')
        wait_for('return !document.querySelector("#ping-status")')
        check(command('snapshot')['urlTests'] is None and all(p.get('measurement') is None for p in command('snapshot')['profiles']), 'clearing URL results removes both the batch and library latency cache')
        request('POST', base + '/window/rect', {'width': 1280, 'height': 860})
        tcp_id = add('TCP endpoint', 'sing-box-outbound', {'type':'socks', 'server':'127.0.0.1', 'server_port':server.server_port})
        wg_id = add('Amnezia endpoint', 'sing-box-outbound', {'type':'wireguard', 'address':['10.0.0.2/32'], 'private_key':'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', 'peers':[{'address':'127.0.0.1','port':51820,'public_key':'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=','allowed_ips':['0.0.0.0/0']}], 'amnezia_wg':{}})
        click('.primary-nav button:nth-child(5)'); click('[data-settings-section=testing]')
        select('#setting-ping_method', 'tcp')
        wait_for('return !document.querySelector("#probe-url")')
        check(js('return document.querySelector("#probe-timeout") && document.querySelector("[data-setting=test_concurrent]")'), 'TCP hides the HTTP URL while keeping timeout and parallelism')
        click('#settings-save')
        wait_for('return document.querySelector("#settings-save").disabled && !document.querySelector("[data-navigation-locked=true]")')
        check(command('snapshot')['preferences']['ping']['method']=='tcp', 'selected TCP method persists in the native settings')
        click('.primary-nav button:first-child'); fill('#client-search', 'URL fixture TCP endpoint')
        wait_for('return document.querySelectorAll(".connection-row").length===1 && !document.querySelector("#open-probes").disabled')
        calls_before=sum(calls.values()); click('#open-probes'); tcp_result=done()
        check(tcp_result['method']=='tcp' and tcp_result['entries'][0]['status']=='ok' and sum(calls.values())==calls_before, 'one-click TCP measures the configured port without sending any HTTP request')
        command('startPing', {'ids':[wg_id]}); unsupported=done()['entries'][0]
        check(unsupported['status']=='unsupported' and unsupported['error']=='probe_tcp_inapplicable', 'AmneziaWG is explicitly inapplicable for TCP')
        click('#ping-open-settings'); select('#setting-ping_method', 'icmp'); click('#settings-save')
        wait_for('return document.querySelector("#settings-save").disabled && !document.querySelector("[data-navigation-locked=true]")')
        click('.primary-nav button:first-child'); fill('#client-search', 'URL fixture Amnezia endpoint')
        wait_for('return document.querySelectorAll(".connection-row").length===1 && !document.querySelector("#open-probes").disabled')
        click('.row-more'); click('#probe-one'); icmp_result=done()
        check(icmp_result['method']=='icmp' and icmp_result['entries'][0]['status']=='ok', 'profile menu immediately runs real ICMP for AmneziaWG')
        wait_for('return document.querySelector("[data-profile-latency]").title.includes("ICMP")')
        screenshot('icmp-amnezia-result-ru')
        state_now=command('snapshot')
        check(next(p for p in state_now['profiles'] if p['id']==tcp_id)['measurement'] is None, 'TCP results are excluded from the ICMP view and latency sorting')
        click('#ping-open-settings'); select('#setting-ping_method', 'http')
        check(js('return document.querySelector("#probe-url").value')==origin+'/ok', 'switching back to HTTP restores the saved URL')
        select('#setting-ping_method', 'icmp')
        screenshot('ping-method-settings-ru')
        select('#setting-ping_method', 'http'); fill('#probe-url', 'ftp://invalid.test/')
        select('#setting-ping_method', 'tcp'); click('#settings-save')
        wait_for('return document.querySelector("#settings-save").disabled && !document.querySelector("[data-navigation-locked=true]")')
        saved_ping=command('snapshot')['preferences']['ping']
        check(saved_ping['method']=='tcp' and saved_ping['url']==origin+'/ok', 'an inactive HTTP URL draft cannot block saving TCP or overwrite the saved HTTP URL')
        select('#setting-ping_method', 'auto')
        wait_for('return !!document.querySelector("#probe-url")')
        check(js('return document.querySelector(".field-hint").textContent.includes("HTTP(S) → TCP → ICMP")'), 'Auto explains the fallback order and keeps the HTTP URL editable')
        fill('#probe-url', origin+'/ok'); click('#settings-save')
        wait_for('return document.querySelector("#settings-save").disabled && !document.querySelector("[data-navigation-locked=true]")')
        screenshot('auto-ping-settings-ru')
        click('.primary-nav button:first-child'); fill('#client-search', 'URL fixture')
        command('startPing', {'ids':[a, tcp_id, c, wg_id]})
        auto_result=done(30)
        entries=auto_result['entries']
        check(auto_result['method']=='auto' and all(e['status']=='ok' for e in entries), 'Auto completes each profile independently through the real cores')
        check([e['effectiveMethod'] for e in entries]==['http','tcp','icmp','icmp'], 'Auto stops at HTTP success, falls back to TCP, then falls back to ICMP')
        check([[a['method'] for a in e['attempts']] for e in entries]==[['http'],['http','tcp'],['http','tcp','icmp'],['http','tcp','icmp']], 'Auto preserves the ordered attempt history without probing beyond the first success')
        # An endpoint is measured over HTTP through its own disposable core; with no
        # peer listening that attempt fails, TCP stays inapplicable and ICMP answers.
        check(entries[2]['attempts'][1]['error']=='probe_connection_refused' and [a['status'] for a in entries[3]['attempts']]==['error','unsupported','ok'] and entries[3]['attempts'][1]['error']=='probe_tcp_inapplicable', 'A refused TCP port falls back to ICMP and AmneziaWG tries HTTP through its endpoint, skips inapplicable TCP and falls back to ICMP')
        wait_for('return [...document.querySelectorAll("[data-profile-latency]")].filter(e=>e.textContent.includes(" · ")).length===4')
        check(js('return [...document.querySelectorAll("[data-profile-latency]")].some(e=>e.textContent.includes("TCP") && e.title.includes("HTTP(S):"))'), 'Auto rows identify the successful method and tooltips describe previous attempts')
        screenshot('auto-ping-results-ru')
        request('POST', base + '/refresh', {})
        wait_for('return !!document.querySelector("#open-probes")')
        check(command('snapshot')['preferences']['ping']['method']=='auto', 'The saved Auto preference survives a webview reload')
        release.clear(); started.clear()
        command('savePingSettings', {'method':'auto','url':origin+'/slow','timeoutMs':5000})
        command('startPing', {'ids':[a, c]}); assert started.wait(5)
        command('cancelUrlTests'); cancelled=done()
        release.set(); time.sleep(.2)
        check(all(e['status']=='cancelled' and e['attempts']==[] for e in cancelled['entries']) and all(e['status']=='cancelled' for e in batch()['entries']), 'Stopping Auto cancels pending profiles and does not trigger TCP or ICMP after a late HTTP reply')
        client.sendall(b'final-tunnel'); check(upstream.recv(12) == b'final-tunnel', 'timeout, cancellation and reload preserve the original connected tunnel')
    finally:
        release.set(); command('cancelUrlTests'); command('clearUrlTests')
        for s in sockets: s.close()
        command('disconnect')
        for pid in ids: command('delete', {'id': pid})
        command('preferences', initial['preferences'])
        if initial['selected']: command('select', {'id': initial['selected']})
        fill('#client-search', '')
        request('POST', base + '/window/rect', {'width': 1280, 'height': 860})
        server.shutdown(); server.server_close()
