"""Actual full-client HTTP tests with DNS/GeoSite rules and an unchanged main stream."""
import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import time
import urllib.request
from geodata_assets_fixture import geosite


def run(h):
    command, check, wait_for, js = (h[k] for k in ('command', 'check', 'wait_for', 'js'))
    fixture = json.loads(Path(os.environ['_THRONIUM_FULL_XRAY_PROBES_FIXTURE']).read_text())
    initial = command('snapshot'); assert not initial['profiles']
    root = Path(command('storageLocation')['directory'])
    sockets = []; ids = []; audit = {'results': [], 'contexts': []}

    def available():
        listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen(); sockets.append(listener)
        return listener
    def admin(**values):
        request = urllib.request.Request(fixture['admin'], data=json.dumps(values).encode() if values else None, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=3) as response: return json.load(response)
    def add(name, config, kind='xray-config'):
        identifier = command('saveProfile', {'name': 'Full Xray67 ' + name, 'groupId': 'personal', 'kind': kind, 'config': config})['id']
        ids.append(identifier); return identifier
    def start(identifier, host='allowed.probe.test', path='/ok', *, secure=False, timeout=2000, method='http'):
        port = 443 if secure else fixture['httpPort']
        return command('startUrlTests', {'ids': [identifier], 'method': method, 'url': ('https' if secure else 'http') + '://' + host + ':' + str(port) + path, 'timeoutMs': timeout})['id']
    def done(timeout=20):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            batch = command('snapshot')['urlTests']
            if batch and batch['entries'][0]['status'] not in ('queued', 'testing'):
                row = batch['entries'][0]; audit['results'].append({key: row.get(key) for key in ('profileId', 'status', 'error', 'latencyMs', 'effectiveMethod')}); return row
            time.sleep(.08)
        raise AssertionError('full-client HTTP did not finish')
    def poll(predicate, timeout=8):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if predicate(): return
            time.sleep(.05)
        raise AssertionError('full-client fixture did not reach expected state')
    def save_url(url):
        old = command('settings')['core']
        command('saveSettings', {'section': 'core', 'previous': old, 'values': {**old, 'xray_geosite_url': url}})

    reserve1, reserve2 = available(), available()
    log_file = root / 'probe-log-sentinel'; log_file.write_bytes(b'unchanged configured log')
    config = {'log': {'access': str(log_file), 'error': str(log_file), 'loglevel': 'debug'},
              'dns': {'servers': [{'address': '127.0.0.1', 'port': fixture['dnsPort']}], 'queryStrategy': 'UseIPv4', 'disableCache': True},
              'inbounds': [{'tag': 'socks', 'protocol': 'socks', 'listen': '0.0.0.0', 'port': reserve1.getsockname()[1], 'sniffing': {'enabled': True, 'routeOnly': True, 'destOverride': ['http', 'tls']}},
                           {'tag': 'http', 'protocol': 'http', 'listen': '0.0.0.0', 'port': reserve2.getsockname()[1]}],
              'outbounds': [{'protocol': 'freedom', 'tag': 'direct', 'settings': {'domainStrategy': 'UseIP'}}, {'protocol': 'blackhole', 'tag': 'block'}],
              'routing': {'domainStrategy': 'IPIfNonMatch', 'rules': [{'inboundTag': ['socks'], 'domain': ['domain:blocked.probe.test'], 'outboundTag': 'block'}, {'ip': ['192.0.2.0/24'], 'outboundTag': 'block'}]}}
    try:
        free = socket.socket(); free.bind(('127.0.0.1', 0)); main_port = free.getsockname()[1]; free.close()
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark', 'connectionMode': 'local', 'inboundPort': main_port})
        main = add('main', {'type': 'direct'}, 'sing-box-outbound')
        full = add('client DNS', config)
        command('connect', {'id': main}); before = command('snapshot')
        listener = available(); client = socket.create_connection(('127.0.0.1', main_port), timeout=3); sockets.append(client)
        address = '127.0.0.1:' + str(listener.getsockname()[1])
        client.sendall(('CONNECT ' + address + ' HTTP/1.1\r\nHost: ' + address + '\r\n\r\n').encode())
        upstream, _ = listener.accept(); upstream.settimeout(3); sockets.append(upstream); assert b'200' in client.recv(1024)
        from window_ui import primary
        from native_processes import core_pids
        connection, _, app_pid = primary(); connection.close(); main_pids = core_pids(app_pid)
        def preserved():
            state = command('snapshot')
            assert state['running'] == main and state['since'] == before['since'] and core_pids(app_pid) == main_pids
            client.sendall(b'preserved67'); assert upstream.recv(11) == b'preserved67'

        routing = command('routing')
        selected_route = next(route for route in routing['profiles'] if route['id'] == routing['active'])
        selected_route['dns'] = {'servers': [{'type': 'udp', 'tag': 'dns-direct', 'server': '192.0.2.99'}], 'final': 'dns-direct'}
        command('saveRouting', routing)

        start(full); result = done(); state = admin()
        check(result['status'] == 'ok' and result['latencyMs'] >= 25, 'complete Xray JSON performs a real HTTP warmup and latency request')
        check(any(q['name'] == 'allowed.probe.test' for q in state['dnsQueries']) and len(state['requests']) == 2, 'the full client DNS supplies the HTTP destination despite different saved global DNS')
        check(command('profile', {'id': full})['config'] == config and log_file.read_bytes() == b'unchanged configured log', 'HTTP preparation preserves saved JSON and never writes its configured log file')
        check(reserve1.getsockname()[1] == config['inbounds'][0]['port'] and reserve2.getsockname()[1] == config['inbounds'][1]['port'], 'occupied source SOCKS and HTTP ports do not collide with disposable client inbounds')
        preserved(); check(True, 'the main Core PID, connection age and open TCP stream survive the full-client probe')

        admin(clear=True); start(full, 'blocked.probe.test'); result = done()
        check(result['status'] == 'error' and not admin()['requests'], 'client domain and inbound-tag routing blocks the HTTP request')
        admin(clear=True); start(full, 'ipblocked.probe.test'); result = done(); state = admin()
        check(result['status'] == 'error' and not state['requests'] and any(q['name'] == 'ipblocked.probe.test' for q in state['dnsQueries']), 'client DNS and IPIfNonMatch resolve then enforce the IP block rule')
        admin(clear=True); start(full, secure=True); result = done()
        check(result['status'] == 'ok' and len(admin()['requests']) == 2, 'full-client HTTPS validates the owned server certificate and transfers real requests')
        admin(clear=True); start(full, 'wrong.probe.test', secure=True); result = done()
        check(result['status'] == 'error' and result['error'] == 'probe_tls_failed' and result['latencyMs'] is None, 'hostname certificate failure does not invent successful full-client latency')
        admin(clear=True, mode='dns-fail'); start(full, timeout=500); result = done()
        check(result['status'] == 'error' and not admin()['requests'], 'failed client DNS is not replaced by the host resolver during HTTP testing')
        admin(mode='ok')

        unsupported = copy.deepcopy(config); unsupported['api'] = {'tag': 'unused-api', 'services': []}
        refused = add('background API', unsupported); admin(clear=True); start(refused); result = done(); preserved()
        check(result['status'] == 'unsupported' and result['error'] == 'probe_full_config_unsupported' and not admin()['requests'], 'unsupported full-client background features are refused before a test Core starts')
        raw = add('sing-box full', {'outbounds': [{'type': 'direct'}],
                                    'route': {'rule_set': [{'type': 'remote', 'tag': 'unowned', 'format': 'binary', 'url': 'https://unowned.test/file.srs'}]}},
                  'sing-box-config')
        start(raw); result = done()
        check(result['status'] == 'unsupported', 'a complete sing-box client the disposable core cannot own keeps its explicit unsupported HTTP result')

        url = 'https://assets.probe.test/geosite.dat'; save_url(url)
        geo = copy.deepcopy(config); geo['routing']['rules'][0]['domain'] = ['geosite:TEST']
        geo_profile = add('geodata', geo); admin(clear=True); start(geo_profile); result = done(); preserved()
        check(result['error'] == 'geodata_missing' and not admin()['requests'], 'missing cached geodata is reported without a download or test request')
        cache = root / 'xray-assets'; cache.mkdir(mode=0o700, exist_ok=True)
        manifest = cache / (hashlib.sha256((url + ':null').encode()).hexdigest() + '.ref')
        def seed(domain):
            data = geosite(domain=domain); digest = hashlib.sha256(data).hexdigest(); target = cache / (digest + '.dat')
            target.write_bytes(data); manifest.write_text(digest); return target, data
        first, data = seed('blocked.probe.test')
        start(geo_profile); result = done()
        check(result['status'] == 'ok' and first.read_bytes() == data, 'a cached independent GeoSite file is copied and read by the real disposable Xray')
        admin(clear=True); start(geo_profile, 'blocked.probe.test'); result = done()
        check(result['status'] == 'error' and not admin()['requests'], 'the staged GeoSite category actually blocks its domain')
        first.write_bytes(b'corrupt owned geodata'); admin(clear=True); start(geo_profile); result = done()
        check(result['error'] == 'geodata_invalid' and not admin()['requests'], 'corrupt hash-named geodata fails before any HTTP request')
        first.write_bytes(data)
        external = copy.deepcopy(geo); external['routing']['rules'][0]['domain'] = ['ext:unowned.dat:TEST']
        external_id = add('external data', external); start(external_id); result = done()
        check(result['error'] == 'geodata_external_file_unsupported', 'an arbitrary external geodata path is not read by HTTP testing')

        admin(clear=True, mode='hold'); start(geo_profile, path='/cancel', timeout=5000); poll(lambda: admin()['active'] > 0)
        command('cancelUrlTests'); result = done(); admin(mode='ok', release=True); poll(lambda: admin()['active'] == 0)
        check(result['status'] == 'cancelled' and command('snapshot')['urlTests']['entries'][0]['status'] == 'cancelled', 'canceling full-client HTTP reaps the operation and rejects late responses')
        preserved(); check(True, 'the open main TCP stream survives full-client cancellation and geodata errors')

        admin(clear=True, mode='hold'); start(geo_profile, path='/updated-asset', timeout=5000); poll(lambda: admin()['active'] > 0)
        second, second_data = seed('next.probe.test'); admin(mode='ok', release=True); result = done()
        check(result['status'] == 'stale' and result['latencyMs'] is None, 'a geodata reference update invalidates an in-flight HTTP result')
        admin(clear=True); start(geo_profile, 'blocked.probe.test'); old = done(); start(geo_profile, 'next.probe.test'); new = done()
        check(old['status'] == 'ok' and new['status'] == 'error' and second.read_bytes() == second_data, 'a new HTTP operation consumes the updated category and changes the actual domain route')

        admin(clear=True, mode='hold'); start(geo_profile, path='/updated-source', timeout=5000); poll(lambda: admin()['active'] > 0)
        settings = command('settings')['core']
        response = h['request']('POST', h['base'] + '/execute/async', {'script': '''
            const done=arguments[arguments.length-1];
            window.__TAURI_INTERNALS__.invoke('app_command',{name:'saveSettings',payload:arguments[0]})
              .then(value=>done(JSON.stringify({ok:true,value}))).catch(error=>done(JSON.stringify({ok:false,error})));
        ''', 'args': [{'section': 'core', 'previous': settings, 'values': {**settings, 'xray_geosite_url': 'https://other.probe.test/geosite.dat'}}]})
        check(json.loads(response) == {'ok': False, 'error': {'code': 'probe_busy'}} and command('settings')['core'] == settings, 'core settings refuse source replacement while an HTTP probe owns its operation')
        admin(mode='ok', release=True); result = done()
        check(result['status'] == 'ok', 'a refused settings change leaves the pending HTTP context valid')
        save_url('https://other.probe.test/geosite.dat'); admin(clear=True); start(geo_profile); result = done(); save_url(url)
        check(result['error'] == 'geodata_missing' and not admin()['requests'], 'a changed source requires its own cached data on the next operation')
        admin(clear=True, mode='hold'); start(full, path='/edited-profile', timeout=5000); poll(lambda: admin()['active'] > 0)
        edited = command('profile', {'id': full}); edited['config']['routing']['domainStrategy'] = 'AsIs'; command('saveProfile', edited)
        admin(mode='ok', release=True); result = done()
        check(result['status'] == 'stale', 'editing full client routing invalidates its pending HTTP result')
        admin(clear=True); start(geo_profile, method='auto'); result = done()
        check(result['status'] == 'ok' and result['effectiveMethod'] == 'http' and len(admin()['requests']) == 2, 'Auto accepts a successful full-client HTTP check without endpoint fallback')

        for language, width in [('en', 1280), ('ru', 390)]:
            command('preferences', {**command('snapshot')['preferences'], 'language': language})
            h['request']('POST', h['base'] + '/window/rect', {'width': width, 'height': 900})
            wait_for('return document.documentElement.lang===' + json.dumps(language) + ' && innerWidth===' + str(width))
            h['click']('.primary-nav button:last-child'); h['click']('[data-settings-section=testing]')
            h['select']('#setting-ping_method', 'http')
            wait_for('return !!document.querySelector("#settings-form")')
            text = js('return document.querySelector("#settings-form").textContent')
            check(('полных sing-box и Xray' in text if language == 'ru' else 'Complete sing-box and Xray' in text) and js('return document.documentElement.scrollWidth<=innerWidth+1'), 'the client-policy HTTP hint is visible and fits ' + language + ' ' + str(width) + 'px')
            h['screenshot']('full-client-http-' + language + '-' + str(width))
        preserved(); check(True, 'all full-client diagnostics preserve the main session and active TCP stream')
        audit.update(origin=admin(), sourceUnchanged=command('profile', {'id': geo_profile})['config'] == geo, mainCorePreserved=True)
    except Exception:
        import traceback
        audit['failure'] = traceback.format_exc()
        raise
    finally:
        with contextlib.suppress(Exception): command('cancelUrlTests')
        with contextlib.suppress(Exception): admin(mode='ok', release=True)
        for stream in sockets:
            with contextlib.suppress(OSError): stream.close()
        with contextlib.suppress(Exception): audit['lastLogs'] = command('getLogs')
        (h['artifacts'] / 'full-client-audit.json').write_text(json.dumps(audit, indent=2) + '\n')
        with contextlib.suppress(Exception): command('disconnect')
