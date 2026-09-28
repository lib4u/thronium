"""Real temporary VPN credentials with an isolated GNOME keyfile backend.

Only own loopback servers, GSettings and child processes are touched. Wire lost
acknowledgement, canceled Rust futures and typed rollback are separate evidence.
"""
import contextlib
import hashlib
import copy
import errno
import fcntl
import http.client
import http.server
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import subprocess
import threading
import sys
from urllib.parse import urlsplit
from gi.repository import Gio, GLib
import time

from native_menu import NativeMenu
from native_processes import core_pids
from vpn_credentials_fixture import OLD_USERNAME, OLD_PASSWORD, NEW_USERNAME, NEW_PASSWORD
from vpn_otp_fixture import SECRET


def run(h):
    command, click, fill, wait_for, js, check = (h[k] for k in ('command', 'click', 'fill', 'wait_for', 'js', 'check'))
    config = Path(os.environ['XDG_CONFIG_HOME'])
    data = Path(os.environ['XDG_DATA_HOME'])
    assert os.environ.get('GSETTINGS_BACKEND') == 'keyfile'
    assert config.parent.name.startswith('thronium-native-test-') and data.parent == config.parent
    assert os.environ['DBUS_SESSION_BUS_ADDRESS'].startswith('unix:path=' + str(config.parent))
    assert all(not os.environ.get(key) for key in ('http_proxy','https_proxy','all_proxy','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY'))
    ready = json.loads(Path(os.environ['_THRONIUM_VPN_CREDENTIALS_READY']).read_text())
    app = Path(h['args'].application).resolve()
    core = app.with_name('ThroniumCore')
    menu = NativeMenu()
    assert Path('/proc', str(menu.pid), 'exe').resolve() == app
    initial = command('snapshot')
    initial_route = command('routing')
    initial_core = command('settings')['core']
    geometry = h['request']('GET', h['base'] + '/window/rect')
    data = Path(os.environ['XDG_DATA_HOME'])
    assert data.parent.name.startswith('thronium-native-test-')
    library = data / 'io.thronium.desktop/library.json'
    group = command('saveGroup', {'name': 'System proxy temporary VPN credentials', 'subscription': None})['id']
    audit = {'states': [], 'kills': [], 'refusals': [], 'layout': {}, 'leases': [], 'resolver': [],
             'hostProxyTouched': False, 'hostPolkitTested': False,
             'openconnectCstpConnectedClaimed': False, 'openvpnPayloadTested': False,
             'wireLostAckTested': False, 'rollbackInjected': False, 'failedCleanupQuitTested': False}
    tokens, otp_id, held, exited = [], None, None, False

    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            with contextlib.suppress(OSError):
                while value := self.request.recv(4096):
                    self.request.sendall(value)

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    origin = Server(('127.0.0.2', 0), Echo)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    port = origin.server_address[1]

    def until(predicate, timeout=25):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            value = predicate()
            if value:
                return value
            time.sleep(.07)
        raise AssertionError('system proxy credentials condition timed out')

    schemas = [Gio.Settings.new('org.gnome.system.proxy' + ('.' + suffix if suffix else ''))
               for suffix in ('', 'http', 'https', 'socks', 'ftp')]
    keys = [(setting, key) for setting in schemas for key in sorted(setting.list_keys())]
    journal = config / 'thronium-system-proxy/recovery.json'
    lock = journal.with_name('owner.lock')

    def settings():
        # External gsettings writers update the keyfile before this long-lived
        # Gio client receives its file-monitor notification. A fresh reader is
        # required for both the applied baseline and each exact later comparison.
        while GLib.MainContext.default().pending():
            GLib.MainContext.default().iteration(False)
        Gio.Settings.sync()
        script = '''from gi.repository import Gio
import json,os
from pathlib import Path
assert os.environ.get('GSETTINGS_BACKEND')=='keyfile'
assert Path(os.environ['XDG_CONFIG_HOME']).parent.name.startswith('thronium-native-test-')
rows=[]
for suffix in ('','http','https','socks','ftp'):
    setting=Gio.Settings.new('org.gnome.system.proxy'+('.'+suffix if suffix else ''))
    for key in sorted(setting.list_keys()):
        user=setting.get_user_value(key)
        rows.append([setting.get_value(key).print_(True), user.print_(True) if user is not None else None])
print(json.dumps(rows))'''
        values = json.loads(subprocess.check_output([sys.executable, '-c', script], text=True, timeout=5))
        audit['settingsReadMode'] = 'fresh-process-private-keyfile'
        return [tuple(row) for row in values]

    def assert_expected_apply(observed, baseline, port, label):
        # Independent documented apply contract: all managed keys become user
        # values; every unrelated key must retain its original effective/user pair.
        expected_managed = {('', 'mode'): "'manual'", ('', 'use-same-proxy'): 'false',
            ('http', 'enabled'): 'true', ('http', 'use-authentication'): 'false'}
        for suffix in ('http', 'https', 'socks', 'ftp'):
            expected_managed[(suffix, 'host')] = "'127.0.0.1'"
            expected_managed[(suffix, 'port')] = str(port)
        names = [(suffix, key) for suffix, setting in zip(('', 'http', 'https', 'socks', 'ftp'), schemas)
                 for key in sorted(setting.list_keys())]
        assert set(expected_managed).issubset(names)
        expected = [(expected_managed[name], expected_managed[name]) if name in expected_managed else old
                    for name, old in zip(names, baseline)]
        audit.setdefault('appliedMappings', []).append({'label': label, 'port': port,
            'keys': [list(name) for name in names], 'expectedValues': expected,
            'observedValues': observed, 'matched': observed == expected})
        assert observed == expected, 'private GNOME applied values do not match every documented managed key'

    def restore(values):
        for (setting, key), (_, user) in zip(keys, values):
            if user is None:
                setting.reset(key)
            else:
                setting.set_value(key, GLib.Variant.parse(setting.get_value(key).get_type(), user, None, None))
        Gio.Settings.sync()

    def leased():
        if not lock.exists():
            return False
        with lock.open('rb') as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                if error.errno in (errno.EAGAIN, errno.EACCES):
                    return True
                raise
            fcntl.flock(handle, fcntl.LOCK_UN)
            return False

    def fingerprint(path):
        state = path.stat()
        return {'bytes': path.read_text(), 'device': state.st_dev, 'inode': state.st_ino,
                'mtimeNs': state.st_mtime_ns, 'size': state.st_size}

    keyfile = config / 'glib-2.0/settings/keyfile'

    def lease():
        return {'journal': fingerprint(journal), 'keyfile': fingerprint(keyfile)}

    original = settings()

    def identity(pid):
        row = Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()
        assert row[0] not in ('Z', 'X')
        return {'pid': int(pid), 'ppid': int(row[1]), 'starttime': int(row[19])}

    def nodes():
        result = []
        for pid in core_pids(menu.pid):
            with contextlib.suppress(OSError):
                if Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()[0] in ('Z', 'X'):
                    continue
                row = identity(pid)
                assert row['ppid'] == menu.pid and Path('/proc', str(pid), 'exe').resolve() == core
                assert b'XDG_DATA_HOME=' + str(data).encode() in Path('/proc', str(pid), 'environ').read_bytes().split(b'\0')
                result.append(row)
        return result

    def current_core():
        values = nodes()
        assert len(values) == 1, 'expected exactly one verified owned local core'
        return values[0]

    def safe(value, include_saved=False):
        text = value if isinstance(value, str) else json.dumps(value)
        forbidden = [SECRET, NEW_USERNAME, NEW_USERNAME.strip(), NEW_PASSWORD, NEW_PASSWORD.strip(), *tokens]
        if include_saved:
            forbidden += [OLD_USERNAME, OLD_PASSWORD]
        return all(item not in text for item in forbidden)

    def snapshot():
        value = command('snapshot')
        assert safe(value, True), 'public snapshot contains private credentials or edit token'
        audit['states'].append({key: value[key] for key in ['running', 'selected', 'phase', 'since', 'vpn', 'routing', 'systemProxy']})
        return value

    def events(protocol):
        path = Path(ready['events'])
        return [row for line in path.read_text().splitlines() if (row := json.loads(line))['protocol'] == protocol]

    def accepted_ovpn():
        return [row for row in events('openvpn') if row.get('accepted') and row.get('usernameExact')]

    def terminal():
        def observed():
            value = snapshot()['vpn']
            row = next((r for r in value['endpoints'] if r['tag'] == 'proxy'), None)
            if row and row['state'] == 'error' and row['authFailed'] and row['challengeId'] is None:
                return {'sessionId': value['sessionId'], 'endpointTag': 'proxy'}
        return until(observed)

    def connected():
        value = snapshot()['vpn']
        return any(row['tag'] == 'proxy' and row['state'] == 'connected' for row in value['endpoints']) and value

    def add(name, config):
        config = copy.deepcopy(config)
        config.pop('tag', None)
        return command('saveProfile', {'name': name, 'groupId': group, 'kind': 'sing-box-outbound', 'config': config})['id']

    def route_value(rules):
        value = copy.deepcopy(command('routing'))
        active = next(row for row in value['profiles'] if row['id'] == value['active'])
        active['mode'], active['rules'] = 'rules', rules
        return value

    def otp():
        return command('otpGet', {'id': otp_id})

    def socket_open():
        state = snapshot()
        sock = socket.create_connection(('127.0.0.1', state['preferences']['inboundPort']), timeout=5)
        target = '127.0.0.2:' + str(port)
        sock.sendall(f'CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n'.encode())
        response = b''
        while b'\r\n\r\n' not in response:
            value = sock.recv(4096)
            assert value, 'owned direct CONNECT closed before response'
            response += value
        assert b' 200 ' in response, 'owned direct route did not open'
        return sock

    def echo(sock):
        sock.sendall(b'owned-proxy-credential-route')
        return sock.recv(128) == b'owned-proxy-credential-route'

    def ui_current(request):
        js('window.__proxyCredentials.match=arguments[0];window.__proxyCredentials.matchedAt=0', request)
        wait_for('return window.__proxyCredentials.matchedAt>0&&Date.now()-window.__proxyCredentials.matchedAt>80')

    def open_dialog(request):
        click('.primary-nav button:first-child')
        wait_for('return !!document.querySelector(".add-connection")')
        ui_current(request)
        click('[data-vpn-credentials=proxy]')
        wait_for('return !!document.querySelector("#vpn-credentials-username:not(:disabled)")')
        view = js('return window.__proxyCredentials.lastView')
        assert set(view) == {'sessionId', 'endpointTag', 'editToken', 'username'}
        assert all(view[key] == request[key] for key in request)
        tokens.append(view['editToken'])
        return {key: view[key] for key in ['sessionId', 'endpointTag', 'editToken']}

    def fill_new():
        fill('#vpn-credentials-username', NEW_USERNAME)
        fill('#vpn-credentials-password', NEW_PASSWORD)

    def close_dialog():
        click('#vpn-credentials-cancel')
        wait_for('return !document.querySelector("#vpn-credentials-cancel")')

    def stale(name, payload):
        try:
            command(name, payload)
        except RuntimeError as error:
            assert 'vpn_credentials_stale' in str(error) and safe(str(error), True)
            audit['refusals'].append(name)
            return True
        raise AssertionError('old system proxy credential token was accepted')

    class Http(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_GET(self):
            assert self.path.startswith('/credentials/')
            body = b'PRIVATE-PROXY-CREDENTIALS-HTTP'
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    http_origin = http.server.ThreadingHTTPServer(('127.0.0.2', 0), Http)
    http_origin.daemon_threads = True
    threading.Thread(target=http_origin.serve_forever, daemon=True).start()

    def traffic(label):
        target = f'http://127.0.0.2:{http_origin.server_port}/credentials/{label}'
        resolved = json.loads(subprocess.check_output([sys.executable, '-c',
            'from gi.repository import Gio; import json,sys; print(json.dumps(Gio.ProxyResolver.get_default().lookup(sys.argv[1],None)))', target], text=True))
        audit['resolver'].append({'label': label, 'freshClient': resolved})
        endpoint = urlsplit(resolved[0])
        assert endpoint.scheme == 'http' and endpoint.hostname == '127.0.0.1' and endpoint.port == proxy_port
        client = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=5)
        try:
            client.request('GET', target)
            response = client.getresponse()
            return response.status == 200 and response.read() == b'PRIVATE-PROXY-CREDENTIALS-HTTP'
        finally:
            client.close()

    def retained(expected_lease, applied):
        current_lease, current_settings, current_locked = lease(), settings(), leased()
        current_proxy = snapshot()['systemProxy']
        bits = {'journal': current_lease['journal'] == expected_lease['journal'],
                'keyfile': current_lease['keyfile'] == expected_lease['keyfile'],
                'locked': current_locked, 'values': current_settings == applied,
                'active': current_proxy['active']}
        audit.setdefault('retainedObservations', []).append({'checks': bits,
            'expectedLease': expected_lease, 'observedLease': current_lease,
            'expectedValues': applied, 'observedValues': current_settings, 'systemProxy': current_proxy})
        return all(bits.values())

    def disconnected():
        until(lambda: settings() == previous and not journal.exists() and not leased())
        return snapshot()['running'] is None and not snapshot()['systemProxy']['active']

    try:
        command('disconnect')
        assert initial['systemProxy']['available'], 'private GNOME backend unavailable'
        schemas[0].set_string('mode', 'auto')
        schemas[0].set_string('autoconfig-url', 'http://127.0.0.1:9/owned-before.pac')
        schemas[0].set_strv('ignore-hosts', ['localhost', '127.0.0.1', '::1'])
        schemas[1].set_string('host', 'previous.proxy.test')
        schemas[1].set_int('port', 3128)
        schemas[1].set_boolean('use-authentication', True)
        schemas[2].reset('host')
        schemas[2].reset('port')
        Gio.Settings.sync()
        previous = settings()
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0))
            proxy_port = reserve.getsockname()[1]
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark',
            'connectionMode': 'system-proxy', 'inboundPort': proxy_port, 'closeBehavior': 'quit'})
        wait_for('return document.documentElement.lang==="en"')
        check(settings() == previous and not journal.exists() and not leased(),
              'saving system-proxy mode leaves the private GNOME effective/user baseline unchanged without acquiring a journal or lease')
        otp_id = command('otpSave', {'value': {'name': 'Proxy retry must not spend HOTP', 'issuer': 'Owned keyfile',
            'secret': SECRET, 'algorithm': 'SHA1', 'type': 'hotp', 'digits': 6, 'period': 30, 'counter': '19'}})['id']
        otp_before = otp()
        ovpn = add('System proxy OpenVPN temporary credentials', ready['openvpn'])
        oc = add('System proxy OpenConnect temporary credentials', ready['openconnect'])
        other = add('Different selected profile', {'type': 'block'})
        direct_rule = {'id': 'proxy-credentials-loopback', 'name': 'Owned direct fixture', 'enabled': True,
            'config': {'ip_cidr': ['127.0.0.2/32'], 'port': [port, http_origin.server_port], 'outbound': 'direct'}}
        command('saveRouting', route_value([direct_rule]))
        applied_route = command('routing')
        js('''const original=window.fetch;const s=window.__proxyCredentials={original,calls:{},lastView:null,match:null,matchedAt:0};
            window.fetch=function(input,options){let name=null;try{if(String(input).includes('/app_command'))name=JSON.parse(options?.body||'{}').name}catch{}
                if(name)s.calls[name]=(s.calls[name]||0)+1;const promise=original.apply(this,arguments);
                if(name!=='vpnCredentials'&&name!=='snapshot')return promise;
                return promise.then(async response=>{let value;try{value=await response.clone().json()}catch{return response}
                    if(name==='snapshot'&&s.match&&value.vpn?.sessionId===s.match.sessionId&&value.vpn.endpoints.some(e=>e.tag===s.match.endpointTag&&e.state==='error'&&e.authFailed&&!e.challengeId))s.matchedAt=Date.now();
                    if(name==='vpnCredentials'&&value.editToken)s.lastView=value;return response;});};''')
        command('connect', {'id': ovpn})
        old = terminal()
        worker = current_core()
        old_lease, applied = lease(), settings()
        assert_expected_apply(applied, previous, proxy_port, 'initial-openvpn')
        audit['leases'].append(old_lease)
        check(snapshot()['phase'] == 'error' and retained(old_lease, applied) and traffic('initial-terminal'),
              'real primary OpenVPN terminal authFailed retains an owned system proxy lease and fresh GNOME-resolved direct HTTP')
        held = socket_open()
        stored, before = library.read_bytes(), snapshot()
        edit = open_dialog(old)
        check(js('return document.querySelector("#vpn-credentials-username").value===arguments[0]&&document.querySelector("#vpn-credentials-password").value===""&&document.querySelector("#vpn-credentials-password").type==="password"', OLD_USERNAME)
              and current_core() == worker and library.read_bytes() == stored and retained(old_lease, applied),
              'real browser details returns only saved username and an empty masked password without changing the core, journal or stored values')
        fill_new()
        close_dialog()
        check(echo(held) and current_core() == worker and snapshot()['vpn']['sessionId'] == old['sessionId']
              and snapshot()['since'] == before['since'] and library.read_bytes() == stored and otp() == otp_before
              and retained(old_lease, applied),
              'native Cancel preserves the same held CONNECT, session/since, journal fingerprint, independent flock and HOTP C19')
        check(stale('restartVpnCredentials', {**edit, 'username': NEW_USERNAME, 'password': NEW_PASSWORD}) and echo(held),
              'a cancelled edit token cannot replace the core or disturb its existing connection')

        for language in ['ru', 'en']:
            command('preferences', {**snapshot()['preferences'], 'language': language})
            wait_for('return document.documentElement.lang===' + json.dumps(language))
            open_dialog(old)
            fill('#vpn-credentials-username', '')
            h['request']('POST', h['base'] + '/window/rect', {'width': 390, 'height': 844})
            def dimensions():
                return js('''const d=document.querySelector('.vpn-auth-modal'),b=d.querySelector('.modal-body');return {width:innerWidth,height:innerHeight,
                    bottom:d.getBoundingClientRect().bottom,scroll:b.scrollWidth,client:b.clientWidth,
                    submit:document.querySelector('#vpn-credentials-submit').getBoundingClientRect().bottom,
                    cancel:document.querySelector('#vpn-credentials-cancel').getBoundingClientRect().bottom}''')
            samples, stable, end = [dimensions()], 0, time.monotonic() + 3
            while stable < 3 and time.monotonic() < end:
                time.sleep(.12)
                sample = dimensions()
                stable = stable + 1 if sample == samples[-1] else 0
                samples.append(sample)
            audit['layout'][language] = samples
            box = samples[-1]
            check(stable == 3 and box['width'] == 390 and box['scroll'] <= box['client'] + 1
                  and box['bottom'] <= box['height'] + 1 and max(box['submit'], box['cancel']) <= box['height'],
                  language + ' system proxy credentials dialog fits 390px with both actions visible and strict no-overflow geometry')
            h['screenshot']('vpn-credentials-system-proxy-' + language + '-390')
            close_dialog()
            h['request']('POST', h['base'] + '/window/rect', geometry)

        edit = open_dialog(old)
        command('saveRouting', route_value([{'id': 'proxy-credentials-pending-deny', 'name': 'Saved pending rejection',
            'enabled': True, 'config': {'network': 'tcp', 'action': 'reject'}}]))
        current = command('settings')['core']
        command('saveSettings', {'section': 'core', 'previous': current, 'values': {**current, 'singbox_tcp_keep_alive_idle': 77}})
        command('select', {'id': other})
        assert snapshot()['routing']['pending']
        saved = library.read_bytes()
        calls = js('return window.__proxyCredentials.calls.restartVpnCredentials||0')
        fill_new()
        click('#vpn-credentials-submit')
        wait_for('return !document.querySelector("#vpn-credentials-cancel")')
        new_session = until(connected)['sessionId']
        until(lambda: len(accepted_ovpn()) == 1)
        replacement = current_core()
        until(lambda: not Path('/proc', str(worker['pid'])).exists())
        check(js('return window.__proxyCredentials.calls.restartVpnCredentials===arguments[0]+1', calls)
              and replacement != worker and new_session != old['sessionId'],
              'one native Reconnect reaps the old core and reaches real OpenVPN connected with new temporary credentials in a fresh session')
        held.close()
        held = socket_open()
        check(echo(held) and traffic('replaced') and retained(old_lease, applied),
              'successful replacement keeps exact GNOME values and original journal bytes/inode/mtime and locked lease while fresh resolved HTTP succeeds')
        check(library.read_bytes() == saved and otp() == otp_before and snapshot()['running'] == ovpn
              and snapshot()['selected'] == other and snapshot()['routing']['pending']
              and command('settings')['core']['singbox_tcp_keep_alive_idle'] == 77,
              'replacement uses frozen routing and source while Library, unbound HOTP, another selection and pending settings remain exact')
        held.close()
        held = None
        fd = os.pidfd_open(replacement['pid'])
        try:
            assert current_core() == replacement
            signal.pidfd_send_signal(fd, signal.SIGKILL, None, 0)
        finally:
            os.close(fd)
        audit['kills'].append(replacement)
        until(lambda: snapshot()['vpn']['sessionId'] not in (None, new_session))
        recovered = until(connected)['sessionId']
        until(lambda: len(accepted_ovpn()) == 2)
        recovered_core = current_core()
        held = socket_open()
        check(recovered_core != replacement and recovered != new_session and echo(held) and traffic('recovered'),
              'SIGKILL of only the verified owned child recovers a new core with committed NEW credentials and genuine OpenVPN connected')
        retained_after_recovery = retained(old_lease, applied)
        library_after_recovery, otp_after_recovery, state_after_recovery = library.read_bytes(), otp(), snapshot()
        invariant_bits = {'retained': retained_after_recovery, 'library': library_after_recovery == saved,
            'otp': otp_after_recovery == otp_before, 'selected': state_after_recovery['selected'] == other,
            'pending': state_after_recovery['routing']['pending']}
        saved_json, current_json = json.loads(saved), json.loads(library_after_recovery)
        audit['recoveryInvariant'] = {'checks': invariant_bits,
            'expectedLibrarySha256': hashlib.sha256(saved).hexdigest(),
            'observedLibrarySha256': hashlib.sha256(library_after_recovery).hexdigest(),
            'changedTopLevelFields': [key for key in sorted(set(saved_json) | set(current_json)) if saved_json.get(key) != current_json.get(key)],
            'expectedOtpCounter': otp_before['counter'], 'observedOtpCounter': otp_after_recovery['counter'],
            'expectedSelected': other, 'observedSelected': state_after_recovery['selected'],
            'routing': state_after_recovery['routing']}
        check(all(invariant_bits.values()),
              'automatic recovery retains the same original GNOME journal and user/effective values without losing pending settings or touching HOTP')
        check(stale('cancelVpnCredentials', edit) and stale('restartVpnCredentials', {**edit, 'username': NEW_USERNAME, 'password': NEW_PASSWORD})
              and echo(held) and snapshot()['vpn']['sessionId'] == recovered,
              'old Cancel and Restart identities cannot act on the recovered connection')
        held.close()
        held = None
        command('disconnect')
        check(disconnected() and library.read_bytes() == saved and otp() == otp_before,
              'Disconnect restores exact prior GNOME user/default values and releases journal/flock without rewriting saved data')
        current = command('settings')['core']
        command('saveSettings', {'section': 'core', 'previous': current, 'values': initial_core})
        current_route = command('routing')
        command('saveRouting', {**current_route, 'active': applied_route['active'], 'profiles': applied_route['profiles']})

        command('connect', {'id': oc})
        oc_old = terminal()
        oc_core = current_core()
        oc_lease, oc_applied = lease(), settings()
        assert_expected_apply(oc_applied, previous, proxy_port, 'initial-openconnect')
        request_count = len(events('openconnect'))
        for _ in range(12):
            snapshot()
            time.sleep(.12)
        check(any(row.get('oldExact') and row.get('httpStatus') == 403 for row in events('openconnect'))
              and any(row['event'] == 'initial-lockout' for row in events('openconnect'))
              and len(events('openconnect')) == request_count,
              'real OpenConnect POST403 and init403 reach terminal authFailed, with no additional HTTPS request during twelve quiet polls')
        open_dialog(oc_old)
        saved = library.read_bytes()
        fill_new()
        click('#vpn-credentials-submit')
        wait_for('return !document.querySelector("#vpn-credentials-cancel")')
        until(lambda: any(row.get('newExact') and row.get('accepted') for row in events('openconnect')))
        def form():
            value = snapshot()['vpn']
            row = next((row for row in value['endpoints'] if row['tag'] == 'proxy' and row['challengeId']), None)
            return row and {'sessionId': value['sessionId'], 'endpointTag': 'proxy', 'challengeId': row['challengeId']}
        request = until(form)
        details = command('vpnChallenge', request)
        final_core = current_core()
        check([row['name'] for row in details['fields']] == ['operator_note']
              and request['sessionId'] != oc_old['sessionId'] and final_core != oc_core,
              'native OpenConnect replacement delivers exact NEW credentials with spaces and reaches a genuine operator-only form without claiming CSTP')
        check(retained(oc_lease, oc_applied) and traffic('openconnect-form') and library.read_bytes() == saved and otp() == otp_before,
              'OpenConnect replacement retains exact journal and settings while direct resolved HTTP works and persistence remains unchanged')
        request_count = len(events('openconnect'))
        command('cancelVpnChallenge', request)
        until(lambda: any(row['tag'] == 'proxy' and row['state'] == 'error' and not row['challengeId'] for row in snapshot()['vpn']['endpoints']))
        time.sleep(2.2)
        check(current_core() == final_core and len(events('openconnect')) == request_count and retained(oc_lease, oc_applied),
              'existing challenge Cancel ends the form without replacing the core, repeating HTTPS login or rewriting system proxy ownership')
        exposed = [snapshot(), command('getLogs', {}), command('exportProfiles',
            {'ids': [ovpn, oc], 'format': 'profiles', 'destination': 'preview'})['text']]
        forbidden = [NEW_USERNAME, NEW_USERNAME.strip(), NEW_PASSWORD, NEW_PASSWORD.strip(), *tokens]
        check(all(safe(value) for value in exposed) and all(item not in library.read_text() for item in forbidden),
              'private session credentials and edit tokens are absent from public metadata, logs, exports and saved Library')
        command('disconnect')
        assert disconnected()

        command('connect', {'id': ovpn})
        old = terminal()
        worker = current_core()
        edit = open_dialog(old)
        held = socket_open()
        saved, before = library.read_bytes(), snapshot()
        subprocess.run(['gsettings', 'set', 'org.gnome.system.proxy.http', 'host', 'foreign.proxy.test'], check=True)
        def foreign_applied():
            return settings()[keys.index((schemas[1], 'host'))] == ("'foreign.proxy.test'", "'foreign.proxy.test'")
        until(foreign_applied)
        foreign = settings()
        foreign_keyfile = fingerprint(keyfile)
        before_accepts = len(accepted_ovpn())
        fill_new()
        click('#vpn-credentials-submit')
        wait_for('return !!document.querySelector("#vpn-credentials-error")?.textContent.trim()')
        notice = js('return document.querySelector("#vpn-credentials-error").textContent')
        audit['foreignNotice'] = notice
        check(notice == 'The system proxy was changed outside Thronium. Retrying sign-in was stopped and those settings were preserved.'
              and safe(notice, True) and current_core() == worker and echo(held)
              and settings() == foreign and fingerprint(keyfile) == foreign_keyfile and not journal.exists() and not leased()
              and snapshot()['vpn']['sessionId'] == old['sessionId'] and snapshot()['since'] == before['since']
              and library.read_bytes() == saved and len(accepted_ovpn()) == before_accepts,
              'external private gsettings change before native Submit refuses replacement with a safe notice and preserves foreign values, old core and held CONNECT without reacquisition')
        close_dialog()
        held.close()
        held = None
        command('disconnect')
        check(settings() == foreign and fingerprint(keyfile) == foreign_keyfile and not journal.exists() and not leased() and snapshot()['running'] is None,
              'Disconnect after lost ownership preserves the whole externally changed proxy values without applying the previous baseline')
        restore(previous)
        command('connect', {'id': ovpn})
        terminal()
        quit_core = current_core()
        assert leased() and journal.exists()
        saved = library.read_bytes()
        audit['beforeCheckedQuit'] = {'core': quit_core, 'oldStoredCredentialsAgainTerminal': True, 'hotpCounter': otp()['counter']}
        menu.activate(menu.ready('Quit'))
        until(lambda: not Path('/proc', str(menu.pid)).exists())
        exited = True
        h['closed_session'] = True
        until(lambda: not Path('/proc', str(quit_core['pid'])).exists())
        until(lambda: settings() == previous and not journal.exists() and not leased())
        check(library.read_bytes() == saved and not nodes(),
              'native checked Quit restores exact baseline and releases journal/lease, reaps owned app/core and preserves stored credentials and HOTP')
        audit['authenticationObservations'] = {'openvpnAccepted': len(accepted_ovpn()),
            'openconnectExactNew': len([row for row in events('openconnect') if row.get('newExact') and row.get('accepted')])}
    finally:
        with contextlib.suppress(Exception):
            audit['beforeCleanup'] = {'appExited': exited, 'cores': nodes(),
                'journalExists': journal.exists(), 'leased': leased(), 'gnomeValues': settings()}
        if held is not None:
            held.close()
        if not exited:
            with contextlib.suppress(Exception):
                js('const u=document.querySelector("#vpn-credentials-username");if(u)u.style.color="transparent"')
                h['screenshot']('vpn-credentials-system-proxy-failure-before-cleanup')
            with contextlib.suppress(Exception):
                js('if(window.__proxyCredentials){window.fetch=window.__proxyCredentials.original;delete window.__proxyCredentials;}')
                command('disconnect')
        restore(original)
        origin.shutdown()
        origin.server_close()
        http_origin.shutdown()
        http_origin.server_close()
        (h['artifacts'] / 'vpn-credentials-system-proxy-audit.json').write_text(json.dumps(audit, indent=2) + '\n')
