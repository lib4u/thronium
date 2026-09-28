"""Actual managed credential replacement in disposable user/net/mount namespaces.

The browser exercises successful transactions and checked cleanup. Lost wire
acknowledgements and failed cleanup are separate Core/Engine tests, not simulated
by delaying a browser response here.
"""
import contextlib
import copy
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import subprocess
import threading
import time

from native_menu import NativeMenu
from native_processes import core_pids
from vpn_credentials_fixture import OLD_USERNAME, OLD_PASSWORD, NEW_USERNAME, NEW_PASSWORD
from vpn_otp_fixture import SECRET


def run(h):
    command, click, fill, wait_for, js, check = (h[k] for k in ('command', 'click', 'fill', 'wait_for', 'js', 'check'))
    ns = {kind: os.readlink('/proc/self/ns/' + kind) for kind in ['net', 'mnt', 'user']}
    assert os.geteuid() == 0 and all(value != os.environ['THRONIUM_TEST_ORIGINAL_' + kind.upper() + 'NS'] for kind, value in ns.items())
    assert not Path('/run/dbus/system_bus_socket').exists()
    ready = json.loads(Path(os.environ['_THRONIUM_VPN_CREDENTIALS_READY']).read_text())
    app = Path(h['args'].application).resolve()
    core = app.with_name('ThroniumCore')
    menu = NativeMenu()
    assert Path('/proc', str(menu.pid), 'exe').resolve() == app
    assert os.readlink('/proc/' + str(menu.pid) + '/ns/net') == ns['net']
    initial = command('snapshot')
    initial_route = command('routing')
    initial_core = command('settings')['core']
    geometry = h['request']('GET', h['base'] + '/window/rect')
    data = Path(os.environ['XDG_DATA_HOME'])
    assert data.parent.name.startswith('thronium-native-test-')
    library = data / 'io.thronium.desktop/library.json'
    group = command('saveGroup', {'name': 'Managed temporary VPN credentials', 'subscription': None})['id']
    audit = {'namespaces': ns, 'states': [], 'kills': [], 'refusals': [], 'layout': {},
             'hostPolkitTested': False, 'openconnectCstpConnectedClaimed': False,
             'openvpnPayloadTested': False, 'wireLostAckTested': False,
             'failedCleanupQuitTested': False, 'hiddenWithoutPollingTested': False}
    tokens, otp_id, held, exited = [], None, None, False

    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            with contextlib.suppress(OSError):
                while value := self.request.recv(4096):
                    self.request.sendall(value)

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    origin = Server(('127.0.0.1', 0), Echo)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    port = origin.server_address[1]

    def until(predicate, timeout=25):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            value = predicate()
            if value:
                return value
            time.sleep(.07)
        raise AssertionError('managed credentials condition timed out')

    def ip(*args):
        return json.loads(subprocess.check_output(['ip', '-j', *args], text=True))

    def network():
        return {'links': [(row['ifindex'], row['ifname']) for row in ip('link')],
                'rules4': ip('-4', 'rule'), 'rules6': ip('-6', 'rule'),
                'routes4': ip('-4', 'route', 'show', 'table', 'all'),
                'routes6': ip('-6', 'route', 'show', 'table', 'all')}

    baseline = network()

    def journals():
        return {str(path): path.read_bytes() for path in Path('/run/thronium-tun').glob('net-*.json')}

    def lease_available():
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as lease:
            try:
                lease.bind('\0thronium-tun-18900')
                return True
            except OSError:
                return False

    def active_network():
        return socket.if_nametoindex('thronium-tun') > 0 and bool(journals()) and not lease_available()

    def identity(pid):
        row = Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()
        assert row[0] not in ('Z', 'X')
        return {'pid': int(pid), 'ppid': int(row[1]), 'starttime': int(row[19])}

    def pair():
        pairs = []
        for pid in core_pids(menu.pid):
            guardian = identity(pid)
            assert guardian['ppid'] == menu.pid and Path('/proc', str(pid), 'exe').resolve() == core
            children = set()
            for task in Path('/proc', str(pid), 'task').glob('*/children'):
                with contextlib.suppress(OSError):
                    children.update(int(child) for child in task.read_text().split())
            for child in children:
                if Path('/proc', str(child), 'exe').resolve() == core:
                    worker = identity(child)
                    assert worker['ppid'] == int(pid)
                    assert os.readlink('/proc/' + str(child) + '/ns/net') == ns['net']
                    pairs.append((guardian, worker))
        assert len(pairs) == 1, 'expected exactly one owned guardian/worker'
        return pairs[0]

    def safe(value, include_saved=False):
        text = value if isinstance(value, str) else json.dumps(value)
        forbidden = [SECRET, NEW_USERNAME, NEW_USERNAME.strip(), NEW_PASSWORD, NEW_PASSWORD.strip(), *tokens]
        if include_saved:
            forbidden += [OLD_USERNAME, OLD_PASSWORD]
        return all(item not in text for item in forbidden)

    def snapshot():
        value = command('snapshot')
        assert safe(value, True), 'public snapshot contains private credentials or edit token'
        audit['states'].append({key: value[key] for key in ['running', 'selected', 'phase', 'since', 'vpn', 'routing']})
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
        target = '127.0.0.1:' + str(port)
        sock.sendall(f'CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n'.encode())
        response = b''
        while b'\r\n\r\n' not in response:
            value = sock.recv(4096)
            assert value, 'owned direct CONNECT closed before response'
            response += value
        assert b' 200 ' in response, 'owned direct route did not open'
        return sock

    def echo(sock):
        sock.sendall(b'owned-managed-credential-route')
        return sock.recv(128) == b'owned-managed-credential-route'

    def ui_current(request):
        js('window.__managedCredentials.match=arguments[0];window.__managedCredentials.matchedAt=0', request)
        wait_for('return window.__managedCredentials.matchedAt>0&&Date.now()-window.__managedCredentials.matchedAt>80')

    def open_dialog(request):
        click('.primary-nav button:first-child')
        wait_for('return !!document.querySelector(".add-connection")')
        ui_current(request)
        click('[data-vpn-credentials=proxy]')
        wait_for('return !!document.querySelector("#vpn-credentials-username:not(:disabled)")')
        view = js('return window.__managedCredentials.lastView')
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
        raise AssertionError('old managed credential token was accepted')

    try:
        command('disconnect')
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark', 'connectionMode': 'tun'})
        wait_for('return document.documentElement.lang==="en"')
        otp_id = command('otpSave', {'value': {'name': 'Managed retry must not spend HOTP', 'issuer': 'Owned namespace',
            'secret': SECRET, 'algorithm': 'SHA1', 'type': 'hotp', 'digits': 6, 'period': 30, 'counter': '19'}})['id']
        otp_before = otp()
        ovpn = add('Managed OpenVPN temporary credentials', ready['openvpn'])
        oc = add('Managed OpenConnect temporary credentials', ready['openconnect'])
        other = add('Different selected profile', {'type': 'block'})
        direct_rule = {'id': 'managed-credentials-loopback', 'name': 'Owned direct fixture', 'enabled': True,
            'config': {'ip_cidr': ['127.0.0.1/32'], 'port': [port], 'outbound': 'direct'}}
        command('saveRouting', route_value([direct_rule]))
        applied_route = command('routing')
        js('''const original=window.fetch;const s=window.__managedCredentials={original,calls:{},lastView:null,match:null,matchedAt:0};
            window.fetch=function(input,options){let name=null;try{if(String(input).includes('/app_command'))name=JSON.parse(options?.body||'{}').name}catch{}
                if(name)s.calls[name]=(s.calls[name]||0)+1;const promise=original.apply(this,arguments);
                if(name!=='vpnCredentials'&&name!=='snapshot')return promise;
                return promise.then(async response=>{let value;try{value=await response.clone().json()}catch{return response}
                    if(name==='snapshot'&&s.match&&value.vpn?.sessionId===s.match.sessionId&&value.vpn.endpoints.some(e=>e.tag===s.match.endpointTag&&e.state==='error'&&e.authFailed&&!e.challengeId))s.matchedAt=Date.now();
                    if(name==='vpnCredentials'&&value.editToken)s.lastView=value;return response;});};''')
        command('connect', {'id': ovpn})
        old = terminal()
        guardian, worker = pair()
        check(snapshot()['phase'] == 'error' and active_network(),
              'a real managed OpenVPN worker reaches terminal plain-password authFailed while namespace TUN, journal and lease remain active')
        held = socket_open()
        stored, before_journal, before_network, before = library.read_bytes(), journals(), network(), snapshot()
        edit = open_dialog(old)
        check(js('return document.querySelector("#vpn-credentials-username").value===arguments[0]&&document.querySelector("#vpn-credentials-password").value===""&&document.querySelector("#vpn-credentials-password").type==="password"', OLD_USERNAME)
              and pair() == (guardian, worker) and library.read_bytes() == stored,
              'managed details uses the real browser IPC contract with saved username and an empty masked password without replacing its worker')
        fill_new()
        close_dialog()
        check(echo(held) and pair() == (guardian, worker) and snapshot()['vpn']['sessionId'] == old['sessionId']
              and snapshot()['since'] == before['since'] and library.read_bytes() == stored and otp() == otp_before
              and journals() == before_journal and network() == before_network,
              'native Cancel retains the held direct CONNECT, exact managed session, worker, journal, network and stored HOTP')
        check(stale('restartVpnCredentials', {**edit, 'username': NEW_USERNAME, 'password': NEW_PASSWORD}) and echo(held),
              'a cancelled managed edit token cannot start a replacement or disturb the held connection')

        for language in ['ru', 'en']:
            prefs = snapshot()['preferences']
            command('preferences', {**prefs, 'language': language})
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
                  language + ' managed credentials dialog fits 390px with both actions visible and no horizontal body overflow')
            h['screenshot']('vpn-credentials-managed-' + language + '-390')
            close_dialog()
            h['request']('POST', h['base'] + '/window/rect', geometry)

        edit = open_dialog(old)
        command('saveRouting', route_value([{'id': 'managed-credentials-pending-deny', 'name': 'Saved pending rejection',
            'enabled': True, 'config': {'network': 'tcp', 'action': 'reject'}}]))
        current_core = command('settings')['core']
        command('saveSettings', {'section': 'core', 'previous': current_core,
            'values': {**current_core, 'singbox_tcp_keep_alive_idle': 77}})
        command('select', {'id': other})
        assert snapshot()['routing']['pending']
        saved = library.read_bytes()
        before_calls = js('return window.__managedCredentials.calls.restartVpnCredentials||0')
        fill_new()
        click('#vpn-credentials-submit')
        wait_for('return !document.querySelector("#vpn-credentials-cancel")')
        new_session = until(connected)['sessionId']
        until(lambda: len(accepted_ovpn()) == 1)
        new_guardian, new_worker = pair()
        until(lambda: not Path('/proc', str(worker['pid'])).exists())
        check(js('return window.__managedCredentials.calls.restartVpnCredentials===arguments[0]+1', before_calls)
              and new_guardian == guardian and new_worker != worker and new_session != old['sessionId'] and active_network(),
              'native Reconnect acknowledges one actual managed transaction, reaps its old worker and reaches OpenVPN connected in a new session under the same guardian')
        held.close()
        held = socket_open()
        check(echo(held) and library.read_bytes() == saved and otp() == otp_before
              and snapshot()['running'] == ovpn and snapshot()['selected'] == other and snapshot()['routing']['pending']
              and command('settings')['core']['singbox_tcp_keep_alive_idle'] == 77,
              'exact temporary credentials preserve stored profiles and HOTP while the frozen direct route works despite saved pending rejection, changed settings and another selection')

        held.close()
        held = None
        fd = os.pidfd_open(new_worker['pid'])
        try:
            assert identity(new_worker['pid']) == new_worker
            signal.pidfd_send_signal(fd, signal.SIGKILL, None, 0)
        finally:
            os.close(fd)
        audit['kills'].append({'guardian': new_guardian, 'worker': new_worker})
        until(lambda: snapshot()['vpn']['sessionId'] not in (None, new_session))
        recovered = until(connected)['sessionId']
        until(lambda: len(accepted_ovpn()) == 2)
        recovered_guardian, recovered_worker = pair()
        held = socket_open()
        check(recovered_guardian == guardian and recovered_worker != new_worker and recovered != new_session
              and echo(held) and active_network() and library.read_bytes() == saved and otp() == otp_before,
              'killing only the verified owned worker recovers with the committed temporary credentials and a fresh session, without reverting to stored rejected credentials')
        check(stale('cancelVpnCredentials', edit) and stale('restartVpnCredentials', {**edit, 'username': NEW_USERNAME, 'password': NEW_PASSWORD})
              and echo(held) and snapshot()['vpn']['sessionId'] == recovered,
              'pre-replacement Cancel and Restart cannot act on the recovered worker or break its held direct CONNECT')
        held.close()
        held = None
        command('disconnect')
        until(lambda: network() == baseline and not journals() and lease_available())
        current_core = command('settings')['core']
        command('saveSettings', {'section': 'core', 'previous': current_core, 'values': initial_core})
        current_route = command('routing')
        command('saveRouting', {**current_route, 'active': applied_route['active'], 'profiles': applied_route['profiles']})
        command('connect', {'id': oc})
        oc_old = terminal()
        oc_guardian, oc_worker = pair()
        request_count = len(events('openconnect'))
        for _ in range(12):
            snapshot()
            time.sleep(.12)
        check(any(row.get('oldExact') and row.get('httpStatus') == 403 for row in events('openconnect'))
              and any(row['event'] == 'initial-lockout' for row in events('openconnect'))
              and len(events('openconnect')) == request_count and active_network(),
              'managed OpenConnect has a genuine credential POST403 and terminal init403, with no additional HTTPS request during twelve quiet status polls')
        edit = open_dialog(oc_old)
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
        final_guardian, final_worker = pair()
        check([row['name'] for row in details['fields']] == ['operator_note']
              and request['sessionId'] != oc_old['sessionId'] and final_guardian == oc_guardian and final_worker != oc_worker
              and library.read_bytes() == saved and otp() == otp_before and active_network(),
              'a real managed OpenConnect replacement accepts exact new credentials including spaces and reaches its operator-only form without storing the override or claiming CSTP connected')
        request_count = len(events('openconnect'))
        command('cancelVpnChallenge', request)
        until(lambda: any(row['tag'] == 'proxy' and row['state'] == 'error' and not row['challengeId'] for row in snapshot()['vpn']['endpoints']))
        time.sleep(2.2)
        check(pair() == (final_guardian, final_worker) and len(events('openconnect')) == request_count
              and active_network() and otp() == otp_before,
              'existing managed challenge Cancel ends the operator form without replacing its worker, repeating HTTPS login or spending HOTP')
        exposed = [snapshot(), command('getLogs', {}), command('exportProfiles',
            {'ids': [ovpn, oc], 'format': 'profiles', 'destination': 'preview'})['text']]
        # The Library intentionally retains the original stored credentials and
        # OTP key; only temporary values/tokens must be absent from persistence.
        stored_text = library.read_text()
        forbidden = [NEW_USERNAME, NEW_USERNAME.strip(), NEW_PASSWORD, NEW_PASSWORD.strip(), *tokens]
        check(all(safe(value) for value in exposed) and all(item not in stored_text for item in forbidden),
              'temporary credentials and edit tokens are absent from public metadata, ordinary logs, export preview and the saved Library')
        command('disconnect')
        until(lambda: network() == baseline and not journals() and lease_available())
        until(lambda: not Path('/proc', str(final_worker['pid'])).exists())
        check(snapshot()['running'] is None and identity(final_guardian['pid']) == final_guardian and otp() == otp_before,
              'successful managed Disconnect reaps its worker, restores exact namespace routes/rules and releases journal/lease while retaining the idle guardian')
        command('connect', {'id': ovpn})
        terminal()
        quit_guardian, quit_worker = pair()
        assert active_network() and quit_guardian == final_guardian
        saved = library.read_bytes()
        audit['beforeCheckedQuit'] = {'guardian': quit_guardian, 'worker': quit_worker,
            'activeTun': True, 'oldStoredCredentialsAgainTerminal': True, 'hotpCounter': otp()['counter']}
        menu.activate(menu.ready('Quit'))
        until(lambda: not Path('/proc', str(menu.pid)).exists())
        exited = True
        h['closed_session'] = True
        until(lambda: all(not Path('/proc', str(row['pid'])).exists() for row in [quit_guardian, quit_worker]))
        check(network() == baseline and not journals() and lease_available() and library.read_bytes() == saved,
              'native checked Quit from a newly active managed session reaps guardian and worker and restores namespace network without changing saved credentials or HOTP')
        audit['authenticationObservations'] = {'openvpnAccepted': len(accepted_ovpn()),
            'openconnectExactNew': len([row for row in events('openconnect') if row.get('newExact') and row.get('accepted')])}
    finally:
        if held is not None:
            held.close()
        if not exited:
            with contextlib.suppress(Exception):
                js('const u=document.querySelector("#vpn-credentials-username");if(u)u.style.color="transparent"')
                h['screenshot']('vpn-credentials-managed-failure-before-cleanup')
            with contextlib.suppress(Exception):
                js('if(window.__managedCredentials){window.fetch=window.__managedCredentials.original;delete window.__managedCredentials;}')
                command('disconnect')
                command('deleteGroup', {'id': group, 'deleteProfiles': True})
                if otp_id:
                    command('otpRemove', {'id': otp_id, 'revision': otp()['revision']})
                current_core = command('settings')['core']
                command('saveSettings', {'section': 'core', 'previous': current_core, 'values': initial_core})
                current_route = command('routing')
                command('saveRouting', {**current_route, 'active': initial_route['active'], 'profiles': initial_route['profiles']})
                command('preferences', initial['preferences'])
        origin.shutdown()
        origin.server_close()
        (h['artifacts'] / 'vpn-credentials-managed-audit.json').write_text(json.dumps(audit, indent=2) + '\n')
