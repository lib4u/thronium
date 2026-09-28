"""Real managed worker auth, epoch refusal and cleanup in a private namespace."""
import contextlib
import copy
import http.client
import json
import os
from pathlib import Path
import select as socket_select
import signal
import socket
import socketserver
import subprocess
import threading
import time
from native_menu import NativeMenu
from native_processes import core_pids
from vpn_auth_fixture import USER, PASSWORD, ANSWER, FORM_USER, FORM_PASSWORD, FORM_ANSWER


def run(h):
    command, click, fill, select, wait_for, js, check = (h[k] for k in ('command', 'click', 'fill', 'select', 'wait_for', 'js', 'check'))
    ns = {kind: os.readlink('/proc/self/ns/' + kind) for kind in ['net', 'mnt', 'user']}
    assert os.geteuid() == 0 and all(value != os.environ['THRONIUM_TEST_ORIGINAL_' + kind.upper() + 'NS'] for kind, value in ns.items())
    assert not Path('/run/dbus/system_bus_socket').exists()
    ready = json.loads(Path(os.environ['_THRONIUM_VPN_AUTH_READY']).read_text())
    app = Path(h['args'].application).resolve()
    core = app.with_name('ThroniumCore')
    menu = NativeMenu()
    assert Path('/proc', str(menu.pid), 'exe').resolve() == app
    assert os.readlink('/proc/' + str(menu.pid) + '/ns/net') == ns['net']
    initial = command('snapshot')
    routing = command('routing')
    geometry = h['request']('GET', h['base'] + '/window/rect')
    xdg = Path(os.environ['XDG_DATA_HOME'])
    assert xdg.parent.name.startswith('thronium-native-test-')
    library = xdg / 'io.thronium.desktop/library.json'
    audit = {'states': [], 'kills': [], 'staleRefusals': [], 'namespaces': ns, 'hostPolkitTested': False, 'controlled': []}
    secrets = [USER, PASSWORD, ANSWER, FORM_USER, FORM_PASSWORD, FORM_ANSWER]
    ids, held, exited = [], None, False
    group = command('saveGroup', {'name': 'Managed auth namespace fixtures', 'subscription': None})['id']

    def until(predicate, timeout=15):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(.07)
        raise AssertionError('Managed auth condition timed out')

    def safe(value):
        return all(secret not in (value if isinstance(value, str) else json.dumps(value)) for secret in secrets)

    def ip(*args):
        return json.loads(subprocess.check_output(['ip', '-j', *args], text=True))

    def network():
        return {'links': [(v['ifindex'], v['ifname']) for v in ip('link')], 'rules4': ip('-4', 'rule'),
                'rules6': ip('-6', 'rule'), 'routes4': ip('-4', 'route', 'show', 'table', 'all'),
                'routes6': ip('-6', 'route', 'show', 'table', 'all')}

    baseline = network()

    def lease_available():
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as lease:
            try:
                lease.bind('\0thronium-tun-18900')
                return True
            except OSError:
                return False

    def journals():
        return {str(path): path.read_bytes() for path in Path('/run/thronium-tun').glob('net-*.json')}

    def snapshot():
        value = command('snapshot')
        assert safe(value), 'Private auth answer in public snapshot'
        audit['states'].append({'phase': value['phase'], 'running': value['running'], 'vpn': value['vpn']})
        return value

    def endpoint(state='auth-pending', tag='proxy'):
        return until(lambda: next((row for row in snapshot()['vpn']['endpoints'] if row['tag'] == tag and row['state'] == state), None))

    def request(tag='proxy'):
        def current():
            value = snapshot()['vpn']
            row = next((row for row in value['endpoints'] if row['tag'] == tag and row['challengeId']), None)
            return row and {'sessionId': value['sessionId'], 'endpointTag': tag, 'challengeId': row['challengeId']}
        return until(current)

    def stale(name, payload):
        try:
            command(name, payload)
        except RuntimeError as error:
            assert 'vpn_auth_stale' in str(error) and safe(str(error))
            audit['staleRefusals'].append(name)
            return True
        raise AssertionError('Old managed request was accepted')

    def sync_ui(current):
        js('''const original=window.fetch;window.__managedSync={original,at:0,want:arguments[0]};window.fetch=function(input,options){let name;try{name=JSON.parse(options?.body||'{}').name}catch{}const result=original.apply(this,arguments);if(name==='snapshot')result.then(r=>r.clone().json()).then(v=>{const s=window.__managedSync;if(s&&v.vpn?.sessionId===s.want.sessionId&&v.vpn.endpoints.some(e=>e.tag===s.want.endpointTag&&e.challengeId===s.want.challengeId))s.at=Date.now();}).catch(()=>{});return result;};''', current)
        try:
            wait_for('return window.__managedSync.at>0&&Date.now()-window.__managedSync.at>50')
        finally:
            js('window.fetch=window.__managedSync.original;delete window.__managedSync')

    def open_auth(tag='proxy'):
        current = request(tag)
        sync_ui(current)
        selector = '[data-vpn-open=' + json.dumps(tag) + ']'
        click(selector if js('return !!document.querySelector(arguments[0])', selector) else '#vpn-auth-open')
        wait_for('return !!document.querySelector("#vpn-auth-form")')
        return current

    def close_auth():
        if js('return !!document.querySelector("#vpn-auth-close")'):
            click('#vpn-auth-close')
            wait_for('return !document.querySelector(".vpn-auth-modal")')

    def add(name, config):
        value = command('saveProfile', {'name': name, 'groupId': group, 'kind': 'sing-box-outbound', 'config': config})['id']
        ids.append(value)
        return value

    def oc(label):
        return {'type': 'openconnect', 'server': 'https://127.0.0.1:' + str(ready['openconnectPort']) + '/form/' + label,
                'flavor': 'anyconnect', 'system': False, 'no_udp': True,
                'tls': {'certificate_authority_path': ready['certificate']}}

    def events(label):
        p = Path(ready['events'])
        return [v for line in p.read_text().splitlines() if (v := json.loads(line))['path'] == '/form/' + label] if p.exists() else []

    def identity(pid):
        process = Path('/proc', str(pid))
        stat = process.joinpath('stat').read_text().rsplit(')', 1)[1].split()
        assert stat[0] not in ('Z', 'X'), 'Owned process is no longer live'
        return {'pid': int(pid), 'ppid': int(stat[1]), 'starttime': int(stat[19])}

    def owned_children(parent):
        children = set()
        for task in Path('/proc', str(parent), 'task').glob('*/children'):
            with contextlib.suppress(OSError):
                children.update(int(pid) for pid in task.read_text().split())
        return sorted(children)

    def worker_pair():
        pairs = []
        for guardian in core_pids(menu.pid):
            g = identity(guardian)
            assert g['ppid'] == menu.pid and Path('/proc', guardian, 'exe').resolve() == core
            # Supervisor execs /proc/self/exe, so worker comm can be 'exe'.
            # Scope by owned parent plus executable identity, never by name.
            for child in owned_children(int(guardian)):
                if Path('/proc', str(child), 'exe').resolve() != core:
                    continue
                w = identity(child)
                assert w['ppid'] == int(guardian)
                assert os.readlink('/proc/' + str(child) + '/ns/net') == ns['net']
                pairs.append((g, w))
        assert len(pairs) == 1, 'Expected one owned guardian/worker pair'
        return pairs[0]

    def kill_worker():
        guardian, worker = worker_pair()
        fd = os.pidfd_open(worker['pid'])
        try:
            assert identity(worker['pid']) == worker
            signal.pidfd_send_signal(fd, signal.SIGKILL, None, 0)
        finally:
            os.close(fd)
        audit['kills'].append({'guardian': guardian, 'worker': worker})
        return guardian, worker

    def active_network():
        return socket.if_nametoindex('thronium-tun') > 0 and bool(journals()) and not lease_available()

    def stop():
        close_auth()
        command('disconnect')
        until(lambda: snapshot()['running'] is None)
        until(lambda: network() == baseline and not journals() and lease_available())
        wait_for('return !document.querySelector(".vpn-auth-modal")')

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            with contextlib.suppress(OSError):
                while value := self.request.recv(8192):
                    self.request.sendall(value)

    socks_observations = []

    class Socks(socketserver.BaseRequestHandler):
        def handle(self):
            def read(n):
                data = b''
                while len(data) < n:
                    chunk = self.request.recv(n - len(data))
                    if not chunk:
                        raise EOFError()
                    data += chunk
                return data
            try:
                self.request.settimeout(5)
                version, count = read(2)
                assert version == 5 and 0 in read(count)
                self.request.sendall(b'\x05\x00')
                version, method, reserved, kind = read(4)
                assert (version, method, reserved, kind) == (5, 1, 0, 1)
                target = socket.inet_ntoa(read(4))
                port = int.from_bytes(read(2), 'big')
                assert (target, port) == ('198.18.0.80', 80)
                self.request.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50')
                header = b''
                while b'\r\n\r\n' not in header:
                    header += read(1)
                assert header.startswith(b'GET /managed-auth-tun ')
                socks_observations.append({'target': target, 'port': port})
                payload = b'OWNED-MANAGED-AUTH-TUN'
                self.request.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(payload)).encode() + b'\r\nConnection: close\r\n\r\n' + payload)
            except (OSError, EOFError, AssertionError):
                return

    socks = Server(('127.0.0.1', 0), Socks)
    threading.Thread(target=socks.serve_forever, daemon=True).start()
    echo = Server(('127.0.0.1', 0), Echo)
    threading.Thread(target=echo.serve_forever, daemon=True).start()
    try:
        command('disconnect')
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0))
            inbound = reserve.getsockname()[1]
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark', 'connectionMode': 'tun',
                               'inboundPort': inbound, 'closeBehavior': 'quit',
                               'tun': {**initial['preferences']['tun'], 'autoReconnect': True, 'requestPermission': False}})
        wait_for('return document.documentElement.lang==="en"')
        check(snapshot()['vpn']['sessionId'] is None and lease_available() and network() == baseline,
              'managed idle metadata does not acquire a TUN lease or change namespace routes')
        invalid = {'sessionId': 'old', 'endpointTag': 'proxy', 'challengeId': 'old'}
        check(stale('vpnChallenge', invalid) and not journals(), 'idle managed auth refuses stale identity without spawning a worker')
        vpn_name = 'Managed OpenVPN — собственный сервер'
        vpn = add(vpn_name, {'type': 'openvpn-client', 'server': '127.0.0.1', 'server_port': ready['openvpnPort'],
                  'network': 'udp', 'system': False, 'static_challenge': 'Synthetic managed answer',
                  'tls': {'certificate_path': ready['certificate'], 'server_name': ready['serverName']}})
        command('connect', {'id': vpn})
        endpoint()
        guardian, worker = worker_pair()
        check(active_network() and snapshot()['vpn']['error'] is None,
              'a real managed supervisor and worker expose OpenVPN auth while owning a namespace TUN and journal')
        before_journal = journals()
        for language in ['ru', 'en']:
            command('preferences', {**snapshot()['preferences'], 'language': language})
            wait_for('return document.documentElement.lang===' + json.dumps(language))
            open_auth()
            h['request']('POST', h['base'] + '/window/rect', {'width': 390, 'height': 844})
            check(js('const d=document.querySelector(".vpn-auth-modal");return d.textContent.includes(arguments[0])&&d.scrollWidth<=d.clientWidth+1&&document.querySelector("#vpn-auth-submit").getBoundingClientRect().bottom<=innerHeight', vpn_name),
                  language + ' managed credentials show the actual profile name and usable actions at 390 pixels')
            h['screenshot']('managed-auth-credentials-' + language + '-390')
            close_auth()
            h['request']('POST', h['base'] + '/window/rect', geometry)
        old = open_auth()
        fill('#vpn-auth-username', USER)
        fill('#vpn-auth-password', PASSWORD)
        fill('#vpn-auth-secret', ANSWER)
        click('#vpn-auth-submit')
        endpoint('connected')
        check(worker_pair() == (guardian, worker) and active_network(), 'native managed Submit establishes a real userspace OpenVPN tunnel in the same worker')
        check(journals() == before_journal and safe(library.read_text()), 'transient managed credentials do not enter the network journal or profile store')
        check(stale('submitVpnChallenge', {**old, 'secret': ANSWER}), 'completed managed OpenVPN challenge cannot be answered twice')
        stop()
        check(network() == baseline and lease_available(), 'Disconnect removes the real TUN, policy routes, journal and exclusive lease')

        form_id = add('Managed HTTPS form', oc('managed-form'))
        command('connect', {'id': form_id})
        first = open_auth()
        details = command('vpnChallenge', first)
        check({f['kind'] for f in details['fields']} == {'text', 'password', 'select'}, 'managed Query returns actual HTTPS text, password and select fields')
        for item in details['fields']:
            value = {'username': FORM_USER, 'password': FORM_PASSWORD, 'realm': 'two'}[item['name']]
            selector = '[data-vpn-field=' + json.dumps(item['submissionKey']) + ']'
            (select if item['kind'] == 'select' else fill)(selector, value)
        click('#vpn-auth-submit')
        second = until(lambda: (value := request())['challengeId'] != first['challengeId'] and value)
        close_auth()
        open_auth()
        details = command('vpnChallenge', second)
        check(events('managed-form')[-1]['formExact'] and len(details['fields']) == 1, 'guarded managed Submit sends exact form values and opens the next real OTP challenge')
        fill('[data-vpn-field=' + json.dumps(details['fields'][0]['submissionKey']) + ']', FORM_ANSWER)
        click('#vpn-auth-submit')
        until(lambda: any(e['otpExact'] for e in events('managed-form')))
        third = until(lambda: (value := request())['challengeId'] != second['challengeId'] and value)
        check(stale('cancelVpnChallenge', first) and stale('submitVpnChallenge', {**second, 'formValues': {}}), 'old managed form and OTP IDs cannot cancel or answer a newer challenge')
        close_auth()
        open_auth()
        click('#vpn-auth-cancel')
        endpoint('error')
        count = len(events('managed-form'))
        time.sleep(2.2)
        check(len(events('managed-form')) == count and not snapshot()['vpn']['endpoints'][0]['challengeId'], 'managed OpenConnect Cancel is terminal without another authentication POST')
        stop()

        restart_id = add('Managed worker generation', oc('managed-restart'))
        command('connect', {'id': restart_id})
        previous = request()
        command('vpnChallenge', previous)
        # Hold a real old automatic App snapshot. Backend execution is unchanged;
        # newer explicit UI refreshes must not be overwritten when it arrives.
        js('''const original=window.fetch;const s=window.__managedOldSnapshot={original,old:arguments[0],held:false,release:null,newSession:null,newAt:0};window.fetch=function(input,options){let name;try{name=JSON.parse(options?.body||'{}').name}catch{}const response=original.apply(this,arguments);if(name!=='snapshot')return response;return response.then(async result=>{const value=await result.clone().json();const session=value.vpn?.sessionId;if(!s.held&&session===s.old){s.held=true;return await new Promise(resolve=>s.release=()=>resolve(result));}if(session&&session!==s.old){s.newSession=session;s.newAt=Date.now();}return result;});};''', previous['sessionId'])
        wait_for('return window.__managedOldSnapshot.held')
        guardian, old_worker = kill_worker()
        current = until(lambda: (value := request())['sessionId'] != previous['sessionId'] and value)
        new_guardian, new_worker = worker_pair()
        check(new_guardian == guardian and new_worker['starttime'] != old_worker['starttime'], 'automatic managed recovery replaces only the owned worker and retains its authorized guardian')
        check(current['challengeId'] == previous['challengeId'], 'the real restarted OpenConnect worker reuses its challenge ID, exercising generation isolation')
        count = len(events('managed-restart'))
        check(stale('vpnChallenge', previous) and stale('submitVpnChallenge', {**previous, 'formValues': {}}) and stale('cancelVpnChallenge', previous), 'old session cannot Query, Submit or Cancel the repeated challenge ID on a replacement worker')
        check(len(events('managed-restart')) == count and request() == current, 'stale generation requests send no HTTPS authentication response and preserve the new pending challenge')
        # A real favorite click invokes App.perform -> refresh while the periodic
        # poll awaits its old response. Clicking the profile row would reconnect.
        button = '.connection-row:has([data-profile-menu=' + json.dumps(restart_id) + ']) .favorite-button'
        js('window.__managedOldSnapshot.newAt=0;window.__managedOldSnapshot.newSession=null')
        click(button)
        wait_for('return window.__managedOldSnapshot.newSession===' + json.dumps(current['sessionId']) + '&&Date.now()-window.__managedOldSnapshot.newAt>100')
        click('#vpn-auth-open')
        key = json.dumps([current['sessionId'], current['endpointTag'], current['challengeId']], separators=(',', ':'))
        wait_for('return document.querySelector("[data-vpn-auth-key]")?.dataset.vpnAuthKey===' + json.dumps(key) + '&&!!document.querySelector("#vpn-auth-form")')
        details = command('vpnChallenge', current)
        draft_field = next(f for f in details['fields'] if f['kind'] in ('text', 'password'))
        selector = '[data-vpn-field=' + json.dumps(draft_field['submissionKey']) + ']'
        fill(selector, FORM_ANSWER)
        js('''const s=window.__managedOldSnapshot;s.expectedKey=arguments[0];s.lost=false;s.observer=new MutationObserver(()=>{if(document.querySelector('[data-vpn-auth-key]')?.dataset.vpnAuthKey!==s.expectedKey||!document.querySelector('#vpn-auth-form'))s.lost=true;});s.observer.observe(document.body,{subtree:true,childList:true});s.release();''', key)
        time.sleep(1.3)
        check(js('return !window.__managedOldSnapshot.lost&&document.querySelector(arguments[0])?.value===arguments[1]', selector, FORM_ANSWER) and request() == current,
              'a delayed genuine snapshot from the old worker cannot replace the new managed form or erase its typed draft after a newer UI refresh')
        audit['controlled'].append('actual old automatic snapshot delivery held across worker restart; native favorite action causes newer App refresh; old response released after typing in new session')
        js('const s=window.__managedOldSnapshot;s.observer.disconnect();window.fetch=s.original;delete window.__managedOldSnapshot')
        stop()

        auxiliary = add('Independent managed OpenConnect endpoint', oc('managed-aux'))
        direct = add('Managed direct traffic', {'type': 'direct', 'udp_fragment': True})
        changed = copy.deepcopy(command('routing'))
        active = next(p for p in changed['profiles'] if p['id'] == changed['active'])
        active['mode'] = 'rules'
        active['rules'] = [{'id': 'auth-unused-aux', 'name': 'Unrequested auxiliary path', 'enabled': True,
                           'config': {'domain': ['never-requested.fixture.invalid'], 'outbound': 'profile:' + auxiliary}}]
        command('saveRouting', changed)
        command('connect', {'id': direct})
        state = snapshot()
        tag = until(lambda: next((e['tag'] for e in snapshot()['vpn']['endpoints'] if e['protocol'] == 'openconnect'), None))
        endpoint(tag=tag)
        held = socket.create_connection(('127.0.0.1', inbound), timeout=5)
        target = '127.0.0.1:' + str(echo.server_address[1])
        held.sendall(f'CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n'.encode())
        header = b''
        while b'\r\n\r\n' not in header:
            header += held.recv(4096)
        assert b' 200 ' in header
        pair = worker_pair()
        open_auth(tag)
        click('#vpn-auth-cancel')
        endpoint('error', tag)
        held.sendall(b'managed-auth-independent-traffic')
        check(held.recv(128) == b'managed-auth-independent-traffic' and worker_pair() == pair and snapshot()['since'] == state['since'],
              'Cancel of a managed auxiliary VPN endpoint preserves a real held direct HTTP CONNECT and worker identity')
        held.close()
        held = None
        stop()
        tun_path = add('Managed actual kernel packet path', {'type': 'socks', 'server': '127.0.0.1',
                       'server_port': socks.server_address[1], 'version': '5'})
        command('connect', {'id': tun_path})
        tag = until(lambda: next((e['tag'] for e in snapshot()['vpn']['endpoints'] if e['protocol'] == 'openconnect'), None))
        endpoint(tag=tag)
        before_pair = worker_pair()
        open_auth(tag)
        click('#vpn-auth-cancel')
        endpoint('error', tag)
        client = http.client.HTTPConnection('198.18.0.80', 80, timeout=8)
        try:
            # No HTTP proxy here: the socket is captured by the namespace TUN.
            client.request('GET', '/managed-auth-tun')
            response = client.getresponse()
            received = response.status == 200 and response.read() == b'OWNED-MANAGED-AUTH-TUN'
        finally:
            client.close()
        check(received and len(socks_observations) == 1 and active_network() and worker_pair() == before_pair,
              'after auxiliary Cancel an ordinary socket crosses the actual namespace TUN and reaches the owned SOCKS/HTTP responder')
        audit['actualTunHttp'] = socks_observations
        stop()
        current_routing = command('routing')
        command('saveRouting', {**current_routing, 'active': routing['active'], 'profiles': routing['profiles']})
        check(safe(library.read_text()) and safe(command('getLogs')), 'managed answers remain absent from persisted profiles and application logs')
        command('connect', {'id': vpn})
        open_auth()
        fill('#vpn-auth-secret', ANSWER)
        stored = library.read_bytes()
        pair = worker_pair()
        menu.activate(menu.ready('Quit'))
        until(lambda: not Path('/proc', str(menu.pid)).exists())
        exited = True
        h['closed_session'] = True
        until(lambda: all(not Path('/proc', str(node['pid'])).exists() for node in pair))
        check(network() == baseline and not journals() and lease_available() and library.read_bytes() == stored,
              'native Quit cancels managed auth, reaps supervisor/worker and restores exact namespace routes and lease without saving answers')
    finally:
        if held:
            held.close()
        if not exited:
            with contextlib.suppress(Exception):
                js('if(window.__managedOldSnapshot){const s=window.__managedOldSnapshot;s.observer?.disconnect();window.fetch=s.original;s.release?.();delete window.__managedOldSnapshot;}')
                close_auth()
                command('disconnect')
                current_routing = command('routing')
                command('saveRouting', {**current_routing, 'active': routing['active'], 'profiles': routing['profiles']})
                command('deleteGroup', {'id': group, 'deleteProfiles': True})
                command('preferences', initial['preferences'])
                h['request']('POST', h['base'] + '/window/rect', geometry)
        echo.shutdown()
        echo.server_close()
        socks.shutdown()
        socks.server_close()
        (h['artifacts'] / 'managed-auth-audit.json').write_text(json.dumps(audit, indent=2) + '\n')
