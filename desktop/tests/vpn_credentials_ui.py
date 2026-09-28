"""Real terminal VPN failures and ephemeral manual credentials in native UI."""
import contextlib
import copy
import json
import os
from pathlib import Path
import socket
import socketserver
import threading
import time

from native_menu import NativeMenu
from native_processes import core_pids
from vpn_credentials_fixture import OLD_USERNAME, OLD_PASSWORD, NEW_USERNAME, NEW_PASSWORD
from vpn_otp_fixture import SECRET


def run(h):
    command, click, fill, wait_for, js, check = (h[k] for k in ('command', 'click', 'fill', 'wait_for', 'js', 'check'))
    ready = json.loads(Path(os.environ['_THRONIUM_VPN_CREDENTIALS_READY']).read_text())
    initial = command('snapshot')
    initial_route = command('routing')
    initial_core = command('settings')['core']
    geometry = h['request']('GET', h['base'] + '/window/rect')
    menu = NativeMenu()
    assert Path('/proc', str(menu.pid), 'exe').resolve() == Path(h['args'].application).resolve()
    data = Path(os.environ['XDG_DATA_HOME'])
    assert data.parent.name.startswith('thronium-native-test-')
    library = data / 'io.thronium.desktop/library.json'
    group = command('saveGroup', {'name': 'Native temporary VPN credentials', 'subscription': None})['id']
    ids, tokens = [], []
    audit = {'states': [], 'refusals': [], 'controlled': [], 'layout': {},
             'openconnectCstpConnectedClaimed': False, 'openvpnPayloadTested': False}
    otp_id, held = None, None

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

    def until(predicate, timeout=16):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            value = predicate()
            if value:
                return value
            time.sleep(.07)
        raise AssertionError('native credentials condition timed out')

    def safe(value, include_saved=False):
        text = value if isinstance(value, str) else json.dumps(value)
        forbidden = [NEW_USERNAME, NEW_PASSWORD, *tokens]
        if include_saved:
            forbidden += [OLD_USERNAME, OLD_PASSWORD]
        return all(item not in text for item in forbidden)

    def snapshot():
        value = command('snapshot')
        assert safe(value, True), 'public snapshot contains private credentials or edit token'
        audit['states'].append({'running': value['running'], 'selected': value['selected'],
            'phase': value['phase'], 'since': value['since'], 'vpn': value['vpn'], 'routing': value['routing']})
        return value

    def events(protocol='openconnect'):
        p = Path(ready['events'])
        return [v for line in p.read_text().splitlines() if (v := json.loads(line))['protocol'] == protocol]

    def add(name, config, kind='sing-box-outbound'):
        config = copy.deepcopy(config)
        if kind == 'sing-box-outbound':
            config.pop('tag', None)
        value = command('saveProfile', {'name': name, 'groupId': group, 'kind': kind, 'config': config})['id']
        ids.append(value)
        return value

    def route_value(rules):
        value = copy.deepcopy(command('routing'))
        active = next(row for row in value['profiles'] if row['id'] == value['active'])
        active['mode'] = 'rules'
        active['rules'] = rules
        return value

    def restore_route():
        value = command('routing')
        command('saveRouting', {**value, 'active': initial_route['active'], 'profiles': initial_route['profiles']})

    def terminal(tag='proxy'):
        def observed():
            value = snapshot()
            row = next((r for r in value['vpn']['endpoints'] if r['tag'] == tag), None)
            if row and row['state'] == 'error' and row['authFailed'] and row['challengeId'] is None:
                return {'sessionId': value['vpn']['sessionId'], 'endpointTag': tag}
        return until(observed)

    def ui_current(identity):
        # No helper Snapshot during this interval: the observed response must
        # come from the application's automatic poll and then reach React.
        js('window.__credentialsTest.match=arguments[0];window.__credentialsTest.matchedAt=0;', identity)
        wait_for('return window.__credentialsTest.matchedAt>0&&Date.now()-window.__credentialsTest.matchedAt>80')

    def page():
        click('.primary-nav button:first-child')
        wait_for('return !!document.querySelector(".add-connection")')

    def close_dialog():
        click('#vpn-credentials-cancel')
        wait_for('return !document.querySelector("#vpn-credentials-cancel")')

    def open_dialog(identity=None, error=False):
        page()
        identity = identity or terminal()
        ui_current(identity)
        click('[data-vpn-credentials=' + json.dumps(identity['endpointTag']) + ']')
        wait_for('return !!document.querySelector("#vpn-credentials-error")' if error else
                 'return !!document.querySelector("#vpn-credentials-username:not(:disabled)")')
        if error:
            return identity
        view = js('return window.__credentialsTest.lastView')
        assert set(view) == {'sessionId', 'endpointTag', 'editToken', 'username'}
        assert view['sessionId'] == identity['sessionId'] and view['endpointTag'] == identity['endpointTag']
        tokens.append(view['editToken'])
        return {key: view[key] for key in ['sessionId', 'endpointTag', 'editToken']}

    def refusal(name, payload, code):
        try:
            command(name, payload)
        except RuntimeError as error:
            assert code in str(error) and safe(str(error), True), 'unsafe or unexpected credentials refusal'
            audit['refusals'].append({'operation': name, 'code': code})
            return True
        raise AssertionError('credentials command unexpectedly succeeded: ' + name)

    def stop():
        if js('return !!document.querySelector("#vpn-credentials-cancel:not(:disabled)")'):
            close_dialog()
        command('disconnect')
        until(lambda: snapshot()['running'] is None)

    def connect(id):
        stop()
        command('connect', {'id': id})
        return terminal()

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
        sock.sendall(b'owned-temporary-credentials-route')
        return sock.recv(128) == b'owned-temporary-credentials-route'

    def fill_new():
        fill('#vpn-credentials-username', NEW_USERNAME)
        fill('#vpn-credentials-password', NEW_PASSWORD)

    def otp():
        return command('otpGet', {'id': otp_id})

    def unhook():
        js('if(window.__credentialsTest){const s=window.__credentialsTest;window.fetch=s.original;if(s.release)s.release();delete window.__credentialsTest;}')

    try:
        command('disconnect')
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark', 'connectionMode': 'local'})
        wait_for('return document.documentElement.lang==="en"')
        otp_id = command('otpSave', {'value': {'name': 'Unspent credential-retry HOTP', 'issuer': 'Owned fixture',
            'secret': SECRET, 'algorithm': 'SHA1', 'type': 'hotp', 'digits': 6, 'period': 30, 'counter': '19'}})['id']
        otp_before = otp()
        ovpn = add('Owned OpenVPN temporary credentials', ready['openvpn'])
        oc = add('Owned OpenConnect temporary credentials', ready['openconnect'])
        other = add('Different selected profile', {'type': 'block'})
        direct = add('Held direct connection', {'type': 'direct', 'udp_fragment': True})
        direct_rule = {'id': 'credentials-loopback', 'name': 'Owned direct fixture', 'enabled': True,
            'config': {'ip_cidr': ['127.0.0.1/32'], 'port': [port], 'outbound': 'direct'}}
        command('saveRouting', route_value([direct_rule]))
        applied_route = command('routing')
        # Fetch is the observed Tauri HTTP transport. Preserve its receiver.
        js('''const original=window.fetch;const s=window.__credentialsTest={original,calls:{},lastView:null,match:null,matchedAt:0,holdGet:false,held:false,release:null};
            window.fetch=function(input,options){let name=null;try{if(String(input).includes('/app_command'))name=JSON.parse(options?.body||'{}').name}catch{}
                if(name)s.calls[name]=(s.calls[name]||0)+1;const promise=original.apply(this,arguments);
                if(name!=='vpnCredentials'&&name!=='snapshot')return promise;
                return promise.then(async response=>{let value;try{value=await response.clone().json()}catch{return response}
                    if(name==='snapshot'&&s.match&&value.vpn?.sessionId===s.match.sessionId&&value.vpn.endpoints.some(e=>e.tag===s.match.endpointTag&&e.state==='error'&&e.authFailed&&!e.challengeId))s.matchedAt=Date.now();
                    if(name==='vpnCredentials'&&value.editToken){s.lastView=value;if(s.holdGet){s.holdGet=false;s.held=true;s.heldView=value;return await new Promise(resolve=>s.release=()=>resolve(response));}}
                    return response;});};''')

        identity = connect(ovpn)
        page()
        ui_current(identity)
        check(snapshot()['phase'] == 'error' and js('return !!document.querySelector("[data-vpn-credentials=proxy]")'),
              'real plain-password OpenVPN rejection is terminal authFailed without a challenge and offers explicit Retry sign-in')
        held = socket_open()
        before = snapshot()
        stored, pids = library.read_bytes(), core_pids(menu.pid)
        edit = open_dialog(identity)
        check(js('return document.querySelector("#vpn-credentials-username").value===arguments[0]&&document.querySelector("#vpn-credentials-password").value===""&&document.querySelector("#vpn-credentials-password").type==="password"', OLD_USERNAME)
              and library.read_bytes() == stored and otp() == otp_before and core_pids(menu.pid) == pids,
              'explicit details prefills only the applied username with an empty masked password and makes no persistent or process change')
        fill_new()
        close_dialog()
        check(echo(held) and snapshot()['vpn']['sessionId'] == identity['sessionId'] and snapshot()['since'] == before['since']
              and library.read_bytes() == stored and otp() == otp_before,
              'native Cancel discards temporary credentials while preserving a real held direct CONNECT, session, Library and HOTP')
        check(refusal('restartVpnCredentials', {**edit, 'username': NEW_USERNAME, 'password': NEW_PASSWORD}, 'vpn_credentials_stale')
              and echo(held), 'a cancelled one-use token cannot restart the active connection')

        edit = open_dialog(identity)
        for invalid in ['{otp}', 'я' * 2049]:
            fill('#vpn-credentials-username', invalid)
            fill('#vpn-credentials-password', '')
            check(js('return document.querySelector("#vpn-credentials-submit").disabled&&!!document.querySelector("#vpn-credentials-form [role=alert]")')
                  and echo(held) and library.read_bytes() == stored,
                  'an unsupported OTP template or oversized UTF-8 username disables native Reconnect with a visible explanation')
        check(refusal('restartVpnCredentials', {**edit, 'username': 'bad\0name', 'password': ''}, 'vpn_credentials_invalid')
              and echo(held) and otp() == otp_before, 'backend invalid-input preflight consumes no OTP and keeps the real active listener')
        fill_new()
        click('#vpn-credentials-submit')
        wait_for('return !!document.querySelector("#vpn-credentials-reload")')
        check(js('return !document.querySelector("#vpn-credentials-password")&&!!document.querySelector("#vpn-credentials-error")')
              and snapshot()['vpn']['sessionId'] == identity['sessionId'],
              'a consumed token is refused once and the dialog removes submitted password before offering Reload')
        click('#vpn-credentials-reload')
        wait_for('return !!document.querySelector("#vpn-credentials-password:not(:disabled)")')
        check(js('return document.querySelector("#vpn-credentials-password").value===""&&window.__credentialsTest.lastView.editToken!==arguments[0]', edit['editToken']),
              'Reload obtains a distinct real edit token and requires the password to be entered again')
        latest = js('return window.__credentialsTest.lastView')
        tokens.append(latest['editToken'])
        valid_edit = {key: latest[key] for key in ['sessionId', 'endpointTag', 'editToken']}
        pending = route_value([{'id': 'credentials-pending-deny', 'name': 'Saved pending rejection', 'enabled': True,
            'config': {'network': 'tcp', 'action': 'reject'}}])
        command('saveRouting', pending)
        current_core = command('settings')['core']
        command('saveSettings', {'section': 'core', 'previous': current_core,
            'values': {**current_core, 'singbox_tcp_keep_alive_idle': 77}})
        command('select', {'id': other})
        assert snapshot()['routing']['pending']
        saved = library.read_bytes()
        before_calls = js('return window.__credentialsTest.calls.restartVpnCredentials||0')
        fill_new()
        js('const f=document.querySelector("#vpn-credentials-form");f.requestSubmit();f.requestSubmit();')
        wait_for('return !document.querySelector("#vpn-credentials-cancel")')
        until(lambda: any(r['tag'] == 'proxy' and r['state'] == 'connected' for r in snapshot()['vpn']['endpoints']))
        check(js('return window.__credentialsTest.calls.restartVpnCredentials===arguments[0]+1', before_calls)
              and snapshot()['vpn']['sessionId'] != identity['sessionId'],
              'two immediate native submits cause one acknowledged Restart and a new real OpenVPN session')
        until(lambda: any(r.get('accepted') and r.get('usernameExact') for r in events('openvpn')))
        check(library.read_bytes() == saved and otp() == otp_before and safe(library.read_text()),
              'the real server accepts exact temporary plain credentials while stored profiles and HOTP remain unchanged')
        held.close()
        held = socket_open()
        check(echo(held) and snapshot()['running'] == ovpn and snapshot()['selected'] == other and snapshot()['routing']['pending']
              and command('settings')['core']['singbox_tcp_keep_alive_idle'] == 77,
              'Restart uses the frozen applied direct route and original profile while retaining a different selection and saved pending settings')
        check(refusal('restartVpnCredentials', {**valid_edit, 'username': NEW_USERNAME, 'password': NEW_PASSWORD}, 'vpn_credentials_stale')
              and echo(held), 'the pre-restart token cannot act on the replacement session')
        held.close()
        held = None
        stop()
        current = command('routing')
        command('saveRouting', {**current, 'active': applied_route['active'], 'profiles': applied_route['profiles']})
        current = command('settings')['core']
        command('saveSettings', {'section': 'core', 'previous': current, 'values': initial_core})
        identity = connect(ovpn)
        check(snapshot()['vpn']['sessionId'] != valid_edit['sessionId'] and command('profile', {'id': ovpn})['config']['password'] == OLD_PASSWORD,
              'a new explicit Connect uses saved rejected credentials again instead of retaining the prior session override')

        identity = connect(oc)
        check(any(r.get('oldExact') and not r['accepted'] for r in events()) and any(r['event'] == 'initial-lockout' for r in events()),
              'the owned HTTPS server receives saved credentials and two genuine 403 exchanges produce terminal OpenConnect authFailed')
        count = len(events())
        for _ in range(12):
            snapshot()
            time.sleep(.1)
        check(len(events()) == count, 'terminal OpenConnect polling does not retry credentials or issue additional HTTPS requests')

        # An existing unrelated editor cannot be replaced by the retry control.
        page()
        selector = '[data-profile-menu=' + json.dumps(other) + ']'
        js('document.querySelector(arguments[0]).scrollIntoView({block:"center",behavior:"instant"})', selector)
        time.sleep(.2)
        click(selector)
        click('#menu-edit-profile')
        click('[data-profile-tab=main]')
        fill('#profile-name', 'Unsaved unrelated editor draft')
        calls = js('return window.__credentialsTest.calls.vpnCredentials||0')
        check(js('const b=document.querySelector("[data-vpn-credentials=proxy]");if(!b||!b.disabled)return false;b.click();return document.querySelector("#profile-name").value==="Unsaved unrelated editor draft"&&window.__credentialsTest.calls.vpnCredentials===arguments[0]', calls),
              'a disabled retry control preserves the existing profile editor draft and does not request credentials')
        click('#main-modal > .modal-head > button')
        if js('return !!document.querySelector("[data-confirm-accept]")'):
            click('[data-confirm-accept]')
        wait_for('return !document.querySelector("dialog[open]")')

        for language in ['ru', 'en']:
            command('preferences', {**snapshot()['preferences'], 'language': language})
            wait_for('return document.documentElement.lang===' + json.dumps(language))
            open_dialog(identity)
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
                  language + ' manual credentials dialog fits 390px with both native actions reachable and no horizontal body overflow')
            h['screenshot']('vpn-credentials-' + language + '-390')
            close_dialog()
            h['request']('POST', h['base'] + '/window/rect', geometry)

        # Delay delivery of genuine old details, not its execution or identity.
        ui_current(identity)
        js('window.__credentialsTest.holdGet=true;window.__credentialsTest.held=false')
        click('[data-vpn-credentials=proxy]')
        wait_for('return window.__credentialsTest.held')
        old_view = js('return window.__credentialsTest.heldView')
        old = {key: old_view[key] for key in ['sessionId', 'endpointTag', 'editToken']}
        tokens.append(old['editToken'])
        command('disconnect')
        wait_for('return !document.querySelector("#vpn-credentials-username")')
        close_dialog()
        identity = connect(oc)
        edit = open_dialog(identity)
        fill_new()
        count = len(events())
        js('window.__credentialsTest.release();window.__credentialsTest.release=null')
        time.sleep(.4)
        check(js('return document.querySelector("#vpn-credentials-username").value===arguments[0]&&document.querySelector("#vpn-credentials-password").value===arguments[1]', NEW_USERNAME, NEW_PASSWORD)
              and edit['sessionId'] != old['sessionId'] and len(events()) == count,
              'releasing real old-session IPC details cannot overwrite the replacement dialog or its typed credentials')
        audit['controlled'].append({'case': 'delayed-real-details', 'oldAndNewSessionsDiffer': True, 'payloadModified': False})
        check(refusal('cancelVpnCredentials', old, 'vpn_credentials_stale') and refusal('restartVpnCredentials',
              {**old, 'username': NEW_USERNAME, 'password': NEW_PASSWORD}, 'vpn_credentials_stale') and len(events()) == count,
              'stale old-session Cancel and Restart cannot consume the current dialog token or send new credentials')
        saved = library.read_bytes()
        click('#vpn-credentials-submit')
        wait_for('return !document.querySelector("#vpn-credentials-cancel")')
        until(lambda: any(r.get('newExact') and r['accepted'] for r in events()))
        until(lambda: any(r['tag'] == 'proxy' and r['state'] == 'auth-pending' for r in snapshot()['vpn']['endpoints']))
        state = snapshot()['vpn']
        challenge = next(r for r in state['endpoints'] if r['tag'] == 'proxy')
        details = command('vpnChallenge', {'sessionId': state['sessionId'], 'endpointTag': 'proxy', 'challengeId': challenge['challengeId']})
        check([r['name'] for r in details['fields']] == ['operator_note'] and library.read_bytes() == saved and otp() == otp_before,
              'OpenConnect receives exact new credentials including spaces and reaches its real operator-only form without storing the override or consuming HOTP')
        stop()

        blocked_config = copy.deepcopy(ready['openconnect'])
        blocked_config['form_entries'] = [{'form_id': 'unused', 'name': 'unused', 'value': 'fixed'}]
        blocked = add('Forced form fields require manual profile review', blocked_config)
        identity = connect(blocked)
        saved = library.read_bytes()
        open_dialog(identity, error=True)
        check(js('return !document.querySelector("#vpn-credentials-username")&&document.querySelector("#vpn-credentials-submit").disabled&&document.querySelector("#vpn-credentials-error").textContent.includes("cookie")')
              and library.read_bytes() == saved and otp() == otp_before,
              'a real terminal profile with predefined form values refuses replacement visibly without discarding its stored configuration')
        close_dialog()
        stop()

        full = add('Full JSON cannot impersonate a primary profile', {
            'inbounds': [{'type': 'mixed', 'listen': '127.0.0.1', 'listen_port': initial['preferences']['inboundPort']}],
            'endpoints': [{**ready['openconnect'], 'tag': 'proxy'}],
            'outbounds': [{'type': 'direct', 'tag': 'direct'}], 'route': {'final': 'direct'}}, 'sing-box-config')
        identity = connect(full)
        held = socket_open()
        before = snapshot()
        check(refusal('vpnCredentials', identity, 'vpn_credentials_unsupported') and echo(held)
              and snapshot()['since'] == before['since'],
              'a full JSON proxy tag cannot acquire credential authority or interrupt its held direct CONNECT')
        held.close()
        held = None
        stop()
        command('saveRouting', route_value([{'id': 'credentials-aux', 'name': 'Unused auxiliary endpoint', 'enabled': True,
            'config': {'domain': ['unused.credentials.fixture.invalid'], 'outbound': 'profile:' + oc}}]))
        command('connect', {'id': direct})
        tag = until(lambda: next((r['tag'] for r in snapshot()['vpn']['endpoints'] if r['protocol'] == 'openconnect'), None))
        identity = terminal(tag)
        held = socket_open()
        before = snapshot()
        # An endpoint a route sends traffic to is a VPN node of this connection
        # like any other: the person may sign in to it again. Asking for the
        # form changes nothing by itself.
        auxiliary = command('vpnCredentials', identity)
        check(auxiliary['endpointTag'] == tag and echo(held)
              and snapshot()['running'] == direct and snapshot()['since'] == before['since'],
              'an auxiliary endpoint of a route offers its own sign-in without touching the running connection')
        exported = command('exportProfiles', {'ids': [ovpn, oc], 'format': 'profiles', 'destination': 'preview'})['text']
        check(safe(command('getLogs', {})) and safe(library.read_text()) and safe(exported)
              and all(safe(command('profile', {'id': id})) for id in ids) and otp() == otp_before,
              'session passwords and edit tokens remain absent from ordinary logs, stored profiles, Library and profile exports')
    except BaseException:
        with contextlib.suppress(Exception):
            audit['failureBeforeCleanup'] = js('return {hidden:document.hidden,dialog:!!document.querySelector("#vpn-credentials-cancel"),fieldPresent:!!document.querySelector("#vpn-credentials-password"),errorPresent:!!document.querySelector("#vpn-credentials-error")}')
            # Mask the explicitly exposed username before taking failure evidence.
            js('const e=document.querySelector("#vpn-credentials-username");if(e)e.style.color="transparent"')
            h['screenshot']('vpn-credentials-failure-before-cleanup')
        raise
    finally:
        if held:
            held.close()
        with contextlib.suppress(Exception):
            unhook()
            if js('return !!document.querySelector("#vpn-credentials-cancel:not(:disabled)")'):
                close_dialog()
            command('disconnect')
            restore_route()
            command('deleteGroup', {'id': group, 'deleteProfiles': True})
            if otp_id:
                command('otpRemove', {'id': otp_id, 'revision': otp()['revision']})
            current = command('settings')['core']
            command('saveSettings', {'section': 'core', 'previous': current, 'values': initial_core})
            command('preferences', initial['preferences'])
            h['request']('POST', h['base'] + '/window/rect', geometry)
        origin.shutdown()
        origin.server_close()
        (h['artifacts'] / 'vpn-credentials-audit.json').write_text(json.dumps(audit, indent=2) + '\n')
