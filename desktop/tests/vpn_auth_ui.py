"""Actual userspace VPN authentication, private answers, and native UI guards."""
import contextlib
import copy
import json
import os
from pathlib import Path
import select as socket_select
import socket
import socketserver
import threading
import time
from rfd_dialog_fixture import file_dialog
from native_menu import NativeMenu
from native_processes import core_pids
from vpn_auth_fixture import USER, PASSWORD, ANSWER, FORM_USER, FORM_PASSWORD, FORM_ANSWER


def run(h):
    command, click, fill, select, wait_for, js, check = (h[k] for k in ('command', 'click', 'fill', 'select', 'wait_for', 'js', 'check'))
    ready = json.loads(Path(os.environ['_THRONIUM_VPN_AUTH_READY']).read_text())
    initial = command('snapshot')
    geometry = h['request']('GET', h['base'] + '/window/rect')
    menu = NativeMenu()
    app = Path(h['args'].application).resolve()
    assert Path('/proc', str(menu.pid), 'exe').resolve() == app
    xdg = Path(os.environ['XDG_DATA_HOME'])
    assert xdg.parent.name.startswith('thronium-native-test-')
    library_path = xdg / 'io.thronium.desktop/library.json'
    group = command('saveGroup', {'name': 'Native VPN auth fixtures', 'subscription': None})['id']
    ids = []
    held = None
    exited = False
    delayed = None
    audit = {'states': [], 'rejections': [], 'controlled': []}
    secrets = [USER, PASSWORD, ANSWER, FORM_USER, FORM_PASSWORD, FORM_ANSWER]

    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            with contextlib.suppress(OSError):
                while data := self.request.recv(4096):
                    self.request.sendall(data)

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    origin = Server(('127.0.0.1', 0), Echo)
    threading.Thread(target=origin.serve_forever, daemon=True).start()

    def until(predicate, timeout=12):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(.07)
        raise AssertionError('VPN auth fixture condition timed out')

    def viewport_ready(label):
        # Await actual WebView resize, not just the X11 window size. Preserve
        # every observed rectangle; three unchanged in-bounds samples are
        # required before the old assertion and screenshot run.
        samples = audit.setdefault('viewportGeometry', {}).setdefault(label, [])
        stable, previous = 0, None
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            sample = js("""const d=document.querySelector('.vpn-auth-modal');if(!d)return null;
                const b=d.querySelector('.modal-body'),f=d.querySelector('.modal-footer'),s=document.querySelector('#vpn-auth-submit');
                const rect=e=>{const r=e.getBoundingClientRect();return {left:r.left,right:r.right,bottom:r.bottom,width:r.width}};
                return {width:innerWidth,height:innerHeight,dialog:rect(d),body:rect(b),footer:rect(f),submit:rect(s),scroll:b.scrollWidth,client:b.clientWidth};""")
            samples.append(sample)
            valid = sample and sample['width'] == 390 and sample['dialog']['left'] >= 0 and sample['dialog']['right'] <= 390 \
                and sample['dialog']['bottom'] <= sample['height'] + 1 and sample['footer']['bottom'] <= sample['height'] + 1 \
                and sample['submit']['bottom'] <= sample['height'] and sample['scroll'] <= sample['client'] + 1
            stable = stable + 1 if valid and sample == previous else (1 if valid else 0)
            if stable >= 3: return
            previous = sample
            time.sleep(.15)
        raise AssertionError('actual 390px authentication viewport did not settle inside its boundaries')

    def safe(value):
        text = value if isinstance(value, str) else json.dumps(value)
        return all(secret not in text for secret in secrets)

    def snapshot():
        state = command('snapshot')
        assert safe(state), 'Snapshot leaked an authentication response'
        audit['states'].append({'time': time.monotonic(), 'running': state['running'], 'phase': state['phase'], 'vpn': state['vpn']})
        return state

    def endpoint(state='auth-pending', tag='proxy'):
        return until(lambda: next((row for row in snapshot()['vpn']['endpoints'] if row['tag'] == tag and row['state'] == state), None))

    def maybe_request(tag='proxy'):
        state = snapshot()['vpn']
        row = next((row for row in state['endpoints'] if row['tag'] == tag), None)
        if row and row['challengeId']:
            return {'sessionId': state['sessionId'], 'endpointTag': tag, 'challengeId': row['challengeId']}

    def request(tag='proxy'):
        return until(lambda: maybe_request(tag))

    def rejected(name, payload, code):
        try:
            command(name, payload)
        except RuntimeError as error:
            assert code in str(error) and safe(str(error)), 'Unsafe or unexpected rejection'
            audit['rejections'].append({'operation': name, 'code': code})
            return True
        raise AssertionError('Expected challenge rejection: ' + name)

    def page():
        click('.primary-nav button:first-child')
        wait_for('return !!document.querySelector(".add-connection")')

    def close_auth():
        click('#vpn-auth-close')
        wait_for('return !document.querySelector(".vpn-auth-modal")')

    def open_auth(tag='proxy'):
        current = request(tag)
        ui_current(current)
        if js('return !!document.querySelector("[data-vpn-open="+JSON.stringify(arguments[0])+"]")', tag):
            click('[data-vpn-open=' + json.dumps(tag) + ']')
        else:
            click('#vpn-auth-open')
        wait_for('return !!document.querySelector("#vpn-auth-form")')
        return current

    def next_form(previous, tag='proxy'):
        current = until(lambda: (value := maybe_request(tag)) and value['challengeId'] != previous['challengeId'] and value)
        key = json.dumps([current['sessionId'], tag, current['challengeId']], separators=(',', ':'))
        # The core may expose a short no-challenge phase. App either remounts
        # the next challenge in place or closes and offers its explicit notice.
        def ready_form():
            if js('return document.querySelector("[data-vpn-auth-key]")?.dataset.vpnAuthKey===arguments[0]&&!!document.querySelector("#vpn-auth-form")', key):
                return True
            if js('return !document.querySelector("dialog[open]")&&!!document.querySelector("#vpn-auth-open:not(:disabled)")'):
                click('#vpn-auth-open')
            return False
        until(ready_form)
        return current

    def add(name, config, kind='sing-box-outbound'):
        id = command('saveProfile', {'name': name, 'groupId': group, 'kind': kind, 'config': config})['id']
        ids.append(id)
        return id

    def profile(id):
        return command('profile', {'id': id})

    def vpn_config(configured=False, echo=False):
        result = {'type': 'openvpn-client', 'server': '127.0.0.1', 'server_port': ready['openvpnPort'],
            'network': 'udp', 'system': False, 'static_challenge': 'Synthetic answer', 'static_challenge_echo': echo,
            'tls': {'certificate_path': ready['certificate'], 'server_name': ready['serverName']}}
        if configured:
            result.update(username=USER, password=PASSWORD)
        return result

    def oc_config(label, tag=None):
        result = {'type': 'openconnect', 'server': 'https://127.0.0.1:' + str(ready['openconnectPort']) + '/form/' + label,
            'flavor': 'anyconnect', 'system': False, 'no_udp': True,
            'tls': {'certificate_authority_path': ready['certificate']}}
        if tag:
            result['tag'] = tag
        return result

    def events(label=None):
        path = Path(ready['events'])
        values = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
        return [value for value in values if label is None or value['path'] == '/form/' + label]

    def stop():
        command('disconnect')
        until(lambda: snapshot()['vpn']['sessionId'] is None)
        wait_for('return !document.querySelector(".vpn-auth-modal")')

    def connect(id):
        page()
        command('connect', {'id': id})
        endpoint()
        ui_current(request())
        wait_for('return !!document.querySelector("#vpn-auth-open:not(:disabled)")')

    def ui_current(current):
        # Observe the next automatic App poll after our own status read. Native
        # command('snapshot') alone does not update React's displayed session.
        js('''const original=window.fetch;window.__vpnUiSync={original,current:arguments[0],at:0,calls:0};window.fetch=function(input,options){let name=null;try{if(String(input).includes('/app_command'))name=JSON.parse(options?.body||'{}').name}catch{}const result=original.apply(this,arguments);if(name==='snapshot')result.then(r=>r.clone().json()).then(value=>{const state=window.__vpnUiSync;if(state)state.calls++;if(state&&value.vpn?.sessionId===state.current.sessionId&&value.vpn.endpoints.some(e=>e.tag===state.current.endpointTag&&e.challengeId===state.current.challengeId))state.at=Date.now();}).catch(()=>{});return result;};''', current)
        try:
            wait_for('return window.__vpnUiSync.at>0&&Date.now()-window.__vpnUiSync.at>50')
        finally:
            audit.setdefault('uiSync', []).append(js('return {calls:window.__vpnUiSync.calls,matched:window.__vpnUiSync.at>0}'))
            js('window.fetch=window.__vpnUiSync.original;delete window.__vpnUiSync')

    def fill_credentials():
        fill('#vpn-auth-username', USER)
        fill('#vpn-auth-password', PASSWORD)
        fill('#vpn-auth-secret', ANSWER)

    def editor(id):
        page()
        selector = '[data-profile-menu=' + json.dumps(id) + ']'
        wait_for('return !!document.querySelector(' + json.dumps(selector) + ')')
        js('window.__vpnScroll=Date.now();window.__vpnScrolled=()=>window.__vpnScroll=Date.now();document.addEventListener("scroll",window.__vpnScrolled,true);document.querySelector(arguments[0]).scrollIntoView({block:"center",behavior:"instant"})', selector)
        wait_for('return Date.now()-window.__vpnScroll>150')
        js('document.removeEventListener("scroll",window.__vpnScrolled,true)')
        click(selector)
        click('#menu-edit-profile')
        wait_for('return !!document.querySelector("#profile-editor")')

    def close_editor():
        click('#main-modal > .modal-head > button')
        if js('return !!document.querySelector("[data-confirm-accept]")'):
            click('[data-confirm-accept]')
        wait_for('return !document.querySelector("dialog[open]")')

    def settings(section):
        click('.primary-nav button:last-child')
        wait_for('return !!document.querySelector("#settings-search")')
        click('[data-settings-section=' + section + ']')

    def form_values(details, values):
        for item in details['fields']:
            selector = '[data-vpn-field=' + json.dumps(item['submissionKey']) + ']'
            if item['kind'] == 'select':
                select(selector, values[item['name']])
            else:
                fill(selector, values[item['name']])

    def install_hook(mode):
        # The original backend executes. Only delivery of a private details
        # response is delayed/modified, and command counts never retain payloads.
        js('''const original=window.fetch;window.__vpnTest={original,mode:arguments[0],release:null,calls:[],held:false};window.fetch=function(input,options){let name=null;try{if(String(input).includes('/app_command'))name=JSON.parse(options?.body||'{}').name}catch{}if(name)window.__vpnTest.calls.push(name);const result=original.apply(this,arguments);if(name!=='vpnChallenge')return result;return result.then(async response=>{if(window.__vpnTest.mode==='delay'){window.__vpnTest.held=true;return await new Promise(resolve=>window.__vpnTest.release=()=>resolve(response));}if(window.__vpnTest.mode==='expire'){const value=await response.clone().json();value.deadline=Math.floor(Date.now()/1000)+4;return new Response(JSON.stringify(value),{status:response.status,headers:response.headers});}return response;});};''', mode)

    def remove_hook():
        js('if(window.__vpnTest){window.fetch=window.__vpnTest.original;if(window.__vpnTest.release)window.__vpnTest.release();delete window.__vpnTest;}')

    def pause_snapshots():
        js('''const original=window.fetch;window.__vpnPoll={original,queue:[],automatic:0,observations:0};window.fetch=function(input,options){let name=null,payload={};try{if(String(input).includes('/app_command'))({name,payload}=JSON.parse(options?.body||'{}'))}catch{}if(name==='snapshot'){if(payload?.__authObserve){window.__vpnPoll.observations++;return original.apply(this,arguments);}return new Promise((resolve,reject)=>window.__vpnPoll.queue.push({input,options,resolve,reject}));}return original.apply(this,arguments);};''')

    def resume_snapshots():
        js('if(window.__vpnPoll){const state=window.__vpnPoll;window.fetch=state.original;for(const item of state.queue.splice(0))state.original.call(window,item.input,item.options).then(item.resolve,item.reject);delete window.__vpnPoll;}')

    try:
        command('disconnect')
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark', 'connectionMode': 'local', 'closeBehavior': 'quit'})
        wait_for('return document.documentElement.lang==="en"')
        before_pids = core_pids(menu.pid)
        for _ in range(3):
            state = snapshot()
        check(state['vpn'] == {'sessionId': None, 'endpoints': [], 'error': None} and core_pids(menu.pid) == before_pids,
            'idle VPN status polling has no endpoints and does not spawn a core')
        invalid = {'sessionId': 'stale-session', 'endpointTag': 'proxy', 'challengeId': 'stale-challenge'}
        check(rejected('vpnChallenge', invalid, 'vpn_auth_stale') and core_pids(menu.pid) == before_pids,
            'opening a stale idle challenge refuses without starting any core')
        vpn = add('Native OpenVPN credentials', vpn_config())
        command('checkProfile', profile(vpn))
        check(snapshot()['vpn']['sessionId'] is None and profile(vpn)['config'] == vpn_config(),
            'real endpoint Check does not create a connection or persist authentication answers')
        connect(vpn)
        row = endpoint()
        state = snapshot()
        check(state['running'] == vpn and state['phase'] == 'auth-pending' and row['challengeKind'] == 'credentials' and not js('return !!document.querySelector("dialog[open]")'),
            'OpenVPN Start exposes auth-pending and a notice without opening a dialog automatically')
        check(set(state['vpn']) == {'sessionId', 'endpoints', 'error'} and set(row) == {'tag', 'protocol', 'state', 'challengeId', 'challengeKind', 'authFailed', 'error', 'tunnel'} and row['tunnel'] is None,
            'public VPN metadata excludes private challenge text, field values, URL and username')
        check(js('return document.querySelector("[data-vpn-state=auth-pending]").textContent.includes("Authentication required")'),
            'the native endpoint panel distinguishes pending authentication from an established tunnel')
        check(bool(menu.ready('VPN authentication required', enabled=False)), 'the real DBus menu reports authentication pending instead of a connected VPN')
        old_request = open_auth()
        check(js('return document.querySelector("#vpn-auth-password").type==="password"&&document.querySelector("#vpn-auth-secret").type==="password"'),
            'OpenVPN credentials and non-echo challenge responses use masked input fields')
        fill_credentials()
        time.sleep(1.2)
        check(js('return document.querySelector("#vpn-auth-password").value===arguments[0]&&document.querySelector("#vpn-auth-secret").value===arguments[1]', PASSWORD, ANSWER),
            'periodic status refresh preserves the current unsent answers')
        close_auth()
        check(request() == old_request and endpoint()['state'] == 'auth-pending',
            'Close dismisses the form while leaving the real core challenge pending')
        open_auth()
        check(js('return !document.querySelector("#vpn-auth-password").value&&!document.querySelector("#vpn-auth-secret").value'),
            'reopening a dismissed challenge does not restore previously entered secret answers')
        fill_credentials()
        stored = library_path.read_bytes()
        click('#vpn-auth-submit')
        endpoint('connected')
        wait_for('return !document.querySelector(".vpn-auth-modal")')
        check(snapshot()['running'] == vpn and library_path.read_bytes() == stored,
            'native Submit establishes a real userspace OpenVPN tunnel without writing answers to the library')
        check(rejected('submitVpnChallenge', {**old_request, 'username': USER, 'password': PASSWORD, 'secret': ANSWER, 'formValues': {}}, 'vpn_auth_stale'),
            'the completed OpenVPN request cannot be submitted again')
        stop()

        for echo in [False, True]:
            configured = add('Native OpenVPN secret ' + str(echo), vpn_config(True, echo))
            connect(configured)
            check(endpoint()['challengeKind'] == 'secret', 'configured OpenVPN credentials produce a separate secret challenge: ' + str(echo))
            open_auth()
            check(js('return !document.querySelector("#vpn-auth-password")&&document.querySelector("#vpn-auth-secret").type===arguments[0]', 'text' if echo else 'password'),
                'the secret challenge follows its actual echo flag: ' + str(echo))
            click('#vpn-auth-cancel')
            endpoint('error')
            time.sleep(1.3)
            check(endpoint('error')['challengeId'] is None, 'OpenVPN Cancel becomes terminal without a new challenge: ' + str(echo))
            stop()

        # Submitted-only values must be absent; configured credentials are an
        # intentional profile field and are excluded from this persistence check.
        for id in list(ids):
            if profile(id)['config'].get('username') == USER:
                command('deleteProfiles', {'ids': [id]})
                ids.remove(id)
        oc = add('Native OpenConnect form', oc_config('primary'))
        connect(oc)
        first = open_auth()
        details = command('vpnChallenge', first)
        check({entry['kind'] for entry in details['fields']} == {'text', 'password', 'select'},
            'a real OpenConnect HTTPS response renders all three supported field kinds')
        check(js('return [...document.querySelectorAll(".vpn-server-text")].some(e=>e.textContent.includes("<b>plain text</b>"))&&!document.querySelector(".vpn-server-text b")'),
            'server banner markup is displayed as text rather than interpreted as HTML')
        password_key = next(entry['submissionKey'] for entry in details['fields'] if entry['kind'] == 'password')
        check(js('return document.querySelector(arguments[0]).type==="password"', '[data-vpn-field=' + json.dumps(password_key) + ']'),
            'OpenConnect password fields stay masked in the native form')
        invalid_answers = {item['submissionKey']: 'invalid-choice' if item['kind'] == 'select' else '' for item in details['fields']}
        event_count = len(events('primary'))
        check(rejected('submitVpnChallenge', {**first, 'username': '', 'password': '', 'secret': '', 'formValues': invalid_answers}, 'vpn_auth_invalid_response') and len(events('primary')) == event_count and request() == first,
            'an invalid select value is rejected before any HTTPS submission and leaves the real form available')
        check(rejected('submitVpnChallenge', {**first, 'username': '', 'password': '', 'secret': '', 'formValues': {}}, 'vpn_auth_invalid_response') and request() == first,
            'missing OpenConnect answers cannot silently submit an incomplete form')
        for language in ['ru', 'en']:
            command('preferences', {**snapshot()['preferences'], 'language': language})
            wait_for('return document.documentElement.lang===' + json.dumps(language))
            h['request']('POST', h['base'] + '/window/rect', {'width': 390, 'height': 844})
            viewport_ready('form-' + language)
            check(js('const d=document.querySelector(".vpn-auth-modal"),b=d.querySelector(".modal-body");return d.getBoundingClientRect().bottom<=innerHeight+1&&b.scrollWidth<=b.clientWidth+1&&document.querySelector("#vpn-auth-submit").getBoundingClientRect().bottom<=innerHeight'),
                language + ' server form, select labels and actions fit the native window at 390 pixels')
            h['screenshot']('vpn-auth-form-' + language + '-390')
        h['request']('POST', h['base'] + '/window/rect', {'width': 1280, 'height': 860})
        form_values(details, {'username': FORM_USER, 'password': FORM_PASSWORD, 'realm': 'two'})
        stored = library_path.read_bytes()
        install_hook('observe')
        js('const button=document.querySelector("#vpn-auth-submit");button.click();button.click()')
        second = next_form(first)
        wait_for('return document.querySelectorAll("[data-vpn-field]").length===1')
        check(js('return window.__vpnTest.calls.filter(n=>n==="submitVpnChallenge").length===1') and len(events('primary')) == event_count + 1,
            'two immediate native Submit clicks produce one actual response and one HTTPS request')
        remove_hook()
        check(any(event['formExact'] for event in events('primary')) and library_path.read_bytes() == stored,
            'native text/password/select submission sends exact option values over verified HTTPS and does not save answers')
        check(js('return document.querySelector("[data-vpn-field]").type==="password"&&!document.querySelector("[data-vpn-field]").value'),
            'the next real OTP challenge has empty masked fields and no previous form answers')
        check(rejected('submitVpnChallenge', {**first, 'username': '', 'password': '', 'secret': '', 'formValues': {}}, 'vpn_auth_stale') and rejected('cancelVpnChallenge', first, 'vpn_auth_stale') and request() == second,
            'stale Submit and Cancel cannot answer or close the next OpenConnect challenge')
        details = command('vpnChallenge', second)
        form_values(details, {'answer': FORM_ANSWER})
        click('#vpn-auth-submit')
        next_form(second)
        wait_for('return !!document.querySelector("[data-vpn-field]")')
        check(any(event['otpExact'] for event in events('primary')), 'a real native OTP response reaches only the owned HTTPS server')
        count = len(events('primary'))
        click('#vpn-auth-cancel')
        endpoint('error')
        time.sleep(2.2)
        check(endpoint('error')['challengeId'] is None and len(events('primary')) == count,
            'OpenConnect Cancel is terminal across retry intervals without another HTTPS request')
        stop()

        class Delay(socketserver.BaseRequestHandler):
            def handle(self):
                # Delay TLS transport readiness, not a fabricated core status.
                # This keeps the first Connect query in the connecting phase.
                time.sleep(2.2)
                with contextlib.suppress(OSError):
                    with socket.create_connection(('127.0.0.1', ready['openconnectPort']), timeout=5) as upstream:
                        while True:
                            readable, _, _ = socket_select.select([self.request, upstream], [], [], 10)
                            if not readable:
                                return
                            for source in readable:
                                data = source.recv(65536)
                                if not data:
                                    return
                                (upstream if source is self.request else self.request).sendall(data)
        delayed = Server(('127.0.0.1', 0), Delay)
        threading.Thread(target=delayed.serve_forever, daemon=True).start()
        hidden_config = oc_config('hidden')
        hidden_config['server'] = 'https://127.0.0.1:' + str(delayed.server_address[1]) + '/form/hidden'
        hidden = add('Hidden VPN worker fixture', hidden_config)
        pause_snapshots()
        click('[data-window-action=minimize]')
        wait_for('return document.hidden')
        command('connect', {'id': hidden})
        menu.ready('Connecting to VPN…', enabled=False)
        menu.ready('VPN authentication required', enabled=False)
        # The actual native menu transition above precedes any explicit poll.
        observed = command('snapshot', {'__authObserve': True})
        hidden_endpoint = next(row for row in observed['vpn']['endpoints'] if row['tag'] == 'proxy')
        check(hidden_endpoint['state'] == 'auth-pending' and hidden_endpoint['challengeId'] and len(events('hidden')) == 1 and js('return window.__vpnPoll.queue.length>0&&window.__vpnPoll.automatic===0&&window.__vpnPoll.observations===1'),
            'the backend updates the real DBus menu from connecting to authentication required while the hidden WebView sends no snapshots')
        audit['controlled'].append('hidden window with automatic snapshot forwarding suspended; owned delayed TLS relay; DBus transition observed before explicit snapshot poll')
        resume_snapshots()
        menu.activate(menu.ready('Open Thronium'))
        wait_for('return !document.hidden')
        open_auth()
        check(js('return document.querySelectorAll("[data-vpn-field]").length===3'),
            'showing the window exposes the current server form without starting another connection')
        click('#vpn-auth-cancel')
        endpoint('error')
        stop()

        connect(vpn)
        previous = request()
        stop()
        connect(vpn)
        current = request()
        check(current['sessionId'] != previous['sessionId'] and rejected('submitVpnChallenge', {**previous, 'username': USER, 'password': PASSWORD, 'secret': ANSWER, 'formValues': {}}, 'vpn_auth_stale') and rejected('cancelVpnChallenge', previous, 'vpn_auth_stale') and request() == current,
            'reconnecting the same endpoint creates a new session that rejects both old response operations')
        install_hook('delay')
        click('#vpn-auth-open')
        wait_for('return window.__vpnTest.held')
        stop()
        connect(vpn)
        js('window.__vpnTest.release()')
        time.sleep(.3)
        check(not js('return !!document.querySelector(".vpn-auth-modal")') and request()['sessionId'] != current['sessionId'],
            'a controlled late private response cannot reopen an obsolete form after the session changes')
        audit['controlled'].append('late private details delivery after real Disconnect/Connect')
        remove_hook()
        install_hook('expire')
        open_auth()
        fill_credentials()
        wait_for('return !document.querySelector(".vpn-auth-modal")')
        check(endpoint()['state'] == 'auth-pending' and js('return !window.__vpnTest.calls.includes("submitVpnChallenge")&&!window.__vpnTest.calls.includes("cancelVpnChallenge")'),
            'a controlled UI deadline clears answer fields without sending a response or cancelling the real timeless challenge')
        audit['controlled'].append('UI deadline only; actual static challenge deadline remains zero')
        remove_hook()
        stop()

        direct = add('Unrelated editor draft', {'type': 'direct'})
        editor(direct)
        fill('#profile-name', 'Unsubmitted auth fixture draft')
        command('connect', {'id': vpn})
        endpoint()
        wait_for('return !!document.querySelector("#vpn-auth-notice")')
        check(js('return document.querySelector("#profile-name").value==="Unsubmitted auth fixture draft"&&document.querySelector("#vpn-auth-open").disabled&&!document.querySelector(".vpn-auth-modal")'),
            'an incoming real challenge does not replace or erase an already open profile editor')
        close_editor()
        stop()
        settings('testing')
        fill('#setting-test_concurrent', '9')
        click('[data-settings-section=appearance]')
        command('connect', {'id': vpn})
        endpoint()
        wait_for('return !!document.querySelector("#vpn-auth-open:not(:disabled)")')
        open_auth()
        close_auth()
        click('[data-settings-section=testing]')
        check(js('return document.querySelector("#setting-test_concurrent").value==="9"'),
            'opening and dismissing authentication preserves a settings draft in a previously hidden category')
        click('#settings-form .settings-save button[type=button]')
        stop()
        settings('dns')
        click('[data-resource-view=json]')
        raw = '{"unfinished":"auth hidden DNS draft"'
        fill('#route-json', raw)
        click('[data-settings-section=appearance]')
        command('connect', {'id': vpn})
        endpoint()
        open_auth()
        close_auth()
        click('[data-settings-section=dns]')
        check(js('return document.querySelector("#route-json").value===arguments[0]', raw),
            'the authentication dialog preserves an unfinished raw DNS buffer without navigating away from settings')
        click('[data-resource-view=fields]')
        click('#resource-json-discard')
        stop()

        for language in ['ru', 'en']:
            command('preferences', {**snapshot()['preferences'], 'language': language})
            wait_for('return document.documentElement.lang===' + json.dumps(language))
            connect(vpn)
            open_auth()
            h['request']('POST', h['base'] + '/window/rect', {'width': 390, 'height': 844})
            viewport_ready('credentials-' + language)
            check(js('const d=document.querySelector(".vpn-auth-modal"),b=d.querySelector(".modal-body");return d.getBoundingClientRect().bottom<=innerHeight+1&&b.scrollWidth<=b.clientWidth+1&&document.querySelector("#vpn-auth-submit").getBoundingClientRect().bottom<=innerHeight'),
                language + ' credentials form and Submit/Cancel fit the native window at 390 pixels')
            h['screenshot']('vpn-auth-credentials-' + language + '-390')
            close_auth()
            stop()
            h['request']('POST', h['base'] + '/window/rect', {'width': 1280, 'height': 860})

        command('preferences', {**snapshot()['preferences'], 'language': 'en'})
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            inbound = reservation.getsockname()[1]
        full_config = {'inbounds': [{'type': 'mixed', 'tag': 'fixture-in', 'listen': '127.0.0.1', 'listen_port': inbound}],
            'outbounds': [{'type': 'direct', 'tag': 'direct'}], 'route': {'final': 'direct'},
            'endpoints': [oc_config('auxiliary', 'vpn-aux')]}
        full = add('Independent VPN endpoint and direct socket', full_config, 'sing-box-config')
        command('connect', {'id': full})
        endpoint(tag='vpn-aux')
        held = socket.create_connection(('127.0.0.1', inbound), timeout=5)
        target = '127.0.0.1:' + str(origin.server_address[1])
        held.sendall(f'CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n'.encode())
        header = b''
        while b'\r\n\r\n' not in header:
            header += held.recv(4096)
        assert b' 200 ' in header
        before = snapshot()
        open_auth('vpn-aux')
        click('#vpn-auth-cancel')
        endpoint('error', 'vpn-aux')
        held.sendall(b'auth-endpoint-isolation')
        response = held.recv(64)
        check(response == b'auth-endpoint-isolation' and snapshot()['running'] == full and snapshot()['since'] == before['since'],
            'cancelling one VPN endpoint preserves an unrelated real held HTTP CONNECT socket and the active core session')
        held.close()
        held = None
        stop()
        check(safe(library_path.read_text()) and safe(command('getLogs', {})) and all(safe(profile(id)) for id in ids),
            'submitted credentials and OTP are absent from stored profiles, the library and normal application logs')
        settings('backup')
        backup = h['artifacts'] / 'auth-after-backup.json'
        click('#backup-save')
        file_dialog('Save backup', backup, audit=audit.setdefault('chooser', []), wait_ready=True)
        until(backup.exists)
        check(safe(backup.read_text()), 'a real native backup export contains no submitted authentication answers')
        connect(vpn)
        open_auth()
        fill_credentials()
        stored = library_path.read_bytes()
        own_core_pids = core_pids(menu.pid)
        menu.activate(menu.ready('Quit'))
        until(lambda: not Path('/proc', str(menu.pid)).exists())
        exited = True
        h['closed_session'] = True
        until(lambda: all(not Path('/proc', str(pid)).exists() for pid in own_core_pids))
        check(library_path.read_bytes() == stored and safe(library_path.read_text()),
            'native Quit closes a pending authentication session and its owned core without saving entered answers')

    finally:
        if held:
            held.close()
        if not exited:
            with contextlib.suppress(Exception):
                audit['beforeCleanup'] = js('return {hook:window.__vpnTest?{mode:window.__vpnTest.mode,calls:window.__vpnTest.calls,held:window.__vpnTest.held}:null,modal:!!document.querySelector(".vpn-auth-modal"),form:!!document.querySelector("#vpn-auth-form"),key:document.querySelector("[data-vpn-auth-key]")?.dataset.vpnAuthKey||null}')
                remove_hook()
                resume_snapshots()
                if js('return !!document.querySelector(".vpn-auth-modal")'):
                    close_auth()
                if js('return !!document.querySelector("#profile-editor")'):
                    close_editor()
                command('disconnect')
                command('deleteGroup', {'id': group, 'deleteProfiles': True})
                command('preferences', initial['preferences'])
                h['request']('POST', h['base'] + '/window/rect', geometry)
        (h['artifacts'] / 'vpn-auth-audit.json').write_text(json.dumps(audit, indent=2) + '\n')
        origin.shutdown()
        origin.server_close()
        if delayed:
            delayed.shutdown()
            delayed.server_close()
