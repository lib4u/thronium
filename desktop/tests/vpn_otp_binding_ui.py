"""Native OTP binding and actual independently verified VPN auth responses."""
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
from vpn_otp_fixture import SECRET, USER, PASSWORD, FORM_USER, FORM_PASSWORD, code_at


def run(h):
    command, click, fill, select, wait_for, js, check = (h[k] for k in ('command', 'click', 'fill', 'select', 'wait_for', 'js', 'check'))
    ready = json.loads(Path(os.environ['_THRONIUM_VPN_OTP_READY']).read_text())
    initial = command('snapshot')
    initial_system = command('settings')['system']
    initial_routing = command('routing')
    geometry = h['request']('GET', h['base'] + '/window/rect')
    menu = NativeMenu()
    assert Path('/proc', str(menu.pid), 'exe').resolve() == Path(h['args'].application).resolve()
    xdg = Path(os.environ['XDG_DATA_HOME'])
    assert xdg.parent.name.startswith('thronium-native-test-')
    library = xdg / 'io.thronium.desktop/library.json'
    group = command('saveGroup', {'name': 'Native live OTP bindings', 'subscription': None})['id']
    ids, otp_ids = [], []
    audit = {'rejections': [], 'controlled': [], 'snapshots': []}
    held, origin = None, None
    original_clipboard, original_image = None, None
    try:
        original_clipboard = command('readClipboard')
    except RuntimeError:
        import gi
        gi.require_version('Gtk', '3.0')
        from gi.repository import Gtk, Gdk
        original_image = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD).wait_for_image()

    def until(predicate, timeout=14):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(.07)
        raise AssertionError('native OTP binding condition timed out')

    def private_free(value):
        encoded = value if isinstance(value, str) else json.dumps(value)
        return all(secret not in encoded for secret in [SECRET, USER, PASSWORD, FORM_USER, FORM_PASSWORD])

    def snapshot():
        value = command('snapshot')
        assert private_free(value), 'public OTP snapshot contains private source values'
        for endpoint in value['vpn']['endpoints']:
            if endpoint.get('otp') is not None:
                assert set(endpoint['otp']) == {'state', 'error'}, 'unexpected private OTP metadata field'
        audit['snapshots'].append({'running': value['running'], 'phase': value['phase'], 'vpn': value['vpn']})
        return value

    def events(name, key=None):
        path = Path(ready['events'])
        rows = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
        return [row for row in rows if row['case'] == '/otp/' + name and (key is None or row.get(key))]

    def responses(name):
        return [row for row in events(name) if row['event'] == 'received' and row['response']]

    def otp(name, kind='hotp', counter='0'):
        draft = {'name': name, 'issuer': 'Owned VPN fixture', 'secret': SECRET,
                 'algorithm': 'SHA1', 'type': kind, 'digits': 6, 'period': 8, 'counter': counter}
        value = command('otpSave', {'value': draft})
        otp_ids.append(value['id'])
        return value['id']

    def entry(id):
        return command('otpGet', {'id': id})

    def draft(value):
        return {key: value[key] for key in ['name', 'issuer', 'secret', 'algorithm', 'type', 'digits', 'period', 'counter']}

    def add(name, config, kind='sing-box-outbound'):
        config = copy.deepcopy(config)
        if kind == 'sing-box-outbound':
            config.pop('tag', None)
        value = command('saveProfile', {'name': name, 'groupId': group, 'kind': kind, 'config': config})
        ids.append(value['id'])
        return value['id']

    def bind(id, otp_id, mode=None):
        view = command('getVpnOtpBinding', {'profileId': id})
        return command('saveVpnOtpBinding', {'profileId': id, 'editToken': view['editToken'],
            'otpId': otp_id, 'otpRevision': entry(otp_id)['revision'] if otp_id else None, **({'mode': mode} if mode else {})})

    def rejected(name, payload, code):
        try:
            command(name, payload)
        except RuntimeError as error:
            assert code in str(error) and private_free(str(error)), 'unsafe or unexpected binding refusal'
            audit['rejections'].append({'command': name, 'code': code})
            return True
        raise AssertionError('expected binding refusal: ' + name)

    def page():
        click('.primary-nav button:first-child')
        wait_for('return !!document.querySelector(".add-connection")')

    def open_binding(id):
        page()
        selector = '[data-profile-menu=' + json.dumps(id) + ']'
        wait_for('return !!document.querySelector(' + json.dumps(selector) + ')')
        js('document.querySelector(arguments[0]).scrollIntoView({block:"center",behavior:"instant"})', selector)
        time.sleep(.2)
        click(selector)
        click('#menu-vpn-otp-profile')
        wait_for('return !!document.querySelector("#vpn-otp-entry:not(:disabled)")')

    def stop():
        command('disconnect')
        until(lambda: snapshot()['vpn']['sessionId'] is None)
        wait_for('return !document.querySelector(".vpn-auth-modal")')

    def connect(id):
        command('connect', {'id': id})

    def endpoint(state=None):
        return until(lambda: next((row for row in snapshot()['vpn']['endpoints'] if row['tag'] == 'proxy' and (state is None or row['state'] == state)), None))

    def request(tag='proxy'):
        def current():
            state = snapshot()['vpn']
            row = next((row for row in state['endpoints'] if row['tag'] == tag and row['challengeId']), None)
            return row and {'sessionId': state['sessionId'], 'endpointTag': tag, 'challengeId': row['challengeId']}
        return until(current)

    def settings_otp():
        click('.primary-nav button:last-child')
        wait_for('return !!document.querySelector("[data-settings-section=otp]")')
        click('[data-settings-section=otp]')
        wait_for('return !!document.querySelector("#otp-manager")')

    def suspend_snapshots():
        js('''const original=window.fetch;window.__bindingPoll={original,queue:[],forwarded:0};window.fetch=function(input,options){let name=null;try{name=JSON.parse(options?.body||'{}').name}catch{}if(name==='snapshot')return new Promise((resolve,reject)=>window.__bindingPoll.queue.push({input,options,resolve,reject}));return original.apply(this,arguments);};''')

    def resume_snapshots():
        js('if(window.__bindingPoll){const s=window.__bindingPoll;window.fetch=s.original;for(const p of s.queue)s.original.call(window,p.input,p.options).then(p.resolve,p.reject);delete window.__bindingPoll;}')

    def show():
        from Xlib import X, protocol
        from window_ui import primary
        connection, window, pid = primary()
        assert pid == menu.pid
        try:
            connection.screen().root.send_event(protocol.event.ClientMessage(window=window,
                client_type=connection.intern_atom('_NET_ACTIVE_WINDOW'),
                data=(32, [2, X.CurrentTime, 0, 0, 0])),
                event_mask=X.SubstructureRedirectMask | X.SubstructureNotifyMask)
            connection.sync()
        finally:
            connection.close()
        wait_for('return !document.hidden')

    try:
        stop()
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark', 'connectionMode': 'local'})
        wait_for('return document.documentElement.lang==="en"')
        hotp = otp('Native HOTP — следующий шаг')
        totp = otp('Native TOTP — живой код', 'totp')
        vpn_config = {**ready['openvpn'], 'username': USER, 'password': PASSWORD}
        vpn = add('Owned OpenVPN automatic HOTP', vpn_config)
        pool = {name: add('Owned ' + name, config) for name, config in ready['endpoints'].items()}
        before_pids = core_pids(menu.pid)
        before_counter = entry(hotp)
        open_binding(vpn)
        check(js('return document.querySelector("#vpn-otp-entry").value===""&&document.querySelector("#vpn-otp-save").disabled'),
              'ordinary OpenVPN profile menu opens an explicit unbound OTP picker without a default selection')
        select('#vpn-otp-entry', hotp)
        check(js('return !!document.querySelector("#vpn-otp-hotp-hint")') and core_pids(menu.pid) == before_pids and entry(hotp) == before_counter,
              'opening and choosing an OTP explains C+1 without creating a code, connection or counter change')
        # The picker retains a user choice across a real concurrent OTP edit.
        updated = draft(before_counter)
        updated['name'] += ' updated'
        command('otpSave', {'id': hotp, 'revision': before_counter['revision'], 'value': updated})
        click('#vpn-otp-save')
        wait_for('return !!document.querySelector("#vpn-otp-error")')
        check(js('return document.querySelector("#vpn-otp-entry").value===arguments[0]', hotp) and command('getVpnOtpBinding', {'profileId': vpn})['binding'] is None,
              'a stale chosen OTP revision refuses Save and preserves the unsaved picker choice')
        click('#vpn-otp-reload')
        wait_for('return !document.querySelector("#vpn-otp-entry").disabled')
        check(js('return document.querySelector("#vpn-otp-entry").value===arguments[0]', hotp),
              'Reload refreshes current revisions while retaining the chosen OTP draft')
        js('const original=window.fetch;window.__bindingSave={original,count:0};window.fetch=function(input,options){try{if(JSON.parse(options?.body||"{}").name==="saveVpnOtpBinding")window.__bindingSave.count++}catch{}return original.apply(this,arguments)}')
        click('#vpn-otp-save')
        wait_for('return !document.querySelector(".vpn-otp-modal")')
        check(js('return window.__bindingSave.count===1') and command('getVpnOtpBinding', {'profileId': vpn})['binding']['otpId'] == hotp,
              'one native Save creates exactly one acknowledged binding')
        js('window.fetch=window.__bindingSave.original;delete window.__bindingSave')
        check(json.loads(library.read_text())['version'] == 3 and entry(hotp)['counter'] == '0' and core_pids(menu.pid) == before_pids,
              'saving the binding promotes Library to v3 without consuming HOTP or starting Core')
        current = entry(hotp)
        check(rejected('otpRemove', {'id': hotp, 'revision': current['revision']}, 'otp_in_use'),
              'a bound OTP cannot be deleted into a dangling profile reference')
        old_view = command('getVpnOtpBinding', {'profileId': vpn})
        bind(vpn, None)
        check(rejected('saveVpnOtpBinding', {'profileId': vpn, 'editToken': old_view['editToken'], 'otpId': hotp,
              'otpRevision': entry(hotp)['revision']}, 'vpn_otp_binding_changed') and json.loads(library.read_text())['version'] == 3,
              'a stale binding token refuses resurrection after removal and version never decreases')

        for name, fields, reason, message in [
            ('Overlapping fixed and OTP form values', [
                {'form_id': 'otp', 'name': 'custom_challenge', 'value': 'frozen-static-value'},
                {'form_id': 'otp', 'name': 'custom_challenge', 'value': 'prefix-{otp}-suffix-{otp}'},
            ], 'vpn_otp_form_shadowed', 'The form has overlapping fixed values and OTP templates. Keep one value for each field before enabling automatic OTP.'),
            ('OTP template in an AnyConnect password cache field', [
                {'form_id': 'otp', 'name': 'password', 'value': '{otp}'},
            ], 'vpn_otp_form_cache_unsupported', 'This OTP template targets a field that may be filled or reused automatically by the VPN core. Use a separate named challenge field in an AnyConnect form.'),
        ]:
            blocked_config = copy.deepcopy(ready['endpoints']['hotp-template'])
            blocked_config['form_entries'] = fields
            blocked = add(name, blocked_config)
            before_library, before_entry, before_core = library.read_bytes(), entry(hotp), core_pids(menu.pid)
            view = command('getVpnOtpBinding', {'profileId': blocked})
            open_binding(blocked)
            wait_for('return !!document.querySelector("#vpn-otp-reason")')
            ui = js('''return {reason:document.querySelector('#vpn-otp-reason').textContent,
                saveDisabled:document.querySelector('#vpn-otp-save').disabled,
                optionsDisabled:[...document.querySelectorAll('#vpn-otp-entry option')].filter(o=>o.value).every(o=>o.disabled)}''')
            click('#vpn-otp-close')
            wait_for('return !document.querySelector(".vpn-otp-modal")')
            check(view['supported'] is False and view['reason'] == reason and view['binding'] is None
                  and ui['saveDisabled'] and ui['optionsDisabled'] and ui['reason'] == message
                  and library.read_bytes() == before_library and entry(hotp) == before_entry and core_pids(menu.pid) == before_core,
                  name + ': localized refusal disables Save and OTP choices without changing Library, counter or Core')

        # A genuine unbound pending endpoint makes the Activity semantics visible.
        page()
        connect(vpn)
        endpoint('auth-pending')
        click('.primary-nav button:nth-child(3)')
        wait_for('return !!document.querySelector("[data-activity-connection-state=auth-pending]")')
        check(js('return !document.querySelector("[data-activity-connection-state=auth-pending]").textContent.includes("Connected")'),
              'Activity distinguishes an actual pending VPN challenge from a connected tunnel')
        stop()
        bind(vpn, hotp)
        before = entry(hotp)
        command('checkProfile', command('profile', {'id': vpn}))
        check(entry(hotp) == before, 'real Core Check of a bound VPN does not consume HOTP')
        connect(vpn)
        endpoint('connected')
        after = entry(hotp)
        check(after['counter'] == '1' and after['revision'] != before['revision'],
              'automatic OpenVPN reaches actual connected only after the server accepts generated HOTP C+1')
        check(rejected('otpSave', {'id': hotp, 'revision': before['revision'], 'value': draft(before)}, 'otp_changed'),
              'an editor revision captured before HOTP consumption cannot roll its counter back')
        stop()

        # The code is inserted before Start on a second real OpenVPN server.
        start_hotp = otp('HOTP inserted before Start')
        start_vpn = add('Owned OpenVPN code before Start', {**ready['openvpnStart'], 'username': USER, 'password': '{otp}'})
        view = command('getVpnOtpBinding', {'profileId': start_vpn})
        check(view['supported'] is False and view['reason'] == 'vpn_otp_start_mode_required' and view['startSupported'] is True and view['startReason'] is None,
              'an OpenVPN profile with {otp} in its credentials offers only insertion before connecting')
        open_binding(start_vpn)
        select('#vpn-otp-entry', start_hotp)
        wait_for('return !!document.querySelector("#vpn-otp-mode")')
        picker = js('''return {mode:document.querySelector('#vpn-otp-mode').value,
            liveDisabled:[...document.querySelectorAll('#vpn-otp-mode option')].find(o=>o.value==='auto-live').disabled,
            hint:!!document.querySelector('#vpn-otp-start-hint'), saveEnabled:!document.querySelector('#vpn-otp-save').disabled}''')
        check(picker['mode'] == 'auto-start' and picker['liveDisabled'] and picker['hint'] and picker['saveEnabled'],
              'the picker preselects insertion before connecting, disables the live option and explains the HOTP cost')
        click('#vpn-otp-save')
        wait_for('return !document.querySelector(".vpn-otp-modal")')
        binding = command('getVpnOtpBinding', {'profileId': start_vpn})['binding']
        check(binding['otpId'] == start_hotp and binding['mode'] == 'auto-start' and json.loads(library.read_text())['version'] == 4 and entry(start_hotp)['counter'] == '0',
              'saving a before-Start binding records the mode, raises Library to v4 and spends nothing')
        before = entry(start_hotp)
        command('checkProfile', command('profile', {'id': start_vpn}))
        check(entry(start_hotp) == before, 'real Core Check of a before-Start binding does not consume HOTP')
        connect(start_vpn)
        endpoint('connected')
        after = entry(start_hotp)
        check(after['counter'] == '1' and after['revision'] != before['revision'],
              'before-Start OpenVPN reaches actual connected with generated HOTP C+1 inserted into the password')
        otp_state = until(lambda: next((row['otp'] for row in snapshot()['vpn']['endpoints'] if row['tag'] == 'proxy' and row.get('otp') and row['otp']['state'] == 'ready'), None))
        active = json.dumps(command('connectionConfiguration', {'id': start_vpn, 'active': True}))
        check(otp_state['error'] is None and code_at(1) not in active and '{otp}' in active and 'auth_retry' in active,
              'the endpoint reports ready and the active configuration view shows the template, never the inserted code')
        stop()
        scrv1_hotp = otp('HOTP packed as SCRV1 before Start')
        scrv1_vpn = add('Owned OpenVPN SCRV1 before Start', {**ready['openvpnStart'], 'username': USER + '-scrv1', 'password': PASSWORD + '-{otp}', 'static_challenge': 'Owned generated HOTP'})
        bind(scrv1_vpn, scrv1_hotp, 'auto-start')
        connect(scrv1_vpn)
        endpoint('connected')
        check(entry(scrv1_hotp)['counter'] == '1' and code_at(1) not in json.dumps(command('profile', {'id': scrv1_vpn})),
              'a static-challenge profile packs the substituted password and code as SCRV1 and connects without touching the source profile')
        stop()
        # The spent step is never resent: the same entry now yields C2, which this
        # server rejects. Qt then starts the connection again with a code of its
        # own, and stops once its budget runs out.
        connect(start_vpn)
        failed = until(lambda: next((row for row in snapshot()['vpn']['endpoints'] if row['tag'] == 'proxy' and row['authFailed']), None))
        limited = until(lambda: next((row['otp'] for row in snapshot()['vpn']['endpoints']
                                      if row['tag'] == 'proxy' and row.get('otp') and row['otp']['state'] == 'limited'), None), 40)
        spent = int(entry(start_hotp)['counter'])
        time.sleep(2.2)
        check(not failed['challengeId'] and limited['error'] == 'vpn_otp_retry_limited'
              and spent >= 5 and int(entry(start_hotp)['counter']) == spent,
              'a rejected inserted code is never resent, the connection starts again with a fresh one, and the budget ends it')
        stop()

        # A manual URL test of a before-Start binding bakes the code into the
        # disposable test and spends exactly one HOTP step at issue; the same server
        # accepts that code and rejects the next one.
        probe_hotp = otp('HOTP spent by a manual test')
        probe_vpn = add('Owned OpenVPN probed before Start', {**ready['openvpnStart'], 'username': USER, 'password': '{otp}'})
        bind(probe_vpn, probe_hotp, 'auto-start')
        check(next(p for p in snapshot()['profiles'] if p['id'] == probe_vpn)['ipSpeedSupported'], 'a bound before-Start profile advertises isolated tests')
        def completed_batch():
            batch = snapshot().get('urlTests')
            return batch['entries'] if batch and batch.get('entries') and all(e['status'] not in ('queued', 'testing') for e in batch['entries']) else None
        command('startUrlTests', {'ids': [probe_vpn], 'url': 'http://10.78.0.1:9/', 'timeoutMs': 3000})
        rows = until(completed_batch, timeout=45)
        visible = json.dumps([snapshot(), command('getLogs'), command('getMeasurementJournal')])
        check(entry(probe_hotp)['counter'] == '1' and rows[0]['status'] in ('connected-only', 'ok') and code_at(1) not in visible,
              'a manual URL test of a before-Start binding spends exactly one HOTP step, the server accepts that code and the digits never reach snapshot, log or journal')
        command('startUrlTests', {'ids': [probe_vpn], 'url': 'http://10.78.0.1:9/', 'timeoutMs': 3000})
        rows = until(completed_batch, timeout=45)
        check(entry(probe_hotp)['counter'] == '2' and rows[0]['status'] == 'auth-required',
              'the next manual test spends the next step, which this server rejects, and the batch reports authentication instead of retrying')
        command('clearUrlTests')

        two = otp('HOTP manager live counter')
        bind(pool['hotp-two'], two)
        settings_otp()
        row = '[data-otp-id=' + json.dumps(two) + ']'
        until(lambda: js('return document.querySelector(arguments[0]+" [data-otp-remaining]")?.textContent.includes("0")', row))
        connect(pool['hotp-two'])
        until(lambda: len(events('hotp-two', 'otpExact')) == 2)
        until(lambda: js('return document.querySelector(arguments[0]+" [data-otp-remaining]")?.textContent.includes("2")&&document.querySelector(arguments[0]+" [data-otp-code]")?.textContent===arguments[1]', row, code_at(2)))
        check([event['counter'] for event in events('hotp-two', 'otpExact')] == ['1', '2'] and entry(two)['counter'] == '2',
              'two actual OpenConnect forms consume C1/C2 and the already-open manager updates counter and code without Refresh')
        click(row + ' [data-otp-copy]')
        # Read only after the app confirms the write: a fresh display starts with an empty selection.
        wait_for('return document.querySelector("#otp-notice")?.textContent.includes("copied")')
        check(command('readClipboard') == code_at(2) and entry(two)['counter'] == '2',
              'Copy returns the manager current C2 code and never consumes C3')
        stop()

        login_hotp = otp('HOTP login stage spends no code')
        login = command('profile', {'id': pool['hotp-login']})
        login['config'].update(username=FORM_USER, password=FORM_PASSWORD,
            form_entries=[{'form_id': 'login', 'name': 'realm', 'value': 'two'}])
        command('saveProfile', login)
        bind(pool['hotp-login'], login_hotp)
        connect(pool['hotp-login'])
        until(lambda: events('hotp-login', 'otpExact'))
        check(len(events('hotp-login', 'formExact')) == 1 and [row['counter'] for row in events('hotp-login', 'otpExact')] == ['1'] and entry(login_hotp)['counter'] == '1',
              'the credential-only real login form spends no HOTP and the subsequent OTP stage sends exactly C1')
        stop()

        # No HOTP at the credential-only login stage; TOTP is generated live.
        login = command('profile', {'id': pool['totp-login']})
        login['config'].update(username=FORM_USER, password=FORM_PASSWORD,
            form_entries=[{'form_id': 'login', 'name': 'realm', 'value': 'two'}])
        command('saveProfile', login)
        bind(pool['totp-login'], totp)
        before = entry(totp)
        connect(pool['totp-login'])
        until(lambda: events('totp-login', 'otpExact'))
        check(len(events('totp-login', 'formExact')) == 1 and entry(totp) == before,
              'automatic text/password/select login and a real time-based OTP reach the HTTPS verifier without writing the TOTP entry')
        stop()

        template = otp('HOTP repeated live template')
        value = command('profile', {'id': pool['hotp-template']})
        value['config']['form_entries'] = [{'form_id': 'otp', 'name': 'custom_challenge', 'value': 'prefix-{otp}-suffix-{otp}'}]
        command('saveProfile', value)
        bind(pool['hotp-template'], template)
        connect(pool['hotp-template'])
        until(lambda: events('hotp-template', 'otpExact'))
        check(entry(template)['counter'] == '1' and command('profile', {'id': pool['hotp-template']})['config'] == value['config'],
              'a frozen live template replaces every OTP placeholder with one consumed code while source JSON remains exact')
        stop()

        unknown = otp('HOTP must remain unused')
        bind(pool['hotp-unknown'], unknown)
        before = entry(unknown)
        connect(pool['hotp-unknown'])
        endpoint('auth-pending')
        time.sleep(2.2)
        check(not responses('hotp-unknown') and entry(unknown) == before,
              'an unresolved real form remains manual without any auth response or HOTP consumption')
        stop()
        maximum = otp('HOTP exact maximum', counter='9223372036854775807')
        bind(pool['hotp-drop'], maximum)
        before = entry(maximum)
        connect(pool['hotp-drop'])
        endpoint('auth-pending')
        time.sleep(2.2)
        check(not responses('hotp-drop') and entry(maximum) == before,
              'HOTP i64MAX refuses before writing or posting to the real server')
        stop()

        rejected_hotp = otp('HOTP bounded retry')
        bind(pool['hotp-reject'], rejected_hotp)
        connect(pool['hotp-reject'])
        until(lambda: len(events('hotp-reject', 'otpExact')) >= 4)
        time.sleep(2.2)
        check([event['counter'] for event in events('hotp-reject', 'otpExact')] == ['1', '2', '3', '4'] and entry(rejected_hotp)['counter'] == '4',
              'rejected HOTP uses four distinct durable steps then stops its automatic retry budget')
        stop()

        bind(pool['totp-reject'], totp)
        while time.time() % 8 > 2:
            time.sleep(.05)
        connect(pool['totp-reject'])
        first = until(lambda: events('totp-reject', 'otpExact'))[0]
        time.sleep(1.2)
        check(len(responses('totp-reject')) == 1, 'a rejected TOTP is not posted again immediately in the same live clock window')
        until(lambda: len(events('totp-reject', 'otpExact')) >= 2, timeout=12)
        rows = events('totp-reject', 'otpExact')
        check(rows[1]['timeStep'] > first['timeStep'] and not rows[1]['codeRepeated'],
              'a later real clock window supplies a different generated TOTP after rejection')
        command('cancelVpnChallenge', request())
        count = len(responses('totp-reject'))
        time.sleep(2.2)
        check(len(responses('totp-reject')) == count, 'explicit Cancel prevents the automatic OTP loop from responding again')
        stop()

        # A plausible tag in untrusted full JSON is not endpoint provenance.
        hidden_hotp = otp('HOTP hidden independent worker')
        bind(pool['hotp-one'], hidden_hotp)
        fake_tag = 'thronium-route-' + pool['hotp-one']
        full = add('Full JSON fake ordinary endpoint tag', {
            'endpoints': [{**ready['endpoints']['hotp-one'], 'tag': fake_tag}],
            'outbounds': [{'type': 'direct', 'tag': 'direct'}], 'route': {'final': 'direct'}}, 'sing-box-config')
        connect(full)
        until(lambda: any(row['tag'] == fake_tag and row['state'] == 'auth-pending' for row in snapshot()['vpn']['endpoints']))
        time.sleep(2.2)
        check(not responses('hotp-one') and entry(hidden_hotp)['counter'] == '0',
              'a full JSON endpoint with an existing bound profile tag remains manual and cannot impersonate builder provenance')
        stop()

        page()
        current_system = command('settings')['system']
        command('saveSettings', {'section': 'system', 'previous': current_system, 'values': {**current_system, 'disable_tray': True}})
        suspend_snapshots()
        wait_for('return window.__bindingPoll.queue.length>0')
        click('[data-window-action=minimize]')
        wait_for('return document.hidden')
        connect(pool['hotp-one'])
        until(lambda: events('hotp-one', 'otpExact'))
        check(js('return window.__bindingPoll.queue.length>0&&window.__bindingPoll.forwarded===0') and entry(hidden_hotp)['counter'] == '1',
              'the independent backend sends verified HOTP with a hidden window, disabled tray and no forwarded WebView snapshots')
        audit['controlled'].append('automatic WebView snapshots suspended; disabled tray; actual HTTPS verification observed from file before any explicit engine Snapshot')
        resume_snapshots()
        show()
        current_system = command('settings')['system']
        command('saveSettings', {'section': 'system', 'previous': current_system, 'values': initial_system})
        stop()

        dropped = otp('HOTP lost acknowledgement remains consumed')
        bind(pool['hotp-drop'], dropped)
        connect(pool['hotp-drop'])
        until(lambda: events('hotp-drop', 'otpExact'))
        time.sleep(2.2)
        stop()
        rows = events('hotp-drop', 'otpExact')
        counters = [int(row['counter']) for row in rows]
        check(counters and counters[0] == 1 and counters == sorted(set(counters)) and int(entry(dropped)['counter']) >= counters[-1],
              'closing real TLS responses after receipt never reuses a received HOTP step or rolls the durable counter back')

        class Echo(socketserver.BaseRequestHandler):
            def handle(self):
                with contextlib.suppress(OSError):
                    while data := self.request.recv(4096):
                        self.request.sendall(data)

        class EchoServer(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        origin = EchoServer(('127.0.0.1', 0), Echo)
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        direct = add('Unrelated direct socket during automatic OTP', {'type': 'direct', 'udp_fragment': True})
        route = copy.deepcopy(command('routing'))
        active = next(row for row in route['profiles'] if row['id'] == route['active'])
        active['mode'] = 'rules'
        active['rules'] = [{'id': 'otp-unused-aux', 'name': 'Unused auxiliary route', 'enabled': True,
                           'config': {'domain': ['not-requested.otp.fixture.invalid'], 'outbound': 'profile:' + pool['totp-reject']}}]
        command('saveRouting', route)
        before = len(events('totp-reject', 'otpExact'))
        connect(direct)
        until(lambda: len(events('totp-reject', 'otpExact')) > before)
        state = snapshot()
        tag = next(row['tag'] for row in state['vpn']['endpoints'] if row['protocol'] == 'openconnect')
        held = socket.create_connection(('127.0.0.1', state['preferences']['inboundPort']), timeout=5)
        target = '127.0.0.1:' + str(origin.server_address[1])
        held.sendall(f'CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n'.encode())
        header = b''
        while b'\r\n\r\n' not in header:
            data = held.recv(4096)
            assert data, 'owned CONNECT closed before response'
            header += data
        assert b' 200 ' in header
        command('cancelVpnChallenge', request(tag))
        after_cancel = len(responses('totp-reject'))
        time.sleep(2.2)
        held.sendall(b'owned-automatic-otp-direct-connection')
        check(held.recv(128) == b'owned-automatic-otp-direct-connection' and snapshot()['running'] == direct
              and snapshot()['since'] == state['since'] and len(responses('totp-reject')) == after_cancel,
              'Cancel of a genuinely bound auxiliary OTP endpoint preserves a real held direct HTTP CONNECT and its active session')
        held.close()
        held = None
        stop()
        current_route = command('routing')
        command('saveRouting', {**current_route, 'active': initial_routing['active'], 'profiles': initial_routing['profiles']})

        for language in ['ru', 'en']:
            command('preferences', {**snapshot()['preferences'], 'language': language})
            wait_for('return document.documentElement.lang===' + json.dumps(language))
            open_binding(vpn)
            h['request']('POST', h['base'] + '/window/rect', {'width': 390, 'height': 844})
            def layout():
                return js('''const d=document.querySelector('.vpn-otp-modal'),b=d.querySelector('.modal-body');
                    return {width:innerWidth,height:innerHeight,modal:d.getBoundingClientRect().toJSON(),
                        body:b.getBoundingClientRect().toJSON(),scrollWidth:b.scrollWidth,clientWidth:b.clientWidth,
                        save:document.querySelector('#vpn-otp-save').getBoundingClientRect().toJSON(),
                        children:[...b.children].map(e=>({tag:e.tagName,id:e.id,scrollWidth:e.scrollWidth,clientWidth:e.clientWidth,rect:e.getBoundingClientRect().toJSON()}))}''')
            samples = [layout()]
            stable, deadline = 0, time.monotonic() + 3
            while stable < 3 and time.monotonic() < deadline:
                time.sleep(.12)
                sample = layout()
                stable = stable + 1 if sample == samples[-1] else 0
                samples.append(sample)
            audit.setdefault('layout', {})[language] = samples
            box = samples[-1]
            if os.environ.get('_THRONIUM_OTP_LAYOUT_DIAGNOSTIC') == '1':
                from vpn_otp_layout_ui import probe_existing
                probe_existing(h, language)
            initial_fits = stable == 3 and box['width'] == 390 and box['modal']['bottom'] <= box['height'] + 1 \
                and box['scrollWidth'] <= box['clientWidth'] + 1 and box['save']['bottom'] <= box['height']
            # Gate the original resize path before focus or keyboard actions can
            # change WebKit's select layout state. Do not count this separately.
            assert initial_fits, language + ' OTP binding picker initial resize geometry overflows before keyboard input'
            h['screenshot']('vpn-otp-binding-' + language + '-390')
            picker_controls = True
            if os.environ.get('_THRONIUM_OTP_LAYOUT_DIAGNOSTIC') != '1':
                # Exercise the real select keyboard path on the built CSS,
                # without assigning value or dispatching synthetic DOM change.
                from Xlib import X, XK, protocol
                from window_ui import primary
                selected_index = js('return document.querySelector("#vpn-otp-entry").selectedIndex')
                selected_value = js('return document.querySelector("#vpn-otp-entry").value')
                last_value = js('return [...document.querySelector("#vpn-otp-entry").options].filter(o=>!o.disabled).at(-1).value')
                stored_before_keys = library.read_bytes()
                js('''window.__otpPickerKeys=[];window.__otpPickerKeyObserver=e=>window.__otpPickerKeys.push({key:e.key,trusted:e.isTrusted});
                    document.addEventListener('keydown',window.__otpPickerKeyObserver,true);document.querySelector('#vpn-otp-entry').focus();''')
                def native_key(value):
                    count = js('return window.__otpPickerKeys.length')
                    connection, window, pid = primary()
                    try:
                        assert pid == menu.pid, 'keyboard target must be the owned application'
                        for event in (protocol.event.KeyPress, protocol.event.KeyRelease):
                            window.send_event(event(time=X.CurrentTime, root=connection.screen().root, window=window, child=X.NONE,
                                root_x=0, root_y=0, event_x=0, event_y=0, state=0,
                                detail=connection.keysym_to_keycode(XK.string_to_keysym(value)), same_screen=1), propagate=True)
                        connection.sync()
                    finally:
                        connection.close()
                    wait_for('return window.__otpPickerKeys.length>' + str(count))
                try:
                    native_key('Home')
                    wait_for('return document.querySelector("#vpn-otp-entry").value===""')
                    native_key('End')
                    wait_for('return document.querySelector("#vpn-otp-entry").value===' + json.dumps(last_value))
                    native_key('Home')
                    for _ in range(selected_index):
                        native_key('Down')
                    wait_for('return document.querySelector("#vpn-otp-entry").value===' + json.dumps(selected_value))
                    controls = js('''const s=document.querySelector('#vpn-otp-entry'),c=getComputedStyle(s);return {
                        keys:window.__otpPickerKeys,focused:document.activeElement===s,resize:c.resize,
                        overflow:c.overflow,textOverflow:c.textOverflow,labelOverflow:getComputedStyle(s.closest('label')).overflow};''')
                    audit.setdefault('pickerControls', {})[language] = controls
                    picker_controls = bool(controls['keys']) and all(row['trusted'] for row in controls['keys']) \
                        and controls['focused'] and controls['resize'] == 'none' and controls['overflow'] == 'hidden' \
                        and controls['textOverflow'] == 'ellipsis' and controls['labelOverflow'] == 'visible' \
                        and library.read_bytes() == stored_before_keys
                finally:
                    js('document.removeEventListener("keydown",window.__otpPickerKeyObserver,true);delete window.__otpPickerKeyObserver;delete window.__otpPickerKeys')
            final_box = layout()
            audit.setdefault('layoutAfterControls', {})[language] = final_box
            check(picker_controls and initial_fits and final_box['width'] == 390
                  and final_box['modal']['bottom'] <= final_box['height'] + 1
                  and final_box['scrollWidth'] <= final_box['clientWidth'] + 1
                  and final_box['save']['bottom'] <= final_box['height'],
                  language + ' OTP binding picker fits 390px before and after native keyboard selection and focus without a resize handle')
            h['screenshot']('vpn-otp-binding-' + language + '-390-after-controls')
            click('#vpn-otp-close')
            wait_for('return !document.querySelector(".vpn-otp-modal")')
            h['request']('POST', h['base'] + '/window/rect', geometry)
        log_text = json.dumps(command('getLogs', {}))
        configs = [json.dumps(command('profile', {'id': id})['config']) for id in ids]
        generated = {code_at(1), code_at(2)}
        for line in Path(ready['events']).read_text().splitlines():
            row = json.loads(line)
            if row.get('otpExact'):
                generated.add(code_at(int(row['counter']) if row.get('counter') is not None else row['timeStep']))
        check(private_free(log_text) and all(SECRET not in value for value in configs)
              and all(code not in log_text and all(code not in value for value in configs) for code in generated),
              'ordinary logs and profile configurations exclude the stored OTP key and transient generated answers')
    except BaseException:
        with contextlib.suppress(Exception):
            audit['failureBeforeCleanup'] = js('return {hidden:document.hidden,page:document.querySelector(".primary-nav [aria-current=page]")?.textContent,activity:document.querySelector("[data-activity-connection-state]")?.dataset.activityConnectionState,bindingDialog:!!document.querySelector(".vpn-otp-modal"),authDialog:!!document.querySelector(".vpn-auth-modal")}')
            h['screenshot']('vpn-otp-failure-before-cleanup')
        raise
    finally:
        if held:
            held.close()
        with contextlib.suppress(Exception):
            resume_snapshots()
            if js('return document.hidden'):
                show()
            if js('return !!document.querySelector("#vpn-otp-close")'):
                click('#vpn-otp-close')
            command('disconnect')
            current_route = command('routing')
            command('saveRouting', {**current_route, 'active': initial_routing['active'], 'profiles': initial_routing['profiles']})
            command('deleteGroup', {'id': group, 'deleteProfiles': True})
            for id in otp_ids:
                value = entry(id)
                command('otpRemove', {'id': id, 'revision': value['revision']})
            command('preferences', initial['preferences'])
            current_system = command('settings')['system']
            command('saveSettings', {'section': 'system', 'previous': current_system, 'values': initial_system})
            if original_clipboard is not None:
                command('writeClipboard', {'text': original_clipboard})
            elif original_image is not None:
                from gi.repository import Gtk, Gdk
                Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD).set_image(original_image)
                Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD).store()
            h['request']('POST', h['base'] + '/window/rect', geometry)
        if origin:
            origin.shutdown()
            origin.server_close()
        (h['artifacts'] / 'vpn-otp-binding-audit.json').write_text(json.dumps(audit, indent=2) + '\n')
