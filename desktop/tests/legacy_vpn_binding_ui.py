"""Actual Qt archives through native chooser and explicit legacy VPN binding review.

Static import acceptance only. No connection to documentation/example VPN hosts;
the only connection is an owned direct loopback HTTP CONNECT for refusal proof.
"""
import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import socketserver
import tempfile
import threading
import time
import uuid
from native_dialogs import file_dialog
from native_menu import NativeMenu
from native_processes import core_pids

DEFAULT = {'onlyAdvertisedRoutes': True, 'useTunnelDns': True, 'blockOutsideDns': False}
SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
PRIVATE = [SECRET, 'synthetic-password', 'synthetic-user', 'metadata-secret-fixture', 'invalid-fixture-key!', 'Current private fixture', '{otp}', 'otpauth://']


def run(h):
    command, click, select, wait_for, js, check = (h[k] for k in ('command', 'click', 'select', 'wait_for', 'js', 'check'))
    source = Path(os.environ['_THRONIUM_LEGACY_VPN_FIXTURES'])
    manifest = json.loads((source / 'manifest.json').read_text())
    artifacts = Path(h['args'].artifacts)
    menu = NativeMenu()
    assert Path('/proc', str(menu.pid), 'exe').resolve() == Path(h['args'].application).resolve()
    xdg = Path(os.environ['XDG_DATA_HOME'])
    assert xdg.parent.name.startswith('thronium-native-test-')
    library = xdg / 'io.thronium.desktop/library.json'
    initial = command('snapshot')
    geometry = h['request']('GET', h['base'] + '/window/rect')
    held = None
    audit = {'layout': {}, 'rejections': [], 'sourceHashes': {}, 'vpnAuthenticationClaimed': False,
             'pushedPolicyDataPlaneClaimed': False, 'privatePreparedIdsVisible': False}

    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            with contextlib.suppress(OSError):
                while body := self.request.recv(65536):
                    self.request.sendall(body)
    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True
    server = Server(('127.0.0.1', 0), Echo)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def state(): return json.loads(library.read_text())
    def hotp_kept(expected, actual):
        # A restore never lowers a HOTP counter already used for that secret:
        # such entries keep the higher counter under a new revision.
        expected = copy.deepcopy(expected)
        used = max((int(e['counter']) for e in actual['otp'] if e['type'] == 'hotp' and e['secret'] == SECRET), default=0)
        current = {e['id']: e for e in actual['otp']}
        for entry in expected['otp']:
            if entry['type'] == 'hotp' and entry['secret'] == SECRET and int(entry['counter']) < used and entry['id'] in current:
                entry['counter'] = str(used); entry['revision'] = current[entry['id']]['revision']
        return expected
    def digest(value): return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()
    def upgraded(value):
        value = copy.deepcopy(value)
        value['version'] = max(value['version'], 4)
        return value
    def until(predicate, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = predicate()
            if result: return result
            time.sleep(.08)
        raise AssertionError('legacy VPN observation timed out')
    def settings():
        click('.primary-nav button:nth-child(5)')
        click('[data-settings-section=backup]')
        wait_for('return !!document.querySelector("#backup-open:not(:disabled)")')
    def hook():
        js('''const original=window.fetch;const a=window.__legacyVpn={original,previews:[],calls:[]};
        window.fetch=function(input,options){let name;try{if(String(input).includes('/app_command'))name=JSON.parse(options?.body||'{}').name}catch{}
          if(name)a.calls.push(name);const promise=original.apply(this,arguments);
          if(['readBackup','legacyBackupScopes','refreshBackupPreview','previewPreviousBackup'].includes(name))promise.then(r=>r.clone().json()).then(v=>{const p=v?.preview||v;if(p?.token&&p?.current)a.previews.push(p)}).catch(()=>{});
          return promise;};''')
        command('snapshot')
        wait_for('return window.__legacyVpn.calls.includes("snapshot")')
    def previews(): return js('return window.__legacyVpn.previews')
    def wait_preview(count):
        wait_for('return window.__legacyVpn.previews.length>' + str(count))
        wait_for('return !!document.querySelector("#backup-confirm") && !document.querySelector("#backup-refresh").disabled')
        return previews()[-1]
    def open_path(path, invalid=False):
        count = len(previews())
        ru = command('snapshot')['preferences']['language'] == 'ru'
        click('#backup-open')
        file_dialog('Открыть резервную копию' if ru else 'Open backup', path, opening=True)
        wait_for('return !document.querySelector("#backup-open").disabled')
        if path is None: return None
        if invalid:
            wait_for('return !!document.querySelector(".backup-panel > .desktop-inline-error[role=alert]")')
            return None
        return wait_preview(count)
    def open_archive(name): return open_path(source / name)
    def close():
        click('#main-modal > .modal-head > button')
        wait_for('return !document.querySelector("dialog[open]")')
    def toggle(selector):
        count = len(previews()); click(selector); return wait_preview(count)
    def choose(value):
        count = len(previews()); select('#legacy-vpn-bindings-choice', value); return wait_preview(count)
    def refresh():
        count = len(previews()); click('#backup-refresh'); return wait_preview(count)
    def codes(p): return {issue['code'] for issue in p['legacy']['issues']}
    def safe(p):
        text = json.dumps(p, ensure_ascii=False) + js('return document.querySelector("#main-modal")?.textContent||""')
        return not any(word in text for word in PRIVATE)
    def reject(token, code):
        before = state()
        try: command('restoreBackup', {'token': token})
        except RuntimeError as error:
            assert code in str(error) and not any(word in str(error) for word in PRIVATE), 'unexpected or private refusal'
            audit['rejections'].append(code)
        else: raise AssertionError('forbidden import accepted')
        assert state() == before, 'refusal modified Library'
        return True
    def apply():
        if not js('return document.querySelector("#backup-acknowledge").checked'): click('#backup-acknowledge')
        click('#backup-confirm')
        wait_for('return !document.querySelector("dialog[open]") && !!document.querySelector("#backup-notice")')
    def undo():
        click('#backup-undo'); wait_for('return !!document.querySelector("#backup-confirm")'); apply()
    def save_file(path):
        ru = command('snapshot')['preferences']['language'] == 'ru'
        click('#backup-save'); file_dialog('Сохранить резервную копию' if ru else 'Save backup', path)
        wait_for('return !document.querySelector("#backup-save").disabled')
        until(path.exists)
        return json.loads(path.read_text())
    def save_otp(name):
        return command('otpSave', {'id': '', 'revision': '', 'value': {'name': name, 'issuer': 'Current fixture',
            'secret': SECRET, 'type': 'hotp', 'algorithm': 'SHA1', 'counter': '77', 'digits': 6, 'period': 30}})
    def offline(expected): return core_pids(menu.pid) == expected and command('snapshot')['running'] is None
    def echo(label):
        payload = ('legacy-vpn-' + label).encode(); held.sendall(payload); result = b''
        while len(result) < len(payload):
            part = held.recv(4096)
            if not part: break
            result += part
        return result == payload
    def binding_dialog(id):
        click('.primary-nav button:first-child')
        selector = '[data-profile-menu=' + json.dumps(id) + ']'
        wait_for('return !!document.querySelector(' + json.dumps(selector) + ')')
        js('document.querySelector(arguments[0]).scrollIntoView({block:"center",behavior:"instant"})', selector)
        time.sleep(.2); click(selector); click('#menu-vpn-otp-profile')
        wait_for('return !!document.querySelector("#vpn-otp-entry:not(:disabled)")')
    def keyboard_choice(language):
        from Xlib import X, XK, protocol
        from window_ui import primary
        stored = library.read_bytes()
        js("window.__legacyVpn.keys=[];window.__legacyVpn.onKey=e=>window.__legacyVpn.keys.push({key:e.key,trusted:e.isTrusted,target:e.target.id});document.addEventListener('keydown',window.__legacyVpn.onKey,true);document.querySelector('#legacy-vpn-bindings-choice').focus()")
        try:
            for key, wanted in [('Home', 'require-choice'), ('End', 'manual')]:
                count = len(previews()); token_before = previews()[-1]['token']
                js('document.querySelector("#legacy-vpn-bindings-choice").focus()')
                assert js('return document.activeElement===document.querySelector("#legacy-vpn-bindings-choice")')
                connection, window, pid = primary()
                try:
                    assert pid == menu.pid
                    for event in (protocol.event.KeyPress, protocol.event.KeyRelease):
                        window.send_event(event(time=X.CurrentTime, root=connection.screen().root, window=window, child=X.NONE,
                            root_x=0,root_y=0,event_x=0,event_y=0,state=0,detail=connection.keysym_to_keycode(XK.string_to_keysym(key)),same_screen=1),propagate=True)
                    connection.sync()
                finally: connection.close()
                updated = wait_preview(count)
                assert updated['token'] != token_before and library.read_bytes() == stored
                wait_for('return document.querySelector("#legacy-vpn-bindings-choice").value===' + json.dumps(wanted))
            controls=js('const s=document.querySelector("#legacy-vpn-bindings-choice");return {keys:window.__legacyVpn.keys,focused:document.activeElement===s,resize:getComputedStyle(s).resize}')
            audit.setdefault('controls',{})[language]=controls
            return controls['resize']=='none' and len(controls['keys'])>=2 and all(k['trusted'] and k['target']=='legacy-vpn-bindings-choice' for k in controls['keys']) and library.read_bytes()==stored
        finally: js('document.removeEventListener("keydown",window.__legacyVpn.onKey,true)')
    def layout(language):
        samples = []
        for _ in range(3):
            samples.append(js('''const d=document.querySelector('#main-modal'),b=d.querySelector('.modal-body'),f=d.querySelector('.modal-footer'),s=document.querySelector('#legacy-vpn-bindings-choice');
              const rect=e=>{const r=e.getBoundingClientRect();return {left:r.left,right:r.right,bottom:r.bottom,width:r.width}};
              return {width:innerWidth,height:innerHeight,dialog:rect(d),body:rect(b),footer:rect(f),scroll:b.scrollWidth,client:b.clientWidth,
                select:rect(s),resize:getComputedStyle(s).resize,overflow:getComputedStyle(s).overflow,textOverflow:getComputedStyle(s).textOverflow};'''))
            time.sleep(.12)
        audit['layout'][language] = samples
        assert all(v['width'] == 390 and v['scroll'] <= v['client'] + 1 and v['dialog']['right'] <= 391
                   and v['footer']['bottom'] <= v['height'] + 1 and v['resize'] == 'none' for v in samples), 'original-path legacy VPN geometry overflow'
        h['screenshot']('legacy-vpn-bindings-' + language + '-390')
        return True

    with tempfile.TemporaryDirectory(prefix='legacy-vpn-native-') as temporary:
        root = Path(temporary)
        baseline_path = root / 'baseline.thronium.json'
        try:
            for name, row in manifest['archives'].items():
                assert hashlib.sha256((source / name).read_bytes()).hexdigest() == row['sha256']
                audit['sourceHashes'][name] = row['sha256']
            command('disconnect')
            command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark'})
            wait_for('return document.documentElement.lang==="en"'); settings(); hook()
            baseline = state(); save_file(baseline_path)
            with socket.socket() as free: free.bind(('127.0.0.1', 0)); port = free.getsockname()[1]
            command('connectionSettings', {'mode': 'local', 'port': port})
            group = command('saveGroup', {'name': 'Current VPN binding fixtures', 'subscription': None})['id']
            current_profile = command('saveProfile', {'name': 'Same name', 'groupId': group, 'kind': 'sing-box-outbound',
                'config': {'type': 'openvpn-client', 'server': '192.0.2.20', 'server_port': 1194,
                           'username': 'Current fixture', 'password': 'Current private fixture', 'static_challenge': 'Code', 'auth_retry': 'interact'}})['id']
            direct = command('saveProfile', {'name': 'Owned direct CONNECT', 'groupId': group, 'kind': 'sing-box-outbound',
                'config': {'type': 'direct', 'udp_fragment': True}})['id']
            otp = save_otp('Same name')
            view = command('getVpnOtpBinding', {'profileId': current_profile})
            command('saveVpnOtpBinding', {'profileId': current_profile, 'editToken': view['editToken'], 'otpId': otp['id'], 'otpRevision': otp['revision']})
            command('select', {'id': direct})
            audit['beforeNonNetworkSettingsCorePids'] = core_pids(menu.pid)
            testing = command('settings')['testing']
            command('saveSettings', {'section': 'testing', 'previous': testing, 'values': {**testing, 'test_concurrent': 3}})
            audit['afterNonNetworkSettingsCorePids'] = core_pids(menu.pid)
            before = state(); before_bytes = library.read_bytes(); no_core = core_pids(menu.pid)
            assert not no_core
            check(before['version'] == 3 and before['vpnOtpBindings'][current_profile]['otpId'] == otp['id'], 'current same-name OTP and existing binding form an independent version-3 baseline')
            open_path(None)
            check(state() == before and offline(no_core), 'cancelling native archive selection preserves Library and never starts ThroniumCore')
            first = open_archive('default-policy-parts-09.thrbackup')
            check(first['legacy']['vpnBindingCount'] == 2 and first['legacy']['vpnBindingsPlanned'] == 0 and not first['legacy']['canApply']
                  and first['legacy']['scopes']['vpnBindings'] == 'require-choice' and not first['legacy']['scopes']['otp'], 'actual Qt VPN archive requires an explicit choice and does not select OTP implicitly')
            rows = first['legacy']['vpnBindings']
            check({(r['sourceId'], r['otpSourceId'], r['manualAllowed']) for r in rows} == {(17, 41, True), (41, 17, False)}
                  and all(set(r) == {'sourceId', 'otpSourceId', 'name', 'otpName', 'manualAllowed', 'mode'} for r in rows) and safe(first), 'review exposes bounded source provenance despite equal OTP names and excludes private source values')
            check(reject(first['token'], 'legacy_import_blocked') and 'legacy_vpn_bindings_choice_required' in codes(first), 'backend rejects the unchosen complete import atomically')
            auto = choose('automatic')
            check(not auto['legacy']['canApply'] and 'legacy_vpn_bindings_require_otp' in codes(auto), 'automatic binding requires OTP selected from this source archive')
            manual = choose('manual')
            check(not manual['legacy']['canApply'] and 'legacy_vpn_binding_required' in codes(manual) and safe(manual), 'manual mode refuses the mixed OpenConnect OTP template without dropping the other profile')
            choose('automatic'); accepted = toggle('#legacy-scope-otp')
            check(accepted['legacy']['canApply'] and accepted['legacy']['vpnBindingsPlanned'] == 2 and 'legacy_otp_bindings_deferred' not in codes(accepted)
                  and js('return !document.querySelector("#backup-acknowledge").checked && document.querySelector("#backup-confirm").disabled'), 'selecting source OTP plans exactly two links while retaining the acknowledgement gate')
            click('#backup-acknowledge'); off = toggle('#legacy-scope-profiles')
            check(off['legacy']['canApply'] and off['legacy']['vpnBindingsPlanned'] == 0 and not js('return !!document.querySelector("#legacy-vpn-bindings-choice")')
                  and not js('return document.querySelector("#backup-acknowledge").checked'), 'profiles opt-out leaves independent OTP-only import and clears acknowledgement')
            accepted = toggle('#legacy-scope-profiles'); refreshed = refresh()
            check(refreshed['token'] != accepted['token'] and refreshed['legacy']['scopes'] == accepted['legacy']['scopes']
                  and refreshed['legacy']['vpnBindings'] == accepted['legacy']['vpnBindings'] and reject(accepted['token'], 'backup_preview_expired'), 'refresh preserves source mapping and choices while expiring the old public preview token')
            close()
            check(library.read_bytes() == before_bytes and offline(no_core), 'preview, scope toggles, refresh and Cancel leave exact disk bytes, HOTP counters and core processes unchanged')

            # Long-name Manual fixture has no OTP rows. Sample original resize
            # path BEFORE any focus/key sequence that could reset WebKit layout.
            for language in ['en', 'ru']:
                command('preferences', {**command('snapshot')['preferences'], 'language': language})
                wait_for('return document.documentElement.lang===' + json.dumps(language))
                p = open_archive('manual-ovpn-only-parts-01.thrbackup'); p = choose('manual')
                h['request']('POST', h['base'] + '/window/rect', {'width': 390, 'height': 820})
                check(p['legacy']['canApply'] and layout(language) and safe(p), 'long source name, explicit Manual choice and footer fit ' + language + ' at 390 pixels before keyboard interaction')
                check(keyboard_choice(language), 'real owned keyboard targets the focused selector and reaches both choices without applying or spending OTP in ' + language)
                close(); h['request']('POST', h['base'] + '/window/rect', {'width': 1280, 'height': 860})
            command('preferences', {**command('snapshot')['preferences'], 'language': 'en'})
            wait_for('return document.documentElement.lang==="en"')
            before = state()
            p = open_archive('manual-ovpn-only-parts-01.thrbackup')
            check(p['legacy']['vpnBindingCount'] == 1 and not p['legacy']['inventory']['parts']['otp'] and not p['legacy']['canApply'], 'physical profiles-only manual fixture still requires explicit consent and exposes no OTP section')
            p = choose('automatic')
            check(not p['legacy']['canApply'] and 'legacy_vpn_bindings_require_otp' in codes(p), 'same-name current OTP cannot satisfy a source profile-only archive in automatic mode')
            p = choose('manual'); apply(); imported = state()
            added = imported['profiles'][len(before['profiles']):]
            check(len(added) == 1 and added[0]['config']['type'] == 'openvpn-client' and added[0]['config']['static_challenge'] == 'OTP code'
                  and added[0]['vpnPolicy'] == DEFAULT and imported['otp'] == before['otp'] and imported['vpnOtpBindings'] == before['vpnOtpBindings'], 'explicit Manual imports the full OpenVPN challenge and policy without creating or consuming an OTP binding')
            check(imported['version'] == 4 and offline(no_core), 'policy import promotes the reader to version 4 without launching either a VPN or the core')
            undo()
            check(state() == upgraded(before) and offline(no_core), 'Undo restores every business field while retaining the monotonic version-4 reader guard')

            before = state()
            command('connect', {'id': direct})
            held = socket.create_connection(('127.0.0.1', port), timeout=5)
            target = '127.0.0.1:' + str(server.server_address[1])
            held.sendall(f'CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n'.encode()); headers = b''
            while b'\r\n\r\n' not in headers:
                part = held.recv(4096); assert part; headers += part
            assert b' 200 ' in headers.split(b'\r\n', 1)[0]
            active_pids = core_pids(menu.pid); since = command('snapshot')['since']
            routing = command('routing')
            active_route = next(r for r in routing['profiles'] if r['id'] == routing['active'])
            active_route['mode'] = 'rules'
            active_route['rules'] = [{'id': 'legacy-vpn-pending', 'name': 'Saved pending rejection', 'enabled': True, 'config': {'network': 'tcp', 'action': 'reject'}}]
            command('saveRouting', routing); command('select', {'id': current_profile})
            before = state()
            assert command('snapshot')['routing']['pending']
            p = open_archive('default-policy-parts-09.thrbackup'); choose('automatic'); p = toggle('#legacy-scope-otp'); click('#backup-acknowledge')
            check(js('return document.querySelector("#backup-confirm").disabled') and echo('review') and core_pids(menu.pid) == active_pids, 'active review preserves a real owned HTTP CONNECT and disables import in the UI')
            check(reject(p['token'], 'backup_disconnect_first') and echo('backend-refusal') and state() == before
                  and command('snapshot')['since'] == since and command('snapshot')['routing']['pending']
                  and command('snapshot')['selected'] == current_profile, 'backend active-session guard keeps the same session, socket, pending routing, selection, current binding and counters')
            close(); held.close(); held = None; command('disconnect')
            offline_pids = core_pids(menu.pid)
            before = state()
            p = open_archive('default-policy-parts-09.thrbackup'); choose('automatic'); p = toggle('#legacy-scope-otp')
            save_otp('Added while reviewing')
            stale_before = state()
            check(reject(p['token'], 'backup_preview_stale') and state() == stale_before, 'a legitimate current OTP addition makes the prepared import stale without partial profile changes')
            fresh = refresh()
            check(fresh['legacy']['scopes'] == p['legacy']['scopes'] and fresh['incoming']['otp'] == len(stale_before['otp']) + 2
                  and not js('return document.querySelector("#backup-acknowledge").checked'), 'refresh rebases onto the new current entry and retains explicit Auto plus OTP selection')
            apply(); imported = state()
            profiles = imported['profiles'][len(stale_before['profiles']):]; entries = imported['otp'][len(stale_before['otp']):]
            check(len(profiles) == len(entries) == 2 and [p['config']['type'] for p in profiles] == ['openconnect', 'openvpn-client']
                  and all(e['counter'] == '9007199254740993' and e['secret'] == SECRET for e in entries), 'successful apply preserves Qt profile order, duplicate OTP names and counters beyond JavaScript integer precision')
            bindings = imported['vpnOtpBindings']
            check(bindings[profiles[0]['id']]['otpId'] == entries[0]['id'] and bindings[profiles[1]['id']]['otpId'] == entries[1]['id']
                  and all(bindings[p['id']]['otpId'] != otp['id'] and bindings[p['id']]['mode'] == 'auto-live' for p in profiles), 'source 41 to OTP17 and source17 to OTP41 resolve to their newly imported UUIDs rather than equal current names')
            ids = [p['id'] for p in profiles] + [e['id'] for e in entries] + [e['revision'] for e in entries] + [bindings[p['id']]['revision'] for p in profiles]
            check(len(ids) == len(set(ids)) and all(str(uuid.UUID(v)) == v for v in ids), 'new profile, OTP and binding identities and revisions are distinct valid UUIDs')
            check(all(p['vpnPolicy'] == DEFAULT and p['config']['username'] == ' synthetic-user ' and p['config']['password'] == ' synthetic-password ' for p in profiles)
                  and any(e['value'] == '{otp}' for e in profiles[0]['config']['form_entries']), 'profile policy, whitespace-bearing credentials and the original OpenConnect OTP template persist exactly')
            stripped = copy.deepcopy(imported); stripped['profiles'] = stripped['profiles'][:len(stale_before['profiles'])]
            stripped['otp'] = stripped['otp'][:len(stale_before['otp'])]; stripped['groups'] = stripped['groups'][:len(stale_before['groups'])]
            for p in profiles: del stripped['vpnOtpBindings'][p['id']]
            check(stripped == stale_before and offline(offline_pids), 'merge preserves all current groups, profiles, selected ID, routing, settings, OTP entries and existing binding with no offline core launch')
            for p, entry in zip(profiles, entries):
                binding_dialog(p['id'])
                check(js('return document.querySelector("#vpn-otp-entry").value===arguments[0]', entry['id'])
                      and command('getVpnOtpBinding', {'profileId': p['id']})['binding'] == bindings[p['id']], 'the ordinary profile binding dialog reopens the imported UUID for ' + p['config']['type'])
                click('#vpn-otp-close'); wait_for('return !document.querySelector("dialog[open]")')
            settings(); saved_path = root / 'imported.thronium.json'; exported = save_file(saved_path)
            check(exported['version'] == 1 and exported['library'] == imported, 'real native full-backup Save preserves version-4 policy, exact bindings and unconsumed HOTP counters')
            audit.setdefault('previewHistory', []).extend(previews())
            h['request']('POST', h['base'] + '/refresh', {})
            wait_for('return !!document.querySelector(".primary-nav")'); settings(); hook()
            check(state() == imported and offline(offline_pids), 'WebView reload preserves imported metadata and all OTP revisions without connecting')
            undo(); restored = state()
            check(restored == hotp_kept(stale_before, restored), 'Previous library restores the pre-import business state without lowering used HOTP counters')
            open_path(saved_path); apply()
            reopened = state()
            check(reopened == hotp_kept(imported, reopened) and offline(offline_pids), 'native full-backup Open and restore preserve the imported binding graph and used HOTP counters')
            undone = state() if undo() is None else None
            check(undone == hotp_kept(stale_before, undone), 'undoing the full-backup restore returns the current graph without lowering used HOTP counters')

            before_start = state()
            p = open_archive('start-otp-parts-09.thrbackup')
            check({r['mode'] for r in p['legacy']['vpnBindings']} == {'auto-live', 'auto-start'} and not p['legacy']['canApply'], 'Qt credential placeholder and live prompt show their distinct OTP modes before consent')
            p = choose('manual')
            check(not p['legacy']['canApply'], 'manual choice refuses a credential placeholder without its source OTP')
            choose('automatic'); p = toggle('#legacy-scope-otp')
            check(p['legacy']['canApply'] and 'legacy_vpn_bindings_auto_start' in codes(p) and safe(p), 'automatic import plans before-Start OTP and explains code consumption only at Connect')
            apply(); imported_start = state()
            start_profile = next(p for p in imported_start['profiles'][len(before_start['profiles']):] if p['config']['type'] == 'openvpn-client')
            binding = imported_start['vpnOtpBindings'][start_profile['id']]
            entry = next(e for e in imported_start['otp'] if e['id'] == binding['otpId'])
            check(binding['mode'] == 'auto-start' and start_profile['config']['password'] == 'prefix-{otp}' and entry['counter'] == '9007199254740993', 'actual Qt archive retains the credential template, before-Start binding and unconsumed precise HOTP counter')
            binding_dialog(start_profile['id'])
            check(command('getVpnOtpBinding', {'profileId': start_profile['id']})['binding']['mode'] == 'auto-start', 'ordinary binding editor reopens the imported before-Start mode')
            h['screenshot']('legacy-otp-before-start')
            click('#vpn-otp-close'); wait_for('return !document.querySelector("dialog[open]")')
            settings(); undo()
            check(state() == before_start and offline(offline_pids), 'undo restores the exact library after before-Start import without launching Core or generating OTP')

            for name, wanted in [('missing-otp-parts-09.thrbackup', 'legacy_vpn_binding_missing'),
                                 ('invalid-otp-parts-09.thrbackup', 'legacy_otp_secret_invalid')]:
                before = state(); open_archive(name); choose('automatic'); p = toggle('#legacy-scope-otp')
                check(not p['legacy']['canApply'] and wanted in codes(p) and safe(p) and reject(p['token'], 'legacy_import_blocked'), 'missing or invalid source OTP blocks the whole selected batch: ' + name)
                close(); check(state() == before and offline(offline_pids), 'failed source binding conversion leaves exact Library and core state: ' + name)
            before = state(); p = open_archive('default-policy-parts-01.thrbackup'); choose('automatic')
            check(not js('return !document.querySelector("#legacy-scope-otp").disabled') and not previews()[-1]['legacy']['canApply'], 'Parts1 forbids importing physically present but excluded OTP rows')
            close(); p = open_archive('default-policy-parts-08.thrbackup')
            check(not p['legacy']['inventory']['parts']['profiles'] and p['legacy']['vpnBindingCount'] == 0
                  and not js('return !!document.querySelector("#legacy-vpn-bindings-choice")'), 'Parts8 exposes only independent OTP and no source VPN choices')
            p = toggle('#legacy-scope-otp'); apply(); otp_only = state()
            check(len(otp_only['otp']) == len(before['otp']) + 2 and otp_only['profiles'] == before['profiles'] and otp_only['vpnOtpBindings'] == before['vpnOtpBindings'], 'OTP-only import never reconstructs excluded VPN profiles or links')
            undo(); check(state() == before, 'OTP-only Undo preserves the existing policy and binding graph exactly')
            p = open_archive('policy-off-parts-09.thrbackup'); choose('automatic'); toggle('#legacy-scope-otp'); apply(); off = state()
            check(all(p['vpnPolicy'] == {k: False for k in DEFAULT} for p in off['profiles'][len(before['profiles']):]), 'explicit false Qt policy values remain distinct from omitted defaults after import')
            undo(); check(state() == before, 'Undo of the explicit-false policy batch restores exact current values')
            p = open_archive('complete-schema-default-policy-parts-31.thrbackup'); choose('automatic'); p = toggle('#legacy-scope-otp')
            check(p['legacy']['canApply'] and all(p['legacy']['inventory']['parts'][k] for k in ['profiles', 'routes', 'settings', 'otp'])
                  and p['legacy']['vpnBindingsPlanned'] == 2, 'corrected complete-schema Parts31 is accepted without implicitly selecting unrelated sections')
            apply(); all_parts = state()
            check(len(all_parts['profiles']) == len(before['profiles']) + 2 and all_parts['routing'] == before['routing'] and all_parts['settings'] == before['settings'], 'Parts31 imports only the explicitly selected profiles, OTP and links while routes and settings stay exact')
            undo(); check(state() == before, 'complete-schema import Undo restores the exact pre-import state')
            count = len(previews()); open_path(source / 'default-policy-parts-31.thrbackup', invalid=True)
            check(len(previews()) == count and not js('return !!document.querySelector("dialog[open]")') and state() == before, 'historical incomplete-schema Parts31 remains rejected without manufacturing a preview or mutating data')
            check(offline(offline_pids) and all(hashlib.sha256((source / name).read_bytes()).hexdigest() == value for name, value in audit['sourceHashes'].items()), 'all nine immutable Qt archives remain byte-identical and static import never starts VPN authentication')
            open_path(baseline_path); apply()
            check(state() == upgraded(baseline), 'final baseline restore removes every fixture record while keeping only the monotonic reader version upgrade')
            audit['passed'] = True
        finally:
            with contextlib.suppress(Exception):
                audit['previews'] = previews(); audit['finalLibrarySha256'] = digest(state())
                if not audit.get('passed'): h['screenshot']('legacy-vpn-failure-before-cleanup')
            (artifacts / 'legacy-vpn-review.json').write_text(json.dumps(audit, ensure_ascii=False, indent=2) + '\n')
            if held: held.close()
            with contextlib.suppress(Exception):
                if js('return !!document.querySelector("dialog[open]")'): close()
                command('disconnect')
                js('if(window.__legacyVpn){window.fetch=window.__legacyVpn.original;delete window.__legacyVpn}')
                command('preferences', initial['preferences'])
                h['request']('POST', h['base'] + '/window/rect', geometry)
            server.shutdown(); server.server_close()
