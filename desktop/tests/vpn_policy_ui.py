"""Isolated native34 foundation draft; requires final policy-aware App pin.

These editor/store cases do not claim pushed-route or DNS data-plane behavior.
The final wrapper will freeze this module and its shared native dependencies.
"""
import base64
import contextlib
import copy
import json
import os
import socket
import socketserver
import threading
import tempfile
from native_dialogs import file_dialog
from native_menu import NativeMenu
from native_processes import core_pids
from pathlib import Path
import time

KEYS = ('onlyAdvertisedRoutes', 'useTunnelDns', 'blockOutsideDns')
DEFAULT = dict(zip(KEYS, (True, True, False)))
ALL_FALSE = dict.fromkeys(KEYS, False)


def run(h):
    command, click, fill, select, wait_for, js, check = (h[k] for k in ('command', 'click', 'fill', 'select', 'wait_for', 'js', 'check'))
    initial = command('snapshot')
    initial_route = command('routing')
    ready = json.loads(Path(os.environ['_THRONIUM_VPN_CREDENTIALS_READY']).read_text())
    owned_menu = NativeMenu()
    assert Path('/proc', str(owned_menu.pid), 'exe').resolve() == Path(h['args'].application).resolve()
    original_clipboard = None
    with contextlib.suppress(Exception):
        original_clipboard = command('readClipboard')
    held, origin = None, None
    geometry = h['request']('GET', h['base'] + '/window/rect')
    root = Path(os.environ['XDG_DATA_HOME'])
    assert root.parent.name.startswith('thronium-native-test-')
    library = root / 'io.thronium.desktop/library.json'
    group = command('saveGroup', {'name': 'VPN policy foundation', 'subscription': None})['id']
    audit = {'layout': {}, 'runtimeDataPlaneClaimed': False, 'expectedChecks': 60}

    def until(predicate, timeout=12):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(.07)
        raise AssertionError('policy native condition timed out')

    def transport_hook():
        js('''const original=window.fetch;const state=window.__policyTransport={original,calls:[]};
            window.fetch=function(input,options){let name;try{if(String(input).includes('/app_command'))name=JSON.parse(options?.body||'{}').name}catch{}
                if(name)state.calls.push(name);return original.apply(this,arguments)};''')
        command('snapshot')
        wait_for('return window.__policyTransport.calls.includes("snapshot")')
        js('window.__policyTransport.calls=[]')

    def transport_unhook():
        js('if(window.__policyTransport){window.fetch=window.__policyTransport.original;delete window.__policyTransport}')

    def state():
        return json.loads(library.read_text())

    def profile(id):
        return command('profile', {'id': id})

    def add(name, config, **metadata):
        return command('saveProfile', {'name': name, 'groupId': group, 'kind': 'sing-box-outbound',
                                      'config': config, **metadata})['id']

    def menu(id, item):
        click('.primary-nav button:first-child')
        selector = '[data-profile-menu=' + json.dumps(id) + ']'
        wait_for('return !!document.querySelector(' + json.dumps(selector) + ')')
        js('''window.__policyScrollAt=Date.now();window.__policyScroll=()=>window.__policyScrollAt=Date.now();
            document.addEventListener('scroll',window.__policyScroll,true);
            document.querySelector(arguments[0]).scrollIntoView({block:'center',behavior:'instant'});''', selector)
        wait_for('return Date.now()-window.__policyScrollAt>150')
        js('document.removeEventListener("scroll",window.__policyScroll,true);delete window.__policyScroll;delete window.__policyScrollAt')
        click(selector)
        click(item)

    def editor(id):
        menu(id, '#menu-edit-profile')
        wait_for('return !!document.querySelector("#profile-editor")')
        click('[data-profile-tab="vpn-policy"]')

    def close():
        click('#main-modal > .modal-head > button')
        if js('return !!document.querySelector("[data-confirm-accept]")'):
            click('[data-confirm-accept]')
        wait_for('return !document.querySelector("dialog[open]")')

    def save():
        click('button[form="profile-editor"]')
        wait_for('return !document.querySelector("dialog[open]")')

    def values():
        return js('return Object.fromEntries(arguments[0].map(k=>[k,document.querySelector("#vpn-policy-"+k).checked]))', list(KEYS))

    def config_draft():
        click('[data-profile-tab="json"]')
        result = json.loads(js('return document.querySelector("#profile-json").value'))
        click('[data-profile-tab="vpn-policy"]')
        return result

    def rejection(payload, code):
        before = library.read_bytes()
        try:
            command('saveProfile', payload)
        except RuntimeError as error:
            assert code in str(error)
        else:
            raise AssertionError('invalid policy mutation was accepted')
        return library.read_bytes() == before

    try:
        command('disconnect')
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark', 'connectionMode': 'local'})
        wait_for('return document.documentElement.lang==="en"')
        select('.group-strip select', 'all')
        configs = {
            'openvpn': {'type': 'openvpn-client', 'server': '127.0.0.1', 'server_port': 1194,
                        'mode': 'tls', 'network': 'udp', 'username': 'policy-user', 'password': 'policy-private-source',
                        'tls': {'remote_certificate_tls': 'server'}},
            'openconnect': {'type': 'openconnect', 'server': '127.0.0.1', 'server_port': 443,
                            'username': 'policy-user', 'password': 'policy-private-source'},
        }
        # Real new-profile editor path: viewing policy never implicitly enables it.
        before_new, version = library.read_bytes(), state()['version']
        click('.add-connection')
        click('#add-choice-advanced')
        select('#profile-type', 'openvpn')
        click('[data-profile-tab="vpn-policy"]')
        check(js('return !!document.querySelector("#vpn-policy-enable")') and library.read_bytes() == before_new,
              'new advanced OpenVPN editor starts with no policy and does not write defaults')
        click('#vpn-policy-enable')
        check(values() == DEFAULT and library.read_bytes() == before_new,
              'explicit policy enable in a new unsaved profile remains only a draft')
        close()
        check(library.read_bytes() == before_new and state()['version'] == version,
              'discarding a new policy profile leaves Library bytes and version exact')
        ids = {}
        for protocol, config in configs.items():
            id = add('Unconfigured ' + protocol, config)
            ids[protocol] = id
            before, version = library.read_bytes(), state()['version']
            editor(id)
            check(js('return !!document.querySelector("#vpn-policy-enable")&&!document.querySelector("#vpn-policy-fields")')
                  and config_draft() == config and library.read_bytes() == before,
                  protocol + ' existing absent policy remains absent across opening and JSON/fields tab changes')
            click('[data-profile-tab="main"]')
            fill('#profile-name', 'Renamed ' + protocol)
            save()
            check('vpnPolicy' not in profile(id) and profile(id)['config'] == config and state()['version'] == version,
                  protocol + ' ordinary rename/save does not materialize policy or promote the Library')
            before = library.read_bytes()
            editor(id)
            click('#vpn-policy-enable')
            check(values() == DEFAULT and library.read_bytes() == before,
                  protocol + ' explicit Enable drafts exact Qt true/true/false defaults without saving')
            click('#vpn-policy-onlyAdvertisedRoutes')
            click('#vpn-policy-useTunnelDns')
            check(values() == ALL_FALSE and config_draft() == config,
                  protocol + ' three boolean policy values stay outside the exact core config JSON')
            click('#vpn-policy-blockOutsideDns')
            check(values() == {**ALL_FALSE, 'blockOutsideDns': True} and config_draft() == config,
                  protocol + ' third policy checkbox preserves true independently of disabled advertised-route gating')
            close()
            check(library.read_bytes() == before and 'vpnPolicy' not in profile(id),
                  protocol + ' discarding enabled policy leaves the saved profile and version unchanged')

        id = ids['openvpn']
        editor(id)
        click('#vpn-policy-enable')
        click('#vpn-policy-useTunnelDns')
        click('#vpn-policy-blockOutsideDns')
        expected = {**DEFAULT, 'useTunnelDns': False, 'blockOutsideDns': True}
        save()
        check(profile(id)['vpnPolicy'] == expected and state()['version'] == 4 and profile(id)['config'] == configs['openvpn'],
              'Save atomically stores profile policy outside source config and promotes Library version4')
        h['request']('POST', h['base'] + '/refresh', {})
        wait_for('return !!document.querySelector(".add-connection")')
        editor(id)
        check(values() == expected and config_draft() == configs['openvpn'],
              'real WebView reload and reopen retain explicit false rather than replacing it with effective defaults')
        save()
        check(profile(id)['vpnPolicy'] == expected, 'unchanged editor Save preserves all policy metadata')
        before = library.read_bytes()
        editor(id)
        click('#vpn-policy-clear')
        check(js('return !!document.querySelector("#vpn-policy-enable")') and library.read_bytes() == before,
              'Clear removes only the current policy draft until Save')
        close()
        check(library.read_bytes() == before and profile(id)['vpnPolicy'] == expected,
              'Cancel after Clear preserves the saved policy')
        editor(id)
        click('#vpn-policy-clear')
        save()
        check('vpnPolicy' not in profile(id) and state()['version'] == 4,
              'Clear+Save removes policy metadata without downgrading the Library')
        command('saveProfile', {**profile(id), 'vpnPolicy': ALL_FALSE})
        check(profile(id)['vpnPolicy'] == ALL_FALSE, 'all-false policy is distinct from missing metadata')
        payload = profile(id)
        payload.pop('vpnPolicy')
        payload['name'] = 'Omitted metadata update'
        command('saveProfile', payload)
        check(profile(id)['vpnPolicy'] == ALL_FALSE, 'omitted policy in a save request preserves existing metadata')
        check(rejection({**profile(id), 'vpnPolicy': {'onlyAdvertisedRoutes': True}}, 'invalid_command_payload'),
              'partial invalid policy refuses the whole update without mutating the Library')
        editor(id)
        select('#profile-type', 'socks')
        check(js('return !!document.querySelector("#vpn-policy-unsupported")') and profile(id)['vpnPolicy'] == ALL_FALSE,
              'switching to an unsupported protocol retains the policy draft and shows an explicit removal requirement')
        click('button[form="profile-editor"]')
        wait_for('return !!document.querySelector("#profile-editor [role=alert]")')
        check(profile(id)['config'] == configs['openvpn'], 'unsupported protocol Save cannot silently drop profile policy')
        select('#profile-type', 'openvpn')
        click('[data-profile-tab="vpn-policy"]')
        check(values() == ALL_FALSE and config_draft() == configs['openvpn'],
              'switching back restores the exact protocol draft and policy values')
        close()
        # Native config-only editor carries no replacement policy payload.
        menu(id, '#export-one')
        wait_for('return !!document.querySelector("#configuration-json")')
        changed_config = {**configs['openvpn'], 'username': 'edited-source-username'}
        fill('#configuration-json', json.dumps(changed_config))
        click('#configuration-save')
        wait_for('return !document.querySelector("dialog[open]")')
        check(profile(id)['config'] == changed_config and profile(id)['vpnPolicy'] == ALL_FALSE,
              'config-only native editor preserves separately stored VPN policy metadata')
        before_ids = {row['id'] for row in command('snapshot')['profiles']}
        menu(id, '#menu-clone-profile')
        wait_for('return !document.querySelector("#menu-clone-profile")')
        clones = until(lambda: [row['id'] for row in command('snapshot')['profiles'] if row['id'] not in before_ids])
        assert len(clones) == 1
        clone = clones[0]
        check(profile(clone)['vpnPolicy'] == ALL_FALSE and profile(clone)['config'] == changed_config,
              'native Clone allocates a new profile ID and preserves exact policy and source config')
        editor(clone)
        before_clear = library.read_bytes()
        select('#profile-type', 'socks')
        click('#vpn-policy-clear-unsupported')
        check(not js('return !!document.querySelector("#vpn-policy-unsupported")') and library.read_bytes() == before_clear,
              'explicit removal on an unsupported protocol clears only the unsaved policy draft')
        click('[data-profile-tab="json"]')
        socks_config = {'type': 'socks', 'server': '127.0.0.1', 'server_port': 9}
        fill('#profile-json', json.dumps(socks_config))
        save()
        check(profile(clone)['config'] == socks_config and 'vpnPolicy' not in profile(clone) and state()['version'] == 4,
              'unsupported protocol can save after explicit Clear without retaining policy or downgrading the Library')
        bundle = json.loads(command('exportProfiles', {'ids': [id], 'format': 'profiles', 'destination': 'preview'})['text'])
        check(bundle['version'] == 2 and bundle['profiles'][0]['vpnPolicy'] == ALL_FALSE
              and bundle['profiles'][0]['config'] == changed_config,
              'full profile bundle2 retains metadata outside exact core source JSON')
        menu(id, '#export-one')
        transport_hook()
        before_export = library.read_bytes()
        command('writeClipboard', {'text': 'POLICY-SOURCE-EXPORT-MUST-NOT-REPLACE'})
        check(js('return document.querySelector("#configuration-copy").disabled&&document.querySelector("#configuration-export").disabled&&!!document.querySelector("#configuration-policy-hint")&&!document.querySelector("#configuration-share").disabled'),
              'source JSON export buttons are disabled with a policy hint and explicit full-profile export remains available')
        # DOM activation follows the same native WebView button path as the
        # shared click helper, while deliberately retaining the disabled state.
        js('document.querySelector("#configuration-copy").click();document.querySelector("#configuration-export").click()')
        time.sleep(.12)
        check(not js('return window.__policyTransport.calls.includes("exportConfiguration")')
              and command('readClipboard') == 'POLICY-SOURCE-EXPORT-MUST-NOT-REPLACE' and library.read_bytes() == before_export,
              'disabled source actions send no export IPC and preserve clipboard and Library')
        audit['sourceExportObservedNames'] = js('return window.__policyTransport.calls')
        transport_unhook()
        try:
            command('exportConfiguration', {'config': changed_config, 'destination': 'clipboard', 'sourceProfileId': id})
        except RuntimeError as error:
            assert 'vpn_policy_export_requires_bundle' in str(error)
        else:
            raise AssertionError('source-profile raw export IPC accepted a policy profile')
        check(command('readClipboard') == 'POLICY-SOURCE-EXPORT-MUST-NOT-REPLACE' and library.read_bytes() == before_export,
              'Tauri source-profile export guard independently refuses lossy IPC without writing clipboard or Library')
        command('saveProfile', {**profile(id), 'vpnPolicy': DEFAULT})
        click('#configuration-share')
        select('#export-format', 'thronium-link')
        click('#export-reveal')
        wait_for('return !!document.querySelector("#export-content")')
        current_link = js('return document.querySelector("#export-content").textContent')
        current_bundle = json.loads(base64.urlsafe_b64decode(current_link.split('/profiles/', 1)[1] + '==='))
        check(current_bundle['profiles'][0]['vpnPolicy'] == DEFAULT and current_bundle['profiles'][0]['config'] == changed_config,
              'full-profile export reloads current saved policy while preserving the open configuration draft')
        click('dialog:not(#main-modal) > .modal-head > button')
        wait_for('return document.querySelectorAll("dialog[open]").length===1')
        command('saveProfile', {**profile(id), 'vpnPolicy': ALL_FALSE})
        click('#configuration-share')
        select('#export-format', 'thronium-link')
        click('#export-reveal')
        wait_for('return !!document.querySelector("#export-content")')
        link = js('return document.querySelector("#export-content").textContent')
        decoded = json.loads(base64.urlsafe_b64decode(link.split('/profiles/', 1)[1] + '==='))
        check(decoded['version'] == 2 and decoded['profiles'][0]['vpnPolicy'] == ALL_FALSE,
              'native portable link contains version2 profile policy metadata')
        for format in ['configurations', 'links']:
            select('#export-format', format)
            click('#export-reveal')
            wait_for('return !!document.querySelector("dialog:not(#main-modal) [role=alert]")')
            message = js('return document.querySelector("dialog:not(#main-modal) [role=alert]").textContent')
            check('policy-private-source' not in message and 'Thronium' in message
                  and not js('return !!document.querySelector("#export-content")'),
                  'native lossy ' + format + ' export requires a complete profile bundle without exposing source credentials')
        click('dialog:not(#main-modal) > .modal-head > button')
        wait_for('return document.querySelectorAll("dialog[open]").length===1')
        close()
        before_ids = {row['id'] for row in command('snapshot')['profiles']}
        click('.add-connection')
        click('#add-choice-link')
        fill('#import-source', link)
        click('#import-review')
        wait_for('return document.querySelectorAll(".import-select").length===1')
        select('#import-group', group)
        check(js('return !!document.querySelector(".import-vpn-policy")')
              and {row['id'] for row in command('snapshot')['profiles']} == before_ids,
              'native full-metadata import previews VPN policy before any profile is written')
        click('#import-save')
        wait_for('return !document.querySelector("dialog[open]")')
        imported = until(lambda: [row['id'] for row in command('snapshot')['profiles'] if row['id'] not in before_ids])
        assert len(imported) == 1
        check(profile(imported[0])['vpnPolicy'] == ALL_FALSE and profile(imported[0])['config'] == changed_config,
              'native portable import creates a new profile with exact policy and source configuration')
        malformed = []
        for kind, bad_policy in [('unknown-key', {**ALL_FALSE, 'future-private-policy-key': True}),
                                 ('non-boolean', {**ALL_FALSE, 'blockOutsideDns': 'private-invalid-value'})]:
            bad = copy.deepcopy(decoded)
            bad['profiles'][0]['vpnPolicy'] = bad_policy
            malformed.append((kind, json.dumps(bad)))
        duplicate = json.dumps(decoded).replace('"onlyAdvertisedRoutes": false', '"onlyAdvertisedRoutes": true, "onlyAdvertisedRoutes": false', 1)
        assert duplicate != json.dumps(decoded)
        malformed.append(('duplicate-key', duplicate))
        for kind, source in malformed:
            before_invalid = library.read_bytes()
            click('.add-connection')
            click('#add-choice-link')
            fill('#import-source', source)
            click('#import-review')
            wait_for('return !!document.querySelector(".import-row.has-error")')
            message = js('return document.querySelector(".import-row.has-error").textContent')
            check(library.read_bytes() == before_invalid and js('return !document.querySelector(".import-select")&&document.querySelector("#import-save").disabled')
                  and 'private-invalid-value' not in message and 'policy-private-source' not in message,
                  'native import rejects ' + kind + ' policy metadata atomically with no private values in its error')
            close()
        # Native backup file round trip (the file stays in a private temp dir).
        click('.primary-nav button:nth-child(5)')
        wait_for('return !!document.querySelector("[data-settings-section=backup]")')
        click('[data-settings-section=backup]')
        wait_for('return !!document.querySelector("#backup-save")')
        with tempfile.TemporaryDirectory(prefix='thronium-policy-backup-') as folder:
            path = Path(folder) / 'policy-backup.json'
            click('#backup-save')
            file_dialog('Save backup', path)
            wait_for('return document.querySelector("#backup-notice")?.textContent.includes("saved")')
            backed = json.loads(path.read_text())
            saved_profile = next(row for row in backed['library']['profiles'] if row['id'] == id)
            check(backed['version'] == 1 and backed['library']['version'] == 4
                  and saved_profile['vpnPolicy'] == ALL_FALSE and saved_profile['config'] == changed_config,
                  'actual full backup keeps envelope1 and nested Library4 with exact policy outside core config')
            command('saveProfile', {**profile(id), 'vpnPolicy': DEFAULT})
            changed = state()
            click('#backup-open')
            file_dialog('Open backup', path, opening=True)
            wait_for('return !!document.querySelector("#backup-confirm")')
            check(js('return document.querySelector("#backup-confirm").disabled') and state() == changed,
                  'native backup review requires acknowledgement and does not apply saved policy before confirmation')
            click('#backup-acknowledge')
            click('#backup-confirm')
            wait_for('return !document.querySelector("dialog[open]")')
            check(state() == backed['library'] and profile(id)['vpnPolicy'] == ALL_FALSE,
                  'confirmed full backup restore replaces the Library exactly, including all profile policies')
            click('#backup-undo')
            wait_for('return !!document.querySelector("#backup-confirm")')
            click('#backup-acknowledge')
            click('#backup-confirm')
            wait_for('return !document.querySelector("dialog[open]")')
            check(state() == changed and profile(id)['vpnPolicy'] == DEFAULT,
                  'native restore undo recovers exact prior Library and its different policy')
        click('.primary-nav button:first-child')
        h['request']('POST', h['base'] + '/refresh', {})
        wait_for('return !!document.querySelector(".add-connection")')
        editor(id)
        check(values() == DEFAULT and profile(id)['config'] == changed_config,
              'policy controls reopen after backup/undo and real WebView reload without losing metadata')
        close()
        # Actual endpoint status plus owned direct CONNECT: session preservation,
        # not proof of advertised-route or pushed-DNS data plane.
        class Echo(socketserver.BaseRequestHandler):
            def handle(self):
                with contextlib.suppress(OSError):
                    while value := self.request.recv(4096):
                        self.request.sendall(value)
        class EchoServer(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True
        origin = EchoServer(('127.0.0.1', 0), Echo)
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        destination = origin.server_address[1]
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0))
            inbound = reserve.getsockname()[1]
        command('preferences', {**command('snapshot')['preferences'], 'inboundPort': inbound})
        routing = copy.deepcopy(command('routing'))
        route = next(row for row in routing['profiles'] if row['id'] == routing['active'])
        route['mode'] = 'rules'
        route['rules'] = [{'id': 'policy-owned-explicit-route', 'name': 'Owned direct traffic', 'enabled': True,
            'config': {'ip_cidr': ['127.0.0.1/32'], 'port': [destination], 'outbound': 'direct'}}]
        command('saveRouting', routing)
        config = copy.deepcopy(ready['openconnect'])
        config.pop('tag', None)
        active_id = add('Owned active VPN policy', config, vpnPolicy=DEFAULT)
        # Exercise the real Tauri ProfileDraft adapter: omitted metadata means
        # the saved policy, explicit null means a policy-less Check only.
        collision = copy.deepcopy(command('routing'))
        collision_route = next(row for row in collision['profiles'] if row['id'] == collision['active'])
        collision_route['dns']['servers'].append({'type': 'local', 'tag': 'thronium-vpn-dns-proxy'})
        command('saveRouting', collision)
        guarded = library.read_bytes()
        source = profile(active_id)
        source.pop('vpnPolicy')
        try:
            command('checkProfile', source)
        except RuntimeError as error:
            assert 'vpn_policy_tag_conflict' in str(error)
        else:
            raise AssertionError('omitted policy bypassed the saved policy in Check')
        check(library.read_bytes() == guarded and profile(active_id)['vpnPolicy'] == DEFAULT,
              'real checkProfile adapter preserves saved policy when omitted and rejects a reserved DNS tag conflict without mutation')
        event_file = Path(ready['events'])
        events_before_explicit_null = event_file.read_bytes()
        command('checkProfile', {**source, 'vpnPolicy': None})
        check(library.read_bytes() == guarded and profile(active_id)['vpnPolicy'] == DEFAULT
              and event_file.read_bytes() == events_before_explicit_null and command('snapshot')['running'] is None,
              'explicit null Check omits policy only for that real Core request, accepts the same DNS config and leaves stored policy unchanged')
        command('saveRouting', {**command('routing'), 'active': routing['active'], 'profiles': routing['profiles']})
        editor(active_id)
        stored = library.read_bytes()
        event_file = Path(ready['events'])
        events_before_check = event_file.read_bytes()
        click('.editor-modal .modal-footer .button.secondary')
        wait_for('return !!document.querySelector(".editor-modal [role=status]")')
        check(library.read_bytes() == stored and profile(active_id)['vpnPolicy'] == DEFAULT
              and event_file.read_bytes() == events_before_check and command('snapshot')['running'] is None,
              'native policy-aware Core Check accepts real fixture configuration without saving or starting a VPN endpoint')
        close()
        command('connect', {'id': active_id})
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            connection = command('snapshot')
            if any(row['tag'] == 'proxy' and row['state'] == 'error' and row['authFailed'] and not row['challengeId'] for row in connection['vpn']['endpoints']):
                break
            time.sleep(.08)
        else:
            raise AssertionError('owned actual OpenConnect endpoint did not reach terminal authFailed')
        active = command('connectionConfiguration', {'id': active_id, 'active': True})
        children = core_pids(owned_menu.pid)
        held = socket.create_connection(('127.0.0.1', inbound), timeout=5)
        target = '127.0.0.1:' + str(destination)
        held.sendall(f'CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n'.encode())
        header = b''
        while b'\r\n\r\n' not in header:
            value = held.recv(4096)
            assert value, 'owned direct CONNECT closed before response'
            header += value
        assert b' 200 ' in header
        editor(active_id)
        click('#vpn-policy-onlyAdvertisedRoutes')
        click('#vpn-policy-useTunnelDns')
        check(values() == ALL_FALSE and js('return document.querySelector("button[form=profile-editor]").disabled')
              and profile(active_id)['vpnPolicy'] == DEFAULT,
              'an in-use profile allows a pending policy draft while Save remains blocked and stored policy stays exact')
        close()
        held.sendall(b'POLICY-FOUNDATION-HELD-CONNECT')
        check(held.recv(128) == b'POLICY-FOUNDATION-HELD-CONNECT'
              and command('connectionConfiguration', {'id': active_id, 'active': True}) == active
              and core_pids(owned_menu.pid) == children and command('snapshot')['since'] == connection['since'],
              'discarding active policy edits retains exact frozen request, owned child, session and real held direct CONNECT')
        menu(active_id, '#export-one')
        transport_hook()
        for mode in ['preview', 'active']:
            click('#configuration-' + mode)
            wait_for('return document.querySelector("#configuration-' + mode + '").getAttribute("aria-pressed")==="true"&&!document.querySelector("#configuration-copy").disabled')
            rendered = json.loads(js('return document.querySelector("#configuration-json").value'))
            before_calls = js('return window.__policyTransport.calls.filter(n=>n==="exportConfiguration").length')
            click('#configuration-copy')
            wait_for('return document.querySelector("#configuration-status")?.textContent.includes("Copied")')
            copied = json.loads(command('readClipboard'))
            policy_dns = next((server for server in copied.get('dns', {}).get('servers', []) if server.get('tag') == 'thronium-vpn-dns-proxy'), None)
            check(copied == rendered and 'vpnPolicy' not in copied and policy_dns is not None
                  and policy_dns.get('type') == 'openconnect' and policy_dns.get('endpoint') == 'proxy'
                  and js('return window.__policyTransport.calls.filter(n=>n==="exportConfiguration").length') == before_calls + 1
                  and not js('return !!document.querySelector("#configuration-policy-hint")'),
                  mode + ' diagnostic export copies the actual compiled configuration through real IPC while keeping portable metadata separate')
        audit['compiledExportObservedNames'] = js('return window.__policyTransport.calls')
        transport_unhook()
        close()
        held.sendall(b'POLICY-DIAGNOSTIC-EXPORT-HELD')
        check(held.recv(128) == b'POLICY-DIAGNOSTIC-EXPORT-HELD'
              and command('connectionConfiguration', {'id': active_id, 'active': True}) == active
              and profile(active_id)['vpnPolicy'] == DEFAULT and core_pids(owned_menu.pid) == children,
              'diagnostic preview and clipboard export preserve the active request, saved policy and held direct connection')
        command('disconnect')
        held.close()
        held = None
        editor(active_id)
        click('#vpn-policy-onlyAdvertisedRoutes')
        click('#vpn-policy-useTunnelDns')
        save()
        check(profile(active_id)['vpnPolicy'] == ALL_FALSE and command('snapshot')['running'] is None,
              'after explicit Disconnect the same policy edit saves without reconnecting automatically')
        for language in ['ru', 'en']:
            command('preferences', {**command('snapshot')['preferences'], 'language': language})
            wait_for('return document.documentElement.lang===' + json.dumps(language))
            editor(id)
            h['request']('POST', h['base'] + '/window/rect', {'width': 390, 'height': 844})
            def dimensions():
                return js('''const d=document.querySelector('.editor-modal'),b=d.querySelector('.modal-body');return {
                    width:innerWidth,height:innerHeight,bodyScroll:b.scrollWidth,bodyClient:b.clientWidth,
                    bottom:d.getBoundingClientRect().bottom,footer:d.querySelector('.modal-footer').getBoundingClientRect().bottom};''')
            samples, stable, deadline = [dimensions()], 0, time.monotonic() + 3
            while stable < 3 and time.monotonic() < deadline:
                time.sleep(.12)
                sample = dimensions()
                stable = stable + 1 if sample == samples[-1] else 0
                samples.append(sample)
            audit['layout'][language] = samples
            box = samples[-1]
            check(stable == 3 and box['width'] == 390 and box['bodyScroll'] <= box['bodyClient'] + 1
                  and box['bottom'] <= box['height'] + 1 and box['footer'] <= box['height'] + 1,
                  language + ' policy section retains strict narrow-window geometry and visible Save/Cancel')
            h['screenshot']('vpn-policy-' + language + '-390')
            close()
            h['request']('POST', h['base'] + '/window/rect', geometry)
    finally:
        if held is not None:
            held.close()
        if origin is not None:
            origin.shutdown()
            origin.server_close()
        with contextlib.suppress(Exception):
            transport_unhook()
            if original_clipboard is not None:
                command('writeClipboard', {'text': original_clipboard})
            if js('return !!document.querySelector("dialog[open]")'):
                h['screenshot']('vpn-policy-before-cleanup')
                close()
            command('disconnect')
            current_route = command('routing')
            command('saveRouting', {**current_route, 'active': initial_route['active'], 'profiles': initial_route['profiles']})
            command('deleteGroup', {'id': group, 'deleteProfiles': True})
            command('preferences', initial['preferences'])
            h['request']('POST', h['base'] + '/window/rect', geometry)
        (h['artifacts'] / 'vpn-policy-audit.json').write_text(json.dumps(audit, indent=2) + '\n')
