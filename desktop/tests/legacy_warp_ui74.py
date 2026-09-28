"""Real Qt WARP settings import, exact Undo and an independent userspace peer."""
import contextlib
import copy
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import time
import urllib.request
from native_dialogs import file_dialog

SOURCE = Path(__file__).resolve().parents[1] / 'engine/src/legacy_backup/settings/warp-fixtures'


def run(h):
    command, click, js, wait_for, check = (h[k] for k in ('command', 'click', 'js', 'wait_for', 'check'))
    manifest = json.loads((SOURCE / 'manifest.json').read_text())
    info = json.loads(Path(os.environ['_THRONIUM_LEGACY_WARP_READY']).read_text())
    root = Path(command('storageLocation')['directory']); audit = {'traffic': []}; streams = []
    fields = manifest['fields']
    def library(): return json.loads((root / 'library.json').read_text())
    def registrations():
        with urllib.request.urlopen(info['registrationAdmin'], timeout=3) as response: return json.load(response)['requests']
    def stats(): return json.loads(Path(info['stats']).read_text())
    def poll(predicate, timeout=8):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if predicate(): return
            time.sleep(.05)
        raise AssertionError('Owned WARP state did not settle')
    def show(selector): js('document.querySelector(arguments[0]).scrollIntoView({block:"center",behavior:"instant"})', selector)
    def press(selector): show(selector); click(selector)
    def settings(section='backup'):
        click('.primary-nav button:last-child'); click('[data-settings-section=' + section + ']')
        if section == 'backup': wait_for('return !!document.querySelector("#backup-open")')
        else:
            wait_for('return !!document.querySelector("[data-warp-generator]")')
            js('document.querySelector("[data-warp-generator]").closest("details").open=true')
    def install_hook():
        js('''const original=window.fetch;window.__legacyWarp74={original,previews:[]};window.fetch=function(input,options){let name=null;try{if(String(input).includes('/app_command'))name=JSON.parse(options?.body||'{}').name;}catch{}const result=original.apply(this,arguments);if(['readBackup','legacyBackupScopes','refreshBackupPreview','previewPreviousBackup'].includes(name))result.then(r=>r.clone().json()).then(v=>{const p=v?.preview||v;if(p?.token&&p?.current)window.__legacyWarp74.previews.push(p)}).catch(()=>{});return result;};''')
    def previews(): return js('return window.__legacyWarp74?.previews || []')
    def next_preview(count):
        wait_for('return window.__legacyWarp74.previews.length>' + str(count))
        wait_for('return !!document.querySelector("#backup-confirm") && !document.querySelector("#backup-refresh").disabled')
        return previews()[-1]
    def open_file(path):
        count = len(previews()); ru = command('snapshot')['preferences']['language'] == 'ru'
        press('#backup-open'); title = 'Открыть резервную копию' if ru else 'Open backup'
        try: file_dialog(title, path, opening=True)
        except AssertionError as error:
            if str(error) != 'Native file chooser has no visible editable path field': raise
            file_dialog(title, path, opening=True)
        wait_for('return !document.querySelector("#backup-open").disabled'); return next_preview(count)
    def toggle(group='warp'):
        count = len(previews()); press('#legacy-scope-settings-' + group); return next_preview(count)
    def close(): click('#main-modal > .modal-head > button'); wait_for('return !document.querySelector("dialog[open]")')
    def apply():
        if not js('return document.querySelector("#backup-acknowledge").checked'): press('#backup-acknowledge')
        press('#backup-confirm'); wait_for('return !document.querySelector("dialog[open]") && !!document.querySelector("#backup-notice")')
    def undo(): press('#backup-undo'); wait_for('return !!document.querySelector("#backup-confirm")'); apply()
    def rejected(token, error):
        try: command('restoreBackup', {'token': token})
        except RuntimeError as failure: return error in str(failure)
        return False
    def expected(before, rows):
        result = copy.deepcopy(before)
        for key in fields:
            if key not in rows: continue
            result['settings'][key] = json.loads(rows[key]) if key in ['enable_warp', 'warp_ifc_addrs', 'warp_reserved'] else rows[key]
        return result
    def safe(preview):
        text = json.dumps(preview)
        return not any(marker in text for marker in [manifest['modes']['valid']['warp_private_key'], manifest['modes']['valid']['warp_public_key'], 'private-invalid-canary74', 'private-column-value74', info['sourceRows']['warp_private_key'], info['sourceRows']['warp_public_key']])
    def no_traffic():
        current = stats(); assert not current['requests'] and not current['receivedWirePacketTypes']
        assert not registrations()
    try:
        for filename, digest in manifest['sha256'].items(): assert hashlib.sha256((SOURCE / filename).read_bytes()).hexdigest() == digest
        initial = command('snapshot'); assert not initial['profiles']
        with socket.socket() as reservation: reservation.bind(('127.0.0.1', 0)); port = reservation.getsockname()[1]
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark', 'connectionMode': 'local', 'inboundPort': port})
        primary = command('saveProfile', {'name': 'WARP import primary74', 'kind': 'xray-config', 'groupId': 'personal', 'config': {'outbounds': [{'protocol': 'freedom', 'tag': 'direct'}]}})['id']
        command('connect', {'id': primary}); running = command('snapshot')
        listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen(); streams.append(listener)
        client = socket.create_connection(('127.0.0.1', port), timeout=3); streams.append(client)
        authority = '127.0.0.1:' + str(listener.getsockname()[1]); client.sendall(('CONNECT ' + authority + ' HTTP/1.1\r\nHost: ' + authority + '\r\n\r\n').encode())
        peer, _ = listener.accept(); peer.settimeout(3); streams.append(peer); assert b'200' in client.recv(1024)
        from window_ui import primary as window_primary
        from native_processes import core_pids
        connection, _, app_pid = window_primary(); connection.close(); main_pids = core_pids(app_pid)
        settings(); install_hook(); before = library(); preview = open_file(SOURCE / 'valid.thrbackup')
        check(preview['legacy']['settingsCount'] == 0 and not preview['legacy']['scopes'].get('settings', {}).get('warp'), 'real Qt WARP category defaults to unselected')
        picked = toggle()
        check(picked['legacy']['settingsCount'] == 6 and safe(picked) and any(i['code'] == 'legacy_warp_enabled' for i in picked['legacy']['issues']), 'six field names and explicit next-connection enable notice appear without key values')
        check(js('return document.querySelector("#backup-confirm").disabled') and rejected(picked['token'], 'backup_disconnect_first'), 'active import is disabled in the window and rejected by the API')
        client.sendall(b'warp74'); assert peer.recv(6) == b'warp74'
        check(library() == before and command('snapshot')['since'] == running['since'] and core_pids(app_pid) == main_pids, 'active WARP preview preserves the library, Core PID and real primary TCP stream')
        close(); command('disconnect'); poll(lambda: command('snapshot')['running'] is None)
        for stream in streams: stream.close()
        streams.clear(); no_traffic()
        for language, width in [('en', 1280), ('ru', 390)]:
            command('preferences', {**command('snapshot')['preferences'], 'language': language})
            h['request']('POST', h['base'] + '/window/rect', {'width': width, 'height': 900})
            wait_for('return document.documentElement.lang===' + json.dumps(language) + ' && innerWidth===' + str(width))
            settings(); before = library(); open_file(SOURCE / 'disabled.thrbackup'); picked = toggle()
            check(picked['legacy']['canApply'] and safe(picked) and not js('return document.querySelector("#backup-acknowledge").checked'), 'WARP is separately selectable and requires replacement acknowledgement in ' + language)
            show('#legacy-settings-review')
            check(js('return document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth+1') and ('Приватный ключ WARP' if language == 'ru' else 'WARP private key') in js('return document.querySelector("#legacy-settings-fields").textContent'), 'translated WARP field labels fit the review at ' + str(width) + 'px')
            h['screenshot']('legacy-warp-review-' + language + '-' + str(width))
            apply(); check(library() == expected(before, manifest['modes']['disabled']), 'WARP import changes exactly six selected settings in ' + language)
            settings('intercept')
            check(js('return document.querySelector("#setting-warp_private_key").type==="password" && !document.querySelector("#setting-enable_warp").checked') and js('return document.querySelector("#setting-warp_public_key").value') == manifest['modes']['disabled']['warp_public_key'], 'real settings mask the private key, preserve the peer public key and saved Off state')
            show('#setting-warp_private_key')
            wait_for('const r=document.querySelector("#setting-warp_private_key").getBoundingClientRect();return r.top>=65&&r.bottom<innerHeight-70')
            check(js('const r=document.querySelector("#setting-warp_private_key").getBoundingClientRect();return r.left>=0&&r.right<=innerWidth&&document.documentElement.scrollWidth<=innerWidth+1'), 'masked WARP key input is actually visible and fits ' + language + ' ' + str(width) + 'px')
            from native_screenshot import private_display_server
            from Xlib import X
            assert private_display_server() is not None
            display, window, _ = window_primary()
            try:
                window.configure(stack_mode=X.Above)
                window.set_input_focus(X.RevertToParent, X.CurrentTime); display.sync()
            finally: display.close()
            js('document.querySelector("#setting-warp_private_key").focus({preventScroll:true})')
            wait_for('return document.activeElement===document.querySelector("#setting-warp_private_key")')
            # X11 capture observes presented pixels, not WebKit's layout tree.
            # Give the scroll/focus frame time to reach the private compositor.
            time.sleep(.35)
            h['screenshot']('legacy-warp-settings-' + language + '-' + str(width)); no_traffic()
            settings(); undo(); check(library() == before, 'native Undo restores the exact library in ' + language)
        for name in ['incomplete', 'bad-key', 'bad-reserved', 'ipv6-endpoint', 'unknown-column']:
            before = library(); open_file(SOURCE / (name + '.thrbackup')); bad = toggle()
            check(not bad['legacy']['canApply'] and safe(bad) and rejected(bad['token'], 'legacy_import_blocked'), name + ' blocks WARP without exposing keys')
            if name != 'unknown-column':
                toggle(); good = toggle('logging'); check(good['legacy']['canApply'] and good['legacy']['settingsCount'] == 1, 'opting out of ' + name + ' preserves independent logging import')
            close(); check(library() == before, 'refused ' + name + ' leaves the whole library unchanged')
        before = library(); preview = open_file(SOURCE / 'excluded-settings.thrbackup')
        check(js('return document.querySelector("#legacy-scope-settings-warp").disabled'), 'Qt section mask disables WARP selection')
        forged = command('legacyBackupScopes', {'token': preview['token'], 'scopes': {'profiles': False, 'routes': False, 'settings': {'warp': True}}})
        check(not forged['legacy']['canApply'] and rejected(forged['token'], 'legacy_import_blocked') and library() == before, 'forged scope cannot bypass the excluded Settings section')
        close(); no_traffic()
        before = library(); open_file(SOURCE / 'empty.thrbackup'); toggle(); apply()
        check(library() == expected(before, manifest['modes']['empty']), 'explicit disabled empty bundle clears all old WARP credentials')
        undo(); check(library() == before, 'Undo restores credentials after explicit clear')
        before = library(); open_file(Path(info['linkedArchive']))
        count = len(previews()); press('#legacy-scope-routes'); linked = next_preview(count)
        check(not linked['legacy']['canApply'] and any(i['code'] == 'legacy_import_requires_warp' for i in linked['legacy']['issues']), 'linked WARP routes require the WARP category from the same archive')
        check('backups.warp_import_dependency' not in js('return document.querySelector("dialog").textContent') and js('return document.querySelector("#backup-confirm").disabled'), 'localized dependency notice keeps import disabled')
        linked = toggle()
        check(linked['legacy']['canApply'] and 'legacy_routing_warp_required' not in linked['legacy']['requirements'] and safe(linked), 'selecting complete WARP settings resolves the dependency without exposing keys')
        h['screenshot']('legacy-warp-linked-route-review')
        apply()
        imported = next(p for p in library()['routing']['profiles'] if p['name'] == 'Imported WARP policy')
        check(imported['route']['final'] == 'warp-bypass' and imported['legacyConstraints']['warpEnabled'] and library()['routing']['active'] == before['routing']['active'], 'default bypass and source WARP policy import together without changing the active preset')
        undo(); check(library() == before, 'linked route and WARP settings Undo restores the complete library atomically')
        no_traffic()
        route = command('routing')
        for preset in route['profiles']: preset['route']['auto_detect_interface'] = False
        command('saveRouting', route)
        direct = command('saveProfile', {'name': 'WARP after selected Direct74', 'kind': 'sing-box-outbound', 'groupId': 'personal', 'config': {'type': 'direct'}})['id']
        before = library(); open_file(Path(info['archive'])); picked = toggle(); apply()
        check(library() == expected(before, info['sourceRows']) and safe(picked), 'live Qt archive imports exactly its generated client key, peer key, endpoint and reserved bytes')
        no_traffic(); check(command('snapshot')['running'] is None and not registrations(), 'import, Undo and settings inspection never initiate a VPN handshake or WARP registration')
        h['request']('POST', h['base'] + '/refresh', {}); wait_for('return !!document.querySelector(".add-connection")')
        check(library() == expected(before, info['sourceRows']), 'live WARP identity survives a WebView reload')
        install_hook(); command('connect', {'id': direct})
        active = command('connectionConfiguration', {'id': direct, 'active': True})
        configs = [part['config'] for part in active['parts']]
        endpoint = next(e for cfg in configs for e in cfg.get('endpoints', []) if e.get('tag') == 'proxy')
        check(endpoint['private_key'] == info['sourceRows']['warp_private_key'] and endpoint['peers'][0]['public_key'] == info['sourceRows']['warp_public_key'] and endpoint['peers'][0]['reserved'] == [0, 128, 255] and endpoint['detour'] == 'settings-warp-base' and endpoint['mtu'] == 1280 and endpoint['peers'][0]['persistent_keepalive_interval'] == 10, 'actually running Core uses imported WARP after the selected outbound with exact peer and reserved bytes')
        for family in ['4', '6']:
            path = '/fixture/legacy-warp74-' + family
            conn = http.client.HTTPConnection('127.0.0.1', port, timeout=12)
            try:
                conn.request('GET', info['http' + family] + path); response = conn.getresponse(); status, body = response.status, response.read()
            finally: conn.close()
            poll(lambda: any(row['path'] == path for row in stats()['requests']))
            current = stats(); raw_types = current['receivedWirePacketTypes']
            check(status == 200 and body == ('wg43:' + path).encode() and raw_types.get(str(0xff800001), 0) > 0 and raw_types.get(str(0xff800004), 0) > 0 and current['metrics']['last_handshake_time_sec'] > 0, 'IPv' + family + ' HTTP crosses the independent encrypted peer; actual wire headers contain imported reserved bytes')
            assert any(row['path'] == path and row['remote'].startswith('10.177.43.2:' if family == '4' else '[fd00:43::2]:') for row in current['requests'])
            audit['traffic'].append({'family': family, 'path': path, 'stats': current})
        command('disconnect'); settings(); before = library(); open_file(SOURCE / 'off-only.thrbackup'); toggle(); apply()
        check(library() == expected(before, {'enable_warp': 'false'}), 'a lone explicit Off disables WARP while preserving all identity fields')
        command('connect', {'id': direct}); active = command('connectionConfiguration', {'id': direct, 'active': True})
        check(not any(e.get('type') == 'wireguard' for p in active['parts'] for e in p['config'].get('endpoints', [])), 'next explicit connection after imported Off has no WARP endpoint')
        command('disconnect')
        check(all(hashlib.sha256((SOURCE / name).read_bytes()).hexdigest() == digest for name, digest in manifest['sha256'].items()), 'all source Qt archives remain byte-for-byte unchanged')
        audit['activePreviewPreserved'] = True; audit['sourceArchivesUnchanged'] = True
    finally:
        for stream in streams:
            with contextlib.suppress(OSError): stream.close()
        with contextlib.suppress(Exception): command('disconnect')
        (h['artifacts'] / 'legacy-warp-audit.json').write_text(json.dumps(audit, indent=2) + '\n')
