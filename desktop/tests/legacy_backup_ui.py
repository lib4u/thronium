"""Real Qt binary chooser import, additive review, guards and exact undo.

Only synthetic archives and the disposable native library are used. Connections
use a loopback echo fixture; imported remote endpoints are never connected.
"""
import contextlib
import copy
import hashlib
import json
import pathlib
import shutil
import socket
import socketserver
import tempfile
import threading
import time
import uuid
from legacy_backup_fixtures import DIRECTORY, FULL_SINGBOX, FULL_XRAY, GROUPS, SECRETS, sources
from native_dialogs import file_dialog


def run(h):
    command, click, wait_for, js, check, screenshot = (h[key] for key in ('command', 'click', 'wait_for', 'js', 'check', 'screenshot'))
    request, base = h['request'], h['base']
    initial = command('snapshot')
    geometry = request('GET', base + '/window/rect')
    audit = None
    connection = None
    baseline_path = None
    manifest = json.loads((DIRECTORY / 'manifest.json').read_text())
    for name, expected in manifest['sha256'].items():
        assert hashlib.sha256((DIRECTORY / name).read_bytes()).hexdigest() == expected

    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            with contextlib.suppress(ConnectionResetError, BrokenPipeError, OSError):
                while data := self.request.recv(65536):
                    self.request.sendall(data)

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    server = Server(('127.0.0.1', 0), Echo)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def settings():
        click('.primary-nav button:nth-child(5)')
        wait_for('return !!document.querySelector("[data-settings-section=backup]")')
        click('[data-settings-section=backup]')
        wait_for('return !!document.querySelector("#backup-save")')

    def value(selector):
        return js('return document.querySelector(arguments[0])?.textContent || ""', selector)

    def previews():
        return js('return window.__legacyAudit?.previews || []')

    def latest():
        return previews()[-1]

    def open_file(path=None, legacy=True):
        count = len(previews())
        language = command('snapshot')['preferences']['language']
        click('#backup-open')
        file_dialog('Открыть резервную копию' if language == 'ru' else 'Open backup', path, opening=True)
        wait_for('return !document.querySelector("#backup-open").disabled')
        if path is not None and legacy:
            wait_for('return !!document.querySelector("#legacy-import-review")')
            wait_for('return window.__legacyAudit.previews.length > ' + str(count))
        return latest() if len(previews()) > count else None

    def close():
        count = js('return window.__legacyAudit?.discards || 0')
        click('.modal-head .icon-button')
        wait_for('return !document.querySelector("dialog")')
        wait_for('return (window.__legacyAudit?.discards || 0) > ' + str(count))

    def save(path):
        language = command('snapshot')['preferences']['language']
        click('#backup-save')
        file_dialog('Сохранить резервную копию' if language == 'ru' else 'Save backup', path)
        wait_for('return !!document.querySelector("#backup-notice") && !document.querySelector("#backup-save").disabled')
        deadline = time.monotonic() + 5
        while not path.exists() and time.monotonic() < deadline:
            time.sleep(.05)
        return json.loads(path.read_text())['library']

    def state(label):
        return save(root / (label + '-' + str(time.monotonic_ns()) + '.json'))

    def apply():
        click('#backup-acknowledge')
        click('#backup-confirm')
        wait_for('return !document.querySelector("dialog")')
        wait_for('return !!document.querySelector("#backup-notice")')

    def refresh():
        count = len(previews())
        click('#backup-refresh')
        wait_for('return !document.querySelector("#backup-refresh").disabled && !document.querySelector("#backup-acknowledge").checked')
        wait_for('return window.__legacyAudit.previews.length > ' + str(count))
        return latest()

    def reject(token, code):
        try:
            command('restoreBackup', {'token': token})
        except RuntimeError as error:
            assert code in str(error), str(error)
        else:
            raise AssertionError('Backend accepted forbidden backup operation')

    def private_ui(shown=()):
        text = js('return document.body.textContent')
        return not any(secret in text for secret in SECRETS + ['synthetic-wireguard-private-secret', 'synthetic-external-core-secret', 'synthetic-future-field-secret', '/missing/synthetic-private.srs'] if secret not in shown)

    def echo(token):
        body = ('legacy-backup-' + token).encode()
        connection.sendall(body)
        received = b''
        while len(received) < len(body):
            part = connection.recv(len(body) - len(received))
            if not part:
                break
            received += part
        return received == body

    with tempfile.TemporaryDirectory(prefix='thronium-legacy-ui-') as directory:
        root = pathlib.Path(directory)
        copies = {}
        for name in manifest['sha256']:
            path = root / name
            shutil.copyfile(DIRECTORY / name, path)
            copies[name] = path
        try:
            command('disconnect')
            command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark'})
            wait_for('return document.documentElement.lang === "en"')
            settings()
            # Tauri's invoke and ipc are readonly. Observe the actual fetch
            # response without changing IPC payloads, headers or returned data.
            js('''
const original = window.fetch;
window.__legacyAudit = {original, previews: [], discards: 0};
window.fetch = function(input, options) {
  let name = null;
  try { const body = JSON.parse(options?.body || '{}'); if (String(input).includes('/app_command')) name = body.name; } catch {}
  const result = original.apply(this, arguments);
  if (['readBackup','refreshBackupPreview','previewPreviousBackup'].includes(name)) {
    result.then(response => response.clone().json()).then(value => {
      const preview = value?.preview || value;
      if (preview?.token && preview?.current && preview?.incoming) window.__legacyAudit.previews.push(preview);
    }).catch(() => {});
  }
  if (name === 'discardBackupPreview') result.then(response => {
    if (response.ok) window.__legacyAudit.discards += 1;
  }).catch(() => {});
  return result;
};
''')
            baseline_path = root / 'baseline.json'
            baseline = save(baseline_path)
            with socket.socket() as available:
                available.bind(('127.0.0.1', 0))
                port = available.getsockname()[1]
            command('preferences', {**command('snapshot')['preferences'], 'inboundPort': port})
            command('connectionSettings', {'mode': 'local', 'port': port})
            existing = command('saveProfile', {'name': 'Current local profile', 'groupId': 'personal', 'kind': 'sing-box-outbound', 'config': {'type': 'direct'}})['id']
            command('favorite', {'id': existing})
            command('select', {'id': existing})
            routing = command('routing')
            routing['profiles'][0].update(name='Current routing retained', dns={'servers': [{'type': 'local', 'tag': 'dns-current'}], 'final': 'dns-current'}, route={'final': 'proxy', 'auto_detect_interface': True, 'default_domain_resolver': 'dns-current'})
            command('saveRouting', routing)
            before_settings = command('settings')['testing']
            command('saveSettings', {'section': 'testing', 'previous': before_settings, 'values': {**before_settings, 'url_test_timeout_ms': 4200}})
            before = state('before')
            open_file()
            check(not js('return !!document.querySelector("dialog")') and state('cancel-native') == before, 'cancelling the real native file chooser leaves the entire current library unchanged')
            preview = open_file(copies['valid.thrbackup'])
            check(preview['legacy']['canApply'] and preview['legacy']['mode'] == 'add-profiles' and 'Import profiles from Throne' in value('#modal-title'), 'real Qt binary archive opens as additive Throne profile import through the native chooser')
            inventory = preview['legacy']['inventory']
            check(inventory['profiles'] == 13 and inventory['groups'] == 4 and inventory['routes'] == 1 and inventory['rules'] == 1 and inventory['settings'] == 3 and inventory['otp'] == 1 and inventory['icons'] == 2, 'safe inventory reports actual profile, group, routing, settings, OTP and icon sections')
            check(preview['incoming']['profiles'] == len(before['profiles']) + 13 and preview['incoming']['groups'] == len(before['groups']) + 4 and 'After import' in value('.backup-summary'), 'review compares current counts with the complete additive result')
            check('Fri Sep 11 12:00:00 2026 🦊' in value('dialog') and '1970' not in value('dialog'), 'Qt TextDate is shown intact without a false Unix-epoch date')
            check(js('return document.querySelector("#backup-confirm").disabled && !document.querySelector("#backup-acknowledge").checked') and 'current client routing and settings' in value('.backup-acknowledge'), 'import requires explicit acknowledgement that current client routing and settings will be used')
            check(private_ui() and all({'code', 'entity', 'sourceId', 'name'} == set(issue) for issue in preview['legacy']['issues']) and not any(secret in json.dumps(preview, ensure_ascii=False) for secret in SECRETS), 'preview exposes only safe inventory and named issue codes, without SQL, configuration credentials or subscription URLs')
            check('Routing' in value('#legacy-import-deferred') and 'Settings, including client DNS' in value('#legacy-import-deferred'), 'deferred client routing and DNS are visible before import')
            cancelled_token = preview['token']
            close()
            reject(cancelled_token, 'backup_preview_expired')
            check(state('cancel-review') == before, 'closing additive review discards its backend token and preserves the exact library')

            command('connect', {'id': existing})
            connection = socket.create_connection(('127.0.0.1', port), timeout=5)
            target = '127.0.0.1:' + str(server.server_address[1])
            connection.sendall(f'CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n'.encode())
            headers = b''
            while b'\r\n\r\n' not in headers:
                part = connection.recv(4096)
                assert part, 'Loopback CONNECT closed before headers'
                headers += part
            assert b' 200 ' in headers.split(b'\r\n', 1)[0]
            preview = open_file(copies['valid.thrbackup'])
            wait_for('return !!document.querySelector("#backup-connected")')
            click('#backup-acknowledge')
            check(js('return document.querySelector("#backup-confirm").disabled') and command('snapshot')['running'] == existing and echo('review'), 'review during an active connection disables import while the same real CONNECT socket continues to carry data')
            reject(preview['token'], 'backup_disconnect_first')
            check(command('snapshot')['running'] == existing and echo('backend-guard'), 'backend independently rejects active import and preserves the existing running core connection')
            close()
            connection.close()
            connection = None
            command('disconnect')
            before = state('before-stale')

            preview = open_file(copies['valid.thrbackup'])
            new_current = command('saveProfile', {'name': 'Current record added during review', 'groupId': 'personal', 'kind': 'sing-box-outbound', 'config': {'type': 'direct'}})['id']
            click('#backup-acknowledge')
            click('#backup-confirm')
            wait_for('return document.querySelector("dialog .desktop-inline-error")?.textContent.includes("changed")')
            check(any(p['id'] == new_current for p in command('snapshot')['profiles']) and len(command('snapshot')['profiles']) == len(before['profiles']) + 1, 'stale additive review cannot overwrite a profile added while the review was open')
            refreshed = refresh()
            check(refreshed['legacy'] == preview['legacy'] and refreshed['current']['profiles'] == preview['current']['profiles'] + 1 and refreshed['incoming']['profiles'] == preview['incoming']['profiles'] + 1 and refreshed['token'] != preview['token'], 'refresh retains the safe legacy report and recomputes the additive result against the new current record')
            reject(preview['token'], 'backup_preview_expired')
            check(js('return document.querySelector("#backup-confirm").disabled'), 'refresh invalidates the old token and requires a fresh acknowledgement')

            request('POST', base + '/window/rect', {'width': 390, 'height': 844})
            check(js('return document.querySelector("dialog").scrollWidth <= document.querySelector("dialog").clientWidth + 1 && document.querySelector(".modal-footer").getBoundingClientRect().bottom <= innerHeight + 1'), 'English additive review and confirmation fit the 390-pixel native window')
            screenshot('legacy-import-narrow-en')
            command('preferences', {**command('snapshot')['preferences'], 'language': 'ru', 'theme': 'light'})
            wait_for('return document.documentElement.lang === "ru"')
            refreshed = refresh()
            check('Импорт профилей из Throne' in value('#modal-title') and 'текущими маршрутизацией и настройками клиента' in value('.backup-acknowledge') and js('return document.querySelector("dialog").scrollWidth <= document.querySelector("dialog").clientWidth + 1 && document.querySelector(".modal-footer").getBoundingClientRect().bottom <= innerHeight + 1'), 'Russian import scope, deferred sections and acknowledgement remain usable at 390 pixels')
            screenshot('legacy-import-narrow-ru')
            request('POST', base + '/window/rect', {'width': 1280, 'height': 860})
            # Capture the exact current state through native export after locale
            # changes; refreshing the review keeps its original UUID plan.
            close()
            before_apply = state('before-apply')
            preview = open_file(copies['valid.thrbackup'])
            apply()
            imported = state('imported')
            added = imported['profiles'][len(before_apply['profiles']):]
            groups = imported['groups'][len(before_apply['groups']):]
            check(len(added) == 13 and len(groups) == 4 and imported['profiles'][:len(before_apply['profiles'])] == before_apply['profiles'] and imported['groups'][:len(before_apply['groups'])] == before_apply['groups'], 'acknowledged import appends all 13 converted profiles and four groups without changing existing records')
            ids = [p['id'] for p in added] + [g['id'] for g in groups]
            check(len(set(ids)) == len(ids) and all(str(uuid.UUID(pid)) == pid for pid in ids) and not set(ids).intersection(p['id'] for p in before_apply['profiles'] + before_apply['groups']), 'imported profiles and groups receive fresh unique UUIDs instead of colliding with source integer IDs')
            by_name = {p['name']: p for p in added}
            check({p['name'] for p in added} == {row[2] for row in sources()}, 'ordinary tags and custom or chain names take precedence over stale source database labels')
            ordinary_kinds = {row[2]: 'xray-outbound' if row[1] == 'xrayvless' else 'sing-box-outbound' for row in sources() if row[1] not in ('custom', 'chain')}
            check(all(by_name[name]['kind'] == kind for name, kind in ordinary_kinds.items()) and by_name['Legacy chain']['kind'] == 'chain', 'SOCKS, HTTP, Shadowsocks, VMess, VLESS, Trojan and Xray VLESS retain their expected destination kinds')
            check(by_name['Legacy full sing-box']['config'] == FULL_SINGBOX and by_name['Legacy full Xray']['config'] == FULL_XRAY and by_name['Legacy full sing-box']['kind'] == 'sing-box-config' and by_name['Legacy full Xray']['kind'] == 'xray-config', 'both custom full JSON variants preserve every source DNS, routing and inbound JSON value exactly')
            source_custom = {name: json.loads(config['config']) for _, kind, name, _, config in sources() if kind == 'custom'}
            check(all(by_name[name]['config'] == config for name, config in source_custom.items()) and by_name['Legacy custom outbound']['kind'] == 'sing-box-outbound' and by_name['Legacy custom Xray outbound']['kind'] == 'xray-outbound', 'all four custom variants preserve their destination kind and complete JSON including synthetic credentials')
            expected_order = [next(row[2] for row in sources() if row[0] == pid) for group in GROUPS for pid in json.loads(group[3])]
            check([p['name'] for p in added] == expected_order and [g['name'] for g in groups] == [g[1] for g in GROUPS], 'source group order and per-group profile order survive additive import')
            front, landing = by_name['Legacy socks 🦊']['id'], by_name['Legacy http']['id']
            chained_group = next(g for g in groups if g['name'] == 'Legacy front and landing')
            check(by_name['Legacy chain']['config'] == {'type': 'chain', 'hops': [front, landing]} and chained_group['proxyChain'] == {'front': front, 'landing': landing} and by_name['Legacy group member']['groupId'] == chained_group['id'], 'chain hops, profile groups and front or landing references are remapped to the new UUIDs')
            subscription = next(g['subscription'] for g in groups if 'subscription' in g)
            check(subscription['intervalMinutes'] == 0 and subscription['inheritDefaults'] is False and subscription['managedIds'] == [] and subscription['url'] == GROUPS[0][2] and subscription['metadata']['announcement'] == GROUPS[0][6], 'subscription URL and notice survive while automatic scheduling and inherited defaults start disabled')
            preferences = copy.deepcopy(imported['preferences'])
            overrides = preferences['vlessOverrides']
            for profile in added:
                overrides.pop(profile['id'], None)
            check(preferences == before_apply['preferences'] and imported['settings'] == before_apply['settings'] and imported['routing'] == before_apply['routing'] and imported['selected'] == before_apply['selected'] and command('snapshot')['running'] is None, 'current client DNS, routing, settings, selected server and preferences remain unchanged and no VPN starts')
            check(imported['preferences']['vlessOverrides'][by_name['Legacy vless']['id']] == 'sing-box' and imported['preferences']['vlessOverrides'][by_name['Legacy Xray VLESS']['id']] == 'xray', 'import freezes source VLESS core choices independently of the current default core')
            check(private_ui() and all(hashlib.sha256(path.read_bytes()).hexdigest() == manifest['sha256'][name] for name, path in copies.items()), 'source Qt archives remain byte-for-byte unchanged and sensitive source values never appear in the webview')
            click('#backup-undo')
            wait_for('return !!document.querySelector("#backup-confirm")')
            check(not js('return !!document.querySelector("#legacy-import-review")'), 'Previous library uses the existing full restore review to undo additive import')
            apply()
            check(state('undone') == before_apply, 'undo restores the exact library from immediately before import, including current DNS and the record added during review')

            command('preferences', {**command('snapshot')['preferences'], 'language': 'en', 'theme': 'dark'})
            wait_for('return document.documentElement.lang === "en"')
            no_change = state('before-blocked')
            blocked = open_file(copies['blocked.thrbackup'])
            codes = {issue['code'] for issue in blocked['legacy']['issues']}
            skipped = lambda source_id, code: any(issue['sourceId'] == source_id and issue['code'] == code for issue in blocked['legacy']['issues'])
            check(blocked['legacy']['canApply'] is False and {'legacy_profile_skipped', 'legacy_selector_field_unsupported', 'legacy_profile_field_unsupported'}.issubset(codes) and 'legacy_wireguard_system_unsupported' not in codes and 'legacy_profile_external_resource' not in codes and not any(issue['sourceId'] == 58 for issue in blocked['legacy']['issues']) and all(skipped(source_id, 'legacy_profile_skipped') and skipped(source_id, 'legacy_profile_field_unsupported') for source_id in [56,57]) and any(resource['path'] == '/missing/synthetic-private.srs' for resource in blocked['legacy']['resources']) and js('return document.querySelector("#backup-confirm").disabled && document.querySelector("#backup-acknowledge").disabled'), 'autoselector, external core and unknown fields are named and left out while a system WireGuard interface converts; the full profile with a rule-set path converts and the batch waits for its file')
            reject(blocked['token'], 'legacy_import_blocked')
            check(private_ui(shown=('/missing/synthetic-private.srs',)) and not any(secret in json.dumps(blocked, ensure_ascii=False) for secret in SECRETS + ['synthetic-wireguard-private-secret', 'synthetic-external-core-secret', 'synthetic-future-field-secret']) and js('return !!document.querySelector("#legacy-import-blocked") && !!document.querySelector("#legacy-import-issues")'), 'the partial preview shows only the file it needs, keeps other values private, and the backend rejects a forged apply call')
            close()
            check(state('after-blocked') == no_change, 'a mixed supported and unsupported batch leaves every current record unchanged')
            no_profiles = open_file(copies['no-profiles.thrbackup'])
            check(no_profiles['legacy']['canApply'] is False and no_profiles['legacy']['scopes']['profiles'] is False and no_profiles['legacy']['inventory']['parts']['profiles'] is False and any(issue['code'] == 'legacy_import_select_scope' for issue in no_profiles['legacy']['issues']), 'archive parts flags prevent importing profile rows from an unselected source section')
            close()
            invalid = root / 'invalid.thrbackup'
            invalid.write_bytes(b'THRN\x02\0\0\0synthetic-source-dns-secret')
            open_file(invalid, legacy=False)
            wait_for('return !!document.querySelector(".backup-panel > .desktop-inline-error")')
            check(private_ui() and not js('return !!document.querySelector("dialog")') and state('after-invalid') == no_change, 'malformed binary input fails without exposing its body or partially changing the library')
            open_file(baseline_path, legacy=False)
            wait_for('return !!document.querySelector("#backup-confirm")')
            apply()
            check(state('final-baseline') == baseline and all(hashlib.sha256(path.read_bytes()).hexdigest() == manifest['sha256'][name] for name, path in copies.items()), 'restoring the native baseline removes all test fixtures, retains original IDs and leaves every source archive unchanged')
            audit = {'previews': previews(), 'sourceHashes': manifest['sha256'], 'nativeFixtureProfiles': 13, 'nativeFixtureGroups': 4, 'fullJsonExact': True, 'sourceUnchanged': True}
        finally:
            with contextlib.suppress(Exception):
                if audit is None:
                    audit = {'previews': previews(), 'sourceHashes': manifest['sha256'], 'failed': True}
                (pathlib.Path(h['args'].artifacts) / 'legacy-import-review.json').write_text(json.dumps(audit, ensure_ascii=False, indent=2) + '\n')
            if connection:
                connection.close()
            with contextlib.suppress(Exception):
                if js('return !!document.querySelector("dialog")'):
                    close()
                command('disconnect')
                command('preferences', initial['preferences'])
                js('if(window.__legacyAudit){window.fetch=window.__legacyAudit.original;delete window.__legacyAudit;}')
                click('.primary-nav button:nth-child(1)')
                request('POST', base + '/window/rect', geometry)
            server.shutdown()
            server.server_close()
