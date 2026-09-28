"""Actual Qt backup import/undo, native source controls and owned HTTPS download."""
import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import tempfile
import time
import urllib.request
from native_dialogs import file_dialog

SOURCE = Path(__file__).resolve().parents[1] / 'engine/src/legacy_backup/settings/geodata-fixtures'


def run(h):
    command, click, js, wait_for, check = (h[k] for k in ('command', 'click', 'js', 'wait_for', 'check'))
    fixture = json.loads(Path(os.environ['_THRONIUM_GEODATA_FIXTURE']).read_text())
    manifest = json.loads((SOURCE / 'manifest.json').read_text())
    root = Path(command('storageLocation')['directory']); sockets = []; audit = {'previews': []}
    fields = manifest['fields']; rows = manifest['sourceRows']
    def library(): return json.loads((root / 'library.json').read_text())
    def sources(): return command('xrayGeodataSources')
    def admin():
        with urllib.request.urlopen(fixture['admin'], timeout=3) as response: return json.load(response)
    def poll(predicate, timeout=8):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if predicate(): return
            time.sleep(.05)
        raise AssertionError('legacy geodata fixture did not reach expected state')
    def show(selector): js('document.querySelector(arguments[0]).scrollIntoView({block:"center",behavior:"instant"})', selector)
    def press(selector): show(selector); click(selector)
    def settings(section='backup'):
        click('.primary-nav button:last-child'); click('[data-settings-section=' + section + ']')
        if section == 'backup': wait_for('return !!document.querySelector("#backup-open")')
        else:
            wait_for('return !!document.querySelector("#xray-geo-assets")')
            js('document.querySelector("#settings-xray").open=true')
            wait_for('return !document.querySelector("[data-geo-source=geosite]").disabled')
    def previews(): return js('return window.__legacyGeo73?.previews || []')
    def next_preview(count):
        wait_for('return window.__legacyGeo73.previews.length>' + str(count))
        wait_for('return !!document.querySelector("#backup-confirm") && !document.querySelector("#backup-refresh").disabled')
        value = previews()[-1]; audit['previews'].append(value); return value
    def open_file(path, malformed=False):
        count = len(previews()); ru = command('snapshot')['preferences']['language'] == 'ru'
        press('#backup-open')
        title = 'Открыть резервную копию' if ru else 'Open backup'
        try: file_dialog(title, path, opening=True)
        except AssertionError as error:
            if str(error) != 'Native file chooser has no visible editable path field': raise
            file_dialog(title, path, opening=True)
        wait_for('return !document.querySelector("#backup-open").disabled')
        if malformed:
            wait_for('return !!document.querySelector(".backup-panel > .desktop-inline-error")'); return None
        return next_preview(count)
    def toggle(group='geodata'):
        count = len(previews()); press('#legacy-scope-settings-' + group); return next_preview(count)
    def close(): click('#main-modal > .modal-head > button'); wait_for('return !document.querySelector("dialog[open]")')
    def apply():
        if not js('return document.querySelector("#backup-acknowledge").checked'): press('#backup-acknowledge')
        press('#backup-confirm'); wait_for('return !document.querySelector("dialog[open]") && !!document.querySelector("#backup-notice")')
    def undo(): press('#backup-undo'); wait_for('return !!document.querySelector("#backup-confirm")'); apply()
    def rejected(token, expected):
        try: command('restoreBackup', {'token': token})
        except RuntimeError as error: return expected in str(error)
        return False
    def safe(preview):
        text = json.dumps(preview)
        return not any(marker in text for marker in ('private-source73', 'private-history73', 'private-user73', 'private-password73', 'private-column-value73'))
    def imported(before, source_rows):
        expected = copy.deepcopy(before)
        for key in fields:
            if key not in source_rows: continue
            value = source_rows[key]
            expected['settings'][key] = json.loads(value) if key.endswith('_history') else value or manifest['sourceDefaults'][key]
        return expected
    def assert_no_download(): check(not admin()['requests'], 'preview/import/undo and source inspection never download a geodata database')
    try:
        initial = command('snapshot'); assert not initial['profiles']
        with socket.socket() as reservation: reservation.bind(('127.0.0.1', 0)); port = reservation.getsockname()[1]
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark', 'connectionMode': 'local', 'inboundPort': port})
        old = command('settings')['core']
        command('saveSettings', {'section': 'core', 'previous': old, 'values': {**old,
            'xray_geoip_url': 'https://assets.thronium.test/previous73/geoip.dat',
            'xray_geosite_url': 'https://assets.thronium.test/previous73/geosite.dat'}})
        profile = command('saveProfile', {'name': 'Legacy geodata primary73', 'kind': 'xray-config', 'groupId': 'personal',
                                         'config': {'outbounds': [{'protocol': 'freedom', 'tag': 'direct'}]}})['id']
        command('connect', {'id': profile}); running = command('snapshot')
        listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen(); sockets.append(listener)
        client = socket.create_connection(('127.0.0.1', port), timeout=3); sockets.append(client)
        authority = '127.0.0.1:' + str(listener.getsockname()[1])
        client.sendall(('CONNECT ' + authority + ' HTTP/1.1\r\nHost: ' + authority + '\r\n\r\n').encode())
        peer, _ = listener.accept(); peer.settimeout(3); sockets.append(peer); assert b'200' in client.recv(1024)
        from window_ui import primary
        from native_processes import core_pids
        connection, _, app_pid = primary(); connection.close(); main_pids = core_pids(app_pid)
        def preserved():
            current = command('snapshot'); assert current['running'] == profile and current['since'] == running['since'] and core_pids(app_pid) == main_pids
            client.sendall(b'preserved73'); assert peer.recv(11) == b'preserved73'
        settings()
        js('''const original=window.fetch;window.__legacyGeo73={original,previews:[]};window.fetch=function(input,options){let name=null;try{if(String(input).includes('/app_command'))name=JSON.parse(options?.body||'{}').name;}catch{}const result=original.apply(this,arguments);if(['readBackup','legacyBackupScopes','refreshBackupPreview','previewPreviousBackup'].includes(name))result.then(r=>r.clone().json()).then(v=>{const p=v?.preview||v;if(p?.token&&p?.current)window.__legacyGeo73.previews.push(p)}).catch(()=>{});return result;};''')
        with tempfile.TemporaryDirectory(prefix='thronium-legacy-geodata-ui73-') as temporary:
            copies = {}
            for name, digest in manifest['sha256'].items():
                assert hashlib.sha256((SOURCE / name).read_bytes()).hexdigest() == digest
                copies[name] = Path(temporary) / name; shutil.copy2(SOURCE / name, copies[name])
            before = library(); first = open_file(copies['valid.thrbackup'])
            check(first['legacy']['settingsCount'] == 0 and not first['legacy']['scopes'].get('settings', {}).get('geodata'), 'actual Qt geodata archive starts with its new category unselected')
            picked = toggle()
            check(picked['legacy']['settingsCount'] == 4 and safe(picked), 'geodata review exposes four constant field labels and counts without source URLs')
            check(js('return document.querySelector("#backup-confirm").disabled') and rejected(picked['token'], 'backup_disconnect_first'), 'active-connection import stays disabled and the API requires disconnect')
            preserved(); close()
            check(library() == before and not admin()['requests'], 'active geodata preview preserves the whole library and existing TCP stream')
            audit['activePreviewPreserved'] = True
            command('disconnect'); poll(lambda: command('snapshot')['running'] is None)
            check(command('snapshot')['since'] is None and core_pids(app_pid) == main_pids, 'Disconnect stops the connection while retaining the owned idle Core for later requests')
            for stream in sockets: stream.close()
            sockets.clear()
            for language, width in [('en', 1280), ('ru', 390)]:
                command('preferences', {**command('snapshot')['preferences'], 'language': language})
                h['request']('POST', h['base'] + '/window/rect', {'width': width, 'height': 900})
                wait_for('return document.documentElement.lang===' + json.dumps(language) + ' && innerWidth===' + str(width))
                settings(); before = library(); open_file(copies['valid.thrbackup']); picked = toggle()
                check(picked['legacy']['canApply'] and picked['legacy']['settingsCount'] == 4 and js('return !document.querySelector("#backup-acknowledge").checked'), 'geodata category is independently selectable and requires acknowledgement in ' + language)
                show('#legacy-settings-review')
                text = js('return document.querySelector("#legacy-settings-fields").textContent')
                check(('Последние' if language == 'ru' else 'Recent') in text and safe(picked) and js('return document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth+1'), 'localized source/history labels fit ' + language + ' ' + str(width) + 'px without exposing addresses')
                h['screenshot']('legacy-geodata-review-' + language + '-' + str(width))
                apply(); check(library() == imported(before, rows), 'geodata import replaces only its four selected settings in ' + language)
                settings('core')
                check(js('return document.querySelector("#setting-xray_geoip_url").value') == rows['xray_geoip_url'] and js('return document.querySelector("#setting-xray_geosite_url").value') == rows['xray_geosite_url'], 'imported current URLs appear in actual settings controls')
                expected_history = list(dict.fromkeys(url for url in manifest['history'] if url != manifest['sourceDefaults']['xray_geosite_url']))
                check(sources()['history']['geosite'] == expected_history and sources()['history']['geoip'] == json.loads(rows['xray_geoip_url_history']), 'source controls display preserved history order with duplicate/provider choices deduplicated')
                show('[data-geo-source=geosite]'); h['screenshot']('legacy-geodata-sources-' + language + '-' + str(width)); assert_no_download()
                settings(); undo(); check(library() == before, 'native Undo restores the exact previous library after geodata import in ' + language)
            settings(); before = library(); open_file(copies['valid.thrbackup']); toggle(); apply(); valid = library()
            open_file(copies['clear-site-history.thrbackup']); picked = toggle(); check(picked['legacy']['settingsCount'] == 1, 'an explicit empty GeoSite history imports one field without inventing absent defaults')
            apply(); check(library() == imported(valid, {'xray_geosite_url_history': '[]'}), 'clearing GeoSite history preserves GeoIP history and both current URLs')
            undo(); check(library() == valid, 'Undo restores the cleared history exactly')
            open_file(copies['explicit-empty-sources.thrbackup']); picked = toggle()
            check(sum(issue['code'] == 'legacy_geodata_default_source' for issue in picked['legacy']['issues']) == 2 and safe(picked), 'explicit empty current URLs explain their original Qt fallback in preview')
            apply(); check(library() == imported(valid, manifest['modes']['explicit-empty-sources']['sourceRows']), 'explicit empty current sources use the original Qt first-provider URLs')
            undo(); check(library() == valid, 'Undo preserves custom sources after explicit fallback import')
            for name in ['bad-json', 'bad-history-type', 'too-many', 'http-url', 'credential-url', 'unknown-column']:
                before = library(); open_file(copies[name + '.thrbackup']); bad = toggle()
                check(not bad['legacy']['canApply'] and safe(bad) and rejected(bad['token'], 'legacy_import_blocked'), 'invalid ' + name + ' refuses geodata import without exposing source values')
                if name != 'unknown-column':
                    toggle(); good = toggle('logging'); check(good['legacy']['canApply'] and good['legacy']['settingsCount'] == 1, 'opting out of invalid ' + name + ' leaves the independent logging category usable')
                close(); check(library() == before, 'refused ' + name + ' import leaves the library unchanged')
            before = library(); open_file(copies['bad-sqlite-type.thrbackup'], malformed=True)
            check(library() == before and not js('return !!document.querySelector("dialog[open]")'), 'wrong SQLite value types are rejected by the archive parser before a selectable plan')
            excluded = open_file(copies['excluded-settings.thrbackup'])
            check(js('return document.querySelector("#legacy-scope-settings-geodata").disabled'), 'excluded source settings disable geodata selection')
            forged = command('legacyBackupScopes', {'token': excluded['token'], 'scopes': {'profiles': False, 'routes': False, 'settings': {'geodata': True}}})
            check(not forged['legacy']['canApply'] and rejected(forged['token'], 'legacy_import_blocked'), 'forged IPC scope cannot import settings excluded by the Qt backup mask')
            close(); assert_no_download()
            h['request']('POST', h['base'] + '/refresh', {}); wait_for('return !!document.querySelector(".add-connection")'); settings('core')
            check(library() == valid and sources()['history']['geoip'] == json.loads(rows['xray_geoip_url_history']), 'imported sources and history survive a WebView reload')
            command('connect', {'id': profile}); running_after = command('snapshot'); pids_after = core_pids(app_pid)
            press('[data-geo-download=geoip]')
            wait_for('return !document.querySelector("[data-geo-cancel]") && !document.querySelector("[data-geo-download=geoip]").disabled', 20)
            poll(lambda: admin()['active'] == 0)
            status = command('xrayGeodataStatus', {'kind': 'geoip', 'url': rows['xray_geoip_url']})
            check(status['state'] == 'ready' and len(admin()['requests']) == 1 and admin()['requests'][0]['path'] == '/private-source73/geoip.dat', 'only explicit Download contacts the imported HTTPS source and validates real GeoIP data')
            check(command('snapshot')['running'] == profile and command('snapshot')['since'] == running_after['since'] and core_pids(app_pid) == pids_after, 'explicit geodata download preserves the reconnected primary Core')
            check(all(hashlib.sha256(path.read_bytes()).hexdigest() == manifest['sha256'][name] for name, path in copies.items()), 'all independent Qt backup files remain unchanged')
            audit['sourceArchivesUnchanged'] = True; audit['requests'] = admin()['requests']
    except BaseException:
        import traceback
        audit['failure'] = traceback.format_exc()
        raise
    finally:
        for stream in sockets:
            with contextlib.suppress(OSError): stream.close()
        with contextlib.suppress(Exception): command('disconnect')
        (h['artifacts'] / 'legacy-geodata-audit.json').write_text(json.dumps(audit, indent=2) + '\n')
