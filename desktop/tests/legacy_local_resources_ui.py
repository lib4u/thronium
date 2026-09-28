"""Actual Qt backup → native file selection → Core DNS/rules → portable restore."""
import contextlib
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import socket
import threading

from legacy_local_resources_fixtures import generate
from native_dialogs import file_dialog


def run(h):
    command, click, wait_for, js, check = (h[k] for k in ('command', 'click', 'wait_for', 'js', 'check'))
    root = Path(os.environ['XDG_DATA_HOME']) / 'io.thronium.desktop'
    assert 'thronium-native-test-' in str(root)
    assert not command('snapshot')['profiles'] and command('snapshot')['running'] is None
    artifacts = h['artifacts']
    archive, files, manifest = generate(artifacts / 'qt-fixture')
    command('preferences', {**command('snapshot')['preferences'], 'language': 'en'})
    state = lambda: json.loads((root / 'library.json').read_text())
    original = state()
    geometry = h['request']('GET', h['base'] + '/window/rect')
    hits = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            self.send_response(200); self.end_headers(); self.wfile.write(b'portable-policy-ok')
        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0)); inbound = reservation.getsockname()[1]

    def settings():
        click('.primary-nav button:nth-child(5)'); click('[data-settings-section=backup]')
        wait_for('return !!document.querySelector("#backup-open")')
    def open_file(path):
        click('#backup-open')
        file_dialog('Open backup' if command('snapshot')['preferences']['language'] == 'en' else 'Открыть резервную копию', path, opening=True)
        wait_for('return !!document.querySelector("#backup-confirm")')
    def apply():
        click('#backup-acknowledge'); click('#backup-confirm')
        wait_for('return !document.querySelector("dialog[open]")')
    def selected_rows():
        return js('return [...document.querySelectorAll("[data-legacy-resource]")].map(e=>({id:e.dataset.legacyResource,path:e.querySelector(".legacy-resource-path").textContent}))')
    def choose(row, file):
        click(f'[data-legacy-resource="{row["id"]}"] button')
        file_dialog('Choose routing file', file, opening=True)
        wait_for('return !document.querySelector("#backup-refresh").disabled')
    def request(host):
        with socket.create_connection(('127.0.0.1', inbound), timeout=3) as connection:
            address = f'{host}:{server.server_port}'
            connection.sendall(f'GET http://{address}/policy HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n'.encode())
            data = b''
            with contextlib.suppress(OSError):
                while len(data) < 8192:
                    part = connection.recv(2048)
                    if not part: break
                    data += part
            return data
    try:
        settings(); open_file(archive)
        click('#legacy-scope-routes')
        wait_for('return document.querySelectorAll("[data-legacy-resource]").length===3 && !document.querySelector("#backup-refresh").disabled')
        check(state() == original and js('return document.querySelector("#backup-confirm").disabled'), 'opening real Qt paths neither reads source files nor changes the library')
        rows = selected_rows()
        invalid = artifacts / 'invalid.json'; invalid.write_text('{"version":3,"version":4,"rules":[]}')
        json_row = next(row for row in rows if row['path'].endswith('local.json'))
        choose(json_row, invalid)
        button_selector = json.dumps(f'[data-legacy-resource="{json_row["id"]}"] button')
        check(state() == original and js('return document.querySelector(' + button_selector + ').textContent.trim()==="Choose file"'), 'duplicate JSON keys reject a selected resource without making the review applicable')
        for row in rows:
            choose(row, files / Path(row['path']).name)
        wait_for('return !document.querySelector("#legacy-import-blocked")')
        check(state() == original and not (root / 'routing-resources').exists(), 'all three file choices remain a preview without runtime files')
        click('#legacy-scope-routes'); wait_for('return !document.querySelector("#backup-refresh").disabled')
        click('#legacy-scope-routes'); wait_for('return !document.querySelector("#backup-refresh").disabled')
        check(len(selected_rows()) == 3 and not js('return !!document.querySelector("#legacy-import-blocked")'), 'scope changes retain the selected resource copies')
        h['request']('POST', h['base'] + '/window/rect', {'width': 390, 'height': 844})
        js('document.querySelector("#legacy-resources-title").scrollIntoView({block:"start"})')
        check(js('return document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth+1'), 'file paths and selection controls fit a narrow English review')
        h['screenshot']('legacy-resources-en-390')
        command('preferences', {**command('snapshot')['preferences'], 'language': 'ru'})
        wait_for('return document.documentElement.lang==="ru"')
        click('#backup-refresh'); wait_for('return !document.querySelector("#backup-refresh").disabled')
        h['screenshot']('legacy-resources-ru-390')
        check('Файлы маршрутизации' in js('return document.querySelector(".legacy-resources").textContent'), 'Russian resource review is localized')
        apply()
        imported = state()
        check(imported['version'] == 6 and len(imported['routingResources']) == 3 and '/old/Throne' not in json.dumps(imported), 'import stores portable resource bytes under the version-six reader boundary')
        shutil.rmtree(files)
        preset = next(p for p in command('routing')['profiles'] if p['name'] == 'Qt local resources')
        command('checkRouting', preset)
        check(len(list((root / 'routing-resources').iterdir())) == 3, 'real Core validates hosts, JSON and SRS after the selected originals have been removed')
        profile = command('saveProfile', {'name': 'Resource fixture', 'groupId': 'personal', 'kind': 'sing-box-outbound', 'config': {'type': 'direct'}})['id']
        routing = command('routing'); routing['active'] = preset['id']; command('saveRouting', routing)
        command('connectionSettings', {'mode': 'local', 'port': inbound})
        command('connect', {'id': profile})
        good = request('resource.fixture.invalid')
        check(b'portable-policy-ok' in good and len(hits) == 1, 'copied hosts resolve a real HTTP request allowed by the local JSON rule set')
        blocked = request('127.0.0.1')
        check(b'portable-policy-ok' not in blocked and len(hits) == 1, 'the copied binary SRS blocks a matching IP request before it reaches the server')
        command('disconnect')
        settings(); saved = artifacts / 'portable-resource-backup.json'
        click('#backup-save'); file_dialog('Сохранить резервную копию', saved)
        wait_for('return !document.querySelector("#backup-save").disabled')
        check(len(json.loads(saved.read_text())['library']['routingResources']) == 3, 'native backup export includes all selected resources')
        click('#backup-undo'); wait_for('return !!document.querySelector("#backup-confirm")'); apply()
        check(not state().get('routingResources'), 'Undo removes the imported policies and their library resources')
        shutil.rmtree(root / 'routing-resources')
        open_file(saved); apply()
        command('checkRouting', preset)
        check(len(list((root / 'routing-resources').iterdir())) == 3, 'restoring the portable backup reconstructs every Core file without the original paths or cache')
        (artifacts / 'resource-audit.json').write_text(json.dumps({'manifest': manifest, 'httpRequests': len(hits), 'resources': len(state()['routingResources'])}, indent=2) + '\n')
    except Exception:
        with contextlib.suppress(Exception):
            (artifacts / 'review-failure.txt').write_text(js('return document.body.innerText'))
            h['screenshot']('resource-review-failure')
        raise
    finally:
        with contextlib.suppress(Exception):
            command('disconnect')
            if js('return !!document.querySelector("dialog[open]")'): click('#main-modal > .modal-head > button')
            backup = {'format': 'thronium-backup', 'version': 1, 'createdAt': 1, 'library': original}
            restore = artifacts / 'original.json'; restore.write_text(json.dumps(backup))
            settings(); open_file(restore); apply()
            h['request']('POST', h['base'] + '/window/rect', geometry)
        server.shutdown(); server.server_close()


PROFILE_FIXTURES = Path(__file__).resolve().parents[1] / 'engine/src/legacy_backup/profile_resources/fixtures'


def run_profiles(h):
    """Custom sing-box/SSH profiles that name files: per-file choice, PEM/text kinds, version 7, exact undo."""
    import hashlib
    import subprocess
    command, click, wait_for, js, check = (h[k] for k in ('command', 'click', 'wait_for', 'js', 'check'))
    root = Path(os.environ['XDG_DATA_HOME']) / 'io.thronium.desktop'
    assert 'thronium-native-test-' in str(root)
    artifacts = h['artifacts'] / 'legacy-profile-resources'
    artifacts.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((PROFILE_FIXTURES / 'manifest.json').read_text())
    for name, entry in manifest['archives'].items():
        assert hashlib.sha256((PROFILE_FIXTURES / (name + '.thrbackup')).read_bytes()).hexdigest() == entry['sha256'], name
    # A throwaway self-signed certificate stands in for the user's CA/key files; nothing is committed.
    pem = artifacts / 'fixture-ca.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
                    '-keyout', str(artifacts / 'fixture-ca.key'), '-out', str(pem), '-days', '2', '-subj', '/CN=fixture.invalid'],
                   check=True, capture_output=True)
    key = artifacts / 'fixture-ca.key'
    command('preferences', {**command('snapshot')['preferences'], 'language': 'en'})
    wait_for('return document.documentElement.lang==="en"')
    state = lambda: json.loads((root / 'library.json').read_text())
    original = state()
    # The routes scenario above may already own a resource store; listing the
    # profile inputs must leave whatever is there untouched.
    stored = lambda: sorted(str(p.relative_to(root)) for p in (root / 'routing-resources').rglob('*')) if (root / 'routing-resources').exists() else []
    original_resources = stored()

    def settings():
        click('.primary-nav button:nth-child(5)'); click('[data-settings-section=backup]')
        wait_for('return !!document.querySelector("#backup-open")')

    def open_file(path):
        click('#backup-open')
        file_dialog('Open backup', path, opening=True)
        wait_for('return !!document.querySelector("#backup-confirm")')

    def apply():
        click('#backup-acknowledge'); click('#backup-confirm')
        wait_for('return !document.querySelector("dialog[open]")')

    def rows():
        return js('return [...document.querySelectorAll("[data-legacy-resource]")].map(e=>({id:e.dataset.legacyResource,entity:e.dataset.legacyResourceEntity,path:e.querySelector(".legacy-resource-path").textContent,text:e.textContent}))')

    def choose(row, file):
        click(f'[data-legacy-resource="{row["id"]}"] button')
        file_dialog('Choose routing file', file, opening=True)
        wait_for('return !document.querySelector("#backup-refresh").disabled')

    try:
        settings(); open_file(PROFILE_FIXTURES / 'profiles-resources.thrbackup')
        wait_for('return document.querySelectorAll("[data-legacy-resource]").length===4 && !document.querySelector("#backup-refresh").disabled')
        listed = rows()
        check(all(r['entity'] == 'profile' for r in listed) and js('return document.querySelector("#backup-confirm").disabled')
              and js('return !!document.querySelector("[data-legacy-resource-group=profile] h4")')
              and any('Full config with files' in r['text'] for r in listed) and any('PEM' in r['text'] for r in listed),
              'custom profile inputs are listed under the profiles group with their owner and kind, and block apply until chosen')
        check(state() == original and stored() == original_resources, 'listing profile inputs reads nothing from the old paths')
        wrong = artifacts / 'not-a-certificate.pem'; wrong.write_text('plain text without a PEM block\n')
        ca_row = next(r for r in listed if r['path'].endswith('ca.pem'))
        choose(ca_row, wrong)
        check(js('return document.querySelector(' + json.dumps(f'[data-legacy-resource="{ca_row["id"]}"] button') + ').textContent.trim()==="Choose file"'),
              'a file without a PEM block is refused for a certificate input')
        for r in listed:
            path = r['path']
            if path.endswith('custom.hosts'): file = PROFILE_FIXTURES / 'selectable/custom.hosts'
            elif path.endswith('loopback.srs'): file = PROFILE_FIXTURES / 'selectable/loopback.srs'
            elif path.endswith('id_fixture'): file = key
            else: file = pem
            choose(r, file)
        wait_for('return !document.querySelector("#backup-confirm").disabled || !!document.querySelector("#backup-acknowledge")')
        check(all(r['text'].count('Selected') == 1 for r in rows()) and state() == original, 'every profile input is selected once and the library is still untouched')
        h['request']('POST', h['base'] + '/window/rect', {'width': 390, 'height': 844})
        js('document.querySelector("#legacy-resources-title").scrollIntoView({block:"start"})')
        check(js('return document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth+1'), 'grouped profile inputs fit a narrow English review')
        h['screenshot']('legacy-profile-resources-en-390')
        command('preferences', {**command('snapshot')['preferences'], 'language': 'ru'})
        wait_for('return document.documentElement.lang==="ru"')
        click('#backup-refresh'); wait_for('return !document.querySelector("#backup-refresh").disabled')
        check('Профили' in js('return document.querySelector(".legacy-resources").textContent'), 'Russian review names the profile group')
        h['screenshot']('legacy-profile-resources-ru-390')
        command('preferences', {**command('snapshot')['preferences'], 'language': 'en'})
        wait_for('return document.documentElement.lang==="en"')
        click('#backup-refresh'); wait_for('return !document.querySelector("#backup-refresh").disabled')
        h['request']('POST', h['base'] + '/window/rect', {'width': 1280, 'height': 860})
        apply()
        imported = state()
        check(imported['version'] == 7 and len(imported['routingResources']) == 4 and '/old/Throne' not in json.dumps(imported)
              and all(r['kind'] in ('hosts', 'rule-set-binary', 'pem', 'text') for r in imported['routingResources'].values()),
              'import stores one portable copy per distinct file under the version-seven reader boundary')
        full = next(p for p in imported['profiles'] if p['name'] == 'Full config with files')
        ssh = next(p for p in imported['profiles'] if p['name'] == 'SSH with key files')
        check(full['config']['outbounds'][0]['tls']['certificate_path'].startswith('thronium-resource:')
              and 'initial_path' not in json.dumps(full['config']) and ssh['config']['private_key_path'].startswith('thronium-resource:'),
              'profile configurations reference the copies and the remote seed path is dropped')
        pem.unlink(); key.unlink()
        for profile in (full, ssh):
            command('checkProfile', command('profile', {'id': profile['id']}))
        cached = sorted(p.name for p in (root / 'routing-resources').iterdir())
        # The content-addressed cache may still hold copies from the routes scenario above.
        check(sum(n.endswith('.pem') for n in cached) == 2 and any(n.endswith('.hosts') for n in cached) and any(n.endswith('.srs') for n in cached),
              'the real Core validates both profiles from immutable copies after the chosen originals were removed')
        key_mode = next((root / 'routing-resources' / n).stat().st_mode & 0o777 for n in cached if n.endswith('.pem'))
        check(key_mode == 0o600, 'materialised certificate and key copies stay private to the user')
        settings(); saved = artifacts / 'portable-profile-backup.json'
        click('#backup-save'); file_dialog('Save backup', saved)
        wait_for('return !document.querySelector("#backup-save").disabled')
        check(json.loads(saved.read_text())['library']['version'] == 7, 'native backup export carries the profile inputs as version seven')
        click('#backup-undo'); wait_for('return !!document.querySelector("#backup-confirm")'); apply()
        check(not state().get('routingResources') and not any(p['name'] == 'SSH with key files' for p in state()['profiles']),
              'undo removes the imported profiles and their copies')
        shutil.rmtree(root / 'routing-resources')
        open_file(saved); apply()
        for profile in (full, ssh):
            command('checkProfile', command('profile', {'id': profile['id']}))
        restored = [n.suffix.lstrip('.') for n in (root / 'routing-resources').iterdir()]
        check(restored.count('pem') == 2 and 'hosts' in restored and 'srs' in restored,
              'restoring the portable backup reconstructs the Core files on an empty cache')
        # A list an Xray configuration names by `ext:` is a file the review asks
        # for by name, and the core reads it from its own asset directory.
        settings(); open_file(PROFILE_FIXTURES / 'profiles-resources-blocked.thrbackup')
        wait_for('return document.querySelectorAll("[data-legacy-resource]").length>=1 && !document.querySelector("#backup-refresh").disabled')
        asset_row = next(r for r in rows() if r['path'].endswith('private.dat'))
        check('List of sites or addresses' in asset_row['text'] and js('return document.querySelector("#backup-confirm").disabled'),
              'the list an Xray configuration names is asked for by its own name and blocks apply until answered')
        wrong = artifacts / 'not-a-list.dat'; wrong.write_bytes(b'not a list of sites at all')
        choose(asset_row, wrong)
        check(js('return document.querySelector(' + json.dumps(f'[data-legacy-resource="{asset_row["id"]}"] button') + ').textContent.trim()==="Choose file"'),
              'a file that is not a list of sites or addresses is refused for such a name')
        # One category with one domain, in the shape Xray reads: it looks the
        # code up in upper case, exactly as its own lists store it.
        domain = b'\x08\x00\x12\x0ffixture.invalid'
        entry = b'\x0a\x03TAG\x12' + bytes([len(domain)]) + domain
        listing = artifacts / 'private.dat'; listing.write_bytes(b'\x0a' + bytes([len(entry)]) + entry)
        choose(asset_row, listing)
        # The same profile also carries ordinary inputs; the whole set is answered.
        fresh = artifacts / 'ext-ca.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
                        '-keyout', str(artifacts / 'ext-ca.key'), '-out', str(fresh), '-days', '2', '-subj', '/CN=fixture.invalid'],
                       check=True, capture_output=True)
        for row in rows():
            if row['path'].endswith('.pem'):
                choose(row, fresh)
            elif row['path'].endswith('.key'):
                choose(row, artifacts / 'ext-ca.key')
        apply()
        carried = state()
        check(carried['version'] == 8 and any(r['kind'] == 'geodata' for r in carried['routingResources'].values()),
              'the carried list travels with the library under the version-eight reader boundary')
        xray = next(p for p in carried['profiles'] if 'ext:thronium-resource:' in json.dumps(p['config']))
        try:
            command('checkProfile', command('profile', {'id': xray['id']}))
        except Exception:
            (artifacts / 'ext-check-failure.json').write_text(json.dumps({
                'profile': command('profile', {'id': xray['id']}),
                'assets': sorted(p.name for p in (root / 'xray-assets').iterdir()) if (root / 'xray-assets').is_dir() else [],
                'log': [e.get('text') for e in command('getLogs', {})['entries'][-12:]]}, indent=2))
            raise
        command('connect', {'id': xray['id']})
        wait_for('return true')
        assets = sorted(p.name for p in (root / 'xray-assets').iterdir() if p.suffix == '.dat')
        running = command('connectionConfiguration', {'id': xray['id'], 'active': True})
        named = json.dumps(running)
        check(command('snapshot')['running'] == xray['id'] and any(('ext:' + name + ':tag') in named for name in assets),
              'the real Xray starts with the list the person supplied, read from the asset directory: ' + json.dumps(assets))
        check(listing.read_bytes() == (root / 'xray-assets' / next(n for n in assets if ('ext:' + n + ':tag') in named)).read_bytes(),
              'the copy in the asset directory is exactly the file that was chosen')
        command('disconnect')
        settings(); click('#backup-undo'); wait_for('return !!document.querySelector("#backup-confirm")'); apply()
        (artifacts / 'profile-resource-audit.json').write_text(json.dumps({'manifest': manifest['archives'], 'cached': cached}, indent=2) + '\n')
    except Exception:
        with contextlib.suppress(Exception):
            (artifacts / 'review-failure.txt').write_text(js('return document.body.innerText'))
            h['screenshot']('profile-resource-review-failure')
        raise
    finally:
        with contextlib.suppress(Exception):
            command('disconnect')
            if js('return !!document.querySelector("dialog[open]")'): click('#main-modal > .modal-head > button')
            backup = {'format': 'thronium-backup', 'version': 1, 'createdAt': 1, 'library': original}
            restore = artifacts / 'original.json'; restore.write_text(json.dumps(backup))
            settings(); open_file(restore); apply()
