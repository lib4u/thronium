"""Focused native coverage of legacy network/subscription settings import."""
import contextlib
import copy
import hashlib
import json
from pathlib import Path
import socket
import tempfile
import time
from native_dialogs import file_dialog

SOURCE = Path(__file__).resolve().parents[1] / 'engine/src/legacy_backup/settings/network-fixtures'


def run(h):
    command, click, js, wait, check = (h[k] for k in ('command', 'click', 'js', 'wait_for', 'check'))
    manifest = json.loads((SOURCE / 'manifest.json').read_text())
    root = Path(command('storageLocation')['directory'])
    sockets = []
    def library(): return json.loads((root / 'library.json').read_text())
    def settings(section='backup'):
        click('.primary-nav button:last-child')
        click('[data-settings-section=' + section + ']')
        wait('return document.querySelector("[data-settings-section=' + section + ']").getAttribute("aria-current")==="page"')
    def previews(): return js('return window.__legacyNetwork75.previews')
    def next_preview(count):
        wait('return window.__legacyNetwork75.previews.length>' + str(count))
        wait('return !!document.querySelector("#backup-confirm") && !document.querySelector("#backup-refresh").disabled')
        return previews()[-1]
    def open_file(path):
        count = len(previews()); click('#backup-open')
        title = 'Открыть резервную копию' if command('snapshot')['preferences']['language'] == 'ru' else 'Open backup'
        try: file_dialog(title, path, opening=True)
        except AssertionError as error:
            if str(error) != 'Native file chooser has no visible editable path field': raise
            file_dialog(title, path, opening=True)
        return next_preview(count)
    def toggle(group):
        count = len(previews()); click('#legacy-scope-settings-' + group)
        return next_preview(count)
    def close():
        click('#main-modal > .modal-head > button'); wait('return !document.querySelector("dialog[open]")')
    def apply():
        click('#backup-acknowledge'); click('#backup-confirm')
        wait('return !document.querySelector("dialog[open]") && !!document.querySelector("#backup-notice")')
    def undo():
        click('#backup-undo'); wait('return !!document.querySelector("#backup-confirm")'); apply()
    def safe(value):
        text = json.dumps(value) + js('return document.querySelector("#main-modal").textContent')
        return not any(s in text for s in ['private-agent75', 'private-hwid75', 'private-model75', 'fixture-version75'])
    def frame(language):
        # Presentation is independent of the functional assertions; owned display only.
        from native_screenshot import private_display_server
        from window_ui import primary
        from Xlib import X
        private_display_server()
        display, window, _ = primary()
        try:
            window.configure(stack_mode=X.Above)
            window.set_input_focus(X.RevertToParent, X.CurrentTime); display.sync()
        finally: display.close()
        js('const n=document.querySelector("#legacy-scope-settings-network");n.focus({preventScroll:true});n.scrollIntoView({block:"center",behavior:"instant"})')
        time.sleep(.35)
        h['screenshot']('legacy-network-review-' + language)
    try:
        initial = command('snapshot'); assert not initial['profiles']
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0)); port = reservation.getsockname()[1]
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark'})
        command('connectionSettings', {'mode': 'local', 'port': port})
        main = command('saveProfile', {'name': 'Network import held connection', 'kind': 'sing-box-outbound', 'groupId': 'personal', 'config': {'type': 'direct'}})['id']
        command('connect', {'id': main}); running = command('snapshot')
        origin = socket.socket(); sockets.append(origin); origin.settimeout(5)
        origin.bind(('127.0.0.1', 0)); origin.listen()
        client = socket.create_connection(('127.0.0.1', port), timeout=5); sockets.append(client)
        target = '127.0.0.1:' + str(origin.getsockname()[1])
        client.sendall(('CONNECT ' + target + ' HTTP/1.1\r\nHost: ' + target + '\r\n\r\n').encode())
        peer, _ = origin.accept(); sockets.append(peer); peer.settimeout(5)
        assert b'200' in client.recv(1024)
        settings()
        js('''const original=window.fetch;window.__legacyNetwork75={previews:[]};window.fetch=function(input,options){let name;try{if(String(input).includes('/app_command'))name=JSON.parse(options?.body||'{}').name;}catch{}const p=original.apply(this,arguments);if(['readBackup','legacyBackupScopes','refreshBackupPreview','previewPreviousBackup'].includes(name))p.then(r=>r.clone().json()).then(v=>{const p=v?.preview||v;if(p?.token&&p?.current)window.__legacyNetwork75.previews.push(p)}).catch(()=>{});return p;};''')
        with tempfile.TemporaryDirectory(prefix='thronium-network-import-') as temporary:
            paths = {}
            for name in ['valid', 'bad-agent', 'clear-all']:
                path = SOURCE / (name + '.thrbackup')
                assert hashlib.sha256(path.read_bytes()).hexdigest() == manifest['sha256'][path.name]
                paths[name] = Path(temporary) / path.name; paths[name].write_bytes(path.read_bytes())
            before = library(); initial_review = open_file(paths['valid'])
            check(initial_review['legacy']['settingsCount'] == 0 and not js('return document.querySelector("#legacy-scope-settings-network").checked || document.querySelector("#legacy-scope-settings-subscriptions").checked'), 'new network and subscription categories start unselected')
            toggle('network'); picked = toggle('subscriptions')
            check(picked['legacy']['settingsCount'] == 9 and safe(picked), 'review selects nine settings without exposing private UA or HWID values')
            check(js('return document.querySelector("#backup-confirm").disabled'), 'settings import is disabled while connected')
            client.sendall(b'preview75'); assert peer.recv(9) == b'preview75'
            peer.sendall(b'reply75'); assert client.recv(7) == b'reply75'
            check(library() == before and command('snapshot')['since'] == running['since'], 'active preview keeps the library and real bidirectional TCP connection')
            close(); command('disconnect')
            for stream in sockets: stream.close()
            sockets.clear()
            for language, width in [('en', 1280), ('ru', 390)]:
                command('preferences', {**command('snapshot')['preferences'], 'language': language})
                h['request']('POST', h['base'] + '/window/rect', {'width': width, 'height': 900})
                wait('return document.documentElement.lang===' + json.dumps(language) + ' && innerWidth===' + str(width))
                settings(); before = library(); open_file(paths['valid']); toggle('network'); picked = toggle('subscriptions')
                check(picked['legacy']['canApply'] and not js('return document.querySelector("#backup-acknowledge").checked') and safe(picked), 'explicit import selection requires acknowledgement in ' + language)
                check(js('return document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth+1 && document.querySelectorAll("#legacy-settings-fields li").length===9'), 'nine localized fields fit the native review at ' + str(width) + 'px')
                frame(language); apply()
                expected = copy.deepcopy(before)
                for group in ['network', 'subscriptions']: expected['settings'].update(manifest['expectations']['valid'][group])
                check(library() == expected, 'native import changes exactly the nine chosen settings in ' + language)
                for section in ['network', 'subscriptions']:
                    settings(section)
                    values = {k: v for group in manifest['expectations']['valid'].values() for k, v in group.items()
                              if ('network' if k in ['net_use_proxy', 'net_insecure'] else 'subscriptions') == section}
                    current = command('settings')[section]
                    check(all(current[k] == v for k, v in values.items()), 'imported values reach the current ' + section + ' settings')
                settings(); undo(); check(library() == before, 'native Undo restores the exact preceding library in ' + language)
            for name, invalid, valid in [('bad-agent', 'network', 'subscriptions')]:
                before = library(); open_file(paths[name]); bad = toggle(invalid)
                check(not bad['legacy']['canApply'] and safe(bad), 'unsupported ' + name + ' blocks its selected category without private values')
                toggle(invalid); good = toggle(valid)
                check(good['legacy']['canApply'] and library() == before, 'opting out of ' + name + ' retains the independent supported category')
                close()
            before = library(); open_file(paths['clear-all']); picked = toggle('subscriptions')
            check(picked['legacy']['canApply'] and safe(picked), 'Qt clear-all imports as explicit recreation with a private-safe review')
            check(any(issue['code'] == 'legacy_subscription_recreate' for issue in picked['legacy']['issues']), 'legacy review explains the destructive recreation mode before apply')
            apply()
            expected = copy.deepcopy(before); expected['settings'].update(manifest['expectations']['clear-all']['subscriptions'])
            check(library() == expected and command('settings')['subscriptions']['sub_update_mode'] == 'recreate', 'native legacy apply maps one Qt flag to the two destination settings')
            undo(); check(library() == before, 'undo removes the derived recreation setting and restores exact state')
            check(all(hashlib.sha256(path.read_bytes()).hexdigest() == manifest['sha256'][path.name] for path in paths.values()), 'native chooser and importer leave Qt archives unchanged')
    finally:
        for stream in sockets:
            with contextlib.suppress(OSError): stream.close()
        with contextlib.suppress(Exception): command('disconnect')
