"""Native backup files, explicit replacement, stale review and recovery round trip."""
import json
import pathlib
import socket
import tempfile
import time
from native_dialogs import file_dialog


def run(h):
    command, click, fill, select, wait_for, js, check, screenshot = (h[k] for k in ('command', 'click', 'fill', 'select', 'wait_for', 'js', 'check', 'screenshot'))
    initial = command('snapshot')
    def settings():
        click('.primary-nav button:nth-child(5)'); wait_for('return !!document.querySelector("[data-settings-section=backup]")')
        click('[data-settings-section=backup]'); wait_for('return !!document.querySelector("#backup-save")')
    def save(path):
        click('#backup-save'); file_dialog('Save backup', path); wait_for('return document.querySelector("#backup-notice")?.textContent.includes("saved")')
    def open_file(path=None):
        click('#backup-open'); file_dialog('Open backup', path, opening=True)
        wait_for('return !document.querySelector("#backup-open").disabled')
    def close(): click('.modal-head .icon-button'); wait_for('return !document.querySelector("dialog")')
    def apply(): click('#backup-acknowledge'); click('#backup-confirm'); wait_for('return !document.querySelector("dialog")')
    def state(path):
        if path.exists(): path = path.with_name(f'{path.stem}-{time.monotonic_ns()}{path.suffix}')
        save(path); return json.loads(path.read_text())['library']
    with tempfile.TemporaryDirectory(prefix='thronium-backup-ui-') as folder:
        root = pathlib.Path(folder); baseline = root / 'baseline.json'; backup = root / 'backup.json'; current = root / 'current.json'
        try:
            command('disconnect'); command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark'})
            settings(); wait_for('return document.documentElement.lang==="en"')
            baseline_library = state(baseline)
            a = command('saveProfile', {'name': 'Backup member 🦊', 'groupId': 'personal', 'kind': 'sing-box-outbound', 'config': {'type': 'socks', 'server': '127.0.0.1', 'server_port': 9, 'password': 'private-backup-ui-secret'}})['id']
            command('favorite', {'id': a})
            chain = command('saveProfile', {'name': 'Backup chain', 'groupId': 'personal', 'kind': 'chain', 'config': {'type': 'chain', 'hops': [a]}})['id']
            pool = command('saveProfile', {'name': 'Backup pool', 'groupId': 'personal', 'kind': 'auto-selector', 'config': {'type': 'auto-selector', 'members': [a], 'pinned_profile': a}})['id']
            expected = state(backup)
            check(json.loads(backup.read_text())['format'] == 'thronium-backup' and all(pid in [p['id'] for p in expected['profiles']] for pid in [a, chain, pool]), 'native save creates a complete backup retaining IDs, chains and automatic pools')
            check(next(p for p in expected['profiles'] if p['id'] == a)['config']['password'] == 'private-backup-ui-secret', 'backup file retains complete configuration credentials for recovery')
            check(not js('return document.body.textContent.includes("private-backup-ui-secret")'), 'backup controls never reveal the file body in the webview')
            open_file(); check(not js('return !!document.querySelector("dialog")'), 'cancelling the native open dialog leaves the library and review unchanged')
            extra = command('saveProfile', {'name': 'Added after backup', 'groupId': 'personal', 'kind': 'sing-box-outbound', 'config': {'type': 'direct'}})['id']
            open_file(backup); wait_for('return !!document.querySelector("#backup-confirm")')
            check(js('return Number(document.querySelector("[data-backup-current=profiles]").textContent)===Number(document.querySelector("[data-backup-incoming=profiles]").textContent)+1'), 'restore review compares current and incoming profile counts before replacing anything')
            check(js('return document.querySelector("#backup-confirm").disabled && !document.body.textContent.includes("private-backup-ui-secret")'), 'replacement requires explicit acknowledgement without disclosing saved secrets')
            close(); check(any(p['id'] == extra for p in command('snapshot')['profiles']), 'closing restore review preserves profiles added after the backup')
            open_file(backup); wait_for('return !!document.querySelector("#backup-acknowledge")')
            command('favorite', {'id': extra}); click('#backup-acknowledge'); click('#backup-confirm')
            wait_for('return document.querySelector("dialog .desktop-inline-error")?.textContent.includes("changed")')
            check(any(p['id'] == extra for p in command('snapshot')['profiles']), 'native restore rejects a stale review after a library change')
            click('#backup-refresh'); wait_for('return !document.querySelector("#backup-refresh").disabled && !document.querySelector("#backup-acknowledge").checked')
            check(js('return document.querySelector("#backup-confirm").disabled'), 'refreshing the comparison requires a new explicit acknowledgement')
            close()
            with socket.socket() as s:
                s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]
            command('preferences', {**command('snapshot')['preferences'], 'inboundPort': port}); command('connect', {'id': extra})
            open_file(backup); wait_for('return !!document.querySelector("#backup-connected")'); click('#backup-acknowledge')
            check(js('return document.querySelector("#backup-confirm").disabled') and command('snapshot')['running'] == extra, 'an active VPN protects restore and remains connected while the backup is reviewed')
            command('disconnect'); click('#backup-refresh'); wait_for('return !document.querySelector("#backup-refresh").disabled')
            command('preferences', {**command('snapshot')['preferences'], 'language': 'ru', 'theme': 'light'})
            wait_for('return document.documentElement.lang==="ru"'); click('#backup-refresh'); wait_for('return !document.querySelector("#backup-refresh").disabled')
            h['request']('POST', h['base'] + '/window/rect', {'width': 390, 'height': 844})
            check(js('return document.querySelector("#modal-title").textContent.includes("Восстановление") && document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth && document.querySelector(".modal-footer").getBoundingClientRect().bottom<=innerHeight'), 'Russian restore comparison and confirmation fit the narrow native window')
            screenshot('backup-restore-narrow-ru'); apply()
            wait_for('return document.documentElement.lang==="en" && !!document.querySelector("#backup-notice")')
            h['request']('POST', h['base'] + '/window/rect', {'width': 1280, 'height': 860})
            check(state(current) == expected and command('snapshot')['running'] is None, 'restoration replaces the full library exactly and does not start a VPN connection')
            click('#backup-undo'); wait_for('return !!document.querySelector("#backup-confirm")'); apply()
            wait_for('return document.documentElement.lang==="ru"')
            check(any(p['id'] == extra for p in command('snapshot')['profiles']), 'previous-library recovery restores the profiles that replacement removed')
            command('preferences', {**command('snapshot')['preferences'], 'language': 'en'}); wait_for('return document.documentElement.lang==="en"')
            bad = root / 'invalid.json'; bad.write_text('{"format":"other","password":"invalid-backup-secret"}')
            before = len(command('snapshot')['profiles']); open_file(bad)
            wait_for('return !!document.querySelector(".backup-panel > .desktop-inline-error")')
            check(len(command('snapshot')['profiles']) == before and not js('return document.body.textContent.includes("invalid-backup-secret")'), 'invalid backup files fail without changing the library or exposing their contents')
            open_file(baseline); wait_for('return !!document.querySelector("#backup-confirm")'); apply(); wait_for('return document.documentElement.lang==="en"')
            check(state(current) == baseline_library, 'restoring the original test baseline removes all added fixtures while retaining original IDs and preferences')
        finally:
            command('disconnect'); command('preferences', initial['preferences'])
            click('.primary-nav button:nth-child(1)')
            h['request']('POST', h['base'] + '/window/rect', {'width': 1280, 'height': 860})
