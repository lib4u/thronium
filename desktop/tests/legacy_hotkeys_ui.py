"""Native import of Qt global shortcuts (hk_*) with actual Qt archives."""
import contextlib
import hashlib
import json
from pathlib import Path
from native_dialogs import file_dialog

DESKTOP = Path(__file__).resolve().parents[1]
SOURCE = DESKTOP / 'engine/src/legacy_backup/settings/hotkeys-fixtures'


def run(h):
    command, click, wait, js, check = (h[k] for k in ('command', 'click', 'wait_for', 'js', 'check'))
    manifest = json.loads((SOURCE / 'manifest.json').read_text())
    initial = command('snapshot')['preferences']
    original_system = command('settings')['system']

    def settings(section='backup'):
        click('.primary-nav button:nth-child(5)')
        wait('return !!document.querySelector("[data-settings-section=' + section + ']")')
        click('[data-settings-section=' + section + ']')
        wait('return document.querySelector("[data-settings-section=' + section + ']").getAttribute("aria-current")==="page"')

    def previews(): return js('return window.__hotkeys82d.previews')

    def reviewed(count):
        wait('return window.__hotkeys82d.previews.length>' + str(count))
        wait('return !!document.querySelector("#backup-confirm") && !document.querySelector("#backup-refresh").disabled')
        return previews()[-1]

    def open_file(mode):
        count = len(previews()); click('#backup-open')
        ru = command('snapshot')['preferences']['language'] == 'ru'
        file_dialog('Открыть резервную копию' if ru else 'Open backup', SOURCE / (mode + '.thrbackup'), opening=True)
        return reviewed(count)

    def toggle(scope):
        count = len(previews()); click('#legacy-scope-settings-' + scope); return reviewed(count)

    def close():
        click('#main-modal > .modal-head > button'); wait('return !document.querySelector("dialog[open]")')

    def apply():
        click('#backup-acknowledge'); click('#backup-confirm')
        wait('return !document.querySelector("dialog[open]") && !!document.querySelector("#backup-notice")')

    def undo():
        click('#backup-undo'); wait('return !!document.querySelector("#backup-confirm")'); apply()

    def codes(review): return {issue['code'] for issue in review['legacy']['issues']}
    def hotkeys(): return {k: v for k, v in command('settings')['system'].items() if k.startswith('hotkey_')}
    def safe(review): return 'Ctrl+' not in json.dumps(review) + js('return document.querySelector("#main-modal").textContent')

    try:
        command('disconnect')
        js('''const original=window.fetch;window.__hotkeys82d={original,previews:[]};window.fetch=function(input,options){let name;try{name=JSON.parse(options?.body||'{}').name;}catch{}const result=original.apply(this,arguments);if(['readBackup','legacyBackupScopes','refreshBackupPreview'].includes(name))result.then(r=>r.clone().json()).then(v=>{const p=v?.preview||v;if(p?.token)window.__hotkeys82d.previews.push(p)}).catch(()=>{});return result;};''')
        for language, width in [('en', 1080), ('ru', 390)]:
            command('preferences', {**command('snapshot')['preferences'], 'language': language})
            wait('return document.documentElement.lang===' + json.dumps(language))
            h['request']('POST', h['base'] + '/window/rect', {'width': width, 'height': 860})
            settings(); before = hotkeys(); first = open_file('valid')
            check(first['legacy']['settingsGroups']['hotkeys']['count'] == 5 and first['legacy']['settingsCount'] == 0, 'the shortcut category starts unselected with its count in ' + language)
            chosen = toggle('hotkeys')
            check(chosen['legacy']['canApply'] and chosen['legacy']['settingsCount'] == 5 and 'legacy_hotkeys_registered' in codes(chosen) and safe(chosen), 'five shortcuts have a value-free review with the registration notice in ' + language)
            check(js('return document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth+1'), 'review fits ' + str(width) + 'px')
            h['screenshot']('hotkeys82d-review-' + language)
            apply()
            check(hotkeys() == manifest['expected']['valid'], 'import writes the converted shortcuts into the system settings in ' + language)
            settings('system')
            check(js('return document.querySelector(\'[data-setting="hotkey_mainwindow"]\').value') == 'Ctrl+Shift+M' and js('return document.querySelector(\'[data-setting="hotkey_group"]\').value') == 'Super+G', 'the system settings form shows the imported shortcuts')
            settings(); undo(); check(hotkeys() == before, 'undo restores the previous shortcuts in ' + language)
        for mode, code in manifest['blocked'].items():
            before = hotkeys(); open_file(mode); bad = toggle('hotkeys')
            check(not bad['legacy']['canApply'] and code in codes(bad) and bad['legacy']['settingsGroups']['hotkeys']['count'] == 0 and safe(bad), mode + ' blocks the shortcut category with ' + code)
            close(); check(hotkeys() == before, mode + ': nothing changes')
        before = hotkeys(); open_file('sparse'); toggle('hotkeys'); apply()
        check(hotkeys() == {**before, **manifest['expected']['sparse']}, 'a sparse archive imports only the shortcut it contains')
        settings(); undo(); check(hotkeys() == before, 'sparse import has exact undo')
        check(all(hashlib.sha256((SOURCE / n).read_bytes()).hexdigest() == digest for n, digest in manifest['sha256'].items()), 'all five Qt archives remain unchanged')
    finally:
        with contextlib.suppress(Exception):
            if js('return !!document.querySelector("dialog[open]")'): close()
            current = command('settings')['system']
            if current != original_system: command('saveSettings', {'section': 'system', 'previous': current, 'values': original_system})
            command('preferences', initial)
            js('window.fetch=window.__hotkeys82d.original;delete window.__hotkeys82d')
