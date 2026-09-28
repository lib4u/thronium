"""Native functional settings import with actual Qt files and the existing review UI."""
import contextlib
import copy
import hashlib
import json
from pathlib import Path
import tempfile
from native_dialogs import file_dialog

SOURCE = Path(__file__).resolve().parents[1] / 'engine/src/legacy_backup/settings/basic-fixtures'


def run(h):
    command, click, wait, js, check = (h[k] for k in ('command', 'click', 'wait_for', 'js', 'check'))
    manifest = json.loads((SOURCE / 'manifest.json').read_text())
    initial = command('snapshot')['preferences']
    geometry = h['request']('GET', h['base'] + '/window/rect')

    def settings(section='backup'):
        click('.primary-nav button:nth-child(5)')
        wait('return !!document.querySelector("[data-settings-section=' + section + ']")')
        click('[data-settings-section=' + section + ']')
        wait('return document.querySelector("[data-settings-section=' + section + ']").getAttribute("aria-current")==="page"')

    def previews(): return js('return window.__basic82.previews')

    def reviewed(count):
        wait('return window.__basic82.previews.length>' + str(count))
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

    def library():
        # Reuse the real export command/chooser; do not expose private library through a test API.
        path = root / ('library-' + str(len(list(root.iterdir()))) + '.json')
        click('#backup-save')
        ru = command('snapshot')['preferences']['language'] == 'ru'
        file_dialog('Сохранить резервную копию' if ru else 'Save backup', path)
        wait('return !document.querySelector("#backup-save").disabled')
        return json.loads(path.read_text())['library']

    def safe(review):
        return 'private-marker82' not in json.dumps(review) + js('return document.querySelector("#main-modal").textContent')

    with tempfile.TemporaryDirectory(prefix='thronium-basic82-ui-') as temporary:
        root = Path(temporary)
        try:
            command('disconnect')
            js('''const original=window.fetch;window.__basic82={original,previews:[]};window.fetch=function(input,options){let name;try{name=JSON.parse(options?.body||'{}').name;}catch{}const result=original.apply(this,arguments);if(['readBackup','legacyBackupScopes','refreshBackupPreview'].includes(name))result.then(r=>r.clone().json()).then(v=>{const p=v?.preview||v;if(p?.token)window.__basic82.previews.push(p)}).catch(()=>{});return result;};''')
            for language, theme, width in [('en', 'dark', 1080), ('ru', 'light', 390)]:
                command('preferences', {**command('snapshot')['preferences'], 'language': language, 'theme': theme})
                wait('return document.documentElement.lang===' + json.dumps(language))
                h['request']('POST', h['base'] + '/window/rect', {'width': width, 'height': 860})
                settings(); before = library(); first = open_file('valid')
                check(first['legacy']['settingsCount'] == 0, 'functional settings start unselected in ' + language)
                toggle('testing'); chosen = toggle('logging')
                check(chosen['legacy']['canApply'] and chosen['legacy']['settingsCount'] == 18 and safe(chosen), 'eighteen functional settings have a value-free review in ' + language)
                check(js('return document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth+1 && document.querySelector("#backup-confirm").disabled'), 'review fits ' + str(width) + 'px and requires acknowledgement')
                h['screenshot']('basic82-review-' + language)
                apply(); after = library(); expected = copy.deepcopy(before)
                expected['settings'].update(manifest['modes']['valid']); expected['settings']['connection_sort'] = 'process'
                check(after == expected, 'import replaces exactly selected functional values and preserves appearance in ' + language)
                settings('logging')
                check(js('return document.querySelector("#setting-log_level").value==="debug" && document.querySelector("#setting-max_log_line").value==="300" && !document.querySelector("#setting-log_file_enabled").checked'), 'actual logging form receives values without enabling file logging')
                check(js('return document.querySelector("#setting-log_include_regex").value.includes("(?i)allow")'), 'regex rows remain editable in the shared settings form')
                settings('testing')
                check(js('return document.querySelector("#setting-direct_test_url").value.endsWith("private-marker82")'), 'internet check URL reaches its testing field')
                settings(); undo(); check(library() == before, 'undo restores the complete library in ' + language)
            for mode, code in [('bad-sort', 'legacy_settings_sort_unsupported'), ('bad-regex', 'legacy_settings_regex_unsupported'), ('bad-list', 'legacy_settings_value_invalid'), ('bad-limit', 'legacy_settings_value_invalid')]:
                before = library(); open_file(mode); bad = toggle('logging')
                check(not bad['legacy']['canApply'] and safe(bad) and code in {i['code'] for i in bad['legacy']['issues']}, mode + ' blocks the selected category without exposing values')
                toggle('logging'); good = toggle('testing')
                check(good['legacy']['canApply'] and good['legacy']['settingsCount'] == 1, 'category opt-out permits the unrelated internet-check URL')
                apply(); expected = copy.deepcopy(before); expected['settings']['direct_test_url'] = manifest['modes'][mode]['direct_test_url']
                check(library() == expected, 'category opt-out changes one field'); undo(); check(library() == before, 'category opt-out has exact undo')
            check(all(hashlib.sha256((SOURCE / n).read_bytes()).hexdigest() == digest for n, digest in manifest['sha256'].items()), 'all eight Qt archives remain unchanged')
        finally:
            with contextlib.suppress(Exception):
                if js('return !!document.querySelector("dialog[open]")'): close()
                command('preferences', initial)
                js('window.fetch=window.__basic82.original;delete window.__basic82')
                h['request']('POST', h['base'] + '/window/rect', geometry)
