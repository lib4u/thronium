"""Native runtime settings import (inbound, system, presets, intercept, TUN, core) with actual Qt files."""
import contextlib
import copy
import hashlib
import json
from pathlib import Path
import tempfile
from native_dialogs import file_dialog

DESKTOP = Path(__file__).resolve().parents[1]
SOURCE = DESKTOP / 'engine/src/legacy_backup/settings/runtime-fixtures'
CATALOG = {field['id']: field for field in json.loads((DESKTOP / 'contracts/settings.catalog.json').read_text())}


def expect(library, values):
    """Apply converted values the way the Engine does: preference pointers or the settings map."""
    expected = copy.deepcopy(library)
    for field, value in values.items():
        pointer = CATALOG[field].get('preference')
        if pointer:
            target = expected['preferences']
            *parents, last = pointer.split('/')[1:]
            for part in parents:
                target = target[part]
            target[last] = value
        else:
            expected['settings'][field] = value
    return expected


def run(h):
    command, click, wait, js, check = (h[k] for k in ('command', 'click', 'wait_for', 'js', 'check'))
    manifest = json.loads((SOURCE / 'manifest.json').read_text())
    # The manifest owns the category sizes; the review must count all of them.
    total = sum(len(fields) for fields in manifest['groups'].values())
    groups = list(manifest['groups'])
    marker = manifest['marker']
    initial = command('snapshot')['preferences']
    geometry = h['request']('GET', h['base'] + '/window/rect')

    def settings(section='backup'):
        click('.primary-nav button:nth-child(5)')
        wait('return !!document.querySelector("[data-settings-section=' + section + ']")')
        click('[data-settings-section=' + section + ']')
        wait('return document.querySelector("[data-settings-section=' + section + ']").getAttribute("aria-current")==="page"')

    def previews(): return js('return window.__runtime82c.previews')

    def reviewed(count):
        wait('return window.__runtime82c.previews.length>' + str(count))
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
        return marker not in json.dumps(review) + js('return document.querySelector("#main-modal").textContent')

    def codes(review):
        return {issue['code'] for issue in review['legacy']['issues']}

    def form(section, field):
        settings(section)
        # data-setting is the catalog id; element ids are derived per control.
        return js('const e=document.querySelector(\'[data-setting="' + field + '"]\');return e ? (e.type==="checkbox" ? e.checked : e.value) : null')

    with tempfile.TemporaryDirectory(prefix='thronium-runtime82c-ui-') as temporary:
        root = Path(temporary)
        try:
            command('disconnect')
            js('''const original=window.fetch;window.__runtime82c={original,previews:[]};window.fetch=function(input,options){let name;try{name=JSON.parse(options?.body||'{}').name;}catch{}const result=original.apply(this,arguments);if(['readBackup','legacyBackupScopes','refreshBackupPreview'].includes(name))result.then(r=>r.clone().json()).then(v=>{const p=v?.preview||v;if(p?.token)window.__runtime82c.previews.push(p)}).catch(()=>{});return result;};''')
            valid = {field: value for group in manifest['expected']['valid'].values() for field, value in group.items()}
            for language, theme, width in [('en', 'dark', 1080), ('ru', 'light', 390)]:
                command('preferences', {**command('snapshot')['preferences'], 'language': language, 'theme': theme})
                wait('return document.documentElement.lang===' + json.dumps(language))
                h['request']('POST', h['base'] + '/window/rect', {'width': width, 'height': 860})
                settings(); before = library(); first = open_file('valid')
                check(first['legacy']['settingsCount'] == 0 and all(first['legacy']['settingsGroups'][g]['count'] == len(manifest['groups'][g]) for g in groups), 'runtime categories start unselected with per-category counts in ' + language)
                for group in groups: chosen = toggle(group)
                check(chosen['legacy']['canApply'] and chosen['legacy']['settingsCount'] == total and safe(chosen), 'every runtime setting of the fixture has a value-free review in ' + language)
                check({'legacy_inbound_auth_enabled', 'legacy_inbound_lan_listen', 'legacy_tun_permission_disabled', 'legacy_core_clash_api_enabled', 'legacy_system_tray_disabled'} <= codes(chosen), 'side-effect notices name the imported listener, privilege and tray choices')
                check(js('return document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth+1 && document.querySelector("#backup-confirm").disabled'), 'review fits ' + str(width) + 'px and requires acknowledgement')
                h['screenshot']('runtime82c-review-' + language)
                apply(); after = library()
                check(after == expect(before, valid), 'import replaces exactly the selected runtime values through settings and preferences in ' + language)
                check({field: form('tun', field) for field in ('vpn_mtu', 'vpn_implementation', 'tun_request_permission')} == {'vpn_mtu': '1400', 'vpn_implementation': 'mixed', 'tun_request_permission': False}, 'actual TUN form shows the imported MTU, stack and inverted privilege choice')
                check(form('inbound', 'inbound_socks_port') == '2085' and form('inbound', 'inbound_auth') is True, 'actual inbound form shows the imported port and authentication')
                check(form('core', 'core_box_clash_enabled') is True and form('core', 'core_box_api_enabled') is False and form('core', 'ruleset_mirror') == 'gcore', 'actual core form splits the sign-encoded listeners and names the mirror')
                settings(); undo(); check(library() == before, 'undo restores the complete library in ' + language)
            for mode, blocked in manifest['blocked'].items():
                (group, code), = blocked.items()
                before = library(); open_file(mode); bad = toggle(group)
                check(not bad['legacy']['canApply'] and safe(bad) and code in codes(bad) and bad['legacy']['settingsGroups'][group]['count'] == 0, mode + ' blocks only the ' + group + ' category without exposing values')
                toggle(group); good = toggle('presets')
                check(good['legacy']['canApply'] and good['legacy']['settingsCount'] == len(manifest['groups']['presets']), mode + ': an unrelated category still imports')
                apply(); check(library() == expect(before, manifest['expected']['valid']['presets']), mode + ': only the selected category changes')
                undo(); check(library() == before, mode + ': exact undo')
            before = library(); open_file('defaults'); core = toggle('core')
            check(core['legacy']['canApply'] and {'legacy_core_ntp_default_port', 'legacy_core_route_interval_disabled'} <= codes(core), 'Qt defaults explain the NTP port and disabled rule-set interval')
            apply(); check(library() == expect(before, manifest['expected']['defaults']['core']), 'Qt default listeners import disabled with their ports kept')
            undo(); check(library() == before, 'defaults import has exact undo')
            check(all(hashlib.sha256((SOURCE / n).read_bytes()).hexdigest() == digest for n, digest in manifest['sha256'].items()), 'all eight Qt archives remain unchanged')
        finally:
            with contextlib.suppress(Exception):
                if js('return !!document.querySelector("dialog[open]")'): close()
                command('preferences', initial)
                js('window.fetch=window.__runtime82c.original;delete window.__runtime82c')
                h['request']('POST', h['base'] + '/window/rect', geometry)
