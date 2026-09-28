"""Actual export/import, clipboard, file chooser and lossless profile round trips."""
import json
import pathlib
import tempfile
import time
from native_dialogs import file_dialog


def run(h):
    command, click, fill, select, wait_for, js, check, screenshot = (h[k] for k in ('command', 'click', 'fill', 'select', 'wait_for', 'js', 'check', 'screenshot'))
    from configuration_ui import run as configuration_checks
    configuration_checks(h)
    initial = command('snapshot')
    source = command('saveGroup', {'name': 'Export fixtures', 'subscription': None})['id']
    target = command('saveGroup', {'name': 'Imported fixtures', 'subscription': None})['id']
    first = {'type': 'socks', 'server': '127.0.0.1', 'server_port': 1080, 'username': 'fixture', 'password': 'synthetic-export-secret', 'future': {'note': '[Interface]', 'list': ['a', 'b']}}
    second = {'inbounds': [], 'outbounds': [], 'routing': {'domainStrategy': 'AsIs'}, 'future': True}
    ids = [command('saveProfile', {'name': name, 'groupId': source, 'kind': kind, 'config': config})['id'] for name, kind, config in [('Экспорт 🦊', 'sing-box-outbound', first), ('Opaque Xray', 'xray-config', second)]]
    original_clipboard = None
    try:
        try: original_clipboard = command('readClipboard')
        except RuntimeError: pass
        command('preferences', {**initial['preferences'], 'language': 'en'})
        wait_for('return document.documentElement.lang==="en" && [...document.querySelector(".group-strip select").options].some(o=>o.value===' + json.dumps(source) + ')')
        select('.group-strip select', source); fill('#client-search', '')
        wait_for('return document.querySelectorAll(".connection-row").length===2')
        fill('#client-search', 'Экспорт 🦊'); click('#library-more'); click('#library-export')
        check(js('return !document.querySelector("#export-content") && !document.querySelector("dialog").textContent.includes("synthetic-export-secret")'), 'export dialog lists profiles without disclosing their credentials before reveal')
        click('#export-reveal')
        wait_for('return !!document.querySelector("#export-content")')
        bundle = json.loads(js('return document.querySelector("#export-content").textContent'))
        check(bundle['profiles'][0]['config'] == first and bundle['profiles'][0]['name'] == 'Экспорт 🦊', 'single-profile export preserves Unicode names and unknown configuration fields')
        select('#export-format', 'configurations')
        check(js('return !document.querySelector("#export-content")'), 'changing the export format hides the previous secret preview')
        click('#export-reveal'); wait_for('return !!document.querySelector("#export-content")')
        check(json.loads(js('return document.querySelector("#export-content").textContent')) == first, 'raw single export is exactly the original core configuration')
        select('#export-format', 'profiles')
        click('#export-save'); file_dialog('Save export')
        wait_for('return !document.querySelector("#export-save").disabled')
        check(js('return !document.querySelector("#export-status")'), 'cancelling the native save dialog does not claim a saved file')
        with tempfile.TemporaryDirectory(prefix='thronium-export-') as directory:
            path = pathlib.Path(directory) / 'profiles.json'
            click('#export-save'); file_dialog('Save export', path)
            wait_for('return document.querySelector("#export-status")?.textContent.includes("File saved")')
            check(json.loads(path.read_text()) == bundle, 'native file chooser saves the complete export to the chosen file')
        click('.modal-head .icon-button'); fill('#client-search', ''); click('#bulk-select-toggle'); click('#bulk-select-visible'); click('#bulk-export')
        click('#export-reveal'); wait_for('return !!document.querySelector("#export-content")')
        batch_text = js('return document.querySelector("#export-content").textContent')
        batch = json.loads(batch_text)
        check(len(batch['profiles']) == 2 and batch['profiles'][1]['kind'] == 'xray-config' and batch['profiles'][1]['config'] == second, 'bulk export retains explicit opaque Xray type and every selected profile')
        check(all('id' not in p and 'groupId' not in p for p in batch['profiles']), 'portable export excludes local IDs and source group membership')
        # Preserve an existing text clipboard. Non-text clipboard contents are left untouched.
        if original_clipboard is not None:
            click('#export-copy'); wait_for('return document.querySelector("#export-status")?.textContent.includes("Copied")')
            check(json.loads(command('readClipboard')) == batch, 'copy writes the selected export to the actual system clipboard')
        click('.modal-head .icon-button'); click('#bulk-select-toggle'); click('.add-connection'); click('#add-choice-link')
        if original_clipboard is not None:
            click('#import-clipboard'); wait_for('return document.querySelector("#import-source").value.includes("thronium-profiles")')
            check(js('return document.querySelector("#import-source").value') == batch_text, 'paste-from-clipboard reads the actual exported profile collection')
        else: fill('#import-source', batch_text)
        select('#import-group', target); click('#import-review')
        check(js('return document.querySelectorAll(".import-select").length===2 && !document.querySelector(".import-acknowledge")'), 'exported collection is recognized by the existing import preview without lossy conversion')
        click('#import-save'); wait_for('return !document.querySelector("dialog")')
        profiles = [p for p in command('snapshot')['profiles'] if p['groupId'] == target]
        imported = [command('profile', {'id': p['id']}) for p in profiles]
        check([p['config'] for p in imported] == [first, second] and [p['kind'] for p in imported] == ['sing-box-outbound', 'xray-config'] and all(p['id'] not in ids for p in imported), 'export and reimport preserve all settings and assign new IDs in the chosen group')
        select('.group-strip select', source); fill('#client-search', 'Экспорт 🦊'); click('#library-more'); click('#library-export')
        command('preferences', {**command('snapshot')['preferences'], 'language': 'ru', 'theme': 'light'})
        wait_for('return document.documentElement.lang==="ru"')
        h['request']('POST', h['base'] + '/window/rect', {'width': 390, 'height': 844})
        check(js('return document.querySelector("#modal-title").textContent.includes("Экспорт") && document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth && document.querySelector(".modal-footer").getBoundingClientRect().bottom<=innerHeight'), 'export actions fit the narrow native window in Russian')
        screenshot('export-narrow-ru'); click('.modal-head .icon-button')
    finally:
        if original_clipboard is not None: command('writeClipboard', {'text': original_clipboard})
        command('deleteGroup', {'id': source, 'deleteProfiles': True}); command('deleteGroup', {'id': target, 'deleteProfiles': True})
        command('preferences', initial['preferences'])
        if initial['selected']: command('select', {'id': initial['selected']})
        h['request']('POST', h['base'] + '/window/rect', {'width': 1280, 'height': 860})
