"""Native additive userspace WG/AWG import and loss-aware exported forms.

Checks use the actual bundled core's configuration validation. No WireGuard
handshake, system interface, route, DNS or external endpoint is started.
"""
import contextlib
import copy
import hashlib
import json
import pathlib
import shutil
import tempfile
import time
import uuid
from legacy_wg_fixtures import DIRECTORY, BASIC, AWG, SECRETS, normalized
from native_dialogs import file_dialog


def run(h):
    command, click, fill, select, wait_for, js, check, screenshot = (h[key] for key in ('command', 'click', 'fill', 'select', 'wait_for', 'js', 'check', 'screenshot'))
    initial = command('snapshot')
    geometry = h['request']('GET', h['base'] + '/window/rect')
    manifest = json.loads((DIRECTORY / 'manifest.json').read_text())
    for name, digest in manifest['sha256'].items():
        assert hashlib.sha256((DIRECTORY / name).read_bytes()).hexdigest() == digest
    audit = None

    def settings():
        click('.primary-nav button:nth-child(5)')
        wait_for('return !!document.querySelector("[data-settings-section=backup]")')
        click('[data-settings-section=backup]')
        wait_for('return !!document.querySelector("#backup-open")')

    def open_file(path):
        count = js('return window.__legacyWgAudit.previews.length')
        click('#backup-open')
        file_dialog('Open backup', path, opening=True)
        wait_for('return !!document.querySelector("#backup-confirm") && !document.querySelector("#backup-open").disabled')
        wait_for('return window.__legacyWgAudit.previews.length > ' + str(count))
        return js('return window.__legacyWgAudit.previews.slice(-1)[0]')

    def close():
        click('#main-modal > .modal-head > button')
        wait_for('return !document.querySelector("dialog[open]")')

    def apply():
        click('#backup-acknowledge')
        click('#backup-confirm')
        wait_for('return !document.querySelector("dialog[open]") && !!document.querySelector("#backup-notice")')

    def state(label):
        path = root / (label + '-' + str(time.monotonic_ns()) + '.json')
        click('#backup-save')
        file_dialog('Save backup', path)
        wait_for('return !!document.querySelector("#backup-notice") && !document.querySelector("#backup-save").disabled')
        return json.loads(path.read_text())['library'], path

    def editor(pid):
        selector = '[data-profile-menu=' + json.dumps(pid) + ']'
        wait_for('return !!document.querySelector(' + json.dumps(selector) + ')')
        click(selector)
        click('#export-one')
        wait_for('return !!document.querySelector("#configuration-json")')

    def share_close():
        click('dialog:not(#main-modal) > .modal-head > button')
        wait_for('return document.querySelectorAll("dialog[open]").length === 1')

    def import_text(text, group):
        click('.add-connection')
        click('#add-choice-link')
        fill('#import-source', text)
        wait_for('return [...document.querySelector("#import-group").options].some(option => option.value === ' + json.dumps(group) + ')')
        select('#import-group', group)
        click('#import-review')
        wait_for('return !!document.querySelector(".import-select")')
        check(not js('return !!document.querySelector(".import-acknowledge")'), 'exported imported WG/AWG form re-enters native import without loss warnings')
        click('#import-save')
        wait_for('return !document.querySelector("dialog[open]") || !!document.querySelector(".desktop-import-modal [role=alert]")')
        error = js('return document.querySelector(".desktop-import-modal [role=alert]")?.textContent || ""')
        assert not error, error
        wait_for('return !document.querySelector("dialog[open]")')

    def private_review(preview):
        rendered = js('return document.body.textContent')
        public = json.dumps(preview, ensure_ascii=False)
        return not any(secret in rendered or secret in public for secret in SECRETS)

    with tempfile.TemporaryDirectory(prefix='thronium-legacy-wg-ui-') as temporary:
        root = pathlib.Path(temporary)
        for name in manifest['sha256']:
            shutil.copyfile(DIRECTORY / name, root / name)
        try:
            command('disconnect')
            command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark'})
            wait_for('return document.documentElement.lang === "en"')
            settings()
            js('''
const original=window.fetch;window.__legacyWgAudit={original,previews:[]};
window.fetch=function(input,options){
 let name=null;try{if(String(input).includes('/app_command'))name=JSON.parse(options?.body||'{}').name;}catch{}
 const result=original.apply(this,arguments);
 if(['readBackup','previewPreviousBackup','refreshBackupPreview'].includes(name))result.then(r=>r.clone().json()).then(v=>{const p=v?.preview||v;if(p?.token&&p?.current)window.__legacyWgAudit.previews.push(p);}).catch(()=>{});
 return result;
};
''')
            baseline, baseline_path = state('baseline')
            existing = command('saveProfile', {'name': 'Current profile retained for WG import', 'groupId': 'personal', 'kind': 'sing-box-outbound', 'config': {'type': 'direct'}})['id']
            command('select', {'id': existing})
            routing = command('routing')
            routing['profiles'][0].update(name='Current DNS retained for WG', dns={'servers': [{'type': 'local', 'tag': 'dns-before-wg'}], 'final': 'dns-before-wg'}, route={'final': 'proxy', 'default_domain_resolver': 'dns-before-wg', 'auto_detect_interface': True})
            command('saveRouting', routing)
            before, _ = state('before')
            preview = open_file(root / 'valid.thrbackup')
            check(preview['legacy']['canApply'] and preview['legacy']['inventory']['profiles'] == 2 and preview['legacy']['inventory']['groups'] == 1, 'real Qt archive accepts ordinary userspace WireGuard and AmneziaWG as additive profiles')
            check(private_review(preview) and js('return document.querySelector("#backup-confirm").disabled && !document.querySelector("#backup-acknowledge").checked'), 'WG/AWG preview hides all keys and requires explicit additive acknowledgement')
            close()
            check(state('cancelled')[0] == before, 'cancelling a WG import review leaves the complete current library unchanged')
            open_file(root / 'valid.thrbackup')
            apply()
            imported, _ = state('imported')
            added = imported['profiles'][len(before['profiles']):]
            groups = imported['groups'][len(before['groups']):]
            by_name = {p['name']: p for p in added}
            check(len(added) == 2 and len(groups) == 1 and all(p['kind'] == 'sing-box-outbound' and p['config']['type'] == 'wireguard' for p in added), 'both source endpoint profiles are stored with the supported sing-box WireGuard kind')
            check([p['name'] for p in added] == [AWG['tag'], BASIC['tag']] and all(str(uuid.UUID(p['id'])) == p['id'] for p in added + groups) and all(p['groupId'] == groups[0]['id'] for p in added), 'WG/AWG names, source ordering and remapped group UUID survive the import')
            basic = by_name[BASIC['tag']]
            awg = by_name[AWG['tag']]
            check(basic['config'] == normalized(BASIC), 'legacy WG maps worker_count, expands bare IPv4/IPv6 addresses and materializes source MTU/system/AllowedIPs defaults without dropping peer fields')
            check(awg['config'] == normalized(AWG), 'legacy AWG preserves every 3.x padding, header, timing, range, cookie and peer field exactly')
            unchanged = copy.deepcopy(imported)
            unchanged['profiles'] = unchanged['profiles'][:len(before['profiles'])]
            unchanged['groups'] = unchanged['groups'][:len(before['groups'])]
            check(unchanged == before and command('snapshot')['running'] is None, 'WG/AWG addition preserves current client DNS, routes, preferences and selected profile without starting a connection')
            click('.primary-nav button:nth-child(1)')
            for profile in (basic, awg):
                editor(profile['id'])
                check(json.loads(js('return document.querySelector("#configuration-json").value')) == profile['config'], 'native JSON editor displays the complete converted configuration for ' + profile['name'])
                click('#configuration-check')
                wait_for('return !!document.querySelector("#configuration-status") && !document.querySelector("#configuration-check").disabled', 25)
                check(not js('return !!document.querySelector(".configuration-modal [role=alert]")') and command('snapshot')['running'] is None, 'actual bundled core validates imported ' + profile['name'] + ' without starting a WireGuard session')
                close()
                config = command('connectionConfiguration', {'id': profile['id'], 'active': False})
                parts = config['parts']
                check(any(any(endpoint.get('private_key') == profile['config']['private_key'] for endpoint in part['config'].get('endpoints', [])) for part in parts), 'runtime preview places imported ' + profile['name'] + ' in core endpoints with its source key intact')
            exported = command('exportProfiles', {'ids': [basic['id'], awg['id']], 'format': 'profiles', 'destination': 'preview'})['text']
            exported_json = json.loads(exported)
            check({p['name']: p['config'] for p in exported_json['profiles']} == {p['name']: p['config'] for p in added}, 'portable profile export retains all converted WG/AWG JSON fields')
            target = command('saveGroup', {'name': 'WG round-trip target', 'subscription': None})['id']
            import_text(exported, target)
            roundtrip = [command('profile', {'id': p['id']}) for p in command('snapshot')['profiles'] if p['groupId'] == target]
            check({p['name']: p['config'] for p in roundtrip} == {p['name']: p['config'] for p in added}, 'portable native reimport preserves both converted WG/AWG profiles exactly')
            editor(basic['id'])
            click('#configuration-share')
            select('#export-format', 'wireguard')
            click('#export-reveal')
            wait_for('return !!document.querySelector("dialog:not(#main-modal) [role=alert]")')
            check('reserved' in js('return document.querySelector("dialog:not(#main-modal) [role=alert]").textContent') and not js('return !!document.querySelector("#export-content")'), 'WG .conf export refuses the unrepresentable reserved bytes instead of silently losing them')
            share_close()
            close()
            editor(awg['id'])
            click('#configuration-share')
            select('#export-format', 'wireguard')
            click('#export-reveal')
            wait_for('return !!document.querySelector("#export-content")')
            conf = js('return document.querySelector("#export-content").textContent')
            check(conf.count('[Peer]') == 2 and 'H1 = 1-100' in conf and 'Endpoint = [::1]:31504' in conf and 'HeaderProtectionKey = ' + AWG['amnezia_wg']['header_protection_key'] in conf, 'AWG .conf export retains both peers, IPv6, ranges and the header protection key')
            share_close()
            close()
            import_text(conf, target)
            roundtrip = [command('profile', {'id': p['id']}) for p in command('snapshot')['profiles'] if p['groupId'] == target]
            expected_conf = normalized(AWG)
            for field in ('system', 'workers', 'udp_timeout', 'tag'):
                expected_conf.pop(field, None)
            check(any(p['config'] == expected_conf for p in roundtrip), 'AWG .conf reimport preserves all protocol and peer values represented by that file format')
            settings()
            click('#backup-undo')
            wait_for('return !!document.querySelector("#backup-confirm")')
            apply()
            check(state('undone')[0] == before, 'Previous library exactly restores the state before WG/AWG import, including current DNS and selection')
            mixed = open_file(root / 'blocked.thrbackup')
            codes = {issue['code'] for issue in mixed['legacy']['issues']}
            # Qt's "Use System Interface" is an ordinary field, so that row imports;
            # only an OS directive and a conflicting worker alias stay out.
            check({'legacy_wireguard_field_unsupported', 'legacy_wireguard_alias_conflict'}.issubset(codes) and 'legacy_wireguard_system_unsupported' not in codes and not any(issue['sourceId'] == 503 for issue in mixed['legacy']['issues']) and {issue['sourceId'] for issue in mixed['legacy']['issues'] if issue['code'] == 'legacy_profile_skipped'} == {504, 505}, 'the mixed WG batch names and leaves out only the OS directive and the conflicting worker alias')
            check(private_review(mixed), 'the mixed WG report keeps every key and directive of the source out of the window')
            for language, theme in [('en', 'dark'), ('ru', 'light')]:
                command('preferences', {**command('snapshot')['preferences'], 'language': language, 'theme': theme})
                wait_for('return document.documentElement.lang === ' + json.dumps(language))
                h['request']('POST', h['base'] + '/window/rect', {'width': 390, 'height': 844})
                check(js('return document.querySelector("dialog").scrollWidth <= document.querySelector("dialog").clientWidth + 1 && document.querySelector(".modal-footer").getBoundingClientRect().bottom <= innerHeight + 1'), language + ' WireGuard partial-import report fits 390px')
                screenshot('legacy-wireguard-partial-' + language)
            command('preferences', before['preferences'])
            wait_for('return document.documentElement.lang === "en"')
            h['request']('POST', h['base'] + '/window/rect', {'width': 1280, 'height': 860})
            apply()
            imported = {p['name']: p for p in command('snapshot')['profiles']}
            system_profile = next((p for p in imported.values() if p['name'] == 'Unsupported system WG'), None)
            check(system_profile is not None and command('profile', {'id': system_profile['id']})['config']['system'] is True, 'a Qt profile that asks for a system interface imports with that field intact')
            check('Unsupported OS directive WG' not in imported and 'Conflicting workers WG' not in imported, 'the rows named as left out never reach the library')
            settings()
            click('#backup-undo')
            wait_for('return !!document.querySelector("#backup-confirm")')
            apply()
            check(state('after-mixed')[0] == before and all(hashlib.sha256((root / name).read_bytes()).hexdigest() == digest for name, digest in manifest['sha256'].items()), 'undoing the mixed WG batch restores the library and leaves both original Qt archives unchanged')
            open_file(baseline_path)
            apply()
            check(state('final-baseline')[0] == baseline, 'test baseline is restored exactly after WG import, export and rejection checks')
            audit = {'previews': js('return window.__legacyWgAudit.previews'), 'sourceHashes': manifest['sha256'], 'expectedKinds': ['wireguard', 'amneziawg'], 'coreConfigChecks': 2, 'wireguardHandshakes': 0, 'sourceUnchanged': True}
        finally:
            with contextlib.suppress(Exception):
                if audit is None:
                    errors = js('return [...document.querySelectorAll("dialog [role=alert]")].map(node => node.textContent)')
                    for secret in SECRETS:
                        errors = [error.replace(secret, '[synthetic key redacted]') for error in errors]
                    audit = {'previews': js('return window.__legacyWgAudit?.previews || []'), 'failed': True, 'errors': errors}
                (pathlib.Path(h['args'].artifacts) / 'legacy-wireguard-review.json').write_text(json.dumps(audit, ensure_ascii=False, indent=2) + '\n')
                if js('return !!document.querySelector("dialog:not(#main-modal)[open]")'):
                    share_close()
                if js('return !!document.querySelector("dialog[open]")'):
                    close()
                command('disconnect')
                command('preferences', initial['preferences'])
                js('if(window.__legacyWgAudit){window.fetch=window.__legacyWgAudit.original;delete window.__legacyWgAudit;}')
                click('.primary-nav button:nth-child(1)')
                h['request']('POST', h['base'] + '/window/rect', geometry)
