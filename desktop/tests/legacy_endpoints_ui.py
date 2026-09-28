"""Qt auxiliary endpoints and custom inbound tags through the native import review.
Uses the engine's Qt golden archives; the real Core validates the imported preset
with its OpenVPN endpoint (CheckConfig only, no tunnel is dialled)."""
import contextlib
import hashlib
import json
from pathlib import Path

from native_dialogs import file_dialog

DESKTOP = Path(__file__).resolve().parents[1]
SOURCE = DESKTOP / 'engine/src/legacy_backup/routes/fixtures'


def run(h):
    command, click, wait_for, js, check, screenshot = (
        h[k] for k in ('command', 'click', 'wait_for', 'js', 'check', 'screenshot')
    )
    manifest = json.loads((SOURCE / 'manifest.json').read_text())
    for name, entry in manifest['archives'].items():
        assert hashlib.sha256((SOURCE / (name + '.thrbackup')).read_bytes()).hexdigest() == entry['sha256'], name
    initial = command('snapshot')
    geometry = h['request']('GET', h['base'] + '/window/rect')

    def settings():
        click('.primary-nav button:nth-child(5)')
        wait_for('return !!document.querySelector("[data-settings-section=backup]")')
        click('[data-settings-section=backup]')
        wait_for('return !!document.querySelector("#backup-open")')

    def previews():
        return js('return window.__legacyEndpoints.previews')

    def reviewed(count):
        wait_for('return window.__legacyEndpoints.previews.length>' + str(count))
        wait_for('return !!document.querySelector("#backup-confirm") && !document.querySelector("#backup-refresh").disabled')
        return previews()[-1]

    def open_file(name):
        count = len(previews())
        click('#backup-open')
        ru = command('snapshot')['preferences']['language'] == 'ru'
        file_dialog('Открыть резервную копию' if ru else 'Open backup', SOURCE / (name + '.thrbackup'), opening=True)
        return reviewed(count)

    def scope(selector):
        count = len(previews())
        click(selector)
        return reviewed(count)

    def close():
        if js('return !!document.querySelector("dialog[open]")'):
            click('#main-modal > .modal-head > button')
            wait_for('return !document.querySelector("dialog[open]")')

    def apply():
        click('#backup-acknowledge')
        click('#backup-confirm')
        wait_for('return !document.querySelector("dialog[open]") && !!document.querySelector("#backup-notice")')

    def undo():
        click('#backup-undo')
        wait_for('return !!document.querySelector("#backup-confirm")')
        apply()

    def library():
        path = root / ('library-' + str(len(list(root.iterdir()))) + '.json')
        click('#backup-save')
        ru = command('snapshot')['preferences']['language'] == 'ru'
        file_dialog('Сохранить резервную копию' if ru else 'Save backup', path)
        wait_for('return !document.querySelector("#backup-save").disabled')
        return json.loads(path.read_text())['library']

    def codes(review):
        return {issue['code'] for issue in review['legacy']['issues']}

    def reject(name, payload, code):
        try:
            command(name, payload)
        except RuntimeError as error:
            assert code in str(error), str(error)
        else:
            raise AssertionError(f'{name} accepted forbidden action')

    root = h['artifacts'] / 'legacy-endpoints'
    root.mkdir(parents=True, exist_ok=True)
    try:
        command('disconnect')
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark'})
        wait_for('return document.documentElement.lang==="en"')
        settings()
        js('''const original=window.fetch;window.__legacyEndpoints={original,previews:[]};window.fetch=function(input,options){let name;try{name=JSON.parse(options?.body||'{}').name;}catch{}const result=original.apply(this,arguments);if(['readBackup','legacyBackupScopes','refreshBackupPreview','chooseLegacyResource'].includes(name))result.then(r=>r.clone().json()).then(v=>{const p=v?.preview||v;if(p?.token)window.__legacyEndpoints.previews.push(p)}).catch(()=>{});return result;};''')
        before = library()
        open_file('routes-endpoints')
        review = scope('#legacy-scope-routes')
        check(review['legacy']['canApply'] and review['legacy']['routeCount'] == 2
              and {'legacy_route_endpoint_rule_added', 'legacy_route_endpoint_tunnel_dns', 'legacy_vpn_policy_preserved'} <= codes(review)
              and 'synthetic-password' not in json.dumps(review),
              'an archive with OpenVPN/OpenConnect endpoints is importable with explicit notes and no credentials in the review')
        h['request']('POST', h['base'] + '/window/rect', {'width': 390, 'height': 844})
        check(js('return document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth+1'),
              'the endpoint notes fit the 390-pixel English review')
        screenshot('legacy-endpoints-review-en-390')
        command('preferences', {**command('snapshot')['preferences'], 'language': 'ru'})
        wait_for('return document.documentElement.lang==="ru"')
        click('#backup-refresh')
        wait_for('return !document.querySelector("#backup-refresh").disabled')
        check('ворота' in js('return document.querySelector("#legacy-import-review").textContent'), 'Russian review explains the appended gate rule')
        screenshot('legacy-endpoints-review-ru-390')
        command('preferences', {**command('snapshot')['preferences'], 'language': 'en'})
        wait_for('return document.documentElement.lang==="en"')
        h['request']('POST', h['base'] + '/window/rect', geometry)
        click('#backup-refresh')
        wait_for('return !document.querySelector("#backup-refresh").disabled')
        apply()
        after = library()
        presets = after['routing']['profiles'][len(before['routing']['profiles']):]
        by_name = {p['name']: p for p in after['profiles'] if p['name'] in ('Fixture OpenVPN', 'Fixture OpenConnect')}
        structured = next(p for p in presets if p['name'] == 'Endpoints structured')
        raw = next(p for p in presets if p['name'] == 'Endpoints raw verbatim')
        ovpn, oc = by_name['Fixture OpenVPN']['id'], by_name['Fixture OpenConnect']['id']
        gate = lambda pid: {'preferred_by': ['profile:' + pid], 'action': 'route', 'outbound': 'profile:' + pid}
        check(structured['legacyConstraints']['version'] == 6 and structured['legacyConstraints']['endpoints'] == [ovpn, oc]
              and structured['rules'][2]['config'] == gate(ovpn) and structured['rules'][4]['config'] == gate(oc)
              and raw['rules'][-1]['config'] == gate(ovpn) and raw['legacyConstraints']['rawVerbatim'] is True,
              'imported presets carry the positioned and appended gates as profile references and declare their endpoints')
        check(any(s['type'] == 'openvpn' and s['endpoint'] == 'profile:' + ovpn for s in structured['dns']['servers'])
              and structured['dns']['rules'][0]['preferred_by'] == ['dns-vpn-1']
              and all(s['type'] != 'openconnect' for s in structured['dns']['servers']),
              'tunnel DNS follows the saved use_tunnel_dns flag of each endpoint')
        try:
            command('checkRouting', structured)
        except RuntimeError:
            # The boundary hides core details; print the app log for the stand.
            for entry in command('getLogs', {'source': 'app'})['entries'][-8:]:
                print('APP LOG', entry.get('level'), entry.get('text'))
            raise
        check(True, 'the real Core accepts the preset with its OpenVPN endpoint, gate and tunnel DNS')
        # OpenVPN is also a hop of the fixture chain, which is reported first;
        # OpenConnect is referenced only by the preset.
        reject('deleteProfiles', {'ids': [ovpn]}, 'profile_used_in_chain')
        reject('deleteProfiles', {'ids': [oc]}, 'profile_used_in_routing')
        check(True, 'an endpoint used by an imported preset is protected from deletion')
        settings()
        undo()
        restored = library()
        check({**restored, 'version': 0} == {**before, 'version': 0}, 'undo removes the endpoint presets and profiles exactly')

        # The archive that marks inner hops of a chain endpoint: the node inside
        # the chain is addressable now, so the section applies like any other.
        open_file('routes-endpoints-blocked')
        marked = scope('#legacy-scope-routes')
        check(marked['legacy']['canApply'] and 'legacy_route_endpoint_chain_unsupported' not in codes(marked),
              'a preset that prefers nodes inside a chain endpoint is applied, not blocked: ' + json.dumps(sorted(codes(marked))))
        apply()
        marked_library = library()
        marked_presets = marked_library['routing']['profiles'][len(before['routing']['profiles']):]
        inner_preset = marked_presets[0]
        chain = next(p for p in marked_library['profiles'] if p['name'] == 'Fixture chain')
        check(inner_preset['rules'][-1]['config'] == gate(chain['id'])
              and any(s['type'] == 'openvpn' and s['endpoint'] == 'profile:' + chain['id'] for s in inner_preset['dns']['servers']),
              'the chain endpoint keeps its own gate and tunnel resolver')
        command('checkRouting', inner_preset)
        check(True, 'the real Core accepts the preset that came from the marked archive')
        settings()
        undo()
        check({**library(), 'version': 0} == {**before, 'version': 0}, 'undo removes the marked import exactly')

        open_file('routes-inbounds')
        review = scope('#legacy-scope-routes')
        check(not review['legacy']['canApply'] and 'legacy_route_inbound_requires_settings' in codes(review),
              'rules naming a custom inbound need the inbound settings from the same backup')
        review = scope('#legacy-scope-settings-inbound')
        check(review['legacy']['canApply'] and 'legacy_inbound_custom_listeners' in codes(review) and review['legacy']['requirements'] == [],
              'selecting the inbound category satisfies the dependency and names the new listener')
        apply()
        after = library()
        preset = next(p for p in after['routing']['profiles'] if p['name'] == 'Inbound tags')
        check(preset['legacyConstraints']['inboundTags'] == ['lan-socks'] and preset['rules'][2]['config']['inbound'] == ['lan-socks']
              and after['settings']['custom_inbound'][0]['tag'] == 'lan-socks',
              'the imported preset records its custom tag and the listener is stored in settings')
        command('checkRouting', preset)
        previous = command('settings')['inbound']
        command('saveSettings', {'section': 'inbound', 'previous': previous, 'values': {**previous, 'custom_inbound': []}})
        reject('checkRouting', preset, 'legacy_routing_inbound_missing')
        check(True, 'removing the listener later is reported per tag instead of a blanket inbound conflict')
        command('saveSettings', {'section': 'inbound', 'previous': command('settings')['inbound'], 'values': {**previous}})
        settings()
        undo()
        restored = library()
        check({**restored, 'version': 0} == {**before, 'version': 0}, 'undo restores settings and presets after the inbound import')

        open_file('routes-inbounds-blocked')
        blocked = scope('#legacy-scope-routes')
        check(not blocked['legacy']['canApply'] and {'legacy_route_inbound_unsupported', 'legacy_route_inbound_unknown'} <= codes(blocked),
              'Throne-injected and unknown inbound tags are refused per route')
        close()
        (root / 'endpoints-audit.json').write_text(json.dumps({'archives': list(manifest['archives'])}, indent=2) + '\n')
    finally:
        with contextlib.suppress(Exception):
            close()
            command('preferences', initial['preferences'])
            js('window.fetch=window.__legacyEndpoints.original;delete window.__legacyEndpoints')
            h['request']('POST', h['base'] + '/window/rect', geometry)
