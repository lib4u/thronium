"""Registration, cancellation, settings and WG editor in the real native window."""
import base64
import contextlib
import datetime
import json
import os
from pathlib import Path
import socket
import time
import urllib.request
import uuid


def run(h):
    command, click, fill, select, wait_for, js, check, screenshot = (h[k] for k in ('command', 'click', 'fill', 'select', 'wait_for', 'js', 'check', 'screenshot'))
    fixture = json.loads(Path(os.environ['_THRONIUM_WARP_FIXTURE']).read_text())
    initial = command('snapshot'); original_settings = command('settings')
    group = command('saveGroup', {'name': 'Owned WARP generation fixtures'})['id']
    pending = set(); secrets = []; audit = {'errors': [], 'latencies': []}

    def admin(**values):
        request = urllib.request.Request(fixture['admin'], data=json.dumps(values).encode() if values else None, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=3) as response: return json.load(response)

    def poll(predicate, timeout=5):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if predicate(): return
            time.sleep(.05)
        raise AssertionError('Owned WARP fixture did not reach expected state')

    def save(section, **values):
        old = command('settings')[section]
        return command('saveSettings', {'section': section, 'previous': old, 'values': {**old, **values}})

    def rejected(name, payload, expected):
        result = json.loads(h['request']('POST', h['base'] + '/execute/async', {'script': "const done=arguments[arguments.length-1];window.__TAURI_INTERNALS__.invoke('app_command',{name:arguments[0],payload:arguments[1]}).then(value=>done(JSON.stringify({ok:true,value}))).catch(error=>done(JSON.stringify({ok:false,error})));", 'args': [name, payload]}))
        assert not result['ok'] and result['error'].get('code') == expected, str(result.get('error', 'unexpected success'))
        audit['errors'].append(expected); return True

    def token(): return str(uuid.uuid4())

    def begin(identifier):
        pending.add(identifier)
        js('''window.__warp61??={};const id=arguments[0];window.__warp61[id]={done:false};window.__TAURI_INTERNALS__.invoke('app_command',{name:'registerWarp',payload:{requestId:id,acceptTerms:true}}).then(value=>window.__warp61[id]={done:true,ok:true,value}).catch(error=>window.__warp61[id]={done:true,ok:false,error});''', identifier)

    def finish(identifier, error=None):
        wait_for('return window.__warp61?.[' + json.dumps(identifier) + ']?.done', 12)
        result = json.loads(js('return JSON.stringify(window.__warp61[arguments[0]])', identifier)); pending.discard(identifier)
        assert result['ok'] == (error is None), str(result.get('error', 'unexpected successful registration'))
        if error: assert result['error'].get('code') == error
        else: secrets.append(result['value']['privateKey'])
        return result.get('value')

    def section():
        click('.primary-nav button:last-child'); click('[data-settings-section=intercept]')
        wait_for('return !!document.querySelector("[data-warp-generator]")')
        js('document.querySelector("[data-warp-generator]").closest("details").open=true')

    def generate():
        if not js('return document.querySelector("[data-warp-terms]").checked'): click('[data-warp-terms]')
        click('[data-warp-generate]')

    def ready(): wait_for('return !document.querySelector("[data-warp-cancel]") && !document.querySelector("[data-warp-generate]").disabled', 12)

    def core_pids():
        target = Path(h['args'].application).with_name('ThroniumCore').resolve()
        found = []
        for process in Path('/proc').iterdir():
            if not process.name.isdigit(): continue
            with contextlib.suppress(OSError):
                if (process / 'exe').resolve() == target: found.append(int(process.name))
        return sorted(found)

    try:
        with socket.socket() as listener: listener.bind(('127.0.0.1', 0)); port = listener.getsockname()[1]
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark', 'connectionMode': 'local', 'inboundPort': port})
        h['request']('POST', h['base'] + '/window/rect', {'width': 1280, 'height': 900})
        wait_for('return document.documentElement.lang==="en"')
        before = len(admin()['requests']); section()
        check(js('return document.querySelector("[data-warp-generate]").disabled && !document.querySelector("[data-warp-terms]").checked'), 'registration requires an explicit terms checkbox')
        click('[data-warp-open-terms]')
        terms = Path(os.environ['_THRONIUM_WARP_TERMS_FILE']); poll(terms.exists)
        check(json.loads(terms.read_text()) == ['https://www.cloudflare.com/application/terms/'], 'terms button opens only the fixed Cloudflare URL through the owned launcher')
        check(rejected('registerWarp', {'requestId': token(), 'acceptTerms': False}, 'warp_terms_required') and rejected('registerWarp', {'requestId': token(), 'acceptTerms': True, 'url': 'https://not-allowed.invalid'}, 'warp_invalid_request') and len(admin()['requests']) == before, 'invalid registration requests never reach the HTTPS service')
        save('network', net_use_proxy=True)
        check(rejected('registerWarp', {'requestId': token(), 'acceptTerms': True}, 'warp_proxy_unavailable') and len(admin()['requests']) == before and not core_pids(), 'requested application proxy fails before key generation when disconnected')
        save('network', net_use_proxy=False)
        cancelled = token(); command('cancelWarpRegistration', {'requestId': cancelled})
        check(rejected('registerWarp', {'requestId': cancelled, 'acceptTerms': True}, 'warp_request_finished') and len(admin()['requests']) == before, 'cancellation arriving before registration prevents a late POST')

        fill('#setting-redirect_listen_port', '16443'); generate()
        wait_for('return !!document.querySelector("[data-warp-result], [data-warp-generator] [role=alert]")', 15)
        assert js('return !!document.querySelector("[data-warp-result]")'), js('return document.querySelector("[data-warp-generator] [role=alert]")?.textContent')
        check(command('settings')['intercept'] == original_settings['intercept'] and command('snapshot')['running'] is None, 'successful direct HTTPS registration leaves saved settings and connection state unchanged')
        rows = admin()['requests']; assert len(rows) == before + 1
        public = rows[-1]['body']['key']; assert len(base64.b64decode(public)) == 32
        check(set(rows[-1]['body']) == {'key', 'install_id', 'warp_enabled', 'tos', 'type', 'locale'} and rows[-1]['body']['type'] == 'Linux' and rows[-1]['userAgent'] == 'WARP for Android' and rows[-1]['path'] == '/v0a737/reg' and datetime.datetime.fromisoformat(rows[-1]['body']['tos']).utcoffset() == datetime.timedelta(), 'HTTPS request matches Qt registration endpoint, public key, OS, UTC consent time and user agent')
        check(not js('return /privateKey|private-token-canary61|private-account-canary61/.test(document.querySelector("[data-warp-result]").textContent)'), 'registration preview displays addresses and endpoint without keys or provider account tokens')
        js('document.querySelector("[data-warp-result]").scrollIntoView({block:"center"})'); screenshot('warp-preview-en-1280')
        click('[data-warp-use]'); secret = js('return document.querySelector("#setting-warp_private_key").value'); secrets.append(secret)
        check(len(base64.b64decode(secret)) == 32 and secret != public and js('return document.querySelector("#setting-warp_private_key").type==="password" && document.querySelector("#setting-redirect_listen_port").value==="16443" && !document.querySelector("#setting-enable_warp").checked') and command('settings')['intercept'] == original_settings['intercept'], 'Use fills the five WARP draft fields, masks private key, preserves another edit and keeps WARP disabled')
        click('#settings-save'); wait_for('return document.querySelector("#settings-save").disabled && !!document.querySelector("[data-setting]:enabled")')
        saved = command('settings')['intercept']
        check(saved['warp_private_key'] == secret and saved['warp_public_key'] == fixture['peerPublicKey'] and saved['warp_ifc_addrs'] == ['172.16.0.2/32', '2606:4700:110:8c5a::2/128'] and saved['warp_reserved'] == ['0', '128', '255'] and saved['redirect_listen_port'] == 16443 and not saved['enable_warp'], 'explicit Save persists normalized WARP keys, address prefixes and reserved bytes without enabling the tunnel')

        for mode, expected in [('http-error', 'warp_registration_rejected'), ('malformed', 'warp_invalid_response'), ('oversize', 'warp_invalid_response'), ('chunked', 'warp_invalid_response'), ('redirect', 'warp_registration_rejected')]:
            admin(mode=mode); count = len(admin()['requests']); identifier = token()
            check(rejected('registerWarp', {'requestId': identifier, 'acceptTerms': True}, expected) and len(admin()['requests']) == count + 1 and command('settings')['intercept'] == saved, mode + ' is bounded, sanitized, does not retry or overwrite saved configuration')
        admin(mode='hold'); identifier = token(); begin(identifier); poll(lambda: admin()['active'] == 1)
        started = time.monotonic(); assert command('snapshot')['running'] is None; elapsed = time.monotonic() - started; audit['latencies'].append({'snapshotWhileHeld': elapsed})
        check(elapsed < 2 and rejected('registerWarp', {'requestId': token(), 'acceptTerms': True}, 'warp_busy'), 'held HTTPS response leaves snapshots responsive and rejects duplicate active registration')
        command('cancelWarpRegistration', {'requestId': token()}); assert not js('return window.__warp61[arguments[0]].done', identifier)
        command('cancelWarpRegistration', {'requestId': identifier}); finish(identifier, 'warp_cancelled'); admin(release=True); poll(lambda: admin()['active'] == 0)
        check(rejected('registerWarp', {'requestId': identifier, 'acceptTerms': True}, 'warp_request_finished'), 'only matching cancellation discards the request and prevents replay')
        save('network', network_timeout=5); admin(mode='hold'); identifier = token(); begin(identifier); poll(lambda: admin()['active'] == 1)
        started = time.monotonic(); finish(identifier, 'warp_timeout'); elapsed = time.monotonic() - started
        admin(release=True); poll(lambda: admin()['active'] == 0)
        check(3 < elapsed < 8 and command('settings')['intercept'] == saved, 'application network timeout ends registration without changing saved WARP settings')

        admin(mode='hold'); generate(); poll(lambda: admin()['active'] == 1)
        click('[data-warp-cancel]'); ready(); admin(release=True); poll(lambda: admin()['active'] == 0)
        check(not js('return !!document.querySelector("[data-warp-result]")') and command('settings')['intercept'] == saved, 'Cancel button suppresses a late successful response and preserves the form')
        admin(mode='hold'); generate(); poll(lambda: admin()['active'] == 1)
        click('[data-settings-section=appearance]'); admin(release=True); poll(lambda: admin()['active'] == 0); section()
        check(not js('return !!document.querySelector("[data-warp-result]")'), 'leaving the generator cancels ownership and never fills a newly mounted form')

        proxy = command('saveProfile', {'name': 'Owned SOCKS hop', 'groupId': group, 'kind': 'sing-box-outbound', 'config': {'type': 'socks', 'server': '127.0.0.1', 'server_port': fixture['socksPort']}})['id']
        command('connect', {'id': proxy}); pids = core_pids(); assert pids
        save('network', net_use_proxy=True); admin(mode='ok'); before = len(admin()['proxyConnections'])
        identifier = token(); begin(identifier); value = finish(identifier)
        check(len(admin()['proxyConnections']) == before + 1 and command('snapshot')['running'] == proxy and core_pids() == pids, 'registration uses the active application proxy and preserves the running Core process')
        admin(mode='hold'); identifier = token(); begin(identifier); poll(lambda: admin()['active'] == 1)
        started = time.monotonic(); command('disconnect'); elapsed = time.monotonic() - started; audit['latencies'].append({'disconnectWhileHeld': elapsed})
        command('cancelWarpRegistration', {'requestId': identifier})
        wait_for('return window.__warp61?.[' + json.dumps(identifier) + ']?.done')
        result = json.loads(js('return JSON.stringify(window.__warp61[arguments[0]])', identifier)); pending.discard(identifier)
        check(elapsed < 3 and not result['ok'] and result['error'].get('code') in ('warp_cancelled', 'warp_request_failed') and command('snapshot')['running'] is None, 'Disconnect remains responsive while registration waits through the active proxy')
        admin(release=True); poll(lambda: admin()['active'] == 0); save('network', net_use_proxy=False); admin(mode='ok')

        profile = command('saveProfile', {'name': 'WARP editable profile', 'groupId': group, 'kind': 'sing-box-outbound', 'config': {'type': 'wireguard', 'private_key': secret, 'address': ['10.20.0.2/32'], 'mtu': 1420, 'workers': 2, 'peers': [{'address': '127.0.0.1', 'port': 2408, 'public_key': fixture['peerPublicKey'], 'allowed_ips': ['0.0.0.0/0']}]}})['id']
        original_profile = command('profile', {'id': profile})
        click('.primary-nav button:first-child'); select('.group-strip select', 'all'); fill('#client-search', '')
        click('[data-profile-menu="' + profile + '"]'); click('#menu-edit-profile'); wait_for('return document.activeElement.id==="profile-name"')
        fill('#profile-name', 'Generated WARP profile'); click('[data-profile-tab=peers]'); generate()
        wait_for('return !!document.querySelector("[data-warp-result], [data-warp-generator] [role=alert]")', 15)
        assert js('return !!document.querySelector("[data-warp-result]")'), js('return document.querySelector("[data-warp-generator] [role=alert]")?.textContent')
        check(command('profile', {'id': profile}) == original_profile, 'WireGuard editor registration keeps the saved profile intact until Save')
        h['request']('POST', h['base'] + '/window/rect', {'width': 390, 'height': 900})
        js('document.querySelector("[data-warp-result]").scrollIntoView({block:"center"})')
        check(js('return document.documentElement.scrollWidth<=innerWidth+1 && document.querySelector("#main-modal").scrollWidth<=document.querySelector("#main-modal").clientWidth+1'), 'WARP preview fits the narrow WireGuard editor')
        screenshot('warp-editor-en-390')
        h['request']('POST', h['base'] + '/window/rect', {'width': 1280, 'height': 900})
        click('[data-warp-use]'); click('[data-profile-tab=json]')
        edited = json.loads(js('return document.querySelector("#profile-json").value')); secrets.append(edited['private_key'])
        check(edited['workers'] == 2 and edited['mtu'] == 1280 and edited['address'] == saved['warp_ifc_addrs'] and len(edited['peers']) == 1 and edited['peers'][0]['persistent_keepalive_interval'] == 10 and edited['peers'][0]['reserved'] == [0, 128, 255] and edited['peers'][0]['allowed_ips'] == ['0.0.0.0/0', '::/0'] and edited['private_key'] != secret, 'WireGuard editor receives a fresh key and complete WARP peer while preserving unrelated profile fields')
        command('checkProfile', {**original_profile, 'name': 'Generated WARP profile', 'config': edited})
        check(True, 'actual adjacent Core accepts the generated WireGuard configuration')
        click('button[form=profile-editor]'); wait_for('return !document.querySelector("dialog[open]")')
        check(command('profile', {'id': profile})['config'] == edited and command('profile', {'id': profile})['name'] == 'Generated WARP profile', 'native profile Save persists the reviewed WARP configuration and edited name')

        h['request']('POST', h['base'] + '/refresh', {}); wait_for('return !!document.querySelector(".add-connection")')
        check(command('settings')['intercept'] == saved and command('profile', {'id': profile})['config'] == edited, 'saved WARP settings and WireGuard profile survive a webview restart')
        command('preferences', {**command('snapshot')['preferences'], 'language': 'ru'}); wait_for('return document.documentElement.lang==="ru"'); section(); admin(mode='http-error'); generate(); ready()
        check(js('return document.querySelector("[data-warp-generator] [role=alert]").textContent.includes("Cloudflare") && !document.querySelector("[data-warp-generator] [role=alert]").textContent.includes("warp_")'), 'registration service rejection is translated in the Russian UI')
        for width in [1280, 390]:
            h['request']('POST', h['base'] + '/window/rect', {'width': width, 'height': 900})
            js('document.querySelector("[data-warp-generator]").scrollIntoView({block:"center"})')
            check(js('return document.documentElement.scrollWidth<=innerWidth+1'), 'WARP settings fit Russian ' + str(width) + 'px layout'); screenshot('warp-settings-ru-' + str(width))
        rows = admin()['requests']
        check(all(not any(secret in json.dumps(row) for secret in secrets) for row in rows), 'no generated private key is transmitted in any registration request')
        logs = command('getLogs'); assert logs['entries'], 'Real connection log must be nonempty'
        check(not any(value in json.dumps(logs) for value in secrets + ['private-response-canary61', 'private-token-canary61', 'private-account-canary61']), 'nonempty application log contains neither generated private keys nor provider response canaries')
        audit.update({'requestCount': len(rows), 'proxyCount': len(admin()['proxyConnections']), 'logEntriesChecked': len(logs['entries']), 'externalRegistration': False})
    finally:
        with contextlib.suppress(Exception): audit['lastUIError'] = js('return document.querySelector("[data-warp-generator] [role=alert]")?.textContent')
        for identifier in pending:
            with contextlib.suppress(Exception): command('cancelWarpRegistration', {'requestId': identifier})
        admin(release=True, mode='ok')
        with contextlib.suppress(Exception): command('disconnect')
        with contextlib.suppress(Exception): command('deleteGroup', {'id': group, 'deleteProfiles': True})
        for section_id in ('network', 'intercept'):
            with contextlib.suppress(Exception):
                old = command('settings')[section_id]; command('saveSettings', {'section': section_id, 'previous': old, 'values': original_settings[section_id]})
        (h['artifacts'] / 'warp-audit.json').write_text(json.dumps(audit, indent=2) + '\n')
