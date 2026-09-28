"""Real form / JSON conflicts and reload. Uses only the runner's isolated library."""
import json
import time
from pathlib import Path


def run(h):
    command, click, fill, wait, js, check = (h[k] for k in ('command', 'click', 'fill', 'wait_for', 'js', 'check'))
    initial = command('snapshot')
    command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark'})
    config = {'protocol': 'vless', 'settings': {'vnext': [{'address': 'server.example', 'port': 443, 'users': [{'id': '00000000-0000-4000-8000-000000000038', 'encryption': 'none'}]}]}, 'streamSettings': {'network': 'tcp', 'security': 'none'}, 'future': {'keep': True}}
    pid = command('saveProfile', {'name': 'Revision fixture', 'groupId': 'personal', 'kind': 'xray-outbound', 'config': config})['id']

    def current():
        return command('profile', {'id': pid})

    def open_editor(menu):
        css = '[data-profile-menu="' + pid + '"]'
        wait('return !!document.querySelector(' + json.dumps(css) + ')')
        js('document.querySelector(arguments[0]).scrollIntoView({block:"center",behavior:"instant"})', css)
        time.sleep(.15)
        click(css)
        click(menu)

    def change_saved(port):
        saved = current()
        saved['config']['settings']['vnext'][0]['port'] = port
        command('saveProfile', saved)

    rare_id = None
    extra = []

    def open_profile(profile_id, tab):
        css = '[data-profile-menu="' + profile_id + '"]'
        wait('return !!document.querySelector(' + json.dumps(css) + ')')
        js('document.querySelector(arguments[0]).scrollIntoView({block:"center",behavior:"instant"})', css)
        time.sleep(.15)
        click(css)
        click('#menu-edit-profile')
        click('[data-profile-tab=' + tab + ']')

    try:
        wait('return document.documentElement.lang==="en"')
        check(next(p for p in command('snapshot')['profiles'] if p['id'] == pid)['address'] == 'server.example', 'Xray address reaches the real snapshot')
        open_editor('#menu-edit-profile')
        fill('#profile-name', 'Unsaved form')
        change_saved(8443)
        click('button[form="profile-editor"]')
        wait('return !!document.querySelector("#profile-reload")')
        check(js('return document.querySelector("#profile-name").value') == 'Unsaved form' and current()['config']['settings']['vnext'][0]['port'] == 8443, 'stale form retains draft and cannot overwrite the fresh port')
        ru_error = json.loads((Path(__file__).resolve().parents[1] / 'locales/ru/errors.json').read_text())['profile_configuration_changed']
        command('preferences', {**initial['preferences'], 'language': 'ru', 'theme': 'light'})
        wait('return document.documentElement.lang === "ru" && document.querySelector("#profile-editor [role=alert]").textContent.trim() === ' + json.dumps(ru_error))
        check(js('return document.querySelector("#profile-name").value') == 'Unsaved form', 'open conflict and form switch to Russian/light without resetting the draft')
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark'})
        wait('return document.documentElement.lang === "en"')
        click('#profile-reload')
        click('[data-confirm-accept]')
        wait('return !document.querySelector("#profile-reload")')
        check(js('return document.querySelector("#profile-name").value') == 'Revision fixture', 'explicit reload replaces the whole form baseline')
        fill('#profile-name', 'Fresh form')
        command('favorite', {'id': pid})
        click('button[form="profile-editor"]')
        wait('return !document.querySelector("dialog[open]")')
        check(current()['name'] == 'Fresh form' and current()['favorite'], 'favorite changes do not conflict or get lost on save')
        open_editor('#export-one')
        wait('return !!document.querySelector("#configuration-json")')
        unsaved = current()['config']
        unsaved['future']['draft'] = True
        fill('#configuration-json', json.dumps(unsaved))
        change_saved(9443)
        click('#configuration-save')
        wait('return !!document.querySelector("#configuration-reload")')
        check(json.loads(js('return document.querySelector("#configuration-json").value')) == unsaved and current()['config']['settings']['vnext'][0]['port'] == 9443, 'JSON conflict preserves unsaved text and fresh saved configuration')
        click('#configuration-reload')
        click('[data-confirm-accept]')
        wait('return !document.querySelector("#configuration-reload")')
        check(json.loads(js('return document.querySelector("#configuration-json").value')) == current()['config'], 'JSON reload installs the latest configuration and revision')
        unsaved = current()['config']
        unsaved['future']['coreEdit'] = True
        fill('#configuration-json', json.dumps(unsaved))
        h['select']('#profile-vless-core', 'xray')
        wait('return !!document.querySelector("#configuration-status")')
        check(json.loads(js('return document.querySelector("#configuration-json").value')) == unsaved, 'core-only edit preserves the unsaved JSON buffer')
        click('#configuration-save')
        wait('return !document.querySelector("dialog[open]")')
        check(current()['config'] == unsaved and current()['vlessCore'] == 'xray', 'JSON save after a core change uses the returned revision')
        # Rare fields: OpenVPN TLS extras, LZO compression and endpoint UDP NAT go through the form.
        rare_id = command('saveProfile', {'name': 'Rare fields fixture', 'groupId': 'personal', 'kind': 'sing-box-outbound', 'config': {'type': 'openvpn-client', 'server': '127.0.0.1', 'server_port': 1194, 'mode': 'tls', 'network': 'udp', 'username': 'test', 'password': 'test-password', 'tls': {'remote_certificate_tls': 'server', 'peer_fingerprint': ['ab' * 32]}, 'future': {'keep': True}}})['id']

        def open_rare(tab):
            css = '[data-profile-menu="' + rare_id + '"]'
            wait('return !!document.querySelector(' + json.dumps(css) + ')')
            js('document.querySelector(arguments[0]).scrollIntoView({block:"center",behavior:"instant"})', css)
            time.sleep(.15)
            click(css)
            click('#menu-edit-profile')
            click('[data-profile-tab=' + tab + ']')

        open_rare('tls')
        wait('return !!document.querySelector("#field-tls-crl_path")')
        fill('#field-tls-crl_path', '/etc/openvpn/crl.pem')
        h['select']('#field-tls-certificate_profile', 'preferred')
        h['select']('#field-tls-version_min', '1.2')
        click('[data-profile-tab=vpn]')
        wait('return !!document.querySelector("#field-compression_lzo")')
        h['select']('#field-compression_lzo', 'adaptive')
        h['select']('#field-udp_mapping', 'address_dependent')
        fill('#field-udp_nat_max', '1024')
        click('[data-profile-tab=json]')
        wait('return !!document.querySelector("#profile-json")')
        draft = json.loads(js('return document.querySelector("#profile-json").value'))
        check(draft['tls']['crl_path'] == '/etc/openvpn/crl.pem' and draft['tls']['certificate_profile'] == 'preferred' and draft['tls']['version_min'] == '1.2' and draft['compression_lzo'] == 'adaptive' and draft['udp_mapping'] == 'address_dependent' and draft['udp_nat_max'] == 1024 and draft['future'] == {'keep': True} and draft['tls']['peer_fingerprint'] == ['ab' * 32], 'rare OpenVPN fields reach the JSON draft under their core keys and types without touching unknown data')
        click('button[form="profile-editor"]')
        wait('return !document.querySelector("dialog[open]")')
        saved = command('profile', {'id': rare_id})['config']
        check(saved['tls']['crl_path'] == '/etc/openvpn/crl.pem' and saved['compression_lzo'] == 'adaptive' and saved['udp_mapping'] == 'address_dependent' and saved['udp_nat_max'] == 1024, 'the saved profile keeps the rare fields')
        # Hysteria v1 windows, Qt option lists and the Tailscale node's DNS.
        hysteria_id = command('saveProfile', {'name': 'Hysteria v1 fixture', 'groupId': 'personal', 'kind': 'sing-box-outbound',
                                              'config': {'type': 'hysteria', 'server': '192.0.2.10', 'server_port': 443, 'auth_str': 'fixture',
                                                         'tls': {'enabled': True, 'server_name': 'example.test'}}})['id']
        extra.append(hysteria_id)
        open_profile(hysteria_id, 'main')
        wait('return !!document.querySelector("#field-recv_window_conn")')
        fill('#field-recv_window_conn', '65536')
        fill('#field-recv_window', '131072')
        h['select']('#field-disable_mtu_discovery', 'true')
        click('[data-profile-tab=tls]')
        wait('return !!document.querySelector("#field-tls-utls-fingerprint")')
        fingerprints = js('return [...document.querySelectorAll("#field-tls-utls-fingerprint option")].map(o=>o.value)')
        check(fingerprints == ['', 'chrome', 'firefox', 'edge', 'safari', '360', 'qq', 'ios', 'android', 'random', 'randomized'],
              'uTLS fingerprints are offered as the list Qt offers, not free text')
        h['select']('#field-tls-utls-fingerprint', 'safari')
        click('button[form="profile-editor"]')
        wait('return !document.querySelector("dialog[open]")')
        saved_hysteria = command('profile', {'id': hysteria_id})['config']
        check(saved_hysteria['recv_window_conn'] == 65536 and saved_hysteria['recv_window'] == 131072
              and saved_hysteria['disable_mtu_discovery'] is True and saved_hysteria['tls']['utls']['fingerprint'] == 'safari',
              'the Hysteria v1 window settings Qt still edits are saved from the form')

        ss_id = command('saveProfile', {'name': 'Cipher fixture', 'groupId': 'personal', 'kind': 'sing-box-outbound',
                                        'config': {'type': 'shadowsocks', 'server': '192.0.2.11', 'server_port': 8388,
                                                   'method': 'aes-256-gcm', 'password': 'fixture'}})['id']
        extra.append(ss_id)
        open_profile(ss_id, 'main')
        wait('return !!document.querySelector("#field-method")')
        ciphers = [v for v in js('return [...document.querySelectorAll("#field-method option")].map(o=>o.value)') if v]
        check(len(ciphers) == 18 and ciphers[:4] == ['2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305', 'none']
              and 'rc4-md5' in ciphers and 'aes-192-ctr' in ciphers,
              'every cipher Qt lists for Shadowsocks can be chosen')
        click('#main-modal > .modal-head > button')
        if js('return !!document.querySelector("[data-confirm-accept]")'):
            click('[data-confirm-accept]')
        wait('return !document.querySelector("dialog[open]")')

        node_id = command('saveProfile', {'name': 'Tailnet fixture', 'groupId': 'personal', 'kind': 'sing-box-outbound',
                                          'config': {'type': 'tailscale', 'auth_key': 'tskey-fixture', 'hostname': 'thronium'}})['id']
        extra.append(node_id)
        open_profile(node_id, 'vpn-policy')
        wait('return !!document.querySelector("#vpn-policy-enable")')
        check(js('return [...document.querySelectorAll("[data-profile-tab]")].some(t=>t.textContent.includes("Tailscale"))'),
              'a Tailscale node offers its own DNS tab, not the VPN routes one')
        click('#vpn-policy-enable')
        wait('return !!document.querySelector("#vpn-policy-useTunnelDns")')
        check(js('return document.querySelectorAll("#vpn-policy-fields input[type=checkbox]").length===1'),
              'the node offers only Qt global DNS switch')
        h['screenshot']('profile-tailscale-dns-en')
        click('button[form="profile-editor"]')
        wait('return !document.querySelector("dialog[open]")')
        check(command('profile', {'id': node_id})['vpnPolicy'] == {'onlyAdvertisedRoutes': False, 'useTunnelDns': True, 'blockOutsideDns': False},
              'the node saves Qt globalDNS as its tunnel DNS policy')

        command('preferences', {**initial['preferences'], 'language': 'ru', 'theme': 'light'})
        wait('return document.documentElement.lang==="ru"')
        h['request']('POST', h['base'] + '/window/rect', {'width': 390, 'height': 844})
        wait('return innerWidth===390')
        open_rare('tls')
        wait('return document.querySelector("#field-tls-crl_path")?.value==="/etc/openvpn/crl.pem"')
        check(js('return document.querySelector("#field-tls-certificate_profile").value==="preferred" && document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth'), 'the reopened TLS tab shows the saved extras and fits the narrow Russian window')
        h['screenshot']('profile-tls-extras-narrow-ru')
        click('#main-modal > .modal-head > button')
        if js('return !!document.querySelector("[data-confirm-accept]")'):
            click('[data-confirm-accept]')
        wait('return !document.querySelector("dialog[open]")')
    finally:
        # The outer native runner always tears down its private application and directory.
        if rare_id:
            command('delete', {'id': rare_id})
        for profile_id in extra:
            command('delete', {'id': profile_id})
        h['request']('POST', h['base'] + '/window/rect', {'width': 1280, 'height': 860})
        command('preferences', initial['preferences'])
