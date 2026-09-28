"""Native chain editor, graph protection, core preview and portable import."""
import json
import socket


def run(h):
    command, click, fill, select, wait_for, js, check, screenshot = (h[k] for k in ('command', 'click', 'fill', 'select', 'wait_for', 'js', 'check', 'screenshot'))
    initial = command('snapshot')
    source = command('saveGroup', {'name': 'Chain fixtures', 'subscription': None})['id']
    target = command('saveGroup', {'name': 'Imported chain', 'subscription': None})['id']
    def add(name, kind, config):
        return command('saveProfile', {'name': name, 'groupId': source, 'kind': kind, 'config': config})['id']
    def close():
        click('.modal-head .icon-button')
        if js('return !!document.querySelector(".editor-discard")'): click('.editor-discard .button.secondary')
        wait_for('return !document.querySelector("dialog")')
    def rejected(name, payload, error):
        try: command(name, payload)
        except RuntimeError as e: return error in str(e)
        return False
    try:
        command('disconnect')
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark', 'inboundPort': port})
        a = add('Chain entry', 'sing-box-outbound', {'type': 'direct'})
        b = add('Chain exit', 'xray-outbound', {'protocol': 'freedom', 'settings': {}})
        opaque = add('Not a chain hop', 'sing-box-config', {'outbounds': [{'type': 'direct'}]})
        wg_hop = add('WireGuard hop', 'sing-box-outbound', {'type': 'wireguard', 'private_key': 'cHJpdmF0ZQ==', 'address': ['10.177.43.2/32'], 'peers': [{'address': '127.0.0.1', 'port': 51820, 'public_key': 'cHVibGlj', 'allowed_ips': ['0.0.0.0/0']}]})
        # The core requires a trust anchor for OpenVPN TLS mode: a throwaway self-signed CA.
        from vpn_otp_fixture import certificate_files
        ca, _ = certificate_files(h['artifacts'])
        ovpn = add('OpenVPN hop', 'sing-box-outbound', {'type': 'openvpn-client', 'server': '192.0.2.10', 'server_port': 1194, 'network': 'udp', 'username': 'synthetic-user', 'password': 'synthetic-password', 'tls': {'server_name': 'vpn.fixture.invalid', 'certificate_path': str(ca)}})
        fullx = add('Complete Xray hop', 'xray-config', {'inbounds': [{'tag': 'user-in', 'protocol': 'socks', 'listen': '127.0.0.1', 'port': 1}], 'outbounds': [{'tag': 'exit', 'protocol': 'freedom', 'settings': {}}], 'routing': {'rules': [{'type': 'field', 'inboundTag': ['user-in'], 'outboundTag': 'exit'}]}})
        wait_for('return document.documentElement.lang==="en" && [...document.querySelector(".group-strip select").options].some(o=>o.value===' + json.dumps(source) + ')')
        select('.group-strip select', source); fill('#client-search', '')
        click('.add-connection'); click('#add-choice-advanced'); select('#profile-type', 'chain'); fill('#profile-name', 'Native mixed chain'); select('#profile-group', source)
        check(js('return document.querySelectorAll("[data-chain-hop]").length===1 && ![...document.querySelector("[data-chain-hop]").options].some(o=>o.value===' + json.dumps(opaque) + ')'), 'chain editor starts with one hop and excludes unsupported full configurations')
        select('[data-chain-hop="0"]', a); click('#chain-add-hop'); select('[data-chain-hop="1"]', b)
        check(js('return [...document.querySelector(\'[data-chain-hop="0"]\').options].some(o=>o.value===' + json.dumps(fullx) + ') && ![...document.querySelector(\'[data-chain-hop="1"]\').options].some(o=>o.value===' + json.dumps(fullx) + ')'), 'a complete Xray configuration is offered for the first hop only')
        check(js('return [0,1].every(i=>[...document.querySelector(\'[data-chain-hop="\'+i+\'"]\').options].some(o=>o.value===' + json.dumps(wg_hop) + '))'), 'a userspace WireGuard endpoint is offered for any hop')
        check(js('return [0,1].every(i=>[...document.querySelector(\'[data-chain-hop="\'+i+\'"]\').options].some(o=>o.value===' + json.dumps(ovpn) + '))'), 'an OpenVPN endpoint is offered for any hop')
        click('[data-chain-up="1"]')
        check(js('return [...document.querySelectorAll("[data-chain-hop]")].map(e=>e.value)') == [b, a], 'moving a hop changes the visible device-to-exit order')
        click('[data-chain-down="0"]'); click('#chain-add-hop'); select('[data-chain-hop="2"]', a); click('[data-chain-remove="2"]')
        click('[data-profile-tab="json"]')
        check(json.loads(js('return document.querySelector("#profile-json").value'))['hops'] == [a, b], 'structured chain controls and JSON retain the same ordered references')
        click('[data-profile-tab="main"]'); click('.modal-footer .button.secondary')
        wait_for('return !!document.querySelector(".desktop-success")')
        check(True, 'new mixed chain validates through the actual bundled core')
        click('button[form="profile-editor"]'); wait_for('return !document.querySelector("dialog")')
        chain = next(p['id'] for p in command('snapshot')['profiles'] if p['name'] == 'Native mixed chain')
        h['request']('POST', h['base'] + '/refresh', {}); wait_for('return !!document.querySelector(".add-connection")')
        check(command('profile', {'id': chain})['config']['hops'] == [a, b], 'saved chain survives a native webview reload')
        check(rejected('delete', {'id': a}, 'profile_used_in_chain'), 'deleting a member leaves the referencing chain intact')
        check(rejected('checkProfile', {**command('profile', {'id': chain}), 'config': {'type': 'chain', 'hops': [a, fullx]}}, 'chain_full_config_position'), 'a complete Xray configuration behind another hop is refused before any core starts')
        wg_fixed = add('WireGuard fixed port', 'sing-box-outbound', {**{'type': 'wireguard', 'private_key': 'cHJpdmF0ZQ==', 'address': ['10.177.43.2/32'], 'peers': [{'address': '127.0.0.1', 'port': 51820, 'public_key': 'cHVibGlj', 'allowed_ips': ['0.0.0.0/0']}]}, 'listen_port': 51999})
        check(rejected('checkProfile', {**command('profile', {'id': chain}), 'config': {'type': 'chain', 'hops': [a, wg_fixed]}}, 'chain_endpoint_listen_port_unsupported') and not rejected('checkProfile', {**command('profile', {'id': chain}), 'config': {'type': 'chain', 'hops': [a, wg_hop]}}, 'chain_endpoint_listen_port_unsupported'), 'a fixed WireGuard port behind another hop is refused before any core starts while a plain endpoint hop is accepted for validation')
        # The pinned sing-box refuses `detour` on a direct outbound, so the hop beside the VPN is a socks outbound.
        socks_entry = add('Chain socks entry', 'sing-box-outbound', {'type': 'socks', 'server': '127.0.0.1', 'server_port': 9})
        vpn_chain = add('Native VPN exit chain', 'chain', {'type': 'chain', 'hops': [socks_entry, ovpn]})
        command('checkProfile', command('profile', {'id': vpn_chain}))
        preview = next(p['config'] for p in command('connectionConfiguration', {'id': vpn_chain, 'active': False})['parts'] if p['name'] == 'sing-box')
        exit_hop = next(e for e in preview['endpoints'] if e['tag'] == 'proxy')
        check(exit_hop['type'] == 'openvpn-client' and exit_hop['detour'] == 'thronium-chain-proxy-0' and 'synthetic-password' not in json.dumps(command('snapshot')), 'an OpenVPN exit hop validates through the real core, dials through the entry hop and keeps its credentials out of snapshots')
        entry_chain = add('Native VPN entry chain', 'chain', {'type': 'chain', 'hops': [ovpn, socks_entry]})
        command('checkProfile', command('profile', {'id': entry_chain}))
        preview = next(p['config'] for p in command('connectionConfiguration', {'id': entry_chain, 'active': False})['parts'] if p['name'] == 'sing-box')
        check(preview['endpoints'][0]['tag'] == 'thronium-chain-proxy-0' and next(o for o in preview['outbounds'] if o['tag'] == 'proxy')['detour'] == 'thronium-chain-proxy-0', 'an OpenVPN entry hop is the endpoint the exit hop detours into')
        # The pinned sing-box refuses `detour` on a direct outbound, so the hop behind the instance is a socks outbound.
        full_chain = add('Native full-config chain', 'chain', {'type': 'chain', 'hops': [fullx, add('Chain socks hop', 'sing-box-outbound', {'type': 'socks', 'server': '127.0.0.1', 'server_port': 9})]})
        command('checkProfile', command('profile', {'id': full_chain}))
        check({p['name'] for p in command('connectionConfiguration', {'id': full_chain, 'active': False})['parts']} == {'sing-box', 'Xray 2'}, 'a complete Xray first hop validates through the real cores and runs as its own instance')
        nested = add('Native nested chain', 'chain', {'type': 'chain', 'hops': [chain]})
        draft = command('profile', {'id': chain}); draft['config']['hops'] = [nested]
        check(rejected('saveProfile', draft, 'chain_cycle') and command('profile', {'id': chain})['config']['hops'] == [a, b], 'cycle rejection preserves the previously saved chain atomically')
        command('connect', {'id': nested})
        with socket.create_connection(('127.0.0.1', port), timeout=2): pass
        check(command('snapshot')['running'] == nested, 'nested chain starts the real core and its local listener')
        draft = command('profile', {'id': a}); draft['name'] += ' changed'
        check(rejected('saveProfile', draft, 'stop_before_editing'), 'an active nested chain protects changes to its leaf profile')
        command('disconnect')
        select('.group-strip select', source); fill('#client-search', 'Native nested chain')
        wait_for('return document.querySelectorAll(".connection-row").length===1')
        click('.row-more'); click('#export-one')
        check(js('return document.querySelector("#export-format option[value=configurations]").disabled'), 'chain export offers the portable bundle that can retain all references')
        click('#export-reveal'); wait_for('return !!document.querySelector("#export-content")')
        text = js('return document.querySelector("#export-content").textContent'); bundle = json.loads(text)
        check(len(bundle['profiles']) == 4 and all(old not in text for old in [a, b, chain, nested]), 'export automatically includes nested members and replaces local IDs with portable aliases')
        close(); click('.add-connection'); click('#add-choice-link'); fill('#import-source', text); select('#import-group', target); click('#import-review')
        check(js('return document.querySelectorAll(".import-select").length') == 4, 'import preview recognizes all members of a portable nested chain')
        index = next(i for i, p in enumerate(bundle['profiles']) if p['name'] == 'Native nested chain')
        buttons = js('return [...document.querySelectorAll("[data-import-check]")].map(e=>e.dataset.importCheck)')
        before = len(command('snapshot')['profiles']); click('[data-import-check="' + buttons[index] + '"]')
        wait_for('return !!document.querySelector(".import-valid")')
        check(len(command('snapshot')['profiles']) == before, 'import core validation resolves the candidate graph without saving any profile')
        click('#import-save'); wait_for('return !document.querySelector("dialog")')
        imported = [command('profile', {'id': p['id']}) for p in command('snapshot')['profiles'] if p['groupId'] == target]
        new_ids = {p['id'] for p in imported}
        check(len(imported) == 4 and all(set(p['config']['hops']) <= new_ids for p in imported if p['kind'] == 'chain'), 'native import atomically remaps every nested edge to newly created profiles')
        imported_root = next(p['id'] for p in imported if p['name'] == 'Native nested chain')
        command('connect', {'id': imported_root}); check(command('snapshot')['running'] == imported_root, 'imported chain starts without referencing any original profile'); command('disconnect')
        select('.group-strip select', source); fill('#client-search', 'Native mixed chain'); wait_for('return document.querySelectorAll(".connection-row").length===1')
        click('.row-more'); click('#menu-edit-profile')
        wait_for('return !!document.querySelector("[data-chain-hop]")')
        check(not js('return [...document.querySelector("[data-chain-hop]").options].some(o=>o.value===' + json.dumps(chain) + ')'), 'editing an existing chain excludes itself from the hop picker')
        command('preferences', {**command('snapshot')['preferences'], 'language': 'ru', 'theme': 'light'})
        wait_for('return document.documentElement.lang==="ru"')
        h['request']('POST', h['base'] + '/window/rect', {'width': 390, 'height': 844})
        check(js('return document.querySelector(".chain-fields").textContent.includes("Добавить узел") && document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth && document.querySelector(".modal-footer").getBoundingClientRect().bottom<=innerHeight'), 'Russian chain controls fit the narrow native window')
        screenshot('chain-narrow-ru'); close()
        command('deleteGroup', {'id': source, 'deleteProfiles': True}); source = None
        command('connect', {'id': imported_root}); check(command('snapshot')['running'] == imported_root, 'imported chain remains usable after deleting the entire original group')
    finally:
        command('disconnect')
        if source: command('deleteGroup', {'id': source, 'deleteProfiles': True})
        command('deleteGroup', {'id': target, 'deleteProfiles': True})
        command('preferences', initial['preferences'])
        if initial['selected']: command('select', {'id': initial['selected']})
        fill('#client-search', '')
        h['request']('POST', h['base'] + '/window/rect', {'width': 1280, 'height': 860})
