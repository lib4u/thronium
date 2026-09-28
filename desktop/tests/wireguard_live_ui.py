"""Real standard WG handshakes against an independent userspace loopback peer."""
import base64
import copy
import http.client
import json
import os
import socket
import time
from pathlib import Path
from native_dialogs import file_dialog


def run(h):
    command, click, fill, select, wait_for, js, check = (h[k] for k in ('command', 'click', 'fill', 'select', 'wait_for', 'js', 'check'))
    info = json.loads(Path(os.environ['_THRONIUM_WIREGUARD_LIVE_READY']).read_text())
    initial = command('snapshot')
    original_routing = command('routing')
    original_logging = command('settings')['logging']
    initial_groups = {g['id'] for g in initial['groups']}
    group = command('saveGroup', {'name': 'Owned live WireGuard fixtures', 'subscription': None})['id']
    audit = {'http': [], 'negative': [], 'cleanupErrors': []}
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]

    def private_json(name, value):
        path = h['artifacts'] / name
        path.write_text(json.dumps(value, indent=2) + '\n')
        path.chmod(0o600)

    def stats():
        return json.loads(Path(info['stats']).read_text())

    def request(family, path, timeout=10):
        client = http.client.HTTPConnection('127.0.0.1', port, timeout=timeout)
        try:
            client.request('GET', info['http' + family] + path)
            response = client.getresponse()
            return response.status, response.read()
        finally:
            client.close()

    def start(pid, label):
        profile = command('profile', {'id': pid})
        command('checkProfile', profile)
        command('connect', {'id': pid})
        active = command('connectionConfiguration', {'id': pid, 'active': True})
        private_json(label + '-active-private.json', active)
        assert any(p['config']['route'].get('auto_detect_interface') is info['autoDetectInterface'] for p in active['parts'])
        return profile

    def transfer(pid, label):
        before = stats()
        profile = start(pid, label)
        for family in ['4', '6']:
            path = '/fixture/' + label + '-' + family
            status, body = request(family, path)
            current = stats()
            assert any(r['path'] == path and r['remote'].startswith('10.177.43.2:' if family == '4' else '[fd00:43::2]:') for r in current['requests'])
            assert current['receivedWirePacketTypes'].get('1', 0) > before['receivedWirePacketTypes'].get('1', 0)
            assert current['receivedWirePacketTypes'].get('4', 0) > before['receivedWirePacketTypes'].get('4', 0)
            stamp = lambda s: (s['metrics']['last_handshake_time_sec'], s['metrics']['last_handshake_time_nsec'])
            assert stamp(current) > stamp(before)
            check(status == 200 and body == ('wg43:' + path).encode(), label + ' IPv' + family + ': independent server confirms new WG handshake and actual HTTP body')
            audit['http'].append({'label': label, 'family': family, 'path': path, 'serverStats': current})
        check(command('profile', {'id': pid})['config'] == profile['config'], label + ': handshake and traffic leave the saved profile unchanged')
        command('disconnect')

    def import_text(text):
        before = {p['id'] for p in command('snapshot')['profiles']}
        click('.primary-nav button:first-child')
        click('.add-connection')
        click('#add-choice-link')
        fill('#import-source', text)
        wait_for('return [...document.querySelector("#import-group").options].some(o=>o.value===' + json.dumps(group) + ')')
        select('#import-group', group)
        click('#import-review')
        wait_for('return document.querySelectorAll(".import-select").length===1')
        check(not js('return !!document.querySelector(".import-acknowledge")'), 'native WG .conf preview reports no dropped fields')
        click('#import-save')
        wait_for('return !document.querySelector("dialog[open]")')
        after = [p['id'] for p in command('snapshot')['profiles'] if p['id'] not in before]
        assert len(after) == 1
        return after[0]

    def negative(config, label, initiation):
        pid = command('saveProfile', {'name': label, 'groupId': group, 'kind': 'sing-box-outbound', 'config': config})['id']
        before = stats()
        saved = start(pid, label)
        path = '/fixture/' + label
        outcome = None
        try:
            status, body = request('4', path, timeout=3)
            outcome = {'status': status, 'bytes': len(body)}
            assert status != 200, 'negative fixture unexpectedly returned HTTP success'
        except (TimeoutError, ConnectionError, http.client.HTTPException) as error:
            outcome = {'error': type(error).__name__}
        time.sleep(0.2)  # server statistics refresh every 100 ms
        after = stats()
        check(after['requests'] == before['requests'], label + ': no HTTP reaches the independent server')
        if initiation:
            assert after['receivedWirePacketTypes'].get('1', 0) > before['receivedWirePacketTypes'].get('1', 0)
            assert all(after['metrics'][k] == before['metrics'][k] for k in ['last_handshake_time_sec', 'last_handshake_time_nsec'])
        check(command('snapshot')['running'] == pid and command('profile', {'id': pid})['config'] == saved['config'], label + ': running state is distinct from successful handshake; profile is preserved')
        audit['negative'].append({'label': label, 'outcome': outcome, 'before': before, 'after': after})
        command('disconnect')

    try:
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark', 'connectionMode': 'local', 'inboundPort': port})
        wait_for('return document.documentElement.lang==="en"')
        routing = copy.deepcopy(original_routing)
        # Exercise the chosen interface policy explicitly, preserving it in all
        # imported and reconnected profiles. The original policy is restored below.
        for preset in routing['profiles']:
            preset['route']['auto_detect_interface'] = info['autoDetectInterface']
        command('saveRouting', routing)
        command('saveSettings', {'section': 'logging', 'previous': original_logging, 'values': {**original_logging, 'log_level': 'debug'}})
        cfg = info['profile']
        direct = command('saveProfile', {'name': 'Exact live WG Core profile', 'groupId': group, 'kind': 'sing-box-outbound', 'config': cfg})['id']
        transfer(direct, 'core-profile')
        peer = cfg['peers'][0]
        text = '[Interface]\nPrivateKey = ' + cfg['private_key'] + '\nAddress = ' + ', '.join(cfg['address']) + '\nMTU = 1420\n\n[Peer]\nPublicKey = ' + peer['public_key'] + '\nPresharedKey = ' + peer['pre_shared_key'] + '\nAllowedIPs = ' + ', '.join(peer['allowed_ips']) + '\nEndpoint = ' + info['endpoint'] + '\n'
        imported = import_text(text)
        expected = copy.deepcopy(cfg)
        expected.pop('system')
        check(command('profile', {'id': imported})['config'] == expected, 'native .conf import preserves both addresses, allowed networks, endpoint and generated private/public/preshared keys')
        transfer(imported, 'native-conf-import')

        before_profiles = {p['id'] for p in command('snapshot')['profiles']}
        before_routing = command('routing')
        click('.primary-nav button:nth-child(5)')
        click('[data-settings-section=backup]')
        wait_for('return !!document.querySelector("#backup-open")')
        click('#backup-open')
        file_dialog('Open backup', info['archive'], opening=True)
        wait_for('return !!document.querySelector("#backup-confirm") && !document.querySelector("#backup-open").disabled')
        check(js('return document.querySelector("#backup-confirm").disabled && !document.querySelector("#backup-acknowledge").checked'), 'real Qt archive is reviewed before additive import')
        click('#backup-acknowledge')
        click('#backup-confirm')
        wait_for('return !document.querySelector("dialog[open]") && !!document.querySelector("#backup-notice")')
        added = [p['id'] for p in command('snapshot')['profiles'] if p['id'] not in before_profiles]
        assert len(added) == 1
        legacy = command('profile', {'id': added[0]})
        expected_legacy = {**copy.deepcopy(cfg), 'workers': 2, 'tag': 'Legacy live WG peer'}
        check(legacy['config'] == expected_legacy and command('routing') == before_routing, 'legacy import normalizes bare addresses and worker_count while preserving keys, peers and current DNS/routes')
        transfer(added[0], 'native-legacy-import')

        wrong_key = copy.deepcopy(cfg)
        wrong_key['peers'][0]['public_key'] = base64.b64encode(os.urandom(32)).decode()
        negative(wrong_key, 'wrong-public-key', True)
        denied = copy.deepcopy(cfg)
        denied['peers'][0]['allowed_ips'] = ['10.177.43.99/32']
        negative(denied, 'destination-outside-allowed-ips', False)
        transfer(imported, 'reconnect-after-negatives')
        audit['passed'] = True
    finally:
        for name, action in [
            ('logs', lambda: audit.update(logsBeforeCleanup=command('getLogs'))),
            ('disconnect', lambda: command('disconnect')),
            ('groups', lambda: [command('deleteGroup', {'id': g['id'], 'deleteProfiles': True}) for g in command('snapshot')['groups'] if g['id'] not in initial_groups]),
            ('preferences', lambda: command('preferences', initial['preferences'])),
            ('routing', lambda: command('saveRouting', {**original_routing, 'revision': command('routing')['revision']})),
            ('logging', lambda: command('saveSettings', {'section': 'logging', 'previous': command('settings')['logging'], 'values': original_logging})),
        ]:
            try:
                action()
            except Exception as error:
                audit['cleanupErrors'].append({'step': name, 'error': str(error)})
        audit['cleanupCompleted'] = not audit['cleanupErrors']
        private_json('wireguard-live-audit.json', audit)
        assert audit['cleanupCompleted'], audit['cleanupErrors']
        restored = command('routing')
        check({**restored, 'revision': original_routing['revision']} == original_routing and command('snapshot')['running'] is None and {g['id'] for g in command('snapshot')['groups']} == initial_groups, 'owned profiles/groups are removed and original routing is restored after live traffic')
