"""Independent peers: fixed port, multi-peer routes, key replacement, rollback,
localhost-named endpoints, mixed outer families, keepalive, rekey and retry."""
import copy
import base64
import http.client
import json
import os
import select
import socket
import subprocess
import time
from contextlib import ExitStack
from pathlib import Path


class Peer:
    def __init__(self, binary, directory, outer, **options):
        self.directory = directory
        self.outer = outer
        options_file = directory.with_suffix('.options.json')
        options_file.write_text(json.dumps(options))
        options_file.chmod(0o600)
        self.log = directory.with_suffix('.stderr.log').open('w')
        self.process = subprocess.Popen([str(binary), str(directory), outer, str(options_file)],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.log, text=True)
        try:
            assert select.select([self.process.stdout], [], [], 10)[0], 'independent WG peer readiness timeout'
            self.info = json.loads(Path(self.process.stdout.readline().strip()).read_text())
        except BaseException:
            self.close()
            raise

    def close(self):
        if not self.process.stdin.closed:
            self.process.stdin.close()
        try:
            code = self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
            raise AssertionError('independent WG peer failed to stop')
        finally:
            self.log.close()
        assert code == 0, 'independent WG peer failed; inspect its private stderr log'

    def stats(self):
        return json.loads(Path(self.info['stats']).read_text())


def run(h):
    command, check = h['command'], h['check']
    click, fill, select, wait_for, js = (h[k] for k in ('click', 'fill', 'select', 'wait_for', 'js'))
    root = h['artifacts']
    binary = Path(os.environ['_THRONIUM_WG_TOPOLOGY_FIXTURE'])
    outer = os.environ.get('_THRONIUM_WG_TOPOLOGY_OUTER', '127.0.0.1')
    initial = command('snapshot')
    routing = command('routing')
    group = command('saveGroup', {'name': 'Owned WG topology78', 'subscription': None})['id']
    with socket.socket() as socket_port:
        socket_port.bind(('127.0.0.1', 0))
        proxy_port = socket_port.getsockname()[1]
    family = socket.AF_INET6 if ':' in outer else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as socket_port:
        socket_port.bind((outer, 0))
        fixed_port = socket_port.getsockname()[1]
    audit = {'transfers': [], 'cleanupErrors': [], 'outer': outer, 'fixedPort': fixed_port}

    def save(config, name, previous=None):
        draft = {'name': name, 'groupId': group, 'kind': 'sing-box-outbound', 'config': config}
        if previous:
            draft['id'] = previous
            draft['expectedRevision'] = command('profile', {'id': previous})['expectedRevision']
        return command('saveProfile', draft)['id']

    def transfer(peer, label, fixed=None):
        before = peer.stats()
        for inner in ['4', '6']:
            path = '/fixture/' + label + '-' + inner
            client = http.client.HTTPConnection('127.0.0.1', proxy_port, timeout=5)
            try:
                client.request('GET', peer.info['http' + inner] + path)
                response = client.getresponse()
                body = response.read()
                assert response.status == 200 and body == ('wg43:' + path).encode(), 'actual WG response differs'
            finally:
                client.close()
            current = peer.stats()
            assert any(r['path'] == path and r['remote'].startswith('10.177.43.2:' if inner == '4' else '[fd00:43::2]:') for r in current['requests'])
            assert current['receivedWirePacketTypes'].get('4', 0) > before['receivedWirePacketTypes'].get('4', 0)
            assert current['metrics']['last_handshake_time_sec'] > 0
            if fixed:
                sender = f'[{peer.outer}]:{fixed}' if ':' in peer.outer else f'{peer.outer}:{fixed}'
                assert current['receivedFrom'].get(sender, 0) > before['receivedFrom'].get(sender, 0), 'fixed UDP port did not reach the peer'
            audit['transfers'].append({'label': label, 'inner': inner, 'stats': current})
            check(True, label + ' IPv' + inner + ': independent encrypted peer receives the requested payload')

    def import_conf(text):
        # The review names every wg-quick directive by class; nothing from the file is executed.
        before = {p['id'] for p in command('snapshot')['profiles']}
        click('.primary-nav button:first-child'); click('.add-connection'); click('#add-choice-link')
        fill('#import-source', text)
        wait_for('return [...document.querySelector("#import-group").options].some(o=>o.value===' + json.dumps(group) + ')')
        select('#import-group', group); click('#import-review')
        wait_for('return document.querySelectorAll(".import-select").length===1')
        warnings = js('return [...document.querySelectorAll(".import-warnings li")].map(e=>e.textContent)')
        check(sorted(warnings) == sorted(['Host command from the file is not executed: PostUp', 'Interface setting not applied by the app: DNS', 'Interface setting not applied by the app: Table']), 'review classifies host commands and interface settings from the .conf separately')
        check(js('return !!document.querySelector("#import-acknowledge") && document.querySelector("#import-save").disabled'), 'unapplied .conf directives require explicit acknowledgement before import')
        click('#import-acknowledge'); click('#import-save')
        wait_for('return !document.querySelector("dialog[open]")')
        after = [p['id'] for p in command('snapshot')['profiles'] if p['id'] not in before]
        assert len(after) == 1
        return after[0]

    def occupied(base, label):
        # A real UDP owner prevents the candidate bind. Rollback must use the
        # exact old active request and still carry traffic.
        active = command('snapshot')['running']
        before_active = command('connectionConfiguration', {'id': active, 'active': True})
        with socket.socket(family, socket.SOCK_DGRAM) as blocker:
            blocker.bind((outer, 0))
            blocked = {**copy.deepcopy(base), 'listen_port': blocker.getsockname()[1]}
            blocked_id = save(blocked, label)
            try:
                command('connect', {'id': blocked_id})
                raise AssertionError('WG started despite an occupied fixed port')
            except RuntimeError as error:
                private_values = [blocked['private_key'], blocked['peers'][0]['pre_shared_key']]
                private_values += [base64.b64decode(v).hex() for v in private_values]
                check(not any(value in str(error) for value in private_values), label + ': fixed-port failure omits private key material from its diagnostic')
            check(command('snapshot')['running'] == active, label + ': failed fixed-port Start restores the preceding profile')
            check(command('connectionConfiguration', {'id': active, 'active': True}) == before_active, label + ': failed fixed-port Start restores the exact active request')
            return blocked_id

    def initiations(sock, seconds):
        count, deadline = 0, time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                data, _ = sock.recvfrom(2048)
            except socket.timeout:
                continue
            count += data[:1] == b'\x01'
        return count

    try:
        command('preferences', {**initial['preferences'], 'language': 'en', 'connectionMode': 'local', 'inboundPort': proxy_port})
        wait_for('return document.documentElement.lang==="en"')
        next_routing = copy.deepcopy(routing)
        for preset in next_routing['profiles']:
            preset['route']['auto_detect_interface'] = True
        command('saveRouting', next_routing)
        with ExitStack() as peers:
            first = Peer(binary, root / 'peer-a', outer)
            peers.callback(first.close)
            config = copy.deepcopy(first.info['profile'])
            pid = save(config, 'WG single automatic')
            command('connect', {'id': pid})
            transfer(first, 'single-auto')
            command('disconnect')

            fixed_config = {**copy.deepcopy(config), 'listen_port': fixed_port}
            fixed_id = save(fixed_config, 'WG fixed automatic')
            command('connect', {'id': fixed_id})
            transfer(first, 'fixed-auto', fixed_port)
            command('disconnect')
            check(command('profile', {'id': fixed_id})['config'] == fixed_config, 'fixed listen port and peer parameters remain saved exactly')

            second = Peer(binary, root / 'peer-b', outer, subnet=44, clientPrivateKey=config['private_key'])
            peers.callback(second.close)
            multi_config = {**copy.deepcopy(fixed_config), 'peers': config['peers'] + second.info['profile']['peers']}
            multi_id = save(multi_config, 'WG independent peers')
            command('connect', {'id': multi_id})
            transfer(first, 'multiple-a', fixed_port)
            transfer(second, 'multiple-b', fixed_port)
            before_active = command('connectionConfiguration', {'id': multi_id, 'active': True})

            occupied(config, 'Occupied WG port')
            transfer(first, 'rollback-a', fixed_port)
            transfer(second, 'rollback-b', fixed_port)
            command('disconnect')

            # Rotate all key material at the same endpoint; saved UUID stays the
            # same, while a new independent process must accept the new keys.
            endpoint_port = config['peers'][0]['port']
            first.close()
            rotated = Peer(binary, root / 'peer-a-rotated', outer, listenPort=endpoint_port)
            peers.callback(rotated.close)
            replacement = {**copy.deepcopy(rotated.info['profile']), 'listen_port': fixed_port}
            check(all(replacement[key] != config[key] for key in ['private_key', 'peers']), 'fixture rotates private, public and preshared material at the same server endpoint')
            save(replacement, 'WG rotated keys', fixed_id)
            command('connect', {'id': fixed_id})
            transfer(rotated, 'rotated-keys', fixed_port)
            check(command('profile', {'id': fixed_id})['config'] == replacement, 'new key material reaches the Core without changing the saved profile ID')
            command('disconnect')

            # A localhost-named peer resolves through the app's DNS router and
            # still reaches the loopback fixture; the .conf review classifies
            # wg-quick directives and the import executes none of them.
            marker = root / 'must-not-exist'
            peer_conf = replacement['peers'][0]
            text = ('[Interface]\nPrivateKey = ' + replacement['private_key'] + '\nAddress = ' + ', '.join(replacement['address']) + '\nMTU = 1420\nDNS = 10.177.43.1\nTable = off\nPostUp = touch ' + str(marker)
                    + '\n\n[Peer]\nPublicKey = ' + peer_conf['public_key'] + '\nPresharedKey = ' + peer_conf['pre_shared_key'] + '\nAllowedIPs = ' + ', '.join(peer_conf['allowed_ips']) + '\nEndpoint = localhost:' + str(peer_conf['port']) + '\nPersistentKeepalive = 1\n')
            domain_id = import_conf(text)
            expected = {k: v for k, v in replacement.items() if k not in ('system', 'listen_port')}
            expected['peers'] = [{**peer_conf, 'address': 'localhost', 'persistent_keepalive_interval': 1}]
            check(command('profile', {'id': domain_id})['config'] == expected and not marker.exists(), 'imported .conf keeps the localhost endpoint and keepalive, applies no DNS/Table and runs no PostUp command')
            started = time.monotonic()
            command('connect', {'id': domain_id})
            transfer(rotated, 'localhost-endpoint')
            # The keepalive-driven first handshake must resolve the name at once,
            # not after the 5 s rekey retry.
            check(time.monotonic() - started < 4, 'localhost peer with keepalive completes its first handshake without waiting for a retry')
            idle = rotated.stats()
            time.sleep(3)
            kept = rotated.stats()
            check(kept['receivedWirePacketTypes'].get('4', 0) > idle['receivedWirePacketTypes'].get('4', 0) and kept['requests'] == idle['requests'], 'persistent keepalive keeps sending transport packets to the independent peer without new HTTP requests')
            command('disconnect')

            domain_fixed = {**copy.deepcopy(replacement), 'peers': [{**peer_conf, 'address': 'localhost'}]}
            domain_fixed_id = save(domain_fixed, 'WG localhost fixed port')
            command('connect', {'id': domain_fixed_id})
            transfer(rotated, 'localhost-fixed', fixed_port)
            occupied(domain_fixed, 'Occupied localhost port')
            transfer(rotated, 'localhost-fixed-rollback', fixed_port)
            command('disconnect')

            # Both outer families inside one tunnel on one fixed port.
            other = '::1' if family == socket.AF_INET else '127.0.0.1'
            mixed_peer = Peer(binary, root / 'peer-mixed', other, subnet=45, clientPrivateKey=replacement['private_key'])
            peers.callback(mixed_peer.close)
            mixed = {**copy.deepcopy(replacement), 'peers': replacement['peers'] + mixed_peer.info['profile']['peers']}
            mixed_id = save(mixed, 'WG mixed outer families')
            command('connect', {'id': mixed_id})
            transfer(rotated, 'mixed-a', fixed_port)
            transfer(mixed_peer, 'mixed-b', fixed_port)
            command('disconnect')

            # Client-side rekey timer on a standard server: a new handshake
            # inside one connection, distinct from manual key replacement.
            rekey = {**copy.deepcopy(replacement), 'amnezia_wg': {'rekey_after_time': 1}}
            rekey_id = save(rekey, 'WG accelerated rekey')
            command('connect', {'id': rekey_id})
            transfer(rotated, 'rekey-first', fixed_port)
            first_stats = rotated.stats()
            # A rekey initiation is still rate-limited by the default 5 s rekey
            # timeout since the last handshake; only rekey_after_time is changed.
            time.sleep(5.5)
            transfer(rotated, 'rekey-second', fixed_port)
            second_stats = rotated.stats()
            stamp = lambda s: (s['metrics']['last_handshake_time_sec'], s['metrics']['last_handshake_time_nsec'])
            check(stamp(second_stats) > stamp(first_stats) and second_stats['receivedWirePacketTypes'].get('1', 0) > first_stats['receivedWirePacketTypes'].get('1', 0), 'rekey_after_time=1 renews the session with a new handshake accepted by the standard server inside one connection')
            check(command('profile', {'id': rekey_id})['config'] == rekey, 'accelerated rekey timers stay saved exactly')
            command('disconnect')

            # Retransmitted initiations toward an unreachable peer, then a clean stop.
            with socket.socket(family, socket.SOCK_DGRAM) as dead:
                dead.bind((outer, 0))
                dead.settimeout(0.2)
                retry = {**copy.deepcopy(replacement), 'peers': [{**peer_conf, 'port': dead.getsockname()[1]}], 'amnezia_wg': {'rekey_timeout': 1, 'max_handshake_attempts': 3}}
                retry_id = save(retry, 'WG unreachable peer retry')
                command('connect', {'id': retry_id})
                client = http.client.HTTPConnection('127.0.0.1', proxy_port, timeout=4)
                try:
                    client.request('GET', rotated.info['http4'] + '/fixture/retry')
                    client.getresponse().read()
                    raise AssertionError('HTTP succeeded through an unreachable peer')
                except (OSError, http.client.HTTPException):
                    pass
                finally:
                    client.close()
                sent = initiations(dead, 1)
                check(2 <= sent <= 6 and command('snapshot')['running'] == retry_id, 'rekey_timeout=1 retransmits the handshake to an unreachable peer while the session stays up')
                command('disconnect')
                check(initiations(dead, 1.5) == 0, 'disconnect stops handshake retransmissions')
                audit['retryInitiations'] = sent

            # Two independent WireGuard endpoints as members of one automatic
            # pool: each member is its own endpoint in the core, the
            # pinned member carries traffic, health probes run through both
            # tunnels and a manual selection moves traffic to the other peer.
            pool_peer = Peer(binary, root / 'peer-pool', outer)
            peers.callback(pool_peer.close)
            member_a = {k: v for k, v in copy.deepcopy(replacement).items() if k != 'listen_port'}
            member_b = copy.deepcopy(pool_peer.info['profile'])
            a_id = save(member_a, 'WG pool member A')
            b_id = save(member_b, 'WG pool member B')
            pool_config = {'type': 'auto-selector', 'members': [a_id, b_id], 'pinned_profile': a_id,
                           'url': rotated.info['http4'] + '/fixture/pool-health', 'interval': '1s', 'timeout': '3s'}
            pool_id = command('saveProfile', {'name': 'WG endpoint pool', 'groupId': group, 'kind': 'auto-selector', 'config': pool_config})['id']
            summary = next(p for p in command('snapshot')['profiles'] if p['id'] == pool_id)
            check(summary['ipSpeedSupported'], 'a pool pinned to a WireGuard member advertises IP/speed diagnostics through that member')
            command('connect', {'id': pool_id})
            generated = next(part['config'] for part in command('connectionConfiguration', {'id': pool_id, 'active': True})['parts'] if part['name'] == 'sing-box')
            member_tags = ['thronium-selector-proxy-' + a_id, 'thronium-selector-proxy-' + b_id]
            group_outbound = next(o for o in generated['outbounds'] if o.get('type') == 'auto-selector')
            check(sorted(e['tag'] for e in generated.get('endpoints', []) if e.get('type') == 'wireguard') == sorted(member_tags)
                  and group_outbound['outbounds'] == member_tags and group_outbound.get('pinned') == member_tags[0]
                  and not any(o.get('type') == 'wireguard' for o in generated['outbounds']),
                  'the pool compiles each WireGuard member as its own endpoint under the member tag with the pin preserved')
            transfer(rotated, 'pool-pinned-a')
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                status = next((g for g in command('getAutoSelectors') if g['tag'] == 'proxy'), None)
                if status and status['membersAlive'] == 2 and all(m['probes'] > 0 for m in status['members']):
                    break
                time.sleep(.2)
            check(status is not None and status['membersAlive'] == 2 and status['pinned'] == member_tags[0]
                  and {m['profileId'] for m in status['members']} == {a_id, b_id},
                  'health probes reach the shared fixture URL through both WireGuard members: ' + json.dumps({m['tag']: m['state'] for m in status['members']} if status else None))
            # The member switch is journaled by name. Driving the
            # snapshot poll makes the host observe the pinned selection first;
            # command('snapshot') calls engine.poll() which reads the selector.
            def switch_to(name, timeout=20):
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    command('snapshot')
                    entries = command('getSwitchHistory')['entries']
                    hit = next((e for e in entries if e['toName'] == name), None)
                    if hit:
                        return hit, entries
                    time.sleep(.5)
                return None, command('getSwitchHistory')['entries']
            first_switch, entries = switch_to('WG pool member A')
            check(first_switch is not None and first_switch['fromName'] == '' and first_switch['poolName'] == 'WG endpoint pool',
                  'the pool\'s first pinned selection is journaled with no origin: ' + json.dumps([(e['fromName'], e['toName']) for e in entries[:3]]))
            command('autoSelectorAction', {'tag': 'proxy', 'action': 'select', 'member': member_tags[1]})
            transfer(pool_peer, 'pool-selected-b')
            after = next(g for g in command('getAutoSelectors') if g['tag'] == 'proxy')
            check(after['pinned'] == member_tags[1] and after['selected'] == member_tags[1], 'manual selection moves the pool to the other WireGuard member')
            moved, entries = switch_to('WG pool member B')
            check(moved is not None and moved['fromName'] == 'WG pool member A'
                  and entries == sorted(entries, key=lambda e: -e['id']),
                  'the manual move A to B is journaled by name, newest first: ' + json.dumps([(e['fromName'], e['toName']) for e in entries[:3]]))
            click('.primary-nav button:nth-child(3)')
            wait_for('return !!document.querySelector("#switch-history-table [data-switch-entry]")')
            js('document.querySelector("#switch-history").scrollIntoView({block:"start"})')
            rows = js('return [...document.querySelectorAll("#switch-history-table [data-switch-entry]")].map(r=>[...r.cells].map(c=>c.textContent))')
            headers = js('return [...document.querySelectorAll("#switch-history-table thead th")].map(h=>h.textContent)')
            check(headers == ['Time', 'Server', 'Change'] and any(r[2] == 'WG pool member A \u2192 WG pool member B' for r in rows) and any('First selection: WG pool member A' in r[2] for r in rows),
                  'the switch-history card lists the moves under labelled columns: ' + json.dumps([headers] + rows[:2]))
            audit['switchRows'] = rows
            click('.primary-nav button:first-child')
            command('disconnect')
            clash_b = save({**member_b, 'listen_port': fixed_port}, 'WG pool member B fixed', b_id)
            pool_fixed = {**pool_config, 'members': [fixed_id, clash_b]}
            try:
                command('saveProfile', {'id': pool_id, 'expectedRevision': command('profile', {'id': pool_id})['expectedRevision'],
                                        'name': 'WG endpoint pool', 'groupId': group, 'kind': 'auto-selector', 'config': pool_fixed})
                raise AssertionError('a pool saved two members on one fixed port')
            except RuntimeError as error:
                check('selector_member_port_conflict' in str(error), 'two members on one fixed WireGuard port are refused when the pool is saved')

            # Reserved bytes and udp_timeout on the wire: the peer that
            # expects reserved bytes sees them in every client packet, a plain
            # peer cannot even parse such an initiation, and udp_timeout reaches
            # the generated endpoint while the profile stays saved exactly.
            reserved_peer = Peer(binary, root / 'peer-reserved', outer, reserved=[1, 2, 3])
            peers.callback(reserved_peer.close)
            reserved_config = copy.deepcopy(reserved_peer.info['profile'])
            reserved_config['peers'][0]['reserved'] = [1, 2, 3]
            reserved_config['udp_timeout'] = '30s'
            reserved_id = save(reserved_config, 'WG reserved bytes')
            command('connect', {'id': reserved_id})
            generated = next(part['config'] for part in command('connectionConfiguration', {'id': reserved_id, 'active': True})['parts'] if part['name'] == 'sing-box')
            endpoint = next(e for e in generated['endpoints'] if e.get('type') == 'wireguard')
            check(endpoint['udp_timeout'] == '30s' and endpoint['peers'][0]['reserved'] == [1, 2, 3], 'udp_timeout and reserved bytes reach the generated endpoint unchanged')
            transfer(reserved_peer, 'reserved-bytes')
            seen = reserved_peer.stats()
            check(seen['reservedSeen'].get('010203', 0) > 0 and list(seen['reservedSeen']) == ['010203'] and seen['receivedWirePacketTypes'].get('1', 0) > 0 and seen['receivedWirePacketTypes'].get('4', 0) > 0,
                  'every client packet carries the configured reserved bytes and the peer still parses initiations and transport: ' + json.dumps(seen['reservedSeen']))
            check(seen['sentWirePacketTypes'].get('2', 0) > 0 and seen['sentWirePacketTypes'].get('4', 0) > 0, 'the peer answers with reserved bytes of its own and the client strips them')
            check(command('profile', {'id': reserved_id})['config'] == reserved_config, 'reserved bytes and udp_timeout stay saved exactly')
            command('disconnect')
            # The same client against a plain peer: the initiation arrives with a
            # message type the peer does not know and no handshake completes.
            plain_before = rotated.stats()
            mismatch = {**copy.deepcopy(reserved_config), 'private_key': replacement['private_key'], 'peers': [{**replacement['peers'][0], 'reserved': [1, 2, 3]}]}
            mismatch_id = save(mismatch, 'WG reserved bytes mismatch')
            command('connect', {'id': mismatch_id})
            client = http.client.HTTPConnection('127.0.0.1', proxy_port, timeout=3)
            try:
                client.request('GET', rotated.info['http4'] + '/fixture/reserved-mismatch')
                client.getresponse().read()
                raise AssertionError('HTTP succeeded through a peer that cannot parse reserved bytes')
            except (OSError, http.client.HTTPException):
                pass
            finally:
                client.close()
            plain_after = rotated.stats()
            unknown_type = str(1 | (1 << 8) | (2 << 16) | (3 << 24))
            check(plain_after['receivedWirePacketTypes'].get(unknown_type, 0) > plain_before['receivedWirePacketTypes'].get(unknown_type, 0)
                  and plain_after['receivedWirePacketTypes'].get('1', 0) == plain_before['receivedWirePacketTypes'].get('1', 0)
                  and plain_after['metrics']['last_handshake_time_sec'] == plain_before['metrics']['last_handshake_time_sec'],
                  'a peer without reserved bytes receives an unknown message type and completes no handshake')
            command('disconnect')
        audit['passed'] = True
    finally:
        for name, action in [
            ('logs', lambda: audit.update(logsBeforeCleanup=command('getLogs'))),
            ('disconnect', lambda: command('disconnect')),
            ('groups', lambda: command('deleteGroup', {'id': group, 'deleteProfiles': True})),
            ('routing', lambda: command('saveRouting', {**routing, 'revision': command('routing')['revision']})),
            ('preferences', lambda: command('preferences', initial['preferences'])),
        ]:
            try:
                action()
            except Exception as error:
                audit['cleanupErrors'].append({'step': name, 'error': str(error)})
        path = root / 'wireguard-topology-audit.json'
        path.write_text(json.dumps(audit, indent=2) + '\n')
        path.chmod(0o600)
        assert not audit['cleanupErrors'], audit['cleanupErrors']
        check(command('snapshot')['running'] is None, 'owned WG sessions are stopped and original routing is restored')
