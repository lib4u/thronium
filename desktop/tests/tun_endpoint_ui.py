"""Real TUN with WireGuard and every AmneziaWG field set against independent peers, on every TUN stack."""
import http.client
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import time

from wireguard_topology_ui import Peer

STACKS = ('gvisor', 'mixed', 'system')
# Field sets Amnezia gates per version: 2.0, 2.0 with special junk, 3.x protection, 3.1 client shape, 3.1 with cookies off.
AWG_MODES = ('basic', 'signatures', 'protected', 'trailers', 'cookies')


def run(h):
    command, check = h['command'], h['check']
    assert os.geteuid() == 0 and os.environ['THRONIUM_TEST_ORIGINAL_NETNS'] != os.readlink('/proc/self/ns/net')
    root = Path(h['artifacts'])
    initial = command('snapshot'); assert not initial['profiles']
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0)); port = reservation.getsockname()[1]
    # The peers live in 10.177.43.0/24 inside their tunnels; the default TUN exclusions bypass 10/8, so narrow them for the stand.
    excludes = [cidr for cidr in initial['preferences']['tun']['excludeAddresses'] if cidr not in ('10.0.0.0/8', '172.16.0.0/12')]
    command('preferences', {**initial['preferences'], 'language': 'en', 'tun': {**initial['preferences']['tun'], 'excludeAddresses': excludes}})
    audit = {'transfers': [], 'stacks': {}}
    wg = Peer(Path(os.environ['_THRONIUM_TUN_ENDPOINT_WG_FIXTURE']), root / 'wg-peer', '127.0.0.1')
    awg = {}
    for mode in AWG_MODES:
        log = (root / ('awg-' + mode + '.stderr.log')).open('w')
        process = subprocess.Popen([os.environ['_THRONIUM_TUN_ENDPOINT_AWG_FIXTURE'], str(root / ('awg-' + mode)), '127.0.0.1', mode],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, text=True)
        awg[mode] = (process, log)
    try:
        peers = {'wireguard': {'profile': wg.info['profile'], 'http': wg.info['http4'], 'body': 'wg43:', 'stats': wg.stats}}
        for mode, (process, _) in awg.items():
            assert select.select([process.stdout], [], [], 15)[0], 'AWG peer readiness timeout: ' + mode
            info = json.loads(Path(process.stdout.readline().strip()).read_text())
            peers['amneziawg-' + mode] = {'profile': info['profile'], 'http': info['http4'], 'body': 'awg51:',
                                          'stats': (lambda path: lambda: json.loads(Path(path).read_text()))(info['stats'])}
        ids = {kind: command('saveProfile', {'name': 'TUN ' + kind, 'groupId': 'personal', 'kind': 'sing-box-outbound', 'config': peer['profile']})['id']
               for kind, peer in peers.items()}
        for stack in STACKS:
            preferences = command('snapshot')['preferences']
            command('preferences', {**preferences, 'tun': {**preferences['tun'], 'stack': stack}})
            command('connectionSettings', {'mode': 'tun', 'port': port})
            for kind, peer in peers.items():
                label = stack + '-' + kind
                command('connect', {'id': ids[kind]})
                check(command('snapshot')['running'] == ids[kind], label + ': real TUN core starts with the endpoint profile')
                configuration = command('connectionConfiguration', {'id': ids[kind], 'active': True})
                tun = next(i for p in configuration['parts'] for i in p['config']['inbounds'] if i['type'] == 'tun')
                audit['stacks'][label] = tun['stack']
                check(tun['stack'] == ('mixed' if stack == 'gvisor' else stack), label + ': the live TUN uses ' + ('mixed instead of the pinned core\'s broken gvisor flow path' if stack == 'gvisor' else 'the chosen stack'))
                before = peer['stats']()
                host, _, target_port = peer['http'][len('http://'):].partition(':')
                path = '/fixture/' + label
                outcome = None
                for attempt in range(3):
                    client = http.client.HTTPConnection(host, int(target_port), timeout=8)
                    try:
                        client.request('GET', path); response = client.getresponse(); body = response.read()
                        outcome = [response.status, body.decode(errors='replace')]
                        break
                    except (OSError, http.client.HTTPException) as error:
                        outcome = ['error', type(error).__name__]
                    finally:
                        client.close()
                current = peer['stats']()
                served = any(r['path'] == path for r in current['requests'])
                audit['transfers'].append({'label': label, 'outcome': outcome, 'served': served})
                check(outcome == [200, peer['body'] + path] and served, label + ': HTTP through the TUN reaches the independent peer and comes back')
                command('disconnect')
                check(command('snapshot')['running'] is None, label + ': disconnect stops the TUN core')
    finally:
        for process, log in awg.values():
            if not process.stdin.closed: process.stdin.close()
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
            log.close()
        wg.close()
        (root / 'tun-endpoint-audit.json').write_text(json.dumps(audit, indent=2) + '\n')
