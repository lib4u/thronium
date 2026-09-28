"""Live AWG pools and real cookie challenges from an independent official peer."""
import copy
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
    def __init__(self, binary, directory, mode):
        self.log = directory.with_suffix('.stderr.log').open('w')
        self.process = subprocess.Popen([str(binary), str(directory), '127.0.0.1', mode],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.log,
                                        text=True, env={**os.environ, 'GOMAXPROCS': '2'})
        try:
            assert select.select([self.process.stdout], [], [], 15)[0], 'AWG peer readiness timeout'
            self.info = json.loads(Path(self.process.stdout.readline().strip()).read_text())
        except BaseException:
            self.close()
            raise

    def stats(self):
        return json.loads(Path(self.info['stats']).read_text())

    def load(self):
        self.process.stdin.write('{"op":"load"}\n')
        self.process.stdin.flush()
        assert select.select([self.process.stdout], [], [], 5)[0]
        assert json.loads(self.process.stdout.readline()) == {'started': True}
        eventually(lambda: self.stats()['underLoadSeen'], 'official peer never entered overload')

    def close(self):
        if not self.process.stdin.closed:
            self.process.stdin.close()
        try:
            code = self.process.wait(timeout=25)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
            raise AssertionError('AWG peer failed to stop')
        finally:
            self.log.close()
        assert code == 0, 'AWG peer failed; inspect private stderr log'


def eventually(predicate, message, timeout=25):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(.2)
    raise AssertionError(message)


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


def run(h):
    command, check = h['command'], h['check']
    initial = command('snapshot')
    group = command('saveGroup', {'name': 'Owned AWG migration78e', 'subscription': None})['id']
    proxy_port = free_port()
    audit = {'transfers': [], 'cookies': [], 'cleanupErrors': []}

    def save(config, name, kind='sing-box-outbound'):
        return command('saveProfile', {'name': name, 'groupId': group, 'kind': kind, 'config': config})['id']

    def transfer(peer, label):
        for family in ['4', '6']:
            path = '/fixture/' + label + '-' + family
            attempts = []
            deadline = time.monotonic() + 40
            while True:
                client = http.client.HTTPConnection('127.0.0.1', proxy_port, timeout=15)
                success = False
                try:
                    client.request('GET', peer.info['http' + family] + path)
                    response = client.getresponse()
                    body = response.read()
                    attempts.append({'status': response.status, 'bytes': len(body)})
                    success = response.status == 200 and body == ('awg51:' + path).encode()
                except (TimeoutError, ConnectionError, http.client.HTTPException) as error:
                    attempts.append({'error': type(error).__name__})
                finally:
                    client.close()
                if success:
                    break
                # A deliberately saturated handshake queue may drop packets.
                # Prove recovery in the same running session and retain every
                # failed request; ordinary pool transfers must succeed first try.
                assert label.startswith('loaded-') and time.monotonic() < deadline, attempts
                time.sleep(.2)
            stats = eventually(lambda: (s if any(r['path'] == path for r in s['requests']) else None)
                               if (s := peer.stats()) else None, 'selected peer did not receive HTTP')
            check(stats['metrics']['last_handshake_time_sec'] > 0
                  and any(r['path'] == path and r['remote'].startswith('10.177.43.2:' if family == '4' else '[fd00:43::2]:') for r in stats['requests']),
                  label + ': IPv' + family + ' HTTP arrives through the independent AWG tunnel')
            audit['transfers'].append({'label': label, 'family': family, 'stats': stats, 'attempts': attempts})

    try:
        command('preferences', {**initial['preferences'], 'language': 'en', 'connectionMode': 'local', 'inboundPort': proxy_port})
        with ExitStack() as stack:
            def peer(name, mode):
                p = Peer(Path(os.environ['_THRONIUM_AWG_MIGRATION_FIXTURE']), h['artifacts'] / name, mode)
                stack.callback(p.close)
                return p

            a, b = peer('pool-a', 'basic'), peer('pool-b', 'trailers')
            a_id, b_id = save(a.info['profile'], 'AWG pool A'), save(b.info['profile'], 'AWG pool B')
            cfg = {'type': 'auto-selector', 'members': [a_id, b_id], 'pinned_profile': a_id,
                   'url': a.info['http4'] + '/fixture/pool-health', 'interval': '1s', 'timeout': '3s'}
            pool = save(cfg, 'AWG pool', 'auto-selector')
            command('connect', {'id': pool})
            generated = next(p['config'] for p in command('connectionConfiguration', {'id': pool, 'active': True})['parts'] if p['name'] == 'sing-box')
            tags = ['thronium-selector-proxy-' + pid for pid in [a_id, b_id]]
            endpoints = {e['tag']: e for e in generated['endpoints']}
            check(all(endpoints[tag]['amnezia_wg'] == p.info['profile']['amnezia_wg'] for tag, p in zip(tags, [a, b])),
                  'the live pool preserves independent basic and AWG 3.1 endpoint parameters')
            transfer(a, 'pool-pinned-a')

            def healthy():
                status = next((g for g in command('getAutoSelectors') if g['tag'] == 'proxy'), None)
                return status if status and status['membersAlive'] == 2 and all(m['probes'] > 0 for m in status['members']) else None

            status = eventually(healthy, 'both AWG pool members did not become healthy')
            check(all(any(r['path'] == '/fixture/pool-health' for r in p.stats()['requests']) for p in [a, b]),
                  'health probes cross both independently encrypted AWG tunnels')
            command('autoSelectorAction', {'tag': 'proxy', 'action': 'select', 'member': tags[1]})
            transfer(b, 'pool-selected-b')
            status = next(g for g in command('getAutoSelectors') if g['tag'] == 'proxy')
            check(status['pinned'] == tags[1] and status['selected'] == tags[1] and command('snapshot')['running'] == pool,
                  'manual selection moves traffic to AWG 3.1 while the pool session remains active')
            check(command('profile', {'id': pool})['config'] == cfg, 'runtime member selection leaves the saved pool unchanged')
            audit['pool'] = status
            command('disconnect')

            for mode in ['basic', 'trailers', 'cookies']:
                p = peer('load-' + mode, mode)
                fixed_port = free_port(socket.SOCK_DGRAM)
                config = {**copy.deepcopy(p.info['profile']), 'listen_port': fixed_port}
                pid = save(config, 'AWG cookie load ' + mode)
                p.load()
                command('connect', {'id': pid})
                transfer(p, 'loaded-' + mode)
                s = p.stats()
                cookie_count = s['sentCookiePorts'].get(str(fixed_port), 0)
                mac2_count = s['receivedMac2Ports'].get(str(fixed_port), 0)
                if mode == 'cookies':
                    check(s['underLoadSeen'] and cookie_count == 0 and mac2_count == 0,
                          'disable_cookies serves real tunnel traffic under load without challenging the client')
                else:
                    check(s['underLoadSeen'] and cookie_count > 0 and mac2_count > 0,
                          mode + ': the real client receives a cookie and retries with MAC2 before tunnel traffic succeeds')
                audit['cookies'].append({'mode': mode, 'clientPort': fixed_port, 'stats': s})
                check(command('profile', {'id': pid})['config'] == config, mode + ': cookie exchange preserves stored protocol settings')
                command('disconnect')
    finally:
        for name, action in [('disconnect', lambda: command('disconnect')),
                             ('group', lambda: command('deleteGroup', {'id': group})),
                             ('preferences', lambda: command('preferences', initial['preferences']))]:
            try:
                action()
            except Exception as error:
                audit['cleanupErrors'].append({'step': name, 'error': str(error)})
        (h['artifacts'] / 'awg-migration-audit.json').write_text(json.dumps(audit, indent=2) + '\n')
        assert not audit['cleanupErrors'], audit['cleanupErrors']
    check(command('snapshot')['running'] is None, 'AWG acceptance disconnects and removes its private profiles')
