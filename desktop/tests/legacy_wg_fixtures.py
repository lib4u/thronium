"""Real Qt archives for the additional userspace WireGuard/AWG import slice."""
import base64
import copy
import hashlib
import json
import pathlib
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from legacy_backup_fixtures import database

DIRECTORY = pathlib.Path(__file__).with_name('fixtures') / 'legacy-wireguard'
KEY = base64.b64encode(bytes([11]) * 32).decode()
PUBLIC = base64.b64encode(bytes([12]) * 32).decode()
PRESHARED = base64.b64encode(bytes([13]) * 32).decode()
HEADER = base64.b64encode(bytes([14]) * 32).decode()
BASIC = {
    'type': 'wireguard', 'tag': 'Legacy userspace WG 🦊', 'private_key': KEY,
    'address': ['10.51.0.2', 'fd51::2'], 'worker_count': 2, 'udp_timeout': '45s',
    'peers': [
        {'address': '127.0.0.1', 'port': 31501, 'public_key': PUBLIC, 'pre_shared_key': PRESHARED, 'reserved': [1, 2, 3], 'persistent_keepalive_interval': '15-30'},
        {'address': '::1', 'port': 31502, 'public_key': KEY, 'allowed_ips': ['10.0.0.0/8', 'fd00::/8'], 'persistent_keepalive_interval': 25},
    ],
}
AWG = {
    'type': 'wireguard', 'tag': 'Legacy AmneziaWG 3.x', 'private_key': PRESHARED,
    'address': ['10.52.0.2/32', 'fd52::2/128'], 'mtu': 1380,
    'amnezia_wg': {
        'jc': 3, 'jmin': 40, 'jmax': 70, 's1': 16, 's2': 32, 's3': 48, 's4': 64,
        'h1': '1-100', 'h2': '101-200', 'h3': '201-300', 'h4': '301-400',
        'i1': '<b 0xabcdef>', 'i2': '<b 0x112233>', 'i3': '<b 0x445566>', 'i4': '<b 0x778899>', 'i5': '<b 0xaabbcc>',
        'header_protection_key': HEADER, 'content_padding_addition': '7-14',
        'rekey_after_time': 90, 'rekey_timeout': '5-10', 'reject_after_time': 180,
        'keepalive_timeout': '10-15', 'max_handshake_attempts': '3-5',
        'random_trailers': True, 'disable_cookies': False,
    },
    'peers': [
        {'address': '127.0.0.1', 'port': 31503, 'public_key': KEY, 'pre_shared_key': PRESHARED, 'allowed_ips': ['0.0.0.0/0'], 'persistent_keepalive_interval': 25},
        {'address': '::1', 'port': 31504, 'public_key': PUBLIC, 'allowed_ips': ['::/0'], 'persistent_keepalive_interval': '15-30'},
    ],
}
SECRETS = [KEY, PUBLIC, PRESHARED, HEADER, '<b 0xabcdef>', 'synthetic-post-up-never-run']


def normalized(config):
    expected = copy.deepcopy(config)
    if 'worker_count' in expected:
        expected['workers'] = expected.pop('worker_count')
    expected.setdefault('mtu', 1420)
    expected.setdefault('system', False)
    expected['address'] = [address if '/' in address else address + ('/128' if ':' in address else '/32') for address in expected['address']]
    for peer in expected['peers']:
        peer.setdefault('allowed_ips', ['0.0.0.0/0', '::/0'])
    return expected


def generate(writer):
    DIRECTORY.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='thronium-legacy-wg-fixture-') as temporary:
        root = pathlib.Path(temporary)
        for name, blocked in [('valid', False), ('blocked', True)]:
            path = root / (name + '.sqlite')
            database(path)
            db = sqlite3.connect(path)
            for table in ['profiles', 'groups', 'groups_order', 'route_profiles', 'route_rules', 'settings', 'otp_profiles', 'entity_ids']:
                db.execute('DELETE FROM ' + table)
            rows = [(501, BASIC), (502, AWG)]
            if blocked:
                rows += [
                    (503, {**copy.deepcopy(BASIC), 'tag': 'Unsupported system WG', 'system': True}),
                    (504, {**copy.deepcopy(BASIC), 'tag': 'Unsupported OS directive WG', 'post_up': 'synthetic-post-up-never-run'}),
                    (505, {**copy.deepcopy(BASIC), 'tag': 'Conflicting workers WG', 'workers': 3}),
                ]
            for pid, config in rows:
                db.execute('INSERT INTO profiles VALUES(?,?,?,?,?)', (pid, 'wireguard', 'Source database label ' + str(pid), 21, json.dumps(config)))
            order = [502, 501] + ([503, 504, 505] if blocked else [])
            db.execute('INSERT INTO groups VALUES(?,?,?,?,?,?,?,?,?,?)', (21, 'Legacy WG group', '', json.dumps(order), -1, -1, '', 0, 0, 0))
            db.execute('INSERT INTO groups_order VALUES(?,?)', (21, 0))
            db.execute('INSERT INTO entity_ids VALUES(?,?)', (505 if blocked else 502, 21))
            db.commit()
            db.close()
            output = root / name
            output.mkdir()
            subprocess.run([str(writer), str(output), str(path)], check=True)
            shutil.copyfile(output / 'parts-31.thrbackup', DIRECTORY / (name + '.thrbackup'))
    manifest = {
        'writer': 'desktop/tests/thrbackup_writer.py: byte for byte the Qt6 QDataStream Qt_6_0 little-endian writer',
        'data': 'Synthetic loopback WireGuard/AWG keys and endpoints only; generator never connects them.',
        'validProfiles': 2, 'validGroups': 1, 'blockedProfiles': 5,
        'sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(DIRECTORY.glob('*.thrbackup'))},
    }
    (DIRECTORY / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    generate(pathlib.Path(sys.argv[1]))
