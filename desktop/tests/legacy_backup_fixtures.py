"""Synthetic import fixtures, encoded independently by the real Qt6 writer.

Regenerate with: python3 legacy_backup_fixtures.py thrbackup_writer.py
The native suite consumes committed archives and needs no Qt development files.
"""
import hashlib
import copy
import base64
import json
import pathlib
import shutil
import sqlite3
import subprocess
import sys
import tempfile

DIRECTORY = pathlib.Path(__file__).with_name('fixtures') / 'legacy-import'
UUID = '00000000-0000-0000-0000-000000000041'
PASSWORD = 'synthetic-legacy-password-never-display'
WIREGUARD_KEY = base64.b64encode(bytes([7]) * 32).decode()
FULL_SINGBOX = {
    'dns': {'servers': [{'type': 'local', 'tag': 'legacy-dns'}], 'final': 'legacy-dns'},
    'route': {'rules': [{'domain': ['legacy-private-domain.example.test'], 'outbound': 'direct'}], 'final': 'direct'},
    'inbounds': [{'type': 'mixed', 'listen': '127.0.0.1', 'listen_port': 31081}],
    'outbounds': [{'type': 'direct', 'tag': 'direct'}],
}
FULL_XRAY = {
    'dns': {'queryStrategy': 'UseIP', 'servers': ['1.1.1.1', '1.0.0.1']},
    'routing': {'domainStrategy': 'IPIfNonMatch', 'rules': [{'type': 'field', 'domain': ['full:legacy-private-domain.example.test'], 'outboundTag': 'direct'}]},
    'inbounds': [{'listen': '127.0.0.1', 'port': 31082, 'protocol': 'socks', 'settings': {'udp': True}}],
    'outbounds': [{'protocol': 'freedom', 'tag': 'direct'}],
}
XRAY = {'protocol': 'vless', 'settings': {'address': '127.0.0.1', 'port': 31083, 'id': UUID, 'encryption': 'none'}, 'streamSettings': {'network': 'grpc', 'security': 'none', 'grpcSettings': {'serviceName': 'legacy-service'}}}


def sources():
    rows = []
    for pid, kind, extra in [
        (41, 'socks', {'version': '5', 'username': 'legacy-user', 'password': PASSWORD}),
        (42, 'http', {'username': 'legacy-user', 'password': PASSWORD}),
        (43, 'shadowsocks', {'method': 'aes-128-gcm', 'password': PASSWORD}),
        (44, 'vmess', {'uuid': UUID, 'security': 'auto', 'alter_id': 0}),
        (45, 'vless', {'uuid': UUID}),
        (46, 'trojan', {'password': PASSWORD, 'tls': {'enabled': True, 'server_name': 'legacy.example.test'}}),
    ]:
        name = 'Legacy ' + kind + (' 🦊' if pid == 41 else '')
        rows.append((pid, kind, name, 0, {'type': kind, 'tag': name, 'server': '127.0.0.1', 'server_port': 31080 + pid, **extra}))
    rows.append((47, 'xrayvless', 'Legacy Xray VLESS', 0, {'tag': 'Legacy Xray VLESS', **XRAY}))
    for pid, subtype, name, config in [
        (48, 'outbound', 'Legacy custom outbound', {'type': 'socks', 'server': '127.0.0.1', 'server_port': 31148, 'password': PASSWORD}),
        (49, 'fullconfig', 'Legacy full sing-box', FULL_SINGBOX),
        (50, 'xrayoutbound', 'Legacy custom Xray outbound', XRAY),
        (51, 'xrayfullconfig', 'Legacy full Xray', FULL_XRAY),
    ]:
        rows.append((pid, 'custom', name, 7, {'type': 'custom', 'name': name, 'subtype': subtype, 'config': json.dumps(config, ensure_ascii=False)}))
    rows.append((52, 'chain', 'Legacy chain', 8, {'type': 'chain', 'name': 'Legacy chain', 'list': [41, 42]}))
    rows.append((53, 'socks', 'Legacy group member', 9, {'type': 'socks', 'tag': 'Legacy group member', 'server': '127.0.0.1', 'server_port': 31153}))
    return rows


GROUPS = [
    (7, 'Legacy subscription 日本', 'https://example.test/synthetic-subscription-secret', '[51,49,48,50]', -1, -1, 'Legacy provider notice', 0, 0, 1710000000),
    (0, 'Legacy ordinary', '', '[47,46,45,44,43,42,41]', -1, -1, '', 0, 0, 0),
    (8, 'Legacy chains', '', '[52]', -1, -1, '', 0, 0, 0),
    (9, 'Legacy front and landing', '', '[53]', 41, 42, '', 0, 0, 0),
]
SECRETS = [PASSWORD, UUID, WIREGUARD_KEY, 'synthetic-subscription-secret', 'synthetic-source-dns-secret', 'legacy-private-domain.example.test', 'metadata-secret-fixture', 'SQLite format 3', 'CREATE TABLE', 'JBSWY3DPEHPK3PXP']


def database(path, blocked=False):
    db = sqlite3.connect(path)
    db.executescript('''
    CREATE TABLE profiles(id INTEGER PRIMARY KEY,type TEXT NOT NULL,name TEXT,gid INTEGER NOT NULL,outbound_json TEXT NOT NULL);
    CREATE TABLE groups(id INTEGER PRIMARY KEY,name TEXT NOT NULL,url TEXT,profiles_json TEXT,front_proxy_id INTEGER,landing_proxy_id INTEGER,info TEXT,archive INTEGER,skip_auto_update INTEGER,sub_last_update INTEGER);
    CREATE TABLE groups_order(group_id INTEGER PRIMARY KEY,display_order INTEGER);
    CREATE TABLE route_profiles(id INTEGER PRIMARY KEY,name TEXT NOT NULL,default_outbound_id INTEGER,raw_route TEXT,is_raw INTEGER);
    CREATE TABLE route_rules(route_profile_id INTEGER,rule_order INTEGER,type INTEGER,domain_json TEXT,outbound TEXT,PRIMARY KEY(route_profile_id,rule_order));
    CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
    CREATE TABLE otp_profiles(id INTEGER PRIMARY KEY,name TEXT,secret TEXT,issuer TEXT);
    CREATE TABLE entity_ids(profile_last_id INTEGER,group_last_id INTEGER);
    ''')
    rows = sources()
    if blocked:
        external = copy.deepcopy(FULL_SINGBOX)
        external['route']['rule_set'] = [{'type': 'local', 'tag': 'private', 'format': 'binary', 'path': '/missing/synthetic-private.srs'}]
        for pid, kind, config in [
            (54, 'autoselector', {'type': 'autoselector', 'list': [41]}),
            (55, 'wireguard', {'type': 'wireguard', 'private_key': WIREGUARD_KEY, 'address': ['10.55.0.2/32'], 'system': True, 'peers': [{'address': '127.0.0.1', 'port': 31555, 'public_key': WIREGUARD_KEY}]}),
            (56, 'extracore', {'type': 'extracore', 'command': 'synthetic-external-core-secret'}),
            (57, 'socks', {'type': 'socks', 'server': '127.0.0.1', 'server_port': 31157, 'future_field': 'synthetic-future-field-secret'}),
            (58, 'custom', {'type': 'custom', 'name': 'Unsupported external resource', 'subtype': 'fullconfig', 'config': json.dumps(external)}),
        ]:
            rows.append((pid, kind, 'Unsupported ' + kind, 0, config))
    for pid, kind, name, gid, config in rows:
        # The ordinary tag/custom name is authoritative, unlike this stale DB label.
        db.execute('INSERT INTO profiles VALUES(?,?,?,?,?)', (pid, kind, 'Database label ' + str(pid), gid, json.dumps(config, ensure_ascii=False)))
    for group in GROUPS:
        db.execute('INSERT INTO groups VALUES(?,?,?,?,?,?,?,?,?,?)', group)
    db.executemany('INSERT INTO groups_order VALUES(?,?)', [(g[0], i) for i, g in enumerate(GROUPS)])
    db.execute('INSERT INTO route_profiles VALUES(?,?,?,?,?)', (5, 'Deferred source route', 41, '', 0))
    db.execute('INSERT INTO route_rules VALUES(?,?,?,?,?)', (5, 0, 0, '["source-client.example.test"]', 'direct'))
    db.executemany('INSERT INTO settings VALUES(?,?)', [('remote_dns', 'https://dns.example.test/synthetic-source-dns-secret'), ('language', '4'), ('remember_id', '41')])
    db.execute('INSERT INTO otp_profiles VALUES(?,?,?,?)', (9, 'Synthetic OTP', 'JBSWY3DPEHPK3PXP', 'Fixture'))
    db.execute('INSERT INTO entity_ids VALUES(?,?)', (58 if blocked else 53, 9))
    db.commit()
    db.close()


def generate(writer):
    DIRECTORY.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='thronium-import-goldens-') as directory:
        root = pathlib.Path(directory)
        for name, blocked in [('valid', False), ('blocked', True)]:
            path = root / (name + '.sqlite')
            database(path, blocked)
            output = root / name
            output.mkdir()
            subprocess.run([str(writer), str(output), str(path)], check=True)
            shutil.copyfile(output / 'parts-31.thrbackup', DIRECTORY / (name + '.thrbackup'))
            if name == 'valid':
                shutil.copyfile(output / 'parts-30.thrbackup', DIRECTORY / 'no-profiles.thrbackup')
    manifest = {'writer': 'desktop/tests/thrbackup_writer.py: byte for byte the Qt6 QDataStream Qt_6_0 little-endian writer', 'data': 'Synthetic loopback profiles only; archives are never executed by this fixture generator.', 'validProfiles': len(sources()), 'validGroups': len(GROUPS), 'sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(DIRECTORY.glob('*.thrbackup'))}}
    (DIRECTORY / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    generate(pathlib.Path(sys.argv[1]))
