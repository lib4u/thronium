"""Synthetic external profiles encoded by actual Qt6, with no executable in archives.

Static fixtures use a deliberately absent absolute executable. Native traffic
fixtures replace only that source DTO before the real Qt writer encodes SQLite.
"""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import qt_snapshot

ROOT = Path(__file__).resolve().parents[2]
DIRECTORY = Path(__file__).with_name('fixtures') / 'legacy-external-core'
# Writes archives byte for byte as Qt-Throne does (see thrbackup_writer.py).
DEFAULT_WRITER = Path(__file__).resolve().with_name('thrbackup_writer.py')
PRIVATE = 'legacy-external-synthetic-private-value'
CONFIG = {
    'type': 'extracore', 'name': 'Legacy external 日本',
    'socks_address': '127.0.0.1', 'socks_port': 31981,
    'extra_core_path': '/absent/legacy external/foreground helper',
    'extra_core_args': '  --config %s --literal "two words" --literal "" --literal "$HOME %d"  ',
    'extra_core_conf': ' \r\n\t' + PRIVATE + '\r\nopaque: [not JSON]\n ',
    'no_logs': False,
}
MODES = ['valid', 'relative-path', 'unknown-field', 'chain', 'containing-wrapper',
         'empty-group-wrapper', 'selector-member', 'selector-pool']


def ddls(repo, count):
    values = qt_snapshot.ddl(repo, count)
    assert all('CREATE TABLE' in v for v in values)
    return values


def database(path, mode='valid', config=None):
    full = copy.deepcopy(config or CONFIG)
    minimal = {'type': 'extracore', 'socks_port': full['socks_port'],
               'extra_core_path': '/absent/legacy external/no-executable'}
    empty = {**copy.deepcopy(full), 'name': 'Legacy empty launch fields',
             'extra_core_args': '', 'extra_core_conf': '', 'no_logs': True}
    rows = [(11, 'extracore', 'Stale SQL name 11', full),
            (12, 'extracore', 'Legacy fallback label', minimal),
            (13, 'socks', 'Stale SQL name 13', {'type': 'socks', 'tag': 'Ordinary preserved source',
             'server': '127.0.0.1', 'server_port': 31983}),
            (14, 'extracore', 'Stale SQL name 14', empty)]
    order = [12, 11, 14, 13]
    front, groups = -1, []
    if mode == 'relative-path': full['extra_core_path'] = './' + PRIVATE
    if mode == 'unknown-field': full['env'] = {'TOKEN': PRIVATE}
    if mode == 'chain':
        rows.append((15, 'chain', 'SQL chain', {'type': 'chain', 'name': 'Unsupported external chain', 'list': [13, 11]})); order.insert(0, 15)
    if mode == 'containing-wrapper': front = 13
    if mode == 'empty-group-wrapper': groups.append((8, 'Empty group with external front', '[]', 11, -1))
    if mode in ['selector-member', 'selector-pool']:
        rows.append((15, 'autoselector', 'SQL selector', {'type': 'autoselector', 'name': 'Saved selector source',
             'gid': 7, 'last_built': [11] if mode == 'selector-member' else [13], 'pool': [11, 13]})); order.insert(0, 15)
    with sqlite3.connect(path) as db:
        for repo, count in [('GroupsRepo', 2), ('ProfilesRepo', 1), ('RoutesRepo', 2), ('SettingsRepo', 1), ('OtpProfilesRepo', 1)]:
            for ddl in ddls(repo, count): db.execute(ddl)
        groups.insert(0, (7, 'Legacy external group', json.dumps(order), front, -1))
        for index, (gid, name, members, first, last) in enumerate(groups):
            db.execute('INSERT INTO groups(id,name,profiles_json,front_proxy_id,landing_proxy_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?)', (gid, name, members, first, last, 1, 1))
            db.execute('INSERT INTO groups_order VALUES(?,?)', (gid, index))
        for pid, kind, name, value in rows:
            db.execute('INSERT INTO profiles(id,type,name,gid,outbound_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?)', (pid, kind, name, 7, json.dumps(value, ensure_ascii=False), 1, 1))
        db.execute('INSERT INTO route_profiles(id,name,default_outbound_id,created_at,updated_at) VALUES(?,?,?,?,?)', (5, 'Source route to external', -1, 1, 1))
        db.execute('INSERT INTO route_rules(route_profile_id,rule_order,type,domain_suffix_json,outbound_id) VALUES(?,?,?,?,?)', (5, 0, 1, '["external-source.example.test"]', 11))
        db.executemany('INSERT INTO settings(key,value) VALUES(?,?)', [
            ('language', '4'), ('log_auto_scroll', 'false'), ('remember_id', '11'),
            ('extra_core_paths', PRIVATE), ('use_dns_object', 'true'),
            ('dns_object', json.dumps({'servers': [{'type': 'udp', 'tag': 'dns-direct', 'server': '127.0.0.1', 'server_port': 31989}], 'final': 'dns-direct'}))])
    return {'profiles': len(rows), 'groups': len(groups), 'order': order,
            'configs': {str(pid): value for pid, _, _, value in rows},
            'names': {str(pid): value.get('name') or value.get('tag') or name for pid, _, name, value in rows}}


def generate(writer, destination=DIRECTORY, config=None, modes=MODES):
    writer, destination = Path(writer), Path(destination)
    assert writer.is_file(), 'Actual Qt golden writer is required'
    destination.mkdir(parents=True, exist_ok=True)
    manifest = {'writer': 'desktop/tests/thrbackup_writer.py',
                'writerExecutableSha256': hashlib.sha256(writer.read_bytes()).hexdigest(),
                'archiveContainsExecutable': False, 'partsMask': 7, 'cases': {}}
    with tempfile.TemporaryDirectory(prefix='thronium-legacy-external-qt-') as temporary:
        root = Path(temporary)
        for mode in modes:
            source = root / (mode + '.sqlite'); expected = database(source, mode, config)
            output = root / mode; output.mkdir()
            manifest['qtRuntime'] = subprocess.check_output([str(writer), str(output), str(source)], text=True).strip()
            shutil.copyfile(output / 'parts-07.thrbackup', destination / (mode + '.thrbackup'))
            manifest['cases'][mode + '.thrbackup'] = expected
            if mode == 'valid':
                for name, mask in [('excluded-profiles', 6), ('excluded-settings', 3)]:
                    shutil.copyfile(output / f'parts-{mask:02d}.thrbackup', destination / (name + '.thrbackup'))
                    manifest['cases'][name + '.thrbackup'] = {**expected, 'partsMask': mask}
    manifest['sha256'] = {name: hashlib.sha256((destination / name).read_bytes()).hexdigest() for name in manifest['cases']}
    (destination / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    return manifest


if __name__ == '__main__':
    result = generate(Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_WRITER)
    print(f"Qt {result['qtRuntime']}: {len(result['cases'])} synthetic external archives")
