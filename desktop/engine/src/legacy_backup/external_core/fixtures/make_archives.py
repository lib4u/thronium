#!/usr/bin/env python3
"""Synthetic reader-to-policy fixtures; no production converter or executable is run."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('writer', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    out = root / 'archives'
    out.mkdir(exist_ok=True)
    complete = json.loads((root / 'inputs.json').read_text())[0]['source']
    baseline = [
        (41, 'extracore', 'Stale database41', 0, complete),
        (42, 'extracore', 'Fallback database42', 0,
         {'type': 'extracore', 'socks_port': 19081, 'extra_core_path': '/missing/synthetic-helper2'}),
        (43, 'socks', 'Stale database43', 0,
         {'type': 'socks', 'tag': 'Ordinary TCP', 'server': '127.0.0.1', 'server_port': 19082}),
    ]
    variants = [
        ('standalone', 'accept3profiles1group', [0, 1, 5, 31]),
        ('chain', 'legacy_chain_hop_unsupported', [31]),
        ('containing-front', 'legacy_group_chain_unsupported', [31]),
        ('other-empty-group-front', 'legacy_group_chain_unsupported', [31]),
        ('selector-member', 'legacy_selector_member_unsupported', [31]),
        ('selector-pool-only', 'accept4profiles1group-with-explicit-last-built', [31]),
        ('route-target', 'accept-profiles; selected-routes-legacy_route_target_unsupported', [31]),
        ('missing-port', 'legacy-external-port-error; Parts30-excludes-profiles', [30, 31]),
        ('relative-path', 'legacy-external-path-error', [31]),
    ]
    metadata = {}
    for name, expected, masks in variants:
        rows = copy.deepcopy(baseline)
        group_ids = [42, 41, 43]
        if name in ('chain', 'selector-member', 'selector-pool-only'):
            if name == 'chain':
                kind, config = 'chain', {'type': 'chain', 'name': 'Unsupported external chain', 'list': [41, 43]}
            else:
                kind = 'autoselector'
                config = {'type': kind, 'name': 'Snapshot source', 'gid': 0, 'last_built': [41] if name == 'selector-member' else [43],
                          'pool': [41, 43], 'pinned_id': 41 if name == 'selector-member' else 43}
            rows.append((44, kind, 'Stale database44', 0, config))
            group_ids.append(44)
        if name == 'missing-port':
            rows[0][4].pop('socks_port')
        if name == 'relative-path':
            rows[0][4]['extra_core_path'] = './original-install/helper'
        groups = [(0, 'Standalone imported group', '', json.dumps(group_ids), 43 if name == 'containing-front' else -1, -1, '', 0, 0, 0)]
        if name == 'other-empty-group-front':
            groups.append((7, 'Empty group referencing external', '', '[]', 41, -1, '', 0, 0, 0))
        path = out / (name + '.sqlite')
        if path.exists():
            path.unlink()
        db = sqlite3.connect(path)
        db.executescript('''
        CREATE TABLE profiles(id INTEGER PRIMARY KEY,type TEXT NOT NULL,name TEXT,gid INTEGER NOT NULL,outbound_json TEXT NOT NULL);
        CREATE TABLE groups(id INTEGER PRIMARY KEY,name TEXT NOT NULL,url TEXT,profiles_json TEXT,front_proxy_id INTEGER,landing_proxy_id INTEGER,info TEXT,archive INTEGER,skip_auto_update INTEGER,sub_last_update INTEGER);
        CREATE TABLE groups_order(group_id INTEGER PRIMARY KEY,display_order INTEGER);
        CREATE TABLE route_profiles(id INTEGER PRIMARY KEY,name TEXT NOT NULL,default_outbound_id INTEGER,raw_route TEXT,is_raw INTEGER);
        CREATE TABLE route_rules(route_profile_id INTEGER,rule_order INTEGER,type INTEGER,PRIMARY KEY(route_profile_id,rule_order));
        CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE otp_profiles(id INTEGER PRIMARY KEY,name TEXT,secret TEXT);
        CREATE TABLE entity_ids(profile_last_id INTEGER,group_last_id INTEGER);
        ''')
        db.executemany('INSERT INTO profiles VALUES(?,?,?,?,?)', [(i, t, n, g, json.dumps(c, ensure_ascii=False)) for i, t, n, g, c in rows])
        db.executemany('INSERT INTO groups VALUES(?,?,?,?,?,?,?,?,?,?)', groups)
        db.executemany('INSERT INTO groups_order VALUES(?,?)', [(g[0], i) for i, g in enumerate(groups)])
        route = {'rules': [], 'final': 41 if name == 'route-target' else 'direct'}
        db.execute('INSERT INTO route_profiles VALUES(?,?,?,?,?)', (5, 'Independent imported route', -2, json.dumps(route), 1))
        settings = [('remember_id', '41'), ('extra_core_paths', '["./old-install/history-only"]'),
                    ('use_dns_object', 'true'), ('dns_object', json.dumps({'servers': [{'type': 'udp', 'tag': 'fixture-dns', 'server': '127.0.0.1', 'server_port': 19535}], 'final': 'fixture-dns'}))]
        db.executemany('INSERT INTO settings VALUES(?,?)', settings)
        db.execute('INSERT INTO entity_ids VALUES(?,?)', (44, 7))
        db.commit()
        db.close()
        with tempfile.TemporaryDirectory(prefix='thronium-external-archive-') as directory:
            subprocess.run([args.writer.resolve(), directory, path], check=True, stdout=subprocess.DEVNULL)
            for mask in masks:
                destination = out / (name + '-parts-' + str(mask).zfill(2) + '.thrbackup')
                shutil.copyfile(Path(directory) / ('parts-' + str(mask).zfill(2) + '.thrbackup'), destination)
                metadata[destination.name] = dict(partsMask=mask, sourceSQLite=path.name, sourceProfiles=len(rows), sourceGroups=len(groups),
                    plannedConverterOutcome=expected if mask & 1 else 'profiles-excluded-by-Parts; never-import-or-execute-source-profiles', sha256=sha(destination))
    manifest = dict(status='Real Qt archives generated; converter expectations are planned until production activation.',
                    writer=str(args.writer.resolve()), writerSHA256=sha(args.writer), generatorSHA256=sha(Path(__file__)),
                    archives=metadata, sqliteSHA256={p.name: sha(p) for p in sorted(out.glob('*.sqlite'))})
    (out / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(dict(archives=len(metadata), databases=len(variants), output=str(out))))


if __name__ == '__main__':
    main()
