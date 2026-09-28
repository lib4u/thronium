"""Qt archive of a generated owned WARP identity, using original SQLite DDL."""
import json
from pathlib import Path
import sqlite3
import subprocess
import qt_snapshot


def prepare(ready_path, writer):
    ready_path = Path(ready_path); info = json.loads(ready_path.read_text()); root = ready_path.parent
    ddl = qt_snapshot.ddl('SettingsRepo')[0]
    profile = info['profile']; peer = profile['peers'][0]
    rows = {'enable_warp': 'true', 'warp_private_key': profile['private_key'],
            'warp_public_key': peer['public_key'], 'warp_ifc_addrs': json.dumps(profile['address']),
            'warp_ep': info['endpoint'], 'warp_reserved': '["0","128","255"]'}
    db_path = root / 'synthetic-warp.sqlite'
    with sqlite3.connect(db_path) as db:
        db.execute(ddl)
        db.executemany('INSERT INTO settings(key,value) VALUES(?,?)', rows.items())
    db_path.chmod(0o600)
    archives = root / 'qt-archives'; archives.mkdir(mode=0o700)
    qt = subprocess.check_output([str(writer), str(archives), str(db_path)], text=True).strip()
    for p in archives.iterdir(): p.chmod(0o600)
    info.update(archive=str(archives / 'parts-04.thrbackup'), sourceRows=rows, qtRuntime=qt)
    # A second archive exercises the linked route/WARP import, using the same
    # independent peer. Keep the original settings-only fixture unchanged.
    with sqlite3.connect(db_path) as db:
        for ddl in qt_snapshot.ddl('RoutesRepo'):
            if 'CREATE TABLE' in ddl: db.execute(ddl)
        route = {'final': -5, 'auto_detect_interface': False, 'rules': [{'domain': ['warp.fixture.test'], 'outbound': -1}]}
        db.execute('INSERT INTO route_profiles(id,name,is_raw,raw_route) VALUES(1,?,1,?)', ('Imported WARP policy', json.dumps(route)))
        dns = {'servers': [{'tag': 'dns-direct', 'type': 'udp', 'server': '127.0.0.1'}], 'final': 'dns-direct'}
        db.executemany('INSERT INTO settings(key,value) VALUES(?,?)', [('use_dns_object', 'true'), ('dns_object', json.dumps(dns))])
    linked = root / 'qt-linked-archives'; linked.mkdir(mode=0o700)
    subprocess.check_output([str(writer), str(linked), str(db_path)], text=True)
    for p in linked.iterdir(): p.chmod(0o600)
    info['linkedArchive'] = str(linked / 'parts-06.thrbackup')
    ready_path.write_text(json.dumps(info, indent=2) + '\n'); ready_path.chmod(0o600)
