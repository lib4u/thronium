"""Qt QDataStream archive with references to three absent policy resources."""
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import qt_snapshot

DESKTOP = Path(__file__).resolve().parents[1]


def generate(output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    writer = DESKTOP / 'tests/thrbackup_writer.py'
    files = output / 'selected-files'
    files.mkdir()
    (files / 'custom.hosts').write_text('127.0.0.1 resource.fixture.invalid\n')
    (files / 'local.json').write_text(json.dumps({'version': 3, 'rules': [{'domain': ['resource.fixture.invalid']}]}))
    shutil.copy2(DESKTOP / 'tests/fixtures/tray-controls/loopback.srs', files / 'loopback.srs')
    dns = {'servers': [{'type': 'hosts', 'tag': 'saved-hosts', 'path': ['/old/Throne DNS/custom.hosts']}], 'final': 'saved-hosts'}
    route = {'final': -2, 'default_domain_resolver': 'saved-hosts',
             'rule_set': [{'type': 'local', 'tag': 'source-set', 'path': '/old/Throne rules/local.json'},
                          {'type': 'local', 'tag': 'binary-set', 'format': 'binary', 'path': '/old/Throne rules/loopback.srs'}],
             'rules': [{'rule_set': ['source-set'], 'outbound': -2}, {'rule_set': ['binary-set'], 'action': 'reject'}]}
    with tempfile.TemporaryDirectory(prefix='thronium-qt-resources-') as temporary:
        root = Path(temporary)
        database = root / 'fixture.sqlite'
        with sqlite3.connect(database) as db:
            for ddl in qt_snapshot.ddl('RoutesRepo', 2):
                db.execute(ddl)
            db.execute('CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
            db.executemany('INSERT INTO settings VALUES(?,?)', [('use_dns_object', 'true'), ('dns_object', json.dumps(dns))])
            db.execute('INSERT INTO route_profiles(id,name,is_raw,raw_route,prevent_modifications,created_at,updated_at) VALUES(1,?,1,?,1,1,1)', ('Qt local resources', json.dumps(route)))
        qt = root / 'qt'; qt.mkdir()
        version = subprocess.check_output([str(writer), str(qt), str(database)], text=True).strip()
        archive = output / 'local-resources.thrbackup'
        shutil.copy2(qt / 'parts-06.thrbackup', archive)
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    manifest = {'qtRuntime': version, 'writerSha256': sha(writer), 'ddlSha256': qt_snapshot.source_sha('RoutesRepo'),
                'archiveSha256': sha(archive), 'resources': {p.name: sha(p) for p in files.iterdir()}, 'dns': dns, 'route': route}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return archive, files, manifest
