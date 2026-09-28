"""Independent actual Qt archives and original Qt DNS expectations for DoQ tests."""
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import qt_snapshot

REPO = Path(__file__).resolve().parents[2]
# Writes archives byte for byte as Qt-Throne does (see thrbackup_writer.py).
WRITER = Path(__file__).resolve().with_name('thrbackup_writer.py')
ORACLE = REPO / 'desktop/test-results/continuous-migration-validation/legacy-quic-dns-research/qt-pure-oracle'


def generate(output, ports, writer=WRITER, oracle=ORACLE):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    ddl = qt_snapshot.ddl('RoutesRepo', 2)
    common = {'remote_dns': f"tcp://127.0.0.1:{ports['tcp']}",
              'direct_dns': f"quic://127.0.0.1:{ports['direct']}",
              'core_box_underlying_dns': f"tcp://127.0.0.1:{ports['tcp']}",
              'dns_final_out': 'direct', 'dns_disable_cache': 'true',
              'use_dns_object': 'false', 'dns_object': 'inactive-fixture-secret-not-json'}
    cases = [
        ('direct', {}, 7, None),
        ('bootstrap', {'direct_dns': f"tcp://resolver.fixture.invalid:{ports['tcp']}", 'core_box_underlying_dns': f"quic://127.0.0.1:{ports['bootstrap']}"}, 7, None),
        ('both', {'core_box_underlying_dns': f"quic://127.0.0.1:{ports['bootstrap']}"}, 7, None),
        ('default-port', {'direct_dns': 'quic://127.0.0.1', 'core_box_underlying_dns': 'quic://127.0.0.2'}, 7, None),
        ('direct-hostname', {'direct_dns': f"quic://resolver.fixture.invalid:{ports['direct']}"}, 7, None),
        ('bootstrap-hostname', {'core_box_underlying_dns': 'quic://resolver.fixture.invalid'}, 7, 'legacy_dns_bootstrap_hostname_unsupported'),
        ('remote-quic', {'remote_dns': f"quic://127.0.0.1:{ports['direct']}", 'dns_final_out': 'remote'}, 7, None),
        ('remote-udp', {'remote_dns': '127.0.0.1:8853', 'dns_final_out': 'remote'}, 7, None),
        ('no-settings', {}, 3, 'legacy_route_parts_required'),
        ('no-routes', {}, 5, 'legacy_route_parts_required'),
    ]
    manifest = {'qtRuntime': None, 'writerSHA256': hashlib.sha256(writer.read_bytes()).hexdigest(),
                'oracleSHA256': hashlib.sha256(oracle.read_bytes()).hexdigest(),
                'routeSchemaSHA256': qt_snapshot.source_sha('RoutesRepo'), 'cases': []}
    with tempfile.TemporaryDirectory(prefix='thronium-doq-archives-') as folder:
        folder = Path(folder)
        for name, override, mask, error in cases:
            settings = {**common, **override}
            database = folder / (name + '.sqlite')
            with sqlite3.connect(database) as db:
                for statement in ddl:
                    db.execute(statement)
                db.executescript('''CREATE TABLE profiles(id INTEGER PRIMARY KEY,type TEXT NOT NULL,name TEXT,gid INTEGER NOT NULL,outbound_json TEXT NOT NULL);
CREATE TABLE groups(id INTEGER PRIMARY KEY,name TEXT NOT NULL,profiles_json TEXT,front_proxy_id INTEGER,landing_proxy_id INTEGER,url TEXT);
CREATE TABLE groups_order(group_id INTEGER PRIMARY KEY,display_order INTEGER);
CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);''')
                db.execute('INSERT INTO profiles VALUES(11,?,?,0,?)', ('socks','DoQ fixture source',json.dumps({'type':'socks','server':'127.0.0.1','server_port':19099,'version':'5'})))
                db.execute('INSERT INTO groups VALUES(0,?,?,-1,-1,?)', ('DoQ fixture group','[11]',''))
                db.execute('INSERT INTO groups_order VALUES(0,0)')
                db.execute('INSERT INTO route_profiles(id,name,default_outbound_id,created_at,updated_at) VALUES(7,?,-2,1,1)', ('DoQ imported ' + name,))
                db.executemany('INSERT INTO settings VALUES(?,?)', settings.items())
            target = folder / (name + '-qt')
            target.mkdir()
            subprocess.run([str(writer), str(target), str(database)], check=True, capture_output=True)
            archive = output / (name + '.thrbackup')
            shutil.copy2(target / f'parts-{mask:02d}.thrbackup', archive)
            entry = {'name':name,'parts':mask,'sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'settings':settings,'expectedError':error}
            if error is None:
                inputs = folder / (name + '.json')
                inputs.write_text(json.dumps([{'id':name,'settings':settings,'rules':[]}]))
                qt = json.loads(subprocess.check_output([str(oracle),str(inputs)], text=True))
                assert qt['results'][0]['error'] == ''
                manifest['qtRuntime'] = qt['qtRuntime']
                entry['expectedDNS'] = qt['results'][0]['dns']
            manifest['cases'].append(entry)
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


if __name__ == '__main__':
    generate(REPO / 'desktop/engine/tests/fixtures/legacy-quic/archives', {'direct':8853,'bootstrap':8854,'tcp':8855})
