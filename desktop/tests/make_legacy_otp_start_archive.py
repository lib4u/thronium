#!/usr/bin/env python3
"""Qt before-Start OTP fixture from frozen Qt exports and database DDL."""
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile

import qt_snapshot

DESKTOP = Path(__file__).resolve().parents[1]
FIXTURES = DESKTOP / 'tests/fixtures/legacy-vpn-bindings'


def generate():
    sources = FIXTURES / 'source-inputs'
    cases = {row['name']: row['qtExport'] for row in json.loads((sources / 'qt-cases.json').read_text())}
    writer = DESKTOP / 'tests/thrbackup_writer.py'
    source_hashes = {}
    with tempfile.TemporaryDirectory(prefix='thronium-qt-start-otp-') as temporary:
        root = Path(temporary)
        database = root / 'synthetic.sqlite'
        with sqlite3.connect(database) as db:
            for repo in ('GroupsRepo', 'ProfilesRepo', 'OtpProfilesRepo'):
                statements = qt_snapshot.ddl(repo)
                source_hashes[repo + '.cpp'] = qt_snapshot.source_sha(repo)
                for statement in statements:
                    if 'CREATE TABLE' in statement:
                        db.execute(statement)
            db.execute('ALTER TABLE profiles ADD COLUMN latency_at INTEGER NOT NULL DEFAULT 0')
            db.execute("INSERT INTO groups(id,name,profiles_json,created_at,updated_at) VALUES(7,'Qt OTP start','[41,17]',1,2)")
            db.execute('INSERT INTO groups_order VALUES(7,0)')
            for id, otp, name in ((17, 41, 'ovpn-bound-credential-placeholder'), (41, 17, 'oc-bound-form')):
                config = {**cases[name], 'otp_profile_id': otp}
                db.execute('INSERT INTO profiles(id,type,name,gid,outbound_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?)',
                           (id, config['type'], name, 7, json.dumps(config), 1, 2))
            for id in (41, 17):
                db.execute('INSERT INTO otp_profiles(id,name,issuer,secret,algorithm,type,digits,period,counter,sort_order,created_at,updated_at) VALUES(?,?,?,?,0,1,6,30,?,0,1,2)',
                           (id, 'Same name', 'Synthetic RFC4226', 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 9007199254740993))
        output = root / 'qt'
        output.mkdir()
        version = subprocess.check_output([str(writer), str(output), str(database)], text=True).strip()
        target = FIXTURES / 'start-otp-parts-09.thrbackup'
        shutil.copy2(output / 'parts-09.thrbackup', target)
    manifest = json.loads((FIXTURES / 'manifest.json').read_text())
    manifest['archives'][target.name] = {'parts': 9, 'sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
                                      'qtWriter': version, 'writerSha256': hashlib.sha256(writer.read_bytes()).hexdigest(),
                                      'sourceDdl': source_hashes, 'beforeStartOtp': True}
    (FIXTURES / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    generate()
