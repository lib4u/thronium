"""Owned SQLite from Qt DDL, serialized by the existing Qt QDataStream writer."""
import hashlib, json, shutil, sqlite3, subprocess, tempfile
from pathlib import Path
import qt_snapshot
REPO=Path(__file__).resolve().parents[2]

def generate(output, url):
    output=Path(output);output.mkdir(parents=True,exist_ok=True)
    ddl=qt_snapshot.ddl('RoutesRepo',2)
    writer=REPO/'desktop/tests/thrbackup_writer.py'
    dns={'servers':[{'type':'local','tag':'dns-direct'}], 'rules':[{'domain':'record.fixture.invalid','query_type':'A','action':'predefined','answer':'*. 120 IN A 127.0.0.53','ns':[],'extra':[]}], 'final':'dns-direct'}
    raw={'rule_set':[{'type':'inline','tag':'raw-sites','rules':[{'domain_suffix':['raw.fixture.invalid']}]}],'rules':[{'rule_set':['raw-sites'],'outbound':-2}]}
    with tempfile.TemporaryDirectory(prefix='thronium-route-policy-') as folder:
        folder=Path(folder);database=folder/'routes.sqlite'
        with sqlite3.connect(database) as db:
            for statement in ddl:db.execute(statement)
            db.execute('CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
            db.executemany('INSERT INTO settings VALUES(?,?)',[('use_dns_object','true'),('dns_object',json.dumps(dns))])
            db.execute('INSERT INTO route_profiles(id,name,is_raw,raw_route,prevent_modifications,created_at,updated_at) VALUES(1,?,1,?,1,1,1)',('Qt raw verbatim',json.dumps(raw)))
            db.execute('INSERT INTO route_profiles(id,name,is_remote,remote_url,auto_update,remote_last_update,created_at,updated_at) VALUES(2,?,1,?,1,5,1,1)',('Qt remote rules',url))
            db.execute('INSERT INTO route_rules(route_profile_id,rule_order,name,type,domain_suffix_json,outbound_id) VALUES(2,0,?,2,?,-2)',('Original rule','["original.fixture.invalid"]'))
            db.execute('INSERT INTO route_rules(route_profile_id,rule_order,name,type,rule_set_json,outbound_id) VALUES(2,1,?,0,?,-3)',('Owned block set',json.dumps([url.replace('/routing','/block.srs')])))
        qt=folder/'qt';qt.mkdir()
        version=subprocess.check_output([str(writer),str(qt),str(database)],text=True).strip()
        archive=output/'route-policies.thrbackup';shutil.copy2(qt/'parts-06.thrbackup',archive)
    manifest={'qtRuntime':version,'writerSHA256':hashlib.sha256(writer.read_bytes()).hexdigest(),'archiveSHA256':hashlib.sha256(archive.read_bytes()).hexdigest(),'ddlSHA256':qt_snapshot.source_sha('RoutesRepo'),'dns':dns,'raw':raw}
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    return archive,manifest
