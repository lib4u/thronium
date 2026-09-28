from pathlib import Path
import copy,json,os,sqlite3,subprocess,sys
from legacy_backup_fixtures import database

def prepare(ready_path,writer):
    ready_path=Path(ready_path);info=json.loads(ready_path.read_text());root=ready_path.parent
    dbpath=root/'synthetic-source.sqlite';database(dbpath);dbpath.chmod(0o600)
    config=copy.deepcopy(info['profile']);config.update(tag='Legacy live AWG peer',worker_count=2)
    config['address']=[address.split('/')[0] for address in config['address']]
    with sqlite3.connect(dbpath) as db:
        for table in ['profiles','groups','groups_order','route_profiles','route_rules','settings','otp_profiles','entity_ids']:db.execute('DELETE FROM '+table)
        db.execute('INSERT INTO profiles VALUES(?,?,?,?,?)',(43,'wireguard','Stale database label',43,json.dumps(config)))
        db.execute('INSERT INTO groups VALUES(?,?,?,?,?,?,?,?,?,?)',(43,'Owned legacy live AWG group','','[43]',-1,-1,'',0,0,0))
        db.execute('INSERT INTO groups_order VALUES(?,?)',(43,0))
        db.execute('INSERT INTO entity_ids VALUES(?,?)',(43,43))
    archives=root/'qt-archives';archives.mkdir(mode=0o700)
    result=subprocess.run([str(writer),str(archives),str(dbpath)],check=True,capture_output=True,text=True)
    for p in archives.iterdir():p.chmod(0o600)
    info['archive']=str(archives/'parts-31.thrbackup');info['qtVersion']=result.stdout.strip()
    ready_path.write_text(json.dumps(info,indent=2)+'\n');ready_path.chmod(0o600)
