"""Actual Qt binary backup fixtures for explicitly chosen selector snapshots."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from legacy_backup_fixtures import database as base_database, sources as base_sources, GROUPS, WIREGUARD_KEY, SECRETS as BASE_SECRETS
import qt_snapshot

DIRECTORY = Path(__file__).with_name('fixtures') / 'legacy-selector'
TEST_URL = 'http://127.0.0.1:31089/synthetic-selector-probe-secret'
CONNECTIVITY_URL = 'http://127.0.0.1:31089/synthetic-selector-online-secret'
SELECTORS = [
    (54, 0, {'type':'autoselector','name':'Legacy saved selector 🦊','gid':0,'last_built':[45,47],
             'pool':[47,41,45],'pinned_id':47,'name_filter':'(?<=source-only)unmatched',
             'country_filter':'ZZ','exclude_unavailable':True,'pool_cap':2,'build_limit':1,
             'last_built_at':1750000000,'pool_ranked_at':1750000001,
             'history':[{'id':41,'first':1,'last':2,'builds':3,'fails':1,'name':'Previously used'}]}),
    (55, 9, {'type':'autoselector','name':'Legacy wrapped mixed selector','gid':0,'last_built':[47,45],
             'pinned_id':45,'test_url':'http://127.0.0.1:31089/explicit-selector-probe',
             'interval_sec':40,'bench_interval_sec':80,'watch_interval_sec':10,'active_size':2,
             'expected':2,'sampling':6,'tolerance_ms':123,'max_rtt_ms':2500,'dial_retries':3,
             'interrupt_on_switch':False,'balance':True,'balance_mode':'connection','balance_interval_sec':15}),
]
SECRETS = BASE_SECRETS + ['synthetic-selector-probe-secret','synthetic-selector-online-secret','secret-unknown-selector']


def expected_options(config, include_settings=True):
    # Native checks use explicit expected values for these two fixed fixtures;
    # the broader Normalize oracle is generated independently by actual Qt.
    if config['name'] == SELECTORS[0][2]['name']:
        result = {'url':TEST_URL if include_settings else 'http://cp.cloudflare.com/',
                  'interval':'300s','bench_interval':'600s','watch_interval':'15s','active_size':1,
                  'expected':1,'sampling':10,'tolerance':300,'dial_retries':2,'interrupt_exist_connections':True}
    else:
        result = {'url':config['test_url'],'interval':'40s','bench_interval':'80s','watch_interval':'10s',
                  'active_size':2,'expected':2,'sampling':6,'tolerance':123,'max_rtt':'2500ms',
                  'dial_retries':3,'interrupt_exist_connections':False,'balance':True,'balance_mode':'connection','balance_interval':'15s'}
    if include_settings:
        result['connectivity_url'] = CONNECTIVITY_URL
    return result


def database(path, blocked=False):
    base_database(path)
    db = sqlite3.connect(path)
    # The old profile-only fixture intentionally used a minimal deferred route
    # schema. This scope test needs the actual source routing schema instead.
    db.executescript('DROP TABLE route_rules; DROP TABLE route_profiles;')
    ddl=qt_snapshot.ddl('RoutesRepo',2)
    for statement in ddl: db.execute(statement)
    db.execute('INSERT INTO route_profiles(id,name,default_outbound_id,is_raw,raw_route,created_at,updated_at) VALUES(?,?,?,?,?,?,?)',(5,'Route requiring saved selector',-1,0,'',1,1))
    rows = copy.deepcopy(SELECTORS)
    if blocked:
        for pid, config in [
            (56, {'last_built':[45,999]}),
            (57, {'last_built':[45,47],'pinned_id':41}),
            (58, {'last_built':[],'pool':[45,47]}),
            (59, {'last_built':[60]}),
            (61, {'last_built':[51]}),
            (62, {'last_built':[52]}),
            (63, {'last_built':[45],'future_option':'secret-unknown-selector'}),
        ]:
            rows.append((pid, 0, {'type':'autoselector','name':'Blocked selector '+str(pid),'gid':0,**config}))
        wg={'type':'wireguard','tag':'Unchained WG source member','private_key':WIREGUARD_KEY,
            'address':['10.60.0.2/32'],'peers':[{'address':'127.0.0.1','port':31060,'public_key':WIREGUARD_KEY}]}
        db.execute('INSERT INTO profiles VALUES(?,?,?,?,?)',(60,'wireguard','Database label 60',0,json.dumps(wg)))
    for pid,gid,config in rows:
        db.execute('INSERT INTO profiles VALUES(?,?,?,?,?)',(pid,'autoselector','Database label '+str(pid),gid,json.dumps(config,ensure_ascii=False)))
    for group in GROUPS:
        members=json.loads(group[3])
        additional=[pid for pid,gid,_ in rows if gid==group[0]]
        if blocked and group[0]==0: additional.append(60)
        # Selectors precede their dependencies in source display order.
        db.execute('UPDATE groups SET profiles_json=? WHERE id=?',(json.dumps(additional+members),group[0]))
    db.execute('INSERT INTO route_rules(route_profile_id,rule_order,name,type,domain_suffix_json,outbound_id) VALUES(?,?,?,?,?,?)',(5,0,'Saved selector target',1,'["selector-routing.example.test"]',54))
    db.executemany('INSERT OR REPLACE INTO settings VALUES(?,?)',[
        ('test_url',TEST_URL),('direct_test_url',CONNECTIVITY_URL),
        ('use_dns_object','true'),('dns_object',json.dumps({'servers':[{'type':'udp','tag':'dns-direct','server':'127.0.0.1','server_port':31090}],'final':'dns-direct'})),
    ])
    db.execute('UPDATE entity_ids SET profile_last_id=?',(63 if blocked else 55,))
    db.commit();db.close()


def generate(writer):
    DIRECTORY.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='thronium-selector-qt-backups-') as temporary:
        root=Path(temporary)
        for name,blocked in [('valid',False),('blocked',True)]:
            source=root/(name+'.sqlite');database(source,blocked)
            output=root/name;output.mkdir()
            subprocess.run([str(writer),str(output),str(source)],check=True)
            shutil.copyfile(output/'parts-31.thrbackup',DIRECTORY/(name+'.thrbackup'))
            if not blocked:
                shutil.copyfile(output/'parts-27.thrbackup',DIRECTORY/'excluded-settings.thrbackup')
                shutil.copyfile(output/'parts-30.thrbackup',DIRECTORY/'excluded-profiles.thrbackup')
    manifest={'writer':'desktop/tests/thrbackup_writer.py: byte for byte the Qt6 QDataStream Qt_6_0 little-endian writer',
              'validProfiles':len(base_sources())+len(SELECTORS),'validGroups':len(GROUPS),'validSelectors':len(SELECTORS),
              'blockedProfiles':len(base_sources())+len(SELECTORS)+8,'blockedSelectors':9,
              'data':'Synthetic profiles only; no connection is started by the fixture writer.',
              'sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(DIRECTORY.glob('*.thrbackup'))}}
    (DIRECTORY/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(manifest,ensure_ascii=False))


if __name__=='__main__':
    generate(Path(sys.argv[1]))
