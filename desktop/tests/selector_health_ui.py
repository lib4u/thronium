"""Core health persistence from real loopback probes; no manual URL test requests."""
import contextlib
import copy
import json
import os
from pathlib import Path
import socket
import threading
import time
import urllib.request


def run(h):
    command,click,fill,select,wait_for,js,check,screenshot=(h[k] for k in ('command','click','fill','select','wait_for','js','check','screenshot'))
    info=json.loads(Path(os.environ['_THRONIUM_DIAGNOSTICS_FIXTURE']).read_text());initial=command('snapshot');old_route=command('routing');geometry=h['request']('GET',h['base']+'/window/rect')
    groups=[];held=None;thread=None;stop=threading.Event();beats=[];errors=[];cache=None;cache_bytes=None;events=[]
    url='http://127.0.0.1:'+str(info['httpPorts'][0])+'/health'
    def admin(i,**data):
        req=urllib.request.Request(info['admins'][i],data=json.dumps(data).encode() if data else None,headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(req,timeout=3) as response:return json.load(response)
    def release():
        for i in range(2):admin(i,downloadMode='slow')
    def group(name):gid=command('saveGroup',{'name':name})['id'];groups.append(gid);return gid
    def add(gid,name,peer):return command('saveProfile',{'groupId':gid,'name':name,'kind':'sing-box-outbound','config':{'type':'socks','server':'127.0.0.1','server_port':info['ports'][peer]}})['id']
    def eventually(fn,message,timeout=15):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            value=fn()
            if value:return value
            time.sleep(.08)
        raise AssertionError(message)
    def entries():return json.loads(cache.read_text())['entries'] if cache.is_file() else {}
    def status():return next(g for g in command('getAutoSelectors') if g['tag']=='proxy')
    def observed():
        data=entries();return data if set(data)=={a,b} and all(v.get('origin')=='core-average' for v in data.values()) else None
    def config():return command('connectionConfiguration',{'id':pid,'active':True})
    def edit(editable=True):
        click('.primary-nav button:first-child');select('.group-strip select','all');fill('#client-search','');selector='[data-profile-menu="'+pid+'"]';wait_for('return !!document.querySelector('+json.dumps(selector)+')');js('document.querySelector(arguments[0]).scrollIntoView({block:"center"})',selector);click(selector);click('#menu-edit-profile');wait_for('return !!document.querySelector("#selector-persist-health")'+(' && !document.querySelector("#selector-persist-health").disabled' if editable else ''))
    def preview(n=2):wait_for('return !document.querySelector("#selector-preview-loading") && document.querySelectorAll("[data-selector-core-average]").length==='+str(n))
    def save():click('button[form="profile-editor"]');wait_for('return !document.querySelector("dialog[open]")')
    def close():
        click('#main-modal > .modal-head > button')
        if js('return !!document.querySelector(".editor-discard")'):click('.editor-discard [data-confirm-accept]')
        wait_for('return !document.querySelector("dialog[open]")')
    def tunnel(path):
        conn=socket.create_connection(('127.0.0.1',port),timeout=4)
        try:
            host='127.0.0.1:'+str(info['httpPorts'][0])
            def headers():
                data=b''
                while b'\r\n\r\n' not in data:
                    chunk=conn.recv(1);assert chunk;data+=chunk
                assert b' 200 ' in data.split(b'\r\n',1)[0];return data
            conn.sendall(('CONNECT '+host+' HTTP/1.1\r\nHost: '+host+'\r\n\r\n').encode());headers();conn.sendall(('GET '+path+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n').encode());head=headers();length=int(next(l.split(b':',1)[1] for l in head.split(b'\r\n') if l.lower().startswith(b'content-length:')));body=b''
            while len(body)<length:
                chunk=conn.recv(length-len(body));assert chunk;body+=chunk
            return conn,body
        except BaseException:conn.close();raise
    def pulse():
        try:
            while not stop.is_set():
                data=('health50-'+str(len(beats))).encode();held.sendall(data);reply=b''
                while len(reply)<len(data):
                    chunk=held.recv(len(data)-len(reply));assert chunk;reply+=chunk
                assert reply==data;beats.append(time.monotonic());stop.wait(.2)
        except BaseException as error:errors.append(repr(error))
    def stop_stream():
        nonlocal held
        stop.set()
        if thread:thread.join(5);assert not thread.is_alive()
        if held:held.close();held=None
    try:
        command('disconnect')
        with socket.socket() as listener:listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
        command('preferences',{**initial['preferences'],'language':'en','theme':'dark','connectionMode':'local','inboundPort':port})
        route=copy.deepcopy(old_route);current=next(p for p in route['profiles'] if p['id']==route['active']);current['rules']=[{'id':'health50-proxy','name':'Owned HTTP via pool','enabled':True,'config':{'ip_cidr':['127.0.0.1/32'],'outbound':'proxy'}}];command('saveRouting',route)
        source,owner=group('Core health members'),group('Core health pools');a=add(source,'Core Alpha',0);b=add(source,'Core Beta',1);release()
        cfg={'type':'auto-selector','member_source':{'group_id':source},'url':url,'interval':'1h','bench_interval':'1h','watch_interval':'1h','timeout':'10s','sampling':2,'expected':2,'active_size':2,'tolerance':10000,'interrupt_exist_connections':False}
        draft={'groupId':owner,'name':'Core health pool','kind':'auto-selector','config':cfg};pid=command('saveProfile',draft)['id'];draft['id']=pid
        root=Path(os.environ['XDG_DATA_HOME']).resolve();assert root.name=='data' and root.parent.name.startswith('thronium-native-test-');libraries=list(root.rglob('library.json'));assert len(libraries)==1;library=libraries[0];cache=library.with_name('http-latencies-v1.json')
        command('clearUrlTests');command('connect',{'id':pid});eventually(lambda:status()['roundsCompleted']>0,'initial Core round did not complete');time.sleep(6)
        check(entries()=={} and command('snapshot')['urlTests'] is None,'default Core probing does not opt into saved health or create a manual HTTP batch');command('disconnect')
        edit();check(not js('return document.querySelector("#selector-persist-health").checked'),'saving Core health is an explicit native editor option');click('#selector-persist-health');save();cfg=command('profile',{'id':pid})['config'];draft['config']=cfg
        command('checkProfile',draft);command('previewSelector',{'profile':draft});check(entries()=={},'Core CheckConfig and preview do not manufacture HTTP observations')
        command('connect',{'id':pid});first=eventually(observed,'Core HTTP results were not persisted');view=status();by_id={m['profileId']:m for m in view['members']}
        check(all(v['latencyMs']>=200 and v['observedAtMs']==by_id[k]['lastProbeMs'] and v['testedAt']==v['observedAtMs']//1000 and 'timeoutMs' not in v for k,v in first.items()) and command('snapshot')['urlTests'] is None,'real Core HTTP averages preserve the exact probe timestamp without invented manual-test timeout or batch')
        check(cache.stat().st_mode&0o777==0o600 and url not in cache.read_text() and '127.0.0.1' not in cache.read_text() and 'core-average' not in library.read_text(),'derived Core observations stay in a private cache without endpoints or portable-profile changes')
        first_bytes=cache.read_bytes();history=command('getSelectorHistory');active=config();since=command('snapshot')['since'];time.sleep(6)
        check(cache.read_bytes()==first_bytes and command('getSelectorHistory')==history,'repeated status polling preserves original observation age and startup counters')
        bad=command('saveProfile',{'groupId':owner,'name':'Owned occupied listener','kind':'sing-box-config','config':{'inbounds':[{'type':'mixed','tag':'collision','listen':'127.0.0.1','listen_port':info['httpPorts'][0]}],'outbounds':[{'type':'direct','tag':'proxy'}]}})['id']
        try:command('connect',{'id':bad});raise AssertionError('Owned listener collision unexpectedly started')
        except RuntimeError as error:assert 'connection_restored' in str(error),str(error)
        check(command('snapshot')['running']==pid and config()==active and command('getSelectorHistory')==history,'failed actual Core Start restores the exact opted-in request without changing startup history')
        restored=eventually(lambda:observed() if all(entries().get(k,{}).get('observedAtMs',0)>first[k]['observedAtMs'] for k in (a,b)) else None,'restored request no longer collected new Core probes')
        check(all(restored[k]['observedAtMs']>first[k]['observedAtMs'] for k in (a,b)),'restored Core request continues publishing only newly measured health under its original member contexts')
        since=command('snapshot')['since']
        held,body=tunnel('/stream');assert body==b'ready';thread=threading.Thread(target=pulse,name='health50-owned-heartbeat');thread.start()
        command('clearUrlTests');time.sleep(6);check(entries()=={} and config()==active and command('snapshot')['since']==since and len(beats)>10 and not errors,'Clear refuses replayed Core samples while the active configuration and held CONNECT stream continue')
        command('autoSelectorAction',{'tag':'proxy','action':'recheck','member':''});second=eventually(observed,'new Core round did not refill cleared health')
        check(all(second[k]['observedAtMs']>first[k]['observedAtMs'] for k in (a,b)),'only a new real Core recheck refills the cleared health cache')
        # Fault injection is limited to this suite's private temporary XDG cache.
        cache_bytes=cache.read_bytes();cache.unlink();cache.mkdir();before_round=status()['roundsCompleted'];command('autoSelectorAction',{'tag':'proxy','action':'recheck','member':''});eventually(lambda:status()['roundsCompleted']>before_round,'fault-injection recheck did not finish')
        failed_view=status();eventually(lambda:any('latency_cache_write_failed' in e['text'] for e in command('getLogs')['entries']),'cache write failure was not reported')
        preview_failed=command('previewSelector',{'profile':draft});check(preview_failed['rankedByHttp']==2 and config()==active and not errors,'failed Core health persistence keeps prior usable observations and the held connection')
        cache.rmdir();cache.write_bytes(cache_bytes);cache.chmod(0o600);cache_bytes=None
        third=eventually(lambda:observed() if all(entries().get(k,{}).get('observedAtMs',0)>second[k]['observedAtMs'] for k in (a,b)) else None,'same Core status was not retried after restoring cache writes')
        failed_by_id={m['profileId']:m for m in failed_view['members']};check(all(third[k]['observedAtMs']==failed_by_id[k]['lastProbeMs'] for k in (a,b)),'retry after an atomic write failure saves the original probe time rather than retry time')
        check(command('getSelectorHistory')==history and not errors and config()==active,'background health writes and rechecks do not count another startup or rebuild the running pool')
        stop_stream();command('disconnect');edit();preview()
        for language,theme in [('ru','light'),('en','dark')]:
            command('preferences',{**command('snapshot')['preferences'],'language':language,'theme':theme});wait_for('return document.documentElement.lang==='+json.dumps(language));preview();h['request']('POST',h['base']+'/window/rect',{'width':390,'height':844});js('document.querySelector("#selector-persist-health").closest("label").scrollIntoView({block:"start"})');check(js('return document.documentElement.scrollWidth<=innerWidth && document.querySelector(".selector-fields").scrollWidth<=document.querySelector(".selector-fields").clientWidth'),language+' Core persistence option and hint fit a 390-pixel native window');screenshot('selector-health-'+language+'-390')
            js('document.querySelector(".selector-candidates").scrollIntoView({block:"center"})');check(js('return document.querySelectorAll("[data-selector-core-average]").length===2 && document.documentElement.scrollWidth<=innerWidth'),language+' preview explicitly identifies both Core HTTP averages');screenshot('selector-health-source-'+language+'-390')
        h['request']('POST',h['base']+'/window/rect',{'width':1280,'height':860});click('#selector-warm-start');wait_for('return !document.querySelector("#selector-preview-loading") && document.querySelector("#selector-warm-count")?.textContent.endsWith(": 2")');save();before_warm=cache.read_bytes()
        for i in range(2):admin(i,downloadMode='hold')
        forwarded=[admin(i)['warmForwarded'] for i in range(2)];command('connect',{'id':pid});eventually(lambda:any(admin(i)['warmBlocked'] for i in range(2)),'warm Core requests did not reach owned gate',2);warm=status();time.sleep(.8)
        check(all(m['samples']==1 for m in warm['members']) and cache.read_bytes()==before_warm and [admin(i)['warmForwarded'] for i in range(2)]==forwarded,'reconnected Core restores saved averages before new HTTP reaches origin and does not freshen warm-only samples')
        compiled=next(o for p in config()['parts'] for o in p['config'].get('outbounds',[]) if o.get('type')=='auto-selector' and o.get('tag')=='proxy');check(len(compiled['warm'])==2 and all(s['age']>=0 for s in compiled['warm']),'Core-generated startup hints use the previously saved runtime health')
        release();last=eventually(lambda:observed() if all(entries().get(k,{}).get('observedAtMs',0)>third[k]['observedAtMs'] for k in (a,b)) else None,'new post-warm Core probes were not saved')
        check(all(last[k]['observedAtMs']>third[k]['observedAtMs'] for k in (a,b)),'new real checks following warm startup become new observations');conn,body=tunnel('/body');conn.close();check(body==b'country45:0','pool with persisted and restored Core health forwards a complete real HTTP response')
        command('disconnect');edit();click('#selector-persist-health');save();command('clearUrlTests');command('connect',{'id':pid});eventually(lambda:status()['roundsCompleted']>0,'disabled Core round did not complete');time.sleep(6)
        check(entries()=={} and command('snapshot')['urlTests'] is None,'disabling persistence prevents fresh Core checks from refilling the cache')
        Path(h['artifacts']).joinpath('health-network-audit.json').write_text(json.dumps({'manualHttpBatches':0,'actualStartRollback':True,'restoredObservations':restored,'firstObservations':first,'newObservations':second,'retriedObservations':third,'warmSamples':[m['samples'] for m in warm['members']],'heartbeats':len(beats),'heartbeatErrors':errors,'externalRequests':False},indent=2)+'\n')
    finally:
        release();stop_stream()
        if cache is not None and cache_bytes is not None:
            if cache.is_dir():cache.rmdir()
            cache.write_bytes(cache_bytes);cache.chmod(0o600)
        with contextlib.suppress(Exception):
            if js('return !!document.querySelector("dialog[open]")'):close()
        command('disconnect')
        for gid in reversed(groups):command('deleteGroup',{'id':gid,'deleteProfiles':True})
        command('saveRouting',{**old_route,'revision':command('routing')['revision']});command('preferences',initial['preferences'])
        if initial['selected']:command('select',{'id':initial['selected']})
        h['request']('POST',h['base']+'/window/rect',{'width':geometry['width'],'height':geometry['height']})
