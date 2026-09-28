"""Successful membership history and rollback in the production app, owned loopback only."""
import contextlib
import copy
import json
import os
from pathlib import Path
import socket
import threading
import time


def run(h):
    command,click,select,wait_for,js,check,screenshot=(h[k] for k in ('command','click','select','wait_for','js','check','screenshot'))
    info=json.loads(Path(os.environ['_THRONIUM_DIAGNOSTICS_FIXTURE']).read_text());initial=command('snapshot');old_route=command('routing');geometry=h['request']('GET',h['base']+'/window/rect')
    groups=[];held=None;thread=None;stop=threading.Event();beats=[];errors=[];cache=None;cache_bytes=None
    url='http://127.0.0.1:'+str(info['httpPorts'][0])+'/health'
    def group(name):gid=command('saveGroup',{'name':name})['id'];groups.append(gid);return gid
    def add(gid,name,port):return command('saveProfile',{'groupId':gid,'name':name,'kind':'sing-box-outbound','config':{'type':'socks','server':'127.0.0.1','server_port':port}})['id']
    def history():return command('getSelectorHistory')
    def pool_history(pid):return next(p for p in history() if p['profileId']==pid)
    def config(pid):return command('connectionConfiguration',{'id':pid,'active':True})
    def open_history(pid=None):
        click('.primary-nav button:nth-child(3)');wait_for('return !!document.querySelector("#selector-history")')
        js('document.querySelector("#selector-history").scrollIntoView({block:"start"})')
        if not js('return document.querySelector("#selector-history").open'):click('#selector-history > summary')
        wait_for('return !document.querySelector("#selector-history-loading")')
        if pid:wait_for('return !!document.querySelector("#selector-history-pool")');select('#selector-history-pool',pid)
    def counters(expected):
        for pid,count in expected.items():wait_for('return document.querySelector('+json.dumps('[data-selector-history-builds="'+pid+'"]')+')?.textContent==='+json.dumps(str(count)))
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
                data=('history48-'+str(len(beats))).encode();held.sendall(data);reply=b''
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
        route=copy.deepcopy(old_route);current=next(p for p in route['profiles'] if p['id']==route['active']);current['rules']=[{'id':'history48-proxy','name':'Owned HTTP via pool','enabled':True,'config':{'ip_cidr':['127.0.0.1/32'],'outbound':'proxy'}}];command('saveRouting',route)
        source,owner=group('History members'),group('History pools');a=add(source,'History Alpha',info['ports'][0]);b=add(source,'History Beta',info['ports'][1])
        cfg={'type':'auto-selector','member_source':{'group_id':source},'url':url,'interval':'1h','bench_interval':'1h','watch_interval':'1h','timeout':'2s','sampling':2,'expected':2,'active_size':2,'interrupt_exist_connections':False}
        draft={'groupId':owner,'name':'History startup pool','kind':'auto-selector','config':cfg};pid=command('saveProfile',draft)['id'];draft['id']=pid
        command('checkProfile',draft);command('connectionConfiguration',{'id':pid,'active':False});open_history();check(history()==[] and js('return !!document.querySelector("#selector-history-empty")'),'preview and real Core CheckConfig leave startup history empty')
        command('connect',{'id':pid});first=pool_history(pid);check(first['lastBuilt']==[a,b] and all(e['builds']==1 for e in first['entries']),'successful Core startup records the exact built pool and one inclusion for each member')
        root=Path(os.environ['XDG_DATA_HOME']).resolve();assert root.name=='data' and root.parent.name.startswith('thronium-native-test-');libraries=list(root.rglob('library.json'));assert len(libraries)==1;library=libraries[0];cache=library.with_name('selector-history-v1.json');file=cache.read_text();check(cache.stat().st_mode&0o777==0o600 and url not in file and '127.0.0.1' not in file and 'selectorHistory' not in library.read_text(),'startup history is private and independent of the portable profile file')
        for _ in range(3):history();command('getAutoSelectors')
        command('autoSelectorAction',{'tag':'proxy','action':'recheck','member':''});command('checkProfile',draft);check(pool_history(pid)==first,'history reads, Core status, recheck and CheckConfig do not count another startup')
        command('disconnect');open_history(pid);counters({a:1,b:1});check(pool_history(pid)==first and not command('snapshot')['running'],'native history remains visible with the pool disconnected')
        h['request']('POST',h['base']+'/refresh',{});wait_for('return !!document.querySelector(".primary-nav")');open_history(pid);counters({a:1,b:1});check(pool_history(pid)==first,'history remains available after a native webview reload')
        command('connect',{'id':pid});second=pool_history(pid);check(all(e['builds']==2 and e['firstUsed']==next(x for x in first['entries'] if x['profileId']==e['profileId'])['firstUsed'] for e in second['entries']),'explicit reconnect increments each member once and retains first inclusion dates')
        bad=command('saveProfile',{'groupId':owner,'name':'Owned listener collision','kind':'sing-box-config','config':{'inbounds':[{'type':'mixed','tag':'collision','listen':'127.0.0.1','listen_port':info['httpPorts'][0]}],'outbounds':[{'type':'direct','tag':'proxy'}]}})['id'];active=config(pid)
        try:command('connect',{'id':bad});raise AssertionError('Owned occupied listener unexpectedly started')
        except RuntimeError as error:assert 'connection_restored' in str(error),str(error)
        check(command('snapshot')['running']==pid and config(pid)==active and pool_history(pid)==second and any('Previous connection restored' in e['text'] for e in command('getLogs')['entries']),'real failed Start restores the previous Core request without adding a startup or changing its history')
        conn,body=tunnel('/body');conn.close();check(body==b'country45:0','restored pool forwards a complete real HTTP response')
        held,body=tunnel('/stream');assert body==b'ready';thread=threading.Thread(target=pulse,name='history48-owned-heartbeat');thread.start();time.sleep(.5)
        c=add(source,'History Gamma',info['ports'][0]);check(pool_history(pid)==second and config(pid)==active,'adding a dynamic candidate preserves the recorded and active startup membership')
        open_history(pid);counters({a:2,b:2})
        for language,theme in [('ru','light'),('en','dark')]:
            command('preferences',{**command('snapshot')['preferences'],'language':language,'theme':theme});wait_for('return document.documentElement.lang==='+json.dumps(language));h['request']('POST',h['base']+'/window/rect',{'width':390,'height':844});js('document.querySelector("#selector-history").scrollIntoView({block:"start"})');check(js('return document.documentElement.scrollWidth<=innerWidth && document.querySelector("#selector-history").scrollWidth<=document.querySelector("#selector-history").clientWidth'),language+' startup history fits a 390-pixel native window');screenshot('selector-history-'+language+'-390')
        h['request']('POST',h['base']+'/window/rect',{'width':1280,'height':860});js('document.querySelector("#selector-history-clear").scrollIntoView({block:"center"})');click('#selector-history-clear');click('#selector-history-cancel');check(pool_history(pid)==second,'cancelling history deletion keeps all stored startup counts')
        cache_bytes=cache.read_bytes();cache.unlink();cache.mkdir();click('#selector-history-clear');click('#selector-history-erase');wait_for('return !!document.querySelector("#selector-history-error")');check('selector_history_write_failed' not in js('return document.querySelector("#selector-history-error").textContent') and pool_history(pid)==second,'failed history deletion shows a localized error and preserves the previous in-memory history');cache.rmdir();cache.write_bytes(cache_bytes);cache.chmod(0o600);cache_bytes=None
        since=command('snapshot')['since'];beat=len(beats);click('#selector-history-erase');wait_for('return !!document.querySelector("#selector-history-empty")');time.sleep(.45);check(history()==[] and len(beats)>beat and not errors and config(pid)==active and command('snapshot')['since']==since,'clearing history preserves the running Core configuration and the held CONNECT stream')
        stop_stream();command('disconnect');command('connect',{'id':pid});last=pool_history(pid);check(last['lastBuilt']==[a,b,c] and all(e['builds']==1 for e in last['entries']),'next successful startup records the new dynamic membership after history was cleared')
        # The only cache write fault is below our own temporary XDG root.
        cache_bytes=cache.read_bytes();cache.unlink();cache.mkdir();command('disconnect');command('connect',{'id':pid});check(command('snapshot')['running']==pid and pool_history(pid)==last and any('selector_history_write_failed' in e['text'] for e in command('getLogs')['entries']),'history persistence failure logs a finite warning and leaves the successful new connection running');conn,body=tunnel('/body');conn.close();check(body==b'country45:0','connection with a history write failure still forwards the complete HTTP response');cache.rmdir();cache.write_bytes(cache_bytes);cache.chmod(0o600);cache_bytes=None
        command('disconnect');aux_route=copy.deepcopy(route);aux_route['revision']=command('routing')['revision'];next(p for p in aux_route['profiles'] if p['id']==aux_route['active'])['rules'][0]['config']['outbound']='profile:'+pid;command('saveRouting',aux_route);command('connect',{'id':a})
        auxiliary=config(a);aux_tag='thronium-route-'+pid;check(pool_history(pid)['lastBuilt']==[a,b,c] and all(e['builds']==2 for e in pool_history(pid)['entries']) and any(o.get('type')=='auto-selector' and o.get('tag')==aux_tag for part in auxiliary['parts'] for o in part['config'].get('outbounds',[])),'real auxiliary routing pool records its own generated members under the saved selector profile')
        conn,body=tunnel('/body');conn.close();check(body==b'country45:0','auxiliary pool with recorded startup history forwards the complete HTTP response')
        command('disconnect');command('saveRouting',{**route,'revision':command('routing')['revision']});other=command('saveProfile',{**draft,'id':None,'name':'Second history pool'})['id'];command('connect',{'id':other});other_active=config(other);open_history(pid);js('document.querySelector("#selector-history-clear").scrollIntoView({block:"center"})');click('#selector-history-clear');click('#selector-history-erase');wait_for('return document.querySelector("#selector-history-pool")?.value==='+json.dumps(other))
        check([p['profileId'] for p in history()]==[other] and command('snapshot')['running']==other and config(other)==other_active,'clearing one pool leaves the other pool history and its running connection intact')
        command('disconnect');command('delete',{'id':b});open_history(other);wait_for('return document.querySelector('+json.dumps('[data-selector-history-member="'+b+'"]')+')?.textContent.includes("Profile deleted")');check(b in pool_history(other)['lastBuilt'] and next(e for e in pool_history(other)['entries'] if e['profileId']==b)['missing'],'deleted member remains identified in the historical startup without changing that old membership')
        Path(h['artifacts']).joinpath('history-network-audit.json').write_text(json.dumps({'firstMembership':first['lastBuilt'],'nextMembership':last['lastBuilt'],'heartbeats':len(beats),'heartbeatErrors':errors,'actualStartRollback':True,'auxiliaryRouting':True,'clearOnlyOnePool':True,'deletedMemberRetained':True,'externalRequests':False},indent=2)+'\n')
    finally:
        stop_stream()
        if cache is not None and cache_bytes is not None:
            if cache.is_dir():cache.rmdir()
            cache.write_bytes(cache_bytes);cache.chmod(0o600)
        command('disconnect')
        for gid in reversed(groups):command('deleteGroup',{'id':gid,'deleteProfiles':True})
        command('saveRouting',{**old_route,'revision':command('routing')['revision']});command('preferences',initial['preferences'])
        if initial['selected']:command('select',{'id':initial['selected']})
        h['request']('POST',h['base']+'/window/rect',{'width':geometry['width'],'height':geometry['height']})
