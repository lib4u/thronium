"""Actual HTTP queue, initial selector ordering and held traffic on owned proxies."""
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
    command, click, fill, select, wait_for, js, check, screenshot = (h[k] for k in ('command','click','fill','select','wait_for','js','check','screenshot'))
    info=json.loads(Path(os.environ['_THRONIUM_DIAGNOSTICS_FIXTURE']).read_text())
    initial=command('snapshot');old_route=command('routing');geometry=h['request']('GET',h['base']+'/window/rect')
    groups=[];held=None;thread=None;stop=threading.Event();beats=[];errors=[]
    url='http://127.0.0.1:'+str(info['httpPorts'][0])+'/health'
    def admin(i,**data):
        req=urllib.request.Request(info['admins'][i],data=json.dumps(data).encode() if data else None,headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(req,timeout=3) as response:return json.load(response)
    def group(name):
        gid=command('saveGroup',{'name':name})['id'];groups.append(gid);return gid
    def add(gid,name,port):return command('saveProfile',{'groupId':gid,'name':name,'kind':'sing-box-outbound','config':{'type':'socks','server':'127.0.0.1','server_port':port}})['id']
    def close():
        click('#main-modal > .modal-head > button')
        if js('return !!document.querySelector(".editor-discard")'):click('.editor-discard [data-confirm-accept]')
        wait_for('return !document.querySelector("dialog[open]")')
    def preview(ids):
        wait_for('return !document.querySelector("#selector-preview-loading") && JSON.stringify([...document.querySelectorAll("[data-selector-preview-member]")].map(e=>e.dataset.selectorPreviewMember))==='+json.dumps(json.dumps(ids,separators=(',',':'))))
    def edit(pid):
        click('.primary-nav button:first-child');select('.group-strip select','all');fill('#client-search','')
        wait_for('return !!document.querySelector('+json.dumps('[data-profile-menu="'+pid+'"]')+')')
        js('document.querySelector(arguments[0]).scrollIntoView({block:"center"})','[data-profile-menu="'+pid+'"]')
        click('[data-profile-menu="'+pid+'"]');click('#menu-edit-profile');wait_for('return !!document.querySelector("#selector-member-order")')
    def done(batch_id=None):
        end=time.monotonic()+15
        while time.monotonic()<end:
            batch=command('snapshot')['urlTests']
            if batch and (batch_id is None or batch['id']==batch_id) and all(e['status'] not in ('queued','testing') for e in batch['entries']):return batch
            time.sleep(.06)
        raise AssertionError('Owned HTTP queue did not finish')
    def measure(ids):
        batch=command('startUrlTests',{'ids':ids,'url':url,'timeoutMs':3000})['id'];return done(batch)
    def pool(ids):
        end=time.monotonic()+12
        while time.monotonic()<end:
            pools=command('getAutoSelectors')
            if pools and pools[0]['membersAlive']==len(ids) and [m['profileId'] for m in pools[0]['members']]==ids:return pools[0]
            time.sleep(.1)
        raise AssertionError('Runtime pool order did not become '+repr(ids))
    def tunnel(path):
        conn=socket.create_connection(('127.0.0.1',port),timeout=4)
        try:
            host='127.0.0.1:'+str(info['httpPorts'][0])
            def headers():
                data=b''
                while b'\r\n\r\n' not in data:
                    chunk=conn.recv(1);assert chunk;data+=chunk
                assert b' 200 ' in data.split(b'\r\n',1)[0];return data
            conn.sendall(('CONNECT '+host+' HTTP/1.1\r\nHost: '+host+'\r\n\r\n').encode());headers()
            conn.sendall(('GET '+path+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n').encode());head=headers()
            length=int(next(x.split(b':',1)[1] for x in head.split(b'\r\n') if x.lower().startswith(b'content-length:')));body=b''
            while len(body)<length:
                chunk=conn.recv(length-len(body));assert chunk;body+=chunk
            return conn,body
        except BaseException:conn.close();raise
    def pulse():
        try:
            while not stop.is_set():
                data=('ranking46-'+str(len(beats))).encode();held.sendall(data);reply=b''
                while len(reply)<len(data):
                    chunk=held.recv(len(data)-len(reply));assert chunk;reply+=chunk
                assert data==reply;beats.append(time.monotonic());stop.wait(.2)
        except BaseException as error:errors.append(repr(error))
    try:
        command('disconnect')
        with socket.socket() as listener:listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
        command('preferences',{**initial['preferences'],'language':'en','theme':'dark','connectionMode':'local','inboundPort':port,'ping':{'method':'http','url':url,'timeoutMs':3000}})
        route=copy.deepcopy(old_route);current=next(p for p in route['profiles'] if p['id']==route['active']);current['rules']=[{'id':'ranking46-proxy','name':'Owned HTTP through selected proxy','enabled':True,'config':{'ip_cidr':['127.0.0.1/32'],'outbound':'proxy'}}];command('saveRouting',route)
        source,owner=group('HTTP ranking servers'),group('HTTP ranking pools')
        a=add(source,'Rank A',info['ports'][0]);b=add(source,'Rank B',info['ports'][1]);admin(0,downloadMode='slow');admin(1,downloadMode='ok')
        wait_for('return document.documentElement.lang==="en" && document.querySelectorAll("[data-profile-menu]").length===2')
        select('.group-strip select',source);click('#open-probes');batch=done()
        result={e['profileId']:e for e in batch['entries']}
        check(set(result)=={a,b} and all(e['status']=='ok' and e['effectiveMethod']=='http' for e in result.values()) and result[a]['latencyMs']>result[b]['latencyMs']+100
              and admin(0)['rankingRequests']>=2 and admin(1)['rankingRequests']>=2,
              'native Ping action measures two real HTTP exits with different delays, including warmup requests')
        data_root=Path(os.environ['XDG_DATA_HOME']).resolve();assert data_root.name=='data' and data_root.parent.name.startswith('thronium-native-test-')
        libraries=list(data_root.rglob('library.json'));assert len(libraries)==1;library=libraries[0];cache=library.with_name('http-latencies-v1.json')
        text=cache.read_text();check((cache.stat().st_mode&0o777)==0o600 and url not in text and '127.0.0.1' not in text,'HTTP history is private and stores a URL hash instead of the target URL')
        unknown=add(source,'Unmeasured',info['ports'][0])
        cfg={'type':'auto-selector','member_source':{'group_id':source},'url':url,'interval':'1h','bench_interval':'1h','watch_interval':'1h','timeout':'800ms','sampling':2,'expected':2,'active_size':2,'tolerance':10000,'interrupt_exist_connections':False}
        pid=command('saveProfile',{'groupId':owner,'name':'Initial HTTP ranking','kind':'auto-selector','config':cfg})['id']
        edit(pid);preview([a,b,unknown]);check(js('return document.querySelector("#selector-member-order").value==="library" && !document.querySelector("#selector-exclude-unavailable").checked'),'existing library order and inclusion remain the default')
        select('#selector-member-order','http-latency');preview([b,a,unknown])
        check(js('return document.querySelectorAll("[data-selector-http-latency]").length===2 && document.querySelector("#selector-ranking-summary").textContent.includes(": 2.")'),'HTTP order puts measured fast servers before slow and unmeasured servers')
        fill('#selector-result-validity','0');preview([a,b,unknown]);check(js('return document.querySelector("#selector-ranking-summary").textContent.includes(": 0.")'),'zero validity ignores saved results and restores stable library order')
        fill('#selector-result-validity','10081');wait_for('return !!document.querySelector("#selector-preview-error")');check(not js('return document.querySelector("#selector-preview-error").textContent.includes("selector_invalid_ranking")'),'invalid measurement lifetime produces a localized preview error')
        fill('#selector-result-validity','60');click('#selector-exclude-unavailable');preview([b,a,unknown])
        before=library.read_bytes();admin(0,downloadMode='http-error');failed=measure([a]);preview([b,unknown])
        check(failed['entries'][0]['status']=='error' and failed['entries'][0]['error']=='probe_failed' and library.read_bytes()==before,'completed failed HTTP request excludes that server without rewriting the portable library')
        admin(1,downloadMode='http-error');measure([b]);preview([unknown]);check(True,'unknown servers remain eligible when recent HTTP failures are excluded')
        fill('#selector-name-regex','^Rank [AB]$');preview([a,b]);check(js('return document.querySelector("#selector-ranking-fallback").textContent.endsWith(": 2")'),'all-failed fallback retains eligible servers and explains why')
        for lang,theme in [('ru','light'),('en','dark')]:
            command('preferences',{**command('snapshot')['preferences'],'language':lang,'theme':theme});wait_for('return document.documentElement.lang==='+json.dumps(lang));preview([a,b])
            h['request']('POST',h['base']+'/window/rect',{'width':390,'height':844});js('document.querySelector("#selector-member-order").scrollIntoView({block:"start"})')
            check(js('return document.documentElement.scrollWidth<=innerWidth && document.querySelector(".selector-fields").scrollWidth<=document.querySelector(".selector-fields").clientWidth'),lang+' initial-ranking editor fits a 390-pixel native window');screenshot('selector-ranking-'+lang+'-390')
        h['request']('POST',h['base']+'/window/rect',{'width':1280,'height':860})
        admin(0,downloadMode='slow');admin(1,downloadMode='ok');measure([a,b]);preview([b,a])
        click('button[form="profile-editor"]');wait_for('return !document.querySelector("dialog[open]")')
        saved=command('profile',{'id':pid})['config'];check(saved['member_source']['order']=='http-latency' and saved['member_source']['exclude_unavailable'] and saved['member_source']['result_validity_mins']==60,'native Save preserves HTTP ranking, lifetime, exclusions and the dynamic source')
        command('connect',{'id':pid});pool([b,a]);active=command('connectionConfiguration',{'id':pid,'active':True});since=command('snapshot')['since']
        held,body=tunnel('/stream');assert body==b'ready';thread=threading.Thread(target=pulse,name='ranking46-owned-heartbeat');thread.start();time.sleep(.5)
        check(len(beats)>=2 and not errors,'ranked pool forwards a real CONNECT stream through its local proxies')
        admin(0,downloadMode='ok');admin(1,downloadMode='slow');batch=measure([a,b]);values={e['profileId']:e['latencyMs'] for e in batch['entries']};assert values[b]>values[a]+100
        edit(pid);preview([a,b]);count=len(beats);time.sleep(.5)
        check(len(beats)>count and not errors and command('connectionConfiguration',{'id':pid,'active':True})==active and command('snapshot')['since']==since,'new latency ordering refreshes the editor while preserving active configuration and held traffic')
        close();stop.set();thread.join(5);assert not thread.is_alive();held.close();held=None;command('disconnect')
        command('connect',{'id':pid});pool([a,b]);conn,body=tunnel('/body');conn.close();check(body==b'country45:0','next connection uses the newly ranked member order and forwards a complete HTTP response')
        command('disconnect')
        # In-flight cancellation must not replace previously completed observations.
        admin(0,downloadMode='slow');requests=admin(0)['rankingRequests'];before=cache.read_bytes();batch_id=command('startUrlTests',{'ids':[a],'url':url,'timeoutMs':3000})['id']
        end=time.monotonic()+5
        while admin(0)['rankingRequests']==requests and time.monotonic()<end:time.sleep(.01)
        assert admin(0)['rankingRequests']>requests;command('cancelUrlTests');cancelled=done(batch_id)
        check(cancelled['entries'][0]['status']=='cancelled' and cache.read_bytes()==before,'cancelling an actual delayed HTTP request preserves completed ranking history')
        command('clearUrlTests');edit(pid);preview([a,b]);check(js('return document.querySelector("#selector-ranking-summary").textContent.includes(": 0.")') and not json.loads(cache.read_text())['entries'],'Clear tests removes persisted HTTP observations and refreshes the ranking preview')
        close();Path(h['artifacts']).joinpath('ranking-network-audit.json').write_text(json.dumps({'heartbeats':len(beats),'heartbeatErrors':errors,'initialMeasuredOrder':[b,a],'nextMeasuredOrder':[a,b],'requests':[admin(i)['rankingRequests'] for i in range(2)],'externalRequests':False},indent=2)+'\n')
    finally:
        with contextlib.suppress(Exception):command('cancelUrlTests')
        stop.set()
        if thread:thread.join(5)
        if held:
            with contextlib.suppress(OSError):held.shutdown(socket.SHUT_RDWR)
            held.close()
        if thread:assert not thread.is_alive()
        command('disconnect')
        for gid in reversed(groups):command('deleteGroup',{'id':gid,'deleteProfiles':True})
        command('saveRouting',{**old_route,'revision':command('routing')['revision']});command('preferences',initial['preferences'])
        if initial['selected']:command('select',{'id':initial['selected']})
        h['request']('POST',h['base']+'/window/rect',{'width':geometry['width'],'height':geometry['height']})
