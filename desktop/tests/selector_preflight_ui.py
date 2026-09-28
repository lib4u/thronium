"""Automatic connection preparation against owned SOCKS/HTTP fixtures."""
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
    info=json.loads(Path(os.environ['_THRONIUM_DIAGNOSTICS_FIXTURE']).read_text())
    initial=command('snapshot');old_route=command('routing');geometry=h['request']('GET',h['base']+'/window/rect');groups=[]
    held=None;thread=None;stop=threading.Event();beats=[];errors=[];tokens=[]
    url='http://127.0.0.1:'+str(info['httpPorts'][0])+'/health'
    def admin(i,**data):
        req=urllib.request.Request(info['admins'][i],data=json.dumps(data).encode(),headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(req,timeout=3) as response:return json.load(response)
    def modes(mode):
        for i in range(2):admin(i,downloadMode=mode)
    def until(fn,message,timeout=15):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            value=fn()
            if value:return value
            time.sleep(.06)
        raise AssertionError(message)
    def blocked():until(lambda:any(admin(i)['warmBlocked']>0 for i in range(2)), 'No owned HTTP request reached the preflight gate')
    def drained():until(lambda:all(admin(i)['warmBlocked']==0 for i in range(2)), 'Owned HTTP gates did not drain')
    def idle():until(lambda:not command('snapshot').get('connectionPreparation'), 'Connection preparation did not finish')
    def group(name):gid=command('saveGroup',{'name':name})['id'];groups.append(gid);return gid
    def add(gid,name,index):return command('saveProfile',{'groupId':gid,'name':name,'kind':'sing-box-outbound','config':{'type':'socks','server':'127.0.0.1','server_port':info['ports'][index]}})['id']
    def begin(pid,token):
        tokens.append(token)
        js('''window.__preflight56??={};const token=arguments[1];window.__preflight56[token]={done:false};window.__TAURI_INTERNALS__.invoke('app_command',{name:'connect',payload:{id:arguments[0]}}).then(value=>window.__preflight56[token]={done:true,ok:true,value}).catch(error=>window.__preflight56[token]={done:true,ok:false,error});''',pid,token)
    def finish(token):
        wait_for('return window.__preflight56?.['+json.dumps(token)+']?.done',20)
        return json.loads(js('return JSON.stringify(window.__preflight56[arguments[0]])',token))
    def reject(name,payload,code):
        try:command(name,payload)
        except RuntimeError as error:return code in str(error)
        return False
    def cfg(pid):return command('profile',{'id':pid})['config']
    def active(pid):return command('connectionConfiguration',{'id':pid,'active':True})
    def pool_members(pid):
        parts=active(pid)['parts'];core=next(o for p in parts for o in p['config'].get('outbounds',[]) if o.get('type')=='auto-selector' and o.get('tag')=='proxy')
        return [tag.removeprefix('thronium-selector-proxy-') for tag in core['outbounds']]
    def measure(ids):
        batch=command('startUrlTests',{'ids':ids,'url':url,'timeoutMs':3000})['id']
        def ready():
            value=command('snapshot')['urlTests']
            return value and value['id']==batch and all(e['status'] in ('ok','error') for e in value['entries'])
        until(ready,'Saved HTTP measurements did not finish')
    def stream():
        conn=socket.create_connection(('127.0.0.1',port),timeout=4);host='127.0.0.1:'+str(info['httpPorts'][0])
        def headers():
            data=b''
            while b'\r\n\r\n' not in data:
                chunk=conn.recv(1);assert chunk;data+=chunk
            assert b' 200 ' in data.split(b'\r\n',1)[0];return data
        conn.sendall(('CONNECT '+host+' HTTP/1.1\r\nHost: '+host+'\r\n\r\n').encode());headers();conn.sendall(('GET /stream HTTP/1.0\r\nHost: '+host+'\r\n\r\n').encode());head=headers();length=int(next(l.split(b':',1)[1] for l in head.split(b'\r\n') if l.lower().startswith(b'content-length:')));body=b''
        while len(body)<length:body+=conn.recv(length-len(body))
        assert body==b'ready';return conn
    def pulse():
        try:
            while not stop.is_set():
                data=('preflight56-'+str(len(beats))).encode();held.sendall(data);reply=b''
                while len(reply)<len(data):
                    chunk=held.recv(len(data)-len(reply));assert chunk;reply+=chunk
                assert reply==data;beats.append(time.monotonic());stop.wait(.15)
        except BaseException as error:errors.append(repr(error))
    def stop_stream():
        nonlocal held,thread
        stop.set()
        if thread:thread.join(5);assert not thread.is_alive();thread=None
        if held:held.close();held=None
    def row(pid):
        click('.primary-nav button:first-child');select('.group-strip select','all');fill('#client-search','')
        selector='[data-profile-menu="'+pid+'"]';wait_for('return !!document.querySelector('+json.dumps(selector)+')')
        js('document.querySelector(arguments[0]).scrollIntoView({block:"center"})',selector)
        return selector
    try:
        command('disconnect')
        with socket.socket() as listener:listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
        command('preferences',{**initial['preferences'],'language':'en','theme':'dark','connectionMode':'local','inboundPort':port,'ping':{**initial['preferences']['ping'],'timeoutMs':3000}})
        route=copy.deepcopy(old_route);current=next(p for p in route['profiles'] if p['id']==route['active']);current['rules']=[{'id':'preflight56-proxy','name':'Owned preflight traffic','enabled':True,'config':{'ip_cidr':['127.0.0.1/32'],'outbound':'proxy'}}];command('saveRouting',route)
        source,owner=group('Preflight members'),group('Preflight pools');a=add(source,'Preflight Alpha',0);b=add(source,'Preflight Beta',1);c=add(source,'Preflight Gamma',0);old=add(owner,'Existing connection',1)
        config={'type':'auto-selector','member_source':{'group_id':source,'order':'saved-http-latency','build_limit':1,'pool_cap':1},'url':url,'interval':'1h','bench_interval':'1h','watch_interval':'1h','timeout':'2s','sampling':2,'expected':1,'active_size':1,'interrupt_exist_connections':False}
        pid=command('saveProfile',{'groupId':owner,'name':'Automatic preparation','kind':'auto-selector','config':config})['id']
        click(row(pid));click('#menu-edit-profile');wait_for('return !!document.querySelector("#selector-connect-measurements") && !document.querySelector("#selector-preview-loading")');click('#selector-connect-measurements');click('button[form="profile-editor"]');wait_for('return !document.querySelector("dialog[open]")')
        config=cfg(pid);check(config['member_source']['measure_before_connect'] is True,'editor saves the opt-in automatic connection measurement setting')
        measure([b]);command('select',{'id':pid});wait_for('return document.querySelector(".session-card")?.dataset.sessionProfile==='+json.dumps(pid));modes('hold');click('.power-button');blocked();wait_for('return !!document.querySelector("#cancel-connection-preparation")')
        snapshot=command('snapshot');job=snapshot['connectionPreparation'];check(job['total']==2 and job['fresh']==1 and snapshot['running'] is None and len(snapshot['urlTests']['entries'])==2,'Connect automatically measures only the two missing candidates before both one-server limits')
        click('#cancel-connection-preparation');modes('ok');drained();idle();wait_for('return !document.querySelector(".power-button").disabled');check(cfg(pid)==config and command('snapshot')['running'] is None,'native Cancel stops preparation without saving an order or starting the pool')

        command('connect',{'id':old});original_active=active(old);held=stream();stop.clear();thread=threading.Thread(target=pulse,name='preflight56-stream');thread.start()
        command('clearUrlTests');modes('hold');begin(pid,'cancel-active');blocked();snapshot=command('snapshot');job=snapshot['connectionPreparation'];before=len(beats)
        check(reject('connect',{'id':old},'connection_preparing') and not command('cancelConnectionPreparation',{'id':'foreign-job'}),'connection coordinator rejects a duplicate start and ignores a foreign cancellation token')
        check(active(old)==original_active and command('snapshot')['running']==old,'preflight leaves the previous Core configuration active while measuring')
        command('cancelConnectionPreparation',{'id':job['id']});modes('ok');drained();result=finish('cancel-active')
        until(lambda:len(beats)>before or bool(errors),'No heartbeat after preflight cancellation',3)
        print(json.dumps({'cancelActive':{'result':result,'heartbeatsBefore':before,'heartbeatsAfter':len(beats),'errors':errors,'savedPoolUnchanged':cfg(pid)==config}}),flush=True)
        check(not result['ok'] and result['error'].get('code')=='selector_measurements_cancelled' and len(beats)>before and not errors and cfg(pid)==config,'cancelled preflight preserves the saved pool and the previous live CONNECT stream')

        command('clearUrlTests');modes('hold');begin(pid,'stale-candidate');blocked();saved=command('profile',{'id':a});command('saveProfile',{**saved,'config':{**saved['config'],'server_port':info['ports'][1]}});modes('ok');result=finish('stale-candidate');drained();check(not result['ok'] and result['error'].get('code')=='selector_measurements_stale' and active(old)==original_active and cfg(pid)==config,'editing a candidate during measurement prevents starting or persisting a stale pool');command('saveProfile',{**saved,'expectedRevision':command('profile',{'id':a})['expectedRevision']})

        command('clearUrlTests');modes('hold');begin(pid,'replaced-queue');blocked();owned=command('snapshot')['urlTests']['id'];command('cancelUrlTestBatch',{'id':owned});manual=command('startUrlTests',{'ids':[b],'url':url,'timeoutMs':3000})['id'];result=finish('replaced-queue');batch=command('snapshot')['urlTests'];check(not result['ok'] and result['error'].get('code')=='selector_measurements_interrupted' and batch['id']==manual and any(e['status'] in ('queued','testing') for e in batch['entries']),'a replaced preflight queue is rejected without cancelling a newer manual queue');command('cancelUrlTestBatch',{'id':manual});modes('ok');drained()

        command('clearUrlTests');modes('hold');manual=command('startUrlTests',{'ids':[b],'url':url,'timeoutMs':3000})['id'];blocked();check(reject('connect',{'id':pid},'probe_busy') and command('snapshot')['urlTests']['id']==manual and active(old)==original_active,'a busy manual queue prevents preparation without replacing that queue or the active connection');command('cancelUrlTestBatch',{'id':manual});modes('ok');drained()

        # A failed checked Core launch must never save the proposed new ranking.
        admin(0,downloadMode='ok');admin(1,downloadMode='slow');measure([a,b,c]);saved_pool=command('profile',{'id':pid});broken={**saved_pool,'config':{**saved_pool['config'],'interval':'not-a-duration'}};command('saveProfile',broken);begin(pid,'invalid-start');result=finish('invalid-start')
        check(not result['ok'] and cfg(pid)==broken['config'] and active(old)==original_active and not errors,'failed Core validation leaves the old connection and the previous saved ranking intact');command('saveProfile',{**saved_pool,'expectedRevision':command('profile',{'id':pid})['expectedRevision']})
        stop_stream();check(len(beats)>=5 and not errors,'the owned CONNECT stream carried repeated heartbeats across cancellation, staleness and failed preparation')

        # Fresh observations cause no disposable URL batch; successful Start commits rank + selection.
        prior=command('snapshot')['urlTests'];observations=prior['entries'];assert all(e['status']=='ok' for e in observations);expected=min(observations,key=lambda e:(e['latencyMs'],[a,b,c].index(e['profileId'])))['profileId']
        begin(pid,'fresh-success');result=finish('fresh-success');print(json.dumps({'freshSuccess':{'result':result,'expected':expected,'saved':cfg(pid)['member_source'].get('saved_ranking'),'running':command('snapshot')['running']}}),flush=True)
        check(result['ok'] and command('snapshot')['running']==pid and cfg(pid)['member_source']['saved_ranking']['members']==[expected] and pool_members(pid)==[expected],'successful connection atomically saves the ranked candidate and starts that exact server')
        check(command('snapshot')['urlTests']==prior,'fresh candidates are reused without starting another disposable HTTP batch')
        history=next(p for p in command('getSelectorHistory') if p['profileId']==pid);check(history['lastBuilt']==[expected],'startup history records the successfully applied ranked membership')
        command('disconnect')

        # A real DBusMenu connection must use the same missing-check coordinator.
        from native_menu import NativeMenu
        menu=NativeMenu();command('clearUrlTests');modes('hold');menu.activate(menu.ready('Automatic preparation'));blocked()
        pending=command('snapshot')['connectionPreparation'];check(pending['profileId']==pid and pending['total']==3 and command('snapshot')['running'] is None,'native tray connection enters the same preflight coordinator with all three missing candidates')
        modes('ok');idle();until(lambda:command('snapshot')['running']==pid,'Tray preparation did not connect after its HTTP workers finished')
        observations=command('snapshot')['urlTests']['entries'];assert all(e['status']=='ok' for e in observations)
        expected=min(observations,key=lambda e:(e['latencyMs'],[a,b,c].index(e['profileId'])))['profileId']
        check(cfg(pid)['member_source']['saved_ranking']['members']==[expected] and pool_members(pid)==[expected],'completed missing HTTP checks lead to a successful connection and persist the measured order')
        menu.ready('Connected: Automatic preparation',False);menu.ready('Saved routing is applied',False)
        command('clearUrlTests');modes('hold');previous_active=active(pid)
        menu.activate(menu.ready('Direct connection'));blocked()
        pending=command('snapshot')['connectionPreparation']
        check(pending['profileId']==pid and pending['total']==3 and active(pid)==previous_active and command('snapshot')['routing']['pending'],'native tray routing applies through preflight while retaining the previous active pool')
        modes('ok');idle();until(lambda:not command('snapshot')['routing']['pending'],'Tray routing preparation did not apply')
        check(command('snapshot')['running']==pid and command('snapshot')['routing']['mode']=='direct' and cfg(pid)['member_source']['saved_ranking']['members']==pool_members(pid),'tray routing applies the measured membership and marks the new mode active')
        command('disconnect')

        # Verify real progress and cancellation controls in both narrow localized windows.
        for language in ['ru','en']:
            command('clearUrlTests');command('preferences',{**command('snapshot')['preferences'],'language':language});wait_for('return document.documentElement.lang==='+json.dumps(language));h['request']('POST',h['base']+'/window/rect',{'width':390,'height':844});modes('hold');token='layout-'+language;begin(pid,token);blocked();wait_for('return !!document.querySelector("#connection-preparation")');js('document.querySelector("#connection-preparation").scrollIntoView({block:"start"})')
            check(js('const p=document.querySelector("#connection-preparation"),b=p.querySelector("button"),r=p.getBoundingClientRect(),br=b.getBoundingClientRect(),header=document.querySelector(".topbar").getBoundingClientRect();return document.documentElement.scrollWidth<=innerWidth && p.scrollWidth<=p.clientWidth && r.top>=header.bottom && br.bottom<innerHeight-64 && document.elementFromPoint(br.x+br.width/2,br.y+br.height/2)===b'),language+' connection progress and cancellation fit a 390 px native window');screenshot('selector-preflight-'+language+'-390');click('#cancel-connection-preparation');modes('ok');finish(token);drained()
        Path(h['artifacts']).joinpath('preflight-network-audit.json').write_text(json.dumps({'heartbeats':len(beats),'heartbeatErrors':errors,'missingCandidates':2,'freshCandidatesReused':1,'failedPreparationPreservedConnection':True,'manualQueuePreserved':True,'externalRequests':False},indent=2)+'\n')
    finally:
        with contextlib.suppress(Exception):
            pending=command('snapshot').get('connectionPreparation')
            if pending:command('cancelConnectionPreparation',{'id':pending['id']})
        with contextlib.suppress(Exception):command('cancelUrlTests')
        with contextlib.suppress(Exception):modes('ok')
        stop_stream()
        with contextlib.suppress(Exception):command('disconnect')
        for token in tokens:
            with contextlib.suppress(Exception):finish(token)
        for gid in reversed(groups):
            with contextlib.suppress(Exception):command('deleteGroup',{'id':gid,'deleteProfiles':True})
        command('saveRouting',{**old_route,'revision':command('routing')['revision']});command('preferences',initial['preferences'])
        h['request']('POST',h['base']+'/window/rect',{'width':geometry['width'],'height':geometry['height']})
