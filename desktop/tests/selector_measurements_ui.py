"""Missing HTTP measurements, draft guards and owned queue cancellation with live traffic."""
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
    info=json.loads(Path(os.environ['_THRONIUM_DIAGNOSTICS_FIXTURE']).read_text());initial=command('snapshot');old_route=command('routing');geometry=h['request']('GET',h['base']+'/window/rect');groups=[];held=None;thread=None;stop=threading.Event();beats=[];errors=[]
    url='http://127.0.0.1:'+str(info['httpPorts'][0])+'/health'
    def admin(i,**data):
        req=urllib.request.Request(info['admins'][i],data=json.dumps(data).encode(),headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(req,timeout=3) as response:return json.load(response)
    def group(name):gid=command('saveGroup',{'name':name})['id'];groups.append(gid);return gid
    def add(gid,name,p):return command('saveProfile',{'groupId':gid,'name':name,'kind':'sing-box-outbound','config':{'type':'socks','server':'127.0.0.1','server_port':p}})['id']
    def edit(pid,editable=True):
        click('.primary-nav button:first-child');select('.group-strip select','all');fill('#client-search','');selector='[data-profile-menu="'+pid+'"]';wait_for('return !!document.querySelector('+json.dumps(selector)+')');js('document.querySelector(arguments[0]).scrollIntoView({block:"center"})',selector);click(selector);click('#menu-edit-profile');wait_for('return !!document.querySelector("#selector-limit-enabled")')
        if editable:wait_for('return !document.querySelector("#selector-limit-enabled").disabled')
    def close():
        click('#main-modal > .modal-head > button')
        if js('return !!document.querySelector(".editor-discard")'):click('.editor-discard [data-confirm-accept]')
        wait_for('return !document.querySelector("dialog[open]")')
    def preview(ids):wait_for('return !document.querySelector("#selector-preview-loading") && JSON.stringify([...document.querySelectorAll("[data-selector-preview-member]")].map(e=>e.dataset.selectorPreviewMember))==='+json.dumps(json.dumps(ids,separators=(',',':'))))
    def measure(ids):
        run=command('startUrlTests',{'ids':ids,'url':url,'timeoutMs':3000})['id'];deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            batch=command('snapshot')['urlTests']
            if batch and batch['id']==run and all(e['status'] not in ('queued','testing') for e in batch['entries']):
                assert all(e['status']=='ok' for e in batch['entries']);return {e['profileId']:e['latencyMs'] for e in batch['entries']}
            time.sleep(.05)
        raise AssertionError('Owned HTTP queue did not finish')
    def config(pid):
        active=command('connectionConfiguration',{'id':pid,'active':True});return active,next(o for p in active['parts'] for o in p['config'].get('outbounds',[]) if o.get('type')=='auto-selector' and o.get('tag')=='proxy')
    def members(core):return [tag.removeprefix('thronium-selector-proxy-') for tag in core['outbounds']]
    def history(pid):return next(p for p in command('getSelectorHistory') if p['profileId']==pid)
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
                data=('measure54-'+str(len(beats))).encode();held.sendall(data);reply=b''
                while len(reply)<len(data):
                    chunk=held.recv(len(data)-len(reply));assert chunk;reply+=chunk
                assert reply==data;beats.append(time.monotonic());stop.wait(.2)
        except BaseException as error:errors.append(repr(error))
    def stop_stream():
        nonlocal held
        stop.set()
        if thread:thread.join(5);assert not thread.is_alive()
        if held:held.close();held=None
    def eventually(predicate, message):
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            if predicate():return
            time.sleep(.05)
        raise AssertionError(message)
    def modes(mode):
        for i in range(2):admin(i,downloadMode=mode)
    def forwarded():return sum(admin(i)['warmForwarded'] for i in range(2))
    def drained():eventually(lambda:all(admin(i)['warmBlocked']==0 for i in range(2)), 'Owned HTTP gates did not drain')
    def held_checks():eventually(lambda:any(admin(i)['warmBlocked']>0 for i in range(2)), 'No actual HTTP request reached the owned gate')
    def finished():wait_for('return !document.querySelector("#selector-measure-progress") && !document.querySelector("#selector-measure-order").disabled',15)
    def draft():return {'id':pid,'groupId':owner,'name':'Measured order pool','kind':'auto-selector','config':command('profile',{'id':pid})['config']}
    def gate(name):
        js('window.__measure54Fetch=window.fetch; window.__measure54Held=false; window.__measure54Issued=false')
        # Gate only delivery of the real response; do not replace Tauri invoke.
        js('''window.fetch=function(input,init) {let target=false;try {target=!window.__measure54Issued && String(input).endsWith('/app_command') && JSON.parse(init?.body).name==='''+json.dumps(name)+'''}catch(_){} if(target) window.__measure54Issued=true; const pending=window.__measure54Fetch.call(this,input,init);return target ? pending.then(response=>new Promise(resolve=>{window.__measure54Held=true;window.__measure54Release=()=>resolve(response)})) : pending}''')
    def release():js('if(window.__measure54Release) {window.__measure54Release();delete window.__measure54Release} if(window.__measure54Fetch) {window.fetch=window.__measure54Fetch;delete window.__measure54Fetch}')
    try:
        command('disconnect')
        with socket.socket() as listener:listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
        command('preferences',{**initial['preferences'],'language':'en','theme':'dark','connectionMode':'local','inboundPort':port,'ping':{**initial['preferences']['ping'],'timeoutMs':3000}})
        route=copy.deepcopy(old_route);current=next(p for p in route['profiles'] if p['id']==route['active']);current['rules']=[{'id':'measure54-proxy','name':'Owned measured pool traffic','enabled':True,'config':{'ip_cidr':['127.0.0.1/32'],'outbound':'proxy'}}];command('saveRouting',route)
        source,owner=group('Measured order members'),group('Measured order pools');a=add(source,'Measure Alpha',info['ports'][0]);b=add(source,'Measure Beta',info['ports'][1]);c=add(source,'Measure Gamma',info['ports'][0]);ids=[a,b,c]
        admin(0,downloadMode='slow');admin(1,downloadMode='ok');measure([b])
        cfg={'type':'auto-selector','member_source':{'group_id':source,'build_limit':1,'pool_cap':1,'order':'saved-http-latency'},'url':url,'interval':'1h','bench_interval':'1h','watch_interval':'1h','timeout':'2s','sampling':2,'expected':1,'active_size':1,'interrupt_exist_connections':False}
        pid=command('saveProfile',{'groupId':owner,'name':'Measured order pool','kind':'auto-selector','config':cfg})['id']
        plan=command('planSelectorMeasurements',{'profile':draft()});check(plan['ids']==[a,c] and plan['candidateCount']==3 and plan['freshCount']==1,'planning finds two missing checks among all three candidates before both one-member limits')
        edit(pid);preview([b]);requests=forwarded();click('#selector-measure-order');wait_for('return document.querySelector("#selector-saved-order-count")?.textContent.includes("Saved candidates: 1.")');finished();preview([b])
        # Disposable Core HTTP checks perform a warm request then a timed request.
        print(json.dumps({'firstMeasurementAudit':{'requests':forwarded()-requests,'remaining':command('planSelectorMeasurements',{'profile':draft()})['ids'],'unchanged':command('profile',{'id':pid})['config']==cfg}}),flush=True)
        check(forwarded()-requests==4 and command('planSelectorMeasurements',{'profile':draft()})['ids']==[] and command('profile',{'id':pid})['config']==cfg,'native action measures exactly the missing servers beyond both caps and only updates the draft')
        click('button[form="profile-editor"]');wait_for('return !document.querySelector("dialog[open]")');saved=command('profile',{'id':pid})['config'];check(saved['member_source']['saved_ranking']['members']==[b],'Save persists the newly measured capped order')
        edit(pid);preview([b]);requests=forwarded();click('#selector-measure-order');finished();check(forwarded()==requests and command('profile',{'id':pid})['config']==saved,'a fully fresh candidate set reranks without extra HTTP requests or library writes');close()

        # A cancelled sweep retains a pre-existing fresh result and only cancels its own issued batch.
        command('clearUrlTests');measure([b]);modes('hold');edit(pid);preview([b]);click('#selector-measure-order');held_checks();batch=command('snapshot')['urlTests'];check(len(batch['entries'])==2,'only missing candidates enter the owned live queue')
        click('#selector-cancel-measurements');wait_for('return document.querySelector("#selector-measure-error")?.textContent.startsWith("Checks cancelled.")');modes('ok');drained();finished()
        check(command('profile',{'id':pid})['config']==saved and command('planSelectorMeasurements',{'profile':draft()})['freshCount']==1,'Cancel leaves the saved order and the prior completed HTTP result intact');close()

        # Cancellation before the start response arrives must not touch a newer manual batch.
        command('clearUrlTests');modes('hold');edit(pid);preview([b]);gate('startUrlTests');click('#selector-measure-order');wait_for('return window.__measure54Held===true');held_checks();old=command('snapshot')['urlTests']['id'];click('#selector-cancel-measurements');command('cancelUrlTestBatch',{'id':old});modes('ok');drained();modes('hold')
        manual=command('startUrlTests',{'ids':[b],'url':url,'timeoutMs':3000})['id'];held_checks();release();time.sleep(.3);batch=command('snapshot')['urlTests']
        check(batch['id']==manual and all(e['status'] in ('queued','testing') for e in batch['entries']) and not command('cancelUrlTestBatch',{'id':old}),'a late cancelled start response cannot cancel a newer manual HTTP batch')
        command('cancelUrlTestBatch',{'id':manual});modes('ok');drained();close()

        # A filter change and editor closure discard a late final ranking delivery.
        measure(ids);edit(pid);preview([b]);gate('rankMeasuredSelector');click('#selector-measure-order');wait_for('return window.__measure54Held===true');fill('#selector-exclude-regex','^Measure Beta$');release();wait_for('return !document.querySelector("#selector-preview-loading")');time.sleep(.2)
        check(js('return document.querySelector("#selector-exclude-regex").value==="^Measure Beta$"') and command('profile',{'id':pid})['config']==saved,'a late measured ranking does not overwrite an edited filter');close()
        edit(pid);preview([b]);gate('rankMeasuredSelector');click('#selector-measure-order');wait_for('return window.__measure54Held===true');close();release();time.sleep(.2);check(command('profile',{'id':pid})['config']==saved and not js('return !!document.querySelector("dialog[open]")'),'closing the editor discards a late measured ranking');

        # Hold a genuine plan response, change the candidate network, then run that plan.
        command('clearUrlTests');edit(pid);preview([b]);gate('planSelectorMeasurements');click('#selector-measure-order');wait_for('return window.__measure54Held===true');candidate=command('profile',{'id':a});changed={**candidate,'config':{**candidate['config'],'server_port':info['ports'][1]}};command('saveProfile',changed);release();finished()
        check(js('return document.querySelector("#selector-measure-error")?.textContent.startsWith("Server settings or the pool changed")') and command('profile',{'id':pid})['config']==saved,'a changed server network context prevents applying the measured order');close();command('saveProfile',{**candidate,'expectedRevision':command('profile',{'id':a})['expectedRevision']})

        # Failed HTTP observations are completed measurements and are not retried immediately.
        command('clearUrlTests');admin(0,downloadMode='http-error');admin(1,downloadMode='ok');edit(pid);preview([b]);click('#selector-measure-order');finished();check(not js('return !!document.querySelector("#selector-measure-error")') and command('planSelectorMeasurements',{'profile':draft()})['freshCount']==3,'fresh HTTP failures finish the sweep and remain reusable observations');close();modes('ok')

        # A live connection and open CONNECT stream must survive all measurement workers.
        command('connect',{'id':pid});active,compiled=config(pid);held,body=tunnel('/stream');assert body==b'ready';thread=threading.Thread(target=pulse,name='measure54-owned-heartbeat');thread.start();command('clearUrlTests');edit(pid,False);preview([b]);before=len(beats);click('#selector-measure-order');finished();time.sleep(.45)
        check(len(beats)>before and not errors and config(pid)[0]==active and command('profile',{'id':pid})['config']==saved and history(pid)['lastBuilt']==[b],'HTTP measurements preserve the exact active Core configuration, saved profile, history and open CONNECT stream')
        close();stop_stream();command('disconnect')

        # Review localized controls and finite errors in a real narrow webview.
        edit(pid);preview([b]);fill('#selector-result-validity','0');wait_for('return !document.querySelector("#selector-measure-order").disabled');click('#selector-measure-order');finished();check(js('return document.querySelector("#selector-measure-error")?.textContent.includes("greater than zero")'),'zero measurement lifetime is rejected with a finite explanation before starting a queue')
        for language,theme in [('ru','light'),('en','dark')]:
            command('preferences',{**command('snapshot')['preferences'],'language':language,'theme':theme});wait_for('return document.documentElement.lang==='+json.dumps(language));h['request']('POST',h['base']+'/window/rect',{'width':390,'height':844});js('document.querySelector("#selector-measure-order").scrollIntoView({block:"start"})');check(js('return document.documentElement.scrollWidth<=innerWidth && document.querySelector(".selector-fields").scrollWidth<=document.querySelector(".selector-fields").clientWidth'),language+' measurement controls and finite errors fit a 390-pixel native window');screenshot('selector-measurements-'+language+'-390')
        close();check(command('profile',{'id':pid})['config']==saved,'discarding the editor preserves the last explicitly saved order')
        Path(h['artifacts']).joinpath('measurements-network-audit.json').write_text(json.dumps({'missingChecks':2,'missingRequests':4,'freshRequests':0,'heartbeats':len(beats),'heartbeatErrors':errors,'lateIssuanceProtectedManualQueue':True,'networkContextRejected':True,'externalRequests':False},indent=2)+'\n')
    finally:
        with contextlib.suppress(Exception):release()
        with contextlib.suppress(Exception):modes('ok')
        stop_stream()
        with contextlib.suppress(Exception):command('cancelUrlTests')
        command('disconnect')
        for gid in reversed(groups):command('deleteGroup',{'id':gid,'deleteProfiles':True})
        command('saveRouting',{**old_route,'revision':command('routing')['revision']});command('preferences',initial['preferences'])
        if initial['selected']:command('select',{'id':initial['selected']})
        h['request']('POST',h['base']+'/window/rect',{'width':geometry['width'],'height':geometry['height']})
