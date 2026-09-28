"""Saved HTTP candidate order after real measurements, with held owned proxy traffic."""
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
                data=('order53-'+str(len(beats))).encode();held.sendall(data);reply=b''
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
        route=copy.deepcopy(old_route);current=next(p for p in route['profiles'] if p['id']==route['active']);current['rules']=[{'id':'order53-proxy','name':'Owned HTTP via saved order','enabled':True,'config':{'ip_cidr':['127.0.0.1/32'],'outbound':'proxy'}}];command('saveRouting',route)
        source,owner=group('Saved order members'),group('Saved order pools');a=add(source,'Order Alpha',info['ports'][0]);b=add(source,'Order Beta',info['ports'][1]);c=add(source,'Order Gamma',info['ports'][0]);ids=[a,b,c]
        admin(0,downloadMode='slow');admin(1,downloadMode='ok');latencies=measure(ids);ranked=sorted(ids,key=lambda key:latencies[key]);assert ranked[0]==b
        check(True,'saved order uses actual completed HTTP measurements from independently delayed owned proxies')
        cfg={'type':'auto-selector','member_source':{'group_id':source,'build_limit':2,'pool_cap':4,'warm_start':True},'url':url,'interval':'1h','bench_interval':'1h','watch_interval':'1h','timeout':'2s','sampling':2,'expected':2,'active_size':2,'interrupt_exist_connections':False}
        pid=command('saveProfile',{'groupId':owner,'name':'Saved HTTP order pool','kind':'auto-selector','config':cfg})['id'];edit(pid);preview(ids[:2]);check(not js('return !!document.querySelector("#selector-rank-order")'),'existing library order does not enable saved ranking implicitly')
        select('#selector-member-order','saved-http-latency');preview(ranked[:2]);check(js('return document.querySelector("#selector-saved-order-count").textContent.includes("No saved order yet")'),'new saved-order mode starts without invented ranking history')
        before_requests=[admin(i)['rankingRequests'] for i in range(2)];before_revision=command('snapshot')['libraryRevision'];click('#selector-rank-order');wait_for('return document.querySelector("#selector-saved-order-count")?.textContent.includes("Saved candidates: 3.")');preview(ranked[:2])
        check([admin(i)['rankingRequests'] for i in range(2)]==before_requests and command('snapshot')['libraryRevision']==before_revision and command('profile',{'id':pid})['config']==cfg,'ranking covers all three candidates before the two-member startup limit without HTTP requests or library writes')
        click('button[form="profile-editor"]');wait_for('return !document.querySelector("dialog[open]")');saved=command('profile',{'id':pid})['config'];saved_rank=saved['member_source']['saved_ranking'];check(saved_rank['members']==ranked and saved_rank['ranked_at']>0,'native Save persists the whole ranked candidate list and its timestamp')
        h['request']('POST',h['base']+'/refresh',{});wait_for('return !!document.querySelector(".power-button")');edit(pid);preview(ranked[:2]);check(js('return document.querySelector("#selector-member-order").value==="saved-http-latency" && document.querySelector("#selector-saved-order-count").textContent.includes("Saved candidates: 3.")'),'saved order survives a native webview reload');close()
        admin(0,downloadMode='ok');admin(1,downloadMode='slow');d=add(source,'Order Delta',info['ports'][0]);all_ids=ids+[d];new_times=measure(all_ids);new_ranked=sorted(all_ids,key=lambda key:new_times[key]);assert new_ranked[-1]==b
        edit(pid);preview(ranked[:2]);check(command('profile',{'id':pid})['config']==saved,'new HTTP measurements and a newcomer leave the saved priority intact')
        fill('#selector-build-limit','4');preview(ranked+[d]);check(js('return document.querySelector("#selector-saved-order-count").textContent.includes("Retained in the pool: 3.") && document.querySelector("#selector-saved-order-count").textContent.endsWith("New candidates in the pool: 1")'),'newcomer appends after the three saved eligible candidates');fill('#selector-build-limit','2');preview(ranked[:2])
        # Delay only delivery of an actual rankSelector result in this private webview.
        js('''window.__order53Fetch = window.fetch; window.__order53Held = false; window.fetch = function(input,init) { let target=false; try {target=String(input).endsWith('/app_command') && JSON.parse(init?.body).name==='rankSelector'} catch (_) {} const pending=window.__order53Fetch.call(this,input,init); if(target) return pending.then(response=>new Promise(resolve=>{window.__order53Held=true;window.__order53Release=()=>resolve(response)})); return pending; }''')
        click('#selector-rank-order');wait_for('return window.__order53Held===true');fill('#selector-exclude-regex','^Order Beta$');filtered=[p for p in ranked if p!=b]+[d];preview(filtered[:2]);js('window.__order53Release(); window.fetch=window.__order53Fetch; delete window.__order53Fetch');time.sleep(.3);preview(filtered[:2])
        check(js('return document.querySelector("#selector-exclude-regex").value==="^Order Beta$" && document.querySelector("#selector-saved-order-count").textContent.includes("Saved candidates: 3.")') and command('profile',{'id':pid})['config']==saved,'late RPC result cannot overwrite a changed filter or its saved ranking');close();edit(pid);preview(ranked[:2])
        click('#selector-rank-order');wait_for('return document.querySelector("#selector-saved-order-count")?.textContent.includes("Saved candidates: 4.")');preview(new_ranked[:2]);close();check(command('profile',{'id':pid})['config']==saved,'Cancel discards a freshly reranked draft without altering stored order')
        edit(pid);preview(ranked[:2]);click('#selector-rank-order');wait_for('return document.querySelector("#selector-saved-order-count")?.textContent.includes("Saved candidates: 4.")');preview(new_ranked[:2]);click('button[form="profile-editor"]');wait_for('return !document.querySelector("dialog[open]")');saved=command('profile',{'id':pid})['config'];check(saved['member_source']['saved_ranking']['members']==new_ranked,'explicit Update and Save replace the complete stored ranking')
        command('connect',{'id':pid});active,compiled=config(pid);check(members(compiled)==new_ranked[:2] and len(compiled['warm'])==2 and history(pid)['lastBuilt']==new_ranked[:2],'Core warm tags and successful startup history use the final saved-order members')
        held,body=tunnel('/stream');assert body==b'ready';thread=threading.Thread(target=pulse,name='order53-owned-heartbeat');thread.start();time.sleep(.4)
        admin(0,downloadMode='slow');admin(1,downloadMode='ok');last_times=measure(all_ids);last_ranked=sorted(all_ids,key=lambda key:last_times[key]);assert last_ranked[0]==b
        edit(pid,False);preview(new_ranked[:2]);click('#selector-rank-order');preview(last_ranked[:2]);check(command('profile',{'id':pid})['config']==saved and config(pid)[0]==active,'native reranking while connected changes only the editor draft')
        draft={'id':pid,'groupId':owner,'name':'Saved HTTP order pool','kind':'auto-selector','config':saved};proposed=command('rankSelector',{'profile':draft});assert proposed['members']==last_ranked;count=len(beats);time.sleep(.45)
        check(len(beats)>count and not errors and config(pid)[0]==active and command('profile',{'id':pid})['config']==saved and history(pid)['lastBuilt']==new_ranked[:2],'pure reranking while active preserves the stored order, exact Core request, history and open CONNECT stream')
        changed=copy.deepcopy(saved);changed['member_source']['saved_ranking']=proposed
        try:command('saveProfile',{**draft,'expectedRevision':command('profile',{'id':pid})['expectedRevision'],'config':changed});raise AssertionError('Active saved-order edit unexpectedly accepted')
        except RuntimeError as error:assert 'stop_before_editing' in str(error)
        check(command('profile',{'id':pid})['config']==saved,'active-profile protection rejects replacing the saved ranking');close();stop_stream();command('disconnect')
        edit(pid);preview(new_ranked[:2]);click('#selector-rank-order');wait_for('return !document.querySelector("#selector-rank-order").disabled');preview(last_ranked[:2])
        for language,theme in [('ru','light'),('en','dark')]:
            command('preferences',{**command('snapshot')['preferences'],'language':language,'theme':theme});wait_for('return document.documentElement.lang==='+json.dumps(language));preview(last_ranked[:2]);h['request']('POST',h['base']+'/window/rect',{'width':390,'height':844});js('document.querySelector("#selector-saved-order-hint").scrollIntoView({block:"start"})');check(js('return document.documentElement.scrollWidth<=innerWidth && document.querySelector(".selector-fields").scrollWidth<=document.querySelector(".selector-fields").clientWidth'),language+' saved-order actions and counts fit a 390-pixel native window');screenshot('selector-saved-order-'+language+'-390')
        h['request']('POST',h['base']+'/window/rect',{'width':1280,'height':860});click('button[form="profile-editor"]');wait_for('return !document.querySelector("dialog[open]")');command('connect',{'id':pid});_,next_config=config(pid);check(members(next_config)==last_ranked[:2] and history(pid)['lastBuilt']==last_ranked[:2],'next successful connection applies the explicitly reranked order');conn,body=tunnel('/body');conn.close();check(body==b'country45:0','saved-order pool forwards the complete independent HTTP body')
        command('disconnect');edit(pid);preview(last_ranked[:2]);click('#selector-clear-order');preview(last_ranked[:2]);check(js('return document.querySelector("#selector-saved-order-count").textContent.includes("No saved order yet")'),'Clear removes prior ranking from the draft while retaining the selected mode');click('button[form="profile-editor"]');wait_for('return !document.querySelector("dialog[open]")');source_saved=command('profile',{'id':pid})['config']['member_source'];check('saved_ranking' not in source_saved and source_saved['order']=='saved-http-latency' and source_saved['build_limit']==2 and source_saved['pool_cap']==4,'Save after Clear removes saved IDs and timestamp while retaining independent source settings')
        Path(h['artifacts']).joinpath('saved-order-network-audit.json').write_text(json.dumps({'firstRanking':ranked,'secondRanking':new_ranked,'lastRanking':last_ranked,'heartbeats':len(beats),'heartbeatErrors':errors,'rankingExtraHttpRequests':0,'lateRpcDiscarded':True,'externalRequests':False},indent=2)+'\n')
    finally:
        with contextlib.suppress(Exception):js('if(window.__order53Release) window.__order53Release(); if(window.__order53Fetch) {window.fetch=window.__order53Fetch; delete window.__order53Fetch}')
        stop_stream()
        with contextlib.suppress(Exception):command('cancelUrlTests')
        command('disconnect')
        for gid in reversed(groups):command('deleteGroup',{'id':gid,'deleteProfiles':True})
        command('saveRouting',{**old_route,'revision':command('routing')['revision']});command('preferences',initial['preferences'])
        if initial['selected']:command('select',{'id':initial['selected']})
        h['request']('POST',h['base']+'/window/rect',{'width':geometry['width'],'height':geometry['height']})
