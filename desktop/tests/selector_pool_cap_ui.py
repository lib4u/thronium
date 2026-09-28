"""Separate candidate pool cap after real measurements, with held owned proxy traffic."""
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
                data=('poolcap52-'+str(len(beats))).encode();held.sendall(data);reply=b''
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
        route=copy.deepcopy(old_route);current=next(p for p in route['profiles'] if p['id']==route['active']);current['rules']=[{'id':'poolcap52-proxy','name':'Owned HTTP via limited pool','enabled':True,'config':{'ip_cidr':['127.0.0.1/32'],'outbound':'proxy'}}];command('saveRouting',route)
        source,owner=group('Candidate members'),group('Candidate pools');a=add(source,'Limit Alpha',info['ports'][0]);b=add(source,'Limit Beta',info['ports'][1]);c=add(source,'Limit Gamma',info['ports'][0]);ids=[a,b,c]
        admin(0,downloadMode='slow');admin(1,downloadMode='ok');latencies=measure(ids);ranked=sorted(ids,key=lambda key:latencies[key]);assert ranked[0]==b
        check(True,'startup candidates have real completed HTTP measurements through independently delayed proxies')
        cfg={'type':'auto-selector','member_source':{'group_id':source},'url':url,'interval':'1h','bench_interval':'1h','watch_interval':'1h','timeout':'2s','sampling':2,'expected':2,'active_size':2,'interrupt_exist_connections':False}
        pid=command('saveProfile',{'groupId':owner,'name':'Candidate capped pool','kind':'auto-selector','config':cfg})['id'];edit(pid);preview(ids);check(not js('return document.querySelector("#selector-limit-enabled").checked') and not js('return !!document.querySelector("#selector-build-limit")'),'startup limiting is disabled for an existing dynamic source')
        click('#selector-limit-enabled');fill('#selector-build-limit','3');preview(ids);check(not js('return document.querySelector("#selector-pool-cap-enabled").checked') and not js('return !!document.querySelector("#selector-pool-cap")'),'candidate cap remains optional when startup limiting is enabled')
        click('#selector-pool-cap-enabled');preview(ids);check(js('return document.querySelector("#selector-pool-cap").value==="1000"'),'enabling candidate cap uses the original Throne default of 1000')
        fill('#selector-pool-cap','2');preview(ids[:2]);check(js('return document.querySelector("#selector-pool-cap-count").textContent.includes(": 3.") && document.querySelector("#selector-pool-cap-count").textContent.includes(": 2.") && document.querySelector("#selector-pool-cap-count").textContent.endsWith(": 1")'),'candidate cap applies before startup limit and reports one excluded candidate')
        fill('#selector-build-limit','1');preview(ids[:1]);check(js('return document.querySelector("#selector-limit-count").textContent.includes(": 2.") && document.querySelector("#selector-limit-count").textContent.endsWith(": 1")'),'separate startup cap selects one of the two retained candidates');fill('#selector-build-limit','3');preview(ids[:2])
        for value in ['0','','3001']:
            fill('#selector-pool-cap',value);wait_for('return !!document.querySelector("#selector-preview-error")');click('button[form="profile-editor"]');check(js('return !!document.querySelector("dialog[open]") && !document.querySelector("#selector-preview-error").textContent.includes("selector_invalid_pool_cap")') and command('profile',{'id':pid})['config']==cfg,'invalid candidate cap '+repr(value)+' cannot overwrite the saved pool and has a localized explanation')
        fill('#selector-pool-cap','2');select('#selector-member-order','http-latency');click('#selector-warm-start');preview(ranked[:2]);check(js('return document.querySelector("#selector-warm-count").textContent.endsWith(": 2")'),'HTTP ordering happens before the limit and only the two built members receive startup hints')
        click('button[form="profile-editor"]');wait_for('return !document.querySelector("dialog[open]")');saved=command('profile',{'id':pid})['config'];check(saved['member_source']['build_limit']==3 and saved['member_source']['pool_cap']==2 and saved['member_source']['warm_start'],'native Save retains the explicit cap and independent HTTP warm option')
        h['request']('POST',h['base']+'/refresh',{});wait_for('return !!document.querySelector(".power-button")');edit(pid);preview(ranked[:2]);check(js('return document.querySelector("#selector-limit-enabled").checked && document.querySelector("#selector-build-limit").value==="3" && document.querySelector("#selector-pool-cap").value==="2"'),'candidate and startup limits survive a native webview reload');close()
        command('connect',{'id':pid});active,compiled=config(pid);check(members(compiled)==ranked[:2] and len(compiled['warm'])==2 and history(pid)['lastBuilt']==ranked[:2],'real Core configuration and startup history contain only the chosen limited members')
        held,body=tunnel('/stream');assert body==b'ready';thread=threading.Thread(target=pulse,name='poolcap52-owned-heartbeat');thread.start();time.sleep(.4)
        admin(0,downloadMode='ok');admin(1,downloadMode='slow');next_latencies=measure(ids);next_ranked=sorted(ids,key=lambda key:next_latencies[key]);assert next_ranked[-1]==b;d=add(source,'Limit Delta',info['ports'][0]);edit(pid,False);preview(next_ranked[:2]);count=len(beats);time.sleep(.45)
        check(len(beats)>count and not errors and config(pid)[0]==active and history(pid)['lastBuilt']==ranked[:2],'new measured ordering and an added candidate update preview while retaining the active limited pool and CONNECT stream')
        proposed=copy.deepcopy(saved);proposed['member_source']['pool_cap']=1
        try:command('saveProfile',{'expectedRevision':command('profile',{'id':pid})['expectedRevision'],'id':pid,'groupId':owner,'name':'Candidate capped pool','kind':'auto-selector','config':proposed});raise AssertionError('Active pool edit unexpectedly accepted')
        except RuntimeError as error:assert 'stop_before_editing' in str(error)
        check(command('profile',{'id':pid})['config']==saved and config(pid)[0]==active,'existing active-profile edit protection also applies to a changed startup limit');close();stop_stream();command('disconnect')
        edit(pid);fill('#selector-pool-cap','1');preview(next_ranked[:1])
        for language,theme in [('ru','light'),('en','dark')]:
            command('preferences',{**command('snapshot')['preferences'],'language':language,'theme':theme});wait_for('return document.documentElement.lang==='+json.dumps(language));preview(next_ranked[:1]);h['request']('POST',h['base']+'/window/rect',{'width':390,'height':844});js('document.querySelector("#selector-pool-cap-enabled").closest("label").scrollIntoView({block:"start"})');check(js('return document.documentElement.scrollWidth<=innerWidth && document.querySelector(".selector-fields").scrollWidth<=document.querySelector(".selector-fields").clientWidth'),language+' candidate cap controls fit a 390-pixel native window');screenshot('selector-pool-cap-'+language+'-390')
        h['request']('POST',h['base']+'/window/rect',{'width':1280,'height':860});click('button[form="profile-editor"]');wait_for('return !document.querySelector("dialog[open]")');command('connect',{'id':pid});_,next_config=config(pid);check(members(next_config)==next_ranked[:1] and len(next_config['warm'])==1 and history(pid)['lastBuilt']==next_ranked[:1],'next successful connection applies the new single-candidate cap to Core hints and history');conn,body=tunnel('/body');conn.close();check(body==b'country45:0','limited single-member pool forwards a complete real HTTP response')
        command('disconnect');edit(pid);click('#selector-pool-cap-enabled');preview(next_ranked);click('button[form="profile-editor"]');wait_for('return !document.querySelector("dialog[open]")');without_cap=command('profile',{'id':pid})['config']['member_source'];check('pool_cap' not in without_cap and without_cap['build_limit']==3,'disabling candidate cap preserves the independent startup limit');command('connect',{'id':pid});check(members(config(pid)[1])==next_ranked,'startup limit still selects three members with candidate cap disabled');command('disconnect');edit(pid);click('#selector-pool-cap-enabled');fill('#selector-pool-cap','2');preview(next_ranked[:2]);click('#selector-limit-enabled');wait_for('return !document.querySelector("#selector-limit-enabled").checked');preview(next_ranked+[d]);click('button[form="profile-editor"]');wait_for('return !document.querySelector("dialog[open]")');check(all(k not in command('profile',{'id':pid})['config']['member_source'] for k in ['build_limit','pool_cap']),'disabling the cap removes the optional setting instead of persisting a hidden limit');command('connect',{'id':pid});check(members(config(pid)[1])==next_ranked+[d],'subsequent connection without the cap restores all eligible ordered candidates')
        Path(h['artifacts']).joinpath('pool-cap-network-audit.json').write_text(json.dumps({'firstMembership':ranked[:2],'nextMembership':next_ranked[:1],'uncappedMembership':next_ranked+[d],'heartbeats':len(beats),'heartbeatErrors':errors,'externalRequests':False},indent=2)+'\n')
    finally:
        stop_stream()
        with contextlib.suppress(Exception):command('cancelUrlTests')
        command('disconnect')
        for gid in reversed(groups):command('deleteGroup',{'id':gid,'deleteProfiles':True})
        command('saveRouting',{**old_route,'revision':command('routing')['revision']});command('preferences',initial['preferences'])
        if initial['selected']:command('select',{'id':initial['selected']})
        h['request']('POST',h['base']+'/window/rect',{'width':geometry['width'],'height':geometry['height']})
