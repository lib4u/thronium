"""Native warm startup before any new HTTP response, with owned gated proxies."""
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
    info=json.loads(Path(os.environ['_THRONIUM_DIAGNOSTICS_FIXTURE']).read_text());initial=command('snapshot');old_route=command('routing');old_logging=command('settings')['logging'];geometry=h['request']('GET',h['base']+'/window/rect')
    groups=[];held=None;thread=None;stop=threading.Event();beats=[];errors=[];gates=[]
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
    def edit(pid):
        click('.primary-nav button:first-child');select('.group-strip select','all');fill('#client-search','');selector='[data-profile-menu="'+pid+'"]';wait_for('return !!document.querySelector('+json.dumps(selector)+')');js('document.querySelector(arguments[0]).scrollIntoView({block:"center"})',selector);click(selector);click('#menu-edit-profile');wait_for('return !!document.querySelector("#selector-warm-start")')
    def warm_count(n):wait_for('return !document.querySelector("#selector-preview-loading") && document.querySelector("#selector-warm-count")?.textContent.endsWith('+json.dumps(': '+str(n))+')')
    def measure(ids):
        batch_id=command('startUrlTests',{'ids':ids,'url':url,'timeoutMs':3000})['id'];deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            batch=command('snapshot')['urlTests']
            if batch and batch['id']==batch_id and all(e['status'] not in ('queued','testing') for e in batch['entries']):
                assert all(e['status']=='ok' for e in batch['entries']);return {e['profileId']:e['latencyMs'] for e in batch['entries']}
            time.sleep(.05)
        raise AssertionError('Owned HTTP measurements did not finish')
    def config_group(pid):
        active=command('connectionConfiguration',{'id':pid,'active':True})
        return active,next(o for p in active['parts'] for o in p['config'].get('outbounds',[]) if o.get('type')=='auto-selector' and o.get('tag')=='proxy')
    def gated_start(pid,expected,warm):
        for i in range(2):admin(i,downloadMode='hold')
        before=[admin(i)['warmForwarded'] for i in range(2)];started=time.monotonic();command('connect',{'id':pid})
        deadline=time.monotonic()+1.5
        while time.monotonic()<deadline and not any(admin(i)['warmBlocked'] for i in range(2)):time.sleep(.02)
        view=command('getAutoSelectors')[0];state=[admin(i) for i in range(2)];active,compiled=config_group(pid)
        assert view['selected']=='thronium-selector-proxy-'+expected,view
        assert [s['warmForwarded'] for s in state]==before and any(s['warmBlocked'] for s in state),state
        assert all(m['samples']==(1 if warm else 0) for m in view['members']),view
        assert bool(compiled.get('warm'))==warm,compiled
        gates.append({'warm':warm,'selected':expected,'forwardedBefore':before,'forwardedWhileBlocked':[s['warmForwarded'] for s in state],'samples':[m['samples'] for m in view['members']],'seconds':round(time.monotonic()-started,3)})
        return active,compiled,view
    def release():
        for i in range(2):admin(i,downloadMode='ok')
    def probes_continue(before):
        deadline=time.monotonic()+8
        while time.monotonic()<deadline:
            view=command('getAutoSelectors')[0]
            if sum(m['probes'] for m in view['members'])>before and view['roundsCompleted']>0:return view
            time.sleep(.06)
        raise AssertionError('Normal Core probes did not continue after warm startup')
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
                data=('warm47-'+str(len(beats))).encode();held.sendall(data);reply=b''
                while len(reply)<len(data):
                    chunk=held.recv(len(data)-len(reply));assert chunk;reply+=chunk
                assert reply==data;beats.append(time.monotonic());stop.wait(.2)
        except BaseException as error:errors.append(repr(error))
    try:
        command('disconnect')
        with socket.socket() as listener:listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
        command('preferences',{**initial['preferences'],'language':'en','theme':'dark','connectionMode':'local','inboundPort':port})
        command('saveSettings',{'section':'logging','previous':old_logging,'values':{**old_logging,'log_level':'info'}})
        route=copy.deepcopy(old_route);current=next(p for p in route['profiles'] if p['id']==route['active']);current['rules']=[{'id':'warm47-proxy','name':'Owned HTTP via selected proxy','enabled':True,'config':{'ip_cidr':['127.0.0.1/32'],'outbound':'proxy'}}];command('saveRouting',route)
        source,owner=group('Warm HTTP servers'),group('Warm pools');a=add(source,'Warm A',info['ports'][0]);b=add(source,'Warm B',info['ports'][1]);admin(0,downloadMode='slow');admin(1,downloadMode='ok');latencies=measure([a,b]);assert latencies[a]>latencies[b]+100
        check(True,'warm candidates come from real HTTP measurements with distinct proxy delays')
        cfg={'type':'auto-selector','member_source':{'group_id':source},'url':url,'interval':'1h','bench_interval':'1h','watch_interval':'1h','timeout':'2s','sampling':2,'expected':2,'active_size':2,'tolerance':10000,'interrupt_exist_connections':False}
        pid=command('saveProfile',{'groupId':owner,'name':'Warm startup pool','kind':'auto-selector','config':cfg})['id']
        _,_,cold=gated_start(pid,a,False);check(True,'default cold startup uses library order and zero samples before either HTTP origin receives a new request');release();probes_continue(0);command('disconnect')
        edit(pid);check(js('return !document.querySelector("#selector-warm-start").checked && document.querySelector("#selector-member-order").value==="library"'),'warm startup is a separate opt-in and leaves library order selected')
        click('#selector-warm-start');warm_count(2);fill('#selector-result-validity','0');warm_count(0);check(True,'zero lifetime removes all startup hints in the native preview');fill('#selector-result-validity','60');warm_count(2)
        for language,theme in [('ru','light'),('en','dark')]:
            command('preferences',{**command('snapshot')['preferences'],'language':language,'theme':theme});wait_for('return document.documentElement.lang==='+json.dumps(language));warm_count(2);h['request']('POST',h['base']+'/window/rect',{'width':390,'height':844});js('document.querySelector("#selector-warm-start").closest("label").scrollIntoView({block:"start"})');check(js('return document.documentElement.scrollWidth<=innerWidth && document.querySelector(".selector-fields").scrollWidth<=document.querySelector(".selector-fields").clientWidth'),language+' warm option and explanation fit a 390-pixel native window');screenshot('selector-warm-'+language+'-390')
        h['request']('POST',h['base']+'/window/rect',{'width':1280,'height':860});click('button[form="profile-editor"]');wait_for('return !document.querySelector("dialog[open]")');saved=command('profile',{'id':pid})['config'];check(saved['member_source']['warm_start'] and 'warm' not in saved,'Save stores only the warm preference, not generated Core samples')
        active,compiled,warm=gated_start(pid,b,True);check(True,'Core selects the faster second member from one aged warm sample each before any new HTTP reaches either origin')
        seeds={s['tag']:s for s in compiled['warm']};check(all(seeds['thronium-selector-proxy-'+key]['rtt']==max(1,value) and seeds['thronium-selector-proxy-'+key]['age']>=0 for key,value in latencies.items()),'generated warm values use current member tags, measured RTT and a nonnegative preserved age')
        logs=command('getLogs');check(any('restored health for 2 of 2 members' in row['text'] for row in logs['entries']),'production Core reports restoring health from the generated warm hints')
        release();probes_continue(2);check(True,'normal Core health probes resume and add new samples after the gate is released')
        held,body=tunnel('/stream');assert body==b'ready';thread=threading.Thread(target=pulse,name='warm47-owned-heartbeat');thread.start();time.sleep(.5);since=command('snapshot')['since']
        admin(0,downloadMode='ok');admin(1,downloadMode='slow');next_latencies=measure([a,b]);assert next_latencies[b]>next_latencies[a]+100;count=len(beats);time.sleep(.4)
        check(len(beats)>count and not errors and config_group(pid)[0]==active and command('snapshot')['since']==since,'new HTTP observations preserve the active warm configuration and its held CONNECT stream')
        stop.set();thread.join(5);assert not thread.is_alive();held.close();held=None;command('disconnect')
        _,next_config,_=gated_start(pid,a,True);check(next_config['warm']!=compiled['warm'],'next startup uses the updated warm measurements before new HTTP responses');release();probes_continue(2)
        conn,body=tunnel('/body');conn.close();check(body==b'country45:0','reconnected warm pool forwards a complete real HTTP response')
        Path(h['artifacts']).joinpath('warm-network-audit.json').write_text(json.dumps({'gatedStarts':gates,'heartbeats':len(beats),'heartbeatErrors':errors,'externalRequests':False},indent=2)+'\n')
    finally:
        release()
        with contextlib.suppress(Exception):command('cancelUrlTests')
        stop.set()
        if thread:thread.join(5)
        if held:
            with contextlib.suppress(OSError):held.shutdown(socket.SHUT_RDWR)
            held.close()
        if thread:assert not thread.is_alive()
        command('disconnect')
        for gid in reversed(groups):command('deleteGroup',{'id':gid,'deleteProfiles':True})
        command('saveRouting',{**old_route,'revision':command('routing')['revision']});command('saveSettings',{'section':'logging','previous':command('settings')['logging'],'values':old_logging});command('preferences',initial['preferences'])
        if initial['selected']:command('select',{'id':initial['selected']})
        h['request']('POST',h['base']+'/window/rect',{'width':geometry['width'],'height':geometry['height']})
