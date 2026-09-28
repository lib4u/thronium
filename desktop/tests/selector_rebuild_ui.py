"""Real automatic pool rebuilding through owned SOCKS and HTTP peers."""
import contextlib,copy,http.client,json,os,socket,threading,time,urllib.request
from pathlib import Path

def run(h):
    command,click,fill,select,wait_for,js,check,screenshot=(h[k] for k in ('command','click','fill','select','wait_for','js','check','screenshot'))
    info=json.loads(Path(os.environ['_THRONIUM_DIAGNOSTICS_FIXTURE']).read_text());initial=command('snapshot');old_route=command('routing');geometry=h['request']('GET',h['base']+'/window/rect');groups=[]
    url='http://127.0.0.1:'+str(info['httpPorts'][0])+'/health';held=None;thread=None;stop=threading.Event();beats=[];errors=[];audit={}
    def admin(i,**data):
        req=urllib.request.Request(info['admins'][i],data=json.dumps(data).encode(),headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(req,timeout=3) as response:return json.load(response)
    def until(fn,message,timeout=50):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            value=fn()
            if value:return value
            time.sleep(.1)
        raise AssertionError(message)
    def group(name):gid=command('saveGroup',{'name':name})['id'];groups.append(gid);return gid
    def add(gid,name,i):return command('saveProfile',{'groupId':gid,'name':name,'kind':'sing-box-outbound','config':{'type':'socks','server':'127.0.0.1','server_port':info['ports'][i]}})['id']
    def profile():return command('profile',{'id':pid})
    def active():return command('connectionConfiguration',{'id':pid,'active':True})
    def status():return next(p for p in command('getAutoSelectors') if p['tag']=='proxy')
    def member():
        value=active();pool=next(o for part in value['parts'] for o in part['config'].get('outbounds',[]) if o.get('type')=='auto-selector' and o.get('tag')=='proxy');return [tag.removeprefix('thronium-selector-proxy-') for tag in pool['outbounds']]
    def edit():
        click('.primary-nav button:first-child');select('.group-strip select','all');fill('#client-search','');selector='[data-profile-menu="'+pid+'"]';wait_for('return !!document.querySelector('+json.dumps(selector)+')');js('document.querySelector(arguments[0]).scrollIntoView({block:"center"})',selector)
        h['request']('POST',h['base']+'/execute/async',{'script':'const done=arguments[arguments.length-1];requestAnimationFrame(()=>requestAnimationFrame(()=>done(true)));','args':[]})
        click(selector);click('#menu-edit-profile');wait_for('return !!document.querySelector("#selector-rebuild-exhausted") && !document.querySelector("#selector-preview-loading") && document.activeElement?.id==="profile-name"')
    def close_editor():click('#main-modal > .modal-head > button');wait_for('return !document.querySelector("dialog[open]")')
    def start_stream():
        nonlocal held,thread
        conn=socket.create_connection(('127.0.0.1',port),timeout=4);host='127.0.0.1:'+str(info['httpPorts'][0])
        def headers():
            data=b''
            while b'\r\n\r\n' not in data:
                chunk=conn.recv(1);assert chunk;data+=chunk
            assert b' 200 ' in data.split(b'\r\n',1)[0];return data
        conn.sendall(('CONNECT '+host+' HTTP/1.1\r\nHost: '+host+'\r\n\r\n').encode());headers();conn.sendall(('GET /stream HTTP/1.0\r\nHost: '+host+'\r\n\r\n').encode());head=headers();length=int(next(l.split(b':',1)[1] for l in head.split(b'\r\n') if l.lower().startswith(b'content-length:')));body=b''
        while len(body)<length:body+=conn.recv(length-len(body))
        assert body==b'ready';held=conn;stop.clear()
        def pulse():
            try:
                while not stop.is_set():
                    data=('rebuild57-'+str(len(beats))).encode();conn.sendall(data);reply=b''
                    while len(reply)<len(data):
                        chunk=conn.recv(len(data)-len(reply));assert chunk;reply+=chunk
                    assert reply==data;beats.append(time.monotonic());stop.wait(.15)
            except BaseException as error:errors.append(repr(error))
        thread=threading.Thread(target=pulse,name='selector-rebuild57-stream');thread.start()
    def stop_stream():
        nonlocal held,thread
        stop.set()
        if thread:thread.join(5);assert not thread.is_alive();thread=None
        if held:held.close();held=None
    try:
        command('disconnect')
        with socket.socket() as listener:listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
        command('preferences',{**initial['preferences'],'language':'en','theme':'dark','connectionMode':'local','inboundPort':port,'ping':{**initial['preferences']['ping'],'timeoutMs':3000}})
        route=copy.deepcopy(old_route);current=next(p for p in route['profiles'] if p['id']==route['active']);current['mode']='rules';current['rules']=[{'id':'rebuild57-proxy','name':'Owned traffic','enabled':True,'config':{'ip_cidr':['127.0.0.1/32'],'outbound':'proxy'}}];command('saveRouting',route)
        source,owner=group('Rebuild members'),group('Rebuild pools');a=add(source,'First server',0);b=add(source,'Replacement server',1)
        config={'type':'auto-selector','member_source':{'group_id':source,'order':'saved-http-latency','measure_before_connect':True,'build_limit':1,'pool_cap':2},'url':url,'interval':'1s','bench_interval':'1s','watch_interval':'1s','timeout':'2s','sampling':1,'expected':1,'active_size':1,'interrupt_exist_connections':False}
        pid=command('saveProfile',{'groupId':owner,'name':'Rebuild after failure','kind':'auto-selector','config':config})['id'];edit();check(not js('return document.querySelector("#selector-rebuild-exhausted").checked'),'automatic exhaustion rebuilding is off for an existing preflight pool');click('#selector-rebuild-exhausted');click('button[form="profile-editor"]');wait_for('return !document.querySelector("dialog[open]")');check(profile()['config']['member_source']['rebuild_on_exhaustion'] is True,'native editor saves the separate exhaustion rebuild option')
        admin(0,downloadMode='ok');admin(1,downloadMode='slow');command('connect',{'id':pid});check(member()==[a],'initial measured pool starts the first fast server with one member');until(lambda:status()['membersAlive']==1,'Initial pool never became healthy')
        check(status()['rebuild']=={'attempts':0,'limit':3,'paused':False},'running diagnostics expose the bounded rebuild state')
        original=active();saved_ranking=copy.deepcopy(profile()['config']['member_source']['saved_ranking']);start_stream();before=len(beats);failed_at=time.monotonic();admin(0,downloadMode='http-error');command('autoSelectorAction',{'tag':'proxy','action':'recheck'});command('clearUrlTests');admin(1,downloadMode='hold')
        until(lambda:command('snapshot').get('connectionPreparation'),'Background worker did not prepare a replacement after exhaustion',65)
        until(lambda:admin(1)['warmBlocked']>0,'Replacement measurement did not reach the owned gate',4)
        elapsed=time.monotonic()-failed_at;job=command('snapshot')['connectionPreparation'];audit['firstPreparationAfterSeconds']=elapsed
        check(elapsed>=19.8 and job['profileId']==pid and job['total']==2,'background exhaustion waits its grace and measures candidates before both pool limits')
        check(active()==original and member()==[a] and len(beats)>before and not errors,'the exact old pool and an existing CONNECT stream survive automatic preparation')
        check(profile()['config']['member_source']['saved_ranking']==saved_ranking,'automatic preparation does not save its proposed new ranking early')
        stop_stream();admin(1,downloadMode='ok');until(lambda:not command('snapshot').get('connectionPreparation'),'Automatic preparation did not finish');until(lambda:member()==[b],'Failed first server was not replaced by the available candidate')
        check(profile()['config']['member_source']['saved_ranking']['members'][0]==b,'successful automatic Start commits the replacement membership')
        history=next(p for p in command('getSelectorHistory') if p['profileId']==pid);check(history['lastBuilt']==[b],'history records the new successfully applied membership')
        client=http.client.HTTPConnection('127.0.0.1',port,timeout=4);client.request('GET',url.replace('/health','/runtime'));response=client.getresponse();body=response.read();client.close();check(response.status==200 and body==b'country45:0','the replacement pool carries real HTTP after automatic rebuilding')
        until(lambda:status()['membersAlive']==1 and status()['rebuild']['attempts']==0,'Recovered pool did not reset consecutive attempts',15)
        check(not status()['rebuild']['paused'],'a healthy replacement keeps automatic rebuilding available')

        # A cancelled automatic attempt must not start a second task on the same session.
        original=active();start_stream();before=len(beats);command('clearUrlTests');admin(0,downloadMode='hold');admin(1,downloadMode='http-error');command('autoSelectorAction',{'tag':'proxy','action':'recheck'})
        until(lambda:command('snapshot').get('connectionPreparation'),'Second exhausted pool did not enter preparation',65);wait_for('return !!document.querySelector("#cancel-connection-preparation")');click('#cancel-connection-preparation');admin(0,downloadMode='ok');admin(1,downloadMode='ok');until(lambda:not command('snapshot').get('connectionPreparation'),'Cancellation did not finish');until(lambda:status()['rebuild']['paused'],'Cancelled automatic retries were not paused',5)
        until(lambda:len(beats)>before or bool(errors),'CONNECT heartbeat stopped after cancellation',3)
        check(active()==original and member()==[b] and len(beats)>before and not errors,'cancelling automatic rebuilding preserves the old configuration and CONNECT stream')
        check(status()['rebuild']['attempts']==1 and status()['rebuild']['paused'],'explicit cancellation pauses retries for this running generation')
        stop_stream();command('connect',{'id':pid});check(status()['rebuild']=={'attempts':0,'limit':3,'paused':False},'manual reconnect creates a fresh automatic rebuild generation')
        command('disconnect')
        for language in ['ru','en']:
            command('preferences',{**command('snapshot')['preferences'],'language':language});wait_for('return document.documentElement.lang==='+json.dumps(language));h['request']('POST',h['base']+'/window/rect',{'width':390,'height':844});edit();js('document.querySelector("#selector-rebuild-exhausted").scrollIntoView({block:"center"})')
            check(js('const d=document.querySelector("#main-modal"),b=d.querySelector(".modal-body"),c=document.querySelector("#selector-rebuild-exhausted");const r=c.getBoundingClientRect(),br=b.getBoundingClientRect();return b.scrollWidth<=b.clientWidth+1 && c.checked && r.top>=br.top && r.bottom<=br.bottom && document.elementFromPoint(r.x+r.width/2,r.y+r.height/2)===c'),language+' automatic rebuild option fits the narrow native editor');screenshot('selector-rebuild-'+language+'-390');close_editor()
        audit.update(heartbeats=len(beats),heartbeatErrors=errors,actualReplacement=True,cancelPreservedConnection=True,externalRequests=False);Path(h['artifacts'],'rebuild-network-audit.json').write_text(json.dumps(audit,indent=2)+'\n')
    finally:
        with contextlib.suppress(Exception):
            pending=command('snapshot').get('connectionPreparation')
            if pending:command('cancelConnectionPreparation',{'id':pending['id']})
        for i in range(2):
            with contextlib.suppress(Exception):admin(i,downloadMode='ok')
        stop_stream()
        with contextlib.suppress(Exception):command('cancelUrlTests')
        with contextlib.suppress(Exception):command('disconnect')
        for gid in reversed(groups):
            with contextlib.suppress(Exception):command('deleteGroup',{'id':gid,'deleteProfiles':True})
        command('saveRouting',{**old_route,'revision':command('routing')['revision']});command('preferences',initial['preferences']);h['request']('POST',h['base']+'/window/rect',{'width':geometry['width'],'height':geometry['height']})
