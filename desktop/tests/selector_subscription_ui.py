"""Real automatic pool rebuilding through owned SOCKS and HTTP peers."""
import contextlib,copy,http.client,http.server,json,os,socket,threading,time,urllib.request
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
        click(selector);click('#menu-edit-profile');wait_for('return !!document.querySelector("#selector-rebuild-subscription") && !document.querySelector("#selector-preview-loading") && document.activeElement?.id==="profile-name"')
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
                    data=('subscription58-'+str(len(beats))).encode();conn.sendall(data);reply=b''
                    while len(reply)<len(data):
                        chunk=conn.recv(len(data)-len(reply));assert chunk;reply+=chunk
                    assert reply==data;beats.append(time.monotonic());stop.wait(.15)
            except BaseException as error:errors.append(repr(error))
        thread=threading.Thread(target=pulse,name='selector-subscription58-stream');thread.start()
    def stop_stream():
        nonlocal held,thread
        stop.set()
        if thread:thread.join(5);assert not thread.is_alive();thread=None
        if held:held.close();held=None
    provider_body=[];provider_calls=[]
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self,*_):pass
        def do_GET(self):
            provider_calls.append(self.path);data=json.dumps(provider_body).encode();self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    provider=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);provider_thread=threading.Thread(target=provider.serve_forever,name='selector-subscription58-provider');provider_thread.start()
    def row(name,i,version):return {'tag':name,'type':'socks','server':'127.0.0.1','server_port':info['ports'][i],'connect_timeout':str(version)+'s'}
    def stored():return [p for p in command('snapshot')['profiles'] if p['groupId']==source]
    def queue():
        before=len(command('snapshot')['subscriptionJobs']);command('startSubscriptionUpdates',{'id':source})
        result=until(lambda:(jobs[before] if len(jobs:=command('snapshot')['subscriptionJobs'])>before and jobs[before]['status'] in ['updated','error','needs-review'] else None),'Subscription queue did not finish',40)
        assert result['status']=='updated',result
        if command('snapshot').get('subscriptionNotifications'):
            wait_for('return !!document.querySelector(".subscription-updates-modal")');close_editor()
    def pending():return command('snapshot').get('selectorSubscriptionUpdate')
    def version(i):
        return next((o.get('connect_timeout') for part in active()['parts'] for o in part['config'].get('outbounds',[]) if o.get('type')=='socks' and o.get('server_port')==info['ports'][i]),None)
    def checked_http():
        client=http.client.HTTPConnection('127.0.0.1',port,timeout=4);client.request('GET',url.replace('/health','/runtime'));response=client.getresponse();body=response.read();client.close();return response.status==200 and body==b'country45:0'
    try:
        with socket.socket() as free:free.bind(('127.0.0.1',0));port=free.getsockname()[1]
        command('preferences',{**initial['preferences'],'language':'en','theme':'dark','inboundPort':port,'connectionMode':'local','ping':{**initial['preferences']['ping'],'timeoutMs':3000}})
        route=copy.deepcopy(old_route);current=next(p for p in route['profiles'] if p['id']==route['active']);current['mode']='rules';current['rules']=[{'id':'subscription58-proxy','name':'Owned traffic','enabled':True,'config':{'ip_cidr':['127.0.0.1/32'],'outbound':'proxy'}}];command('saveRouting',route)
        source=command('saveGroup',{'name':'Subscription replacements','subscription':{'url':f'http://127.0.0.1:{provider.server_port}/subscription','headers':{},'viaProxy':False,'inheritDefaults':False}})['id'];groups.append(source);owner=group('Running automatic pool')
        provider_body=[row('A',0,3),row('B',1,3)];queue();a,b=[p['id'] for p in stored()]
        config={'type':'auto-selector','member_source':{'group_id':source,'name_regex':'^(A|B|A new)$','order':'saved-http-latency','result_validity_mins':60,'measure_before_connect':True,'pool_cap':2,'build_limit':1},'url':url,'interval':'1h','bench_interval':'1h','watch_interval':'1h','timeout':'2s','sampling':1,'expected':1,'active_size':1,'interrupt_exist_connections':False}
        pid=command('saveProfile',{'groupId':owner,'name':'Subscription replacements','kind':'auto-selector','config':config})['id'];edit();check(not js('return document.querySelector("#selector-rebuild-subscription").checked'),'subscription replacement is a separate opt-in');click('#selector-rebuild-subscription');click('button[form="profile-editor"]');wait_for('return !document.querySelector("dialog[open]")')
        check(profile()['config']['member_source']['rebuild_on_subscription'] and not profile()['config']['member_source'].get('rebuild_on_exhaustion'),'native editor enables subscription replacement independently from exhaustion')
        admin(0,downloadMode='ok');admin(1,downloadMode='slow');command('connect',{'id':pid});check(member()==[a],'initial measured pool uses the first fast subscription member');until(lambda:status()['membersAlive']==1,'Initial pool never became healthy')
        original=active();start_stream();before=len(beats);provider_body=[row('A',0,4),row('B',1,3)]
        select('.group-strip select',source);click('[data-library-group] [data-group-menu]');click('#update-subscription');click('#subscription-load');wait_for('return !!document.querySelector("#subscription-reload")')
        check(js('return document.querySelectorAll("[data-subscription-action=updated]").length===1'),'manual preview permits the opted-in running member update')
        check(active()==original and not pending(),'preview alone preserves the running request and creates no replacement')
        admin(0,downloadMode='hold');click('#subscription-apply');wait_for('return !document.querySelector("dialog[open]")')
        until(lambda:command('snapshot').get('connectionPreparation'),'Manual subscription apply did not start background preparation',20);until(lambda:admin(0)['warmBlocked']>0,'Updated member did not reach HTTP gate',4)
        check(command('profile',{'id':a})['config']['connect_timeout']=='4s' and active()==original and len(beats)>before and not errors,'same UUID changes in the library while the exact old Core and CONNECT stream survive checks')
        stop_stream();admin(0,downloadMode='ok');until(lambda:not command('snapshot').get('connectionPreparation') and not pending(),'Manual replacement did not finish',30);check(version(0)=='4s' and member()==[a] and checked_http(),'checked replacement reaches the real Core and carries HTTP traffic')
        original=active();since=command('snapshot')['since'];provider_body=[row('A',0,4),row('B',1,4)];queue();time.sleep(6)
        check(active()==original and command('snapshot')['since']==since and not pending(),'updating a non-built candidate does not restart the running pool')
        start_stream();before=len(beats);provider_body=[row('B',1,4)];admin(1,downloadMode='hold');queue();until(lambda:command('snapshot').get('connectionPreparation'),'Removal did not start replacement checks',20);until(lambda:admin(1)['warmBlocked']>0,'Replacement after deletion did not reach gate',4)
        wait_for('return !!document.querySelector("#cancel-connection-preparation")');click('#cancel-connection-preparation');admin(1,downloadMode='ok');until(lambda:not command('snapshot').get('connectionPreparation'),'Cancellation did not finish');until(lambda:status()['subscriptionUpdate']['paused'],'Cancellation did not pause subscription retry')
        check(all(p['id']!=a for p in stored()) and active()==original and len(beats)>before and not errors,'removing the stored active member and cancelling preserves its old Core request and CONNECT stream')
        check(status()['members'][0]['name']=='A','removed running member keeps its readable name until replacement')
        provider_body=[row('B',1,5)];queue();time.sleep(6);check(status()['subscriptionUpdate']['paused'] and active()==original,'a newer subscription preserves explicit cancellation for this connection')
        wait_for('return !!document.querySelector("#apply-selector-subscription")');screenshot('subscription-replacement-pending-en');stop_stream();click('#apply-selector-subscription');until(lambda:not pending() and not command('snapshot').get('connectionPreparation'),'Manual reconnect did not apply the pending subscription',30)
        check(member()==[b] and version(1)=='5s' and checked_http(),'manual pending action applies the new pool after cancellation')
        history=next(p for p in command('getSelectorHistory') if p['profileId']==pid);check(history['lastBuilt']==[b],'history records the applied replacement membership')
        original=active();provider_body=[row('A new',0,6)];admin(0,downloadMode='http-error');queue();until(lambda:pending() and status()['subscriptionUpdate']['attempts']==1 and not command('snapshot').get('connectionPreparation'),'Unreachable replacement did not finish its first attempt',30)
        time.sleep(6);check(active()==original and member()==[b] and status()['subscriptionUpdate']['attempts']==1 and checked_http(),'all failed replacements retain the working old pool and obey retry backoff')
        provider_body=[row('A new',0,7)];admin(0,downloadMode='ok');queue();until(lambda:not pending() and not command('snapshot').get('connectionPreparation'),'New valid subscription version did not resume replacement',30)
        check(version(0)=='7s' and checked_http(),'a newer valid subscription resets failed attempts and replaces the old pool')
        original=active();start_stream();before=len(beats);provider_body=[row('Excluded',0,7),row('B',1,8)];admin(1,downloadMode='hold');queue()
        until(lambda:command('snapshot').get('connectionPreparation'),'Renaming the running member outside its filter did not prepare a replacement',20);until(lambda:admin(1)['warmBlocked']>0,'Rename replacement did not reach HTTP gate',4)
        check(active()==original and len(beats)>before and not errors,'a name-filter change in the subscription keeps the old connection during replacement checks')
        stop_stream();admin(1,downloadMode='ok');until(lambda:not pending() and not command('snapshot').get('connectionPreparation'),'Replacement after name-filter exclusion did not finish',30)
        check(version(1)=='8s' and version(0) is None and checked_http(),'automatic replacement excludes the renamed member and starts the matching candidate')
        settings_before=command('settings')['subscriptions']
        command('saveSettings',{'section':'subscriptions','previous':settings_before,'values':{**settings_before,'sub_update_mode':'recreate'}})
        original=active();old_ids={p['id'] for p in stored()};start_stream();before=len(beats)
        admin(1,downloadMode='hold');queue()
        until(lambda:command('snapshot').get('connectionPreparation'),'Recreation did not prepare the replacement pool',20)
        until(lambda:admin(1)['warmBlocked']>0,'Recreated pool did not reach the HTTP gate',4)
        check(not old_ids.intersection(p['id'] for p in stored()) and active()==original and len(beats)>before and not errors,'full recreation replaces saved IDs while preserving the old active Core and CONNECT stream during validation')
        stop_stream();admin(1,downloadMode='ok')
        until(lambda:not pending() and not command('snapshot').get('connectionPreparation'),'Recreated pool was not applied',30)
        check(not old_ids.intersection(member()) and checked_http(),'recreated IDs reach the running automatic pool and carry real HTTP')
        current=command('settings')['subscriptions'];command('saveSettings',{'section':'subscriptions','previous':current,'values':settings_before})
        command('disconnect')
        for language in ['ru','en']:
            command('preferences',{**command('snapshot')['preferences'],'language':language});wait_for('return document.documentElement.lang==='+json.dumps(language));h['request']('POST',h['base']+'/window/rect',{'width':390,'height':844});edit();js('document.querySelector("#selector-rebuild-subscription").scrollIntoView({block:"center"})')
            check(js('const d=document.querySelector("#main-modal"),b=d.querySelector(".modal-body"),c=document.querySelector("#selector-rebuild-subscription");const r=c.getBoundingClientRect(),br=b.getBoundingClientRect();return b.scrollWidth<=b.clientWidth+1 && c.checked && r.top>=br.top && r.bottom<=br.bottom && document.elementFromPoint(r.x+r.width/2,r.y+r.height/2)===c'),language+' subscription replacement control is reachable in the narrow native editor');screenshot('selector-subscription-'+language+'-390');close_editor()
        audit.update(heartbeats=len(beats),heartbeatErrors=errors,providerRequests=len(provider_calls),externalRequests=False);Path(h['artifacts'],'subscription-network-audit.json').write_text(json.dumps(audit,indent=2)+'\n')
    finally:
        with contextlib.suppress(Exception):
            preparation=command('snapshot').get('connectionPreparation')
            if preparation:command('cancelConnectionPreparation',{'id':preparation['id']})
        for i in range(2):
            with contextlib.suppress(Exception):admin(i,downloadMode='ok')
        stop_stream()
        with contextlib.suppress(Exception):command('cancelSubscriptionUpdates')
        with contextlib.suppress(Exception):command('cancelUrlTests')
        with contextlib.suppress(Exception):command('disconnect')
        for gid in reversed(groups):
            with contextlib.suppress(Exception):command('deleteGroup',{'id':gid,'deleteProfiles':True})
        with contextlib.suppress(Exception):command('saveRouting',old_route)
        with contextlib.suppress(Exception):command('preferences',initial['preferences'])
        with contextlib.suppress(Exception):h['request']('POST',h['base']+'/window/rect',geometry)
        provider.shutdown();provider.server_close();provider_thread.join(timeout=3);assert not provider_thread.is_alive()
