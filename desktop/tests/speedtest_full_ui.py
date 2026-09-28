"""Standard full/download/upload speed modes; actual HTTP-status baseline regression."""
import contextlib
import copy
import json
import os
from pathlib import Path
import socket
import time
import urllib.request


def run(h):
    command,check,js,wait_for=(h[k] for k in ('command','check','js','wait_for'))
    fixture=json.loads(Path(os.environ['_THRONIUM_SPEEDTEST_FULL_FIXTURE']).read_text())
    initial=command('snapshot');assert not initial['profiles'];audit={'results':[]};tokens=[];count=0;sockets=[]
    def admin(**values):
        req=urllib.request.Request(fixture['admin'],data=json.dumps(values).encode() if values else None,headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(req,timeout=3) as response:return json.load(response)
    def poll(predicate,timeout=6):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            if predicate():return
            time.sleep(.05)
        raise AssertionError('standard speed fixture did not reach the expected state')
    def setting(mode):
        old=command('settings')['testing'];command('saveSettings',{'section':'testing','previous':old,'values':{**old,'speed_test_mode':mode,'speed_test_timeout_ms':1000}})
    def begin(identifier):
        nonlocal count
        count+=1;token='speedtest70-'+str(count);tokens.append(token)
        js('''const token=arguments[1];window.__speed70??={};window.__speed70[token]={done:false};
            window.__TAURI_INTERNALS__.invoke('app_command',{name:'testSpeed',payload:{id:arguments[0],requestId:token}})
            .then(value=>window.__speed70[token]={done:true,ok:true,value}).catch(error=>window.__speed70[token]={done:true,ok:false,error});''',identifier,token)
        return token
    def finish(token,release=False):
        wait_for('return window.__speed70?.['+json.dumps(token)+']?.done',30)
        if release:admin(mode='ok',release=True)
        row=json.loads(js('return JSON.stringify(window.__speed70[arguments[0]])',token));poll(lambda:admin()['active']==0)
        audit['results'].append({'result':row,'fixture':admin()});return row
    def add(name,kind,config):
        return command('saveProfile',{'name':name,'kind':kind,'groupId':'personal','config':config})['id']
    try:
        with socket.socket() as temporary:temporary.bind(('127.0.0.1',0));port=temporary.getsockname()[1]
        command('preferences',{**initial['preferences'],'language':'en','connectionMode':'local','inboundPort':port})
        profile=command('saveProfile',{'name':'Standard speed70','kind':'sing-box-outbound','groupId':'personal','config':{'type':'direct'}})['id']
        command('connect',{'id':profile});before=command('snapshot')
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen();sockets.append(listener)
        client=socket.create_connection(('127.0.0.1',port),timeout=3);sockets.append(client);authority='127.0.0.1:'+str(listener.getsockname()[1]);client.sendall(('CONNECT '+authority+' HTTP/1.1\r\nHost: '+authority+'\r\n\r\n').encode())
        upstream,_=listener.accept();upstream.settimeout(3);sockets.append(upstream);assert b'200' in client.recv(1024)
        from window_ui import primary
        from native_processes import core_pids
        connection,_,app_pid=primary();connection.close();main_pids=core_pids(app_pid)
        def preserved():
            poll(lambda:core_pids(app_pid)==main_pids)
            current=command('snapshot');assert current['running']==profile and current['since']==before['since']
            client.sendall(b'preserved70');assert upstream.recv(11)==b'preserved70'
        for mode in ['download','upload','full']:
            setting(mode);admin(mode='ok',clear=True);row=finish(begin(profile));state=admin()
            check(row['ok'],'standard '+mode+' performs discovery, HTTP ping and real transfer')
            result=row['value']['result']
            check((result['downloadBytes']>0)==(mode!='upload') and (result['uploadBytes']>0)==(mode!='download') and (state['downloadBytes']>0)==(mode!='upload') and (state['uploadBytes']>0)==(mode!='download'),'standard '+mode+' credits only its requested directions and transfers actual bytes')
            preserved()
        for mode,failure in [('download','download-http'),('upload','upload-http'),('full','api-http'),('download','latency-http'),('full','api-invalid'),('full','api-empty'),('download','download-empty'),('download','download-truncated')]:
            setting(mode);admin(mode=failure,clear=True);row=finish(begin(profile))
            check(not row['ok'] and 'value' not in row,'standard '+mode+' rejects '+failure+' instead of reporting a successful measurement')
            preserved()
        for mode,phase in [('full','api'),('download','download'),('upload','upload')]:
            setting(mode);admin(mode='hold-'+phase,clear=True);token=begin(profile)
            poll(lambda:any(r['phase']==phase for r in admin()['requests']))
            started=time.monotonic();command('cancelSettingsTest',{'requestId':token});row=finish(token,release=True)
            check(not row['ok'] and row['error'].get('code')=='probe_cancelled' and time.monotonic()-started<5,'cancellation during '+phase+' rejects the late result promptly')
            preserved()
        setting('download');admin(mode='hold-download',clear=True);token=begin(profile)
        poll(lambda:any(r['phase']=='download' for r in admin()['requests']))
        setting('upload');admin(mode='ok',release=True);row=finish(token)
        check(not row['ok'] and row['error'].get('code')=='probe_stale','changing the saved speed mode rejects a result started with previous settings');preserved()
        root=Path(command('storageLocation')['directory']);log=root/'speed-log-sentinel';log.write_bytes(b'unchanged70')
        occupied=socket.socket();occupied.bind(('127.0.0.1',0));occupied.listen();sockets.append(occupied)
        oldport=occupied.getsockname()[1]
        sing={'log':{'output':str(log),'level':'debug'},
              'dns':{'servers':[{'type':'udp','tag':'client-dns','server':'127.0.0.1','server_port':fixture['dnsPort']}],'final':'client-dns','disable_cache':True},
              'inbounds':[{'type':'mixed','tag':'client','listen':'0.0.0.0','listen_port':oldport}],
              'outbounds':[{'type':'direct','tag':'proxy'}],
              'route':{'final':'proxy','default_domain_resolver':'client-dns','rules':[{'action':'resolve','strategy':'ipv4_only','server':'client-dns'}]}}
        xray={'log':{'access':str(log),'error':str(log),'loglevel':'debug'},
              'dns':{'servers':[{'address':'127.0.0.1','port':fixture['dnsPort']}],'queryStrategy':'UseIPv4','disableCache':True},
              'inbounds':[{'protocol':'socks','tag':'client','listen':'0.0.0.0','port':oldport}],
              'outbounds':[{'protocol':'freedom','tag':'direct','settings':{'domainStrategy':'UseIP'}},{'protocol':'blackhole','tag':'block'}],
              'routing':{'domainStrategy':'IPIfNonMatch','rules':[]}}
        routing=command('routing');active=next(p for p in routing['profiles'] if p['id']==routing['active'])
        active['dns']={'servers':[{'type':'udp','tag':'dns-direct','server':'192.0.2.99'}],'final':'dns-direct'};command('saveRouting',routing)
        for family,config in [('sing-box',sing),('xray',xray)]:
            identifier=add('Standard speed70 full '+family,family+'-config',config)
            # Each save spends the profile's expected revision, so a restore reads the current one.
            def restore(identifier=identifier,config=config):
                current=command('profile',{'id':identifier});current['config']=copy.deepcopy(config);command('saveProfile',current)
            for mode in ['download','upload','full']:
                setting(mode);admin(mode='ok',clear=True);row=finish(begin(identifier));state=admin()
                check(row['ok'],'complete '+family+' performs standard '+mode+' through its own client')
                result=row['value']['result']
                check((result['downloadBytes']>0)==(mode!='upload') and (result['uploadBytes']>0)==(mode!='download') and (state['downloadBytes']>0)==(mode!='upload') and (state['uploadBytes']>0)==(mode!='download'),'complete '+family+' '+mode+' transfers real bytes in precisely the requested directions')
                check({'www.speedtest.net','speed.peer.test'}<={q['name'] for q in state['dnsQueries']},'complete '+family+' resolves discovery and measurement using client DNS')
                preserved()
            for mode,failure in [('download','download-http'),('upload','upload-http'),('full','api-http'),('full','latency-http')]:
                setting(mode);admin(mode=failure,clear=True);row=finish(begin(identifier))
                check(not row['ok'] and 'value' not in row,'complete '+family+' rejects '+failure)
                preserved()
            for domain in ['www.speedtest.net','speed.peer.test']:
                changed=command('profile',{'id':identifier})
                if family=='sing-box':changed['config']['route']['rules'].insert(0,{'domain':[domain],'action':'reject'})
                else:changed['config']['routing']['rules'].append({'domain':['full:'+domain],'outboundTag':'block'})
                command('saveProfile',changed);setting('full');admin(mode='ok',clear=True);row=finish(begin(identifier))
                check(not row['ok'] and not any(r['host']==domain for r in admin()['requests']),'complete '+family+' routing blocks '+domain+' without bypass')
                restore();preserved()
            setting('download');admin(mode='hold-download',clear=True);token=begin(identifier)
            poll(lambda:any(r['phase']=='download' for r in admin()['requests']))
            changed=command('profile',{'id':identifier})
            if family=='sing-box':changed['config']['dns']['disable_cache']=False
            else:changed['config']['dns']['disableCache']=False
            command('saveProfile',changed);admin(mode='ok',release=True);row=finish(token)
            check(not row['ok'] and row['error'].get('code')=='probe_stale','complete '+family+' DNS edit invalidates pending standard speed result')
            restore();preserved()
            setting('upload');admin(mode='hold-upload',clear=True);token=begin(identifier)
            poll(lambda:any(r['phase']=='upload' for r in admin()['requests']))
            command('cancelSettingsTest',{'requestId':token});row=finish(token,release=True)
            check(not row['ok'] and row['error'].get('code')=='probe_cancelled','complete '+family+' cancels standard upload without a late success');preserved()
            check(command('profile',{'id':identifier})['config']==config and log.read_bytes()==b'unchanged70','standard '+family+' diagnostics preserve full JSON, occupied source port and log file')
        setting('full');admin(mode='ok',clear=True)
        for language,width in [('en',1280),('ru',390)]:
            command('preferences',{**command('snapshot')['preferences'],'language':language});command('select',{'id':identifier})
            h['request']('POST',h['base']+'/window/rect',{'width':width,'height':900})
            wait_for('return document.documentElement.lang==='+json.dumps(language)+' && innerWidth==='+str(width))
            h['click']('.primary-nav button:last-child');h['click']('[data-settings-section=testing]')
            wait_for('return document.querySelector("#diagnostics-profile")?.textContent.includes("full xray") && !document.querySelector("#diagnostics-speed").disabled')
            js('document.querySelector(".settings-test-actions").scrollIntoView({block:"center",behavior:"instant"})')
            wait_for('const r=document.querySelector("#diagnostics-speed").getBoundingClientRect();return r.top>=65 && r.bottom<innerHeight-65')
            h['click']('#diagnostics-speed');wait_for('return !!document.querySelector("#settings-test-result")',30)
            text=js('return document.querySelector("#settings-test-result").textContent')
            check('↓' in text and '↑' in text and '—' not in text,'native standard full button displays both measured directions in '+language)
            js('document.querySelector("#settings-test-result").scrollIntoView({block:"center",behavior:"instant"})')
            wait_for('const r=document.querySelector("#settings-test-result").getBoundingClientRect();return r.top>=65 && r.bottom<innerHeight-12')
            check(js('return document.documentElement.scrollWidth<=innerWidth+1'),'standard full result fits '+language+' '+str(width)+'px')
            h['screenshot']('standard-full-'+language+'-'+str(width));poll(lambda:admin()['active']==0);preserved()
        check(True,'all standard speed scenarios preserve main Core PID, connection age and held TCP stream')
        audit['primaryPreserved']=True
    except Exception:
        import traceback;audit['failure']=traceback.format_exc();raise
    finally:
        for token in tokens:
            with contextlib.suppress(Exception):command('cancelSettingsTest',{'requestId':token})
        with contextlib.suppress(Exception):admin(mode='ok',release=True)
        for stream in sockets:
            with contextlib.suppress(OSError):stream.close()
        with contextlib.suppress(Exception):audit['lastLogs']=command('getLogs')
        (h['artifacts']/'standard-speed-audit.json').write_text(json.dumps(audit,indent=2)+'\n')
        with contextlib.suppress(Exception):command('disconnect')
