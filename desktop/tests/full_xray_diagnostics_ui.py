"""Real IP and speed through a full Xray client policy in an owned network."""
import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import time
import urllib.request
from geodata_assets_fixture import geosite


def run(h):
    command,check,js,wait_for=(h[k] for k in ('command','check','js','wait_for'))
    fixture=json.loads(Path(os.environ['_THRONIUM_FULL_XRAY_DIAGNOSTICS_FIXTURE']).read_text())
    root=Path(command('storageLocation')['directory']);initial=command('snapshot');assert not initial['profiles']
    sockets=[];tokens=[];audit={'results':[]};counter=0
    def admin(**values):
        req=urllib.request.Request(fixture['admin'],data=json.dumps(values).encode() if values else None,headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(req,timeout=3) as response:return json.load(response)
    def poll(predicate,timeout=8):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            if predicate():return
            time.sleep(.05)
        raise AssertionError('full diagnostics fixture did not reach expected state')
    def available():
        s=socket.socket();s.bind(('127.0.0.1',0));s.listen();sockets.append(s);return s
    def add(name,config,kind='xray-config'):
        return command('saveProfile',{'name':'Full Xray68 '+name,'kind':kind,'groupId':'personal','config':config})['id']
    def begin(kind,identifier):
        nonlocal counter
        counter+=1;token='full-diagnostics68-'+str(counter);tokens.append(token)
        js('''const token=arguments[2];window.__full68??={};window.__full68[token]={done:false};
            window.__TAURI_INTERNALS__.invoke('app_command',{name:arguments[0],payload:{id:arguments[1],requestId:token}})
            .then(value=>window.__full68[token]={done:true,ok:true,value})
            .catch(error=>window.__full68[token]={done:true,ok:false,error});''',kind,identifier,token)
        return token
    def finish(token):
        wait_for('return window.__full68?.['+json.dumps(token)+']?.done',20)
        result=json.loads(js('return JSON.stringify(window.__full68[arguments[0]])',token));audit['results'].append(result);return result
    def run_test(kind,identifier):return finish(begin(kind,identifier))
    def setting(section,**values):
        old=command('settings')[section];return command('saveSettings',{'section':section,'previous':old,'values':{**old,**values}})
    def download(host='download.probe.test'):return 'http://'+host+':'+str(fixture['httpPort'])+'/download'
    def error(row,code=None):return not row['ok'] and (code is None or row['error'].get('code')==code) and 'value' not in row
    old1,old2=available(),available();log=root/'diagnostics-log-sentinel';log.write_bytes(b'unchanged log68')
    config={'log':{'access':str(log),'error':str(log),'loglevel':'debug'},
            'dns':{'servers':[{'address':'127.0.0.1','port':fixture['dnsPort']}],'queryStrategy':'UseIPv4','disableCache':True},
            'inbounds':[{'protocol':'socks','tag':'client','listen':'0.0.0.0','port':old1.getsockname()[1],'sniffing':{'enabled':True,'routeOnly':True,'destOverride':['http','tls']}},
                        {'protocol':'http','tag':'http','listen':'0.0.0.0','port':old2.getsockname()[1]}],
            'outbounds':[{'protocol':'freedom','tag':'direct','settings':{'domainStrategy':'UseIP'}},{'protocol':'blackhole','tag':'block'}],
            'routing':{'domainStrategy':'IPIfNonMatch','rules':[{'inboundTag':['client'],'domain':['domain:blocked.probe.test'],'outboundTag':'block'}]}}
    try:
        with socket.socket() as temporary:
            temporary.bind(('127.0.0.1',0));main_port=temporary.getsockname()[1]
        command('preferences',{**initial['preferences'],'language':'en','theme':'dark','connectionMode':'local','inboundPort':main_port,'ping':{**initial['preferences']['ping'],'timeoutMs':1500}})
        setting('testing',speed_test_mode='simple',simple_dl_url=download(),speed_test_timeout_ms=2000)
        main=add('main',{'type':'direct'},'sing-box-outbound');full=add('client policy',config)
        command('connect',{'id':main});before=command('snapshot')
        listener=available();client=socket.create_connection(('127.0.0.1',main_port),timeout=3);sockets.append(client)
        authority='127.0.0.1:'+str(listener.getsockname()[1]);client.sendall(('CONNECT '+authority+' HTTP/1.1\r\nHost: '+authority+'\r\n\r\n').encode())
        upstream,_=listener.accept();upstream.settimeout(3);sockets.append(upstream);assert b'200' in client.recv(1024)
        from window_ui import primary
        from native_processes import core_pids
        connection,_,app_pid=primary();connection.close();main_pids=core_pids(app_pid)
        def preserved():
            poll(lambda:core_pids(app_pid)==main_pids)
            current=command('snapshot');assert current['running']==main and current['since']==before['since']
            client.sendall(b'preserved68');assert upstream.recv(11)==b'preserved68'
        routing=command('routing');active=next(p for p in routing['profiles'] if p['id']==routing['active'])
        active['dns']={'servers':[{'type':'udp','tag':'dns-direct','server':'192.0.2.99'}],'final':'dns-direct'};command('saveRouting',routing)
        check(next(p for p in command('snapshot')['profiles'] if p['id']==full)['ipSpeedSupported'],'native snapshot advertises IP and speed for a supported complete Xray client')
        row=run_test('testIp',full);state=admin()
        check(row['ok'] and row['value']['result']['ip']=='203.0.113.9' and row['value']['result']['countryCode']=='JP','full Xray resolves and calls the owned TLS IP service using its client DNS')
        check(any(q['name']=='api.ip2location.io' for q in state['dnsQueries']) and len(state['requests'])==1,'the IP request reaches the real destination despite different global DNS')
        cache=root/'exit-countries-v1.json';assert json.loads(cache.read_text())['entries'][full]['countryCode']=='JP'
        check(not any(s in cache.read_text() for s in ['203.0.113.9',str(root),'xray-assets']),'the persisted country cache contains no exit IP or local asset path')
        admin(clear=True);row=run_test('testSpeed',full);state=admin()
        check(row['ok'] and row['value']['result']['downloadBytes']==262144 and sum(r['bytes'] for r in state['requests'])==262144,'full Xray speed test transfers and counts the actual download body')
        check(any(q['name']=='download.probe.test' for q in state['dnsQueries']),'speed diagnostics use the complete client DNS for the download domain')
        check(command('profile',{'id':full})['config']==config and log.read_bytes()==b'unchanged log68','IP and speed keep saved full JSON, original ports and configured logs untouched')
        preserved();check(True,'IP and speed preserve the primary Core PID, age and open TCP stream')
        setting('testing',simple_dl_url=download('blocked.probe.test'));admin(clear=True);row=run_test('testSpeed',full)
        check(error(row) and not admin()['requests'],'full-client inbound-tag/domain policy blocks the speed request')
        setting('testing',simple_dl_url=download());admin(clear=True,mode='dns-fail');row=run_test('testIp',full)
        check(error(row) and not admin()['requests'],'IP testing does not replace a failed client DNS with the host resolver')
        for mode in ['ip-invalid','ip-oversize','http-error']:
            admin(clear=True,mode=mode);row=run_test('testIp',full)
            check(error(row),'IP diagnostics reject '+mode+' without a successful result')
        admin(mode='ip-v6');row=run_test('testIp',full)
        check(row['ok'] and row['value']['result']['ip']=='2001:db8::9' and row['value']['result']['countryCode']=='DE','full-client IP accepts a validated IPv6 address and country')
        admin(mode='ip-unknown');row=run_test('testIp',full)
        check(row['ok'] and row['value']['result']['countryCode'] is None and full not in json.loads(cache.read_text())['entries'],'an unknown country clears the previous derived observation')
        for mode in ['speed-empty','speed-truncated','http-error']:
            admin(clear=True,mode=mode);row=run_test('testSpeed',full)
            check(error(row),'speed diagnostics reject '+mode+' without reporting successful throughput')
        admin(mode='ok');url='https://assets.probe.test/geosite.dat';setting('core',xray_geosite_url=url)
        geo=copy.deepcopy(config);geo['routing']['rules'][0]['domain']=['geosite:TEST'];geo_id=add('geodata',geo)
        admin(clear=True);row=run_test('testIp',geo_id)
        check(error(row,'geodata_missing') and not admin()['requests'],'full-client IP reports missing geodata without downloading or dialing')
        data_dir=root/'xray-assets';data_dir.mkdir(mode=0o700,exist_ok=True)
        manifest=data_dir/(hashlib.sha256((url+':null').encode()).hexdigest()+'.ref')
        def seed(domain):
            body=geosite(domain=domain);digest=hashlib.sha256(body).hexdigest();path=data_dir/(digest+'.dat')
            path.write_bytes(body);manifest.write_text(digest);return path,body
        first,body=seed('blocked.probe.test');admin(clear=True);row=run_test('testIp',geo_id)
        check(row['ok'] and first.read_bytes()==body,'full-client IP reads the independently encoded cached GeoSite in its private runtime')
        previous_cache=cache.read_bytes()
        admin(clear=True,mode='hold');token=begin('testIp',geo_id);poll(lambda:admin()['active']>0)
        second,_=seed('api.ip2location.io');admin(mode='ok',release=True);row=finish(token)
        check(error(row,'probe_stale') and cache.read_bytes()==previous_cache,'a geodata update during IP lookup discards the response and preserves the previous cache file')
        admin(clear=True);row=run_test('testIp',geo_id)
        check(error(row) and not admin()['requests'],'the next full-client IP lookup applies the new GeoSite block category')
        admin(clear=True);row=run_test('testSpeed',geo_id)
        check(row['ok'] and row['value']['result']['downloadBytes']==262144,'the same GeoSite version can block IP lookup while permitting the download route')
        admin(clear=True,mode='hold');token=begin('testSpeed',geo_id);poll(lambda:admin()['active']>0)
        seed('download.probe.test');admin(mode='ok',release=True);row=finish(token)
        check(error(row,'probe_stale'),'a geodata update invalidates a pending speed result')
        admin(clear=True);row=run_test('testSpeed',geo_id)
        check(error(row) and not admin()['requests'],'the next speed test consumes the new GeoSite download block')
        first,body=seed('blocked.probe.test');first.write_bytes(b'corrupt owned bytes');admin(clear=True);row=run_test('testSpeed',geo_id)
        check(error(row,'geodata_invalid') and not admin()['requests'],'speed testing refuses corrupt immutable geodata before the request')
        first.write_bytes(body)
        for kind in ['testIp','testSpeed']:
            admin(clear=True,mode='hold');token=begin(kind,geo_id);poll(lambda:admin()['active']>0)
            command('cancelSettingsTest',{'requestId':token});row=finish(token);admin(mode='ok',release=True);poll(lambda:admin()['active']==0)
            check(error(row,'probe_cancelled'),kind+' cancellation rejects late full-client replies');preserved()
        admin(clear=True,mode='hold');token=begin('testIp',geo_id);poll(lambda:admin()['active']>0)
        setting('core',xray_geosite_url='https://other.probe.test/geosite.dat');admin(mode='ok',release=True);row=finish(token);setting('core',xray_geosite_url=url)
        check(error(row,'probe_stale'),'changing the geodata source invalidates the in-flight IP lookup')
        admin(clear=True,mode='hold');token=begin('testSpeed',full);poll(lambda:admin()['active']>0)
        changed=command('profile',{'id':full});changed['config']['routing']['domainStrategy']='AsIs';command('saveProfile',changed)
        admin(mode='ok',release=True);row=finish(token)
        check(error(row,'probe_stale'),'editing full client routing rejects a pending speed result')
        unsupported=copy.deepcopy(config);unsupported['api']={'tag':'api','services':[]};refused=add('unsupported API',unsupported)
        admin(clear=True)
        for kind in ['testIp','testSpeed']:
            row=run_test(kind,refused);check(error(row,'probe_unsupported') and not admin()['requests'],kind+' refuses unsupported full-Xray background features')
        for language,width in [('en',1280),('ru',390)]:
            command('preferences',{**command('snapshot')['preferences'],'language':language});command('select',{'id':geo_id})
            h['request']('POST',h['base']+'/window/rect',{'width':width,'height':900})
            wait_for('return document.documentElement.lang==='+json.dumps(language)+' && innerWidth==='+str(width))
            h['click']('.primary-nav button:last-child');h['click']('[data-settings-section=testing]')
            wait_for('return document.querySelector("#diagnostics-profile")?.textContent.includes("geodata") && !document.querySelector("#diagnostics-ip").disabled')
            js('document.querySelector(".settings-test-actions").scrollIntoView({block:"center",behavior:"instant"})')
            wait_for('const r=document.querySelector("#diagnostics-ip").getBoundingClientRect();return r.top>=0 && r.bottom<innerHeight-65')
            text=js('return document.querySelector(".settings-test-actions").textContent')
            check(('Полные sing-box и Xray JSON' in text if language=='ru' else 'Complete sing-box and Xray JSON' in text) and js('return !document.querySelector("#diagnostics-speed").disabled && document.documentElement.scrollWidth<=innerWidth+1'),'full Xray IP/speed actions and client-policy hint fit '+language+' '+str(width)+'px')
            admin(mode='ok');h['click']('#diagnostics-ip');wait_for('return !!document.querySelector("#diagnostics-exit-ip")',15)
            check(js('return document.querySelector("#diagnostics-exit-ip").textContent==="203.0.113.9"'),'native IP button displays the full-client result in '+language)
            h['screenshot']('full-xray-diagnostics-'+language+'-'+str(width))
        preserved();check(True,'all full-client IP/speed scenarios preserve the original active TCP stream')
        audit.update(mainCorePreserved=True,sourceUnchanged=command('profile',{'id':geo_id})['config']==geo,origin=admin())
    except Exception:
        import traceback
        audit['failure']=traceback.format_exc();raise
    finally:
        for token in tokens:
            with contextlib.suppress(Exception):command('cancelSettingsTest',{'requestId':token})
        with contextlib.suppress(Exception):admin(mode='ok',release=True)
        for stream in sockets:
            with contextlib.suppress(OSError):stream.close()
        with contextlib.suppress(Exception):audit['lastLogs']=command('getLogs')
        (h['artifacts']/'full-diagnostics-audit.json').write_text(json.dumps(audit,indent=2)+'\n')
        with contextlib.suppress(Exception):command('disconnect')
