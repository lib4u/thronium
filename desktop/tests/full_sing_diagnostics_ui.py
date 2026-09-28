"""Real IP and speed through a full sing-box client policy in an owned network."""
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
    fixture=json.loads(Path(os.environ['_THRONIUM_FULL_SING_DIAGNOSTICS_FIXTURE']).read_text())
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
    def add(name,config,kind='sing-box-config'):
        return command('saveProfile',{'name':'Full sing-box69 '+name,'kind':kind,'groupId':'personal','config':config})['id']
    def begin(kind,identifier):
        nonlocal counter
        counter+=1;token='full-diagnostics69-'+str(counter);tokens.append(token)
        js('''const token=arguments[2];window.__full69??={};window.__full69[token]={done:false};
            window.__TAURI_INTERNALS__.invoke('app_command',{name:arguments[0],payload:{id:arguments[1],requestId:token}})
            .then(value=>window.__full69[token]={done:true,ok:true,value})
            .catch(error=>window.__full69[token]={done:true,ok:false,error});''',kind,identifier,token)
        return token
    def finish(token):
        wait_for('return window.__full69?.['+json.dumps(token)+']?.done',20)
        result=json.loads(js('return JSON.stringify(window.__full69[arguments[0]])',token));audit['results'].append(result);return result
    def run_test(kind,identifier):return finish(begin(kind,identifier))
    def setting(section,**values):
        old=command('settings')[section];return command('saveSettings',{'section':section,'previous':old,'values':{**old,**values}})
    def download(host='download.probe.test'):return 'http://'+host+':'+str(fixture['httpPort'])+'/download'
    def error(row,code=None):return not row['ok'] and (code is None or row['error'].get('code')==code) and 'value' not in row
    def http_done():
        poll(lambda:command('snapshot')['urlTests']['entries'][0]['status'] not in ('queued','testing'),20)
        row=command('snapshot')['urlTests']['entries'][0];audit.setdefault('http',[]).append(row);return row
    def http(identifier,host='download.probe.test',method='http'):
        command('startUrlTests',{'ids':[identifier],'method':method,'url':download(host),'timeoutMs':1500})
        return http_done()
    old1,old2=available(),available();log=root/'diagnostics-log-sentinel';log.write_bytes(b'unchanged log69')
    config={'log':{'output':str(log),'level':'debug'},
            'dns':{'servers':[{'type':'udp','tag':'client-dns','server':'127.0.0.1','server_port':fixture['dnsPort']}],'final':'client-dns','disable_cache':True},
            'inbounds':[{'type':'http','tag':'http','listen':'0.0.0.0','listen_port':old1.getsockname()[1]},
                        {'type':'mixed','tag':'client','listen':'::','listen_port':old2.getsockname()[1]}],
            'outbounds':[{'type':'direct','tag':'proxy'}],
            'route':{'final':'proxy','default_domain_resolver':'client-dns','auto_detect_interface':True,
                     'rule_set':[{'type':'inline','tag':'local-category','rules':[{'domain':['inline.probe.test']}]}],
                     'rules':[{'inbound':['client'],'action':'sniff'},
                              {'type':'logical','mode':'and','rules':[{'inbound':['client']},{'domain':['blocked.probe.test']}],'action':'reject'},
                              {'rule_set':['local-category'],'action':'reject'},
                              {'action':'resolve','strategy':'ipv4_only','server':'client-dns'},
                              {'ip_cidr':['192.0.2.0/24'],'action':'reject'}]}}
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
            client.sendall(b'preserved69');assert upstream.recv(11)==b'preserved69'
        routing=command('routing');active=next(p for p in routing['profiles'] if p['id']==routing['active'])
        active['dns']={'servers':[{'type':'udp','tag':'dns-direct','server':'192.0.2.99'}],'final':'dns-direct'};command('saveRouting',routing)
        check(next(p for p in command('snapshot')['profiles'] if p['id']==full)['ipSpeedSupported'],'native snapshot advertises IP and speed for a supported complete sing-box client')
        row=run_test('testIp',full);state=admin()
        check(row['ok'] and row['value']['result']['ip']=='203.0.113.9' and row['value']['result']['countryCode']=='JP','full sing-box resolves and calls the owned TLS IP service using its client DNS')
        check(any(q['name']=='api.ip2location.io' for q in state['dnsQueries']) and len(state['requests'])==1,'the IP request reaches the real destination despite different global DNS')
        cache=root/'exit-countries-v1.json';assert json.loads(cache.read_text())['entries'][full]['countryCode']=='JP'
        check(not any(s in cache.read_text() for s in ['203.0.113.9',str(root),'xray-assets']),'the persisted country cache contains no exit IP or local asset path')
        admin(clear=True);row=run_test('testSpeed',full);state=admin()
        check(row['ok'] and row['value']['result']['downloadBytes']==262144 and sum(r['bytes'] for r in state['requests'])==262144,'full sing-box speed test transfers and counts the actual download body')
        check(any(q['name']=='download.probe.test' for q in state['dnsQueries']),'speed diagnostics use the complete client DNS for the download domain')
        check(command('profile',{'id':full})['config']==config and log.read_bytes()==b'unchanged log69','IP and speed keep saved full JSON, original ports and configured logs untouched')
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
        admin(mode='ok')
        def edit_inline(domain):
            current=command('profile',{'id':full});current['config']['route']['rule_set'][0]['rules'][0]['domain']=[domain]
            command('saveProfile',current)
        def restore():
            current=command('profile',{'id':full});current['config']=copy.deepcopy(config);command('saveProfile',current)
        admin(clear=True);row=http(full)
        check(row['status']=='ok' and len(admin()['requests'])==2,'full sing-box HTTP performs real warmup and measurement through the client router')
        for host,label in [('blocked.probe.test','nested inbound/domain'),('inline.probe.test','inline rule-set'),('ipblocked.probe.test','resolved IP')]:
            admin(clear=True);row=http(full,host)
            check(row['status']=='error' and not admin()['requests'],'client '+label+' rule blocks HTTP rather than being bypassed by an outbound test')
            if host=='ipblocked.probe.test':check(any(q['name']==host for q in admin()['dnsQueries']),'the client resolve action performs DNS before the IP block')
        admin(clear=True);row=http(full,method='auto')
        check(row['status']=='ok' and row['effectiveMethod']=='http' and len(row['attempts'])==1,'Auto accepts full-client HTTP without probing an arbitrary source outbound')
        admin(mode='ok');row=run_test('testIp',full);assert row['ok'];previous_cache=cache.read_bytes()
        admin(clear=True,mode='hold');token=begin('testIp',full);poll(lambda:admin()['active']>0)
        edit_inline('api.ip2location.io');admin(mode='ok',release=True);row=finish(token)
        check(error(row,'probe_stale') and cache.read_bytes()==previous_cache,'editing an inline category during IP lookup discards the reply and preserves the old cache file')
        admin(clear=True);row=run_test('testIp',full)
        check(error(row) and not admin()['requests'],'the next IP lookup follows the updated inline block')
        admin(clear=True);row=run_test('testSpeed',full)
        check(row['ok'] and row['value']['result']['downloadBytes']==262144,'one full-client policy can block IP lookup while allowing download')
        admin(clear=True,mode='hold');token=begin('testSpeed',full);poll(lambda:admin()['active']>0)
        edit_inline('download.probe.test');admin(mode='ok',release=True);row=finish(token)
        check(error(row,'probe_stale'),'inline policy edits reject the pending speed result')
        admin(clear=True);row=run_test('testSpeed',full)
        check(error(row) and not admin()['requests'],'the next speed test applies the edited inline category')
        restore()
        for kind in ['testIp','testSpeed']:
            admin(clear=True,mode='hold');token=begin(kind,full);poll(lambda:admin()['active']>0)
            command('cancelSettingsTest',{'requestId':token});row=finish(token);admin(mode='ok',release=True);poll(lambda:admin()['active']==0)
            check(error(row,'probe_cancelled'),kind+' cancellation rejects late full-client replies');preserved()
        admin(clear=True,mode='hold');command('startUrlTests',{'ids':[full],'method':'http','url':download(),'timeoutMs':5000});poll(lambda:admin()['active']>0)
        edit_inline('download.probe.test');admin(mode='ok',release=True);row=http_done()
        check(row['status']=='stale','editing client inline routing invalidates a pending HTTP result');restore()
        admin(clear=True,mode='hold');command('startUrlTests',{'ids':[full],'method':'http','url':download(),'timeoutMs':5000});poll(lambda:admin()['active']>0)
        command('cancelUrlTests');row=http_done();admin(mode='ok',release=True);poll(lambda:admin()['active']==0)
        check(row['status']=='cancelled','full sing-box HTTP cancellation releases the owned client operation');preserved()
        admin(clear=True,mode='hold');token=begin('testIp',full);poll(lambda:admin()['active']>0)
        changed=command('profile',{'id':full});changed['config']['dns']['servers'][0]['server']='192.0.2.99';command('saveProfile',changed)
        admin(mode='ok',release=True);row=finish(token);restore()
        check(error(row,'probe_stale'),'editing full-client DNS rejects a pending IP result')
        unsupported=[]
        for label in ['external rule-set']:
            invalid=copy.deepcopy(config)
            invalid['route']['rule_set'][0]={'type':'remote','tag':'local-category','format':'binary','url':'https://unowned.test/file.srs'}
            identifier=add(label,invalid);unsupported.append(identifier)
            admin(clear=True);ip=run_test('testIp',identifier);speed=run_test('testSpeed',identifier);latency=http(identifier)
            check(error(ip,'probe_unsupported') and error(speed,'probe_unsupported') and latency['status']=='unsupported' and not admin()['requests'],label+' is explicitly refused by HTTP/IP/Speed before network work')
        # Qt tests a complete client with its own listeners cleared, so these are
        # measured through the client router instead of being refused.
        adapted=[]
        for label in ['TUN','background API','nonselected ingress']:
            variant=copy.deepcopy(config)
            if label=='TUN':variant['inbounds'][0]={'type':'tun','tag':'tun-in','address':['172.19.0.1/30'],'auto_route':True}
            elif label=='background API':variant['experimental']={'clash_api':{'external_controller':'127.0.0.1:60000'}}
            else:variant['route']['rules'][1]['rules'][0]['inbound']=['http']
            identifier=add(label,variant);adapted.append(identifier)
            admin(clear=True,mode='ok');ip=run_test('testIp',identifier)
            check(ip['ok'] and ip['value']['result']['ip']=='203.0.113.9',label+' is measured through the client router, as Qt measures it: '+json.dumps(ip))
            if label=='background API':
                with socket.socket() as probe:
                    check(probe.connect_ex(('127.0.0.1',60000))!=0,'the disposable check never opens the client background API listener')
            if label=='TUN':
                check(not any(name.startswith('tun') for name in os.listdir('/sys/class/net')) or 'tun-in' not in os.listdir('/sys/class/net'),
                      'the disposable check creates no host interface for a client TUN listener')
        caps={p['id']:p['ipSpeedSupported'] for p in command('snapshot')['profiles']}
        check(caps[full] and all(caps[p] for p in adapted) and all(not caps[p] for p in unsupported),'snapshot capability follows supported client policy: adapted listeners stay measurable, an external rule-set does not')
        for language,width in [('en',1280),('ru',390)]:
            command('preferences',{**command('snapshot')['preferences'],'language':language});command('select',{'id':full})
            h['request']('POST',h['base']+'/window/rect',{'width':width,'height':900})
            wait_for('return document.documentElement.lang==='+json.dumps(language)+' && innerWidth==='+str(width))
            h['click']('.primary-nav button:last-child');h['click']('[data-settings-section=testing]')
            wait_for('return document.querySelector("#diagnostics-profile")?.textContent.includes("client policy") && !document.querySelector("#diagnostics-ip").disabled')
            js('document.querySelector(".settings-test-actions").scrollIntoView({block:"center",behavior:"instant"})')
            wait_for('const r=document.querySelector("#diagnostics-ip").getBoundingClientRect();return r.top>=0 && r.bottom<innerHeight-65')
            text=js('return document.querySelector(".settings-test-actions").textContent')
            check(('Полные sing-box и Xray JSON' in text if language=='ru' else 'Complete sing-box and Xray JSON' in text) and js('return !document.querySelector("#diagnostics-speed").disabled && document.documentElement.scrollWidth<=innerWidth+1'),'full sing-box IP/speed actions and client-policy hint fit '+language+' '+str(width)+'px')
            admin(mode='ok');h['click']('#diagnostics-ip');wait_for('return !!document.querySelector("#diagnostics-exit-ip")',15)
            check(js('return document.querySelector("#diagnostics-exit-ip").textContent==="203.0.113.9"'),'native IP button displays the full-client result in '+language)
            js('document.querySelector(".settings-test-actions").scrollIntoView({block:"center",behavior:"instant"})')
            wait_for('const r=document.querySelector("#diagnostics-country").getBoundingClientRect();return r.top>=65 && r.bottom<innerHeight-65')
            h['screenshot']('full-sing-diagnostics-'+language+'-'+str(width))
        preserved();check(True,'all full-client IP/speed scenarios preserve the original active TCP stream')
        audit.update(mainCorePreserved=True,sourceUnchanged=command('profile',{'id':full})['config']==config,origin=admin())
    except Exception:
        import traceback
        audit['failure']=traceback.format_exc();raise
    finally:
        with contextlib.suppress(Exception):command('cancelUrlTests')
        for token in tokens:
            with contextlib.suppress(Exception):command('cancelSettingsTest',{'requestId':token})
        with contextlib.suppress(Exception):admin(mode='ok',release=True)
        for stream in sockets:
            with contextlib.suppress(OSError):stream.close()
        with contextlib.suppress(Exception):audit['lastLogs']=command('getLogs')
        (h['artifacts']/'full-sing-diagnostics-audit.json').write_text(json.dumps(audit,indent=2)+'\n')
        with contextlib.suppress(Exception):command('disconnect')
