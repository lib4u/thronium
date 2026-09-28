"""Real settings, HTTPS downloads and Xray routing against independent owned assets."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import urllib.request
import urllib.parse
import uuid


def run(h):
    command,click,fill,js,wait_for,check=(h[k] for k in ('command','click','fill','js','wait_for','check'))
    fixture=json.loads(Path(os.environ['_THRONIUM_GEODATA_FIXTURE']).read_text())
    initial=command('snapshot');original=command('settings');pending=set();audit={'errors':[],'latencies':[]}
    urls={kind:'https://assets.thronium.test/'+kind+'.dat' for kind in ['geoip','geosite']}
    root=Path(command('storageLocation')['directory'])
    def port():
        with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
    def admin(**values):
        req=urllib.request.Request(fixture['admin'],data=json.dumps(values).encode() if values else None,headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(req,timeout=3) as response:return json.load(response)
    def poll(predicate,timeout=8):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            if predicate():return
            time.sleep(.05)
        raise AssertionError('Geodata fixture state timeout')
    def save(section,**values):
        old=command('settings')[section];return command('saveSettings',{'section':section,'previous':old,'values':{**old,**values}})
    def status(kind='geosite'):return command('xrayGeodataStatus',{'kind':kind,'url':urls[kind]})
    def request(kind='geosite',identifier=None):return {'requestId':identifier or str(uuid.uuid4()),'selection':{'kind':kind,'url':urls[kind]}}
    def rejected(name,payload,expected):
        result=json.loads(h['request']('POST',h['base']+'/execute/async',{'script':"const done=arguments[arguments.length-1];window.__TAURI_INTERNALS__.invoke('app_command',{name:arguments[0],payload:arguments[1]}).then(value=>done(JSON.stringify({ok:true,value}))).catch(error=>done(JSON.stringify({ok:false,error})));",'args':[name,payload]}))
        assert not result['ok'] and result['error'].get('code')==expected,str(result);audit['errors'].append(expected);return True
    def begin(identifier):
        pending.add(identifier)
        js("window.__geo64??={};const id=arguments[0];window.__geo64[id]={done:false};window.__TAURI_INTERNALS__.invoke('app_command',{name:'downloadXrayGeodata',payload:arguments[1]}).then(value=>window.__geo64[id]={done:true,ok:true,value}).catch(error=>window.__geo64[id]={done:true,ok:false,error});",identifier,request(identifier=identifier))
    def finish(identifier,error=None):
        wait_for('return window.__geo64?.['+json.dumps(identifier)+']?.done',12)
        value=json.loads(js('return JSON.stringify(window.__geo64[arguments[0]])',identifier));pending.discard(identifier)
        assert value['ok']==(error is None),str(value)
        if error:assert value['error'].get('code') in (error if isinstance(error,tuple) else (error,)),str(value);audit['errors'].append(value['error'].get('code'))
        return value.get('value')
    def settings():
        click('.primary-nav button:last-child');click('[data-settings-section=core]');wait_for('return !!document.querySelector("#xray-geo-assets")');js('document.querySelector("#settings-xray").open=true')
    def show(selector):js('document.querySelector(arguments[0]).scrollIntoView({block:"center",behavior:"instant"})',selector)
    def press(selector):show(selector);click(selector)
    def ready():wait_for('return !document.querySelector("[data-geo-cancel]") && !document.querySelector("[data-geo-download=geosite]").disabled',20)
    def pids():
        target=Path(h['args'].application).with_name('ThroniumCore').resolve();found=[]
        for proc in Path('/proc').iterdir():
            if proc.name.isdigit():
                with contextlib.suppress(OSError):
                    if (proc/'exe').resolve()==target:found.append(int(proc.name))
        return sorted(found)
    inbound=port();admin_port=urllib.parse.urlsplit(fixture['admin']).port
    def http(host='127.0.0.1'):
        result=subprocess.run(['curl','--fail','--silent','--show-error','--max-time','3','--noproxy','','--proxy','socks5h://127.0.0.1:'+str(inbound),'http://'+host+':'+str(admin_port)+'/traffic64'],capture_output=True,timeout=5)
        audit.setdefault('http',[]).append({'host':host,'exitCode':result.returncode,'stderr':result.stderr.decode(errors='replace')[-500:],'body':result.stdout.decode(errors='replace')[:400]});return result.returncode==0 and b'"requests"' in result.stdout
    try:
        command('preferences',{**initial['preferences'],'language':'en','theme':'dark','connectionMode':'local','inboundPort':inbound})
        h['request']('POST',h['base']+'/window/rect',{'width':1280,'height':900});wait_for('return document.documentElement.lang==="en"')
        count=len(admin()['requests']);check(status()['state']=='missing' and status('geoip')['state']=='missing' and not pids() and len(admin()['requests'])==count,'local asset status neither contacts the network nor starts Core')
        check(rejected('downloadXrayGeodata',{**request(),'extra':True},'geodata_invalid_request') and rejected('xrayGeodataStatus',{'kind':'geoip','url':'http://assets.thronium.test/geoip.dat'},'geodata_url_invalid'),'invalid requests and insecure sources are rejected before a download')
        save('network',net_use_proxy=True);check(rejected('downloadXrayGeodata',request(),'geodata_proxy_unavailable') and len(admin()['requests'])==count,'unavailable selected application proxy does not fall back to direct download');save('network',net_use_proxy=False)
        identifier=str(uuid.uuid4());command('cancelXrayGeodataDownload',{'requestId':identifier});check(rejected('downloadXrayGeodata',request(identifier=identifier),'geodata_request_finished'),'cancel-before-dispatch prevents a late download')
        settings()
        for kind in ['geoip','geosite']:show('#setting-xray_'+kind+'_url');fill('#setting-xray_'+kind+'_url',urls[kind])
        stored=command('settings')['core'];library=json.loads((root/'library.json').read_text())
        press('[data-geo-download=geosite]');ready();first=status();assert first['state']=='ready',js('return document.querySelector("#xray-geo-assets").textContent')
        after_library=json.loads((root/'library.json').read_text());assert after_library['settings'].pop('xray_geosite_url_history')==[urls['geosite']]
        check(first['categories']==1 and first['entries']==1 and command('settings')['core']==stored and after_library==library and not pids(),'visible GeoSite download remembers its URL while keeping source settings and the rest of the library unchanged')
        admin(mode='redirect');press('[data-geo-download=geoip]');ready();ip=status('geoip');check(ip['state']=='ready' and ip['categories']==1 and any(r['host']=='mirror.thronium.test' for r in admin()['requests']),'GeoIP download follows an owned HTTPS redirect and validates independently encoded CIDR data');admin(mode='ok')
        press('#settings-save');poll(lambda:command('settings')['core']['xray_geosite_url']==urls['geosite'])
        check(command('settings')['core']['xray_geoip_url']==urls['geoip'],'source URLs persist only after the normal Save settings action')
        # Route on the requested domain, then dial the owned literal service. This loopback-only namespace has no default egress interface.
        config={'log':{'loglevel':'debug'},'dns':{'hosts':{'blocked.assets.test':'127.0.0.1','next.assets.test':'127.0.0.1'}},'outbounds':[{'protocol':'freedom','tag':'direct','settings':{'redirect':'127.0.0.1:'+str(admin_port)}},{'protocol':'blackhole','tag':'block'}],'routing':{'domainStrategy':'AsIs','rules':[{'type':'field','domain':['geosite:TEST@owned'],'outboundTag':'block'},{'type':'field','ip':['geoip:TEST'],'outboundTag':'block'}]}}
        profile=command('saveProfile',{'name':'Owned geodata Xray64','groupId':'personal','kind':'xray-config','config':config})['id']
        count=len(admin()['requests']);command('connect',{'id':profile});active=pids();since=command('snapshot')['since'];assert active
        initial_http={host:http(host) for host in ['127.0.0.1','blocked.assets.test','next.assets.test']};audit['initialHTTP']=initial_http
        check(initial_http=={'127.0.0.1':True,'blocked.assets.test':False,'next.assets.test':True} and len(admin()['requests'])==count,'a real full Xray connection consumes both downloaded assets without fetching and enforces the GeoSite route')
        for mode,error in [('http-error','geodata_download_rejected'),('malformed','geodata_invalid'),('wrong-kind','geodata_invalid'),('oversize','geodata_too_large'),('chunked','geodata_too_large'),('downgrade','geodata_download_failed'),('credentials','geodata_download_failed'),('missing-category','geodata_category_missing')]:
            admin(mode=mode);check(rejected('downloadXrayGeodata',request(),error) and status()['hash']==first['hash'] and pids()==active and command('snapshot')['since']==since,mode+' leaves the previous asset reference and active Core unchanged')
        admin(mode='hold');identifier=str(uuid.uuid4());begin(identifier);poll(lambda:admin()['active']==1)
        started=time.monotonic();command('snapshot');elapsed=time.monotonic()-started;audit['latencies'].append({'snapshot':elapsed})
        check(elapsed<2 and rejected('downloadXrayGeodata',request(),'geodata_busy'),'a held download leaves snapshot responsive and rejects concurrent jobs')
        command('cancelXrayGeodataDownload',{'requestId':str(uuid.uuid4())});assert not js('return window.__geo64[arguments[0]].done',identifier)
        command('cancelXrayGeodataDownload',{'requestId':identifier});finish(identifier,'geodata_cancelled');admin(release=True);poll(lambda:admin()['active']==0)
        check(status()['hash']==first['hash'] and rejected('downloadXrayGeodata',request(identifier=identifier),'geodata_request_finished'),'matching cancellation preserves cached data and rejects replay')
        save('network',network_timeout=5);admin(mode='hold');identifier=str(uuid.uuid4());begin(identifier);poll(lambda:admin()['active']==1);finish(identifier,'geodata_timeout');admin(release=True);poll(lambda:admin()['active']==0)
        check(status()['hash']==first['hash'] and pids()==active,'timeout preserves the old asset and live session')
        admin(mode='hold');press('[data-geo-download=geosite]');poll(lambda:admin()['active']==1);press('[data-geo-cancel=geosite]');ready();admin(release=True);poll(lambda:admin()['active']==0)
        check(status()['hash']==first['hash'] and not js('return document.querySelector("#setting-xray_geosite_url").disabled'),'visible cancellation preserves data and releases the source fields')
        admin(mode='updated');press('[data-geo-download=geosite]');ready();second=status();check(second['hash']!=first['hash'] and pids()==active and command('snapshot')['since']==since and not http('blocked.assets.test') and http('next.assets.test'),'refresh changes the saved asset reference while the active Xray route keeps its original data')
        command('disconnect');command('connect',{'id':profile});check(http('blocked.assets.test') and not http('next.assets.test'),'the next real connection uses the updated GeoSite routing data')
        command('disconnect');path=root/'xray-assets'/(second['hash']+'.dat');path.write_bytes(b'owned corrupt cache')
        check(status()['state']=='invalid','local status detects a corrupted immutable data file')
        press('[data-geo-download=geosite]');ready();check(status()['hash']==second['hash'] and status()['state']=='ready' and hashlib.sha256(path.read_bytes()).hexdigest()==second['hash'],'redownloading the same asset repairs a corrupted cache')
        # A weekly refresh due at Connect downloads without the Engine lock: the
        # window keeps its snapshot while the fixture holds the request.
        manifest=root/'xray-assets'/(hashlib.sha256((urls['geosite']+':null').encode()).hexdigest()+'.ref');stale=time.time()-8*24*3600;os.utime(manifest,(stale,stale))
        count=len(admin()['requests']);admin(mode='hold')
        js("window.__connect64={done:false};window.__TAURI_INTERNALS__.invoke('app_command',{name:'connect',payload:{id:arguments[0]}}).then(()=>window.__connect64={done:true,ok:true}).catch(error=>window.__connect64={done:true,ok:false,error});",profile)
        poll(lambda:admin()['active']==1);started=time.monotonic();held=command('snapshot');elapsed=time.monotonic()-started;audit['latencies'].append({'connectDownloadSnapshot':elapsed})
        admin(release=True,mode='ok');wait_for('return window.__connect64?.done',20);connected=json.loads(js('return JSON.stringify(window.__connect64)'))
        check(elapsed<2 and held['running'] is None and connected['ok'] and command('snapshot')['running']==profile and pids() and len(admin()['requests'])==count+1,'a list refresh due at Connect downloads once without blocking the window, then the connection starts')
        command('disconnect')
        proxy=command('saveProfile',{'name':'Owned HTTPS SOCKS hop64','groupId':'personal','kind':'sing-box-outbound','config':{'type':'socks','server':'127.0.0.1','server_port':fixture['socksPort']}})['id'];command('connect',{'id':proxy});save('network',net_use_proxy=True);admin(mode='ok');count=len(admin()['proxyConnections'])
        command('downloadXrayGeodata',request());check(len(admin()['proxyConnections'])==count+1,'the application proxy carries an actual HTTPS asset download')
        admin(mode='hold');identifier=str(uuid.uuid4());begin(identifier);poll(lambda:admin()['active']==1);started=time.monotonic();command('disconnect');elapsed=time.monotonic()-started;audit['latencies'].append({'disconnect':elapsed});command('cancelXrayGeodataDownload',{'requestId':identifier});finish(identifier,('geodata_cancelled','geodata_download_failed'));admin(release=True);poll(lambda:admin()['active']==0)
        check(elapsed<2 and command('snapshot')['running'] is None,'Disconnect remains responsive while the download uses the live proxy')
        save('network',net_use_proxy=False);admin(mode='ok');h['request']('POST',h['base']+'/refresh',{});wait_for('return !!document.querySelector(".add-connection")');settings();ready()
        check(status()['state']=='ready' and status('geoip')['state']=='ready','asset status survives a WebView restart')
        for language,width in [('en',1280),('ru',390)]:
            command('preferences',{**command('snapshot')['preferences'],'language':language});h['request']('POST',h['base']+'/window/rect',{'width':width,'height':900});wait_for('return document.documentElement.lang==='+json.dumps(language));wait_for('return innerWidth==='+str(width));show('#xray-geo-assets');wait_for('const r=document.querySelector("#xray-geo-assets").getBoundingClientRect();return r.top>=50&&r.bottom<innerHeight-50')
            check(js('const r=document.querySelector("#xray-geo-assets").getBoundingClientRect();return r.left>=0&&r.right<=innerWidth&&document.documentElement.scrollWidth<=innerWidth+1'),'download cards are visible and fit '+language+' '+str(width)+'px');h['screenshot']('geodata-'+language+'-'+str(width))
        admin(mode='http-error');press('[data-geo-download=geosite]');ready();check(js('return [...document.querySelectorAll("#xray-geo-assets [role=alert]")].some(e=>e.textContent&&!e.textContent.includes("geodata_"))'),'Russian download errors are translated')
        logs=command('getLogs');check(bool(logs['entries']) and 'private-geodata-response64' not in json.dumps(logs),'nonempty Core logs do not expose rejected response bodies')
        audit.update({'requestCount':len(admin()['requests']),'proxyCount':len(admin()['proxyConnections']),'firstHash':first['hash'],'updatedHash':second['hash'],'logEntries':len(logs['entries'])})
    finally:
        for identifier in pending:
            with contextlib.suppress(Exception):command('cancelXrayGeodataDownload',{'requestId':identifier})
        admin(release=True,mode='ok')
        with contextlib.suppress(Exception):audit['lastLogs']=command('getLogs')
        with contextlib.suppress(Exception):command('disconnect')
        with contextlib.suppress(Exception):audit['ui']=js('return document.querySelector("#xray-geo-assets")?.textContent')
        (Path(h['args'].artifacts)/'geodata-audit.json').write_text(json.dumps(audit,indent=2)+'\n')
