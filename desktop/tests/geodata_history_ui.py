"""Real HTTPS download attempts, bounded source history and unchanged primary TCP."""
import contextlib
import json
import os
from pathlib import Path
import socket
import time
import urllib.request
import uuid


def run(h):
    command,click,fill,select,js,wait_for,check=(h[k] for k in ('command','click','fill','select','js','wait_for','check'))
    fixture=json.loads(Path(os.environ['_THRONIUM_GEODATA_FIXTURE']).read_text());audit={};sockets=[]
    def admin(**values):
        req=urllib.request.Request(fixture['admin'],data=json.dumps(values).encode() if values else None,headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(req,timeout=3) as response:return json.load(response)
    def poll(predicate,timeout=8):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            if predicate():return
            time.sleep(.05)
        raise AssertionError('Geodata history fixture state timeout')
    def sources():return command('xrayGeodataSources')
    def history(kind='geosite'):return sources()['history'][kind]
    def url(n,kind='geosite'):return 'https://assets.thronium.test/'+str(n)+'/'+kind+'.dat'
    def show(selector):
        js('document.querySelector(arguments[0]).scrollIntoView({block:"center",behavior:"instant"})',selector)
    def press(selector):show(selector);click(selector)
    def ready():wait_for('return !document.querySelector("[data-geo-cancel]") && !document.querySelector("[data-geo-download=geosite]").disabled',20)
    def settings():
        click('.primary-nav button:last-child');click('[data-settings-section=core]')
        wait_for('return !!document.querySelector("#xray-geo-assets")');js('document.querySelector("#settings-xray").open=true')
        wait_for('return !document.querySelector("[data-geo-source=geosite]").disabled')
    def draft(value,kind='geosite'):
        field='#setting-xray_'+kind+'_url';show(field);fill(field,value)
    def recent_visible(value,kind='geosite'):
        wait_for('return [...document.querySelectorAll("[data-geo-source='+kind+'] option")].some(o=>o.value==='+json.dumps(value)+')')
    def download(n,kind='geosite'):
        value=url(n,kind);draft(value,kind);press('[data-geo-download='+kind+']');ready();poll(lambda:admin()['active']==0);recent_visible(value,kind);return value
    def rejected(name,payload,expected):
        value=json.loads(h['request']('POST',h['base']+'/execute/async',{'script':"const done=arguments[arguments.length-1];window.__TAURI_INTERNALS__.invoke('app_command',{name:arguments[0],payload:arguments[1]}).then(value=>done(JSON.stringify({ok:true,value}))).catch(error=>done(JSON.stringify({ok:false,error})));",'args':[name,payload]}))
        return not value['ok'] and value['error'].get('code')==expected
    def listener():
        stream=socket.socket();stream.bind(('127.0.0.1',0));stream.listen();sockets.append(stream);return stream
    try:
        original=command('settings')['core'];initial=command('snapshot');assert not initial['profiles']
        source=sources();check(len(source['providers'])==4 and source['history']=={'geoip':[],'geosite':[]} and not admin()['requests'],'source suggestions are local, include four original providers and start with separate empty histories')
        check(rejected('xrayGeodataSources',{'extra':True},'geodata_invalid_request'),'source query rejects unknown payload fields')
        with socket.socket() as temp:temp.bind(('127.0.0.1',0));port=temp.getsockname()[1]
        command('preferences',{**initial['preferences'],'language':'en','theme':'dark','connectionMode':'local','inboundPort':port})
        profile=command('saveProfile',{'name':'History main71','kind':'xray-config','groupId':'personal','config':{'outbounds':[{'protocol':'freedom','tag':'direct'}]}})['id']
        command('connect',{'id':profile});before=command('snapshot')
        target=listener();client=socket.create_connection(('127.0.0.1',port),timeout=3);sockets.append(client)
        authority='127.0.0.1:'+str(target.getsockname()[1]);client.sendall(('CONNECT '+authority+' HTTP/1.1\r\nHost: '+authority+'\r\n\r\n').encode())
        peer,_=target.accept();peer.settimeout(3);sockets.append(peer);assert b'200' in client.recv(1024)
        from window_ui import primary
        from native_processes import core_pids
        connection,_,app_pid=primary();connection.close();main_pids=core_pids(app_pid)
        def preserved():
            assert core_pids(app_pid)==main_pids
            current=command('snapshot');assert current['running']==profile and current['since']==before['since']
            client.sendall(b'preserved71');assert peer.recv(11)==b'preserved71'
        h['request']('POST',h['base']+'/window/rect',{'width':1280,'height':900});settings()
        count=len(admin()['requests']);provider=source['providers'][-1]
        show('[data-geo-source=geosite]');select('[data-geo-source=geosite]',provider['geosite'])
        check(js('return document.querySelector("#setting-xray_geosite_url").value')==provider['geosite'] and provider['geosite'].endswith('/dlc.dat') and history()==[] and command('settings')['core']==original and len(admin()['requests'])==count,'choosing the upstream provider changes only the draft, preserving its dlc.dat mapping without a network request')
        for n in range(7):
            download(n)
            check(history()==[url(i) for i in range(n,max(-1,n-5),-1)],'download '+str(n)+' records the five most recent custom GeoSite URLs in order');preserved()
        show('[data-geo-source=geosite]');select('[data-geo-source=geosite]',url(3));press('[data-geo-download=geosite]');ready();poll(lambda:admin()['active']==0)
        check(history()==[url(n) for n in [3,6,5,4,2]] and admin()['requests'][-1]['path']=='/3/geosite.dat','selecting and downloading a recent source promotes it without a duplicate')
        download(99,'geoip')
        check(history('geoip')==[url(99,'geoip')] and history()==[url(n) for n in [3,6,5,4,2]],'GeoIP and GeoSite histories remain independent')
        admin(mode='http-error');download('failed')
        check(history()[0]==url('failed') and js('return !!document.querySelector("#xray-geo-assets [role=alert]")'),'a valid explicit attempt is remembered even when its server returns an error')
        admin(mode='hold');draft(url('cancelled'));press('[data-geo-download=geosite]');poll(lambda:admin()['active']==1)
        check(history()[0]==url('cancelled') and js('return document.querySelector("[data-geo-source=geosite]").disabled'),'an active attempt is remembered and source selection is disabled during download')
        press('[data-geo-cancel=geosite]');ready();admin(release=True,mode='ok');poll(lambda:admin()['active']==0)
        check(history()==[url(n) for n in ['cancelled','failed',3,6,5]],'cancellation keeps the bounded attempted-source history');preserved()
        previous=sources();count=len(admin()['requests']);draft('http://assets.thronium.test/unsafe/geosite.dat');press('[data-geo-download=geosite]');ready()
        check(sources()==previous and len(admin()['requests'])==count,'an invalid URL never enters history or reaches the network')
        token=str(uuid.uuid4());command('cancelXrayGeodataDownload',{'requestId':token})
        check(rejected('downloadXrayGeodata',{'requestId':token,'selection':{'kind':'geosite','url':url('never-dispatched')}},'geodata_request_finished') and sources()==previous,'cancel-before-dispatch does not remember a URL that was never attempted')
        check(command('settings')['core']==original,'all download attempts preserve the separately saved source settings')
        recent_visible(url(3));show('[data-geo-source=geosite]');select('[data-geo-source=geosite]',url(3));press('#settings-save')
        poll(lambda:command('settings')['core']['xray_geosite_url']==url(3))
        check(command('settings')['core']['xray_geoip_url']==url(99,'geoip') and sources()==previous,'normal Save persists both draft sources without changing history order')
        root=Path(command('storageLocation')['directory']);saved=json.loads((root/'library.json').read_text())
        check(saved['settings']['xray_geosite_url_history']==history() and saved['settings']['xray_geoip_url_history']==history('geoip'),'both bounded histories are stored in the library alongside settings for backup and reopen')
        h['request']('POST',h['base']+'/refresh',{});wait_for('return !!document.querySelector(".add-connection")');settings();recent_visible(url('cancelled'))
        check(sources()==previous and js('return document.querySelector("#setting-xray_geosite_url").value')==url(3),'WebView reload restores the saved source and recent choices')
        for language,width in [('en',1280),('ru',390)]:
            command('preferences',{**command('snapshot')['preferences'],'language':language});h['request']('POST',h['base']+'/window/rect',{'width':width,'height':900})
            wait_for('return document.documentElement.lang==='+json.dumps(language)+' && innerWidth==='+str(width))
            show('[data-geo-source=geosite]');wait_for('const r=document.querySelector("[data-geo-source=geosite]").getBoundingClientRect();return r.top>=65&&r.bottom<innerHeight-70')
            text=js('return document.querySelector("[data-geo-source=geosite]").textContent')
            check(('недавний' in text if language=='ru' else 'recent' in text) and js('const r=document.querySelector("[data-geo-source=geosite]").getBoundingClientRect();return r.left>=0&&r.right<=innerWidth&&document.documentElement.scrollWidth<=innerWidth+1'),'editable source and recent URL choices fit '+language+' '+str(width)+'px')
            h['screenshot']('geodata-history-'+language+'-'+str(width))
        preserved();check(True,'source selection, history writes and downloads preserve main Core PID, connection age and held TCP stream')
        audit.update(sources=sources(),mainCorePreserved=True,requestCount=len(admin()['requests']))
    except Exception:
        import traceback;audit['failure']=traceback.format_exc();raise
    finally:
        with contextlib.suppress(Exception):admin(release=True,mode='ok')
        for stream in sockets:
            with contextlib.suppress(OSError):stream.close()
        with contextlib.suppress(Exception):audit['lastLogs']=command('getLogs')
        (h['artifacts']/'geodata-history-audit.json').write_text(json.dumps(audit,indent=2)+'\n')
        with contextlib.suppress(Exception):command('disconnect')
