"""Native HWID: synthetic complete values only, actual loopback subscription GETs."""
import contextlib
import hashlib
import http.server
import json
import os
from pathlib import Path
import socket
import threading
import time

FIELDS=('x-hwid','x-device-os','x-ver-os','x-device-model')
GLOBAL=dict(zip(FIELDS,('hwid-global-fixture','FixtureOS','fixture-version','FixtureModel')))
CUSTOM='hwid=hwid-global-fixture,os=FixtureOS,osVersion=fixture-version,model=FixtureModel'
GROUP={'X-HwId':'hwid-group-fixture','X-DEVICE-OS':'GroupOS','x-Ver-Os':'group-version','X-Device-Model':'GroupModel'}

def run(h):
    command,click,fill,wait_for,js,check,screenshot=(h[k] for k in ('command','click','fill','wait_for','js','check','screenshot'))
    request,base=h['request'],h['base'];initial=command('snapshot');saved_settings=command('settings')['subscriptions'];geometry=request('GET',base+'/window/rect')
    assert 'thronium-native-test-' in os.environ['XDG_DATA_HOME']
    assert not saved_settings['sub_send_hwid'] and not any(g['subscribed'] for g in initial['groups'])
    application=Path(h['args'].application).resolve();assert hashlib.sha256(application.read_bytes()).hexdigest()=='52c465588ad8233af5a7c1d71ceaf380eb9a7927b5a47d19d38aa0fdb88cbdeb'
    received=[];groups=[];sockets=[];main=None;active_since=None;held_checks=0
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self,*_):pass
        def do_GET(self):
            assert self.path in ('/group','/global')
            received.append({'path':self.path,'headers':{k.lower():v for k,v in self.headers.items()}})
            body=('socks://127.0.0.1:19091#HWID%20'+self.path[1:]).encode();self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers()
            with contextlib.suppress(BrokenPipeError,ConnectionResetError):self.wfile.write(body)
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start()
    def until(predicate):
        end=time.monotonic()+15
        while time.monotonic()<end:
            if predicate():return
            time.sleep(.08)
        raise AssertionError('HWID fixture condition timed out')
    def close():click('#main-modal > .modal-head > button');wait_for('return !document.querySelector("dialog[open]")')
    def home():
        click('.primary-nav button:first-child');wait_for('return !!document.querySelector(".group-strip")')
    def settings():
        click('.primary-nav button:last-child');wait_for('return !!document.querySelector("[data-settings-section=subscriptions]")');click('[data-settings-section=subscriptions]');wait_for('return !!document.querySelector("[data-setting=sub_send_hwid]")');js('document.querySelector("[data-setting=sub_send_hwid]").closest("details").open=true')
    def checked(selector,value):
        if js('return document.querySelector(arguments[0]).checked',selector)!=value:click(selector)
    def save():
        click('#settings-save');wait_for('return document.querySelector("#settings-save").disabled && !document.querySelector("[data-navigation-locked=true]")')
    def groups_dialog():home();click('.group-strip .icon-button');wait_for('return !!document.querySelector("#group-new")')
    def members(gid):return [p for p in command('snapshot')['profiles'] if p['groupId']==gid]
    def tunnel(label):
        nonlocal held_checks
        value=('hwid-'+label).encode();client.sendall(value);assert upstream.recv(2048)==value;upstream.sendall(value);assert client.recv(2048)==value
        state=command('snapshot');assert state['running']==main and state['since']==active_since;held_checks+=1
    def manual(gid,expected,agent,label):
        count=len(received);groups_dialog();click('[data-group-update='+json.dumps(gid)+']');wait_for('return !!document.querySelector("#subscription-load")');click('#subscription-load');wait_for('return !!document.querySelector("#subscription-reload")');until(lambda:len(received)>count)
        headers=received[-1]['headers'];check({key:headers[key] for key in FIELDS if key in headers}==expected and headers['user-agent']==agent,label)
        assert not js('return !!document.querySelector(".desktop-inline-error")');tunnel(label);return headers
    try:
        command('preferences',{**initial['preferences'],'language':'en','theme':'dark'});wait_for('return document.documentElement.lang==="en"');request('POST',base+'/window/rect',{'width':1280,'height':900});settings()
        check(not js('return document.querySelector("[data-setting=sub_send_hwid]").checked') and not received,'fresh native settings keep automatic device headers disabled and make no request')
        fill('[data-setting=sub_custom_hwid_params]',CUSTOM);checked('[data-setting=sub_send_hwid]',True)
        check(command('settings')['subscriptions']==saved_settings and not received,'editing all four synthetic device fields does not change saved settings or make requests')
        click('.settings-save .text-button');wait_for('return document.querySelector("#settings-save").disabled && !document.querySelector("[data-navigation-locked=true]")')
        check(not js('return document.querySelector("[data-setting=sub_send_hwid]").checked') and js('return document.querySelector("[data-setting=sub_custom_hwid_params]").value')==saved_settings['sub_custom_hwid_params'],'cancel restores the saved disabled toggle and custom values')
        fill('[data-setting=sub_custom_hwid_params]',CUSTOM);checked('[data-setting=sub_send_hwid]',True);save()
        actual=command('settings')['subscriptions'];check(actual['sub_send_hwid'] and actual['sub_custom_hwid_params']==CUSTOM,'saving HWID stores the exact four explicit synthetic fields')
        request('POST',base+'/refresh',{});wait_for('return !!document.querySelector(".add-connection")');settings()
        check(js('return document.querySelector("[data-setting=sub_send_hwid]").checked') and js('return document.querySelector("[data-setting=sub_custom_hwid_params]").value')==CUSTOM,'saved HWID settings survive a native webview reload')
        for lang in ['en','ru']:
            command('preferences',{**command('snapshot')['preferences'],'language':lang});wait_for('return document.documentElement.lang==='+json.dumps(lang));request('POST',base+'/window/rect',{'width':390,'height':844});js('document.querySelector("[data-setting=sub_send_hwid]").scrollIntoView({block:"center"})')
            text=js('return ["sub_send_hwid","sub_custom_hwid_params"].map(key=>document.querySelector(`[data-setting=${key}]`).closest("label").textContent).join(" ")')
            check(('take priority' in text and 'last nonempty' in text) if lang=='en' else ('имеют приоритет' in text and 'последнее непустое' in text),'HWID explanations describe group priority and empty-value behavior in '+lang)
            check(js('return document.documentElement.scrollWidth<=innerWidth+1'),'HWID settings fit 390 pixels in '+lang);screenshot('subscription-hwid-settings-'+lang)
        request('POST',base+'/window/rect',{'width':1280,'height':900});command('preferences',{**command('snapshot')['preferences'],'language':'en'});wait_for('return document.documentElement.lang==="en"')
        with socket.socket() as available:available.bind(('127.0.0.1',0));port=available.getsockname()[1]
        command('connectionSettings',{'mode':'local','port':port});main=command('saveProfile',{'name':'HWID held local connection','groupId':'personal','kind':'sing-box-outbound','config':{'type':'direct'}})['id'];command('connect',{'id':main});active_since=command('snapshot')['since']
        origin=socket.socket();sockets.append(origin);origin.settimeout(4);origin.bind(('127.0.0.1',0));origin.listen();client=socket.create_connection(('127.0.0.1',port),timeout=4);sockets.append(client);target='127.0.0.1:'+str(origin.getsockname()[1]);client.sendall(f'CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n'.encode());upstream,_=origin.accept();sockets.append(upstream);upstream.settimeout(4);assert b'200' in client.recv(1024);tunnel('start')
        check(True,'a real local HTTP CONNECT is established before subscription HWID tests')
        for name,path,inherit,headers in [('HWID explicit group','/group',False,GROUP),('HWID global defaults','/global',True,{})]:
            groups_dialog();click('#group-new');fill('#group-name',name);click('#group-subscribed');fill('#group-url',f'http://127.0.0.1:{server.server_port}{path}');checked('#group-inherit-settings',inherit);click('.route-advanced summary');fill('#group-headers',json.dumps(headers))
            if not inherit:fill('#group-user-agent','hwid-group-agent')
            click('#group-save');wait_for('return !!document.querySelector("#group-new")');gid=next(g['id'] for g in command('snapshot')['groups'] if g['name']==name);groups.append(gid);close()
            stored=command('group',{'id':gid})['subscription'];check(stored['inheritDefaults']==inherit and stored['headers']==headers,'native group form retains explicit headers and inheritance for '+name)
        group_id,global_id=groups;group_expected={key.lower():value for key,value in GROUP.items()};global_agent=command('settings')['subscriptions']['user_agent']
        manual(group_id,group_expected,'hwid-group-agent','manual update sends the four explicit group headers over global HWID');close()
        manual(global_id,GLOBAL,global_agent,'manual update inherits all four synthetic global fields independently of User-Agent inheritance');close()
        check(not members(group_id) and not members(global_id),'closing both HWID previews leaves group profiles unchanged')
        groups_dialog();click('#subscription-open-jobs');click('#subscription-update-all');wait_for('return document.querySelectorAll("[data-job-status=updated]").length===2',timeout=30);tunnel('queue')
        rows=received[-2:];by_path={row['path']:row['headers'] for row in rows};check({k:by_path['/group'][k] for k in FIELDS}==group_expected and {k:by_path['/global'][k] for k in FIELDS}==GLOBAL,'queued updates use the same explicit-group/global HWID precedence as manual requests')
        check(len(members(group_id))==1 and len(members(global_id))==1,'queue validates and imports both actual subscription responses with the real core')
        check(command('snapshot')['running']==main and held_checks>=4,'manual and queued subscription checks preserve the original core and held TCP connection');screenshot('subscription-hwid-queue-en');close()
        check(command('group',{'id':group_id})['subscription']['headers']==GROUP and command('group',{'id':global_id})['subscription']['headers']=={},'automatic request headers are never persisted into either group')
        snapshot=json.dumps(command('snapshot'));check(all(value not in snapshot for value in list(GLOBAL.values())+list(GROUP.values())),'periodic snapshots omit all synthetic group and device header values')
        settings();checked('[data-setting=sub_send_hwid]',False);save();manual(group_id,group_expected,'hwid-group-agent','turning automatic sending off preserves every explicitly configured group header');close();manual(global_id,{},global_agent,'turning automatic sending off omits all device headers for a group without explicit headers');close()
        settings();fill('[data-setting=sub_custom_hwid_params]',CUSTOM+',HWID=');checked('[data-setting=sub_send_hwid]',True);save();manual(global_id,GLOBAL,global_agent,'a final empty repeated HWID keeps the earlier synthetic nonempty override exactly as Qt');close()
        request('POST',base+'/refresh',{});wait_for('return !!document.querySelector(".add-connection")');tunnel('reloaded');settings()
        check(js('return document.querySelector("[data-setting=sub_custom_hwid_params]").value')==CUSTOM+',HWID=' and command('group',{'id':global_id})['subscription']['headers']=={},'reloading retains custom parser input without promoting generated headers into the group')
        storage=js('return Object.fromEntries(Object.keys(localStorage).map(key=>[key,localStorage.getItem(key)]))')
        check(set(storage)<= {'thronium-library-group'} and all(value not in json.dumps(storage) for value in list(GLOBAL.values())+list(GROUP.values())),'native HWID workflow keeps only the nonsecret library group selection in localStorage')
        checked('[data-setting=sub_send_hwid]',False);save();command('cancelSubscriptionUpdates');command('clearSubscriptionJobs');command('disconnect')
        for gid in groups:command('deleteGroup',{'id':gid,'deleteProfiles':True})
        groups.clear();command('delete',{'id':main});main=None
        current=command('settings')['subscriptions'];command('saveSettings',{'section':'subscriptions','previous':current,'values':saved_settings});command('preferences',initial['preferences'])
        if initial['selected']:command('select',{'id':initial['selected']})
        check(command('settings')['subscriptions']==saved_settings and command('snapshot')['groups']==initial['groups'] and command('snapshot')['profiles']==initial['profiles'] and command('snapshot')['running'] is None,'cleanup restores subscription settings and removes every synthetic group/profile')
        artifact=Path(h['args'].artifacts);(artifact/'hwid-audit.json').write_text(json.dumps({'received':received,'requests':len(received),'heldConnectChecks':held_checks,'allDeviceValuesSynthetic':True,'defaultMachineIdNotRequested':True,'localStorage':storage,'appSHA256':hashlib.sha256(application.read_bytes()).hexdigest(),'coreSHA256':hashlib.sha256(application.with_name('ThroniumCore').read_bytes()).hexdigest()},indent=2)+'\n')
    finally:
        with contextlib.suppress(Exception):
            current=command('settings')['subscriptions'];command('saveSettings',{'section':'subscriptions','previous':current,'values':{**current,'sub_send_hwid':False}});command('cancelSubscriptionUpdates');command('disconnect')
        for sock in sockets:
            with contextlib.suppress(OSError):sock.close()
        server.shutdown();server.server_close()
        with contextlib.suppress(Exception):request('POST',base+'/window/rect',geometry)
