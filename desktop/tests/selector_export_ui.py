"""Explicit selector portable group paths, checked by real loopback proxy traffic."""
import contextlib
import copy
import http.server
import json
import os
from pathlib import Path
import select as network_select
import socket
import socketserver
import threading
import time


def run(h):
    command,click,fill,select,wait_for,js,check,screenshot=(h[k] for k in ('command','click','fill','select','wait_for','js','check','screenshot'))
    initial=command('snapshot');groups=[];owned=[];active=None;servers=[];events=[];lock=threading.Lock()
    geometry=h['request']('GET',h['base']+'/window/rect')

    class Threaded(socketserver.ThreadingTCPServer):
        daemon_threads=True;allow_reuse_address=True
    class Proxy(socketserver.BaseRequestHandler):
        def handle(self):
            with contextlib.suppress(OSError,ValueError):
                self.request.settimeout(5);head=b''
                while b'\r\n\r\n' not in head:
                    part=self.request.recv(4096)
                    if not part or len(head)>16384:return
                    head+=part
                method,authority,_=head.split(b'\r\n',1)[0].decode().split(' ')
                host,port=authority.rsplit(':',1);port=int(port)
                if method!='CONNECT' or host!='127.0.0.1' or port not in allowed_ports:
                    with lock:events.append((self.server.label,'unexpected',authority))
                    return
                with lock:events.append((self.server.label,'connect',port))
                with socket.create_connection((host,port),timeout=5) as remote:
                    self.request.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
                    extra=head.split(b'\r\n\r\n',1)[1]
                    if extra:remote.sendall(extra)
                    while True:
                        ready,_,_=network_select.select([self.request,remote],[],[],.25)
                        for incoming in ready:
                            data=incoming.recv(65536)
                            if not data:return
                            (remote if incoming is self.request else self.request).sendall(data)
    class HTTP(http.server.BaseHTTPRequestHandler):
        def log_message(self,*_):pass
        def do_GET(self):
            self.send_response(204);self.send_header('Content-Length','0');self.end_headers()
    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            with contextlib.suppress(OSError):
                while data:=self.request.recv(65536):self.request.sendall(data)

    def start(server):
        servers.append(server);threading.Thread(target=server.serve_forever,daemon=True).start();return server
    proxies={}
    for label in ['front','member-sb','member-xray','landing','foreign']:
        server=Threaded(('127.0.0.1',0),Proxy);server.label=label;proxies[label]=start(server)
    probe=start(http.server.ThreadingHTTPServer(('127.0.0.1',0),HTTP))
    echo_server=start(Threaded(('127.0.0.1',0),Echo))
    ports={name:s.server_address[1] for name,s in proxies.items()}
    allowed_ports={*ports.values(),probe.server_port,echo_server.server_address[1]}

    def group(name):
        value=command('saveGroup',{'name':name})['id'];groups.append(value);return value
    def add(group_id,name,kind,config):
        value=command('saveProfile',{'groupId':group_id,'name':name,'kind':kind,'config':config})['id'];owned.append(value);return value
    data_root=Path(os.environ['XDG_DATA_HOME']).resolve()
    assert data_root.parent.name.startswith('thronium-native-test-'), 'Library assertions require the runner-owned disposable XDG directory'
    library_path=data_root/'io.thronium.desktop'/'library.json'
    def library():
        return json.loads(library_path.read_text())
    def close():
        click('#main-modal > .modal-head > button');wait_for('return !document.querySelector("dialog[open]")')
    def pool(profile_id,members):
        end=time.monotonic()+15
        while time.monotonic()<end:
            for status in command('getAutoSelectors'):
                if status['profileId']==profile_id and status['membersAlive']==len(members):return status
            time.sleep(.15)
        raise AssertionError('Loopback wrapped pool did not become healthy')
    def tunnel():
        conn=socket.create_connection(('127.0.0.1',local_port),timeout=5)
        authority=f'127.0.0.1:{echo_server.server_address[1]}'
        conn.sendall(f'CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n'.encode())
        headers=b''
        while b'\r\n\r\n' not in headers:
            part=conn.recv(4096);assert part;headers+=part
        assert b' 200 ' in headers.split(b'\r\n',1)[0]
        return conn
    def echo(conn,message):
        body=message.encode();conn.sendall(body);received=b''
        while len(received)<len(body):
            part=conn.recv(65536);assert part;received+=part
        return received==body
    def graph_paths(entries,selector):
        by_ref={p['reference']:p for p in entries}
        def flatten(ref,depth=0):
            assert depth<17
            value=by_ref[ref]
            return [n for hop in value['config']['hops'] for n in flatten(hop,depth+1)] if value['kind']=='chain' else [value['name']]
        return [flatten(ref) for ref in selector['config']['members']]
    def source_row(profile_id,group_id):
        click('.primary-nav button:nth-child(1)')
        wait_for('return !!document.querySelector(".group-strip select") && [...document.querySelector(".group-strip select").options].some(o=>o.value==='+json.dumps(group_id)+')')
        select('.group-strip select',group_id);fill('#client-search','')
        wait_for('return !!document.querySelector('+json.dumps(f'[data-profile-menu="{profile_id}"]')+')')
        js('document.querySelector(arguments[0]).scrollIntoView({block:"center"})',f'[data-profile-menu="{profile_id}"]');time.sleep(.25)
        click(f'[data-profile-menu="{profile_id}"]')

    try:
        command('disconnect')
        with socket.socket() as listener:listener.bind(('127.0.0.1',0));local_port=listener.getsockname()[1]
        command('preferences',{**initial['preferences'],'language':'en','theme':'dark','inboundPort':local_port})
        source,owner,target=group('Explicit export members'),group('Explicit export owner'),group('Portable explicit pool')
        def http_config(label):return {'type':'http','server':'127.0.0.1','server_port':ports[label]}
        front=add(source,'Export front','sing-box-outbound',http_config('front'))
        landing=add(source,'Export landing','sing-box-outbound',http_config('landing'))
        foreign=add(source,'Unrelated foreign wrapper','sing-box-outbound',http_config('foreign'))
        a=add(source,'Export sing-box','sing-box-outbound',http_config('member-sb'))
        b=add(source,'Export Xray','xray-outbound',{'protocol':'http','settings':{'address':'127.0.0.1','port':ports['member-xray']}})
        command('saveGroup',{'id':source,'name':'Explicit export members','proxyChain':{'front':foreign,'landing':foreign}})
        command('saveGroup',{'id':owner,'name':'Explicit export owner','proxyChain':{'front':front,'landing':landing}})
        config={'type':'auto-selector','members':[b,a],'pinned_profile':a,'url':f'http://127.0.0.1:{probe.server_port}/probe','interval':'1s','bench_interval':'2s','watch_interval':'500ms','timeout':'800ms','sampling':2,'expected':2,'active_size':2}
        pid=add(owner,'Explicit wrapped portable pool','auto-selector',config)
        command('connect',{'id':pid});status=pool(pid,[b,a]);active=tunnel()
        check(echo(active,'source-wrapped') and status['pinned'].endswith(a),'source explicit mixed pool forwards loopback traffic with its preferred member')
        before=copy.deepcopy(library());since=command('snapshot')['since']
        source_row(pid,owner);click('#export-one')
        check(not js('return !!document.querySelector("#export-content")'),'native export keeps configuration hidden until reveal')
        click('#export-reveal');wait_for('return !!document.querySelector("#export-content")')
        text=js('return document.querySelector("#export-content").textContent');bundle=json.loads(text)
        entries=bundle['profiles'];exported_pool=next(p for p in entries if p['kind']=='auto-selector')
        check(graph_paths(entries,exported_pool)==[['Export front','Export Xray','Export landing'],['Export front','Export sing-box','Export landing']],'portable explicit pool contains each owner front/member/landing path exactly once in original member order')
        aliases={p['reference'] for p in entries}
        check(len(aliases)==len(entries) and exported_pool['config']['pinned_profile']==exported_pool['config']['members'][1] and all(p not in text for p in owned+[source,owner]),'export uses fresh graph aliases and moves the saved pin to the wrapped member')
        check(not any(p['name']=='Unrelated foreign wrapper' for p in entries) and all(p.get('groupId') is None for p in entries),'member groups and their foreign wrappers do not leak into the portable selector')
        check(library()==before and command('snapshot')['since']==since and echo(active,'export-does-not-restart'),'revealing the complete wrapped export leaves the library, core and held CONNECT unchanged')
        h['request']('POST',h['base']+'/window/rect',{'width':390,'height':844})
        check(js('return document.documentElement.scrollWidth<=innerWidth && document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth'),'portable wrapped selector export fits the narrow native window')
        screenshot('selector-export-narrow-en')
        h['request']('POST',h['base']+'/window/rect',{'width':1280,'height':860})
        close();command('disconnect');active.close();active=None
        click('.add-connection');click('#add-choice-link');fill('#import-source',text);select('#import-group',target);click('#import-review')
        wait_for('return !!document.querySelector("[data-import-check]")')
        buttons=js('return [...document.querySelectorAll("[data-import-check]")].map(e=>e.dataset.importCheck)')
        index=next(i for i,p in enumerate(entries) if p['kind']=='auto-selector');count=len(command('snapshot')['profiles'])
        click('[data-import-check="'+buttons[index]+'"]');wait_for('return !!document.querySelector(".import-valid")')
        check(len(command('snapshot')['profiles'])==count,'real core validates the exported wrapped selector in native import review before saving any profile')
        click('#import-save');wait_for('return !document.querySelector("dialog[open]")')
        imported=[command('profile',{'id':p['id']}) for p in command('snapshot')['profiles'] if p['groupId']==target]
        imported_pool=next(p for p in imported if p['kind']=='auto-selector');new_ids={p['id'] for p in imported};by_id={p['id']:p for p in imported}
        check(set(imported_pool['config']['members'])<new_ids and all(by_id[mid]['kind']=='chain' for mid in imported_pool['config']['members']) and imported_pool['config']['pinned_profile']==imported_pool['config']['members'][1],'atomic native import remaps wrapped chains and pin into the destination group')
        check(not (new_ids & set(owned)) and command('profile',{'id':pid})['config']==config,'portable import allocates fresh profile IDs without changing the source selector configuration')
        command('deleteGroup',{'id':owner,'deleteProfiles':True});groups.remove(owner)
        command('deleteGroup',{'id':source,'deleteProfiles':True});groups.remove(source)
        check(all(p['id'] not in owned for p in command('snapshot')['profiles']),'all original profiles and both source groups can be removed after portable import')
        with lock:events.clear()
        command('connect',{'id':imported_pool['id']});status=pool(imported_pool['id'],imported_pool['config']['members'])
        with tunnel() as conn:check(echo(conn,'portable-source-independent'),'imported wrapped mixed pool forwards real traffic after the entire original graph is deleted')
        check(status['pinned'].endswith(imported_pool['config']['members'][1]) and status['selected'].endswith(imported_pool['config']['members'][1]),'actual core preference and selected member use the imported wrapped-chain reference')
        with lock:captured=list(events)
        destinations=lambda label:{event[2] for event in captured if event[:2]==(label,'connect')}
        check(destinations('front')=={ports['member-sb'],ports['member-xray']} and destinations('member-sb')=={ports['landing']} and destinations('member-xray')=={ports['landing']} and destinations('landing')=={probe.server_port,echo_server.server_address[1]},'actual proxy CONNECT observations prove front to each member to landing to local probe/echo order')
        check(not destinations('foreign') and not any(event[1]=='unexpected' for event in captured),'exported runtime never contacts the unrelated member-group wrapper or a non-loopback destination')
        command('disconnect')
        second=command('exportProfiles',{'ids':[imported_pool['id']],'format':'profiles','destination':'preview'})['text']
        second_bundle=json.loads(second);second_pool=next(p for p in second_bundle['profiles'] if p['kind']=='auto-selector')
        check(graph_paths(second_bundle['profiles'],second_pool)==graph_paths(entries,exported_pool),'re-exporting the imported fixed pool retains each physical wrapper once')
        (Path(h['args'].artifacts)/'selector-export-traffic.json').write_text(json.dumps({'connections':captured,'ports':ports,'probePort':probe.server_port,'echoPort':echo_server.server_address[1],'sourceDeleted':True,'coreChecks':1},indent=2)+'\n')
    finally:
        if active:active.close()
        with contextlib.suppress(Exception):
            if js('return !!document.querySelector("dialog[open]")'):close()
            command('disconnect')
        for group_id in list(reversed(groups)):
            with contextlib.suppress(Exception):command('deleteGroup',{'id':group_id,'deleteProfiles':True})
        command('preferences',initial['preferences'])
        if initial['selected']:command('select',{'id':initial['selected']})
        h['request']('POST',h['base']+'/window/rect',{'width':geometry['width'],'height':geometry['height']})
        for server in servers:server.shutdown();server.server_close()
