"""Actual external launcher, native editor and loopback TCP lifecycle acceptance."""
import base64
import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
import shlex
from select import select as wait_ready
import shutil
import signal
import socket
import socketserver
import struct
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from gi.repository import Gio,GLib
from external_core_fixture import identity
from native_dialogs import file_dialog


def run(h):
    command,click,fill,select,wait_for,js,check,screenshot=(h[k] for k in ('command','click','fill','select','wait_for','js','check','screenshot'))
    initial=command('snapshot');geometry=h['request']('GET',h['base']+'/window/rect')
    assert os.environ.get('_THRONIUM_TEST_BUS'),'Use --external-core-only --private-tray-bus'
    application=Path(h['args'].application).resolve();core=application.with_name('ThroniumCore')
    assert hashlib.sha256(core.read_bytes()).hexdigest()!='2c893cb88a5a2fe4dc807ffa8b4a7cb8635a80e651f9eeb540967a6b097d54cc','External suite requires rebuilt supervised core'
    ids=[];groups=[];connections=[];audit={'launches':[],'checks':[]};baseline_path=None
    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            with contextlib.suppress(OSError):
                while data:=self.request.recv(8192):self.request.sendall(data)
    class Server(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=True
    server=Server(('127.0.0.1',0),Echo);threading.Thread(target=server.serve_forever,daemon=True).start()
    class Hop(socketserver.BaseRequestHandler):
        """The exit of a chain: whatever reaches it came through the program the
        external core profile runs, because that program is what dials it."""
        def handle(self):
            def exact(n):
                value=b''
                while len(value)<n:
                    part=self.request.recv(n-len(value))
                    if not part:raise EOFError()
                    value+=part
                return value
            with contextlib.suppress(OSError,EOFError,ValueError):
                self.request.settimeout(10)
                version,count=exact(2)
                if version!=5 or 0 not in exact(count):return
                self.request.sendall(b'\x05\x00')
                version,kind,_,family=exact(4)
                if version!=5 or kind!=1 or family!=1:return
                host=socket.inet_ntop(socket.AF_INET,exact(4));port_value=struct.unpack('!H',exact(2))[0]
                if host!='127.0.0.1' or port_value!=server.server_address[1]:
                    self.request.sendall(b'\x05\x02\x00\x01'+b'\0'*6);return
                record={'from':self.client_address[0],'port':port_value,'in':0,'out':0};hops.append(record)
                with socket.create_connection((host,port_value),timeout=5) as target:
                    self.request.sendall(b'\x05\x00\x00\x01'+b'\0'*6)
                    while True:
                        readable,_,_=wait_ready([self.request,target],[],[],10)
                        for source in readable or []:
                            data=source.recv(8192)
                            if not data:return
                            record['in' if source is self.request else 'out']+=len(data)
                            (target if source is self.request else self.request).sendall(data)
    hops=[];exit_server=Server(('127.0.0.1',0),Hop);threading.Thread(target=exit_server.serve_forever,daemon=True).start()

    def port():
        with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
    def until(predicate,timeout=10):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            if predicate():return
            time.sleep(.08)
        raise AssertionError('External fixture condition timed out')
    def close():
        click('#main-modal > .modal-head > button')
        if js('return !!document.querySelector("[data-confirm-accept]")'):click('[data-confirm-accept]')
        wait_for('return !document.querySelector("dialog[open]")')
    def library():click('.primary-nav button:first-child');wait_for('return !!document.querySelector(".add-connection")')
    def editor(pid):
        library();selector='[data-profile-menu='+json.dumps(pid)+']'
        wait_for('return !!document.querySelector('+json.dumps(selector)+')');js('document.querySelector(arguments[0]).scrollIntoView({block:"center"})',selector)
        click(selector);click('#menu-edit-profile');wait_for('return !!document.querySelector("#external-core-fields")')
    def chooser(title,path=None):
        try:file_dialog(title,path,opening=True)
        except AssertionError as error:
            if str(error)!='Native file chooser has no visible editable path field':raise
            file_dialog(title,path,opening=True)
    def save(config,name,group='personal'):
        pid=command('saveProfile',{'name':name,'groupId':group,'kind':'external-core','config':config})['id'];ids.append(pid);return pid
    def draft(pid):
        value=command('profile',{'id':pid});return {k:value[k] for k in ['id','name','groupId','kind','config']}
    def rejected(name,payload,code=None):
        try:command(name,payload)
        except RuntimeError as error:
            text=str(error);assert 'synthetic-external-secret' not in text and str(root) not in text,text
            if code:assert code in text,text
            audit['checks'].append({'operation':name,'error':text});return text
        raise AssertionError('Expected external operation rejection: '+name)
    def read_events():return [json.loads(line) for line in marker.read_text().splitlines()] if marker.exists() else []
    def launches():return [v for v in read_events() if v['event']=='launch']
    def current_launch():
        values=launches();assert values;return values[-1]
    def alive(node):
        try:current=identity(node['pid']);return current['starttime']==node['starttime'] and current['state'] not in ['Z','X']
        except (OSError,ValueError):return False
    def gone(node):
        try:return identity(node['pid'])['starttime']!=node['starttime']
        except (OSError,ValueError):return True
    def owned_signal(node,executable):
        assert alive(node)
        process=Path('/proc')/str(node['pid'])
        assert process.joinpath('exe').resolve()==executable.resolve()
        # The identity comes from this run's helper, and the environment proves
        # it belongs to the driver's disposable application scope.
        env=process.joinpath('environ').read_bytes()
        assert any(v.startswith(b'XDG_DATA_HOME=') and b'thronium-native-test-' in v for v in env.split(b'\0'))
        assert identity(node['pid'])['starttime']==node['starttime']
        os.kill(node['pid'],signal.SIGKILL)
    def cleaned(record):
        owner=record['identity']['pid'];nodes=[record['identity'],record['ancestors'][1]]+[v['identity'] for v in read_events() if v['event']=='child' and v['owner']==owner]
        until(lambda:all(gone(n) for n in nodes) and not Path(record['configPath']).exists())
        with socket.socket() as test:test.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);test.bind(('127.0.0.1',record['port']))
        return True
    def native_menu(record):
        candidates=[n for n in record['ancestors'] if (Path('/proc')/str(n['pid'])/'exe').resolve()==application]
        assert len(candidates)==1 and alive(candidates[0]);app_pid=candidates[0]['pid']
        bus=Gio.bus_get_sync(Gio.BusType.SESSION,None)
        def call(service,path,interface,method,signature,args):
            return bus.call_sync(service,path,interface,method,GLib.Variant(signature,args),None,Gio.DBusCallFlags.NONE,2000,None).unpack()
        def find():
            for service in call('org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus','ListNames','()',())[0]:
                if not service.startswith(':'):continue
                try:
                    pid=call('org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus','GetConnectionUnixProcessID','(s)',(service,))[0]
                    if pid!=app_pid:continue
                    paths=['/']
                    for path in paths:
                        xml=ET.fromstring(call(service,path,'org.freedesktop.DBus.Introspectable','Introspect','()',())[0])
                        if any(i.attrib['name']=='com.canonical.dbusmenu' for i in xml.findall('interface')):return service,path
                        paths.extend(path.rstrip('/')+'/'+n.attrib['name'] for n in xml.findall('node'))
                except GLib.Error:continue
        menu=None
        def found():
            nonlocal menu
            menu=find();return menu is not None
        until(found);service,path=menu
        def rows():
            def walk(node):
                yield node
                for child in node[2]:yield from walk(child)
            return list(walk(call(service,path,'com.canonical.dbusmenu','GetLayout','(iias)',(0,-1,[]))[1]))
        def show():
            # A native tray host announces the menu before activating an item.
            call(service,path,'com.canonical.dbusmenu','AboutToShow','(i)',(0,))
            node=next(n for n in rows() if n[1].get('label')=='Open Thronium')
            call(service,path,'com.canonical.dbusmenu','Event','(isvu)',(node[0],'clicked',GLib.Variant('s',''),0))
        def window_state():
            from Xlib import X
            from native_screenshot import connect
            connection=connect()
            try:
                root_window=connection.screen().root;clients=root_window.get_full_property(connection.intern_atom('_NET_CLIENT_LIST'),X.AnyPropertyType)
                result=[]
                for wid in clients.value if clients is not None else []:
                    window=connection.create_resource_object('window',int(wid));owner=window.get_full_property(connection.intern_atom('_NET_WM_PID'),X.AnyPropertyType)
                    if owner is None or int(owner.value[0])!=app_pid:continue
                    state=window.get_full_property(connection.intern_atom('_NET_WM_STATE'),X.AnyPropertyType)
                    result.append({'id':int(wid),'mapped':window.get_attributes().map_state==X.IsViewable,'hidden':state is not None and connection.intern_atom('_NET_WM_STATE_HIDDEN') in state.value,'transient':window.get_wm_transient_for() is not None})
                return result
            finally:connection.close()
        return rows,show,window_state
    def connect_socket():
        s=socket.create_connection(('127.0.0.1',inbound),timeout=5);connections.append(s)
        target='127.0.0.1:'+str(server.server_address[1]);s.sendall(f'CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n'.encode());headers=b''
        while b'\r\n\r\n' not in headers:
            part=s.recv(4096);assert part;headers+=part
        assert b' 200 ' in headers.split(b'\r\n',1)[0];return s
    def echo(s,label):
        value=('external-native-'+label).encode();s.sendall(value);answer=b''
        while len(answer)<len(value):
            part=s.recv(len(value)-len(answer))
            if not part:return False
            answer+=part
        return answer==value
    def backup_page():
        click('.primary-nav button:nth-child(5)');wait_for('return !!document.querySelector("[data-settings-section=backup]")');click('[data-settings-section=backup]');wait_for('return !!document.querySelector("#backup-save")')
    def backup(path):
        # Baseline bookkeeping is not a second native Save-chooser regression.
        # Read only this runner's disposable store; actual Backup Open/Apply
        # remains the cleanup path, and the executable chooser is tested below.
        directory=Path(os.environ['XDG_DATA_HOME']);assert 'thronium-native-test-' in str(directory)
        value=json.loads((directory/'io.thronium.desktop/library.json').read_text())
        path.write_text(json.dumps({'format':'thronium-backup','version':1,'createdAt':int(time.time()),'library':value}))
        return value
    def restore(path):
        backup_page();click('#backup-open');chooser('Open backup',path);wait_for('return !!document.querySelector("#backup-confirm")');click('#backup-acknowledge');click('#backup-confirm');wait_for('return !document.querySelector("dialog[open]")')

    with tempfile.TemporaryDirectory(prefix='thronium-external-native-') as temporary:
        root=Path(temporary);marker=root/'launches.jsonl';helper=root/'owned external helper.py';shutil.copyfile(Path(__file__).with_name('external_core_fixture.py'),helper)
        # Its own file, not the interpreter this test itself runs on: the rule
        # that keeps the external core's traffic out names a program by path.
        executable=root/'owned-external-core';shutil.copyfile(Path('/usr/bin/python3').resolve(),executable);os.chmod(executable,0o755)
        inbound=port();external_port=port()
        literal='$(touch '+str(root/'must-not-exist')+') $HOME %d'
        args=' '.join(shlex.quote(v) for v in [str(helper),'--config','%s','--literal','quoted spaces','--literal','','--literal',literal])
        def config(mode='ready',child=False,port_value=None,echo_port=None):
            content={'marker':str(marker),'port':port_value or external_port,'echoPort':echo_port or server.server_address[1],'mode':mode,'child':child,'secret':'synthetic-external-secret'}
            raw=' \n'+json.dumps(content,ensure_ascii=False,indent=2)+'\n\t '
            return {'type':'extracore','socks_address':'127.0.0.1','socks_port':port_value or external_port,'extra_core_path':str(executable),'extra_core_args':args,'extra_core_conf':raw,'no_logs':True}
        normal=config();empty={**normal,'extra_core_args':'','extra_core_conf':''}
        try:
            command('disconnect');command('preferences',{**initial['preferences'],'language':'en','theme':'dark'});wait_for('return document.documentElement.lang==="en"')
            baseline_path=root/'baseline.json';baseline=backup(baseline_path)
            command('connectionSettings',{'mode':'local','port':inbound});library()
            click('.add-connection');click('#add-choice-advanced');select('#profile-type','extracore');fill('#profile-name','Native external 日本')
            check(js('return document.querySelector("#external-core-path").value==="" && document.querySelector("#external-core-no-logs").value==="true"') and not marker.exists(),'new external editor starts with explicit launch fields and does not execute a program')
            click('#external-core-choose');chooser('Choose core executable');wait_for('return !document.querySelector("#external-core-choose").disabled')
            check(js('return document.querySelector("#external-core-path").value===""') and not marker.exists(),'cancelling native executable chooser retains the editor and launches nothing')
            click('#external-core-choose');chooser('Choose core executable',executable);wait_for('return document.querySelector("#external-core-path").value==='+json.dumps(str(executable)))
            check(not marker.exists(),'native chooser selects the canonical executable without running it')
            fill('#external-core-socks-port',str(external_port));fill('#external-core-args',args);fill('#external-core-config',normal['extra_core_conf']);select('#external-core-no-logs','true')
            for language in ['en','ru']:
                command('preferences',{**command('snapshot')['preferences'],'language':language});wait_for('return document.documentElement.lang==='+json.dumps(language));h['request']('POST',h['base']+'/window/rect',{'width':390,'height':844})
                check(js('const d=document.querySelector("dialog"),b=d.querySelector(".modal-body");return b.scrollWidth<=b.clientWidth+1&&d.querySelector(".modal-footer").getBoundingClientRect().bottom<=innerHeight+1&&document.querySelector("#external-core-config").value===arguments[0]',normal['extra_core_conf']),'external editor and exact configuration fit '+language+' at 390 pixels');screenshot('external-editor-'+language)
            command('preferences',{**command('snapshot')['preferences'],'language':'en'});wait_for('return document.documentElement.lang==="en"');h['request']('POST',h['base']+'/window/rect',geometry)
            click('button[form=profile-editor]');wait_for('return !document.querySelector("dialog[open]")')
            selected=[p for p in command('snapshot')['profiles'] if p['name']=='Native external 日本'];assert len(selected)==1;pid=selected[0]['id'];ids.append(pid)
            check(command('profile',{'id':pid})['config']==normal and not marker.exists(),'native save preserves complete opaque config whitespace and argv without executing it')
            editor(pid);check(js('return [document.querySelector("#external-core-args").value,document.querySelector("#external-core-config").value]')==[args,normal['extra_core_conf']],'reopening the actual editor preserves both exact raw text fields')
            click('.modal-footer .button.secondary');wait_for('return !!document.querySelector(".desktop-success")')
            check(not marker.exists() and 'when connecting' in js('return document.querySelector(".desktop-success").textContent').lower(),'Check executes no program and separates static launch validation from readiness at connection');close()
            empty_id=save(empty,'Empty args preserved');command('checkProfile',draft(empty_id));check(command('profile',{'id':empty_id})['config']==empty and not marker.exists(),'empty arguments and empty config survive save and static Check without launching Python')
            preview=command('connectionConfiguration',{'id':pid});check(any(p['name']=='external-core' and p['config']['extra_core_conf']==normal['extra_core_conf'] for p in preview['parts']) and not marker.exists(),'runtime preview includes original external launch data and executes nothing')
            library();click('.add-connection');click('#add-choice-link');fill('#import-source',json.dumps(normal));click('#import-review');wait_for('return !!document.querySelector("#import-save")');click('#import-save');wait_for('return !document.querySelector("dialog[open]")')
            imported=[p['id'] for p in command('snapshot')['profiles'] if p['id'] not in ids and p['id'] not in [i['id'] for i in initial['profiles']]];ids.extend(imported)
            check(len(imported)==1 and command('profile',{'id':imported[0]})['config']==normal and not marker.exists(),'native JSON import preserves external type and launch data while executing nothing')
            h['request']('POST',h['base']+'/refresh',{});wait_for('return !!document.querySelector(".add-connection")');check(command('profile',{'id':pid})['config']==normal and not marker.exists(),'external profile survives native webview reload without background launch')

            command('startUrlTests',{'ids':[pid],'url':'http://127.0.0.1:'+str(server.server_address[1])+'/not-requested','timeoutMs':1000})
            until(lambda:command('snapshot')['urlTests']['entries'][0]['status']=='unsupported')
            check(not marker.exists(),'URL probe explicitly reports external profiles unsupported without executing their program');command('clearUrlTests')

            command('connect',{'id':pid});first=current_launch();until(lambda:command('snapshot')['running']==pid);held=connect_socket()
            check(echo(held,'first') and any(e['event']=='connect' and e['owner']==first['identity']['pid'] for e in read_events()),'Connect waits for the owned SOCKS5 and real HTTP CONNECT carries loopback payload through that process')
            check(first['configSha256']==hashlib.sha256(normal['extra_core_conf'].encode()).hexdigest() and first['configMode']==0o600 and first['literals']==['quoted spaces','',literal] and not (root/'must-not-exist').exists(),'runtime receives exact config bytes at 0600 and quoted argv including empty and literal shell tokens')
            check('synthetic-external-secret' not in json.dumps(command('snapshot')) and str(helper) not in json.dumps(command('snapshot')),'periodic status excludes external configuration and executable path')
            editor(pid);wait_for('return !!document.querySelector("#editor-running-note")');check(js('return document.querySelector("button[form=profile-editor]").disabled && !!document.querySelector("#editor-running-note")') and echo(held,'editor'),'active external editor refuses edits while retaining the existing TCP tunnel');close()
            rejected('saveProfile',{**draft(pid),'expectedRevision':command('profile',{'id':pid})['expectedRevision'],'name':'Forbidden active edit'},'stop_before_editing');rejected('delete',{'id':pid},'stop_before_editing');check(echo(held,'mutation-refusals'),'backend edit and delete refusals preserve the active owned socket')

            malformed=save({**normal,'extra_core_args':'"unterminated'},'Invalid launch args')
            rejected('connect',{'id':malformed},'external_core_arguments_invalid');check(command('snapshot')['running']==pid and echo(held,'args-refusal') and len(launches())==1,'invalid argv is rejected before interrupting the old connection or spawning a candidate')
            with socket.socket() as foreign:
                foreign.bind(('127.0.0.1',0));foreign.listen();busy=save(config(port_value=foreign.getsockname()[1]),'Foreign occupied port')
                rejected('connect',{'id':busy},'external_core_port_busy');check(command('snapshot')['running']==pid and echo(held,'foreign-port') and len(launches())==1,'foreign occupied SOCKS port is rejected before stopping the old socket or using another process')
                probe=socket.create_connection(foreign.getsockname(),timeout=2);accepted,_=foreign.accept();probe.close();accepted.close();check(foreign.fileno()>=0,'foreign listener remains alive and untouched after preflight refusal')
            failed=save(config('exit',port_value=port()),'Failing foreground candidate')
            rejected('connect',{'id':failed},'connection_restored');until(lambda:command('snapshot')['running']==pid);restored=current_launch();after=connect_socket()
            check(restored['identity']['pid']!=first['identity']['pid'] and echo(after,'restored'),'candidate runtime exit restores the former external profile with a fresh owned process and working new traffic')
            failed_records=[v for v in launches() if v['mode']=='exit'];check(len(failed_records)==1 and cleaned(failed_records[0]) and not Path(first['configPath']).exists(),'failed candidate and replaced former launch clean their private temporary configurations')
            command('disconnect');check(cleaned(restored) and command('snapshot')['running'] is None,'Disconnect removes the external process, listener and temporary configuration')
            command('connect',{'id':pid});second=current_launch();another=connect_socket();check(second['configPath']!=restored['configPath'] and echo(another,'reconnect'),'reconnect creates a fresh temporary config and restores real traffic')
            rows,show,window_state=native_menu(second);until(lambda:any(n[1].get('label','').startswith('Connected:') for n in rows()))
            js('''const original=window.fetch;const state=window.__externalPoll={original,count:0,pending:0,hold:false,queued:[],blocked:0};window.fetch=function(input,options){let snapshot=false;try{snapshot=String(input).includes('/app_command')&&JSON.parse(options?.body||'{}').name==='snapshot';}catch{}if(!snapshot)return original.apply(this,arguments);const context=this,args=arguments,forward=()=>{state.count++;state.pending++;return original.apply(context,args).finally(()=>state.pending--)};if(state.hold){state.blocked++;return new Promise((resolve,reject)=>state.queued.push(()=>forward().then(resolve,reject)));}return forward();};''')
            click('[data-window-action="minimize"]');wait_for('return document.hidden');js('window.__externalPoll.hold=true');wait_for('return window.__externalPoll.pending===0');polls=js('return window.__externalPoll.count')
            owned_signal(second['identity'],executable)
            # Read only native D-Bus here: invoking snapshot would itself observe
            # the dead helper and mask a broken background lifecycle observer.
            until(lambda:any(n[1].get('label')=='Disconnected' for n in rows()))
            audit['rendererSuspension']={'hidden':js('return document.hidden'),'forwardedBefore':polls,'forwardedAfter':js('return window.__externalPoll.count'),'blockedRequests':js('return window.__externalPoll.blocked'),'pending':js('return window.__externalPoll.pending')}
            check(cleaned(second) and audit['rendererSuspension']['hidden'] and audit['rendererSuspension']['forwardedAfter']==polls,'hidden-window helper exit clears native DBusMenu and owned resources while WebKit snapshot requests are held')
            audit['beforeNativeShow']={'windows':window_state(),'menu':rows()};show()
            try:wait_for('return !document.hidden')
            except AssertionError:
                audit['nativeShowFailure']={'windows':window_state(),'menu':rows(),'hidden':js('return document.hidden'),'polls':js('return window.__externalPoll.count')};raise
            js('const s=window.__externalPoll;s.hold=false;window.fetch=s.original;for(const resume of s.queued)resume();delete window.__externalPoll;')
            check(command('snapshot')['running'] is None and command('snapshot')['error'] in ['external_process_failed','external_core_exited','core_error'],'showing the window reflects background external failure and does not reconnect it')

            tree_config=config(child=True);tree_id=save(tree_config,'Owned descendant cleanup');command('connect',{'id':tree_id});tree=current_launch();tree_socket=connect_socket();assert echo(tree_socket,'core-kill-before')
            until(lambda:any(v['event']=='child' and v['owner']==tree['identity']['pid'] for v in read_events()))
            owned_core=[node for node in tree['ancestors'][2:] if (Path('/proc')/str(node['pid'])/'exe').resolve()==core]
            assert len(owned_core)==1;owned_signal(owned_core[0],core);until(lambda:command('snapshot')['running'] is None)
            check(cleaned(tree),'SIGKILL of the verified disposable core removes its external helper, stubborn owned child, port and temp config')
            command('connect',{'id':pid});last=current_launch();check(echo(connect_socket(),'after-core-kill'),'a new managed core can reconnect the external profile after the old core is killed');command('disconnect');assert cleaned(last)

            # Qt's own compositions: a tunnel accepts an external core, and a
            # chain may dial one as its first hop.
            before_count=len(launches());command('connectionSettings',{'mode':'tun','port':inbound});command('checkProfile',draft(pid))
            check(len(launches())==before_count and command('snapshot')['running'] is None,'a tunnel accepts an external core, and validating it starts no program')
            command('connectionSettings',{'mode':'system-proxy','port':inbound});command('connect',{'id':pid});proxied=current_launch();until(lambda:command('snapshot')['systemProxy']['active'])
            check(echo(connect_socket(),'system-proxy') and command('snapshot')['running']==pid,'an external core carries actual traffic while the system proxy points at the window')
            command('disconnect');until(lambda:not command('snapshot')['systemProxy']['active'])
            check(cleaned(proxied),'leaving the system proxy releases both the proxy and the program it started')
            command('connectionSettings',{'mode':'local','port':inbound})
            # WARP is what gives such a connection its UDP: it wraps the socks
            # server of the external core instead of replacing it.
            intercept=command('settings')['intercept']
            command('saveSettings',{'section':'intercept','previous':intercept,'values':{**intercept,'enable_warp':True,
                'warp_private_key':base64.b64encode(bytes(range(32))).decode(),'warp_public_key':base64.b64encode(bytes(range(32,64))).decode(),
                'warp_ep':'127.0.0.1:2408','warp_ifc_addrs':['10.66.0.2/32']}})
            wrapped=next(p for p in command('connectionConfiguration',{'id':pid})['parts'] if p['name']!='external-core')['config']
            endpoint=next(e for e in wrapped['endpoints'] if e['tag']=='proxy')
            bypass=next(o for o in wrapped['outbounds'] if o['tag']==endpoint['detour'])
            check(endpoint['type']=='wireguard' and bypass['type']=='socks' and bypass['server_port']==external_port,'WARP dials through the external core instead of replacing it: '+json.dumps({'endpoint':endpoint['tag'],'detour':endpoint['detour']}))
            command('saveSettings',{'section':'intercept','previous':command('settings')['intercept'],'values':intercept})
            plain=next(p for p in command('connectionConfiguration',{'id':pid})['parts'] if p['name']!='external-core')['config']
            check(not command('settings')['intercept']['enable_warp'] and not plain.get('endpoints') and any(o['tag']=='proxy' and o['server_port']==external_port for o in plain['outbounds']),'turning WARP off leaves the external core dialled on its own again')
            before_count=len(launches())
            rejected('saveProfile',{'name':'Unsupported auto-selector','groupId':'personal','kind':'auto-selector','config':{'type':'auto-selector','members':[pid]}})
            exit_id=command('saveProfile',{'name':'Chain exit','groupId':'personal','kind':'sing-box-outbound','config':{'type':'socks','server':'127.0.0.1','server_port':exit_server.server_address[1]}})['id'];ids.append(exit_id)
            rejected('saveProfile',{'name':'External behind a hop','groupId':'personal','kind':'chain','config':{'type':'chain','hops':[exit_id,pid]}},'external_chain_position')
            check(len(launches())==before_count,'an external core that nothing could reach is refused before any program starts')
            chain_external=save(config(port_value=port(),echo_port=exit_server.server_address[1]),'Chain external core')
            chained=command('saveProfile',{'name':'External first','groupId':'personal','kind':'chain','config':{'type':'chain','hops':[chain_external,exit_id]}})['id'];ids.append(chained)
            command('connect',{'id':chained});chain_launch=current_launch();until(lambda:command('snapshot')['running']==chained)
            (Path(h['args'].artifacts)/'chain-config.json').write_text(json.dumps(command('connectionConfiguration',{'id':chained}),indent=2))
            chain_socket=connect_socket();carried=echo(chain_socket,'chain')
            check(carried,'a chain whose first hop is the external core carries actual traffic to the fixture: hops='+json.dumps(hops)+' events='+json.dumps([v for v in read_events() if v['event']=='connect'][-3:])+' log='+json.dumps([v.get('text') or v.get('code') for v in command('getLogs',{})['entries'][-14:]]))
            check(any(v['event']=='connect' and v['owner']==chain_launch['identity']['pid'] and v['port']==exit_server.server_address[1] for v in read_events()) and hops,'the chain goes through the program the person runs: that process dialled the next hop')
            sing=next(p for p in command('connectionConfiguration',{'id':chained})['parts'] if p['name']!='external-core')
            check(any(rule.get('outbound')=='direct' and str(executable) in json.dumps(rule.get('process_path')) for rule in sing['config']['route']['rules']) and any(str(executable) in json.dumps(rule.get('process_path')) and rule.get('server')=='dns-direct' for rule in sing['config']['dns']['rules']),'the configuration keeps the external core\'s own traffic and its names outside the connection it feeds')
            command('disconnect');check(cleaned(chain_launch) and command('snapshot')['running'] is None,'disconnecting the chain removes the program it started')
            before_count=len(launches());group=command('saveGroup',{'name':'Wrapped external','proxyChain':{'front':None,'landing':None}})['id'];groups.append(group)
            ordinary=command('saveProfile',{'name':'Group front','groupId':'personal','kind':'sing-box-outbound','config':{'type':'socks','server':'127.0.0.1','server_port':9}})['id'];ids.append(ordinary)
            grouped=save(normal,'Group wrapped external',group);command('saveGroup',{'id':group,'name':'Wrapped external','proxyChain':{'front':ordinary,'landing':None}})
            rejected('connect',{'id':grouped},'external_chain_unsupported');check(len(launches())==before_count,'unsupported containing-group proxy wrappers are rejected before starting any external program')
            command('preferences',{**command('snapshot')['preferences'],'language':'en'});wait_for('return document.documentElement.lang==="en"');restore(baseline_path)
            check(backup(root/'final.json')==baseline and all(gone(v['identity']) and gone(v['ancestors'][1]) and not Path(v['configPath']).exists() for v in launches()),'exact baseline backup restore removes all external fixtures and leaves no owned launcher or temporary config')
            audit.update({'launches':read_events(),'sourceConfigSha256':hashlib.sha256(normal['extra_core_conf'].encode()).hexdigest(),'allLoopback':True,'baselineRestored':True,'applicationSha256':hashlib.sha256(application.read_bytes()).hexdigest(),'coreSha256':hashlib.sha256(core.read_bytes()).hexdigest()})
        finally:
            for sock in connections:
                with contextlib.suppress(OSError):sock.close()
            with contextlib.suppress(Exception):
                js('if(window.__externalPoll){const s=window.__externalPoll;s.hold=false;window.fetch=s.original;for(const resume of s.queued)resume();delete window.__externalPoll;}')
                if js('return !!document.querySelector("dialog[open]")'):close()
                command('disconnect');command('preferences',{**command('snapshot')['preferences'],'language':'en'});wait_for('return document.documentElement.lang==="en"')
                if baseline_path and baseline_path.exists() and not audit.get('baselineRestored'):restore(baseline_path)
                command('preferences',initial['preferences']);library();h['request']('POST',h['base']+'/window/rect',geometry)
            audit['launches']=read_events()
            (Path(h['args'].artifacts)/'external-core-audit.json').write_text(json.dumps(audit,ensure_ascii=False,indent=2)+'\n')
            server.shutdown();server.server_close();exit_server.shutdown();exit_server.server_close()
