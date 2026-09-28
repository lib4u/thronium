"""Owned core recovery retains a private GNOME lease and restores exact values."""
import contextlib
import copy
import errno
import fcntl
import http.client
import http.server
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time
from urllib.parse import quote,urlsplit
from gi.repository import Gio,GLib
from Xlib import X,protocol
from external_core_fixture import identity
from native_menu import NativeMenu
from native_processes import core_pids
from window_ui import primary


def run(h):
    command,click,wait_for,js,check=(h[k] for k in ('command','click','wait_for','js','check'))
    root=Path(os.environ['_THRONIUM_RECOVERY_ROOT']);app=Path(h['args'].application).resolve()
    assert root.name.startswith('thronium-core-recovery-native-') and app.parent==root and root.stat().st_mode&0o077==0
    config=Path(os.environ['XDG_CONFIG_HOME']);data=Path(os.environ['XDG_DATA_HOME'])
    assert os.environ.get('GSETTINGS_BACKEND')=='keyfile' and config.parent.name.startswith('thronium-native-test-') and data.parent==config.parent
    core=root/'ThroniumCore';missing=root/'ThroniumCore.disabled';menu=NativeMenu();owner=identity(menu.pid)
    assert Path('/proc',str(menu.pid),'exe').resolve()==app
    journal=config/'thronium-system-proxy/recovery.json';lock=journal.with_name('owner.lock')
    audit={'app':owner,'kills':[],'recoveries':[],'snapshots':[],'http':[],'leases':[],'resolver':[]};exited=False
    schemas=[Gio.Settings.new('org.gnome.system.proxy'+('.'+s if s else '')) for s in ('','http','https','socks','ftp')]
    keys=[(s,k) for s in schemas for k in sorted(s.list_keys())]
    def settings():
        while GLib.MainContext.default().pending():GLib.MainContext.default().iteration(False)
        Gio.Settings.sync()
        return [(s.get_value(k).print_(True),s.get_user_value(k).print_(True) if s.get_user_value(k) is not None else None) for s,k in keys]
    def restore(values):
        for (s,k),(_,user) in zip(keys,values):
            if user is None:s.reset(k)
            else:s.set_value(k,GLib.Variant.parse(s.get_value(k).get_type(),user,None,None))
        Gio.Settings.sync()
    initial=command('snapshot');original=settings();routing=command('routing')
    class Http(http.server.BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            assert self.path.startswith('/retained/')
            audit['http'].append(self.path);body=b'RETAINED-PROXY-HTTP'
            self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    origin=http.server.ThreadingHTTPServer(('127.0.0.2',0),Http);origin.daemon_threads=True
    threading.Thread(target=origin.serve_forever,daemon=True).start()
    def until(fn,timeout=10):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            value=fn()
            if value:return value
            time.sleep(.02)
        raise AssertionError('Private system proxy recovery did not settle')
    def nodes():
        result=[]
        for pid in core_pids(menu.pid):
            with contextlib.suppress(OSError):
                node=identity(int(pid))
                if node['state'] not in ['Z','X']:result.append(node)
        return result
    def kill():
        values=nodes();assert len(values)==1;node=values[0];proc=Path('/proc',str(node['pid']))
        assert node['ppid']==menu.pid and proc.joinpath('exe').resolve() in [core,missing]
        assert b'XDG_DATA_HOME='+str(data).encode() in proc.joinpath('environ').read_bytes().split(b'\0')
        fd=os.pidfd_open(node['pid'])
        try:
            assert identity(node['pid'])['starttime']==node['starttime']
            when=time.monotonic();signal.pidfd_send_signal(fd,signal.SIGKILL,None,0)
        finally:os.close(fd)
        until(lambda:not any(n['pid']==node['pid'] and n['starttime']==node['starttime'] for n in nodes()),3)
        audit['kills'].append({'identity':node,'monotonic':when});return node,when
    def snapshot():
        started=time.monotonic();s=command('snapshot')
        audit['snapshots'].append({'requestMonotonic':started,'responseMonotonic':time.monotonic(),'ownedCores':nodes(),**{k:s[k] for k in ['phase','running','selected','since','trafficAvailable','coreAvailable','error','systemProxy']}});return s
    def stored():return (data/'io.thronium.desktop/library.json').read_bytes()
    def leased():
        if not lock.exists():return False
        with lock.open('rb') as f:
            try:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except OSError as e:
                if e.errno in [errno.EAGAIN,errno.EACCES]:return True
                raise
            fcntl.flock(f,fcntl.LOCK_UN);return False
    def lease():
        st=journal.stat();return {'bytes':journal.read_text(),'device':st.st_dev,'inode':st.st_ino,'modifiedNs':st.st_mtime_ns,'size':st.st_size}
    def traffic(label,expected=True):
        target=f'http://127.0.0.2:{origin.server_port}/retained/{quote(label,safe="")}'
        # The long-lived WebDriver client's resolver can retain pre-Connect
        # settings. Match the existing system_proxy_ui fresh-process oracle.
        cached=Gio.ProxyResolver.get_default().lookup(target,None)
        resolved=json.loads(subprocess.check_output([sys.executable,'-c','from gi.repository import Gio; import json,sys; print(json.dumps(Gio.ProxyResolver.get_default().lookup(sys.argv[1],None)))',target],text=True))
        audit['resolver'].append({'label':label,'existingClient':cached,'freshClient':resolved})
        endpoint=urlsplit(resolved[0]);assert endpoint.scheme=='http' and endpoint.hostname=='127.0.0.1' and endpoint.port==port
        client=http.client.HTTPConnection(endpoint.hostname,endpoint.port,timeout=3)
        try:
            client.request('GET',target);response=client.getresponse();ok=response.status==200 and response.read()==b'RETAINED-PROXY-HTTP'
        except (OSError,http.client.HTTPException):ok=False
        finally:client.close()
        return ok==expected
    def pending(id,old_lease,applied):
        s=snapshot()
        check(s['phase']=='reconnecting' and s['running']==id and s['since'] is None and not s['trafficAvailable'] and not nodes(),'pending system-proxy recovery preserves intent without a new listener or stale traffic')
        check(s['systemProxy']['active'] and settings()==applied and lease()==old_lease and leased(),'pending recovery retains the exact original journal and exclusive proxy lease')
    def recovered(old,when,id,old_lease,applied,label):
        replacement=until(lambda:next((n for n in nodes() if (n['pid'],n['starttime'])!=(old['pid'],old['starttime'])),None))
        delay=time.monotonic()-when;until(lambda:traffic(label));s=until(lambda:(v:=snapshot())['phase']=='connected' and v)
        audit['recoveries'].append({'previous':old,'replacement':replacement,'observedDelaySeconds':delay})
        check(delay>=.19 and s['running']==id and s['systemProxy']['active'] and traffic(label+'-again'),label+' restores actual GNOME-resolved HTTP through a new owned process')
        check(lease()==old_lease and leased() and settings()==applied,label+' keeps the original journal bytes, inode, timestamp and proxy values')
    def restored(label):
        until(lambda:settings()==previous)
        check(not journal.exists() and not leased() and not snapshot()['systemProxy']['active'],label+' restores exact prior effective/user values and releases the journal and lock')
    def terminal(code):return until(lambda:(s:=snapshot())['phase']=='disconnected' and s['error']==code and s)
    def reset_routes():
        current=command('routing');command('saveRouting',{**current,'active':routing['active'],'profiles':routing['profiles']})
    def save_system(value):
        old=command('settings')['system'];command('saveSettings',{'section':'system','previous':old,'values':{**old,'disable_tray':value}})
    def show():
        connection,window,pid=primary();assert pid==menu.pid
        try:
            connection.screen().root.send_event(protocol.event.ClientMessage(window=window,client_type=connection.intern_atom('_NET_ACTIVE_WINDOW'),data=(32,[2,X.CurrentTime,0,0,0])),event_mask=X.SubstructureRedirectMask|X.SubstructureNotifyMask);connection.sync()
        finally:connection.close()
        wait_for('return !document.hidden')
    try:
        command('disconnect');check(initial['systemProxy']['available'],'the application detects the private GNOME proxy backend')
        schemas[0].set_string('mode','auto');schemas[0].set_string('autoconfig-url','http://127.0.0.1:9/synthetic-before.pac');schemas[0].set_strv('ignore-hosts',['localhost','127.0.0.1','::1'])
        schemas[1].set_string('host','previous.proxy.test');schemas[1].set_int('port',3128);schemas[1].set_boolean('use-authentication',True)
        schemas[2].reset('host');schemas[2].reset('port');Gio.Settings.sync();previous=settings()
        with socket.socket() as reserve:reserve.bind(('127.0.0.1',0));port=reserve.getsockname()[1]
        command('preferences',{**initial['preferences'],'language':'en','connectionMode':'system-proxy','inboundPort':port,'closeBehavior':'quit'})
        check(settings()==previous and not journal.exists(),'saving system-proxy preferences does not acquire a lease or change GNOME settings')
        def add(name,kind,value):return command('saveProfile',{'name':name,'groupId':'personal','kind':kind,'config':value})['id']
        direct=add('Retained sing-box','sing-box-outbound',{'type':'direct'});other=add('Different selection','sing-box-outbound',{'type':'block'})
        variants=[(direct,'sing-box'),(add('Retained Xray','xray-outbound',{'protocol':'freedom','settings':{}}),'Xray'),(add('Retained full Xray','xray-config',{'outbounds':[{'protocol':'freedom','settings':{}}]}),'full Xray')]
        for id,label in variants:
            command('connect',{'id':id});check(traffic(label+'-before'),label+' starts real HTTP via the GNOME proxy resolver')
            applied=settings();old_lease=lease();audit['leases'].append({'label':label,'journal':old_lease})
            command('select',{'id':other});before=stored();old,when=kill();pending(id,old_lease,applied);recovered(old,when,id,old_lease,applied,label)
            check(stored()==before and snapshot()['selected']==other,label+' preserves a different selected profile and all saved library bytes')
            command('disconnect');restored(label+' Disconnect')
        command('connect',{'id':direct});applied=settings();old_lease=lease()
        state=command('settings')['core'];command('saveSettings',{'section':'core','previous':state,'values':{**state,'singbox_tcp_keep_alive_idle':77}})
        route=copy.deepcopy(command('routing'));active=next(p for p in route['profiles'] if p['id']==route['active']);active['rules']=[{'id':'pending-proxy-deny','name':'Stored rejection','enabled':True,'config':{'network':'tcp','action':'reject'}}];command('saveRouting',route);before=stored()
        old,when=kill();pending(direct,old_lease,applied);recovered(old,when,direct,old_lease,applied,'cached routing')
        check(stored()==before and snapshot()['routing']['pending'] and command('settings')['core']['singbox_tcp_keep_alive_idle']==77,'retained recovery uses the frozen request while newer routing and core settings remain saved and pending')
        old,_=kill();terminal('core_restart_limited');time.sleep(1.2);restored('rapid crash limit')
        check(not nodes(),'rapid crash limit never leaves a replacement core running')
        for language in ['ru','en']:
            command('preferences',{**command('snapshot')['preferences'],'language':language});wait_for('return document.documentElement.lang==='+json.dumps(language))
            h['request']('POST',h['base']+'/window/rect',{'width':390,'height':844})
            check(js('return document.documentElement.scrollWidth<=innerWidth+1 && !document.querySelector(".power-button").disabled'),language+' terminal recovery notice and retry control fit390px');h['screenshot']('system-proxy-recovery-'+language+'-390')
        h['request']('POST',h['base']+'/window/rect',{'width':1280,'height':860});reset_routes()
        command('connect',{'id':direct});check(traffic('manual-retry'),'manual retry acquires a new lease and restores real HTTP after the rapid-exit limit')
        applied=settings();old_lease=lease();save_system(True)
        js('''const original=window.fetch;window.__proxyRecoveryPoll={original,suspended:true,queue:[],forwarded:0};window.fetch=function(input,options){let name;try{if(String(input).includes('/app_command'))name=JSON.parse(options?.body||'{}').name}catch{}if(name==='snapshot'){if(window.__proxyRecoveryPoll.suspended)return new Promise((resolve,reject)=>window.__proxyRecoveryPoll.queue.push({input,options,resolve,reject}));window.__proxyRecoveryPoll.forwarded++;}return original.apply(this,arguments);};''')
        click('[data-window-action=minimize]');wait_for('return document.hidden');time.sleep(.25);old,when=kill()
        until(lambda:next((n for n in nodes() if n['pid']!=old['pid']),None));until(lambda:traffic('hidden-proxy-worker'))
        check(time.monotonic()-when>=.19 and lease()==old_lease and settings()==applied and leased() and command('settings')['system']['disable_tray'] and js('return window.__proxyRecoveryPoll.forwarded===0'),'hidden backend restores HTTP with the exact lease while the tray icon is disabled and WebKit snapshots are suspended')
        command('connect',{'id':direct});core.rename(missing);old,_=kill()
        # Do not request any Engine snapshot until native cleanup has completed.
        until(lambda:settings()==previous and not journal.exists() and not nodes())
        check(not leased() and js('return document.hidden && window.__proxyRecoveryPoll.forwarded===0'),'hidden failed Start restores the original GNOME values and releases ownership without WebKit status polling');missing.rename(core)
        js('''const s=window.__proxyRecoveryPoll;window.fetch=s.original;for(const q of s.queue.splice(0))s.original(q.input,q.options).then(q.resolve,q.reject);''');show();save_system(False)
        # A new manual connection resets the ten-second budget.
        command('connect',{'id':direct});applied=settings();old_lease=lease();old,_=kill();pending(direct,old_lease,applied)
        schemas[1].set_string('host','external.proxy.test');Gio.Settings.sync();external=settings();s=terminal('core_reconnect_failed');time.sleep(1.2)
        check(s['systemProxy']['error']=='system_proxy_changed' and settings()==external and not nodes() and not journal.exists() and not leased(),'external proxy changes during pending are preserved as a whole and stop automatic acquisition or Start')
        command('disconnect');check(settings()==external,'Disconnect after lost ownership leaves all externally changed proxy values untouched');restore(previous)
        command('connect',{'id':direct});applied=settings();old_lease=lease();core.rename(missing)
        until(lambda:not snapshot()['coreAvailable']);old,_=kill();pending(direct,old_lease,applied);terminal('core_reconnect_failed');time.sleep(1.2);restored('missing executable failure')
        check(not nodes(),'failed automatic spawn has no retry loop');missing.rename(core)
        command('connect',{'id':direct});applied=settings();old_lease=lease();old,_=kill();pending(direct,old_lease,applied);command('disconnect');time.sleep(1.2);restored('pending Disconnect')
        check(not nodes(),'Disconnect cancels the queued system-proxy restart')
        command('connect',{'id':direct});applied=settings();old_lease=lease();core.rename(missing);until(lambda:not snapshot()['coreAvailable']);time.sleep(1.1)
        old,_=kill();pending(direct,old_lease,applied);check(not js('return document.querySelector(".power-button").disabled'),'native Disconnect remains enabled during pending with a missing executable');click('.power-button')
        until(lambda:snapshot()['running'] is None);time.sleep(1.2);restored('native missing-core Disconnect');missing.rename(core)
        command('connect',{'id':direct});check(traffic('before-quit'),'the final explicit retry passes HTTP before pending Quit')
        applied=settings();old_lease=lease();old,_=kill();pending(direct,old_lease,applied);before=stored();menu.activate(menu.ready('Quit'))
        until(lambda:not Path('/proc',str(menu.pid)).exists(),8);exited=True;h['closed_session']=True;until(lambda:settings()==previous);time.sleep(1.2)
        check(not journal.exists() and not leased() and not nodes() and stored()==before,'native Quit cancels pending, restores the exact original GNOME values and releases its journal without modifying the library')
    finally:
        audit['beforeCleanup']={'monotonic':time.monotonic(),'ownedCores':nodes(),'journalExists':journal.exists()}
        if missing.exists():missing.rename(core)
        if not exited:
            with contextlib.suppress(Exception):
                js('''if(window.__proxyRecoveryPoll){const s=window.__proxyRecoveryPoll;window.fetch=s.original;for(const q of s.queue.splice(0))s.original(q.input,q.options).then(q.resolve,q.reject)}''')
                command('disconnect')
        restore(original)
        (h['artifacts']/'system-proxy-recovery-audit.json').write_text(json.dumps(audit,indent=2)+'\n')
        origin.shutdown();origin.server_close()
