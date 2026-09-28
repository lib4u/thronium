"""Owned local core crashes, cached-request HTTP and backend cancellation."""
import contextlib
import copy
import http.client
import http.server
import json
import os
from pathlib import Path
import signal
import socket
import time
import threading
from urllib.parse import quote
from Xlib import X,protocol
from external_core_fixture import identity
from native_menu import NativeMenu
from native_processes import core_pids
from window_ui import primary


def run(h):
    command,click,wait_for,js,check=(h[k] for k in ('command','click','wait_for','js','check'))
    root=Path(os.environ['_THRONIUM_RECOVERY_ROOT']);app=Path(h['args'].application).resolve()
    assert root.name.startswith('thronium-core-recovery-native-') and app.parent==root and root.stat().st_mode&0o077==0
    core=root/'ThroniumCore';missing=root/'ThroniumCore.disabled';menu=NativeMenu();app_owner=identity(menu.pid)
    xdg=Path(os.environ['XDG_DATA_HOME']);assert xdg.parent.name.startswith('thronium-native-test-')
    assert Path('/proc',str(menu.pid),'exe').resolve()==app
    initial=command('snapshot');routing=command('routing');audit={'app':app_owner,'kills':[],'recoveries':[],'snapshots':[],'http':[]};exited=False
    class Http(http.server.BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            assert self.path.startswith('/recovery/')
            audit['http'].append(self.path);body=b'OWNED-RECOVERY-OK'
            self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    origin=http.server.ThreadingHTTPServer(('127.0.0.1',0),Http);origin.daemon_threads=True
    threading.Thread(target=origin.serve_forever,daemon=True).start()
    def stored():return (xdg/'io.thronium.desktop/library.json').read_bytes()
    def nodes():
        result=[]
        for pid in core_pids(menu.pid):
            try:
                value=identity(int(pid))
                if value['state'] not in ['Z','X']:result.append(value)
            except OSError:pass
        return result
    def until(predicate,timeout=8):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            value=predicate()
            if value:return value
            time.sleep(.02)
        raise AssertionError('Owned core recovery condition timed out')
    def one():
        values=nodes();assert len(values)==1;return values[0]
    def kill():
        node=one();proc=Path('/proc',str(node['pid']))
        assert node['ppid']==menu.pid and proc.joinpath('exe').resolve() in [core,missing]
        assert b'XDG_DATA_HOME='+str(xdg).encode() in proc.joinpath('environ').read_bytes().split(b'\0')
        fd=os.pidfd_open(node['pid'])
        try:
            assert identity(node['pid'])['starttime']==node['starttime']
            when=time.monotonic();signal.pidfd_send_signal(fd,signal.SIGKILL,None,0)
        finally:os.close(fd)
        until(lambda:not any(v['pid']==node['pid'] and v['starttime']==node['starttime'] for v in nodes()),timeout=3)
        audit['kills'].append({'identity':node,'monotonic':when});return node,when
    def snapshot():
        started=time.monotonic();value=command('snapshot')
        audit['snapshots'].append({'requestMonotonic':started,'responseMonotonic':time.monotonic(),'ownedCores':nodes(),**{k:value[k] for k in ['phase','running','selected','since','trafficAvailable','error','coreAvailable']}});return value
    def pending(id):
        state=snapshot()
        check(state['phase']=='reconnecting' and state['running']==id and state['since'] is None and not state['trafficAvailable'] and not state['connections'], 'confirmed exit retains running intent with no stale time, traffic or connections')
        check(not nodes(), 'synchronous snapshot does not launch a replacement core')
        return state
    def traffic(label,expected=True):
        client=http.client.HTTPConnection('127.0.0.1',inbound,timeout=3)
        try:
            target=f'http://127.0.0.1:{origin.server_port}/recovery/{quote(label,safe="")}'
            client.request('GET',target);response=client.getresponse();ok=response.status==200 and response.read()==b'OWNED-RECOVERY-OK'
        except (OSError,http.client.HTTPException):ok=False
        finally:client.close()
        return ok==expected
    def recovered(old,when,id,label):
        node=until(lambda:next((v for v in nodes() if (v['pid'],v['starttime'])!=(old['pid'],old['starttime'])),None))
        delay=time.monotonic()-when;until(lambda:traffic(label))
        state=until(lambda:(v:=snapshot())['phase']=='connected' and v)
        audit['recoveries'].append({'previous':old,'replacement':node,'observedDelaySeconds':delay})
        check(delay>=.19 and state['running']==id and state['since'] is not None, label+' restores the intended local profile through a new owned process after the delay')
        check(traffic(label+'-again'), label+' carries actual new HTTP requests after restart')
    def save_settings(section,key,value):
        old=command('settings')[section];return command('saveSettings',{'section':section,'previous':old,'values':{**old,key:value}})
    def reset_routes():
        current=command('routing');command('saveRouting',{**current,'active':routing['active'],'profiles':routing['profiles']})
    def terminal(code):return until(lambda:(v:=snapshot())['phase']=='disconnected' and v['error']==code and v)
    def show():
        connection,window,pid=primary();assert pid==menu.pid
        try:
            connection.screen().root.send_event(protocol.event.ClientMessage(window=window,client_type=connection.intern_atom('_NET_ACTIVE_WINDOW'),data=(32,[2,X.CurrentTime,0,0,0])),event_mask=X.SubstructureRedirectMask|X.SubstructureNotifyMask);connection.sync()
        finally:connection.close()
        wait_for('return !document.hidden')
    try:
        command('disconnect');command('preferences',{**initial['preferences'],'language':'en','connectionMode':'local','closeBehavior':'quit'})
        with socket.socket() as reserve:reserve.bind(('127.0.0.1',0));inbound=reserve.getsockname()[1]
        command('preferences',{**command('snapshot')['preferences'],'inboundPort':inbound})
        def add(name,kind,config):return command('saveProfile',{'name':name,'groupId':'personal','kind':kind,'config':config})['id']
        direct=add('Recovery ordinary sing-box','sing-box-outbound',{'type':'direct'})
        other=add('Selected but not running','sing-box-outbound',{'type':'block'})
        variants=[(direct,'sing-box'),(add('Recovery Xray','xray-outbound',{'protocol':'freedom','settings':{}}),'Xray'),(add('Recovery full sing-box','sing-box-config',{'inbounds':[{'type':'mixed','listen':'127.0.0.1','listen_port':inbound}],'outbounds':[{'type':'direct'}]}),'full sing-box'),(add('Recovery full Xray','xray-config',{'outbounds':[{'protocol':'freedom','settings':{}}]}),'full Xray')]
        # Kill a core spawned only for Check: no running profile means no restart.
        command('checkProfile',command('profile',{'id':direct}));idle,_=kill();state=snapshot();time.sleep(1.3)
        check(state['running'] is None and not nodes() and snapshot()['phase']=='disconnected', 'an idle Check-only core exit never automatically launches another process')
        for id,label in variants:
            command('connect',{'id':id});check(traffic(label+'-before'),label+' forwards loopback HTTP before its crash')
            command('select',{'id':other});before=stored();old,when=kill();pending(id);recovered(old,when,id,label)
            check(stored()==before and snapshot()['selected']==other, label+' recovery preserves the complete library and a different selected profile')
        # Save a policy which denies this traffic, plus a newer core setting.
        command('connect',{'id':direct});check(traffic('cached-before'),'cached request fixture starts with an allowed HTTP route')
        old_settings=command('settings')['core'];save_settings('core','singbox_tcp_keep_alive_idle',77)
        current=command('routing');next_route=copy.deepcopy(current);active=next(p for p in next_route['profiles'] if p['id']==next_route['active']);active['rules']=[{'id':'saved-deny','name':'Pending saved rejection','enabled':True,'config':{'network':'tcp','action':'reject'}}]
        command('saveRouting',next_route);command('select',{'id':other});before=stored();check(snapshot()['routing']['pending'],'newly saved routing and settings remain explicitly pending')
        old,when=kill();pending(direct);recovered(old,when,direct,'cached request')
        check(stored()==before and snapshot()['routing']['pending'] and command('settings')['core']['singbox_tcp_keep_alive_idle']==77, 'restart uses the old working request while preserving saved rejection, newer settings and pending state')
        old,_=kill();state=terminal('core_restart_limited');time.sleep(1.3)
        check(not nodes() and state['running'] is None and traffic('rapid-limited',False), 'a second crash within ten seconds stops automatic restart and leaves no listener')
        for language in ['ru','en']:
            command('preferences',{**command('snapshot')['preferences'],'language':language});wait_for('return document.documentElement.lang==='+json.dumps(language))
            wait_for('return document.body.textContent.includes(arguments[0])'.replace('arguments[0]',json.dumps('за 10 с' if language=='ru' else 'within 10 s')))
            h['request']('POST',h['base']+'/window/rect',{'width':390,'height':844});check(js('return document.documentElement.scrollWidth<=innerWidth+1 && !document.querySelector(".power-button").disabled'),language+' rapid-crash message and manual retry fit the narrow window');h['screenshot']('core-recovery-'+language+'-390')
        h['request']('POST',h['base']+'/window/rect',{'width':1280,'height':860})
        command('connect',{'id':direct});check(snapshot()['phase']=='connected' and traffic('new-saved-policy',False), 'manual retry applies the newer saved rejection instead of the old cached request')
        reset_routes();command('connect',{'id':direct});check(traffic('manual-retry'),'explicit retry after restoring saved routes establishes a working session')
        # Disable the real tray and suspend only WebKit's snapshot forwarding.
        save_settings('system','disable_tray',True)
        js('''const original=window.fetch;window.__recoveryPoll={original,suspended:true,queue:[],forwarded:0};window.fetch=function(input,options){let name;try{if(String(input).includes('/app_command'))name=JSON.parse(options?.body||'{}').name}catch{}if(name==='snapshot'){if(window.__recoveryPoll.suspended)return new Promise((resolve,reject)=>window.__recoveryPoll.queue.push({input,options,resolve,reject}));window.__recoveryPoll.forwarded++;}return original.apply(this,arguments);};''')
        click('[data-window-action=minimize]');wait_for('return document.hidden');time.sleep(.25);old,when=kill()
        node=until(lambda:next((v for v in nodes() if v['pid']!=old['pid']),None));until(lambda:traffic('hidden-worker'))
        check(time.monotonic()-when>=.19 and js('return window.__recoveryPoll.forwarded===0') and command('settings')['system']['disable_tray'], 'backend restores actual HTTP with a hidden window, disabled tray icon and suspended WebKit snapshots')
        js('''const state=window.__recoveryPoll;state.suspended=false;window.fetch=state.original;for(const item of state.queue.splice(0))state.original(item.input,item.options).then(item.resolve,item.reject);''');show();check(snapshot()['running']==direct and traffic('shown'),'showing the recovered window does not start another session');save_settings('system','disable_tray',False)
        # A fresh manual connection resets the rapid-exit budget for cancellation.
        command('connect',{'id':direct});old,_=kill();pending(direct);command('disconnect');time.sleep(1.3)
        check(not nodes() and snapshot()['running'] is None and traffic('cancelled',False), 'Disconnect cancels the queued restart before any replacement listener is started')
        command('connect',{'id':direct});core.rename(missing)
        wait_for('return !document.querySelector(".power-button").disabled && document.querySelector(".power-button").getAttribute("aria-pressed")==="true"')
        # Polling must observe actual missing-binary state before the click.
        until(lambda:not snapshot()['coreAvailable']);time.sleep(1.1)
        check(not js('return document.querySelector(".power-button").disabled'), 'Disconnect remains enabled for a live session even when its core executable is missing')
        old,_=kill();pending(direct);click('.power-button');until(lambda:snapshot()['running'] is None);time.sleep(1.3)
        check(not nodes(),'native Disconnect cancels pending recovery while the executable is missing');missing.rename(core)
        command('connect',{'id':direct});core.rename(missing);old,_=kill();pending(direct);state=terminal('core_reconnect_failed');time.sleep(1.3)
        check(not nodes() and state['running'] is None and state['error']=='core_reconnect_failed','missing executable causes one terminal automatic attempt with a safe retry error')
        missing.rename(core);command('connect',{'id':direct});check(traffic('missing-manual-retry'),'restoring only the owned executable allows an explicit successful retry')
        old,_=kill();pending(direct);before=stored();quit_node=menu.ready('Quit');menu.activate(quit_node)
        until(lambda:not Path('/proc',str(menu.pid)).exists(),timeout=8);exited=True;h['closed_session']=True;time.sleep(1.3)
        check(stored()==before and not Path('/proc',str(old['pid'])).exists(), 'Quit cancels pending recovery, exits cleanly and preserves exact library bytes')
    finally:
        # Capture evidence before deliberate cleanup can change a failed state.
        audit['beforeCleanup']={'monotonic':time.monotonic(),'ownedCores':nodes()}
        if not exited:
            with contextlib.suppress(Exception):
                view=command('getLogs')
                audit['lifecycleLogs']=[entry for entry in view['entries'] if entry['source']=='app' and entry['text'].startswith(('Core process exited unexpectedly','Local core recovery','Local core connection restored','Local core exits too frequently'))]
        if missing.exists():missing.rename(core)
        if not exited:
            with contextlib.suppress(Exception):
                js('''if(window.__recoveryPoll){const s=window.__recoveryPoll;window.fetch=s.original;for(const q of s.queue.splice(0))s.original(q.input,q.options).then(q.resolve,q.reject)}''')
                command('disconnect')
        (h['artifacts']/'core-recovery-audit.json').write_text(json.dumps(audit,indent=2)+'\n')
        origin.shutdown();origin.server_close()
