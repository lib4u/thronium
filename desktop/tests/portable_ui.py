"""Actual isolated launches with distinct and moved data directories."""
import contextlib
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import threading
import time


def run(h):
    command, js, check, wait_for, click = (h[k] for k in ('command','js','check','wait_for','click'))
    root=Path(os.environ['_THRONIUM_PORTABLE_ROOT']);root.mkdir(parents=True,exist_ok=True)
    assert str(root).startswith('/run/thronium-portable63/') and 'thronium-native-test-' in os.environ['XDG_DATA_HOME']
    original=Path(h['args'].application).resolve();known={original};current=original
    data=Path(os.environ['XDG_DATA_HOME']);standard=data/'io.thronium.desktop';audit={'locations':[],'launches':[]};children=[]
    def pids(binary=None):
        result=[]
        for proc in Path('/proc').iterdir():
            if proc.name.isdigit():
                with contextlib.suppress(OSError):
                    exe=(proc/'exe').resolve()
                    if exe in ({binary} if binary else known):result.append(int(proc.name))
        return sorted(result)
    def poll(predicate,timeout=12):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            if predicate():return
            time.sleep(.05)
        raise AssertionError('Portable launch state timed out')
    def close():
        if not h['closed_session']:
            old=pids();h['request']('DELETE',h['base']);h['closed_session']=True
            poll(lambda:not any(Path('/proc',str(pid),'exe').exists() for pid in old))
    def launch(binary,arguments=(),error=None):
        nonlocal current
        close();binary=Path(binary).resolve();known.add(binary);current=binary
        session=h['request']('POST','/session',{'capabilities':{'alwaysMatch':{'tauri:options':{'application':str(binary),'args':list(arguments)}}}})['sessionId']
        h['session']=session;h['base']='/session/'+session;h['closed_session']=False
        wait_for('return !!document.querySelector(".add-connection")')
        location=command('storageLocation');audit['locations'].append(location)
        if error:
            assert location['mode']=='error' and location['error']==error
            wait_for('return !!document.querySelector(".desktop-error[role=alert]")')
            assert error not in js('return document.querySelector(".desktop-error").textContent'), 'storage error must be translated'
        else:assert location['error'] is None
        return location
    def save(section,**values):
        old=command('settings')[section];return command('saveSettings',{'section':section,'previous':old,'values':{**old,**values}})
    def port():
        with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
    def copy_to(directory):
        directory.mkdir(parents=True)
        for name in ['Thronium','ThroniumCore']:shutil.copy2(original.with_name(name),directory/name)
        assert hashlib.sha256((directory/'Thronium').read_bytes()).hexdigest()==hashlib.sha256(original.read_bytes()).hexdigest()
        known.add((directory/'Thronium').resolve());return directory/'Thronium'
    def create_profile(name):return command('saveProfile',{'name':name,'groupId':'personal','kind':'sing-box-outbound','config':{'type':'direct'}})['id']
    def configure():
        old=command('snapshot')['preferences'];local=port();command('preferences',{**old,'language':'en','theme':'dark','connectionMode':'local','inboundPort':local,'closeBehavior':'quit'});return local
    def secondary(binary,args=(),cwd=None):
        child=subprocess.Popen([str(binary),*args],cwd=cwd,stdout=subprocess.PIPE,stderr=subprocess.PIPE);children.append(child)
        stdout,stderr=child.communicate(timeout=15);assert child.returncode==0,(child.returncode,stderr[-200:].decode(errors='replace'))
        audit['launches'].append({'secondaryExit':child.returncode,'outputBytes':len(stdout)+len(stderr)})
    class HTTP(http.server.BaseHTTPRequestHandler):
        def log_message(self,*_):pass
        def do_GET(self):
            body=b'owned portable connection63';self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),HTTP);thread=threading.Thread(target=server.serve_forever);thread.start()
    def real_http(local):
        value=subprocess.check_output(['curl','--fail','--silent','--show-error','--max-time','5','--noproxy','','--proxy','socks5h://127.0.0.1:'+str(local),'http://127.0.0.1:'+str(server.server_port)+'/owned'],timeout=8)
        return value==b'owned portable connection63'
    try:
        first=command('storageLocation');check(first=={'mode':'system','directory':str(standard.resolve()),'error':None},'default launch retains the standard library directory')
        default_id=create_profile('Default library63');js("localStorage.setItem('owned-storage63','system63')");close();default_bytes=(standard/'library.json').read_bytes()
        launch(original,['--data-dir',str(standard)])
        check(any(p['id']==default_id for p in command('snapshot')['profiles']) and js("return localStorage.getItem('owned-storage63')")== 'system63','explicitly selecting the standard directory preserves the same browser store and library')
        close()
        portable_app=copy_to(root/'portable app')
        location=launch(portable_app,['--portable']);portable=portable_app.parent/'thronium-data'
        check(location['mode']=='portable' and Path(location['directory'])==portable and command('snapshot')['profiles']==[] and js("return localStorage.getItem('owned-storage63')") is None,'portable launch creates its own adjacent library and independent browser storage')
        local=configure();profile=create_profile('Portable library63');js("localStorage.setItem('owned-storage63','portable63')")
        h['request']('POST',h['base']+'/window/rect',{'width':930,'height':740});poll(lambda:(portable/'window-state.json').exists() and json.loads((portable/'window-state.json').read_text())['width']==930 and json.loads((portable/'window-state.json').read_text())['height']==740)
        command('connect',{'id':profile});check(real_http(local),'portable library connects through the actual adjacent Core and forwards owned HTTP')
        command('disconnect');audit['geometryBeforeClose']=json.loads((portable/'window-state.json').read_text());close();audit['geometryAfterClose']=json.loads((portable/'window-state.json').read_text());check((portable/'library.json').exists() and (portable/'localstorage').is_dir() and (standard/'library.json').read_bytes()==default_bytes,'portable writes stay with the selected directory and preserve the default library')
        launch(portable_app);check(any(p['id']==profile for p in command('snapshot')['profiles']) and js("return localStorage.getItem('owned-storage63')")== 'portable63','portable profile and browser state survive an application restart')
        rect=h['request']('GET',h['base']+'/window/rect');audit['reopenedGeometry']={'webdriver':rect,'saved':json.loads((portable/'window-state.json').read_text())};check(abs(rect['width']-930)<=2 and abs(rect['height']-740)<=2,'window geometry is restored from the portable directory')
        save('system',autostart=True)
        portable_entry=Path(os.environ['XDG_CONFIG_HOME'])/'autostart/io.thronium.desktop.desktop';portable_primary=pids()
        subprocess.run(['gio','launch',str(portable_entry)],check=True,timeout=15,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        poll(lambda:pids()==portable_primary)
        check('--portable' in portable_entry.read_text() and '--data-dir' not in portable_entry.read_text(),'portable autostart retains the relative-to-executable storage mode')
        close();moved=root/'moved app';portable_app.parent.rename(moved);portable_app=moved/'Thronium';portable=moved/'thronium-data';known.add(portable_app.resolve())
        location=launch(portable_app);check(Path(location['directory'])==portable and any(p['id']==profile for p in command('snapshot')['profiles']) and js("return localStorage.getItem('owned-storage63')")== 'portable63','moving the complete portable folder preserves profiles and browser state at the new location')
        local=configure();command('connect',{'id':profile});check(real_http(local),'the moved portable executable still uses its adjacent Core for real traffic');command('disconnect')
        poll(lambda:str(moved) in portable_entry.read_text())
        check('--portable' in portable_entry.read_text(),'a moved portable launch refreshes its enabled autostart executable without pinning the old data path');save('system',autostart=False)
        marker=portable/'portable-mode';valid_marker=marker.read_bytes();close();marker.write_bytes(b'owned invalid marker')
        launch(portable_app,(), 'storage_portable_marker_invalid');check((standard/'library.json').read_bytes()==default_bytes,'invalid portable marker reports an error without falling back to the standard library');close();marker.write_bytes(valid_marker)
        launch(portable_app,['-appdata']);check(command('storageLocation')['mode']=='system' and any(p['id']==default_id for p in command('snapshot')['profiles']),'explicit -appdata overrides an adjacent portable marker and opens the original standard library')
        custom=root/'custom space quote" dollar$ back` percent% slash\\ папка'
        location=launch(original,['--data-dir',os.path.relpath(custom,Path.cwd())]);check(location['mode']=='custom' and Path(location['directory'])==custom and command('snapshot')['profiles']==[] and js("return localStorage.getItem('owned-storage63')") is None,'relative custom directory resolves against launch cwd and does not reuse portable or default data')
        local=configure();custom_id=create_profile('Custom library63');js("localStorage.setItem('owned-storage63','custom63')");command('connect',{'id':custom_id});check(real_http(local),'custom data path with spaces, quotes and Unicode supports a real Core connection')
        alias=root/'custom-alias';alias.symlink_to(custom,target_is_directory=True);before=(custom/'library.json').read_bytes();since=command('snapshot')['since'];primary=pids()
        secondary(original,['--data-dir',str(alias)],cwd=root)
        check(pids()==primary and (custom/'library.json').read_bytes()==before and command('snapshot')['since']==since and command('snapshot')['running']==custom_id,'a canonical directory alias focuses the same instance without rewriting the library or restarting its connection')
        save('system',autostart=True);entry=Path(os.environ['XDG_CONFIG_HOME'])/'autostart/io.thronium.desktop.desktop'
        assert entry.exists();subprocess.run(['gio','launch',str(entry)],check=True,timeout=15,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE);poll(lambda:pids()==primary)
        check(command('snapshot')['running']==custom_id and (standard/'library.json').read_bytes()==default_bytes,'actual autostart desktop entry preserves the quoted custom data path and existing session')
        save('system',url_scheme_auto_register=True);handler=data/'applications/Thronium-handler.desktop';assert handler.exists()
        subprocess.run(['gio','launch',str(handler),'throne://portable63-fixture'],check=True,timeout=15,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        wait_for('return [...document.querySelectorAll("dialog textarea")].some(e=>e.value.includes("throne://portable63-fixture"))')
        check(pids()==primary and command('snapshot')['running']==custom_id,'the OS URL handler delivers its URI to the selected library while preserving the active connection')
        click('#main-modal > .modal-head > button');wait_for('return !document.querySelector("dialog[open]")');save('system',autostart=False,url_scheme_auto_register=False);command('disconnect')
        click('.primary-nav button:last-child');click('[data-settings-section=system]');wait_for('return !!document.querySelector("#storage-directory")')
        check(js('return document.querySelector("#storage-directory").textContent')==str(custom),'settings show the exact selected data directory')
        for language,width in [('en',1280),('ru',390)]:
            command('preferences',{**command('snapshot')['preferences'],'language':language});h['request']('POST',h['base']+'/window/rect',{'width':width,'height':900});wait_for('return document.documentElement.lang==='+json.dumps(language));wait_for('return innerWidth==='+str(width));js('document.querySelector("#storage-location").scrollIntoView({block:"center",behavior:"instant"})');wait_for('const r=document.querySelector("#storage-location").getBoundingClientRect();return r.top>=50&&r.bottom<=innerHeight-50')
            check(js('const r=document.querySelector("#storage-directory").getBoundingClientRect();return document.documentElement.scrollWidth<=innerWidth+1&&r.left>=0&&r.right<=innerWidth'),'storage location fits '+language+' '+str(width)+'px');h['screenshot']('storage-'+language+'-'+str(width))
        launch(original,['--data-dir='+str(custom)]);check(any(p['id']==custom_id for p in command('snapshot')['profiles']) and js("return localStorage.getItem('owned-storage63')")== 'custom63','inline data-dir syntax reopens the same custom profile and browser state')
        launch(original,['-appdata',str(custom)]);check(any(p['id']==custom_id for p in command('snapshot')['profiles']),'Throne-compatible -appdata path opens the selected Thronium library')
        for arguments in [['--portable','--data-dir',str(root/'must-not-create')],['--data-dir'],['--data-dir=']]:
            launch(original,arguments,'storage_invalid_arguments');check(not (root/'must-not-create').exists() and (standard/'library.json').read_bytes()==default_bytes,'invalid storage arguments show an error without selecting a fallback library')
        obstruction=root/'not-directory';obstruction.write_bytes(b'keep owned contents');launch(original,['--data-dir',str(obstruction)],'storage_unavailable');check(obstruction.read_bytes()==b'keep owned contents','a file at the selected path is preserved and reported as unavailable')
        readonly=root/'readonly';readonly.mkdir();readonly.chmod(0o500);launch(original,['--data-dir',str(readonly)],'storage_unavailable');check(readonly.stat().st_mode&0o777==0o500 and not (readonly/'library.json').exists(),'an explicitly read-only data folder is not made writable or replaced');readonly.chmod(0o700)
        launch(original);check(any(p['id']==default_id for p in command('snapshot')['profiles']) and js("return localStorage.getItem('owned-storage63')")== 'system63','normal launch returns to the original standard library and browser storage')
        audit['defaultLibraryPreserved']=True
    finally:
        for child in children:
            if child.poll() is None:child.terminate();child.wait(timeout=5)
        server.shutdown();server.server_close();thread.join(timeout=3);audit['httpServiceReaped']=not thread.is_alive() and server.socket.fileno()==-1
        (Path(h['args'].artifacts)/'portable-audit.json').write_text(json.dumps(audit,indent=2)+'\n')
