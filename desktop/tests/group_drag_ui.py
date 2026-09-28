"""Reorder complete groups in native WebKit; preserve profiles and connection."""
import json
import socket
import socketserver
import threading
import contextlib
from native_processes import core_pids
import time
from pathlib import Path
from profile_order_input import OwnedInput


def run(h):
    command, click, select, fill, wait_for, js, check, screenshot = (h[k] for k in ('command','click','select','fill','wait_for','js','check','screenshot'))
    request,base=h['request'],h['base']; initial=command('snapshot'); geometry=request('GET',base+'/window/rect')
    groups=[]; personal=None; native=None; held=None
    audit={"trustedMoves":[],"passed":False,"geometry":{}}
    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(10)
            with contextlib.suppress(OSError):
                while data:=self.request.recv(4096):self.request.sendall(data)
    class EchoServer(socketserver.ThreadingTCPServer):
        allow_reuse_address=True
    echo_server=EchoServer(('127.0.0.1',0),Echo)
    echo_thread=threading.Thread(target=echo_server.serve_forever);echo_thread.start()
    def echo():
        held.sendall(b'group-pointer40-held');return held.recv(128)==b'group-pointer40-held'
    def core_identity():
        return [{'pid':int(pid),'starttime':Path('/proc',pid,'stat').read_text().rsplit(')',1)[1].split()[19]} for pid in core_pids(native.pid)]
    def order():return [g['id'] for g in command('snapshot')['groups']]
    def header(gid):return f'[data-group-collapse="{gid}"]'
    def position(gid,where):
        return js('const r=document.querySelector(arguments[0]).getBoundingClientRect();return {x:Math.round(r.x+r.width/2),y:Math.round(arguments[1]==="before"?r.top+7:arguments[1]==="after"?r.bottom-7:r.top+r.height/2)}',header(gid),where)
    def drag(source,target,after=False,drop=True):
        js('document.querySelector(arguments[0]).scrollIntoView({block:"center",behavior:"instant"})',header(source))
        time.sleep(.12);start=len(native.events());native.start_drag(header(source))
        wait_for('return document.querySelector(".group-drag-source")?.dataset.libraryGroup==='+json.dumps(source))
        native.drag_to(position(target,'after' if after else 'before'))
        wait_for('return document.querySelector('+json.dumps('.group-drop-after' if after else '.group-drop-before')+')?.dataset.libraryGroup==='+json.dumps(target))
        if drop:
            native.release();wait_for('return !document.querySelector(".group-drag-source")')
            events=native.events()[start:]
            assert {'pointerdown','pointermove','pointerup'} <= {e['type'] for e in events if e['trusted']}
            audit['trustedMoves'].append({'source':source,'target':target,'after':after,'events':events})
    def collapsed_state():return {g['id']:g.get('collapsed',False) for g in command('snapshot')['groups']}
    try:
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0)); port=listener.getsockname()[1]
        command('preferences',{**initial['preferences'],'language':'ru','theme':'light','inboundPort':port})
        request('POST',base+'/window/rect',{'width':1280,'height':900})
        for name in ('Перенос A','Скрытая группа','Перенос B'):
            gid=command('saveGroup',{'name':name,'subscription':None})['id'];groups.append(gid);command('collapseGroup',{'id':gid,'collapsed':True})
        a,hidden,b=groups
        profile=command('saveProfile',{'name':'Перенос — основной','groupId':a,'kind':'sing-box-outbound','config':{'type':'direct'}})['id']
        personal=command('saveProfile',{'name':'Личный тест','groupId':'personal','kind':'sing-box-outbound','config':{'type':'direct'}})['id']
        command('collapseGroup',{'id':'personal','collapsed':True})
        wait_for('return document.querySelectorAll("[data-group-drag]").length===4')
        native=OwnedInput(h);native.activate()
        before=command('snapshot');profiles=before['profiles'];collapsed=collapsed_state()
        # Native XTEST input, captured by the actual WebView pointer handlers.
        drag(b,a)
        wait_for('return document.querySelectorAll("[data-library-group]")[1]?.dataset.libraryGroup==='+json.dumps(b))
        check(order()==['personal',b,a,hidden], 'Actual pointer input moves a complete group before another and persist its order')
        check(collapsed_state()==collapsed and command('snapshot')['profiles']==profiles, 'dragging preserves expanded state, profiles, membership and selection')
        time.sleep(.3)
        native.click(header(b));wait_for('return document.querySelector(arguments[0])?.getAttribute("aria-expanded")==="true"'.replace('arguments[0]',json.dumps(header(b))))
        check(True,'an ordinary header click still expands the group after dragging')
        command('collapseGroup',{'id':b,'collapsed':True});wait_for('return document.querySelector(arguments[0])?.getAttribute("aria-expanded")==="false"'.replace('arguments[0]',json.dumps(header(b))))
        drag(b,hidden,True)
        wait_for('return document.querySelectorAll("[data-library-group]")[3]?.dataset.libraryGroup==='+json.dumps(b))
        check(order()==['personal',a,hidden,b],'dropping after a target moves across multiple groups in one command')
        drag(b,a,False,False)
        check(js('return !!document.querySelector(".group-drop-before")&&!!document.querySelector(".group-drag-source")'),'dragging highlights the source and intended insertion edge')
        screenshot('group-drag-indicator-ru')
        native.key("Escape");native.release()
        check(order()==['personal',a,hidden,b] and not js('return !!document.querySelector(".group-drag-source,.group-drop-before")'),'Escape cancels the move without saving a new order')
        drag(b,a,False,False);unchanged=order()
        with native.blur():wait_for('return !document.querySelector(".group-drag-source,.group-drop-before")')
        native.release();check(order()==unchanged,'actual window blur cancels group dragging without persistence')
        drag(b,a,False,False)
        added=command('saveGroup',{'name':'Added during pointer drag','subscription':None})['id'];groups.append(added)
        after_add=order();wait_for('return !document.querySelector(".group-drag-source,.group-drop-before")');native.release()
        check(order()==after_add,'a changed visible group set cancels the captured drag without restoring old IDs')
        command('deleteGroup',{'id':added,'deleteProfiles':True});groups.remove(added)
        # Ignore files/URLs and group IDs dragged from outside this library.
        target=position(a,'before')
        js('const d=new DataTransfer();d.setData("application/x-thronium-group",arguments[1]);document.querySelector(arguments[0]).dispatchEvent(new DragEvent("drop",{bubbles:true,cancelable:true,clientX:arguments[2].x,clientY:arguments[2].y,dataTransfer:d}))',header(a),b,target)
        check(order()==['personal',a,hidden,b],'an external drop cannot reorder groups')
        fill('#client-search','Перенос')
        # Empty group B needs a matching profile to remain visible in search.
        command('saveProfile',{'name':'Перенос — второй','groupId':b,'kind':'sing-box-outbound','config':{'type':'direct'}})
        wait_for('return document.querySelectorAll("[data-library-group]").length===2')
        drag(b,a)
        deadline=time.monotonic()+10
        while order()!=['personal',b,a,hidden] and time.monotonic()<deadline:time.sleep(.1)
        check(order()==['personal',b,a,hidden],'reordering filtered groups retains hidden groups and their relative order')
        fill('#client-search','');select('.group-strip select',a)
        check(js('return document.querySelectorAll("[data-group-drag]").length===0'),'a single-group filter does not offer a drag with no destination')
        select('.group-strip select','all')
        audit['beforeReloadEvents']=native.events();native.close();native=None
        request('POST',base+'/refresh',{});wait_for('return document.querySelectorAll("[data-library-group]")[1]?.dataset.libraryGroup==='+json.dumps(b))
        native=OwnedInput(h);native.activate()
        check(order()==['personal',b,a,hidden],'group order survives a webview reload')
        command('connect',{'id':profile});active=command('snapshot')
        active_core=core_identity();active_config=command('connectionConfiguration',{'id':profile,'active':True})
        held=socket.create_connection(('127.0.0.1',port),timeout=5)
        address='127.0.0.1:'+str(echo_server.server_address[1]);held.sendall(f'CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n\r\n'.encode())
        response=b''
        while b'\r\n\r\n' not in response:response+=held.recv(4096)
        assert b' 200 ' in response and echo()

        drag(b,hidden,True)
        deadline=time.monotonic()+10
        while order()!=['personal',a,hidden,b] and time.monotonic()<deadline:time.sleep(.1)
        now=command('snapshot')
        check(now['running']==profile and now['since']==active['since'] and now['localProxy']==active['localProxy'],'reordering a group does not restart or disconnect the active VPN')
        check(core_identity()==active_core and command('connectionConfiguration',{'id':profile,'active':True})==active_config and echo(),'physical group order preserves Core PID/starttime, active configuration parts and held CONNECT traffic')
        held.close();held=None;command('disconnect')
        for language,width in (('ru',1280),('en',390)):
            command('preferences',{**command('snapshot')['preferences'],'language':language})
            request('POST',base+'/window/rect',{'width':width,'height':700})
            wait_for('return document.documentElement.lang==='+json.dumps(language)+'&&innerWidth==='+str(width)+'&&innerHeight===700')
            js('document.querySelector(".library-footer").scrollIntoView({block:"center",behavior:"instant"})')
            samples=[]
            for _ in range(3):
                samples.append(js('const r=document.querySelector(".library-footer").getBoundingClientRect();return {w:innerWidth,h:innerHeight,left:r.left,right:r.right,top:r.top,bottom:r.bottom}'));time.sleep(.15)
            audit['geometry'][language]=samples
            assert samples[0]==samples[1]==samples[2]
            assert all(v['w']==width and v['h']==700 and v['left']>=0 and v['right']<=width and v['top']>=0 and v['bottom']<=700 for v in samples)
            check(js('const f=document.querySelector(".library-footer"),r=f.getBoundingClientRect(),row=f.querySelector(".library-footer-info");return r.height<28&&row.children.length===2&&!f.textContent.includes("Хранятся")&&!f.textContent.includes("Stored on")&&row.scrollWidth<=row.clientWidth'),f'{language} footer keeps core state and server count on one compact row at {width}px')
            screenshot('group-drag-footer-'+language)
        # Autoscroll must keep working with expanded groups larger than the list.
        request('POST',base+'/window/rect',{'width':1280,'height':700})
        command('collapseGroup',{'id':b,'collapsed':False})
        for n in range(16):command('saveProfile',{'name':f'Long group {n}','groupId':b,'kind':'sing-box-outbound','config':{'type':'direct'}})
        wait_for('return document.querySelectorAll(".connection-row").length>=17')
        js('document.querySelector(".connections-scroll").scrollTop=0')
        wait_for('return innerWidth===1280&&innerHeight===700')
        native.start_drag(header(a))
        edge=js('const r=document.querySelector(".connections-scroll").getBoundingClientRect();return {x:r.x+r.width/2,y:r.bottom-3}')
        native.drag_to(edge)
        wait_for('return document.querySelector(".connections-scroll").scrollTop>30')
        check(True,'dragging near the library edge automatically scrolls long group lists')
        native.key("Escape");native.release()
        audit["passed"]=True
    finally:
        try:
            if not audit["passed"]:
                with contextlib.suppress(Exception):screenshot("group-pointer40-failure-before-cleanup")
            if held:held.close()
            if native:
                audit["inputEvents"]=native.events();native.close()
            if command('snapshot')['running']:command('disconnect')
            for gid in groups:command('deleteGroup',{'id':gid,'deleteProfiles':True})
            if personal:command('delete',{'id':personal})
            command('collapseGroup',{'id':'personal','collapsed':next(g for g in initial['groups'] if g['id']=='personal').get('collapsed',False)})
            command('preferences',initial['preferences'])
            if initial['selected']:command('select',{'id':initial['selected']})
            fill('#client-search','');select('.group-strip select','all');request('POST',base+'/window/rect',geometry)
            audit['cleanupCompleted']=True
        finally:
            echo_server.shutdown();echo_server.server_close();echo_thread.join(timeout=5)
            audit['echoServerThreadJoined']=not echo_thread.is_alive()
            (Path(h['args'].artifacts)/'group-pointer40-audit.json').write_text(json.dumps(audit,indent=2)+'\n')
