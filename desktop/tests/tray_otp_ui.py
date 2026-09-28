"""Actual private DBusMenu OTP entry, readonly quick dialog and loopback session."""
import base64
import contextlib
import copy
import hashlib
import hmac
import json
import os
from pathlib import Path
import socket
import socketserver
import threading
import time
import xml.etree.ElementTree as ET
from gi.repository import Gio, GLib
from native_processes import core_pids
from tray_ui import wait

KEY=base64.b32encode(b'12345678901234567890').decode().rstrip('=')


def run(h):
    command,click,fill,wait_for,js,check,screenshot=(h[k] for k in ('command','click','fill','wait_for','js','check','screenshot'))
    assert os.environ.get('_THRONIUM_TEST_BUS'), 'Use --tray-otp-only --private-tray-bus'
    initial=command('snapshot');geometry=h['request']('GET',h['base']+'/window/rect');entries=[];profile=None;connection=None
    original_clipboard=None;original_image=None
    try:original_clipboard=command('readClipboard')
    except RuntimeError:
        import gi
        gi.require_version('Gtk','3.0')
        from gi.repository import Gtk,Gdk
        original_image=Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD).wait_for_image()
    bus=Gio.bus_get_sync(Gio.BusType.SESSION,None)
    def call(service,path,interface,method,signature,args):
        return bus.call_sync(service,path,interface,method,GLib.Variant(signature,args),None,Gio.DBusCallFlags.NONE,2000,None).unpack()
    def isolated(pid):
        try:
            proc=Path('/proc',str(pid))
            return proc.joinpath('comm').read_text().strip()=='Thronium' and any(v==b'XDG_DATA_HOME='+os.environ['XDG_DATA_HOME'].encode() and b'thronium-native-test-' in v for v in proc.joinpath('environ').read_bytes().split(b'\0'))
        except OSError:return False
    def find_menu():
        names=call('org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus','ListNames','()',())[0]
        for service in names:
            if not service.startswith(':'):continue
            try:
                pid=call('org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus','GetConnectionUnixProcessID','(s)',(service,))[0]
                if not isolated(pid):continue
                paths=['/']
                for path in paths:
                    xml=ET.fromstring(call(service,path,'org.freedesktop.DBus.Introspectable','Introspect','()',())[0])
                    if any(i.attrib['name']=='com.canonical.dbusmenu' for i in xml.findall('interface')):return service,path,pid
                    paths.extend(path.rstrip('/')+'/'+n.attrib['name'] for n in xml.findall('node'))
            except GLib.Error:continue
        return None
    service,path,pid=wait(find_menu,'private OTP menu registration')
    def tree():return call(service,path,'com.canonical.dbusmenu','GetLayout','(iias)',(0,-1,[]))[1]
    def walk(node):
        yield node
        for child in node[2]:yield from walk(child)
    def ready(label):return wait(lambda:next((node for node in walk(tree()) if node[1].get('label')==label and node[1].get('enabled',True)),None),'OTP tray '+label)
    def activate():
        label='Коды OTP' if command('snapshot')['preferences']['language']=='ru' else 'OTP Codes';node=ready(label)
        call(service,path,'com.canonical.dbusmenu','Event','(isvu)',(node[0],'clicked',GLib.Variant('s',''),0))
    def open_quick():activate();wait_for('return !!document.querySelector("#otp-quick-panel")')
    def close_quick():click('#otp-quick-close');wait_for('return !document.querySelector("#otp-quick-panel")')
    def close_other():click('dialog > .modal-head > .icon-button');wait_for('return !document.querySelector("dialog[open]")')
    def settings(section):
        click('.primary-nav button:nth-child(5)');wait_for('return !!document.querySelector("[data-settings-section='+section+']")');click('[data-settings-section='+section+']')
        wait_for('return document.querySelector("[data-settings-section='+section+']").getAttribute("aria-current")==="page"')
    def text(selector):return js('return document.querySelector(arguments[0])?.textContent||""',selector)
    def row(id,child=''):return '#otp-quick-panel [data-otp-id='+json.dumps(id)+'] '+child
    def code_ready(id):wait_for('return /^\\d{8}$/.test(document.querySelector('+json.dumps(row(id,'[data-otp-code]'))+')?.textContent||"")')
    def calls():return js('return window.__trayOtpAudit.calls')
    def code_calls():return [c for c in calls() if c['name']=='otpCodes']
    def snapshot_library():
        root=Path(os.environ['XDG_DATA_HOME']).resolve();assert root.parent.name.startswith('thronium-native-test-')
        return json.loads((root/'io.thronium.desktop/library.json').read_text())
    def saved(id):return command('otpGet',{'id':id})
    def save(value):
        result=command('otpSave',{'id':'','revision':'','value':value});entries.append(result['id']);return result['id']
    def expected(value,now):
        counter=int(value['counter']) if value['type']=='hotp' else int(now)//value['period']
        digest=hmac.new(b'12345678901234567890',counter.to_bytes(8,'big'),getattr(hashlib,value['algorithm'].lower())).digest();offset=digest[-1]&15
        return str((int.from_bytes(digest[offset:offset+4],'big')&0x7fffffff)%10**value['digits']).zfill(value['digits'])
    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            with contextlib.suppress(OSError):
                while body:=self.request.recv(8192):self.request.sendall(body)
    class Server(socketserver.ThreadingTCPServer):daemon_threads=True;allow_reuse_address=True
    server=Server(('127.0.0.1',0),Echo);threading.Thread(target=server.serve_forever,daemon=True).start()
    def tunnel():
        conn=socket.create_connection(('127.0.0.1',port),timeout=5);authority=f'127.0.0.1:{server.server_address[1]}'
        conn.sendall(f'CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n'.encode());headers=b''
        while b'\r\n\r\n' not in headers:
            part=conn.recv(4096);assert part;headers+=part
        assert b' 200 ' in headers.split(b'\r\n',1)[0];return conn
    def echo(message):
        body=message.encode();connection.sendall(body);result=b''
        while len(result)<len(body):
            part=connection.recv(8192);assert part;result+=part
        return result==body
    try:
        assert command('otpList')==[], 'Fresh disposable library required'
        command('disconnect');command('preferences',{**initial['preferences'],'language':'en','theme':'dark'})
        js("""const original=window.fetch;window.__trayOtpAudit={original,calls:[]};window.fetch=function(input,options){let body=null;try{if(String(input).includes('/app_command'))body=JSON.parse(options?.body||'{}')}catch{}if(body&&['otpList','otpCodes','otpCopy','otpGet','otpSave','otpRemove'].includes(body.name))window.__trayOtpAudit.calls.push({name:body.name,ids:body.payload?.ids||[],time:Date.now()});return original.apply(this,arguments);};""")
        ready('OTP Codes');processes=core_pids(pid);open_quick()
        check(js('return !!document.querySelector("#otp-quick-empty") && document.querySelectorAll("#otp-quick-panel [data-otp-id]").length===0'),'native OTP menu opens an empty readonly quick view without requiring entries')
        check(core_pids(pid)==processes and command('snapshot')['running'] is None and not code_calls(),'empty quick view does not launch a core or request nonexistent codes')
        close_quick()
        hotp={'name':'Private tray HOTP 🦊','issuer':'Hidden account identity','secret':KEY,'algorithm':'SHA256','type':'hotp','digits':8,'period':30,'counter':'9007199254740993'}
        totp={**hotp,'name':'Private tray TOTP 日本','issuer':'Time identity','type':'totp','counter':'0','period':2}
        a,b=save(hotp),save(totp)
        menu_text=str(tree());check(all(value not in menu_text for value in [KEY,hotp['name'],hotp['issuer'],totp['name'],expected(hotp,0)]) and not ready('OTP Codes')[2],'DBusMenu contains only a static OTP action, without account names, code submenus or secret values')
        settings('testing');wait_for('return !!document.querySelector("#probe-url")');original_draft=js('return document.querySelector("#probe-url").value');fill('#probe-url','http://127.0.0.1:9/unsaved-tray-draft')
        stored=copy.deepcopy(snapshot_library());open_quick();code_ready(a);code_ready(b)
        check(js('return document.querySelectorAll("#otp-quick-panel [data-otp-id]").length===2 && !document.querySelector("#otp-quick-panel [data-otp-edit]") && !document.querySelector("#otp-quick-panel [data-otp-delete]")'),'quick view shows both saved records and only readonly code actions')
        check(KEY not in js('return document.querySelector("#otp-quick-panel").textContent') and not [c for c in calls() if c['name']=='otpGet'],'quick listing obtains metadata and codes without fetching or rendering the shared secret')
        fill('#otp-quick-search','hidden ACCOUNT');wait_for('return document.querySelectorAll("#otp-quick-panel [data-otp-id]").length===1')
        check(js('return document.querySelector("#otp-quick-panel [data-otp-id]").dataset.otpId')==a,'quick search matches issuer and name without case sensitivity')
        before=saved(a)
        for _ in range(2):click(row(a,'[data-otp-copy]'));wait_for('return !!document.querySelector("#otp-quick-notice")')
        check(command('readClipboard')==expected(hotp,0) and saved(a)==before,'actual quick Copy produces the RFC HOTP code without incrementing the exact large counter or revision')
        command('writeClipboard',{'text':'tray-test-placeholder'})
        js('document.querySelector("#otp-quick-search").dispatchEvent(new KeyboardEvent("keydown",{key:"Enter",bubbles:true}))')
        wait(lambda:command('readClipboard')==expected(hotp,0),'Enter quick copy')
        check(saved(a)==before,'Enter copies the first filtered code and leaves HOTP state unchanged')
        activate();activate();time.sleep(.25)
        check(js('return document.querySelectorAll("dialog[open]").length===1 && document.querySelector("#otp-quick-search").value==="hidden ACCOUNT"'),'repeated native OTP events preserve one modal and the current search')
        fill('#otp-quick-search','no-match');wait_for('return !!document.querySelector("#otp-quick-empty")')
        check(js('return document.querySelectorAll("#otp-quick-panel [data-otp-id]").length===0'),'unmatched quick search shows a clear empty result')
        fill('#otp-quick-search','日本');code_ready(b);start=time.time();click(row(b,'[data-otp-copy]'));wait_for('return !!document.querySelector("#otp-quick-notice")');end=time.time()
        check(command('readClipboard') in {expected(totp,t) for t in range(int(start),int(end)+1)} and saved(b)['counter']=='0','TOTP quick Copy uses the current wall-clock code and never mutates its counter')
        close_quick();time.sleep(1.2);count=len(code_calls());time.sleep(1.2)
        check(len(code_calls())==count,'closing quick view stops its periodic code requests')
        check(snapshot_library()==stored and js('return document.querySelector("#probe-url").value')=='http://127.0.0.1:9/unsaved-tray-draft','opening and closing quick OTP preserves the underlying settings page, unsaved field and complete saved library')
        fill('#probe-url',original_draft)

        settings('otp');wait_for('return !!document.querySelector("#otp-manager [data-otp-edit]")');click('#otp-manager [data-otp-id='+json.dumps(a)+'] [data-otp-edit]');wait_for('return !!document.querySelector("#otp-editor")');fill('#otp-name','Keep this unsaved OTP edit')
        activate();time.sleep(.4)
        check(js('return !!document.querySelector("#otp-editor") && !document.querySelector("#otp-quick-panel") && document.querySelector("#otp-name").value==="Keep this unsaved OTP edit" && document.querySelectorAll("dialog[open]").length===1'),'tray OTP never discards an already open editor or its unsaved secret-entry draft')
        close_other();wait_for('return !!document.querySelector("#otp-manager [data-otp-code]")');open_quick();fill('#otp-quick-search','HOTP');code_ready(a);time.sleep(1.2);marker=len(calls());time.sleep(2.2)
        active_calls=[c for c in calls()[marker:] if c['name']=='otpCodes']
        check(active_calls and all(c['ids']==[a] for c in active_calls),'underlying OTP manager pauses while quick view polls only its filtered record')
        close_quick();wait(lambda:any(c['name']=='otpCodes' and c['ids']==[a,b] for c in calls()[marker:]),'manager code polling resume')
        check(True,'closing quick view resumes the underlying manager without replacing its page')
        click('.primary-nav button:nth-child(1)')
        with socket.socket() as listener:listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
        command('preferences',{**command('snapshot')['preferences'],'inboundPort':port})
        profile=command('saveProfile',{'name':'Tray quick loopback','groupId':'personal','kind':'sing-box-outbound','config':{'type':'direct'}})['id'];command('connect',{'id':profile});connection=tunnel();since=command('snapshot')['since']
        open_quick();code_ready(a);code_ready(b);time.sleep(1.2);check(echo('quick-live') and command('snapshot')['since']==since,'opening and polling quick OTP keeps the same real proxy CONNECT alive')
        click('[data-window-action="minimize"]');wait_for('return document.hidden');time.sleep(1.2);count=len(code_calls());time.sleep(1.2)
        check(len(code_calls())==count and echo('quick-hidden'),'a genuinely hidden quick window stops OTP polling while its VPN connection continues')
        activate();wait_for('return !document.hidden && !!document.querySelector("#otp-quick-panel")');wait(lambda:len(code_calls())>count,'visible quick polling resumes')
        check(js('return document.querySelectorAll("dialog[open]").length===1') and echo('quick-restored') and command('snapshot')['since']==since,'native OTP action restores the hidden main window and resumes the existing quick view without restarting VPN')
        for language,theme in [('en','dark'),('ru','light')]:
            command('preferences',{**command('snapshot')['preferences'],'language':language,'theme':theme});ready('Коды OTP' if language=='ru' else 'OTP Codes');wait_for('return document.documentElement.lang==='+json.dumps(language))
            h['request']('POST',h['base']+'/window/rect',{'width':390,'height':844})
            check(js('return document.documentElement.scrollWidth<=innerWidth && document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth && !!document.querySelector("#otp-quick-close")'),language+' quick code search, values and actions fit the 390-pixel native window')
            code_ready(a);code_ready(b);screenshot('tray-otp-narrow-'+language)
        check(all(value not in str(tree()) for value in [KEY,hotp['name'],totp['name'],text(row(a,'[data-otp-code]')),text(row(b,'[data-otp-code]'))]),'localized DBusMenu still excludes live OTP codes and account identities')
        click('#otp-quick-refresh');wait_for('return !document.querySelector("#otp-quick-refresh").disabled');code_ready(a)
        check(saved(a)==before and echo('quick-refresh'),'manual quick refresh leaves counters and the current connection untouched')
        close_quick();command('disconnect');connection.close();connection=None
        check(saved(a)==before and {k:v for k,v in saved(b).items() if k not in ('id','revision')}==totp,'all tray interactions leave both stored OTP records exactly unchanged')
        (Path(h['args'].artifacts)/'tray-otp-audit.json').write_text(json.dumps({'calls':calls(),'staticMenuLabels':[node[1].get('label') for node in walk(tree()) if node[1].get('label')],'realPrivateDBus':True,'heldConnect':True,'syntheticRFCOnly':True},ensure_ascii=False,indent=2)+'\n')
    finally:
        if connection:connection.close()
        with contextlib.suppress(Exception):
            if js('return !!document.querySelector("#otp-quick-panel")'):close_quick()
            elif js('return !!document.querySelector("dialog[open]")'):close_other()
            command('disconnect')
            for id in entries:
                current=saved(id);command('otpRemove',{'id':id,'revision':current['revision']})
            if profile:command('deleteProfiles',{'ids':[profile]})
            command('preferences',initial['preferences'])
            if initial['selected']:command('select',{'id':initial['selected']})
            if original_clipboard is not None:command('writeClipboard',{'text':original_clipboard})
            elif original_image is not None:
                clipboard=Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD);clipboard.set_image(original_image);clipboard.store()
            js('if(window.__trayOtpAudit){window.fetch=window.__trayOtpAudit.original;delete window.__trayOtpAudit;}')
            h['request']('POST',h['base']+'/window/rect',geometry)
        server.shutdown();server.server_close()
