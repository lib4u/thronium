"""Private DBusMenu opens the existing routing importer without implicit work."""
import contextlib
import copy
import http.server
import json
import os
from pathlib import Path
import socket
import socketserver
import threading
import time
from gi.repository import GLib
from external_core_fixture import identity
from native_menu import NativeMenu
from native_processes import core_pids

COUNTRIES = [('Russia', 'Россия'), ('China', 'Китай'), ('Iran', 'Иран')]
URL = 'https://raw.githubusercontent.com/throneproj/routeprofiles/profile/Profile_'
MUTATIONS = {'fetchRoutingSource', 'checkRouting', 'saveRouting', 'applyRouting', 'connect', 'disconnect', 'saveSettings'}


def run(h):
    command, click, fill, wait_for, js, check, screenshot = (h[k] for k in ('command','click','fill','wait_for','js','check','screenshot'))
    initial = command('snapshot'); original = command('routing'); menu = NativeMenu()
    owner = identity(menu.pid); events = []; connections = []
    geometry = h['request']('GET', h['base'] + '/window/rect')
    app = Path(h['args'].application).resolve(); assert Path('/proc', str(menu.pid), 'exe').resolve() == app
    xdg = Path(os.environ['XDG_DATA_HOME']); assert xdg.parent.name.startswith('thronium-native-test-')
    source = {'name':'Owned catalog fixture', 'route':{'final':'direct','rules':[{'domain_suffix':['owned-catalog.test'],'outbound':'proxy'}]}, 'dns':{'servers':[{'type':'local','tag':'dns-direct'}],'final':'dns-direct'}}
    class Http(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            events.append(self.path)
            value = copy.deepcopy(source)
            if self.path == '/invalid.json': value['route']['rules'] = [{'domain_regex':['['],'outbound':'direct'}]
            elif self.path != '/profile.json': self.send_error(404); return
            body = json.dumps(value).encode(); self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
    web_server = http.server.ThreadingHTTPServer(('127.0.0.1',0), Http); web_server.daemon_threads = True
    threading.Thread(target=web_server.serve_forever, daemon=True).start()
    endpoint = f'http://127.0.0.1:{web_server.server_port}'
    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            with contextlib.suppress(OSError):
                while data := self.request.recv(8192): self.request.sendall(data)
    class Tcp(socketserver.ThreadingTCPServer): daemon_threads=True; allow_reuse_address=True
    tcp = Tcp(('127.0.0.1',0), Echo); threading.Thread(target=tcp.serve_forever, daemon=True).start()

    def library(): return json.loads((xdg/'io.thronium.desktop/library.json').read_text())
    def cores(): return [(int(pid), identity(int(pid))['starttime']) for pid in core_pids(menu.pid)]
    def calls(): return js('return window.__catalogAudit.calls')
    def checkpoint(): return {'library':library(),'cores':cores(),'events':len(events),'calls':len(calls())}
    def unchanged(before):
        return (library() == before['library'] and cores() == before['cores'] and len(events) == before['events'] and
                not [v for v in calls()[before['calls']:] if v['name'] in MUTATIONS])
    def close():
        click('dialog[open] > .modal-head > .icon-button')
        if js('return !!document.querySelector("[data-confirm-accept]")'): click('[data-confirm-accept]')
        wait_for('return !document.querySelector("dialog[open]")')
    def choose(country, language='en'):
        label = dict(COUNTRIES)[country] if language == 'ru' else country
        node = menu.ready(label); menu.activate(node); return node
    def opened(country):
        wait_for('return !!document.querySelector("#route-import-url")')
        return js('return document.querySelector("#route-import-url").value === arguments[0] && document.querySelector("[data-route-country="+arguments[1]+"]").classList.contains("primary")', URL+country, country)
    def page():
        click('.primary-nav button:nth-child(2)'); wait_for('return !!document.querySelector("#route-import")')
    def settings(section):
        click('.primary-nav button:nth-child(5)'); wait_for('return !!document.querySelector("[data-settings-section='+section+']")')
        click('[data-settings-section='+section+']'); wait_for('return document.querySelector("[data-settings-section='+section+']").getAttribute("aria-current")==="page"')
    def fits():
        return js('return document.documentElement.scrollWidth<=innerWidth+1 && [...document.querySelectorAll("dialog[open]")].every(d=>{const r=d.getBoundingClientRect(),b=d.querySelector(".modal-body");return r.left>=-1&&r.right<=innerWidth+1&&r.bottom<=innerHeight+1&&b.scrollWidth<=b.clientWidth+1})')
    def tunnel():
        conn = socket.create_connection(('127.0.0.1', inbound), timeout=5); connections.append(conn)
        target = f'127.0.0.1:{tcp.server_address[1]}'
        conn.sendall(f'CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n'.encode()); headers=b''
        while b'\r\n\r\n' not in headers:
            chunk=conn.recv(4096); assert chunk; headers+=chunk
        assert b' 200 ' in headers.split(b'\r\n',1)[0]; return conn
    def echo(conn,label):
        value=('catalog-native-'+label).encode(); conn.sendall(value); answer=b''
        while len(answer)<len(value):
            part=conn.recv(len(value)-len(answer)); assert part; answer+=part
        return answer==value
    def emit(country):
        return h['request']('POST',h['base']+'/execute/async', {'script':"const done=arguments[arguments.length-1];window.__TAURI_INTERNALS__.invoke('plugin:event|emit',{event:'routing-import-open',payload:arguments[0]}).then(()=>done(true)).catch(e=>done({failure:String(e)}));",'args':[country]})

    try:
        command('disconnect'); command('preferences',{**initial['preferences'],'language':'en','theme':'dark'})
        js('''const original=window.fetch;window.__catalogAudit={original,calls:[]};window.fetch=function(input,options){let body;try{if(String(input).includes('/app_command'))body=JSON.parse(options?.body||'{}')}catch{}if(body){window.__catalogAudit.calls.push({name:body.name,url:body.name==='fetchRoutingSource'?body.payload?.url:null});if(body.name==='fetchRoutingSource'&&!String(body.payload?.url||'').startsWith(arguments[2]||window.__catalogEndpoint)){return Promise.reject(Error('Native test forbids unexpected non-loopback catalog requests'));}}return original.apply(this,arguments);};window.__catalogEndpoint=arguments[0];''',endpoint+'/')
        baseline = checkpoint(); check(not baseline['cores'], 'opening the tray catalog starts with no owned core process')
        # The node found by ready: a second layout read can land inside a menu rebuild.
        catalog = menu.ready('Load profile…')
        check([n[1].get('label') for n in catalog[2]] == [c[0] for c in COUNTRIES], 'real Routing submenu contains exactly Russia, China and Iran under Load profile')
        for country,_ in COUNTRIES:
            choose(country); check(opened(country), 'native '+country+' action preselects its exact existing catalog source')
            check(unchanged(baseline), 'opening '+country+' performs no download, validation, save or core launch')
            close(); check(unchanged(baseline), 'cancelling '+country+' retains all stored data and no core')
        for language,theme in [('ru','light'),('en','dark')]:
            command('preferences',{**command('snapshot')['preferences'],'language':language,'theme':theme}); wait_for('return document.documentElement.lang==='+json.dumps(language))
            country='China'; choose(country,language); check(opened(country), language+' native country label opens the matching source')
            h['request']('POST',h['base']+'/window/rect',{'width':390,'height':844})
            check(fits() and js('return document.querySelector("#modal-title").textContent.includes(arguments[0])','Загрузить профиль' if language=='ru' else 'Load routing profile'), language+' importer, source and actions fit a real 390px window')
            screenshot('tray-catalog-'+language+'-390'); close(); h['request']('POST',h['base']+'/window/rect',geometry)
        page(); click('[data-route-tab=raw]'); original_raw=js('return document.querySelector("#route-json").value'); raw='{"unfinished":"catalog routing draft"'
        fill('#route-json',raw); before=checkpoint(); choose('Iran'); check(opened('Iran'), 'tray catalog can open over the current routing page with an unfinished raw draft')
        close(); check(js('return document.querySelector("#route-json").value===arguments[0]',raw) and unchanged(before), 'cancelling the importer retains the exact unfinished routing JSON buffer')
        fill('#route-json',original_raw); click('[data-route-tab=rules]'); click('#route-add-rule'); fill('#rule-name','Unsaved native rule'); before=checkpoint()
        choose('Russia'); time.sleep(.25)
        check(js('return document.querySelector("#rule-name")?.value==="Unsaved native rule" && !document.querySelector("#route-import-url")') and unchanged(before), 'native catalog activation preserves the already open route editor and its draft'); close()
        settings('testing'); wait_for('return !!document.querySelector("#setting-test_concurrent")'); old=js('return document.querySelector("#setting-test_concurrent").value'); changed='9' if old!='9' else '8'
        fill('#setting-test_concurrent',changed); click('[data-settings-section=appearance]'); before=checkpoint(); choose('China'); time.sleep(.25)
        check(js('return !!document.querySelector(".settings-page") && !document.querySelector("#route-import-url")') and unchanged(before), 'a settings draft in a hidden category prevents tray navigation without work')
        click('[data-settings-section=testing]'); check(js('return document.querySelector("#setting-test_concurrent").value===arguments[0]',changed), 'the hidden testing draft remains byte-for-byte in its original form')
        click('#settings-form .settings-save button[type=button]'); wait_for('return !document.querySelector("[data-navigation-locked=true]")')
        choose('China'); check(opened('China'), 'resetting settings explicitly permits the next tray import request'); close()
        settings('dns'); wait_for('return !!document.querySelector("[data-resource-view=json]")'); click('[data-resource-view=json]'); dns_raw='{"dns":"unfinished hidden buffer"'; fill('#route-json',dns_raw)
        click('[data-settings-section=appearance]'); before=checkpoint(); choose('Iran'); time.sleep(.25)
        check(js('return !!document.querySelector(".settings-page") && !document.querySelector("#route-import-url")') and unchanged(before), 'a hidden raw DNS draft also blocks tray navigation without losing its page')
        click('[data-settings-section=dns]'); check(js('return document.querySelector("#route-json").value===arguments[0]',dns_raw), 'the exact unfinished DNS JSON survives the rejected native navigation')
        click('[data-resource-view=fields]'); click('#resource-json-discard'); wait_for('return !document.querySelector("[data-navigation-locked=true]")')
        choose('Iran'); check(opened('Iran'), 'explicitly discarding the DNS draft permits the catalog again'); close()
        before=checkpoint(); assert emit('unknown-country') is True; time.sleep(.2)
        check(not js('return !!document.querySelector("dialog[open]")') and unchanged(before), 'an unknown import event is ignored before navigation or mutation')
        stale=menu.ready('Russia'); command('preferences',{**command('snapshot')['preferences'],'language':'ru'}); menu.ready('Россия'); before=checkpoint()
        menu.activate(stale); time.sleep(.25)
        if js('return !!document.querySelector("#route-import-url")'): check(opened('Russia'), 'a previously read valid native menu item still maps only to its catalog source'); close()
        check(unchanged(before), 'a native menu event retained across a language rebuild never downloads or changes stored routing')
        command('preferences',{**command('snapshot')['preferences'],'language':'en'}); wait_for('return document.documentElement.lang==="en"'); menu.ready('Russia')
        with socket.socket() as port: port.bind(('127.0.0.1',0)); inbound=port.getsockname()[1]
        command('preferences',{**command('snapshot')['preferences'],'inboundPort':inbound})
        direct=command('saveProfile',{'name':'Catalog owned direct','groupId':'personal','kind':'sing-box-outbound','config':{'type':'direct'}})['id']
        command('connect',{'id':direct}); held=tunnel(); live_cores=cores(); check(echo(held,'initial'), 'real owned HTTP CONNECT is held before catalog fetch and validation')
        click('[data-window-action=minimize]'); choose('Russia'); check(opened('Russia') and echo(held,'shown'), 'native tray catalog restores a minimized window without replacing its live connection')
        fill('#route-import-url',endpoint+'/invalid.json'); before=command('routing'); n=len(events); click('#route-import-load'); wait_for('return !!document.querySelector("#route-import-name")')
        check(events[n:]==['/invalid.json'] and command('routing')==before and cores()==live_cores, 'only explicit Load fetches the owned invalid fixture and creates a preview without saving')
        click('#route-import-save'); wait_for('return !!document.querySelector("dialog .desktop-inline-error")',timeout=30)
        check(command('routing')==before and cores()==live_cores and echo(held,'invalid-check'), 'actual core validation refuses invalid imported regex and preserves the existing held connection'); close()
        choose('China'); check(opened('China'), 'a failed import does not poison a later native catalog request')
        fill('#route-import-url',endpoint+'/profile.json'); n=len(events); click('#route-import-load'); wait_for('return !!document.querySelector("#route-import-name")')
        check(events[n:]==['/profile.json'] and command('routing')==before and echo(held,'preview'), 'the valid local download is still review-only until Add profile')
        fill('#route-import-name','Imported through native tray'); click('#route-import-save'); wait_for('return !document.querySelector("dialog[open]")',timeout=30)
        saved=command('routing'); imported=next(p for p in saved['profiles'] if p['id']==saved['active'])
        check(imported['name']=='Imported through native tray' and imported['source']['url']==endpoint+'/profile.json' and imported['dns']==source['dns'] and [r['config'] for r in imported['rules']]==source['route']['rules'], 'the existing importer saves complete routing and DNS with source attribution through real Check')
        check(cores()==live_cores and echo(held,'saved') and command('snapshot')['running']==direct and command('snapshot')['routing']['pending'], 'saved catalog selection remains dormant while the original core and held socket continue')
        exported=command('exportRoutingProfile',{'id':imported['id']}); check(exported['profile']['dns']==imported['dns'] and exported['profile']['rules']==imported['rules'], 'catalog route export preserves the imported DNS and rules exactly')
        held.close(); command('disconnect')
        full=command('saveProfile',{'name':'Catalog full JSON owner','groupId':'personal','kind':'sing-box-config','config':{'inbounds':[{'type':'mixed','listen':'127.0.0.1','listen_port':inbound}],'outbounds':[{'type':'direct','tag':'direct'}],'route':{'final':'direct'}}})['id']
        command('connect',{'id':full}); full_held=tunnel(); before=checkpoint(); choose('Iran')
        check(opened('Iran') and command('snapshot')['routing']['profileOwned'], 'a full JSON profile can open the catalog while retaining its own routing policy')
        close(); check(unchanged(before) and echo(full_held,'full-json'), 'opening and cancelling with full JSON changes neither its config nor the running policy')
        check(not [v for v in calls() if v['name']=='fetchRoutingSource' and not str(v['url']).startswith(endpoint+'/')] and identity(menu.pid)['starttime']==owner['starttime'], 'the entire native catalog run uses only explicit loopback fetches and the same owned application')
    finally:
        with contextlib.suppress(Exception):
            (h['artifacts']/'tray-catalog-audit.json').write_text(json.dumps({'appIdentity':owner,'calls':calls(),'httpPaths':events,'coreIdentities':cores()},indent=2)+'\n')
        for conn in connections: conn.close()
        with contextlib.suppress(Exception): command('disconnect')
        web_server.shutdown(); web_server.server_close(); tcp.shutdown(); tcp.server_close()
