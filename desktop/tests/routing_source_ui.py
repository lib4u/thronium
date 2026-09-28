"""Real Qt archive + native review + owned HTTP update + saved DNS/undo."""
import copy, http.client, json, os, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from native_dialogs import file_dialog
from legacy_route_policy_fixtures import generate

def run(h):
    command,click,wait_for,js,check=(h[k] for k in ('command','click','wait_for','js','check'))
    root=Path(os.environ['XDG_DATA_HOME']);assert 'thronium-native-test-' in str(root)
    command('preferences',command('snapshot')['preferences'])
    state=lambda:json.loads((root/'io.thronium.desktop/library.json').read_text())
    initial=state();routes=Path('/proc/net/route').read_bytes();geometry=h['request']('GET',h['base']+'/window/rect')
    output=Path(h['args'].artifacts);baseline=output/'baseline.json'
    response={'kind':'throne-route-profile','v':1,'default_outbound':'direct','rules':[{'type':'simple_address_bypass','name':'New domain','domain_suffix':['updated.fixture.invalid'],'outbound':'direct'}]}
    requests=[]
    binary=Path(__file__).parent.joinpath('fixtures/tray-controls/loopback.srs').read_bytes()
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path);body=binary if self.path=='/block.srs' else b'owned-route-echo' if self.path=='/echo' else json.dumps(response).encode()
            self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        def log_message(self,*args):pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler);server.daemon_threads=True
    threading.Thread(target=server.serve_forever,daemon=True).start()
    origin=f'127.0.0.1:{server.server_port}'
    archive,manifest=generate(output/'qt',f'http://{origin}/routing')
    response['rules'].append({'type':'custom','name':'Owned block set','rule_set':[f'http://{origin}/block.srs'],'outbound':'block'})
    def settings():
        click('.primary-nav button:nth-child(5)');wait_for('return !!document.querySelector("[data-settings-section=backup]")');click('[data-settings-section=backup]');wait_for('return !!document.querySelector("#backup-open")')
    def opened(path):
        click('#backup-open');language=command('snapshot')['preferences']['language']
        file_dialog('Open backup' if language=='en' else 'Открыть резервную копию',path,opening=True);wait_for('return !!document.querySelector("#backup-confirm")')
    def apply():
        click('#backup-acknowledge');click('#backup-confirm');wait_for('return !document.querySelector("dialog[open]")')
    try:
        command('preferences',{**initial['preferences'],'language':'en'})
        wait_for('return document.documentElement.lang==="en"');settings()
        click('#backup-save');file_dialog('Save backup',baseline);wait_for('return !document.querySelector("#backup-save").disabled')
        opened(archive);click('#legacy-scope-routes');wait_for('return !document.querySelector("#legacy-import-blocked") && !document.querySelector("#backup-refresh").disabled')
        check('without automatic' in js('return document.querySelector("#legacy-import-review").textContent'),'Qt raw verbatim behavior is explained in the import review')
        apply();saved=command('routing');raw=next(p for p in saved['profiles'] if p['name']=='Qt raw verbatim');remote=next(p for p in saved['profiles'] if p['name']=='Qt remote rules')
        check(raw['route']=={'rule_set':manifest['raw']['rule_set']} and raw['legacyConstraints']['rawVerbatim'],'raw route keeps absent final resolver and process defaults absent')
        check(remote['source']['autoUpdate'] and remote['source']['importedAt']==5,'Qt remote URL and auto-update choice are imported')
        command('checkRouting',raw);command('checkRouting',remote)
        check(True,'actual Core accepts verbatim routing and explicit predefined DNS records')
        previous=command('settings')['dns'];command('saveSettings',{'section':'dns','previous':previous,'values':{**previous,'enable_dns_routing':False}})
        saved['active']=remote['id'];command('saveRouting',saved)
        click('.primary-nav button:nth-child(2)');wait_for('return !!document.querySelector("#route-source-refresh")')
        click('#route-source-refresh')
        wait_for('return document.querySelector("#route-source-refresh").textContent.includes("Update rules") && document.body.textContent.includes("New domain")')
        updated=next(p for p in command('routing')['profiles'] if p['id']==remote['id'])
        check(requests.count('/routing')==1 and all(path in ['/routing','/block.srs'] for path in requests) and updated['name']==remote['name'] and updated['route']['final']=='direct','manual refresh uses the owned HTTP source and preserves the local preset name')
        check(updated['dns']==remote['dns'],'remote refresh preserves explicit imported DNS')
        check(updated['route']['rule_set']==remote['route']['rule_set'], 'remote update retains the matching owned binary rule-set definition')
        main=command('saveProfile',{'name':'Owned route-set test','groupId':'personal','kind':'sing-box-outbound','config':{'type':'direct'}})['id']
        command('connect',{'id':main})
        port=command('snapshot')['preferences']['inboundPort']
        direct=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=3)
        direct.request('GET','/echo');assert direct.getresponse().read()==b'owned-route-echo';direct.close()
        proxy=http.client.HTTPConnection('127.0.0.1',port,timeout=3)
        blocked=False
        try:
            proxy.request('GET',f'http://{origin}/echo')
            result=proxy.getresponse();blocked=result.status!=200 or result.read()!=b'owned-route-echo'
        except (OSError,http.client.HTTPException):blocked=True
        finally:proxy.close();command('disconnect')
        check(blocked and '/block.srs' in requests,'imported Qt rule-set downloads from the owned source and blocks real HTTP while the destination itself responds')
        click('#route-source-auto');wait_for('return !document.querySelector("#route-source-auto").checked && !document.querySelector("#route-source-auto").disabled')
        check(not next(p for p in command('routing')['profiles'] if p['id']==remote['id'])['source']['autoUpdate'],'auto-update can be disabled independently in the routing page')
        h['request']('POST',h['base']+'/window/rect',{'width':390,'height':844})
        js('document.querySelector("#route-source-refresh").scrollIntoView({block:"center"})')
        check(js('return document.documentElement.scrollWidth<=window.innerWidth+1'),'English remote update controls fit a narrow window')
        h['screenshot']('routing-source-en-390')
        command('preferences',{**command('snapshot')['preferences'],'language':'ru'})
        wait_for('return document.documentElement.lang==="ru" && document.querySelector("#route-source-refresh").textContent.includes("Обновить")')
        h['screenshot']('routing-source-ru-390')
        response.clear();response.update({'kind':'throne-route-profile','v':1,'rules':[],'endpoints':[{'private_key':'fixture-secret'}]})
        before=state();click('#route-source-refresh');wait_for('return !!document.querySelector(".desktop-inline-error")')
        check(state()==before and 'fixture-secret' not in js('return document.body.textContent'),'unsupported remote endpoint response shows an error and preserves the entire library')
        settings();click('#backup-save');export=output/'export.json';file_dialog('Сохранить резервную копию',export);wait_for('return !document.querySelector("#backup-save").disabled')
        check(next(p for p in json.loads(export.read_text())['library']['routing']['profiles'] if p['id']==remote['id'])['source']==next(p for p in command('routing')['profiles'] if p['id']==remote['id'])['source'],'native export preserves remote source metadata')
    finally:
        if command('snapshot')['running']:command('disconnect')
        if js('return !!document.querySelector("dialog[open]")'):click('#main-modal > .modal-head > button')
        if baseline.exists():settings();opened(baseline);apply()
        command('preferences',initial['preferences']);h['request']('POST',h['base']+'/window/rect',geometry)
        check(state()==initial,'cleanup restores the complete disposable library')
        server.shutdown();server.server_close()
        check(Path('/proc/net/route').read_bytes()==routes,'remote routing acceptance leaves host routes unchanged')
