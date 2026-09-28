"""Routing catalogs in the real Tauri/WebKit app; fixtures and storage are isolated."""
import contextlib
import time
import base64
import http.server
import json
import threading

def varint(n):
    out=bytearray()
    while n>127:out.append(n%128+128);n>>=7
    out.append(n);return bytes(out)
def field(n,b):return varint(n*8+2)+varint(len(b))+b
def database():
    result=b''
    for code in ['ru','cn','ir','category-ads-all','openai']+[f'service-{i:03}' for i in range(130)]:
        first=b'\x08\x02'+field(2,(code+'.test').encode())+field(3,field(1,b'ads'))
        second=b'\x08\x03'+field(2,('exact.'+code+'.test').encode())
        result+=field(1,field(1,code.upper().encode())+field(2,first)+field(2,second))
    return result

def run(h):
    command,click,fill,select,wait_for,js,check,screenshot=(h[k] for k in ('command','click','fill','select','wait_for','js','check','screenshot'))
    data=database();initial=command('snapshot');original=command('routing');geometry=h['request']('GET',h['base']+'/window/rect')
    delayed = threading.Event(); release = threading.Event()
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            if self.path=='/bad.dat':content=b'<html>bad database</html>'
            elif self.path in ['/routing.json', '/slow-routing.json']:content=json.dumps({'name':'Fixture profile','route':{'final':'direct','rules':[{'domain':['fixture.test'],'action':'route','outbound':'proxy'}]},'dns':{'servers':[{'type':'local','tag':'dns-direct'}],'final':'dns-direct'}}).encode()
            else:content=data
            self.send_response(200);self.send_header('Content-Length',str(len(content)));self.end_headers()
            if self.path.startswith('/slow-'):
                self.wfile.write(content[:1]);self.wfile.flush();delayed.set();release.wait(8);content=content[1:]
            with contextlib.suppress(BrokenPipeError,ConnectionResetError):self.wfile.write(content)
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start()
    url=f'http://127.0.0.1:{server.server_port}'
    def route():
        state=command('routing');return next(p for p in state['profiles'] if p['id']==state['active'])
    def close():
        js('const all=[...document.querySelectorAll("dialog[open]")];all[all.length-1]?.querySelector(".modal-head>button")?.click()')
    def fits():return js('return document.documentElement.scrollWidth<=innerWidth+1&&[...document.querySelectorAll("dialog[open]")].every(d=>{const b=d.querySelector(".modal-body"),r=d.getBoundingClientRect();return r.x>=-1&&r.right<=innerWidth+1&&r.bottom<=innerHeight+1&&b.scrollWidth<=b.clientWidth+1})')
    try:
        command('preferences',{**initial['preferences'],'language':'ru','theme':'light'})
        h['request']('POST',h['base']+'/window/rect',{'width':1280,'height':900})
        manual={**original['profiles'][0],'rules':[{'id':'manual','name':'Manual preserved','enabled':True,'config':{'domain':['manual.test'],'action':'route','outbound':'direct'}}]}
        command('saveRouting',{**original,'profiles':[manual]})
        click('.primary-nav button:nth-child(2)');wait_for('return !!document.querySelector("#route-import")')
        click('[data-route-tab=categories]')
        fill('#geo-url',url+'/slow-geosite.dat');click('#geo-load')
        assert delayed.wait(5), 'delayed geodata request did not start'
        before=time.monotonic();command('snapshot');check(time.monotonic()-before<2, 'a delayed native geodata response leaves snapshot responsive')
        click('#geo-cancel');wait_for('return !document.querySelector("#geo-load").disabled');release.set()
        check(not command('geodataSources'), 'cancelled geodata never installs its partial response')
        click('#route-import');fill('#route-import-url',url+'/slow-routing.json');delayed.clear();release.clear();click('#route-import-load')
        assert delayed.wait(5), 'delayed routing request did not start'
        close();wait_for('return !document.querySelector("dialog[open]")');release.set()
        click('#route-import');wait_for('return !!document.querySelector("#route-import-url")')
        check(not js('return !!document.querySelector("#route-import-name")'), 'closing a routing download cannot populate a newly opened editor')
        close();wait_for('return !document.querySelector("dialog[open]")')
        # Return the provider selector to its initial value for the catalog checks.
        select('#geo-provider',js('return [...document.querySelector("#geo-provider").options].find(o=>o.value.startsWith("https://raw.githubusercontent.com/")).value'))
        check(js('const options=[...document.querySelector("#geo-provider").options];return document.querySelector("#geo-url").value.startsWith("https://raw.githubusercontent.com/")&&options.at(-1).value==="custom"&&options.length>2&&options.slice(0,-1).every(o=>o.value.startsWith("https://"))'),'geodata opens with the engine provider catalog and a custom source option')
        fill('#geo-url',url+'/geosite.dat');click('#geo-load');wait_for('return !!document.querySelector("[data-geo-select=ru]")',timeout=30)
        check(js('return document.querySelectorAll(".geo-category-row").length===60&&document.querySelector(".geo-meta").textContent.includes("135")'),'real .dat is decoded into counted categories and paginated rows')
        fill('#geo-search','ru');click('[data-geo-select=ru]');select('#geo-target','direct');click('#geo-add')
        wait_for('return !document.querySelector("#geo-load").disabled',timeout=30)
        saved=route();check(saved['rules'][0]['name']=='geosite:ru' and saved['rules'][1]['id']=='manual' and saved['route']['rule_set'][0]['url']==url+'/geosite.dat','category source and priority save without changing manual rules')
        fill('#geo-search','openai');click('[data-geo-preview=openai]');wait_for('return !!document.querySelector("#geo-make-copy")')
        check(js('return document.querySelector(".geo-preview-text").textContent.includes("exact.openai.test")&&document.querySelector("#geo-attribute").options.length===2'),'category preview exposes real domains and available attributes')
        select('#geo-attribute','ads');wait_for('return !document.querySelector("#geo-add-preview").disabled');check(js('return !document.querySelector(".geo-preview-text").textContent.includes("exact.openai.test")'),'attribute filter updates the actual preview');click('#geo-add-preview');wait_for('return !document.querySelector("dialog[open]")',timeout=30)
        check(any(s.get('category')=='openai@ads' for s in route()['route']['rule_set']),'attribute selection is stored and accepted by the real core')
        fill('#geo-search','ru');click('[data-geo-preview=ru]');click('#geo-make-copy');wait_for('return !!document.querySelector("#geo-content-text")')
        fill('#geo-content-name','My custom domains');fill('#geo-content-text','suffix:owned.test\ndomain:exact.owned.test\nregex:^ads[0-9]{1,3}\\.test$');click('#geo-content-save')
        wait_for('return !document.querySelector("dialog[open]")',timeout=30)
        saved=route();own=next(s for s in saved['route']['rule_set'] if s['type']=='inline');check(any(r.get('domain_regex')==[r'^ads[0-9]{1,3}\.test$'] for r in own['rules']),'editable copy saves complete match types without changing the source category')
        click('[data-route-tab=sets]');wait_for('return !!document.querySelector("[data-set-content]")')
        index=next(i for i,s in enumerate(saved['route']['rule_set']) if s['type']=='inline');click(f'[data-set-content="{index}"]');fill('#geo-content-text','suffix:changed.test');click('#geo-content-save');wait_for('return !document.querySelector("dialog[open]")',timeout=30)
        check(route()['route']['rule_set'][index]['rules']==[{'domain_suffix':['changed.test']}],'saved category copies reopen in the content editor and retain references')
        click('[data-route-tab=categories]');fill('#geo-url',url+'/bad.dat');click('#geo-load');wait_for('return !!document.querySelector(".geo-panel [role=alert]")')
        check(len(route()['rules'])==len(saved['rules']),'invalid database shows an error and leaves saved routing untouched')
        fill('#geo-url',url+'/geosite.dat');click('#geo-load');wait_for('return !!document.querySelector("[data-geo-select=ru]")')
        for language,theme in [('ru','light'),('en','dark')]:
            command('preferences',{**command('snapshot')['preferences'],'language':language,'theme':theme});wait_for('return document.documentElement.lang==='+json.dumps(language))
            for width,height in [(1280,900),(390,740)]:
                h['request']('POST',h['base']+'/window/rect',{'width':width,'height':height});check(fits(),f'category browser fits {width}px in {language}/{theme}');screenshot(f'geo-catalog-{language}-{width}');js('document.querySelector("#geo-search").scrollIntoView({block:"start"})');screenshot(f'geo-categories-{language}-{width}');check(js('return [...document.querySelectorAll(".mode-card")].every(c=>c.querySelector(".mode-icon").getBoundingClientRect().right<=c.children[1].getBoundingClientRect().left)'),'mode icons do not overlap labels')
            h['request']('POST',h['base']+'/window/rect',{'width':1280,'height':900})
        click('#route-import');wait_for('return !!document.querySelector("#route-import-url")')
        check(js('return document.querySelectorAll("[data-route-country]").length===3&&document.querySelector("#route-import-url").value.includes("throneproj/routeprofiles")'),'profile loader provides Russia China Iran and displays its GitHub source')
        fill('#route-import-url',url+'/routing.json');click('#route-import-load');wait_for('return !!document.querySelector("#route-import-name")')
        check(len(command('routing')['profiles'])==1,'downloading a profile previews its rules before changing the library')
        fill('#route-import-name','Loaded and editable');click('#route-import-save');wait_for('return !document.querySelector("dialog[open]")',timeout=30)
        saved=route();check(saved['name']=='Loaded and editable' and saved['source']['url']==url+'/routing.json' and len(command('routing')['profiles'])==2,'profile import adds and selects an independent editable profile with source attribution')
        exported=command('exportRoutingProfile',{'id':saved['id']});check(exported['profile']['rules']==saved['rules'] and exported['profile']['dns']==saved['dns'],'profile export preserves rules DNS and source metadata')
        click('#route-import');click('.route-import-raw summary');fill('#route-import-text',json.dumps(exported));click('#route-import-preview');wait_for('return !!document.querySelector("#route-import-name")');click('#route-import-save');wait_for('return !document.querySelector("dialog[open]")',timeout=30)
        check(route()['id']!=saved['id'] and len(command('routing')['profiles'])==3,'exported routing imports again with an independent identity')
        throne={'kind':'throne-route-profile','v':1,'name':'Throne text','default_outbound':'direct','rules':[{'type':'simple_address_bypass','name':'Local fixture','domain_suffix':['throne.fixture.invalid'],'outbound':'direct'}]}
        click('#route-import');click('.route-import-raw summary');fill('#route-import-text','throne://route/'+base64.urlsafe_b64encode(json.dumps(throne).encode()).decode().rstrip('='));click('#route-import-preview');wait_for('return !!document.querySelector("#route-import-name")')
        click('#route-import-save');wait_for('return !document.querySelector("dialog[open]")',timeout=30)
        pasted=route();check(pasted['name']=='Throne text' and pasted['route']['final']=='direct' and any(r['name']=='Local fixture' for r in pasted['rules']) and not pasted.get('source') and len({p['id'] for p in command('routing')['profiles']})==4,'a pasted Throne route link is converted by the engine into a new profile without an update source')
        local=command('loadGeodata',{'kind':'geosite','name':'fixture.dat','data':base64.b64encode(data).decode()})
        check(local['url'].startswith('local:') and len(local['categories'])==135,'local .dat files use the same parser and category catalog')
        h['request']('POST',h['base']+'/refresh',{});wait_for('return !!document.querySelector(".add-connection")')
        check(len(command('routing')['profiles'])==4 and len(command('geodataSources'))>=2,'profiles and downloaded databases survive a webview restart')
        click('.primary-nav button:nth-child(2)');click('#route-import')
        for width,height in [(1280,900),(390,740)]:
            h['request']('POST',h['base']+'/window/rect',{'width':width,'height':height});check(fits(),f'profile loader fits {width}px');screenshot(f'route-import-{width}')
        close();wait_for('return !document.querySelector("dialog[open]")')
    finally:
        release.set();server.shutdown();server.server_close()
        if js('return !!document.querySelector("dialog[open]")'):
            close()
            if js('return !!document.querySelector("[data-confirm-accept]")'):click('[data-confirm-accept]')
        current=command('routing');command('saveRouting',{**current,'active':original['active'],'profiles':original['profiles']})
        command('preferences',initial['preferences']);h['request']('POST',h['base']+'/window/rect',geometry)
