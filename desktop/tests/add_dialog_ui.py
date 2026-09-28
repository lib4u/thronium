"""Approved add flow, compact toolbar, real file/QR parsing and native persistence."""
import base64
import http.server
import json
import pathlib
import threading
import time


def run(h):
    command, click, select, fill, wait_for, js, check, screenshot = (h[k] for k in ('command', 'click', 'select', 'fill', 'wait_for', 'js', 'check', 'screenshot'))
    initial = command('snapshot'); geometry = h['request']('GET', h['base'] + '/window/rect'); ids = []; groups = []
    fixture = pathlib.Path(__file__).parent / 'fixtures/import-qr.png'
    def close():
        click('#main-modal > .modal-head > button')
        if js('return !!document.querySelector("[data-confirm-accept]")'): click('[data-confirm-accept]')
        wait_for('return !document.querySelector("dialog[open]")')
    def fits():
        return js('const d=document.querySelector("#main-modal"),r=d.getBoundingClientRect(),b=d.querySelector(".modal-body"),f=d.querySelector(".modal-footer"); return Math.abs(r.x+r.width/2-innerWidth/2)<3&&Math.abs(r.y+r.height/2-innerHeight/2)<3&&r.top>=0&&r.bottom<=innerHeight+1&&b.scrollWidth<=b.clientWidth+1&&(!f||f.getBoundingClientRect().bottom<=innerHeight)')
    def file_upload(files):
        js('const d=new DataTransfer();for(const f of arguments[0])d.items.add(new File([Uint8Array.from(atob(f.data),c=>c.charCodeAt(0))],f.name,{type:f.type||"text/plain"}));const input=document.querySelector("#import-file");input.files=d.files;input.dispatchEvent(new Event("change",{bubbles:true}));', files)
        wait_for('return !document.querySelector("#import-file").disabled')
    def text_file(name, text, encoding='utf-8'):
        return {'name': name, 'data': base64.b64encode(text.encode(encoding)).decode()}
    class Subscription(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body=b'proxies: [{name: YAML subscription server, type: socks5, server: 127.0.0.1, port: 1080}]'
            self.send_response(200);self.send_header('Content-Type','text/plain');self.send_header('Content-Length',str(len(body)));self.send_header('announce','Subscription announcement');self.end_headers();self.wfile.write(body)
        def log_message(self, *args): pass
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Subscription);threading.Thread(target=server.serve_forever,daemon=True).start()
    try:
        command('preferences', {**initial['preferences'], 'language': 'ru', 'theme': 'dark'})
        click('.primary-nav button:first-child')
        h['request']('POST',h['base']+'/window/rect',{'width':1280,'height':900})
        for name, config in [('🇳🇱 Netherlands',{'type':'direct'}),('Server 🇯🇵',{'type':'socks','server':'127.0.0.1','server_port':1080}),('👩🏽‍💻 Developer',{'type':'direct'})]:
            ids.append(command('saveProfile', {'name':name,'groupId':'personal','kind':'sing-box-outbound','config':config})['id'])
        wait_for('return document.querySelectorAll(".connection-row").length===3')
        check(js('const rows=[...document.querySelectorAll(".connection-row")];return rows[0].querySelector(".profile-emoji").textContent==="🇳🇱"&&rows[0].querySelector("strong").textContent==="Netherlands"&&rows[1].querySelector(".desktop-profile-icon svg")&&rows[1].querySelector("strong").textContent==="Server 🇯🇵"&&rows[2].querySelector(".profile-emoji").textContent==="👩🏽‍💻"'), 'leading flags and joined emoji replace the icon; interior emoji and stored names remain intact')
        check(command('profile',{'id':ids[0]})['name']=='🇳🇱 Netherlands','emoji presentation does not rename the saved profile')
        check(js('const g=document.querySelector(".group-strip").getBoundingClientRect(),s=document.querySelector(".library-search").getBoundingClientRect();return Math.abs(g.top-s.top)<2&&s.left>=g.right&&!!document.querySelector("#library-sort.icon-button")&&!document.querySelector(".library-order")'),'group and search share one compact row; sorting has an icon instead of a separate row')
        click('#library-sort');click('#library-sort-name');wait_for('return !document.querySelector("[role=menu]")')
        check(command('snapshot')['preferences']['librarySort']=='name','sort dropdown persists the selected ordering')
        click('#library-sort');click('#library-sort-descending')
        check(command('snapshot')['preferences']['librarySortDescending'],'sort direction persists through its dropdown')
        click('#library-filter');click('#library-filter-socks');wait_for('return document.querySelectorAll(".connection-row").length===1')
        check(js('return document.querySelector(".row-server-info").textContent.includes("Server 🇯🇵")'),'protocol filter changes the displayed profiles')
        click('#library-filter');click('#library-filter-all');click('#library-sort');click('#library-sort-original')
        click('#library-more');check(js('return !!document.querySelector("#library-duplicates")&&!!document.querySelector("#library-export")'),'additional library actions are available in the compact menu')
        js('document.querySelector("[role=menu]").dispatchEvent(new KeyboardEvent("keydown",{key:"Escape",bubbles:true}))')
        screenshot('library-compact-dark-ru')
        click('.add-connection')
        check(js('return document.querySelectorAll("dialog:modal").length===1&&document.querySelectorAll(".add-methods>button").length===4') and fits(),'Add opens a centered four-method chooser in the native top layer')
        screenshot('add-chooser-dark-ru');click('#add-choice-link')
        check(js('return document.querySelectorAll(".import-method-tabs button").length===3&&document.querySelector("#import-source").offsetHeight<110') and fits(),'link form matches the compact mockup with three methods')
        screenshot('add-link-dark-ru')
        fill('#import-source','{"type":"direct","tag":"Quick"}');fill('#import-title','Quick imported')
        click('#import-tab-file');check(js('return !document.querySelector("#import-source")&&!!document.querySelector(".import-dropzone")'),'file tab presents its own upload area')
        screenshot('add-file-dark-ru');click('#import-tab-link')
        check(js('return document.querySelector("#import-source").value.includes("Quick")&&document.querySelector("#import-title").value==="Quick imported"'),'source and optional name survive switching import methods')
        click('#import-review');click('#import-save');wait_for('return !document.querySelector("dialog[open]")')
        created=next(p for p in command('snapshot')['profiles'] if p['name']=='Quick imported');ids.append(created['id'])
        check(command('profile',{'id':created['id']})['config']['type']=='direct','review imports and persists the named connection through the real backend')
        click('.add-connection');click('#add-choice-file')
        file_upload([text_file('First.json','{"type":"direct","tag":"first"}'),text_file('Second.yaml','proxies: [{type: socks5, name: second, server: 127.0.0.1, port: 1080}]')])
        click('#import-review');check(js('return document.querySelectorAll(".import-row:not(.has-error)").length===2'),'mixed JSON and YAML files produce separate review rows')
        click('#import-save');wait_for('return !document.querySelector("dialog[open]")')
        ids += [p['id'] for p in command('snapshot')['profiles'] if p['name'] in ['First','second']]
        click('.add-connection');click('#add-choice-file')
        file_upload([text_file('Unicode.conf','protocol=anyconnect\nserver=https://vpn.test\nuser=Иван', 'utf-16')]);click('#import-review')
        check(js('return document.querySelectorAll(".import-row:not(.has-error)").length===1'),'UTF-16 OpenConnect files are decoded and recognized in native WebKit')
        close();click('.add-connection');click('#add-choice-file')
        file_upload([text_file('VPN.ovpn','client\ndev tun\nremote vpn.test 1194\nremote backup.test 443 tcp-client\npeer-fingerprint '+':'.join(['ab']*32)+'\npull-filter ignore route')]);click('#import-review');click('[data-import-check]');wait_for('return !!document.querySelector(".import-valid")')
        check(True,'OpenVPN with multiple remotes and a pull filter passes actual core validation')
        close();click('.add-connection');click('#add-choice-file')
        file_upload([text_file('AnyConnect.xml','<AnyConnectProfile><ServerList><HostEntry><HostName>Corporate</HostName><HostAddress>vpn.test</HostAddress><UserGroup>staff</UserGroup></HostEntry></ServerList></AnyConnectProfile>')]);click('#import-review')
        check(js('return document.querySelector(".import-name").value==="Corporate"'),'AnyConnect XML imports its named host through the native XML parser')
        close();click('.add-connection');click('#add-choice-qr');screenshot('add-qr-dark-ru')
        decoded=command('decodeQrImage',{'data':base64.b64encode(fixture.read_bytes()).decode()})
        check(len(decoded)==1 and decoded[0].startswith('vless://'),'native QR decoder reads a real image into the connection URI')
        file_upload([{'name':'QR.png','type':'image/png','data':base64.b64encode(fixture.read_bytes()).decode()}]);click('#import-review');click('[data-import-check]')
        try: wait_for('return !!document.querySelector(".import-valid")')
        except AssertionError: raise AssertionError(js('return document.querySelector(".import-row").textContent'))
        check(js('return document.querySelector(".import-name").value==="QR fixture"'),'QR file passes the actual core configuration check')
        click('#import-save');wait_for('return !document.querySelector("dialog[open]")');ids.append(next(p['id'] for p in command('snapshot')['profiles'] if p['name']=='QR fixture'))
        click('.add-connection');click('#add-choice-qr');file_upload([text_file('Broken.png','not an image')])
        check(js('return !!document.querySelector("[role=alert]")&&document.querySelector("#import-review").disabled'),'a broken QR image reports an error without importing or enabling review')
        close();click('.add-connection');click('#add-choice-link');fill('#import-title','Local subscription');fill('#import-source',f'http://127.0.0.1:{server.server_port}/sub');click('#import-review')
        wait_for('return !document.querySelector("dialog[open]")')
        state=command('snapshot');gid=next(g['id'] for g in state['groups'] if g['name']=='Local subscription');groups.append(gid)
        deadline=time.monotonic()+20
        while not any(p['groupId']==gid for p in command('snapshot')['profiles']) and time.monotonic()<deadline:time.sleep(.2)
        check(any(p['groupId']==gid for p in command('snapshot')['profiles']),'subscription action creates its group and imports YAML servers without an extra settings dialog')
        wait_for('return !!document.querySelector("[data-group-usage]")||document.querySelector(".group-strip select").value==='+json.dumps(gid))
        select('.group-strip select','all');click('.add-connection');click('#add-choice-advanced');select('#profile-type','direct');fill('#profile-name','Manual draft')
        click('[data-profile-tab=json]');fill('#profile-json','{"type":')
        click('.add-back button');click('#add-choice-link');click('#main-modal>.modal-head>button')
        check(js('return document.querySelectorAll("dialog:modal").length===2&&document.querySelector("#main-modal").inert'),'closing any method protects a dirty manual draft with a centered confirmation')
        click('[data-confirm-cancel]');click('.add-back button');click('#add-choice-advanced')
        check(js('return document.querySelector("#profile-json").value==="{\\"type\\":"'),'returning to manual editing preserves invalid unsaved JSON')
        fill('#profile-json','{"type":"direct"}');click('[data-profile-tab=main]') if js('return !!document.querySelector("[data-profile-tab=main]")') else None
        screenshot('add-manual-dark-ru')
        for language, theme in [('ru','dark'),('en','light')]:
            command('preferences',{**command('snapshot')['preferences'],'language':language,'theme':theme});wait_for('return document.documentElement.lang==='+json.dumps(language))
            for width,height in [(390,620),(1280,900)]:
                h['request']('POST',h['base']+'/window/rect',{'width':width,'height':height})
                for mode in ['link','file','qr','advanced']:
                    click('.add-back button');click('#add-choice-'+mode)
                    check(fits(),f'{mode} remains centered with accessible footer at {width}px in {language}')
                if width==390:screenshot('add-manual-narrow-'+language)
        js('const button=document.querySelector("button[form=profile-editor]");button.click();button.click()');wait_for('return !document.querySelector("#profile-editor")')
        # A completed subscription may notify after the editor releases the modal slot.
        check(js('return [...document.querySelectorAll("dialog[open]")].every(d=>d.classList.contains("subscription-updates-modal"))'), 'saving releases the editor; only the queued subscription notification may take its place')
        if js('return !!document.querySelector("dialog.subscription-updates-modal[open]")'):close()
        ids.append(next(p['id'] for p in command('snapshot')['profiles'] if p['name']=='Manual draft'))
        check(len([p for p in command('snapshot')['profiles'] if p['name']=='Manual draft']) == 1,'manual editing saves once after method switches and rapid repeated submit')
    except Exception:
        screenshot('add-before-cleanup-failure')
        state = js('return {errors:[...document.querySelectorAll("#main-modal [role=alert],#main-modal .field-error")].map(e=>e.textContent.trim()),buttons:[...document.querySelectorAll("button[form=profile-editor]")].map(e=>({disabled:e.disabled,type:e.type})),busy:document.querySelector(".connection-add-panels")?.getAttribute("aria-busy"),dialogs:document.querySelectorAll("dialog[open]").length}')
        (h['artifacts'] / 'add-completion-failure.json').write_text(json.dumps(state,ensure_ascii=False,indent=2))
        raise
    finally:
        if js('return !!document.querySelector("#main-modal")'):close()
        for gid in groups:command('deleteGroup',{'id':gid,'deleteProfiles':True})
        for pid in set(ids):command('delete',{'id':pid})
        command('preferences',initial['preferences']);select('.group-strip select','all')
        h['request']('POST',h['base']+'/window/rect',geometry);server.shutdown();server.server_close()
