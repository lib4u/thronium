"""Configuration editing/export, conflict protection and Amnezia titles in native WebKit."""
import base64
import json
import pathlib
import socket
import tempfile
import time
import zlib
from native_dialogs import file_dialog


def run(h):
    command, click, fill, select, wait_for, js, check, screenshot = (h[k] for k in ('command', 'click', 'fill', 'select', 'wait_for', 'js', 'check', 'screenshot'))
    request, base = h['request'], h['base']
    initial = command('snapshot'); geometry = request('GET', base + '/window/rect'); ids = []
    group = command('saveGroup', {'name': 'Configuration editor', 'subscription': None})['id']
    original = {'type': 'socks', 'server': '127.0.0.1', 'server_port': 1080, 'password': 'synthetic-key', 'future': {'keep': [1, 2]}}
    pid = command('saveProfile', {'name': 'JSON fixture', 'groupId': group, 'kind': 'sing-box-outbound', 'config': original})['id']; ids.append(pid)
    def open_editor(id=pid):
        selector = '[data-profile-menu='+json.dumps(id)+']'
        wait_for('return !!document.querySelector('+json.dumps(selector)+')')
        js('document.querySelector(arguments[0]).scrollIntoView({block:"center"})', selector); time.sleep(.15)
        click(selector); click('#export-one'); wait_for('return !!document.querySelector("#configuration-json")')
    def close():
        click('#main-modal > .modal-head > button')
        if js('return !!document.querySelector("[data-confirm-accept]")'):click('[data-confirm-accept]')
        wait_for('return !document.querySelector("dialog[open]")')
    def fits():
        return js('const d=document.querySelector("#main-modal"),r=d.getBoundingClientRect(),b=d.querySelector(".modal-body"),f=d.querySelector(".modal-footer");return Math.abs(r.x+r.width/2-innerWidth/2)<3&&Math.abs(r.y+r.height/2-innerHeight/2)<3&&r.top>=0&&r.bottom<=innerHeight+1&&b.scrollWidth<=b.clientWidth+1&&f.getBoundingClientRect().bottom<=innerHeight')
    try:
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'light'})
        request('POST', base+'/window/rect', {'width':1280,'height':860});select('.group-strip select', 'all');fill('#client-search','')
        open_editor()
        check(json.loads(js('return document.querySelector("#configuration-json").value'))==original and fits(), 'Export and edit opens the saved configuration directly in a centered JSON editor')
        fill('#configuration-json', '{"type":')
        check(js('return document.querySelector("#configuration-save").disabled&&document.querySelector("#configuration-export").disabled&&document.querySelector("#configuration-check").disabled&&!!document.querySelector("[role=alert]")'),'invalid JSON blocks saving, checking and export without losing the draft')
        click('#main-modal > .modal-head > button')
        check(js('return document.querySelectorAll("dialog:modal").length===2'),'closing modified JSON protects unsaved changes')
        click('[data-confirm-cancel]')
        check(js('return document.querySelector("#configuration-json").value==="{\\"type\\":"'),'cancelling discard retains invalid JSON verbatim')
        edited={**original,'server_port':1081,'future':{'keep':[1,2,3]}}
        fill('#configuration-json', json.dumps(edited));click('#configuration-format')
        check(json.loads(js('return document.querySelector("#configuration-json").value'))==edited, 'formatting retains unknown fields and edited values')
        click('#configuration-export');file_dialog('Save export');wait_for('return !document.querySelector("#configuration-export").disabled')
        check(not js('return !!document.querySelector("#configuration-status")'), 'cancelling file export does not report success or save the profile')
        with tempfile.TemporaryDirectory(prefix='thronium-config-export-') as directory:
            path=pathlib.Path(directory)/'config.json'
            click('#configuration-export');file_dialog('Save export', path);wait_for('return !!document.querySelector("#configuration-status")')
            check(json.loads(path.read_text())==edited and path.stat().st_mode&0o777==0o600, 'native file export writes the edited JSON with private permissions')
        check(command('profile',{'id':pid})['config']==original, 'exporting unsaved edits leaves the stored profile unchanged')
        # A concurrent rename/move/favorite must not be overwritten by a JSON-only save.
        command('saveProfile',{'expectedRevision':command('profile',{'id':pid})['expectedRevision'],'id':pid,'name':'Renamed elsewhere','groupId':'personal','kind':'sing-box-outbound','config':original});command('favorite',{'id':pid})
        click('#configuration-save');wait_for('return !!document.querySelector("#configuration-reload")')
        check(json.loads(js('return document.querySelector("#configuration-json").value'))==edited,'concurrent metadata changes retain the unsaved JSON draft')
        click('#configuration-reload');click('[data-confirm-accept]');wait_for('return !document.querySelector("#configuration-reload")')
        fill('#configuration-json',json.dumps(edited));click('#configuration-save');wait_for('return !document.querySelector("dialog[open]")')
        saved=command('profile',{'id':pid})
        check(saved['config']==edited and saved['name']=='Renamed elsewhere' and saved['groupId']=='personal' and saved['favorite'],'saving after explicit reload preserves the current name, group and favorite')
        open_editor();fill('#configuration-json','{"type":"direct"}');click('#configuration-check');wait_for('return !!document.querySelector("#configuration-status")')
        check(command('profile',{'id':pid})['config']==edited,'actual core validation accepts the draft without saving it')
        click('#configuration-save');wait_for('return !document.querySelector("dialog[open]")')
        request('POST',base+'/refresh',{});wait_for('return !!document.querySelector(".add-connection")')
        check(command('profile',{'id':pid})['config']=={'type':'direct'},'saved JSON survives a native webview reload')
        open_editor();fill('#configuration-json','{"type":"direct","tag":"my draft"}')
        command('saveProfile',{'expectedRevision':command('profile',{'id':pid})['expectedRevision'],'id':pid,'name':'Renamed elsewhere','groupId':'personal','kind':'sing-box-outbound','config':{'type':'direct','tag':'external update'}})
        click('#configuration-save');wait_for('return !!document.querySelector(".configuration-modal [role=alert]")')
        check(command('profile',{'id':pid})['config']['tag']=='external update' and js('return document.querySelector("#configuration-json").value.includes("my draft")'),'concurrent configuration changes block stale saves and preserve the draft for export')
        close()
        with socket.socket() as listener:listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
        command('preferences',{**command('snapshot')['preferences'],'inboundPort':port});command('connect',{'id':pid})
        open_editor();fill('#configuration-json','{"type":"direct","tag":"active edit"}');click('#configuration-save');wait_for('return !!document.querySelector(".configuration-modal [role=alert]")')
        check(command('snapshot')['running']==pid and command('profile',{'id':pid})['config']['tag']=='external update','editing an active profile is rejected without disconnecting it or replacing its configuration')
        close();command('disconnect')
        full={'inbounds':[],'outbounds':[],'routing':{'domainStrategy':'AsIs'},'future':True}
        xid=command('saveProfile',{'name':'Full Xray','groupId':group,'kind':'xray-config','config':full})['id'];ids.append(xid)
        open_editor(xid);full['routing']['domainStrategy']='IPIfNonMatch';fill('#configuration-json',json.dumps(full));click('#configuration-save');wait_for('return !document.querySelector("dialog[open]")')
        check(command('profile',{'id':xid})['kind']=='xray-config' and command('profile',{'id':xid})['config']==full,'full Xray configuration retains its kind, routing and unknown fields')
        key=base64.b64encode(bytes([7])*32).decode()
        wg=f'[Interface]\nPrivateKey={key}\nAddress=10.0.0.2/32\nJc=4\n[Peer]\nPublicKey={key}\nEndpoint=127.0.0.1:51820\nAllowedIPs=0.0.0.0/0'
        wrapped=json.dumps({'description':'🇳🇱 Нидерланды AWG','containers':[{'awg':{'last_config':json.dumps({'config':wg})}}]},ensure_ascii=False).encode()
        uri='vpn://'+base64.urlsafe_b64encode(len(wrapped).to_bytes(4,'big')+zlib.compress(wrapped)).decode().rstrip('=')
        click('.add-connection');click('#add-choice-link');fill('#import-source',uri);click('#import-review')
        check(js('return document.querySelector(".import-name").value==="🇳🇱 Нидерланды AWG"'),'native Amnezia import uses the encoded location rather than the endpoint IP')
        click('#import-save');wait_for('return !document.querySelector("dialog[open]")');awg=next(p for p in command('snapshot')['profiles'] if p['name']=='🇳🇱 Нидерланды AWG');ids.append(awg['id'])
        check(js('const row=document.querySelector(arguments[0]).closest(".connection-row");return row.querySelector(".profile-emoji").textContent==="🇳🇱"&&row.querySelector("strong").textContent==="Нидерланды AWG"','[data-profile-menu='+json.dumps(awg['id'])+']'),'saved Amnezia location and flag appear correctly in the server list')
        for language,theme in [('ru','light'),('en','dark')]:
            command('preferences',{**command('snapshot')['preferences'],'language':language,'theme':theme});open_editor()
            for width,height in [(1280,860),(390,620)]:
                request('POST',base+'/window/rect',{'width':width,'height':height})
                check(fits(),f'JSON editor and export/save buttons fit {width}px in {language}/{theme}')
                screenshot(f'configuration-{language}-{width}')
            close();request('POST',base+'/window/rect',{'width':1280,'height':860})
        for name,payload in [('exportConfiguration',{'config':[],'destination':'preview'}),('exportConfiguration',{'config':{'type':'direct'},'destination':'invalid'})]:
            try:command(name,payload);raise AssertionError('invalid export accepted')
            except RuntimeError:pass
        check(True,'native configuration export rejects non-object JSON and invalid destinations')
    finally:
        if js('return !!document.querySelector("#main-modal")'):close()
        if command('snapshot')['running']:command('disconnect')
        for id in ids:command('delete',{'id':id})
        command('deleteGroup',{'id':group,'deleteProfiles':True});command('preferences',initial['preferences']);request('POST',base+'/window/rect',geometry)
