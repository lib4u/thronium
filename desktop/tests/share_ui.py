"""Native URI/QR/WG sharing, file dialogs, clipboard and exact reimport."""
import base64
import json
import pathlib
import socket
import tempfile
import time
from native_dialogs import file_dialog


def run(h):
    command, click, fill, select, wait_for, js, check, screenshot = (h[k] for k in ('command', 'click', 'fill', 'select', 'wait_for', 'js', 'check', 'screenshot'))
    request, base = h['request'], h['base']
    initial=command('snapshot'); geometry=request('GET',base+'/window/rect')
    group=command('saveGroup',{'name':'Share fixtures','subscription':None})['id']
    target=command('saveGroup',{'name':'Shared imports','subscription':None})['id']
    config={'type':'vless','server':'127.0.0.1','server_port':443,'uuid':'bf422fe4-1a5c-4b64-bc33-43c18a1b9dd1','packet_encoding':'xudp','tls':{'enabled':True,'server_name':'example.test'}}
    pid=command('saveProfile',{'name':'Share 🦊','groupId':group,'kind':'sing-box-outbound','config':config})['id']
    key=base64.b64encode(bytes([7])*32).decode()
    wg={'type':'wireguard','private_key':key,'address':['10.0.0.2/32'],'amnezia_wg':{'jc':3,'h1':'1-100'},'peers':[{'public_key':key,'address':'127.0.0.1','port':51820,'allowed_ips':['0.0.0.0/0']},{'public_key':key,'address':'::1','port':51821,'allowed_ips':['::/0']}]}
    wid=command('saveProfile',{'name':'WG export','groupId':group,'kind':'sing-box-outbound','config':wg})['id']
    original_clipboard=None
    try:original_clipboard=command('readClipboard')
    except RuntimeError:pass
    def editor(id):
        selector='[data-profile-menu='+json.dumps(id)+']'
        wait_for('return !!document.querySelector('+json.dumps(selector)+')');click(selector);click('#export-one');wait_for('return !!document.querySelector("#configuration-share")')
    def share_close():
        click('dialog:not(#main-modal) > .modal-head > button');wait_for('return document.querySelectorAll("dialog[open]").length===1')
    def editor_close():
        click('#main-modal > .modal-head > button')
        if js('return !!document.querySelector("[data-confirm-accept]")'):click('[data-confirm-accept]')
        wait_for('return !document.querySelector("dialog[open]")')
    def import_text(text):
        click('.add-connection');click('#add-choice-link');fill('#import-source',text);select('#import-group',target);click('#import-review')
        check(js('return !!document.querySelector(".import-select")&&!document.querySelector(".import-acknowledge")'),'shared content enters native import preview without loss warnings')
        click('#import-save');wait_for('return !document.querySelector("dialog[open]")')
    try:
        command('preferences',{**initial['preferences'],'language':'en','theme':'dark'})
        command('setVlessCore',{'id':pid,'core':'sing-box'})
        wait_for('return document.documentElement.lang==="en"');select('.group-strip select','all');fill('#client-search','')
        editor(pid);edited={**config,'server_port':8443};fill('#configuration-json',json.dumps(edited));click('#configuration-share')
        # Sharing opens after the saved profile is read; wait for the nested dialog.
        wait_for('return document.querySelectorAll("dialog[open]").length===2')
        check(js('return document.querySelector("#main-modal").inert&&!document.querySelector("#export-content")&&!document.querySelector("#export-qr-image")'),'nested export protects the draft and hides credentials until requested')
        click('#export-copy');wait_for('return !!document.querySelector("#export-status")');uri=command('readClipboard')
        check(uri.startswith('vless://') and ':8443?' in uri and command('profile',{'id':pid})['config']==config,'URI export uses unsaved editor values without changing the saved profile')
        click('#export-qr');wait_for('return !!document.querySelector("#export-qr-image")')
        data=js('return document.querySelector("#export-qr-image").src')
        check(command('decodeQrImage',{'data':data.split(',',1)[1]})==[uri],'actual exported QR decodes to the exact URI')
        if original_clipboard is not None:
            click('#export-qr-copy');wait_for('return !!document.querySelector("#export-status")')
            check(command('readQrClipboard')==[uri],'native image clipboard contains the scannable exported QR')
        with tempfile.TemporaryDirectory(prefix='thronium-share-files-') as folder:
            path=pathlib.Path(folder)/'qr.png'
            click('#export-qr-save');file_dialog('Save QR code');wait_for('return !document.querySelector("#export-qr-save").disabled')
            check(not js('return !!document.querySelector("#export-status")'),'cancelling QR save does not report a saved file')
            click('#export-qr-save');file_dialog('Save QR code',path);wait_for('return !!document.querySelector("#export-status")')
            check(path.stat().st_mode&0o777==0o600 and command('decodeQrImage',{'data':base64.b64encode(path.read_bytes()).decode()})==[uri],'saved PNG has private permissions and decodes to the complete link')
        select('#export-format','thronium-link');check(not js('return !!document.querySelector("#export-qr-image")'),'changing format hides the previous QR')
        click('#export-copy');wait_for('return !!document.querySelector("#export-status")');portable=command('readClipboard')
        bundle=json.loads(base64.urlsafe_b64decode(portable.split('/profiles/',1)[1]+'==='))
        check(bundle['profiles'][0]['config']==edited and bundle['profiles'][0]['vlessCore']=='sing-box','portable link keeps the exact source and selected VLESS core')
        share_close();check(js('return JSON.parse(document.querySelector("#configuration-json").value).server_port===8443&&!document.querySelector("#main-modal").inert'),'closing sharing restores focus and the unsaved editor');editor_close()
        import_text(portable.replace("thronium://", "throne://", 1))
        imported=[command('profile',{'id':p['id']}) for p in command('snapshot')['profiles'] if p['groupId']==target]
        check(len(imported)==1 and imported[0]['config']==edited and command('snapshot')['preferences']['vlessOverrides'][imported[0]['id']]=='sing-box','native OS-normalized portable link creates a new profile and retains VLESS core selection')
        editor(wid);click('#configuration-share');click('#export-copy');wait_for('return !!document.querySelector("dialog:not(#main-modal) [role=alert]")')
        check(js('return document.querySelector("dialog:not(#main-modal) [role=alert]").textContent.includes("one WireGuard peer")'),'a multi-peer WG profile cannot silently become a single-peer URI')
        select('#export-format','wireguard');click('#export-reveal');wait_for('return !!document.querySelector("#export-content")');conf=js('return document.querySelector("#export-content").textContent')
        with tempfile.TemporaryDirectory(prefix='thronium-share-wg-') as folder:
            path=pathlib.Path(folder)/'thronium.conf';click('#export-save');file_dialog('Save export',path);wait_for('return !!document.querySelector("#export-status")')
            check(path.read_text()==conf and conf.count('[Peer]')==2 and 'H1 = 1-100' in conf and path.stat().st_mode&0o777==0o600,'WG/AWG file saves all peers, IPv6 and Amnezia fields with private permissions')
        share_close();editor_close();import_text(conf)
        imported=[command('profile',{'id':p['id']}) for p in command('snapshot')['profiles'] if p['groupId']==target]
        check(any(p['config']==wg for p in imported),'actual .conf reimport retains every WireGuard/Amnezia parameter')
        # Unknown JSON must survive portable export and must prevent a lossy native link.
        editor(pid);unknown={**config,'future':{'secret':'synthetic-hidden'}};fill('#configuration-json',json.dumps(unknown));click('#configuration-share');click('#export-copy');wait_for('return !!document.querySelector("dialog:not(#main-modal) [role=alert]")')
        check(js('const t=document.querySelector("dialog:not(#main-modal) [role=alert]").textContent;return t.includes("future.secret")&&!t.includes("synthetic-hidden")'),'unsupported fields are explained without exposing their values')
        share_close();editor_close()
        for language,theme in [('ru','light'),('en','dark')]:
            command('preferences',{**command('snapshot')['preferences'],'language':language,'theme':theme});wait_for('return document.documentElement.lang==='+json.dumps(language));editor(pid);click('#configuration-share');click('#export-qr');wait_for('return !!document.querySelector("#export-qr-image")')
            request('POST',base+'/window/rect',{'width':390,'height':720})
            check(js('const d=document.querySelector("dialog:not(#main-modal)"),b=d.querySelector(".modal-body");return b.scrollWidth<=b.clientWidth+1&&d.getBoundingClientRect().bottom<=innerHeight+1&&d.querySelector(".modal-footer").getBoundingClientRect().bottom<=innerHeight+1'),f'QR export fits the narrow native window in {language}/{theme}')
            screenshot('share-'+language+'-390');share_close();editor_close();request('POST',base+'/window/rect',{'width':1280,'height':860})
        editor(pid);fill('#configuration-json',json.dumps({**config,'future':'a'*4000}));click('#configuration-share');select('#export-format','thronium-link');click('#export-qr');wait_for('return !!document.querySelector("dialog:not(#main-modal) [role=alert]")')
        check(js('return !document.querySelector("#export-qr-image")&&document.querySelector("dialog:not(#main-modal) [role=alert]").textContent.includes("too large")'),'oversized QR is rejected with a copy/file alternative');share_close();editor_close()
        # Exporting while a core runs must leave its session and effective configuration intact.
        direct=command('saveProfile',{'name':'Share running','groupId':group,'kind':'sing-box-outbound','config':{'type':'direct'}})['id']
        with socket.socket() as listener:listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
        command('preferences',{**command('snapshot')['preferences'],'inboundPort':port});command('connect',{'id':direct})
        active=command('connectionConfiguration',{'id':direct,'active':True});editor(pid);click('#configuration-share');click('#export-copy');wait_for('return !!document.querySelector("#export-status")');share_close();editor_close()
        check(command('snapshot')['running']==direct and command('connectionConfiguration',{'id':direct,'active':True})==active,'sharing another profile leaves the running core and active configuration unchanged');command('disconnect')
        for name,payload in [('exportSharedText',{'text':'test','format':'bad','destination':'preview'}),('exportQr',{'text':'test','destination':'bad'})]:
            try:command(name,payload);raise AssertionError('Invalid request accepted')
            except RuntimeError:pass
        check(True,'native export boundary rejects invalid formats and destinations')
    finally:
        if original_clipboard is not None:command('writeClipboard',{'text':original_clipboard})
        if command('snapshot')['running']:command('disconnect')
        command('deleteGroup',{'id':group,'deleteProfiles':True});command('deleteGroup',{'id':target,'deleteProfiles':True})
        command('preferences',initial['preferences']);request('POST',base+'/window/rect',geometry)
