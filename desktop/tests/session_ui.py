"""Compact native connection panel and direct access to the real profile editor."""
import copy
import json
import socket


def run(h):
    command, click, fill, select, wait_for, js, check, screenshot = (h[k] for k in ('command', 'click', 'fill', 'select', 'wait_for', 'js', 'check', 'screenshot'))
    request, base = h['request'], h['base']
    initial = command('snapshot'); ids = []
    def add(name, kind, config):
        pid = command('saveProfile', {'name': name, 'kind': kind, 'groupId': 'personal', 'config': config})['id']; ids.append(pid); return pid
    def choose(pid):
        command('select', {'id': pid})
        wait_for('return document.querySelector("[data-session-profile]")?.dataset.sessionProfile === ' + json.dumps(pid))
    def field(path, prop='value'):
        return js('return document.querySelector(arguments[0])[arguments[1]]', '[data-field='+json.dumps(path)+']', prop)
    def close():
        click('#main-modal > .modal-head .icon-button')
        wait_for('return !document.querySelector("dialog")')
    def fits():
        return js('const p=document.querySelector(".session-pane");return document.documentElement.scrollWidth<=innerWidth && p.scrollWidth<=p.clientWidth')
    try:
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]
        command('preferences', {**initial['preferences'], 'language': 'ru', 'theme': 'dark', 'connectionMode': 'local', 'inboundPort': port})
        request('POST', base + '/window/rect', {'width':1280,'height':860})
        click('.primary-nav button:first-child')
        wait_for('return document.documentElement.lang==="ru"')
        check(js('return document.querySelector("#session-edit-profile").disabled'), 'empty connection card disables profile editing')
        direct = add('🇳🇱 Компактное подключение', 'sing-box-outbound', {'type':'direct'})
        choose(direct)
        check(js('return document.querySelector(".session-server-icon").textContent==="🇳🇱" && document.querySelector(".destination-city").textContent==="Компактное подключение"'), 'connection card moves the leading emoji into its icon')
        check(js('return document.querySelector(".destination-country > span").textContent==="Личные"'), 'connection card localizes the personal group consistently with the library')
        check(js('return document.querySelector(".session-card .session-metrics") && document.querySelector(".connection-path").getBoundingClientRect().height<45'), 'session metrics sit inside the card and the connection path is a thin row')
        check(fits() and js('const p=document.querySelector(".session-pane"),a=p.querySelector(".pane-heading").getBoundingClientRect(),b=p.querySelector(".connection-options").getBoundingClientRect();return b.bottom-a.top<610'), 'compact controls fit the desktop without wide gaps or overflow')
        click('.power-button')
        wait_for('return document.querySelector(".power-button").getAttribute("aria-pressed")==="true" && !document.querySelector(".power-button").disabled')
        active = command('snapshot')
        click('#session-edit-profile'); wait_for('return !!document.querySelector("#profile-editor")')
        check(js('return document.querySelector("#profile-name").value==="🇳🇱 Компактное подключение" && document.querySelector("#profile-type").value==="direct"'), 'connection parameters open the existing selected profile in the full editor')
        check(command('snapshot')['running']==direct and command('snapshot')['since']==active['since'], 'opening the editor preserves the active connection')
        fill('#profile-name','🇳🇱 Изменённое подключение')
        check(js('return !!document.querySelector("#editor-running-note") && document.querySelector("button[form=profile-editor]").disabled'), 'an active profile explains how to save before submitting changes')
        click('#editor-disconnect')
        wait_for('return !document.querySelector("#editor-running-note") && !document.querySelector("button[form=profile-editor]").disabled')
        check(js('return document.querySelector("#profile-name").value==="🇳🇱 Изменённое подключение"') and not command('snapshot')['running'], 'explicit disconnect keeps the profile draft ready to save')
        click('button[form=profile-editor]'); wait_for('return !document.querySelector("dialog")')
        check(command('profile', {'id':direct})['name']=='🇳🇱 Изменённое подключение' and len(command('snapshot')['profiles'])==1, 'saving from the connection card updates the same profile without duplicating it')
        xconfig={'protocol':'vless','settings':{'vnext':[{'address':'127.0.0.1','port':443,'users':[{'id':'00000000-0000-0000-0000-000000000001','encryption':'none','flow':'','email':'retained'}]}]},'streamSettings':{'network':'xhttp','security':'reality','xhttpSettings':{'path':'/keep','mode':'auto','extra':{'noSSEHeader':True}},'realitySettings':{'serverName':'example.test','publicKey':'fixture','shortId':'00','fingerprint':'chrome'}}}
        xray=add('🇩🇪 VLESS / Xray', 'xray-outbound', xconfig); choose(xray)
        click('#session-edit-profile'); wait_for('return !!document.querySelector("#profile-type")')
        check(js('return document.querySelector("#profile-type").value==="xrayvless"') and field("settings.vnext.0.address")=="127.0.0.1", 'standard imported Xray VLESS opens structured fields instead of an opaque JSON-only form')
        check(js('return !!document.querySelector(".editor-section-heading #editor-vless-core") && [...document.querySelectorAll("[data-profile-tab]")].map(e=>e.dataset.profileTab).join(",")==="main,transport,tls,mux,json"'), 'editor keeps the prototype tabs and places the core selector in the section heading')
        screenshot('session-editor-xray-dark-ru')
        fill('[data-field="settings.vnext.0.port"]','8443')
        click('[data-profile-tab=transport]')
        check(field("streamSettings.xhttpSettings.path")=="/keep", 'XHTTP settings are available through the same editor')
        click('[data-profile-tab=json]')
        actual=json.loads(js('return document.querySelector("#profile-json").value'))
        expected=copy.deepcopy(xconfig);expected['settings']['vnext'][0]['port']=8443
        check(actual==expected, 'field edits preserve credentials, extra XHTTP parameters and the original nested Xray shape')
        click('button[form=profile-editor]'); wait_for('return !document.querySelector("dialog")')
        check(command('profile',{'id':xray})['config']==expected, 'the native backend persists edits from the structured Xray form')
        awgconfig={'type':'wireguard','address':['10.0.0.2/32'],'private_key':'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=','peers':[{'address':'127.0.0.1','port':51820,'public_key':'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=','allowed_ips':['0.0.0.0/0']}],'amnezia_wg':{'jc':4,'s3':10,'s4':20,'h1':'100-200','header_protection_key':'private-fixture','rekey_after_time':'20-30'}}
        awg=add('AmneziaWG 3.1', 'sing-box-outbound', awgconfig);choose(awg)
        check(js('return !!document.querySelector(".session-server-icon .icon")'), 'profiles without a leading emoji use the default server icon')
        click('#session-edit-profile');wait_for('return !!document.querySelector("#profile-type")')
        check(js('return document.querySelector("#profile-type").value==="amneziawg"'), 'AmneziaWG opens its own protocol editor from the card')
        click('[data-profile-tab=peers]')
        check(field("peers.0.address")=="127.0.0.1", 'WireGuard peer address and keys are available in a separate section')
        click('[data-profile-tab=amnezia]')
        check(field("amnezia_wg.rekey_after_time")=="20-30" and field("amnezia_wg.header_protection_key", "type")=="password" and field("amnezia_wg.s4")=="20", 'AWG 3.x ranges, packet parameters and masked secrets match the Throne editor capabilities')
        close(); screenshot('session-compact-dark-ru')
        command('preferences',{**command('snapshot')['preferences'],'language':'en','theme':'light'})
        wait_for('return document.documentElement.lang==="en"')
        screenshot('session-compact-light-en')
        click('.session-diagnostics');wait_for('return !!document.querySelector(".feature-table-wrap")')
        click('.primary-nav button:first-child')
        click('.connection-option:first-child .network-mode');wait_for('return !!document.querySelector("#route-profile-select")')
        click('.primary-nav button:first-child')
        click('.connection-option:nth-child(2) .network-mode');wait_for('return !!document.querySelector("#connection-mode")')
        click('.primary-nav button:first-child')
        for width,height in [(900,700),(390,844)]:
            request('POST',base+'/window/rect',{'width':width,'height':height})
            check(fits(),f'compact connection panel fits {width}px')
            click('#session-edit-profile');wait_for('return !!document.querySelector("#profile-editor")')
            check(js('const d=document.querySelector("dialog"),r=d.getBoundingClientRect();return r.left>=0&&r.right<=innerWidth&&r.top>=0&&r.bottom<=innerHeight&&d.scrollWidth<=d.clientWidth'), f'profile editor stays centered and fits {width}px')
            close()
        screenshot('session-compact-narrow-en')
    finally:
        # All state belongs to the disposable WebDriver instance.
        if js('return !!document.querySelector("dialog[open]")'):
            js('document.querySelectorAll("dialog[open]").forEach(d=>d.close())')
        command('disconnect')
        for pid in ids: command('delete',{'id':pid})
        command('preferences',initial['preferences'])
        if initial['selected']:command('select',{'id':initial['selected']})
        request('POST',base+'/window/rect',{'width':1280,'height':860})
        click('.primary-nav button:first-child')
