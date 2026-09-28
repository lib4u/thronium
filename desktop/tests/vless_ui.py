"""Core preferences and effective configuration in the real native window."""
import json
import socket
import time


def run(h):
    command, click, select, wait_for, js, check, screenshot = (h[k] for k in ('command', 'click', 'select', 'wait_for', 'js', 'check', 'screenshot'))
    initial = command('snapshot'); ids = []; geometry = h['request']('GET', h['base'] + '/window/rect')
    source = {'type': 'vless', 'server': '127.0.0.1', 'server_port': 9, 'uuid': '00000000-0000-0000-0000-000000000001'}

    def editor(pid):
        selector = '[data-profile-menu=' + json.dumps(pid) + ']'
        wait_for('return !!document.querySelector(' + json.dumps(selector) + ')')
        js('document.querySelector(arguments[0]).scrollIntoView({block:"center"})', selector); time.sleep(.15)
        click(selector); click('#export-one'); wait_for('return !!document.querySelector("#configuration-json")')

    def close():
        click('#main-modal > .modal-head > button')
        if js('return !!document.querySelector("[data-confirm-accept]")'): click('[data-confirm-accept]')
        wait_for('return !document.querySelector("dialog[open]")')

    try:
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark'})
        wait_for('return document.documentElement.lang==="en"')
        click('.primary-nav button:last-child')
        if js('return !!document.querySelector("[data-settings-section=core]")'): click('[data-settings-section=core]')
        wait_for('return !!document.querySelector("#vless-core")')
        select('#vless-core', 'sing-box'); click('#settings-save' if js('return !!document.querySelector("#settings-save")') else '#connection-settings-save')
        wait_for('return document.querySelector("#settings-content [role=status], #connection-settings [role=status]")?.textContent.includes("Saved")')
        check(command('snapshot')['preferences']['vlessCore'] == 'sing-box', 'VLESS core setting saves through the native UI')
        h['request']('POST', h['base'] + '/refresh', {}); wait_for('return !!document.querySelector(".primary-nav")')
        click('.primary-nav button:last-child')
        if js('return !!document.querySelector("[data-settings-section=core]")'): click('[data-settings-section=core]')
        wait_for('return !!document.querySelector("#vless-core")')
        check(js('return document.querySelector("#vless-core").value==="sing-box"'), 'VLESS core survives a webview reload')
        click('.primary-nav button:first-child')
        pid = command('saveProfile', {'name': 'VLESS runtime fixture', 'groupId': 'personal', 'kind': 'sing-box-outbound', 'config': source})['id']; ids.append(pid)
        editor(pid)
        select('#profile-vless-core', 'xray'); wait_for('return !!document.querySelector("#configuration-status")')
        check(command('snapshot')['preferences']['vlessOverrides'][pid] == 'xray', 'Per-server Xray override is persisted independently of the default')
        click('#configuration-preview'); wait_for('return document.querySelector("#configuration-json").readOnly')
        preview = json.loads(js('return document.querySelector("#configuration-json").value'))
        check('dns' in preview and 'route' in preview and preview['outbounds'][0]['type'] == 'socks', 'Connection preview includes DNS, routing and the Xray bridge')
        check(js('return document.querySelector("#configuration-active").disabled'), 'Disconnected profiles cannot display an active configuration')
        close()
        with socket.socket() as guard: guard.bind(('127.0.0.1', 0)); port = guard.getsockname()[1]
        command('connectionSettings', {'mode': 'local', 'port': port})
        command('connect', {'id': pid})
        active = command('connectionConfiguration', {'id': pid, 'active': True})
        check(len(active['parts']) == 2 and active['parts'][1]['name'] == 'Xray', 'Actual connection uses the per-server Xray core')
        command('setVlessCore', {'id': pid, 'core': None})
        pending = command('connectionConfiguration', {'id': pid, 'active': False})
        check(len(pending['parts']) == 1 and command('connectionConfiguration', {'id': pid, 'active': True}) == active, 'Pending core changes affect the preview while the running request stays exact')
        check(command('profile', {'id': pid})['config'] == source, 'Core switching preserves the original server JSON')
        editor(pid); click('#configuration-active'); wait_for('return document.querySelector("#configuration-json").readOnly')
        check(json.loads(js('return document.querySelector("#configuration-json").value')) == active['parts'][0]['config'], 'Active tab displays the exact running configuration')
        close(); command('disconnect')
        command('connect', {'id': pid})
        check(len(command('connectionConfiguration', {'id': pid, 'active': True})['parts']) == 1, 'Reconnect applies the inherited sing-box core')
        command('disconnect')
        click('[data-profile-menu=' + json.dumps(pid) + ']'); click('#menu-edit-profile')
        wait_for('return !!document.querySelector("#editor-vless-core")')
        select('#editor-vless-core', 'xray'); click('.editor-modal .modal-footer .button.secondary')
        wait_for('return !!document.querySelector(".editor-modal [role=status], .editor-modal [role=alert]")')
        assert js('return !!document.querySelector(".editor-modal [role=status]")'), js('return document.querySelector(".editor-modal [role=alert]")?.textContent')
        check(command('snapshot')['preferences']['vlessOverrides'].get(pid) is None, 'Manual editor validates the proposed core without changing saved preferences')
        click('button[form=profile-editor]'); wait_for('return !document.querySelector("dialog[open]")')
        check(command('profile', {'id': pid})['vlessCore'] == 'xray' and command('profile', {'id': pid})['config'] == source, 'Manual editor saves the core and preserves the source in one operation')
        xhttp = {'protocol':'vless','settings':{'address':'127.0.0.1','port':9,'id':source['uuid'],'encryption':'none'},'streamSettings':{'network':'xhttp','security':'none','xhttpSettings':{'path':'/fixture'}}}
        xid = command('saveProfile', {'name': 'XHTTP fixture', 'groupId': 'personal', 'kind': 'xray-outbound', 'config': xhttp})['id']; ids.append(xid)
        editor(xid); select('#profile-vless-core', 'sing-box'); wait_for('return !!document.querySelector(".configuration-modal [role=alert]")')
        check(command('snapshot')['preferences']['vlessOverrides'].get(xid) is None, 'Incompatible XHTTP selection is rejected without saving an override')
        close()
        for language, theme in [('ru','light'),('en','dark')]:
            command('preferences', {**command('snapshot')['preferences'], 'language': language, 'theme': theme})
            editor(pid); click('#configuration-preview'); wait_for('return document.querySelector("#configuration-json").readOnly')
            h['request']('POST', h['base'] + '/window/rect', {'width':390,'height':620})
            check(js('const d=document.querySelector("#main-modal"),r=d.getBoundingClientRect(),b=d.querySelector(".modal-body");return r.top>=0&&r.bottom<=innerHeight+1&&b.scrollWidth<=b.clientWidth+1'), f'Effective configuration fits a narrow window in {language}/{theme}')
            screenshot(f'vless-effective-{language}'); close()
            h['request']('POST', h['base'] + '/window/rect', {'width':1280,'height':860})
    finally:
        if js('return !!document.querySelector("#main-modal")'): close()
        if command('snapshot')['running']: command('disconnect')
        for pid in ids: command('delete', {'id': pid})
        command('preferences', initial['preferences']); h['request']('POST', h['base'] + '/window/rect', geometry)
