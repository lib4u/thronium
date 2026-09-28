"""Diagnostic-only actual WebView select overflow probe; no Core Start or VPN."""
import contextlib
import json
import time


def probe_existing(h, label):
    """Measure the existing full-suite dialog; restore its original inline style."""
    js = h['js']
    result = {'label': label, 'diagnosticOnly': True, 'samples': []}
    original = js('return document.querySelector("#vpn-otp-entry").getAttribute("style")')
    def capture(stage):
        value = js('''const s=document.querySelector('#vpn-otp-entry'),b=s.closest('.modal-body');
            const keys=['display','position','width','minWidth','maxWidth','boxSizing','overflow','overflowX','overflowY','textOverflow','whiteSpace','appearance','webkitAppearance','paddingLeft','paddingRight','fontFamily','fontSize','lineHeight','flex','alignSelf'];
            const shape=e=>({tag:e.tagName,id:e.id,className:e.className,rect:e.getBoundingClientRect().toJSON(),
                clientWidth:e.clientWidth,scrollWidth:e.scrollWidth,computed:Object.fromEntries(keys.map(k=>[k,getComputedStyle(e)[k]]))});
            return {width:innerWidth,height:innerHeight,activeElement:document.activeElement?.id,
                selectedText:s.selectedOptions[0]?.textContent,optionTexts:[...s.options].map(o=>o.textContent),
                body:shape(b),label:shape(s.closest('label')),select:shape(s),shadowRootPresent:!!s.shadowRoot,
                descendants:[...s.querySelectorAll('*')].map(shape)};''')
        result['samples'].append({'stage': stage, 'value': value})
        h['screenshot']('otp-existing-' + label + '-' + stage)
    try:
        capture('before')
        for name, style in [('overflow', 'overflow:hidden'), ('ellipsis', 'text-overflow:ellipsis'),
                            ('both', 'overflow:hidden;text-overflow:ellipsis')]:
            js('document.querySelector("#vpn-otp-entry").style.cssText=arguments[0]', style)
            time.sleep(.3)
            capture(name)
    finally:
        js('const s=document.querySelector("#vpn-otp-entry");if(arguments[0]===null)s.removeAttribute("style");else s.setAttribute("style",arguments[0])', original)
        time.sleep(.3)
        capture('restored')
        (h['artifacts'] / ('otp-existing-' + label + '-audit.json')).write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')


def run(h):
    command, click, wait_for, js, check = (h[k] for k in ('command', 'click', 'wait_for', 'js', 'check'))
    initial = command('snapshot')
    group = command('saveGroup', {'name': 'OTP picker layout diagnostic', 'subscription': None})['id']
    otp_id = None
    audit = {'diagnosticOnly': True, 'actualVpnAuthenticationClaimed': False, 'samples': []}
    try:
        command('preferences', {**initial['preferences'], 'language': 'ru', 'theme': 'dark'})
        otp_id = command('otpSave', {'value': {'name': 'Native HOTP — следующий шаг updated', 'issuer': 'Owned VPN fixture',
            'secret': 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 'algorithm': 'SHA1', 'type': 'hotp', 'digits': 6, 'period': 30, 'counter': '19'}})['id']
        profile = command('saveProfile', {'name': 'Owned OpenVPN automatic HOTP', 'groupId': group,
            'kind': 'sing-box-outbound', 'config': {'type': 'openvpn-client', 'server': '127.0.0.1', 'server_port': 1194,
                'username': 'synthetic-layout-user', 'password': 'synthetic-layout-password'}})['id']
        view = command('getVpnOtpBinding', {'profileId': profile})
        command('saveVpnOtpBinding', {'profileId': profile, 'editToken': view['editToken'],
            'otpId': otp_id, 'otpRevision': command('otpGet', {'id': otp_id})['revision']})
        click('.primary-nav button:first-child')
        selector = '[data-profile-menu=' + json.dumps(profile) + ']'
        wait_for('return !!document.querySelector(' + json.dumps(selector) + ')')
        js('document.querySelector(arguments[0]).scrollIntoView({block:"center",behavior:"instant"})', selector)
        click(selector)
        click('#menu-vpn-otp-profile')
        wait_for('return !!document.querySelector("#vpn-otp-entry:not(:disabled)")')

        def capture(label):
            value = js('''const s=document.querySelector('#vpn-otp-entry'),b=s.closest('.modal-body');
                const keys=['display','position','width','minWidth','maxWidth','boxSizing','overflow','overflowX','overflowY','textOverflow','whiteSpace','appearance','webkitAppearance','paddingLeft','paddingRight','fontFamily','fontSize','lineHeight','flex','alignSelf'];
                const shape=e=>({tag:e.tagName,id:e.id,className:e.className,rect:e.getBoundingClientRect().toJSON(),
                    clientWidth:e.clientWidth,scrollWidth:e.scrollWidth,computed:Object.fromEntries(keys.map(k=>[k,getComputedStyle(e)[k]]))});
                return {width:innerWidth,height:innerHeight,activeElement:document.activeElement?.id,
                    selectedText:s.selectedOptions[0]?.textContent,optionCount:s.options.length,
                    body:shape(b),label:shape(s.closest('label')),select:shape(s),shadowRootPresent:!!s.shadowRoot,
                    descendants:[...s.querySelectorAll('*')].map(shape)};''')
            audit['samples'].append({'stage': label, 'value': value})
            return value

        for index in range(3):
            h['request']('POST', h['base'] + '/window/rect', {'width': 1120, 'height': 844})
            time.sleep(.2)
            capture('wide-' + str(index))
            h['request']('POST', h['base'] + '/window/rect', {'width': 390, 'height': 844})
            time.sleep(.4)
            capture('narrow-' + str(index))
        h['screenshot']('otp-select-before-style-probe')
        baseline_style = js('return document.querySelector("#vpn-otp-entry").getAttribute("style")')
        for name, style in [('overflow', 'overflow:hidden'), ('ellipsis', 'text-overflow:ellipsis'),
                            ('both', 'overflow:hidden;text-overflow:ellipsis')]:
            js('document.querySelector("#vpn-otp-entry").style.cssText=arguments[0]', style)
            time.sleep(.3)
            capture(name)
            h['screenshot']('otp-select-probe-' + name)
        js('const s=document.querySelector("#vpn-otp-entry");if(arguments[0]===null)s.removeAttribute("style");else s.setAttribute("style",arguments[0])', baseline_style)
        time.sleep(.4)
        capture('restored-baseline')
        h['screenshot']('otp-select-restored-baseline')
        check(command('snapshot')['running'] is None and command('otpGet', {'id': otp_id})['counter'] == '19',
              'diagnostic select style measurements do not connect a VPN or consume HOTP; original inline style restored')
    finally:
        (h['artifacts'] / 'otp-select-layout-audit.json').write_text(json.dumps(audit, ensure_ascii=False, indent=2) + '\n')
        with contextlib.suppress(Exception):
            if js('return !!document.querySelector("#vpn-otp-close")'):
                click('#vpn-otp-close')
            command('deleteGroup', {'id': group, 'deleteProfiles': True})
            if otp_id:
                command('otpRemove', {'id': otp_id, 'revision': command('otpGet', {'id': otp_id})['revision']})
            command('preferences', initial['preferences'])
