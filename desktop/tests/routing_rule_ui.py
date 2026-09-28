"""Compact routing constructor against the real WebKit window and core validation."""
import json


def run(h):
    command, click, fill, select, wait_for, js, check, screenshot = (h[k] for k in ('command', 'click', 'fill', 'select', 'wait_for', 'js', 'check', 'screenshot'))
    initial=command('snapshot'); routing=command('routing'); old_warp=command('settings')['intercept']; geometry=h['request']('GET',h['base']+'/window/rect')
    def close():
        click('#main-modal > .modal-head > button')
        if js('return !!document.querySelector("[data-confirm-accept]")'):click('[data-confirm-accept]')
        wait_for('return !document.querySelector("dialog[open]")')
    def create(name):
        click('#route-add-rule');fill('#rule-name',name);fill('[data-route-field=domain_suffix]','example.test')
    def save():
        js('const b=document.querySelector("#rule-save");b.click();b.click()');wait_for('return !document.querySelector("dialog[open]")',timeout=30)
    def saved(name):
        state=command('routing');return next(r for p in state['profiles'] if p['id']==state['active'] for r in p['rules'] if r['name']==name)
    def fits():
        return js('const d=document.querySelector("#main-modal"),r=d.getBoundingClientRect(),b=d.querySelector(".modal-body"),f=d.querySelector(".modal-footer");return Math.abs(r.x+r.width/2-innerWidth/2)<3&&Math.abs(r.y+r.height/2-innerHeight/2)<3&&r.top>=0&&r.bottom<=innerHeight+1&&b.scrollWidth<=b.clientWidth+1&&f.getBoundingClientRect().bottom<=innerHeight')
    try:
        command('preferences',{**initial['preferences'],'language':'en','theme':'light'})
        wait_for('return document.documentElement.lang==="en"&&document.documentElement.dataset.theme==="light"')
        h['request']('POST',h['base']+'/window/rect',{'width':1280,'height':900})
        click('.primary-nav button:nth-child(2)');wait_for('return !!document.querySelector("#route-add-rule")')
        click('#route-local');wait_for('return !!document.querySelector(".route-rule-modal")')
        check(js('const m=document.querySelector(".route-rule-modal").textContent;return m.includes("New rule")&&!m.includes("Edit rule")'),'the local network preset opens as a new rule')
        elsewhere=command('routing');active=next(p for p in elsewhere['profiles'] if p['id']==elsewhere['active']);active['name']=active['name']+' · elsewhere';command('saveRouting',elsewhere)
        __import__('time').sleep(1.5);save()
        state=command('routing');current=next(p for p in state['profiles'] if p['id']==state['active'])
        check(current['name'].endswith(' · elsewhere') and any(r['config'].get('ip_is_private') for r in current['rules']),'a preset saved while routing changed elsewhere keeps that change instead of failing as stale')
        create('Compact route')
        check(fits() and js('const d=document.querySelector("#main-modal"),a=document.querySelector("#rule-action").getBoundingClientRect(),t=d.querySelector(".route-target").getBoundingClientRect();return Math.abs(d.getBoundingClientRect().width-830)<1&&Math.abs(a.width-t.width)<1&&a.top===t.top&&d.querySelector("[data-route-field=domain_suffix]").getBoundingClientRect().height<=42'),'rule modal uses the mockup width, compact condition row and equal action columns')
        check(js('return !!document.querySelector("#rule-name").placeholder&&document.querySelector("#rule-add-condition").classList.contains("text-button")&&document.querySelector("[data-route-field=override_port]").getClientRects().length&&!document.querySelector("#main-modal .feature-tabs")'),'primary action options are immediately visible with a lightweight Add condition control')
        fill('[data-route-field=domain_suffix]','example.test, other.test\nthird.test')
        click('#rule-add-condition');select('[data-route-condition="1"]','process_path_regex')
        expression=r'/opt/[a-z]{1,3}/browser'
        fill('[data-route-field=process_path_regex]',expression)
        select('.route-rule-modal .route-target','direct');fill('[data-route-field=override_port]','70000')
        select('#rule-action','reject');select('[data-route-field=method]','drop');click('[data-route-field=no_drop]');select('#rule-action','route')
        check(js('return document.querySelector("[data-route-field=override_port]").value==="70000"&&document.querySelector(".route-rule-modal .route-target").value==="direct"'),'switching actions preserves an unfinished invalid port and the outbound selection')
        click('#rule-save')
        check(js('return !!document.querySelector("dialog[open]")&&document.querySelector("[data-route-field=override_port]").getAttribute("aria-invalid")==="true"'),'invalid action parameters block saving')
        fill('[data-route-field=override_port]','443');click('[data-rule-tab=json]')
        config=json.loads(js('return document.querySelector("#rule-json").value'))
        check(config['domain_suffix']==['example.test','other.test','third.test'] and config['process_path_regex']==[expression] and config['override_port']==443,'compact input parses comma-separated domains while preserving commas inside regular expressions')
        fill('#rule-json','{"domain_suffix":');click('[data-rule-tab=fields]')
        check(js('return document.querySelector("#rule-json").value==="{\\"domain_suffix\\":"&&!!document.querySelector("[role=alert]")'),'invalid JSON remains intact when returning to the constructor is rejected')
        fill('#rule-json',json.dumps(config));click('[data-rule-tab=fields]');select('#rule-action','reject')
        check(js('return document.querySelector("[data-route-field=method]").value==="drop"&&document.querySelector("[data-route-field=no_drop]").checked'),'reject options and checkbox survive a JSON round trip and action switching')
        select('#rule-action','route');save()
        check(sum(r['name']=='Compact route' for p in command('routing')['profiles'] for r in p['rules'])==1 and saved('Compact route')['config']==config,'native core accepts and saves the exact constructor configuration')
        for action in ['reject','hijack-dns','sniff','resolve','route-options','direct']:
            create('Action '+action);select('#rule-action',action)
            if action=='reject':select('[data-route-field=method]','drop')
            if action=='sniff':fill('[data-route-field=sniffer]','tls, http')
            if action=='resolve':fill('[data-route-field=server]','dns-direct');select('[data-route-field=strategy]','ipv4_only')
            if action=='route-options':fill('[data-route-field=override_port]','8443')
            save();check(saved('Action '+action)['config']['action']==action,'real core accepts the '+action+' action from the compact form')
        create('Bypass draft');select('#rule-action','bypass')
        check(js('return !!document.querySelector("[data-route-field=override_port]")&&!document.querySelector("[data-route-field=bind_interface]")&&document.querySelector(".route-rule-modal .route-target").value===""'),'bypass retains its system route and supported route options')
        close()
        logical={'type':'logical','mode':'or','rules':[{'domain_suffix':['one.test']},{'port':[443]}],'action':'route','outbound':'direct'}
        create('Logical rule');click('[data-rule-tab=json]');fill('#rule-json',json.dumps(logical));click('[data-rule-tab=fields]')
        check(js('return !document.querySelector(".route-condition")&&!!document.querySelector(".rule-hint")'),'nested logical conditions are retained without flattening them into AND rows')
        click('[data-rule-tab=json]');check(json.loads(js('return document.querySelector("#rule-json").value'))==logical,'logical JSON survives switching to the constructor and back');save()
        check(saved('Logical rule')['config']==logical,'native core accepts the preserved OR rule')
        create('Missing WARP keys');select('.route-rule-modal .route-target','warp');click('#rule-save')
        wait_for('return !!document.querySelector(".route-rule-modal [role=alert]")')
        check('settings_invalid:' not in js('return document.querySelector(".route-rule-modal [role=alert]").textContent') and js('return !!document.querySelector("dialog[open]")'), 'a WARP rule without keys keeps the editor open and explains the missing setting')
        close()
        current=command('settings')['intercept']
        command('saveSettings', {'section':'intercept','previous':current,'values':{**current,'enable_warp':False,'warp_private_key':'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=','warp_public_key':'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=','warp_ep':'127.0.0.1:2408','warp_ifc_addrs':['10.77.0.2/32']}})
        for target in ['warp','warp-bypass']:
            create('Target '+target);select('.route-rule-modal .route-target',target)
            check(js('return [...document.querySelectorAll(".rule-hint")].some(e=>e.textContent.includes("WARP"))'), 'WARP target explains the selected-server path')
            save();check(saved('Target '+target)['config']['outbound']==target and not command('settings')['intercept']['enable_warp'], 'native validation saves '+target+' with the global toggle off')
        create('Discard draft');fill('[data-route-field=domain_suffix]','unfinished')
        click('#main-modal > .modal-head > button');check(js('return document.querySelectorAll("dialog:modal").length===2'),'closing the constructor protects unsaved rule changes')
        click('[data-confirm-cancel]');check(js('return document.querySelector("[data-route-field=domain_suffix]").value==="unfinished"'),'returning from discard keeps the unfinished condition');close()
        for language,theme in [('ru','dark'),('en','light')]:
            command('preferences',{**command('snapshot')['preferences'],'language':language,'theme':theme})
            wait_for('return document.documentElement.lang==='+json.dumps(language)+'&&document.documentElement.dataset.theme==='+json.dumps(theme))
            create('Браузер через VPN' if language=='ru' else 'Browser through VPN')
            select('.route-rule-modal .route-target','warp')
            check(js("return document.querySelector('.route-rule-modal .route-target option[value=warp]').textContent") == ('Через WARP' if language=='ru' else 'Through WARP'), 'WARP destination is localized in '+language)
            for width,height in [(1280,900),(390,680)]:
                h['request']('POST',h['base']+'/window/rect',{'width':width,'height':height})
                check(fits(),f'compact rule constructor and footer fit {width}px in {language}/{theme}')
                screenshot(f'rule-constructor-{language}-{width}')
                click('[data-rule-tab=json]');check(fits(),f'rule JSON and footer fit {width}px in {language}/{theme}');click('[data-rule-tab=fields]')
            close();h['request']('POST',h['base']+'/window/rect',{'width':1280,'height':900})
        h['request']('POST',h['base']+'/refresh',{});wait_for('return !!document.querySelector(".add-connection")')
        check(saved('Compact route')['config']==config and saved('Logical rule')['config']==logical,'rules and typed parameters persist after the webview reload')
    finally:
        if js('return !!document.querySelector("#main-modal")'):close()
        current=command('routing');command('saveRouting',{**current,'active':routing['active'],'profiles':routing['profiles']})
        current_warp=command('settings')['intercept'];command('saveSettings',{'section':'intercept','previous':current_warp,'values':old_warp})
        command('preferences',initial['preferences']);h['request']('POST',h['base']+'/window/rect',geometry)
