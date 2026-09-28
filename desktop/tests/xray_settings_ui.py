"""Xray accordion against native WebKit, settings transactions and generated configs."""
import json

def run(h):
    command,click,fill,select,wait_for,js,check,screenshot=(h[k] for k in ('command','click','fill','select','wait_for','js','check','screenshot'))
    before=command('settings')['core']
    click('[data-settings-section=core]')
    wait_for('return !!document.querySelector("#settings-xray")')
    check(js('return !document.querySelector("[data-settings-section=xray]")&&!document.querySelector("#settings-xray").open'),'Xray is a collapsed accordion inside Cores and API without a sidebar entry')
    click('#settings-xray > summary')
    check(js('return document.querySelectorAll("#settings-xray [data-setting]").length')==25,'the Xray accordion contains all existing settings')
    check(js('return document.querySelectorAll("#settings-xray .settings-subgroup").length')==6,'Xray keeps log, mux, TCP, connection limits, API and geodata groups')
    js('document.querySelectorAll("#settings-content details").forEach(d=>d.open=true)')
    check(js('return document.querySelector("#setting-xray_policy_conn_idle").disabled&&document.querySelector("#setting-xray_api_port").disabled'),'inactive policy and API fields are disabled')
    click('#setting-xray_policy_enabled');fill('#setting-xray_policy_conn_idle','75')
    click('[data-settings-section=appearance]');click('[data-settings-section=core]')
    check(js('return document.querySelector("#setting-xray_policy_conn_idle").value')=='75','Xray keeps drafts when switching categories')
    js('document.querySelector("#settings-xray").open=false')
    fill('#settings-search','xray_policy_conn_idle');click('[data-settings-result=xray_policy_conn_idle]')
    check(js('return document.querySelector("[data-settings-section=core]").getAttribute("aria-current")==="page"&&document.activeElement.id==="setting-xray_policy_conn_idle"&&document.querySelector("#setting-xray_policy_conn_idle").closest("details").open'),'Xray search opens Cores and API, expands the accordion and focuses the field')
    fill('#setting-xray_policy_conn_idle','-1');click('#settings-save')
    check(js('return document.querySelector("#setting-xray_policy_conn_idle").getAttribute("aria-invalid")==="true"'),'negative Xray timeout is rejected and highlighted')
    fill('#setting-xray_policy_conn_idle','75')
    js('document.querySelectorAll("#settings-content details").forEach(d=>d.open=true)')
    select('#setting-xray_tcp_fast_open','disabled');select('#setting-xray_log_mask_address','half')
    click('#settings-save');wait_for('return document.querySelector("#settings-save").disabled && !document.querySelector("[data-navigation-locked=true]")')
    saved=command('settings')['core']
    check(saved['xray_policy_conn_idle']==75 and saved['xray_tcp_fast_open']=='disabled' and saved['xray_log_mask_address']=='half','Xray controls persist through the native settings transaction')
    fixture=command('saveProfile',{'name':'Xray settings fixture','groupId':'personal','kind':'xray-outbound','config':{'protocol':'freedom','settings':{}}})['id']
    generated=command('connectionConfiguration',{'id':fixture,'active':False})['parts'][1]['config']
    check(generated['policy']['levels']['0']['connIdle']==75 and generated['outbounds'][0]['streamSettings']['sockopt']['tcpFastOpen'] is False and generated['log']['maskAddress']=='half','saved UI values reach the real generated Xray configuration')
    for language,theme in [('ru','dark'),('en','light')]:
        command('preferences',{**command('snapshot')['preferences'],'language':language,'theme':theme})
        wait_for('return document.documentElement.lang==='+json.dumps(language))
        for width in [1280,390]:
            h['request']('POST',h['base']+'/window/rect',{'width':width,'height':900})
            check(js('return document.documentElement.scrollWidth<=innerWidth+1'),'Xray settings fit '+str(width)+'px in '+language)
            if width==1280:
                js('document.querySelectorAll("#settings-content details").forEach(d=>d.open=false);document.querySelector("[data-settings-section=core]").scrollIntoView({block:"center"});document.querySelector("#settings-content").scrollIntoView({block:"start"})')
                screenshot('xray-settings-collapsed-'+language)
                click('#settings-xray > summary')
                screenshot('xray-settings-'+language)
    command('delete',{'id':fixture})
    current=command('settings')['core']
    command('saveSettings',{'section':'core','previous':current,'values':before})
    h['request']('POST',h['base']+'/window/rect',{'width':1280,'height':900})
