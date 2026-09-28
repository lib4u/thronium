"""Additional sing-box settings: native form, inheritance and existing locations."""
import json

def run(h):
    command,click,fill,select,wait_for,js,check,screenshot=(h[k] for k in ('command','click','fill','select','wait_for','js','check','screenshot'))
    preferences=command('snapshot')['preferences']
    before=command('settings')['core']
    click('[data-settings-section=core]')
    wait_for('return !!document.querySelector("#settings-singbox")')
    check(js('return !document.querySelector("#settings-singbox").open&&!document.querySelector("[data-settings-section=singbox]")'),'sing-box is collapsed inside Cores and API without a sidebar entry')
    click('#settings-singbox > summary')
    check(js('return document.querySelectorAll("#settings-singbox [data-setting]").length===13'),'sing-box contains thirteen additional settings')
    check(js('return document.querySelector("#setting-singbox_cache_store_dns").disabled&&document.querySelector("#setting-singbox_mux_max_connections").disabled'),'cache and Mux dependencies are disabled until enabled')
    fill('#setting-singbox_connect_timeout','14')
    click('[data-settings-link=presets]')
    check(js('return document.activeElement.id==="setting-mux_default_on"&&!!document.querySelector("#setting-fragment_default_on")&&!!document.querySelector("#setting-quic_initial_packet_size")'),'existing Mux, TLS and QUIC settings stay in connection presets')
    click('[data-settings-section=logging]')
    check(js('return !!document.querySelector("#setting-log_level")'),'sing-box log level stays in Logs and statistics')
    click('[data-settings-section=core]')
    check(js('return document.querySelector("#setting-singbox_connect_timeout").value==="14"&&!!document.querySelector("#setting-core_box_api_port")&&!!document.querySelector("#setting-core_box_clash_api")'),'draft survives navigation and existing APIs keep their locations')
    fill('#settings-search','singbox_cache_store_dns');click('[data-settings-result=singbox_cache_store_dns]')
    check(js('return document.querySelector("#settings-singbox").open&&document.activeElement.id==="setting-singbox_cache_enabled"'),'search opens disabled cache settings and focuses the enabling switch')
    click('#setting-singbox_cache_enabled');click('#setting-singbox_cache_store_dns');click('#setting-singbox_cache_store_fakeip')
    select('#setting-singbox_tcp_keep_alive','disabled')
    check(js('return document.querySelector("#setting-singbox_tcp_keep_alive_idle").disabled'),'disabling TCP keepalive disables its timing controls')
    select('#setting-singbox_tcp_keep_alive','enabled')
    fill('#setting-singbox_tcp_keep_alive_idle','60')
    select('#setting-singbox_mux_limits','connections');fill('#setting-singbox_mux_max_connections','2');fill('#setting-singbox_mux_min_streams','3')
    fill('#setting-singbox_connect_timeout','-1')
    js('document.querySelector("#settings-singbox").open=false')
    click('#settings-save')
    check(js('return document.querySelector("#settings-singbox").open&&document.activeElement.id==="setting-singbox_connect_timeout"&&document.activeElement.getAttribute("aria-invalid")==="true"'),'invalid sing-box timeout expands the accordion and focuses the error')
    fill('#setting-singbox_connect_timeout','14');click('#settings-save')
    wait_for('return document.querySelector("#settings-save").disabled && !document.querySelector("[data-navigation-locked=true]")')
    saved=command('settings')['core']
    check(saved['singbox_connect_timeout']==14 and saved['singbox_cache_store_dns'] is True and saved['singbox_mux_max_connections']==2,'additional sing-box settings persist through the shared save transaction')
    fixture=command('saveProfile',{'name':'sing-box settings fixture','groupId':'personal','kind':'sing-box-outbound','config':{'type':'trojan','server':'127.0.0.1','server_port':443,'password':'fixture','multiplex':{'enabled':True}}})['id']
    generated=command('connectionConfiguration',{'id':fixture,'active':False})['parts'][0]['config']
    outbound=next(o for o in generated['outbounds'] if o['tag']=='proxy')
    check(outbound['connect_timeout']=='14s' and outbound['tcp_keep_alive']=='60s' and outbound['multiplex']['max_connections']==2 and 'max_streams' not in outbound['multiplex'] and generated['experimental']['cache_file']['store_dns'] is True,'saved sing-box fields reach the actual outbound, exclusive Mux mode and persistent cache')
    click('[data-settings-link=dns]')
    check(js('return document.querySelector("[data-settings-section=dns]").getAttribute("aria-current")==="page"'),'sing-box links to the existing DNS editor')
    click('[data-settings-section=core]')
    for language,theme in [('ru','light'),('en','dark')]:
        command('preferences',{**command('snapshot')['preferences'],'language':language,'theme':theme})
        wait_for('return document.documentElement.lang==='+json.dumps(language))
        js('document.querySelector("#settings-singbox").open=true')
        for width in [1280,390]:
            h['request']('POST',h['base']+'/window/rect',{'width':width,'height':900})
            check(js('return document.documentElement.scrollWidth<=innerWidth+1'),'sing-box settings fit '+str(width)+'px in '+language)
            if width==1280:
                js('document.querySelector("#settings-singbox").scrollIntoView({block:"start",behavior:"instant"})')
                screenshot('singbox-settings-'+language)
                js('document.querySelector("#singbox-group-singbox-cache").scrollIntoView({block:"start",behavior:"instant"})')
                screenshot('singbox-settings-cache-'+language)
    command('delete',{'id':fixture})
    command('saveSettings',{'section':'core','previous':command('settings')['core'],'values':before})
    command('preferences',preferences)
    wait_for('return document.documentElement.lang==='+json.dumps(preferences['language']))
    h['request']('POST',h['base']+'/window/rect',{'width':1280,'height':900})
