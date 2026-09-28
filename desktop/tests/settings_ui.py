"""Categorized settings against the actual native webview and persisted library."""
import json,os,pathlib,subprocess,time

def run(h):
    command,click,fill,select,wait_for,js,check,screenshot=(h[k] for k in ('command','click','fill','select','wait_for','js','check','screenshot'))
    initial=command('snapshot')
    command('preferences',{**initial['preferences'],'language':'en','theme':'light'})
    h['request']('POST',h['base']+'/window/rect',{'width':1280,'height':900})
    click('.primary-nav button:last-child');wait_for('return !!document.querySelector("#settings-search")')
    def section(id):
        click('[data-settings-section='+id+']');wait_for('return document.querySelector("[data-settings-section='+id+']").getAttribute("aria-current")==="page"')
    def save(id,key,value):
        old=command('settings')[id];return command('saveSettings',{'section':id,'previous':old,'values':{**old,key:value}})
    def saved_form():
        # Save is disabled while an RPC is pending AND after a clean save.
        # At least one enabled field proves busy=false; absence of a conflict
        # keeps this wait distinct from the explicit conflict assertions below.
        wait_for('return document.querySelector("#settings-save")?.disabled && !!document.querySelector("#settings-form [data-setting]:enabled") && !document.querySelector("#settings-conflict-current")')
    expected_sections=['appearance','inbound','tun','dns','intercept','network','subscriptions','testing','logging','core','presets','system','security','backup','otp']
    check(js('return [...document.querySelectorAll("[data-settings-section]")].map(element=>element.dataset.settingsSection).sort()')==sorted(expected_sections),'settings contain all fifteen expected categories, with both cores inside Cores and API')
    from xray_settings_ui import run as xray_settings
    xray_settings(h)
    from singbox_settings_ui import run as singbox_settings
    singbox_settings(h)
    section('testing');fill('#probe-url','https://example.test/new-ping');section('appearance');section('testing')
    check(js('return document.querySelector("#probe-url").value')=='https://example.test/new-ping','category switching preserves unsaved values')
    fill('#settings-search','inbound_user');click('[data-settings-result=inbound_user]')
    check(js('return document.querySelector("#setting-inbound_user").closest("details").open&&document.activeElement.id==="setting-inbound_user"'),'search finds upstream keys, expands the card and focuses the field')
    section('testing');check(js('return document.querySelector("#probe-url").value')=='https://example.test/new-ping','search does not erase another category draft')
    fill('#probe-timeout','1');click('#settings-save');check(js('return document.querySelector("#probe-timeout").getAttribute("aria-invalid")==="true"'),'invalid timeout is highlighted and rejected')
    fill('#probe-timeout','2500');click('#settings-save');saved_form()
    check(command('settings')['testing']['url_test_timeout_ms']==2500,'save updates the real ping preference')
    js('document.querySelector("#setting-speed_test_timeout_ms").closest("details").open=true')
    fill('#setting-speed_test_timeout_ms','999')
    js('document.querySelector("#setting-speed_test_timeout_ms").closest("details").open=false')
    click('#settings-save');wait_for('return document.activeElement.id==="setting-speed_test_timeout_ms"')
    check(js('return document.querySelector("#setting-speed_test_timeout_ms").closest("details").open'),'invalid values in collapsed cards are expanded and focused')
    fill('#setting-speed_test_timeout_ms','6000');click('#settings-save');saved_form()
    section('appearance');select('#settings-theme','dark');save('appearance','compact',True);click('#settings-save')
    saved_form()
    check(command('settings')['appearance']['theme']=='dark' and command('settings')['appearance']['compact'],'saving merges unrelated settings changed while the form was open')
    click('#setting-reduce_motion');click('.topbar-actions > button:first-child')
    wait_for('return document.documentElement.dataset.theme==="light" && document.querySelector("#settings-theme").value==="light"')
    check(js('return document.querySelector("#setting-reduce_motion").checked'),'header theme changes refresh the untouched selector without discarding another edit')
    click('#settings-save');saved_form()
    check(command('settings')['appearance']['theme']=='light' and command('settings')['appearance']['reduce_motion'],'saving after a header theme switch preserves both changes without a conflict')
    section('testing');fill('#setting-test_concurrent','2')
    click('.primary-nav .nav-link:first-child');time.sleep(.3)
    check(js('return !!document.querySelector("#setting-test_concurrent") && document.querySelector("#setting-test_concurrent").value==="2" && !!document.querySelector(".toast")'),'leaving Settings with unsaved changes keeps the page and its input and explains why')
    js('document.querySelector("#setting-speed_test_timeout_ms").closest("details").open=true');fill('#setting-speed_test_timeout_ms','7000')
    save('testing','test_concurrent',3);click('#settings-save');wait_for('return !!document.querySelector("#settings-conflict-current")')
    wait_for('return document.activeElement.id==="settings-conflict-current"');screenshot('settings-field-conflict-en')
    check(js('return document.querySelector("#setting-test_concurrent").value==="2"') and command('settings')['testing']['speed_test_timeout_ms']==6000,'a real field conflict preserves input and cannot partially save another field')
    click('#settings-conflict-current');wait_for('return document.querySelector("#setting-test_concurrent").value==="3"')
    check(js('return document.querySelector("#setting-speed_test_timeout_ms").value==="7000"'),'loading the saved conflicting field preserves all other local edits')
    click('#settings-save');saved_form()
    fill('#setting-test_concurrent','2');save('testing','test_concurrent',4);click('#settings-save');wait_for('return !!document.querySelector("#settings-conflict-mine")')
    click('#settings-conflict-mine');saved_form()
    check(command('settings')['testing']['test_concurrent']==2,'explicitly keeping local values resolves and saves the field conflict')
    fill('#settings-search','cache_capacity');click('[data-settings-result=dns_cache_capacity]')
    wait_for('return !!document.querySelector("[data-resource-field=cache_capacity]")')
    check(js('return document.querySelector("[data-resource-tab=cache]").classList.contains("active")'),'DNS search opens the existing scoped editor on the correct tab')
    click('#main-modal > .modal-head > button');wait_for('return !document.querySelector("dialog[open]")')
    for language,theme in [('ru','dark'),('en','light')]:
        command('preferences',{**command('snapshot')['preferences'],'language':language,'theme':theme})
        wait_for('return document.documentElement.lang==='+json.dumps(language))
        section('testing')
        for width in [1280,720,390]:
            h['request']('POST',h['base']+'/window/rect',{'width':width,'height':900})
            check(js('return document.documentElement.scrollWidth<=innerWidth+1'),'settings fit '+str(width)+'px in '+language)
            screenshot('settings-'+language+'-'+str(width))
    section('appearance')
    check(js('return !["show_system_dns","skip_delete_confirmation","use_custom_icons","custom_icon_directory"].some(id=>document.querySelector("[data-setting="+id+"]"))'),'interface category excludes diagnostics, deletion and tray controls')
    check(js('return document.querySelector("#setting-font_size").tagName==="SELECT" && document.querySelector("#setting-font_size option:checked").textContent.includes("100%") && !document.querySelector("#setting-font").closest("details").open'),'interface scale uses percentages and custom font is in additional parameters')
    fill('#settings-search','use_custom_icons');click('[data-settings-result=use_custom_icons]')
    check(js('return document.querySelector("[data-settings-section=system]").getAttribute("aria-current")==="page"'),'search opens tray customization in System settings')
    section('logging');check(js('return !!document.querySelector("#setting-show_system_dns")'),'DNS connection visibility belongs to diagnostics statistics')
    section('security');check(js('return !!document.querySelector("#setting-skip_delete_confirmation")'),'profile deletion confirmation belongs to Security')
    fixture=command('saveProfile',{'name':'Interface density fixture','groupId':'personal','kind':'sing-box-outbound','config':{'type':'direct'}})['id']
    row_selector=json.dumps('[data-profile-menu="'+fixture+'"]')
    compact=command('settings')['appearance']['compact']
    h['request']('POST',h['base']+'/window/rect',{'width':1280,'height':900})
    click('.primary-nav button:first-child');save('appearance','compact',False)
    # The previous 390px window and page switch may still be laying out after
    # the data attribute changes. Measure an actually visible row at final width.
    wait_for('return innerWidth>=1200 && document.documentElement.dataset.compact==="false" && document.querySelector('+row_selector+')?.closest(".connection-row").getBoundingClientRect().height>1')
    measure='const r=document.querySelector('+row_selector+').closest(".connection-row");return {height:r.getBoundingClientRect().height,width:r.getBoundingClientRect().width,innerWidth,compact:document.documentElement.dataset.compact,minHeight:getComputedStyle(r).minHeight}'
    before_density=js(measure);height=before_density['height']
    save('appearance','compact',True)
    try:
        wait_for('return document.documentElement.dataset.compact==="true" && document.querySelector('+row_selector+').closest(".connection-row").getBoundingClientRect().height>1 && document.querySelector('+row_selector+').closest(".connection-row").getBoundingClientRect().height<'+json.dumps(height))
    finally:
        after_density=js(measure)
        (h['artifacts']/'settings-density.json').write_text(json.dumps({'before':before_density,'after':after_density},indent=2)+'\n')
    check(after_density['height']<height,'compact mode actually reduces the server row height')
    save('appearance','compact',compact);command('delete',{'id':fixture})
    click('.primary-nav button:last-child');section('appearance')
    # The server list card carries the displayed-data switches; ids and defaults come from the catalog.
    switches=['compact','show_config_security','list_show_address','list_show_port','list_show_protocol','list_show_latency','list_show_ip','list_show_speed','list_show_traffic','auto_select_enabled']
    check(js('const card=document.querySelector("#setting-compact").closest("details");return arguments[0].every(id=>card.contains(document.querySelector("#setting-"+id))&&document.querySelector("#setting-"+id).getAttribute("role")==="switch")&&card.querySelectorAll("[data-setting]").length===arguments[0].length',switches),'server list card lists exactly the ten displayed-data switches')
    check(command('settings')['appearance']['list_show_port'] is False and command('settings')['appearance']['list_show_latency'] is True,'displayed-data switches start from their catalog defaults')
    js('document.querySelector("#setting-list_show_port").closest("details").open=true');click('#setting-list_show_port');click('#settings-save');saved_form()
    check(command('settings')['appearance']['list_show_port'] is True,'saving the form persists a displayed-data switch')
    h['request']('POST',h['base']+'/refresh',{});wait_for('return !!document.querySelector(".add-connection")')
    click('.primary-nav button:last-child');wait_for('return !!document.querySelector("#settings-search")');section('appearance')
    # The section renders catalog defaults until its saved values arrive; wait for them.
    wait_for('return document.querySelector("#setting-list_show_port")?.checked===true',timeout=15)
    check(js('return document.querySelector("#setting-list_show_port").checked'),'a displayed-data switch survives a webview reload')
    save('appearance','list_show_port',False);wait_for('return !document.querySelector("#setting-list_show_port").checked')
    screenshot('interface-organized-en')
    # OS mutations are confined to this runner's private XDG directories.
    config=pathlib.Path(os.environ['XDG_CONFIG_HOME'])
    assert 'thronium-native-test-' in str(config)
    save('system','autostart',True)
    entry=config/'autostart/io.thronium.desktop.desktop'
    check(entry.exists() and 'Exec=' in entry.read_text(),'autostart writes the current executable into the private XDG registration')
    save('system','autostart',False);check(not entry.exists(),'disabling autostart removes only this application registration')
    before=command('settings')['system'];invalid={**before,'hotkey_route':'Ctrl+Alt+Shift+F11','hotkey_group':'Ctrl+Alt+Shift+F11'}
    try:command('saveSettings',{'section':'system','previous':before,'values':invalid});raise AssertionError('duplicate shortcut accepted')
    except RuntimeError:pass
    check(command('settings')['system']==before,'failed shortcut registration restores persisted settings')
    save('system','hotkey_route','Ctrl+Alt+Shift+F11')
    check(command('settings')['system']['hotkey_route']=='Ctrl+Alt+Shift+F11','global shortcut is registered by the OS')
    save('system','hotkey_route','')
    save('system','url_scheme_auto_register',True)
    handler=subprocess.check_output(['xdg-mime','query','default','x-scheme-handler/thronium'],text=True).strip()
    check(handler=='Thronium-handler.desktop','deep link scheme is registered with the desktop')
    subprocess.run([h['args'].application,'throne://fixture'],check=True,timeout=15,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    wait_for('return [...document.querySelectorAll("dialog textarea")].some(e=>e.value.includes("throne://fixture"))')
    check(command('snapshot')['running'] is None,'a link opens the import editor without connecting or importing automatically')
    click('#main-modal > .modal-head > button');wait_for('return !document.querySelector("dialog[open]")')
    save('system','url_scheme_auto_register',False)
    check(subprocess.check_output(['xdg-mime','query','default','x-scheme-handler/thronium'],text=True).strip()!='Thronium-handler.desktop','disabling links removes the desktop handler')
    h['request']('POST',h['base']+'/refresh',{});wait_for('return !!document.querySelector(".add-connection")')
    check(command('settings')['testing']['url_test_timeout_ms']==2500,'saved settings survive a webview restart')
