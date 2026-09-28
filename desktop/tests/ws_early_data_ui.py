"""Real Xray WS editor, stored JSON and idle Core Check; no endpoint Start."""
import copy
import json
from pathlib import Path
import time
from profile_order_input import OwnedInput


def run(h, transport='ws'):
    assert transport in ('ws','httpupgrade')
    transport_key=transport+'Settings';other='httpupgrade' if transport=='ws' else 'ws'
    prefix='early-data-'+transport
    command,click,fill,select,wait_for,js,check=(h[k] for k in ('command','click','fill','select','wait_for','js','check'))
    initial=command('snapshot');geometry=h['request']('GET',h['base']+'/window/rect');group=None;native=None
    audit={'passed':False,'geometry':{},'inputEvents':[],'endpointStartClaimed':False}
    selector='#xray-'+transport+'-early-data';path_field='[data-field="streamSettings.'+transport_key+'.path"]'
    original_path='/socket?z=%2f+X&ed=1&a=1&a=2#fragment'
    original={'protocol':'vless','settings':{'vnext':[{'address':'192.0.2.38','port':443,'users':[{'id':'00000000-0000-4000-8000-000000000038','encryption':'none'}]}]},'streamSettings':{'network':transport,'security':'none',transport_key:{'path':original_path,'host':'owned.invalid','headers':{'X-Original':'unchanged'},'heartbeatPeriod':7,'x-unknown':{'list':[True,None,'keep'],'number':17}}},'x-unknown':'kept'}
    def val(css):return js('return document.querySelector(arguments[0]).value',css)
    def profile(id):return command('profile',{'id':id})['config']
    def add(name,config,kind='xray-outbound'):return command('saveProfile',{'name':name,'groupId':group,'kind':kind,'config':config})['id']
    def editor(id,transport=True):
        css='[data-profile-menu="'+id+'"]';wait_for('return !!document.querySelector('+json.dumps(css)+')')
        js('document.querySelector(arguments[0]).scrollIntoView({block:"center",behavior:"instant"})',css);time.sleep(.2)
        click(css);click('#menu-edit-profile');wait_for('return !!document.querySelector("#profile-editor")')
        if transport:click('[data-profile-tab="transport"]')
    def close():
        click('#main-modal > .modal-head > button')
        if js('return !!document.querySelector("[data-confirm-accept]")'):click('[data-confirm-accept]')
        wait_for('return !document.querySelector("dialog[open]")')
    def save():click('button[form="profile-editor"]');wait_for('return !document.querySelector("dialog[open]")')
    def draft():
        click('[data-profile-tab="json"]');value=json.loads(val('#profile-json'));click('[data-profile-tab="transport"]');return value
    def raw(config):
        click('[data-profile-tab="json"]');fill('#profile-json',json.dumps(config));click('[data-profile-tab="transport"]')
    def derived(value):wait_for('return document.querySelector('+json.dumps(selector)+')?.value==='+json.dumps(value))
    try:
        command('disconnect');command('preferences',{**initial['preferences'],'language':'en','theme':'dark','librarySort':'original'})
        wait_for('return document.documentElement.lang==="en"');h['request']('POST',h['base']+'/window/rect',{'width':1280,'height':900})
        group=command('saveGroup',{'name':'WS early data38','subscription':None})['id']
        id=add('Owned Xray WS',original);select('.group-strip select','all');editor(id)
        check(val(selector)=='1' and profile(id)==original,'opening the derived field preserves the original WS path and unknown JSON')
        fill(selector,'8192');expected=copy.deepcopy(original);expected['streamSettings'][transport_key]['path']=original_path.replace('ed=1','ed=8192')
        check(draft()==expected and val(path_field)==expected['streamSettings'][transport_key]['path'],'helper edits only ed and immediately resynchronizes the raw Path buffer')
        click('.editor-modal .modal-footer .button.secondary');wait_for('return !!document.querySelector(".editor-modal [role=status]")')
        check(profile(id)==original and command('snapshot')['running'] is None,'real Core Check validates the unsaved WS draft without Start or persistence')
        save();check(profile(id)==expected,'Save persists the path representation with exact unrelated fields')
        editor(id);check(val(selector)=='8192','reopening the actual editor derives the saved maximum value')
        select('[data-field="streamSettings.network"]',other)
        other_selector='#xray-'+other+'-early-data';other_path='[data-field="streamSettings.'+other+'Settings.path"]'
        fill(other_path,'/independent?ed=9');fill(other_selector,'10')
        check(draft()['streamSettings'][other+'Settings']['path']=='/independent?ed=10','editing the other transport creates only its independent path')
        select('[data-field="streamSettings.network"]',transport);derived('8192');fill(selector,'4')
        select('[data-field="streamSettings.network"]',other)
        check(val(other_selector)=='10' and draft()['streamSettings'][transport_key]['path']==expected['streamSettings'][transport_key]['path'].replace('ed=8192','ed=4'),'switching both ways keeps independent valid values for both transports')
        fill(other_selector,'8193');select('[data-field="streamSettings.network"]',transport);derived('4')
        select('[data-field="streamSettings.network"]',other)
        check(val(other_selector)=='10' and not js('return document.querySelector(arguments[0]).hasAttribute("aria-invalid")',other_selector),'leaving an invalid helper buffer restores only that transport last valid value')
        raw(expected);derived('8192')
        fill(path_field,'/new?x=%2f&e%64=2#kept');derived('2')
        check(draft()['streamSettings'][transport_key]['path']=='/new?x=%2f&e%64=2#kept','raw Path edits resynchronize encoded ed without normalization')
        fill(selector,'3');check(val(path_field)=='/new?x=%2f&ed=3#kept','editing the derived value clears a stale manually edited Path buffer')
        updated=copy.deepcopy(expected);updated['streamSettings'][transport_key]['path']='/raw?ed=4&untouched=%2f#tail';raw(updated);derived('4')
        check(draft()==updated,'JSON-tab changes become the new source of the derived field')
        for value in ['0','']:
            raw(updated);fill(selector,value);removed=copy.deepcopy(updated);removed['streamSettings'][transport_key]['path']='/raw?untouched=%2f#tail'
            check(draft()==removed,'zero or clear removes only ed: '+repr(value))
        raw(updated)
        for value in ['-1','8193']:
            fill(selector,value);click('button[form="profile-editor"]');wait_for('return !!document.querySelector("#profile-editor [role=alert]")')
            check(js('return document.querySelector(arguments[0]).getAttribute("aria-invalid")==="true"',selector) and profile(id)==expected,'invalid edited length blocks Save without changing the stored profile: '+value)
        select('[data-field="streamSettings.network"]','grpc')
        check(not js('return !!document.querySelector(arguments[0])',selector) and draft()['streamSettings'][transport_key]['path']==updated['streamSettings'][transport_key]['path'],'switching away hides the helper and retains the last valid WS path')
        select('[data-field="streamSettings.network"]',transport);derived('4')
        check(not js('return document.querySelector(arguments[0]).hasAttribute("aria-invalid")',selector),'returning to WS discards hidden invalid input and derives the retained value')
        fill(path_field,'');fill(selector,'1');check(js('return document.querySelector(arguments[0]).getAttribute("aria-invalid")==="true"',selector) and '/' in js('return document.querySelector('+json.dumps(selector+'-hint')+').textContent'),'positive early data requires an explicit path instead of silently losing the value')
        close();check(profile(id)==expected,'Cancel discards all derived, Path and JSON edits')
        for path in ['/?ed=1&e%64=2',':broken?ed=1','/?ed=8193']:
            bad=copy.deepcopy(original);bad['streamSettings'][transport_key]['path']=path;badid=add('Uninterpreted path',bad);editor(badid)
            check(js('return document.querySelector(arguments[0]).disabled',selector) and len(js('return document.querySelector('+json.dumps(selector+'-hint')+').textContent'))>20,'ambiguous or unsupported raw path disables only the helper: '+path)
            save();check(profile(badid)==bad,'untouched unsupported raw path remains exactly saveable: '+path)
        sb={'type':'vless','server':'192.0.2.38','server_port':443,'uuid':'00000000-0000-4000-8000-000000000038','transport':{'type':'ws','path':'/sb','max_early_data':123,'early_data_header_name':'Sec-WebSocket-Protocol'}}
        sbid=add('Owned sing-box WS',sb,'sing-box-outbound');editor(sbid)
        check(not js('return !!document.querySelector(arguments[0])',selector) and val('[data-field="transport.max_early_data"]')=='123' and val('[data-field="transport.early_data_header_name"]')=='Sec-WebSocket-Protocol','existing sing-box WS fields retain their separate representation');close()
        editor(id);select('[data-field="streamSettings.network"]',other)
        check(not js('return !!document.querySelector(arguments[0])',selector) and val('#xray-'+other+'-early-data')=='0','the selected transport has its own derived field without the previous one');close()
        full={'inbounds':[],'outbounds':[original]};fullid=add('Owned full Xray',full,'xray-config');editor(fullid,False)
        check(not js('return !!document.querySelector(arguments[0])',selector) and json.loads(val('#profile-json'))==full,'complete Xray JSON stays in its existing raw editor');close()
        native=OwnedInput(h);native.activate()
        for language in ['ru','en']:
            command('preferences',{**command('snapshot')['preferences'],'language':language});wait_for('return document.documentElement.lang==='+json.dumps(language))
            editor(id);h['request']('POST',h['base']+'/window/rect',{'width':390,'height':844});wait_for('return innerWidth===390')
            js('document.querySelector(arguments[0]).scrollIntoView({block:"center",behavior:"instant"});document.querySelector(arguments[0]).focus();document.querySelector(arguments[0]).select()',selector)
            start=len(native.events());native.key('4');derived('4');events=native.events()[start:];audit['inputEvents'].extend(events)
            check(any(e['type']=='keydown' and e['key']=='4' and e['trusted'] for e in events) and val(path_field)==expected['streamSettings'][transport_key]['path'].replace('ed=8192','ed=4'),language+' actual keyboard input updates the WS path')
            samples=[]
            for _ in range(3):
                samples.append(js('''const e=document.querySelector(arguments[0]),r=e.getBoundingClientRect(),b=document.querySelector('.editor-modal .modal-body');return {w:innerWidth,h:innerHeight,left:r.left,right:r.right,top:r.top,bottom:r.bottom,scroll:b.scrollWidth,client:b.clientWidth};''',selector+'-field'));time.sleep(.15)
            audit['geometry'][language]=samples
            check(samples[0]==samples[1]==samples[2] and all(s['w']==390 and s['left']>=0 and s['right']<=390 and s['top']>=0 and s['bottom']<=s['h'] and s['scroll']<=s['client']+1 for s in samples),language+' field, explanation and native typing fit stable390 geometry')
            h['screenshot'](prefix+'-'+language+'-390');close();h['request']('POST',h['base']+'/window/rect',{'width':1280,'height':900})
        audit['passed']=True
    finally:
        try:
            if not audit['passed']:h['screenshot'](prefix+'-failure-before-cleanup')
            if native:native.close()
            if js('return !!document.querySelector("#main-modal")'):close()
            command('disconnect')
            if group:command('deleteGroup',{'id':group,'deleteProfiles':True})
            command('preferences',initial['preferences']);h['request']('POST',h['base']+'/window/rect',geometry)
            audit['cleanupCompleted']=True
        finally:(Path(h['args'].artifacts)/(prefix+'-audit.json')).write_text(json.dumps(audit,indent=2)+'\n')
