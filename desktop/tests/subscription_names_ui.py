"""Native name-rule editor and manual/queued updates against a local provider."""
import http.server
import json
import threading
from urllib.parse import quote


def run(h):
    command,click,fill,select,wait_for,js,check,screenshot=(h[k] for k in ('command','click','fill','select','wait_for','js','check','screenshot'))
    request,base=h['request'],h['base'];initial=command('snapshot');geometry=request('GET',base+'/window/rect')
    body='\n'.join('socks://u:p@127.0.0.1:'+str(port)+'#'+quote(name) for name,port in [('US Two',1081),('DE One',1081),('DE Trial',1082)])
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self,*_):pass
        def do_GET(self):
            data=body.encode();self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start()
    group=command('saveGroup',{'name':'Name rules','subscription':{'url':f'http://127.0.0.1:{server.server_port}/subscription','headers':{},'viaProxy':False,'inheritDefaults':False}})['id']
    def members():return [p for p in command('snapshot')['profiles'] if p['groupId']==group]
    def close():click('#main-modal > .modal-head > button');wait_for('return !document.querySelector("dialog[open]")')
    def edit():
        click('.group-strip .icon-button');wait_for('return !!document.querySelector('+json.dumps('[data-group-edit="'+group+'"]')+')');click('[data-group-edit="'+group+'"]');wait_for('return !!document.querySelector("#group-name-rules")');click('#group-name-rules > summary')
    def save():click('#group-save');wait_for('return !!document.querySelector("#group-new")');close()
    def update():
        select('.group-strip select',group);click('[data-library-group] [data-group-menu]');click('#update-subscription');click('#subscription-load');wait_for('return !!document.querySelector("#subscription-reload")')
    try:
        command('preferences',{**initial['preferences'],'language':'en','theme':'dark'})
        wait_for('return document.documentElement.lang==="en"&&[...document.querySelector(".group-strip select").options].some(o=>o.value==='+json.dumps(group)+')')
        command('startSubscriptionUpdates',{'id':group})
        wait_for('return document.querySelectorAll(".connection-row").length>=3',timeout=35)
        original=members();check(len(original)==3,'unfiltered subscription imports all three provider profiles')
        kept=next(p for p in original if p['name']=='DE One');command('favorite',{'id':kept['id']})
        edit();fill('#group-name-include','(?=unsupported)');click('#group-save');wait_for('return !!document.querySelector(".groups-modal [role=alert]")')
        check('nameRules' not in command('group',{'id':group})['subscription'] or command('group',{'id':group})['subscription']['nameRules']['include']=='','invalid regex is rejected without saving partial group settings')
        fill('#group-name-include','^DE');fill('#group-name-exclude','Trial');click('#group-name-add');fill('[data-name-pattern="0"]','^DE (.*)$');fill('[data-name-replacement="0"]','🇩🇪 ${1}');save()
        check(len(members())==3,'saving name rules leaves current profiles unchanged until an update')
        body=body.replace('socks://u:p@','socks://u:rotated@')
        update();check(js('return document.querySelectorAll("[data-subscription-action=removed]").length===2&&document.querySelectorAll("[data-subscription-action=updated]").length===1'),'manual preview shows filtered removals and the renamed server')
        check(len(members())==3,'manual rule preview does not mutate the library')
        click('#subscription-check');wait_for('return !!document.querySelector(".subscription-modal .import-valid")',timeout=30)
        check(True,'manual validation addresses the remaining profile by ID and uses the real core')
        click('#subscription-apply');wait_for('return !document.querySelector("dialog[open]")');after=members()
        check(len(after)==1 and after[0]['id']==kept['id'] and after[0]['favorite'] and after[0]['name']=='🇩🇪 One','apply retains the named duplicate ID and favorite while filtering, renaming and rotating credentials')
        edit();fill('#group-name-include','^NOT_FOUND');save();update();check(js('return document.querySelector("#subscription-apply").disabled&&document.querySelector("[role=alert]").textContent.includes("excluded every")'),'an all-excluding filter blocks apply and explains why');close();check(members()==after,'all-excluded update leaves the stored profiles untouched')
        edit();fill('#group-name-include','^DE');fill('[data-name-replacement="0"]','🇩🇪 Queue ${1}');save();command('startSubscriptionUpdates',{'id':group})
        wait_for('return [...document.querySelectorAll(".connection-row strong")].some(e=>e.textContent.includes("Queue One"))',timeout=35)
        queued=members();check(len(queued)==1 and queued[0]['id']==kept['id'] and queued[0]['name']=='🇩🇪 Queue One','automatic queue applies the same rules once to original provider names')
        edit();fill('#group-name-exclude','.*');save();command('startSubscriptionUpdates',{'id':group})
        import time
        deadline=time.monotonic()+30
        while time.monotonic()<deadline:
            last=next(g for g in command('snapshot')['groups'] if g['id']==group).get('lastUpdate') or {}
            if last.get('error')=='subscription_filtered_empty':break
            time.sleep(.2)
        check(last.get('error')=='subscription_filtered_empty' and members()==queued,'automatic all-excluding filter reports its exact error without deleting servers')
        command('preferences',{**command('snapshot')['preferences'],'language':'ru','theme':'light'});wait_for('return document.documentElement.lang==="ru"');edit();request('POST',base+'/window/rect',{'width':390,'height':720})
        check(js('const d=document.querySelector(".groups-modal"),b=d.querySelector(".modal-body");return b.scrollWidth<=b.clientWidth+1&&d.querySelector(".modal-footer").getBoundingClientRect().bottom<=innerHeight+1'),'name-rule editor fits the narrow Russian window');screenshot('subscription-names-ru-390');close()
        request('POST',base+'/refresh',{});wait_for('return !!document.querySelector(".add-connection")')
        check(command('group',{'id':group})['subscription']['nameRules']['rename'][0]['replacement']=='🇩🇪 Queue ${1}','name rules survive reloading the native webview')
    finally:
        command('deleteGroup',{'id':group,'deleteProfiles':True});command('preferences',initial['preferences']);request('POST',base+'/window/rect',geometry);server.shutdown();server.server_close()
