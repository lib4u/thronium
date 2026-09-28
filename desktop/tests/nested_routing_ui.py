"""Visual nested routing against independent raw-core truth rows and local HTTP."""
import contextlib
import copy
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import tempfile
import time
import uuid
from native_dialogs import file_dialog
from native_menu import NativeMenu
from native_processes import core_pids
from external_core_fixture import identity
from nested_routing_fixtures import ACTION_ONLY, DIRECTORY, MATRIX, Origins, condition, listable, materialize, no_nested_actions


def run(h):
    command,click,fill,select,wait_for,js,check,screenshot=(h[k] for k in ('command','click','fill','select','wait_for','js','check','screenshot'))
    initial=command('snapshot');geometry=h['request']('GET',h['base']+'/window/rect');original_routing=command('routing')
    application=Path(h['args'].application).resolve();core=application.with_name('ThroniumCore');artifacts=Path(h['args'].artifacts)
    menu=NativeMenu();assert Path('/proc',str(menu.pid),'exe').resolve()==application
    owner_identity=identity(menu.pid);origins=Origins();observed=[];connections=[];audit={};baseline_path=None
    matched=origins.matched.server_address[1];fallback=origins.fallback.server_address[1]
    routes_before=Path('/proc/net/route').read_bytes();interfaces_before=sorted(p.name for p in Path('/sys/class/net').iterdir())
    with socket.socket() as s:s.bind(('127.0.0.1',0));inbound=s.getsockname()[1]

    def cores():
        assert identity(menu.pid)['starttime']==owner_identity['starttime']
        result=[]
        for pid in core_pids(menu.pid):
            assert Path('/proc',pid,'exe').resolve()==core
            item=identity(int(pid));result.append((item['pid'],item['starttime']))
        return result
    def page():click('.primary-nav button:nth-child(2)');wait_for('return !!document.querySelector("#route-add-rule")')
    def close():
        click('#main-modal > .modal-head > button')
        if js('return !!document.querySelector("[data-confirm-accept]")'):click('[data-confirm-accept]')
        wait_for('return !document.querySelector("dialog[open]")')
    def active():
        routing=command('routing');return next(p for p in routing['profiles'] if p['id']==routing['active'])
    def stored():return next(r for r in active()['rules'] if r['name']=='Visual truth rule')
    def edit():click('[data-edit-rule='+json.dumps(stored()['id'])+']');wait_for('return !!document.querySelector("#rule-save")')
    def save():click('#rule-save');wait_for('return !document.querySelector("dialog[open]")',timeout=30)
    def root_id():return js('return document.querySelector("#logical-conditions > [data-condition-node]").dataset.conditionNode')
    def node(n):return '[data-condition-node='+json.dumps(n)+']'
    def children(n):return js('return Array.from(document.querySelector(arguments[0]).querySelectorAll(":scope > .condition-children > [data-condition-node]"),e=>e.dataset.conditionNode)',node(n))
    def button(action,n):return '[data-condition-'+action+'='+json.dumps(n)+']'
    def value(n,key):return node(n)+' [data-condition-value='+json.dumps(key)+']'
    def checked(selector,wanted):
        if js('return document.querySelector(arguments[0]).checked',selector)!=wanted:click(selector)
    def field_text(v):
        if isinstance(v,bool):return str(v).lower()
        if isinstance(v,list):return '\n'.join(str(x) for x in v)
        if isinstance(v,dict):return json.dumps(v)
        return str(v)
    def leaf(n,target):
        wanted=[key for key in target if key!='invert']
        old=js('return Array.from(document.querySelector(arguments[0]).querySelectorAll("[data-condition-field]"),e=>e.dataset.conditionField)',node(n))
        if old and wanted and old[0]!=wanted[0] and wanted[0] not in old:
            select(node(n)+' [data-condition-field='+json.dumps(old[0])+']',wanted[0]);old[0]=wanted[0]
        for key in old:
            if key not in wanted:click(node(n)+' [data-condition-remove-field='+json.dumps(key)+']')
        for key in wanted:
            if not js('return !!document.querySelector(arguments[0])',value(n,key)):
                click(button('add-field',n));last=js('return Array.from(document.querySelector(arguments[0]).querySelectorAll("[data-condition-field]")).at(-1).dataset.conditionField',node(n))
                if last!=key:select(node(n)+' [data-condition-field='+json.dumps(last)+']',key)
            if isinstance(target[key],bool):select(value(n,key),field_text(target[key]))
            else:fill(value(n,key),field_text(target[key]))
        checked(button('invert',n),target.get('invert',False))
    def group(n,target,is_root=False):
        select(button('mode',n),target['mode'])
        for child in children(n):click(button('delete',child))
        for desired in target['rules']:
            kind='group' if desired.get('type')=='logical' else 'leaf';click(button('add-'+kind,n));child=children(n)[-1]
            if kind=='group':group(child,desired)
            else:leaf(child,desired)
        checked('#rule-invert' if is_root else button('invert',n),target.get('invert',False))
    def json_value(back=True):
        click('[data-rule-tab=json]');wait_for('return !!document.querySelector("#rule-json")');v=json.loads(js('return document.querySelector("#rule-json").value'))
        if back:click('[data-rule-tab=fields]');wait_for('return !document.querySelector("#rule-json")')
        return v
    def truth_normalize(v):
        # UI edits Listable values as arrays; explicit false inversion is the
        # same pinned boolean default. Stored JSON itself is never normalized.
        v=listable(v)
        if isinstance(v,list):return [truth_normalize(x) for x in v]
        if isinstance(v,dict):return {k:truth_normalize(x) for k,x in v.items() if not (k=='invert' and x is False)}
        return v
    def apply_route():
        wait_for('return !!document.querySelector("#route-apply") && !document.querySelector("#route-apply").disabled',timeout=30);click('#route-apply');wait_for('return !document.querySelector("#route-apply")',timeout=30)
    def request(label):
        before=origins.counts();client=http.client.HTTPConnection('127.0.0.1',inbound,timeout=5)
        try:
            client.request('GET',f'http://127.0.0.1:{fallback}/native-nested/{label}',headers={'Host':f'127.0.0.1:{fallback}','Connection':'close'})
            response=client.getresponse();body=response.read().decode();assert response.status==200
        finally:client.close()
        after=origins.counts();assert sum(after.values())==sum(before.values())+1
        assert after[body]==before[body]+1;return body
    def proof(case):
        desired=materialize(case['condition'],fallback);current=stored()['config']
        assert truth_normalize(condition(current))==truth_normalize(desired),current
        assert no_nested_actions(current);body=request(case['name']);expected='MATCHED' if case['expectedMatched'] else 'FALLBACK'
        observed.append({'name':case['name'],'config':current,'observed':body,'expected':expected})
        check(body==expected,'visual '+case['name']+' sends real HTTP to '+expected+' as specified by the independent core oracle')
    def echo_socket():
        s=socket.create_connection(('127.0.0.1',inbound),timeout=5);connections.append(s);target='127.0.0.1:'+str(origins.echo.server_address[1]);s.sendall(f'CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n'.encode());headers=b''
        while b'\r\n\r\n' not in headers:
            part=s.recv(4096);assert part;headers+=part
        assert b' 200 ' in headers.split(b'\r\n',1)[0];return s
    def echo(s,label):
        body=('nested-routing-'+label).encode();s.sendall(body);answer=b''
        while len(answer)<len(body):
            part=s.recv(len(body)-len(answer))
            if not part:return False
            answer+=part
        return body==answer
    def state():
        root=Path(os.environ['XDG_DATA_HOME']);assert 'thronium-native-test-' in str(root)
        return json.loads((root/'io.thronium.desktop/library.json').read_text())
    def restore(path):
        click('.primary-nav button:nth-child(5)');wait_for('return !!document.querySelector("[data-settings-section=backup]")');click('[data-settings-section=backup]');wait_for('return !!document.querySelector("#backup-open")');click('#backup-open')
        title='Открыть резервную копию' if command('snapshot')['preferences']['language']=='ru' else 'Open backup'
        try:file_dialog(title,path,opening=True)
        except AssertionError as error:
            if str(error)!='Native file chooser has no visible editable path field':raise
            file_dialog(title,path,opening=True)
        wait_for('return !!document.querySelector("#backup-confirm")');click('#backup-acknowledge');click('#backup-confirm');wait_for('return !document.querySelector("dialog[open]")')

    with tempfile.TemporaryDirectory(prefix='thronium-nested-native-') as temporary:
        try:
            command('disconnect');command('preferences',{**initial['preferences'],'language':'en','theme':'dark'});wait_for('return document.documentElement.lang==="en"')
            baseline=state();baseline_path=Path(temporary)/'baseline.json';baseline_path.write_text(json.dumps({'format':'thronium-backup','version':1,'createdAt':int(time.time()),'library':baseline}))
            command('connectionSettings',{'mode':'local','port':inbound});main=command('saveProfile',{'name':'Nested local direct','groupId':'personal','kind':'sing-box-outbound','config':{'type':'direct'}})['id'];command('select',{'id':main})
            preset={'id':str(uuid.uuid4()),'name':'Native nested conditions','mode':'rules','rules':[],'route':{'final':'direct','auto_detect_interface':True,'find_process':False,'default_domain_resolver':'dns-direct'},'dns':{'servers':[{'type':'local','tag':'dns-direct'}],'final':'dns-direct'}}
            routing=command('routing');command('saveRouting',{**routing,'active':preset['id'],'profiles':routing['profiles']+[preset]});page()
            click('#route-add-rule');fill('#rule-name','Visual truth rule');select('[data-route-condition="0"]','domain');fill('[data-route-field=domain]','never-match.invalid');click('#rule-add-condition');select('[data-route-condition="1"]','ip_cidr');fill('[data-route-field=ip_cidr]','127.0.0.0/8');select('.route-rule-modal .route-target','direct');fill('[data-route-field=override_port]',str(matched));click('#rule-group-conditions');wait_for('return !!document.querySelector("#logical-conditions")')
            flat={'domain':['never-match.invalid'],'ip_cidr':['127.0.0.0/8']};wrapped=json_value()
            check(wrapped=={'type':'logical','mode':'and','rules':[flat],'action':'route','outbound':'direct','override_port':matched} and len(children(root_id()))==1,'wrapping a complete flat match preserves one child and keeps every traffic action at the root')
            save();command('connect',{'id':main});check(request('whole-flat-wrap')=='MATCHED','whole-flat wrapping preserves the pinned OR semantics of domain and IP match fields')

            cases=[v for v in MATRIX['http'] if v['name'].startswith(('and-','or-','not-and-','not-or-')) or v['name'].startswith('nested-A-and-B-or-not-C-1')]
            for case in cases:
                edit();group(root_id(),materialize(case['condition'],fallback),True);save();apply_route();proof(case)
            saved_truth=copy.deepcopy(stored()['config']);edit();r=root_id();nested=children(r)[1];port_leaf=children(nested)[1]
            fill(value(port_leaf,'port'),'70000');click(button('up',port_leaf));check(children(nested)[0]==port_leaf and js('return document.querySelector(arguments[0]).value==="70000" && document.querySelector(arguments[0]).getAttribute("aria-invalid")==="true"',value(port_leaf,'port')),'invalid port text and its error follow the same stable node ID when reordered')
            select('#rule-action','reject');select('[data-route-field=method]','drop');select('#rule-action','route');click('[data-rule-tab=json]')
            check(js('return !document.querySelector("#rule-json") && !!document.querySelector("[role=alert]")') and js('return document.querySelector(arguments[0]).value==="70000"',value(port_leaf,'port')),'action changes and a rejected JSON transition retain the unfinished nested numeric input')
            click('#rule-save');check(js('return !!document.querySelector("dialog[open]")') and stored()['config']==saved_truth,'saving an unfinished nested value leaves the saved and active rule unchanged')
            fill(value(port_leaf,'port'),str(fallback));click(button('down',port_leaf));unchanged=json_value();check(no_nested_actions(unchanged) and unchanged==saved_truth,'repair and reorder back recover the exact original tree without injecting nested action parameters')
            # A wrapper changes only grouping. Inverting it and then unwrapping
            # composes inversion into its single child without changing its ID.
            r=root_id();first=children(r)[0];click(button('wrap',first));wrapper=children(r)[0];click(button('invert',wrapper));click(button('unwrap',wrapper))
            check(children(r)[0]==first and js('return document.querySelector(arguments[0]).checked',button('invert',first)),'wrap and unwrap preserve leaf identity and compose a group inversion into its child')
            click(button('invert',first));before_extra=json_value();r=root_id();click(button('add-group',r));added_group=children(r)[-1];click(button('delete',added_group));check(json_value()==before_extra,'adding and deleting an unfinished group preserves all existing condition data')
            for action in ['reject','sniff','resolve','route-options','direct','hijack-dns','bypass']:
                select('#rule-action',action)
                if action=='reject':select('[data-route-field=method]','drop')
                if action=='sniff':fill('[data-route-field=sniffer]','http, tls')
                if action=='resolve':fill('[data-route-field=server]','dns-direct')
                if action=='route-options':fill('[data-route-field=override_port]','8443')
                obj=json_value();check(obj['action']==action and no_nested_actions(obj) and condition(obj)==condition(before_extra),'root '+action+' options and nested conditions survive a JSON round trip without child actions')
            select('#rule-action','route');check(json_value()==before_extra,'returning to route restores exact root outbound and route options after all action variants');close()

            # Backend validation of malformed source must preserve a live socket.
            false_case=next(v for v in MATRIX['http'] if v['name']=='and-00');edit();group(root_id(),false_case['condition'],True);save();apply_route();held=echo_socket();current_cores=cores();before=command('routing');edit();bad={**false_case['condition'],'action':'route','outbound':'direct','override_port':matched};bad['rules']=copy.deepcopy(bad['rules']);bad['rules'][0]['action']='reject';click('[data-rule-tab=json]');fill('#rule-json',json.dumps(bad));click('#rule-save');wait_for('return !!document.querySelector("dialog [role=alert]")')
            check(command('routing')==before and cores()==current_cores and echo(held,'invalid-core-check'),'real core rejects a nested action while preserving the same owned core, saved routing and existing CONNECT socket');close()
            for case in MATRIX['invalid']:
                edit();bad={**materialize(case['condition'],fallback),'action':'route','outbound':'direct','override_port':matched};click('[data-rule-tab=json]');fill('#rule-json',json.dumps(bad));click('[data-rule-tab=fields]');click('[data-rule-tab=json]');wait_for('return !!document.querySelector("#rule-json")')
                check(json.loads(js('return document.querySelector("#rule-json").value'))==bad,'unsupported source '+case['name']+' remains exact and can return to JSON');close()
            unknown={'type':'logical','mode':'or','future_root':{'retain':[1,None,'unknown']},'rules':[{'network':['tcp'],'future_leaf':{'nested':[1,2]}}],'action':'route','outbound':'direct','override_port':matched}
            edit();click('[data-rule-tab=json]');fill('#rule-json',json.dumps(unknown));click('[data-rule-tab=fields]');check(json_value()==unknown,'unknown root and leaf parameters remain exact across the visual fallback and JSON tabs');close()
            # Source shapes outside the form limits are not truncated.
            for kind in ['depth','nodes']:
                excess={'network':['tcp']}
                if kind=='depth':
                    for _ in range(12):excess={'type':'logical','mode':'and','rules':[excess]}
                else:excess={'type':'logical','mode':'or','rules':[{'port':[i+1]} for i in range(129)]}
                excess={**excess,'action':'route','outbound':'direct'};edit();click('[data-rule-tab=json]');fill('#rule-json',json.dumps(excess));click('[data-rule-tab=fields]');check(json_value()==excess,'source beyond the '+kind+' builder limit remains complete in JSON');close()

            # JSC and Node have different recursion limits. Bound both source
            # and predicted pretty output; never force a gigabyte allocation to
            # reach a platform-specific serializer threshold.
            deep_levels=400;assert 20*deep_levels*deep_levels < 4*1024*1024
            deep_source='{"type":"logical","mode":"and","rules":['*deep_levels+'{"network":["tcp"]}'+']}'*deep_levels
            serializer=js('try {const value=JSON.parse(arguments[0]),text=JSON.stringify(value,null,2);return {supported:true,prettyBytes:text.length};}catch(e){return {supported:false,error:String(e.name)};}',deep_source)
            assert len(deep_source)<4*1024*1024 and serializer.get('prettyBytes',0)<4*1024*1024
            (artifacts/'serializer-observation.json').write_text(json.dumps({'depth':deep_levels,'inputBytes':len(deep_source),**serializer},indent=2)+'\n')
            edit();click('[data-rule-tab=json]');fill('#rule-json',deep_source);click('[data-rule-tab=fields]')
            if serializer['supported']:
                wait_for('return !!document.querySelector("#logical-conditions")');click('[data-rule-tab=json]');wait_for('return !!document.querySelector("#rule-json")')
                preserved=js('return JSON.stringify(JSON.parse(document.querySelector("#rule-json").value))===arguments[0]',deep_source)
            else:preserved=js('return document.querySelector("#rule-json")?.value===arguments[0] && !!document.querySelector("dialog [role=alert]")',deep_source)
            check(preserved,'deep source follows the actual WebView serializer capability and remains complete in JSON');close()

            edit();r=root_id();leaf_id=children(r)[0];fill(value(leaf_id,'network'),'unfinished-value');click('#main-modal > .modal-head > button');check(js('return document.querySelectorAll("dialog:modal").length===2'),'closing a modified nested constructor requests discard confirmation');click('[data-confirm-cancel]');check(js('return document.querySelector(arguments[0]).value==="unfinished-value"',value(leaf_id,'network')),'cancelled discard preserves the same nested node and unfinished text');close()
            for language in ['en','ru']:
                command('preferences',{**command('snapshot')['preferences'],'language':language});wait_for('return document.documentElement.lang==='+json.dumps(language));edit();group(root_id(),materialize(next(v for v in cases if v['name']=='nested-A-and-B-or-not-C-101')['condition'],fallback),True)
                h['request']('POST',h['base']+'/window/rect',{'width':390,'height':844})
                check(js('const d=document.querySelector("dialog"),b=d.querySelector(".modal-body");return b.scrollWidth<=b.clientWidth+1 && d.querySelector(".modal-footer").getBoundingClientRect().bottom<=innerHeight+1 && Array.from(d.querySelectorAll(".condition-field-row .text-input")).every(n=>n.getBoundingClientRect().width>=100)'),'nested groups, editable fields and fixed footer fit '+language+' at 390 pixels');screenshot('nested-routing-'+language);close();h['request']('POST',h['base']+'/window/rect',geometry)
            h['request']('POST',h['base']+'/refresh',{});wait_for('return !!document.querySelector(".add-connection")');page();edit();check(truth_normalize(condition(json_value()))==truth_normalize(false_case['condition']) and cores()==current_cores and echo(held,'reload'),'webview reload preserves saved nested routing and the already-open real TCP connection');close()
            command('disconnect');restore(baseline_path);check(state()==baseline and Path('/proc/net/route').read_bytes()==routes_before and sorted(p.name for p in Path('/sys/class/net').iterdir())==interfaces_before,'restoring the isolated baseline removes fixtures without changing host routes or interfaces')
            audit={'http':observed,'httpCounts':origins.counts(),'events':origins.events,'invalidSourceCases':len(MATRIX['invalid']),'baselineRestored':True,'hostNetworkUnchanged':True,'applicationSha256':hashlib.sha256(application.read_bytes()).hexdigest(),'coreSha256':hashlib.sha256(core.read_bytes()).hexdigest(),'oracleSha256':hashlib.sha256((DIRECTORY/'matrix.json').read_bytes()).hexdigest()}
        finally:
            with contextlib.suppress(Exception):
                if not audit:audit={'http':observed,'httpCounts':origins.counts(),'events':origins.events,'failed':True}
                (artifacts/'nested-routing-audit.json').write_text(json.dumps(audit,ensure_ascii=False,indent=2)+'\n')
            for connection in connections:connection.close()
            with contextlib.suppress(Exception):
                if js('return !!document.querySelector("dialog[open]")'):close()
                command('disconnect');command('preferences',initial['preferences']);h['request']('POST',h['base']+'/window/rect',geometry)
    origins.close()
