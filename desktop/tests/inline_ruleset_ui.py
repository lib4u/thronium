"""Native headless rule-set editing with independent HTTP and DNS packet proofs."""
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
from native_menu import NativeMenu
from native_processes import core_pids
from external_core_fixture import identity
from nested_routing_fixtures import Origins, materialize
from inline_ruleset_fixtures import DIRECTORY, MATRIX, DnsOrigins, dns_exchange


def run(h):
    command,click,fill,select,wait_for,js,check,screenshot=(h[k] for k in ('command','click','fill','select','wait_for','js','check','screenshot'))
    initial=command('snapshot');geometry=h['request']('GET',h['base']+'/window/rect')
    application=Path(h['args'].application).resolve();core=application.with_name('ThroniumCore');artifacts=Path(h['args'].artifacts)
    menu=NativeMenu();assert Path('/proc',str(menu.pid),'exe').resolve()==application
    owner=identity(menu.pid);origins=Origins();dns=DnsOrigins();http_rows=[];dns_rows=[];connections=[];audit={}
    matched=origins.matched.server_address[1];fallback=origins.fallback.server_address[1]
    dns_match=dns.matched.server_address[1];dns_fallback=dns.fallback.server_address[1]
    routes_before=Path('/proc/net/route').read_bytes();interfaces_before=sorted(p.name for p in Path('/sys/class/net').iterdir())
    with socket.socket() as available:available.bind(('127.0.0.1',0));inbound=available.getsockname()[1]

    def cores():
        assert identity(menu.pid)['starttime']==owner['starttime']
        result=[]
        for pid in core_pids(menu.pid):
            assert Path('/proc',pid,'exe').resolve()==core
            value=identity(int(pid));result.append((value['pid'],value['starttime']))
        return result
    def state():
        root=Path(os.environ['XDG_DATA_HOME']);assert 'thronium-native-test-' in str(root)
        return json.loads((root/'io.thronium.desktop/library.json').read_text())
    def active():
        routing=command('routing');return next(p for p in routing['profiles'] if p['id']==routing['active'])
    def set_profile(profile):
        routing=command('routing');command('saveRouting',{**routing,'profiles':[profile if p['id']==profile['id'] else p for p in routing['profiles']]})
    def page():
        click('.primary-nav button:nth-child(2)');wait_for('return !!document.querySelector("#route-add-rule")');click('[data-route-tab=sets]');wait_for('return !!document.querySelector("#ruleset-add")')
    def refresh_page():
        click('.primary-nav button:first-child');page()
    def close():
        click('#main-modal > .modal-head > button')
        if js('return !!document.querySelector("[data-confirm-accept]")'):click('[data-confirm-accept]')
        wait_for('return !document.querySelector("dialog[open]")')
    def contents(index=0):
        click('[data-set-content='+json.dumps(str(index))+']');wait_for('return !!document.querySelector("#geo-content-save")')
    def fields():
        click('[data-geo-content-tab=fields]');wait_for('return !!document.querySelector("#logical-conditions")')
    def save():
        click('#geo-content-save');wait_for('return !document.querySelector("dialog[open]")',timeout=30)
    def source(index=0):return active()['route']['rule_set'][index]
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
    def group(n,target):
        select(button('mode',n),target['mode'])
        replace_children(n,target['rules'])
        checked(button('invert',n),target.get('invert',False))
    def replace_children(n,rows):
        for child in children(n):click(button('delete',child))
        for desired in rows:
            kind='group' if desired.get('type')=='logical' else 'leaf';click(button('add-'+kind,n));child=children(n)[-1]
            if kind=='group':group(child,desired)
            else:leaf(child,desired)
    def build(rows):fields();replace_children(root_id(),rows)
    def json_value(back=True):
        click('[data-geo-content-tab=json]');wait_for('return !!document.querySelector("#geo-content-text")')
        value=json.loads(js('return document.querySelector("#geo-content-text").value'))
        if back:fields()
        return value
    def raw(rows):
        click('[data-geo-content-tab=json]');wait_for('return !!document.querySelector("#geo-content-text")');fill('#geo-content-text',json.dumps(rows))
    def truth_normalize(v):
        if isinstance(v,list):return [truth_normalize(x) for x in v]
        if not isinstance(v,dict):return v
        result={k:truth_normalize(x) for k,x in v.items() if not(k=='invert' and x is False)}
        for key in ['network','port','query_type']:
            if key in result and not isinstance(result[key],list):result[key]=[result[key]]
        return result
    def apply_route():
        wait_for('return !!document.querySelector("#route-apply") && !document.querySelector("#route-apply").disabled',timeout=30);click('#route-apply');wait_for('return !document.querySelector("#route-apply")',timeout=30)
    def request(label):
        before=origins.counts();client=http.client.HTTPConnection('127.0.0.1',inbound,timeout=5)
        try:
            client.request('GET',f'http://127.0.0.1:{fallback}/native-nested/inline-{label}',headers={'Host':f'127.0.0.1:{fallback}','Connection':'close'})
            response=client.getresponse();body=response.read().decode();assert response.status==200
        finally:client.close()
        after=origins.counts();assert sum(after.values())==sum(before.values())+1 and after[body]==before[body]+1
        return body
    def hold():
        connection=socket.create_connection(('127.0.0.1',inbound),timeout=5);connections.append(connection)
        target='127.0.0.1:'+str(origins.echo.server_address[1]);connection.sendall(f'CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n'.encode());headers=b''
        while b'\r\n\r\n' not in headers:
            part=connection.recv(4096);assert part;headers+=part
        assert b' 200 ' in headers.split(b'\r\n',1)[0];return connection
    def echo(connection,label):
        body=('inline-ruleset-'+label).encode();connection.sendall(body);answer=b''
        while len(answer)<len(body):
            part=connection.recv(len(body)-len(answer))
            if not part:return False
            answer+=part
        return body==answer
    def watch():
        js('''if(!window.__inlineAudit){window.__inlineAudit={fetch:window.fetch,calls:[]};window.fetch=function(input,options){let data;try{data=JSON.parse(options?.body)}catch{};if(data?.name==='checkRouting'&&String(input).includes('/app_command'))window.__inlineAudit.calls.push(data.payload);return window.__inlineAudit.fetch.apply(this,arguments);};}''')
    def checks():return js('return window.__inlineAudit.calls')
    def validate_failure(expected_rules):
        before=command('routing');n=len(checks());click('#geo-content-check');wait_for('return !!document.querySelector("dialog [role=alert]")',timeout=30)
        assert len(checks())==n+1 and checks()[-1]['route']['rule_set'][0]['rules']==expected_rules
        return command('routing')==before

    with tempfile.TemporaryDirectory(prefix='thronium-inline-native-') as temporary:
        try:
            command('disconnect');command('preferences',{**initial['preferences'],'language':'en','theme':'dark'});wait_for('return document.documentElement.lang==="en"')
            baseline=state()
            command('connectionSettings',{'mode':'local','port':inbound});main=command('saveProfile',{'name':'Inline local direct','groupId':'personal','kind':'sing-box-outbound','config':{'type':'direct'}})['id'];command('select',{'id':main})
            preset={'id':str(uuid.uuid4()),'name':'Native inline conditions','mode':'rules','rules':[],'route':{'final':'direct','auto_detect_interface':True,'find_process':False,'default_domain_resolver':'dns-fallback'},'dns':{'servers':[{'type':'udp','tag':'dns-match','server':'127.0.0.1','server_port':dns_match},{'type':'udp','tag':'dns-fallback','server':'127.0.0.1','server_port':dns_fallback}],'final':'dns-fallback','disable_cache':True}}
            routing=command('routing');command('saveRouting',{**routing,'active':preset['id'],'profiles':routing['profiles']+[preset]});page();watch()
            click('#ruleset-add');select('#resource-type','inline');fill('#resource-tag','fixture');fill('#resource-rules','[{"domain_suffix":"never-match.invalid","invert":false}]');click('#resource-save');wait_for('return !document.querySelector("dialog[open]")',timeout=30)
            original_set=source();contents();fields();r=root_id();leaf_id=children(r)[0]
            allowed=set(js('return Array.from(document.querySelector(arguments[0]).options,o=>o.value)',node(leaf_id)+' [data-condition-field]'))
            expected={'query_type','network','domain','domain_suffix','domain_keyword','domain_regex','source_ip_cidr','ip_cidr','source_port','source_port_range','port','port_range','process_name','process_path','process_path_regex','package_name','package_name_regex','network_type','network_is_expensive','network_is_constrained','wifi_ssid','wifi_bssid','network_interface_address','default_interface_address'}
            check(allowed==expected and js('return document.querySelector(arguments[0]).dataset.conditionKind==="set"',node(r)) and not js('return !!document.querySelector(arguments[0]) || !!document.querySelector(arguments[1]) || !!document.querySelector("#rule-action")',button('mode',r),button('invert',r)),'inline headless fields match all 24 editable pinned fields, with no root mode inversion or traffic action controls')
            check(json_value()==original_set['rules'],'viewing entries conditions and JSON preserves scalar fields and explicit false inversion exactly');click('[data-geo-content-tab=list]');save();check(source()==original_set,'saving an untouched simple list preserves its original JSON representation')
            # The traffic rule and DNS rule contain nested references, so rename
            # must repair both. All actual destinations belong to this fixture.
            current=active();current['rules']=[{'id':str(uuid.uuid4()),'name':'Inline DNS capture','enabled':True,'config':{'network':['udp'],'port':[dns_fallback],'action':'hijack-dns'}},{'id':str(uuid.uuid4()),'name':'Inline HTTP proof','enabled':True,'config':{'type':'logical','mode':'and','rules':[{'network':['tcp']},{'type':'logical','mode':'or','rules':[{'rule_set':['fixture']},{'port':[1]}]}],'action':'route','outbound':'direct','override_port':matched}}]
            current['dns']['rules']=[{'type':'logical','mode':'and','rules':[{'query_type':['A','AAAA']},{'type':'logical','mode':'or','rules':[{'rule_set':['fixture']},{'domain':['never-match.invalid']}]}],'action':'route','server':'dns-match'}]
            set_profile(current);refresh_page();command('connect',{'id':main})
            for case in MATRIX['http']:
                desired=materialize(case['rules'],fallback);contents();build(desired);save();apply_route();actual=source()['rules']
                assert truth_normalize(actual)==truth_normalize(desired)
                body=request(case['name']);expected_body='MATCHED' if case['expectedMatched'] else 'FALLBACK';http_rows.append({'name':case['name'],'rules':actual,'expected':expected_body,'observed':body})
                check(body==expected_body,'inline visual '+case['name']+' sends actual HTTP to '+expected_body+' from the independent oracle')
            for index,case in enumerate(MATRIX['dns']):
                contents()
                if case['name']=='null-query-type-list':raw(case['rules'])
                else:build(case['rules'])
                save();apply_route();actual=source()['rules'];assert truth_normalize(actual)==truth_normalize(case['rules'])
                observations=[]
                for kind,label in [(1,'A'),(28,'AAAA')]:
                    before=dns.counts();answer=dns_exchange(inbound,dns_fallback,f'native-{index}-{kind}.oracle.invalid',kind,100+index*2+(kind==28));after=dns.counts()
                    name='MATCHED' if case['expected'+label] else 'FALLBACK';assert sum(after.values())==sum(before.values())+1 and after[name]==before[name]+1
                    observations.append({'type':label,'origin':name,'address':answer});assert answer==dns.addresses[name][kind]
                dns_rows.append({'name':case['name'],'rules':actual,'observations':observations})
                check(True,'inline '+case['name']+' selects real A and AAAA DNS responders with matching packet counters')
            # Create a valid multi-root draft; syntax errors and reordering must
            # not silently drop the latest entered text when changing tabs.
            contents();build([{'query_type':['A',28]},{'port':[fallback]}]);r=root_id();query,port=children(r);fill(value(query,'query_type'),'A, 65536');click(button('down',query))
            check(children(r)[1]==query and js('return document.querySelector(arguments[0]).value==="A, 65536" && document.querySelector(arguments[0]).getAttribute("aria-invalid")==="true"',value(query,'query_type')),'invalid query type and its error keep the same node ID during root-level reordering')
            n=len(checks());before=command('routing');click('[data-geo-content-tab=json]');click('#geo-content-check');click('#geo-content-save')
            check(not js('return !!document.querySelector("#geo-content-text")') and js('return document.querySelector(arguments[0]).value==="A, 65536"',value(query,'query_type')) and command('routing')==before and len(checks())==n,'unfinished headless input blocks tab change Check and Save without replacing the saved set or reaching the core')
            fill(value(query,'query_type'),'A, 28');click(button('up',query));repaired=json_value();check(repaired==[{'query_type':['A',28]},{'port':[fallback]}],'repair and reverse reorder recover the exact typed headless array')
            r=root_id();query=children(r)[0];click(button('wrap',query));wrapper=children(r)[0];click(button('invert',wrapper));click(button('unwrap',wrapper));check(children(r)[0]==query and js('return document.querySelector(arguments[0]).checked',button('invert',query)),'headless wrap unwrap and inversion retain the same source node identity');close()
            # Ordinary HTTP does not match a query_type-only set, so an owned
            # CONNECT can remain open through every refused candidate check.
            contents();build([{'query_type':['A']}]);save();apply_route();held=hold();held_cores=cores();valid=active()
            for case in MATRIX['invalidCheck']:
                contents();raw(case['rules']);fields();preserved=json_value(False)
                assert preserved==case['rules']
                unchanged=validate_failure(case['rules'])
                check(unchanged and cores()==held_cores and echo(held,'invalid-'+case['name']),'raw '+case['name']+' stays exact while real Check rejects it and preserves the existing CONNECT');close()
            # ResourcesPanel must preserve an unsupported source wrapper and
            # null/malformed children; inspection cannot turn bad data valid.
            unsupported=copy.deepcopy(valid);unsupported_set=unsupported['route']['rule_set'][0];unsupported_set['future_wrapper']={'retain':[1,None,'opaque']};unsupported_set['rules']=[None,{'type':'logical','mode':'and','rules':[{'domain_suffix':['source.invalid'],'future_match':{'retain':False}}]}]
            set_profile(unsupported);refresh_page();contents();fields();check(json_value()==unsupported_set['rules'],'existing raw null children and unknown nested data survive the source content editor without filtering')
            raw(unsupported_set['rules']);before=command('routing');n=len(checks());click('#geo-content-check');wait_for('return !!document.querySelector("dialog [role=alert]")',timeout=30)
            check(len(checks())==n and command('routing')==before and json.loads(js('return document.querySelector("#geo-content-text").value'))==unsupported_set['rules'] and echo(held,'null-source'),'a malformed top-level null stays visible and is refused locally without modifying the saved set or connection');close()
            unsupported_set['rules']=unsupported_set['rules'][1:];set_profile(unsupported);refresh_page();contents();raw(unsupported_set['rules']);before=command('routing');n=len(checks());click('#geo-content-check');wait_for('return !!document.querySelector("dialog [role=alert]")',timeout=30)
            check(len(checks())==n+1 and checks()[-1]['route']['rule_set'][0]==unsupported_set and command('routing')==before and echo(held,'opaque-wrapper'),'content validation forwards the complete unknown wrapper and source rules and never claims success after discarding them');close();set_profile(valid);refresh_page()
            # A comma is legal inside a single opaque tag. No-edit save must
            # not reinterpret that source name as multiple aliases.
            comma=copy.deepcopy(valid)
            def renamed(value,old,new):
                if isinstance(value,dict):return {k:([new if x==old else x for x in v] if k=='rule_set' and isinstance(v,list) else new if k=='rule_set' and v==old else renamed(v,old,new)) for k,v in value.items()}
                if isinstance(value,list):return [renamed(v,old,new) for v in value]
                return value
            comma=renamed(comma,'fixture','opaque, one');comma['route']['rule_set'][0]['tag']='opaque, one';set_profile(comma);refresh_page();contents();fields();json_value();save();check(active()==comma,'unchanged opaque comma tag and nested routing DNS references survive content save without alias splitting')
            contents();fill('#geo-content-name','renamed-inline');save();renamed_profile=active();expected_profile=renamed(comma,'opaque, one','renamed-inline');expected_profile['route']['rule_set'][0]['tag']='renamed-inline'
            check(renamed_profile==expected_profile,'explicit content rename repairs nested route and DNS references while preserving every other field')
            apply_route();held.close();connections.remove(held);held=hold();held_cores=cores();click('[data-resource-delete="set:0"]');click('#resource-delete-confirm');wait_for('return !!document.querySelector("dialog [role=alert]")');check(active()==renamed_profile and echo(held,'delete-ref'),'deleting an inline set with nested route and DNS references refuses atomically');close()
            # List switches without edits preserve grouping, duplicate entries
            # and scalar-vs-array forms; a deliberate list edit can rebuild it.
            rich=copy.deepcopy(renamed_profile);rich['route']['rule_set'][0]['rules']=[{'domain':['one.invalid','one.invalid'],'domain_suffix':'two.invalid','invert':False},{'domain':'three.invalid'}];set_profile(rich);refresh_page();contents();fields();check(json_value()==rich['route']['rule_set'][0]['rules'],'rich source grouping duplicates scalar fields and explicit false defaults survive visual JSON inspection');click('[data-geo-content-tab=list]');save();check(active()==rich,'an untouched simple list saves exact grouped duplicate source data')
            contents();fill('#geo-content-text','suffix:edited.oracle.invalid\ndomain:exact.oracle.invalid');save();check(source()['rules']==[{'domain_suffix':['edited.oracle.invalid']},{'domain':['exact.oracle.invalid']}],'an explicit simple-list edit remains supported alongside the nested constructor')
            contents();build([{'type':'logical','mode':'and','rules':[{'network':['tcp']},{'type':'logical','mode':'or','rules':[{'port':[fallback]},{'domain_suffix':['oracle.invalid'],'invert':True}]}]}]);for_layout=json_value();save();saved=active()
            contents();fields();r=root_id();first_group=children(r)[0];first_leaf=children(first_group)[0];fill(value(first_leaf,'network'),'uncommitted');click('#main-modal > .modal-head > button');check(js('return document.querySelectorAll("dialog:modal").length===2'),'closing a modified headless constructor requests discard confirmation');click('[data-confirm-cancel]');check(js('return document.querySelector(arguments[0]).value==="uncommitted"',value(first_leaf,'network')),'cancelled discard retains the same nested headless input');close()
            for language in ['en','ru']:
                command('preferences',{**command('snapshot')['preferences'],'language':language});wait_for('return document.documentElement.lang==='+json.dumps(language));contents();fields();h['request']('POST',h['base']+'/window/rect',{'width':390,'height':844})
                check(js('const d=document.querySelector("dialog"),b=d.querySelector(".modal-body");return b.scrollWidth<=b.clientWidth+1&&d.querySelector(".modal-footer").getBoundingClientRect().bottom<=innerHeight+1&&Array.from(d.querySelectorAll(".condition-field-row .text-input")).every(n=>n.getBoundingClientRect().width>=100)'),'inline nested conditions and validation footer fit '+language+' at 390 pixels');screenshot('inline-ruleset-'+language);close();h['request']('POST',h['base']+'/window/rect',geometry)
            h['request']('POST',h['base']+'/refresh',{});wait_for('return !!document.querySelector(".add-connection")');page();contents();fields();check(json_value()==for_layout and active()==saved and cores()==held_cores and echo(held,'reload'),'saved headless structure and the active CONNECT survive a WebView reload');close()
            exported=command('exportRoutingProfile',{'id':saved['id']});check(exported['profile']['route']['rule_set']==saved['route']['rule_set'] and exported['profile']['dns']==saved['dns'],'routing export preserves the full inline set and all repaired DNS references')
            command('disconnect');current=command('routing');command('saveRouting',{**current,'active':baseline['routing']['active'],'profiles':baseline['routing']['profiles']});command('deleteProfiles',{'ids':[main]});command('preferences',baseline['preferences'])
            cleaned=state();expected=copy.deepcopy(baseline);expected['routing']['revision']=cleaned['routing']['revision']
            check(cleaned==expected and cleaned['routing']['revision']>baseline['routing']['revision'] and Path('/proc/net/route').read_bytes()==routes_before and sorted(p.name for p in Path('/sys/class/net').iterdir())==interfaces_before,'normal cleanup removes all fixture data while preserving the monotonic routing revision and unchanged host network')
            audit={'http':http_rows,'httpCounts':origins.counts(),'dns':dns_rows,'dnsCounts':dns.counts(),'invalidCheckCases':len(MATRIX['invalidCheck']),'baselineValuesRestored':True,'routingRevisionAdvanced':True,'hostNetworkUnchanged':True,'applicationSha256':hashlib.sha256(application.read_bytes()).hexdigest(),'coreSha256':hashlib.sha256(core.read_bytes()).hexdigest(),'oracleSha256':hashlib.sha256((DIRECTORY/'oracle-contract.json').read_bytes()).hexdigest()}
        finally:
            with contextlib.suppress(Exception):
                if not audit:audit={'http':http_rows,'httpCounts':origins.counts(),'dns':dns_rows,'dnsCounts':dns.counts(),'failed':True}
                (artifacts/'inline-ruleset-audit.json').write_text(json.dumps(audit,ensure_ascii=False,indent=2)+'\n')
            for connection in connections:connection.close()
            with contextlib.suppress(Exception):
                if js('return !!document.querySelector("dialog[open]")'):close()
                command('disconnect');command('preferences',initial['preferences']);h['request']('POST',h['base']+'/window/rect',geometry)
            with contextlib.suppress(Exception):js('if(window.__inlineAudit){window.fetch=window.__inlineAudit.fetch;delete window.__inlineAudit;}')
    origins.close();dns.close()
