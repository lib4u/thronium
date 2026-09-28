"""Actual Qt selector snapshot review; real core Check, current CONNECT guards.

Imported proxies are never started. The held CONNECT uses a disposable direct
profile and loopback echo server. Exact UUID-plan retention also has backend tests.
"""
import contextlib
import copy
import hashlib
import json
from pathlib import Path
import shutil
import socket
import socketserver
import tempfile
import threading
import time
import uuid
from legacy_selector_fixtures import DIRECTORY, SELECTORS, SECRETS, expected_options
from native_dialogs import file_dialog


def run(h):
    command, click, wait_for, js, check, screenshot = (h[k] for k in ('command','click','wait_for','js','check','screenshot'))
    initial=command('snapshot');geometry=h['request']('GET',h['base']+'/window/rect')
    manifest=json.loads((DIRECTORY/'manifest.json').read_text())
    for name,digest in manifest['sha256'].items():
        assert hashlib.sha256((DIRECTORY/name).read_bytes()).hexdigest()==digest
    connection=None; audit=None

    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            with contextlib.suppress(OSError):
                while body:=self.request.recv(65536): self.request.sendall(body)
    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address=True;daemon_threads=True
    server=Server(('127.0.0.1',0),Echo)
    threading.Thread(target=server.serve_forever,daemon=True).start()

    def settings():
        click('.primary-nav button:nth-child(5)')
        wait_for('return !!document.querySelector("[data-settings-section=backup]")')
        click('[data-settings-section=backup]')
        wait_for('return !!document.querySelector("#backup-open")')

    def previews(): return js('return window.__legacySelectorAudit?.previews || []')
    def latest(): return previews()[-1]
    def wait_preview(count):
        wait_for('return window.__legacySelectorAudit.previews.length > '+str(count))
        wait_for('return !!document.querySelector("#backup-confirm") && !document.querySelector("#backup-refresh").disabled')
        return latest()

    def open_file(path=None):
        count=len(previews());ru=command('snapshot')['preferences']['language']=='ru'
        click('#backup-open');file_dialog('Открыть резервную копию' if ru else 'Open backup',path,opening=True)
        wait_for('return !document.querySelector("#backup-open").disabled')
        return wait_preview(count) if path else None

    def close():
        click('#main-modal > .modal-head > button')
        wait_for('return !document.querySelector("dialog[open]")')

    def toggle(selector):
        count=len(previews());click(selector);return wait_preview(count)

    def refresh():
        count=len(previews());click('#backup-refresh');return wait_preview(count)

    def reject(token,code):
        try: command('restoreBackup',{'token':token})
        except RuntimeError as error: assert code in str(error),str(error)
        else: raise AssertionError('Forbidden selector backup operation accepted')

    def apply():
        if not js('return document.querySelector("#backup-acknowledge").checked'): click('#backup-acknowledge')
        click('#backup-confirm')
        wait_for('return !document.querySelector("dialog[open]") && !!document.querySelector("#backup-notice")')

    def state(label):
        path=root/(label+'-'+str(time.monotonic_ns())+'.json')
        ru=command('snapshot')['preferences']['language']=='ru'
        click('#backup-save');file_dialog('Сохранить резервную копию' if ru else 'Save backup',path)
        wait_for('return !document.querySelector("#backup-save").disabled && !!document.querySelector("#backup-notice")')
        return json.loads(path.read_text())['library'],path

    def safe(preview):
        text=json.dumps(preview,ensure_ascii=False)+js('return document.querySelector("#main-modal")?.textContent || ""')
        return not any(secret in text for secret in SECRETS)

    def echo(label):
        body=('legacy-selector-'+label).encode();connection.sendall(body);received=b''
        while len(received)<len(body):
            part=connection.recv(4096)
            if not part: break
            received+=part
        return received==body

    def selectors(library): return {p['name']:p for p in library['profiles'] if p['name'] in {c['name'] for _,_,c in SELECTORS}}

    with tempfile.TemporaryDirectory(prefix='thronium-legacy-selector-ui-') as temporary:
        root=Path(temporary)
        copies={name:root/name for name in manifest['sha256']}
        for name,path in copies.items(): shutil.copyfile(DIRECTORY/name,path)
        try:
            command('disconnect');command('preferences',{**initial['preferences'],'language':'en','theme':'dark'})
            wait_for('return document.documentElement.lang === "en"');settings()
            js('''
const original=window.fetch;window.__legacySelectorAudit={original,previews:[]};
window.fetch=function(input,options){
 let name=null;try{if(String(input).includes('/app_command'))name=JSON.parse(options?.body||'{}').name;}catch{}
 const result=original.apply(this,arguments);
 if(['readBackup','legacyBackupScopes','refreshBackupPreview','previewPreviousBackup'].includes(name))result.then(r=>r.clone().json()).then(v=>{const p=v?.preview||v;if(p?.token&&p?.current)window.__legacySelectorAudit.previews.push(p);}).catch(()=>{});
 return result;
};
''')
            baseline,baseline_path=state('baseline')
            with socket.socket() as available:
                available.bind(('127.0.0.1',0));port=available.getsockname()[1]
            command('preferences',{**command('snapshot')['preferences'],'inboundPort':port})
            command('connectionSettings',{'mode':'local','port':port})
            existing=command('saveProfile',{'name':'Current profile for selector import','groupId':'personal','kind':'sing-box-outbound','config':{'type':'direct'}})['id']
            command('select',{'id':existing})
            routing=command('routing')
            routing['profiles'][0].update(name='Current selector-test DNS',dns={'servers':[{'type':'local','tag':'current-dns'}],'final':'current-dns'},route={'final':'proxy','auto_detect_interface':True,'default_domain_resolver':'current-dns'})
            command('saveRouting',routing)
            before,_=state('before')
            open_file()
            check(not js('return !!document.querySelector("dialog[open]")') and state('chooser-cancel')[0]==before,'cancelling the native chooser leaves the current library intact')
            preview=open_file(copies['valid.thrbackup'])
            check(preview['legacy']['autoSelectorCount']==2 and not preview['legacy']['canApply'] and js('return !document.querySelector("#legacy-selector-snapshot").checked && document.querySelector("#backup-confirm").disabled && document.querySelector("#backup-acknowledge").disabled'),'Qt selector snapshots require a separate explicit choice before acknowledgement or import')
            reject(preview['token'],'legacy_import_blocked')
            check(safe(preview) and sorted((r['sourceId'],r['members'],r['pinned']) for r in preview['legacy']['selectorSnapshots'])==[(54,2,True),(55,2,True)] and all(set(r)=={'sourceId','name','members','pinned'} for r in preview['legacy']['selectorSnapshots']),'safe review shows source names, member counts and preference without probe URLs, configs or SQL')
            picked=toggle('#legacy-selector-snapshot')
            check(picked['legacy']['canApply'] and picked['legacy']['scopes']['autoSelectors']=='last-built' and picked['token']!=preview['token'] and js('return !document.querySelector("#backup-acknowledge").checked && document.querySelector("#backup-confirm").disabled'),'explicit snapshot choice prepares a new token but still requires ordinary additive acknowledgement')
            reject(preview['token'],'backup_preview_expired')
            click('#backup-acknowledge');unpicked=toggle('#legacy-selector-snapshot')
            check(not unpicked['legacy']['canApply'] and js('return !document.querySelector("#backup-acknowledge").checked && document.querySelector("#backup-confirm").disabled'),'removing the snapshot choice resets acknowledgement and blocks the backend plan again')
            reject(unpicked['token'],'legacy_import_blocked')
            toggle('#legacy-scope-routes');route_only=toggle('#legacy-scope-profiles')
            check(not route_only['legacy']['canApply'] and any(i['code']=='legacy_routes_require_profiles' for i in route_only['legacy']['issues']) and not js('return !!document.querySelector("#legacy-selector-snapshot")'),'route-only selection cannot bypass selector consent by importing a route that refers to its profiles')
            reject(route_only['token'],'legacy_import_blocked')
            toggle('#legacy-scope-profiles');toggle('#legacy-scope-routes');picked=toggle('#legacy-selector-snapshot')
            h['request']('POST',h['base']+'/window/rect',{'width':390,'height':820})
            check(safe(picked) and js('return document.querySelector("#legacy-selector-review").textContent.includes("last") && document.querySelector("dialog").scrollWidth <= document.querySelector("dialog").clientWidth+1 && document.querySelector(".modal-footer").getBoundingClientRect().bottom <= innerHeight+1'),'English selector consent, fixed-membership explanation and actions fit at 390 pixels')
            screenshot('legacy-selector-review-en')
            command('preferences',{**command('snapshot')['preferences'],'language':'ru'})
            wait_for('return document.documentElement.lang === "ru"');picked=refresh()
            check(safe(picked) and js('return document.querySelector("#legacy-selector-review").textContent.includes("состав") && document.querySelector("dialog").scrollWidth <= document.querySelector("dialog").clientWidth+1 && document.querySelector(".modal-footer").getBoundingClientRect().bottom <= innerHeight+1'),'Russian selector choice and saved member counts fit at 390 pixels')
            screenshot('legacy-selector-review-ru');close()
            h['request']('POST',h['base']+'/window/rect',{'width':1280,'height':860})
            command('preferences',{**command('snapshot')['preferences'],'language':'en'})
            wait_for('return document.documentElement.lang === "en"')
            check(state('review-cancel')[0]==before,'cancelling selector review preserves all profiles, routes, DNS and restored display preferences')

            command('connect',{'id':existing});connection=socket.create_connection(('127.0.0.1',port),timeout=5)
            target='127.0.0.1:'+str(server.server_address[1]);connection.sendall(f'CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n'.encode())
            headers=b''
            while b'\r\n\r\n' not in headers:
                chunk=connection.recv(4096);assert chunk;headers+=chunk
            assert b' 200 ' in headers.split(b'\r\n',1)[0]
            open_file(copies['valid.thrbackup']);active=toggle('#legacy-selector-snapshot');click('#backup-acknowledge')
            check(js('return document.querySelector("#backup-confirm").disabled') and echo('review') and command('snapshot')['running']==existing,'choosing a snapshot during an active connection preserves the same real CONNECT and disables apply')
            reject(active['token'],'backup_disconnect_first')
            check(echo('backend-guard') and command('snapshot')['running']==existing,'backend active-session guard refuses selector import without stopping the existing core')
            close();connection.close();connection=None;command('disconnect')
            before,_=state('before-stale')
            open_file(copies['valid.thrbackup']);picked=toggle('#legacy-selector-snapshot');click('#backup-acknowledge')
            added_current=command('saveProfile',{'name':'Current record created during selector review','groupId':'personal','kind':'sing-box-outbound','config':{'type':'direct'}})['id']
            before_apply=copy.deepcopy(before);before_apply['profiles'].append({k:v for k,v in command('profile',{'id':added_current}).items() if k not in ('expectedRevision','vlessCore')})
            click('#backup-confirm')
            wait_for('return document.querySelector("dialog .desktop-inline-error")?.textContent.includes("changed")')
            check(len(command('snapshot')['profiles'])==len(before_apply['profiles']),'stale selector preview cannot overwrite a record added while the modal is open')
            updated=refresh()
            check(updated['token']!=picked['token'] and updated['legacy']['selectorSnapshots']==picked['legacy']['selectorSnapshots'] and updated['legacy']['scopes']==picked['legacy']['scopes'] and updated['incoming']['profiles']==picked['incoming']['profiles']+1 and js('return !document.querySelector("#backup-acknowledge").checked'),'refresh retains snapshot consent and member report, rebases on the new record and resets acknowledgement')
            reject(picked['token'],'backup_preview_expired');apply()
            imported,_=state('imported');added=imported['profiles'][len(before_apply['profiles']):];groups=imported['groups'][len(before_apply['groups']):]
            check(len(added)==15 and len(groups)==4 and all(str(uuid.UUID(p['id']))==p['id'] for p in added+groups),'acknowledged snapshot import adds all 15 profiles and four groups with fresh UUIDs')
            by_name={p['name']:p for p in added};pools=selectors(imported)
            source_ids={row[0]:by_name[row[2]]['id'] for row in __import__('legacy_backup_fixtures').sources()}
            for sid,gid,config in SELECTORS:
                profile=pools[config['name']];expected={'type':'auto-selector','members':[source_ids[i] for i in config['last_built']],'pinned_profile':source_ids[config['pinned_id']],**expected_options(config)}
                check(profile['kind']=='auto-selector' and profile['config']==expected,'exact last_built order, pin and Qt health parameters survive for '+config['name'])
            wrapped_group=next(g for g in groups if g['name']=='Legacy front and landing')
            check(wrapped_group['proxyChain']=={'front':source_ids[41],'landing':source_ids[42]} and pools[SELECTORS[1][2]['name']]['groupId']==wrapped_group['id'],'containing-group front and landing remap independently from the selector tracked group')
            unchanged=copy.deepcopy(imported);unchanged['profiles']=unchanged['profiles'][:len(before_apply['profiles'])];unchanged['groups']=unchanged['groups'][:len(before_apply['groups'])]
            for p in added: unchanged['preferences']['vlessOverrides'].pop(p['id'],None)
            if unchanged!=before_apply:
                for label,value in (('additive-before',before_apply),('additive-after',unchanged)): (h['artifacts']/(label+'.json')).write_text(json.dumps(value,ensure_ascii=False,indent=1))
            check(unchanged==before_apply and command('snapshot')['running'] is None,'additive selector import retains the exact current routes, DNS, settings, selection and preexisting records')
            click('.primary-nav button:nth-child(1)')
            for profile in pools.values():
                h['select']('.group-strip select',profile['groupId'])
                selector='[data-profile-menu='+json.dumps(profile['id'])+']';wait_for('return !!document.querySelector('+json.dumps(selector)+')')
                js('document.querySelector(arguments[0]).scrollIntoView({block:"center"})',selector)
                wait_for('const top=document.querySelector('+json.dumps(selector)+').getBoundingClientRect().top;const old=window.__legacySelectorMenuTop;window.__legacySelectorMenuTop=top;return top===old && top>0 && top<innerHeight-40')
                click(selector);click('#menu-edit-profile');wait_for('return !!document.querySelector("#profile-editor")')
                click('[data-profile-tab="json"]')
                check(json.loads(js('return document.querySelector("#profile-json").value'))==profile['config'],'native editor retains complete imported selector references and runtime options')
                click('.modal-footer .button.secondary');wait_for('return !!document.querySelector(".desktop-success") || !!document.querySelector(".editor-modal [role=alert]")',25)
                check(not js('return !!document.querySelector(".editor-modal [role=alert]")') and command('snapshot')['running'] is None,'actual bundled core Check accepts imported '+profile['name']+' without starting its remote proxies')
                close()
                runtime=command('connectionConfiguration',{'id':profile['id'],'active':False})
                outbounds=[o for part in runtime['parts'] for o in part['config'].get('outbounds',[])]
                pool=next(o for o in outbounds if o.get('type')=='auto-selector')
                check(all(tag.endswith(member) for tag,member in zip(pool['outbounds'],profile['config']['members'])) and pool['pinned'].endswith(profile['config']['pinned_profile']),'runtime generation retains ranked member order and preferred-member mapping')
                if profile['name']==SELECTORS[1][2]['name']:
                    exits=[next(o for o in outbounds if o.get('tag')==tag) for tag in pool['outbounds']]
                    check(all(o.get('type')=='http' and o.get('server_port')==31122 and o.get('detour') for o in exits) and any(o.get('type')=='socks' and o.get('server_port')==31121 for o in outbounds),'runtime pool members use the containing-group landing exit and front proxy chain')
            exported=command('exportProfiles',{'ids':[p['id'] for p in pools.values()],'format':'profiles','destination':'preview'})['text'];bundle=json.loads(exported)
            bundle_ids={p['reference'] for p in bundle['profiles']};bundle_pools={p['name']:p for p in bundle['profiles'] if p['kind']=='auto-selector'}
            check(len(bundle_pools)==2 and not any(p['id'] in exported for p in added) and all(set(p['config']['members'])<bundle_ids and p['config']['pinned_profile'] in p['config']['members'] for p in bundle_pools.values()),'portable export includes selector dependencies and remaps every member and pin away from local UUIDs')
            settings();click('#backup-undo');wait_for('return !!document.querySelector("#backup-confirm")');apply()
            check(state('undone')[0]==before_apply,'Previous library exactly undoes snapshot import while retaining the record added during review')

            blocked=open_file(copies['blocked.thrbackup']);blocked=toggle('#legacy-selector-snapshot')
            codes={i['code'] for i in blocked['legacy']['issues']}
            check(blocked['legacy']['canApply'] and {'legacy_profile_skipped','legacy_selector_reference_missing','legacy_selector_pin_outside_snapshot','legacy_selector_snapshot_empty','legacy_selector_member_unsupported','legacy_selector_field_unsupported'}.issubset(codes),'missing, stale-pin, empty, endpoint/full/chain and unknown-field selectors are named and left out while the supported rows stay importable')
            check(safe(blocked),'selector diagnostics of the partial batch reveal no source keys, probe URLs or unknown field values')
            planned=blocked['incoming']['profiles']-blocked['current']['profiles']
            skipped_names={i['name'] for i in blocked['legacy']['issues'] if i['code']=='legacy_profile_skipped'}
            apply();partial=state('partial-selectors')[0]
            added=partial['profiles'][len(before_apply['profiles']):]
            check(planned>0 and len(added)==planned and not any(p['name'] in skipped_names for p in added) and partial['profiles'][:len(before_apply['profiles'])]==before_apply['profiles'],'applying the partial batch adds exactly the planned rows and none of the named left-out selectors')
            settings();click('#backup-undo');wait_for('return !!document.querySelector("#backup-confirm")');apply()
            check(state('blocked-noop')[0]==before_apply,'undo of the partial batch restores the entire previous library')
            excluded=open_file(copies['excluded-settings.thrbackup']);excluded=toggle('#legacy-selector-snapshot')
            check(excluded['legacy']['canApply'] and excluded['legacy']['inventory']['parts']['settings'] is False,'profiles remain importable when source settings were excluded from the Qt backup')
            apply();without_settings,_=state('without-source-settings')
            check(all({k:v for k,v in p['config'].items() if k not in ('type','members','pinned_profile')}==expected_options(next(c for _,_,c in SELECTORS if c['name']==name),False) for name,p in selectors(without_settings).items()),'excluded source settings cannot change probe URL defaults or supply a direct connectivity URL')
            click('#backup-undo');wait_for('return !!document.querySelector("#backup-confirm")');apply()
            check(state('parts-undo')[0]==before_apply,'undo after excluded-settings import restores the exact previous library')
            excluded=open_file(copies['excluded-profiles.thrbackup'])
            check(not excluded['legacy']['canApply'] and excluded['legacy']['autoSelectorCount']==0 and not js('return !!document.querySelector("#legacy-selector-snapshot")'),'excluded profiles cannot be recovered through the snapshot control or source selector inventory')
            close();open_file(baseline_path);apply()
            check(state('final-baseline')[0]==baseline and all(hashlib.sha256(path.read_bytes()).hexdigest()==manifest['sha256'][name] for name,path in copies.items()),'baseline restore removes test additions and every source Qt archive remains byte-for-byte unchanged')
            audit={'previews':previews(),'sourceHashes':manifest['sha256'],'nativeCoreChecks':2,'importedSelectorStart':False,'heldConnectVerified':True,'sourceUnchanged':True}
        finally:
            with contextlib.suppress(Exception):
                if audit is None: audit={'previews':previews(),'sourceHashes':manifest['sha256'],'failed':True}
                (Path(h['args'].artifacts)/'legacy-selector-review.json').write_text(json.dumps(audit,ensure_ascii=False,indent=2)+'\n')
            if connection: connection.close()
            with contextlib.suppress(Exception):
                if js('return !!document.querySelector("dialog[open]")'): close()
                command('disconnect');command('preferences',initial['preferences'])
                js('if(window.__legacySelectorAudit){window.fetch=window.__legacySelectorAudit.original;delete window.__legacySelectorAudit;}')
                click('.primary-nav button:nth-child(1)');h['request']('POST',h['base']+'/window/rect',geometry)
            server.shutdown();server.server_close()
