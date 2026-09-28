"""Independent native import of old settings categories; loopback fixtures only."""
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
from legacy_settings_fixtures import SOURCE, DIRECTORY
from native_dialogs import file_dialog


def run(h):
    command,click,wait_for,js,check,screenshot=(h[k] for k in ('command','click','wait_for','js','check','screenshot'))
    initial=command('snapshot');geometry=h['request']('GET',h['base']+'/window/rect')
    manifest=json.loads((SOURCE/'manifest.json').read_text());mixed=json.loads((DIRECTORY/'manifest.json').read_text())
    groups=manifest['groups'];all_fields=set(sum(groups.values(),[]));copies={};hashes={};connection=None;audit={}
    secrets=['synthetic-private','synthetic_private_column','private-mixed-settings-value','synthetic-legacy-password','synthetic-subscription-secret','JBSWY3DPEHPK3PXP']
    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            with contextlib.suppress(OSError):
                while value:=self.request.recv(8192):self.request.sendall(value)
    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address=True;daemon_threads=True
    server=Server(('127.0.0.1',0),Echo);threading.Thread(target=server.serve_forever,daemon=True).start()

    def settings(section='backup'):
        click('.primary-nav button:nth-child(5)');wait_for('return !!document.querySelector("[data-settings-section='+section+']")');click('[data-settings-section='+section+']')
        wait_for('return document.querySelector("[data-settings-section='+section+']").getAttribute("aria-current")==="page"')
        if section=='backup':wait_for('return !!document.querySelector("#backup-open")')
    def previews():return js('return window.__legacySettingsAudit?.previews || []')
    def wait_preview(count):
        wait_for('return window.__legacySettingsAudit.previews.length > '+str(count));wait_for('return !!document.querySelector("#backup-confirm") && !document.querySelector("#backup-refresh").disabled');return previews()[-1]
    def chooser(title,path=None,opening=False):
        try:file_dialog(title,path,opening=opening)
        except AssertionError as error:
            if str(error)!='Native file chooser has no visible editable path field':raise
            file_dialog(title,path,opening=opening)
    def open_file(path=None,expect_error=False):
        count=len(previews());ru=command('snapshot')['preferences']['language']=='ru';click('#backup-open');chooser('Открыть резервную копию' if ru else 'Open backup',path,True);wait_for('return !document.querySelector("#backup-open").disabled')
        if expect_error:wait_for('return !!document.querySelector(".backup-panel > .desktop-inline-error")');return None
        return wait_preview(count) if path else None
    def close():click('#main-modal > .modal-head > button');wait_for('return !document.querySelector("dialog[open]")')
    def toggle(group):
        count=len(previews());click('#legacy-scope-settings-'+group);return wait_preview(count)
    def toggle_profile():
        count=len(previews());click('#legacy-scope-profiles');return wait_preview(count)
    def all_categories():
        for group in groups:last=toggle(group)
        return last
    def refresh():
        count=len(previews());click('#backup-refresh');return wait_preview(count)
    def reject(token,code):
        try:command('restoreBackup',{'token':token})
        except RuntimeError as error:assert code in str(error) and not any(s in str(error) for s in secrets),str(error)
        else:raise AssertionError('Forbidden legacy settings import accepted')
    def apply():
        if not js('return document.querySelector("#backup-acknowledge").checked'):click('#backup-acknowledge')
        click('#backup-confirm');wait_for('return !document.querySelector("dialog[open]") && !!document.querySelector("#backup-notice")')
        language=command('snapshot')['preferences']['language'];wait_for('return document.documentElement.lang==='+json.dumps(language))
    def undo():click('#backup-undo');wait_for('return !!document.querySelector("#backup-confirm")');apply()
    def state(label):
        path=root/(label+'-'+str(time.monotonic_ns())+'.json');ru=command('snapshot')['preferences']['language']=='ru';click('#backup-save');chooser('Сохранить резервную копию' if ru else 'Save backup',path);wait_for('return !document.querySelector("#backup-save").disabled')
        deadline=time.monotonic()+5
        while not path.exists() and time.monotonic()<deadline:time.sleep(.05)
        return json.loads(path.read_text())['library'],path
    def safe(preview):
        value=json.dumps(preview,ensure_ascii=False)+js('return document.querySelector("#main-modal")?.textContent || ""');return not any(s in value for s in secrets)
    def save_setting(section,key,value):
        previous=command('settings')[section];command('saveSettings',{'section':section,'previous':previous,'values':{**previous,key:value}})
    def echo(label):
        value=('legacy-settings-'+label).encode();connection.sendall(value);answer=b''
        while len(answer)<len(value):
            part=connection.recv(4096)
            if not part:break
            answer+=part
        return answer==value
    def expected_library(current,source,selected=('appearance','testing','logging')):
        result=copy.deepcopy(current)
        for key in sum([groups[g] for g in selected],[]):
            if key not in source:continue
            value=source[key]
            if key=='language':result['preferences']['language']={'1':'en','4':'ru'}[value]
            elif key=='test_url':result['preferences']['ping']['url']=value
            elif key=='url_test_timeout_ms':result['preferences']['ping']['timeoutMs']=int(value)
            elif key in ['show_config_security','skip_delete_confirmation','log_auto_scroll']:result['settings'][key]=value in ['true','1']
            elif key=='speed_test_mode':result['settings'][key]=['full','download','upload','simple'][int(value)]
            elif key in ['test_concurrent','speed_test_timeout_ms']:result['settings'][key]=int(value)
            else:result['settings'][key]=value
        return result
    def difference_paths(actual, expected, prefix='library'):
        if actual == expected:return []
        if isinstance(actual, dict) and isinstance(expected, dict):
            return sum([difference_paths(actual.get(k), expected.get(k), prefix+'.'+k) for k in sorted(actual.keys() | expected.keys())], [])
        if isinstance(actual, list) and isinstance(expected, list) and len(actual)==len(expected):
            return sum([difference_paths(a, b, prefix+'['+str(i)+']') for i, (a,b) in enumerate(zip(actual,expected))], [])
        return [prefix]
    def input_value(selector):return js('const n=document.querySelector(arguments[0]);return n?.type==="checkbox" ? n.checked : n?.value',selector)

    with tempfile.TemporaryDirectory(prefix='thronium-legacy-settings-ui-') as temporary:
        root=Path(temporary)
        for directory,source_manifest,prefix in [(SOURCE,manifest,''),(DIRECTORY,mixed,'mixed-')]:
            for name,digest in source_manifest['sha256'].items():
                assert hashlib.sha256((directory/name).read_bytes()).hexdigest()==digest
                key=prefix+name;copies[key]=root/key;hashes[key]=digest;shutil.copyfile(directory/name,copies[key])
        try:
            command('disconnect');command('preferences',{**initial['preferences'],'language':'en','theme':'dark'});wait_for('return document.documentElement.lang==="en"');settings()
            js('''const original=window.fetch;window.__legacySettingsAudit={original,previews:[]};window.fetch=function(input,options){let name=null;try{if(String(input).includes('/app_command'))name=JSON.parse(options?.body||'{}').name;}catch{}const result=original.apply(this,arguments);if(['readBackup','legacyBackupScopes','refreshBackupPreview','previewPreviousBackup'].includes(name))result.then(r=>r.clone().json()).then(v=>{const p=v?.preview||v;if(p?.token&&p?.current)window.__legacySettingsAudit.previews.push(p)}).catch(()=>{});return result;};''')
            baseline,baseline_path=state('baseline')
            with socket.socket() as available:available.bind(('127.0.0.1',0));port=available.getsockname()[1]
            command('preferences',{**command('snapshot')['preferences'],'inboundPort':port,'ping':{**command('snapshot')['preferences']['ping'],'url':'http://127.0.0.1:31873/current','timeoutMs':2200}});command('connectionSettings',{'mode':'local','port':port})
            existing=command('saveProfile',{'name':'Current settings profile','groupId':'personal','kind':'sing-box-outbound','config':{'type':'direct'}})['id'];command('select',{'id':existing})
            command('otpSave',{'value':{'name':'Current OTP settings preservation','secret':'JBSWY3DPEHPK3PXP','type':'hotp','counter':'9007199254740993'}})
            save_setting('security','skip_delete_confirmation',True);save_setting('logging','max_log_line',1500);save_setting('testing','ping_method','tcp');before,_=state('before')
            open_file();check(not js('return !!document.querySelector("dialog[open]")') and state('chooser-cancel')[0]==before,'cancelling the native archive chooser preserves profiles, OTP and settings')
            first=open_file(copies['valid-ru.thrbackup'])
            check(not first['legacy']['canApply'] and 'settings' not in first['legacy']['scopes'] and first['legacy']['settingsCount']==0 and first['legacy']['settingsDeferred']==10 and {g:first['legacy']['settingsGroups'][g]['count'] for g in groups}=={'appearance':3,'testing':6,'logging':1},'actual Qt settings-only archive starts unselected and reports three independent categories of3/6/1 fields')
            check(all(set(first['legacy']['settingsGroups'][g]['fields'])==set(groups[g]) for g in groups) and safe(first),'settings review exposes only constant supported field IDs and counts, without source values')
            reject(first['token'],'legacy_import_blocked');picked=all_categories()
            check(picked['legacy']['canApply'] and picked['legacy']['settingsCount']==10 and picked['legacy']['settingsDeferred']==0 and js('return document.querySelectorAll("#legacy-settings-fields li").length===10 && !document.querySelector("#backup-acknowledge").checked && document.querySelector("#backup-confirm").disabled'),'explicit categories prepare ten replacements and still require acknowledgement')
            reject(first['token'],'backup_preview_expired');click('#backup-acknowledge');off=toggle('logging')
            check(off['legacy']['settingsCount']==9 and js('return !document.querySelector("#backup-acknowledge").checked'),'category changes rotate the preview and reset acknowledgement');toggle('logging')
            for language in ['en','ru']:
                command('preferences',{**command('snapshot')['preferences'],'language':language});wait_for('return document.documentElement.lang==='+json.dumps(language));picked=refresh();h['request']('POST',h['base']+'/window/rect',{'width':390,'height':820})
                check(safe(picked) and js('return document.querySelector("#legacy-settings-count").textContent.includes("10") && document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth+1 && document.querySelector(".modal-footer").getBoundingClientRect().bottom<=innerHeight+1'),'category review and explicit replacement acknowledgement fit '+language+' at390 pixels');screenshot('legacy-settings-review-'+language)
            close();h['request']('POST',h['base']+'/window/rect',{'width':1280,'height':860});command('preferences',{**command('snapshot')['preferences'],'language':'en'});wait_for('return document.documentElement.lang==="en"');check(state('review-cancel')[0]==before,'cancelling review preserves the complete current library after display preferences return')

            command('connect',{'id':existing});connection=socket.create_connection(('127.0.0.1',port),timeout=5);target='127.0.0.1:'+str(server.server_address[1]);connection.sendall(f'CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n'.encode());headers=b''
            while b'\r\n\r\n' not in headers:
                part=connection.recv(4096);assert part;headers+=part
            assert b' 200 ' in headers.split(b'\r\n',1)[0]
            open_file(copies['valid-ru.thrbackup']);active=all_categories();click('#backup-acknowledge');check(js('return document.querySelector("#backup-confirm").disabled') and echo('review'),'reviewing settings replacements leaves a real existing HTTP CONNECT alive and disables apply')
            reject(active['token'],'backup_disconnect_first');check(echo('refusal') and command('snapshot')['running']==existing,'backend import refusal keeps the same core and socket while connected');close();connection.close();connection=None;command('disconnect')
            open_file(copies['valid-ru.thrbackup']);picked=all_categories();click('#backup-acknowledge');save_setting('logging','max_log_line',3500)
            concurrent=command('saveProfile',{'name':'Concurrent settings review profile','groupId':'personal','kind':'sing-box-outbound','config':{'type':'direct'}})['id'];before_apply=copy.deepcopy(before);before_apply['settings']['max_log_line']=3500;before_apply['profiles'].append({k:v for k,v in command('profile',{'id':concurrent}).items() if k not in ('expectedRevision','vlessCore')})
            click('#backup-confirm');wait_for('return document.querySelector("dialog .desktop-inline-error")?.textContent.includes("changed")');check(command('settings')['logging']['max_log_line']==3500 and len(command('snapshot')['profiles'])==2,'stale preview refuses to overwrite concurrent unselected settings and a new profile')
            updated=refresh();check(updated['token']!=picked['token'] and updated['legacy']['scopes']==picked['legacy']['scopes'] and js('return !document.querySelector("#backup-acknowledge").checked'),'refresh retains category choices, uses current library and requires fresh acknowledgement');reject(picked['token'],'backup_preview_expired');apply()
            imported,_=state('imported');wanted=expected_library(before_apply,manifest['modes']['valid-ru']['sourceRows'])
            if imported != wanted: print('MISMATCH PATHS', difference_paths(imported, wanted), flush=True)
            check(imported==wanted and command('snapshot')['running'] is None,'ten fields import exactly through catalog preferences while profiles, OTP, routing, theme, ping method and other settings stay unchanged')
            settings('appearance');check(input_value('#settings-language')=='ru' and input_value('#setting-show_config_security') is True and command('settings')['appearance']['theme']=='dark','real appearance form shows imported language and profile-security flag with current theme preserved')
            settings('security');check(input_value('#setting-skip_delete_confirmation') is False,'the imported confirmation setting appears in the actual Security form')
            settings('testing');h['select']('#setting-ping_method','auto');wait_for('return !!document.querySelector("#probe-url")');check(input_value('#probe-url')==manifest['validSourceRows']['test_url'] and input_value('#probe-timeout')=='4500' and input_value('#setting-test_concurrent')=='2','real testing form shows exact imported HTTP URL, timeout milliseconds and concurrency');h['select']('#setting-ping_method','tcp');wait_for('return !document.querySelector("#probe-url") && document.querySelector("#settings-save").disabled')
            check(input_value('#setting-speed_test_mode')=='simple' and input_value('#setting-speed_test_timeout_ms')=='6000' and input_value('#setting-simple_dl_url')==manifest['validSourceRows']['simple_dl_url'],'real speed-test fields preserve Qt mode, duration and download URL without starting a test')
            settings('logging');check(input_value('#setting-log_auto_scroll') is False and input_value('#setting-max_log_line')=='3500','real logging form shows imported auto-scroll and preserves the concurrent line limit');settings();undo();check(state('undone')[0]==before_apply,'Previous library exactly undoes all imported settings while keeping concurrent current changes')

            for name,group,code in [('blocked-appearance.thrbackup','appearance','legacy_settings_language_unsupported'),('blocked-testing.thrbackup','testing','legacy_settings_speed_mode_unsupported')]:
                open_file(copies[name]);bad=all_categories();check(not bad['legacy']['canApply'] and code in {i['code'] for i in bad['legacy']['issues']} and safe(bad),'unsupported source '+group+' blocks the entire chosen batch with a safe diagnostic');reject(bad['token'],'legacy_import_blocked');rest=toggle(group)
                check(rest['legacy']['canApply'],'unchecking unsupported '+group+' leaves the other valid categories importable');apply();actual,_=state('category-optout');expected=expected_library(before_apply,manifest['modes'][name.removesuffix('.thrbackup')]['sourceRows'],tuple(g for g in groups if g!=group));check(actual==expected,'category opt-out applies only the other supported fields and preserves the blocked category');undo();check(state('category-undo')[0]==before_apply,'category-specific import has an exact whole-library undo')
            open_file(copies['missing-fields.thrbackup']);partial=all_categories();check(partial['legacy']['settingsCount']==2 and partial['legacy']['canApply'],'a sparse archive plans only present fields and does not fill missing values from defaults');apply();check(state('missing-values')[0]==expected_library(before_apply,manifest['modes']['missing-fields']['sourceRows']),'missing language, URLs and other fields retain the exact current values');undo()
            open_file(copies['unknown-values.thrbackup']);unknown=all_categories();check(unknown['legacy']['settingsCount']==10 and unknown['legacy']['settingsDeferred']==1 and safe(unknown),'unknown key and value stay private while the review shows one deferred setting');close()
            open_file(copies['unknown-column.thrbackup']);bad=all_categories();check(not bad['legacy']['canApply'] and safe(bad),'unsupported columns in known settings cannot silently change any selected category');reject(bad['token'],'legacy_import_blocked');close()
            excluded=open_file(copies['excluded-settings.thrbackup']);check(excluded['legacy']['inventory']['settings']==10 and not excluded['legacy']['inventory']['parts']['settings'] and all(excluded['legacy']['settingsGroups'][g]['count']==0 for g in groups) and js('return Array.from(document.querySelectorAll("[id^=legacy-scope-settings-]")).every(n=>n.disabled)'),'source Parts disables settings import even though malformed source rows are physically present')
            forged=command('legacyBackupScopes',{'token':excluded['token'],'scopes':{'profiles':False,'routes':False,'otp':False,'settings':{g:True for g in groups}}});check(not forged['legacy']['canApply'] and 'legacy_settings_part_missing' in {i['code'] for i in forged['legacy']['issues']},'forged IPC category selection cannot bypass excluded source settings');reject(forged['token'],'legacy_import_blocked');close()
            open_file(copies['empty.thrbackup']);empty=all_categories();check(not empty['legacy']['canApply'] and empty['legacy']['settingsCount']==0,'empty selected settings categories cannot claim a successful restore');close()
            open_file(copies['bad-sqlite-type.thrbackup'],expect_error=True);check(not js('return !!document.querySelector("dialog[open]")') and not any(s in js('return document.querySelector(".backup-panel").textContent') for s in secrets),'a structurally invalid SQLite setting is rejected before review without showing its bytes')
            check(state('invalid-noop')[0]==before_apply,'unknown, excluded, empty and structurally malformed archives leave the current library intact')

            first=open_file(copies['mixed-blocked-profiles.thrbackup']);both=all_categories();check(both['legacy']['canApply'] and 'legacy_profile_skipped' in {i['code'] for i in both['legacy']['issues']},'unsupported profiles are named and left out of a combined profile and settings import');only=toggle_profile();check(only['legacy']['canApply'],'unchecking unsupported profiles permits independent settings import');apply();check(state('mixed-settings-only')[0]==wanted,'settings-only import from a mixed archive preserves current profiles and imports the exact ten fields');undo()
            first=open_file(copies['mixed-blocked-settings.thrbackup']);check(first['legacy']['canApply'] and 'settings' not in first['legacy']['scopes'],'unselected unsupported settings do not block valid profile import');bad=toggle('appearance');reject(bad['token'],'legacy_import_blocked');check(not bad['legacy']['canApply'],'choosing unsupported appearance prevents partial import of otherwise valid profiles');toggle('appearance');apply();actual,_=state('mixed-profiles-only');rest=copy.deepcopy(actual);added=rest['profiles'][len(before_apply['profiles']):];rest['profiles']=rest['profiles'][:len(before_apply['profiles'])];rest['groups']=rest['groups'][:len(before_apply['groups'])]
            for p in added:rest['preferences']['vlessOverrides'].pop(p['id'],None)
            check(len(added)==13 and rest==before_apply,'profile-only mixed import preserves all current settings and OTP while adding only source profiles, groups and their core overrides');undo();check(state('mixed-undo')[0]==before_apply,'mixed-scope profile import has an exact undo')
            open_file(baseline_path);apply();check(state('restored-baseline')[0]==baseline and all(hashlib.sha256(path.read_bytes()).hexdigest()==hashes[name] for name,path in copies.items()),'final baseline restore removes all fixtures and all thirteen Qt archives remain byte-for-byte unchanged')
            audit={'previews':previews(),'sourceHashes':hashes,'heldConnectVerified':True,'actualSettingsFormFields':10,'sourceUrlsNotRequestedByHarness':True,'sourceUnchanged':True}
        finally:
            with contextlib.suppress(Exception):(Path(h['args'].artifacts)/'legacy-settings-review.json').write_text(json.dumps(audit or {'previews':previews(),'sourceHashes':hashes,'failed':True},ensure_ascii=False,indent=2)+'\n')
            if connection:connection.close()
            with contextlib.suppress(Exception):
                if js('return !!document.querySelector("dialog[open]")'):close()
                command('disconnect');command('preferences',initial['preferences']);js('if(window.__legacySettingsAudit){window.fetch=window.__legacySettingsAudit.original;delete window.__legacySettingsAudit;}');click('.primary-nav button:nth-child(1)');h['request']('POST',h['base']+'/window/rect',geometry)
            server.shutdown();server.server_close()
