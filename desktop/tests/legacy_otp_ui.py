"""Native old Qt OTP import with public RFC keys and a held loopback CONNECT."""
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
from legacy_otp_fixtures import SOURCE, DIRECTORY
from native_dialogs import file_dialog


def run(h):
    command, click, wait_for, js, check, screenshot = (h[k] for k in ('command','click','wait_for','js','check','screenshot'))
    initial=command('snapshot'); geometry=h['request']('GET',h['base']+'/window/rect')
    manifest=json.loads((SOURCE/'manifest.json').read_text()); mixed_manifest=json.loads((DIRECTORY/'manifest.json').read_text())
    expected=sorted(manifest['rows'],key=lambda row:(row['sort_order'],row['id']))
    secrets={r['secret'] for r in expected}|{r['secret'].upper() for r in expected}|{'invalid-private-fixture!','private-blob','private-future-secret','private-mixed-configuration','JBSWY3DPEHPK3PXP'}
    connection=None; audit=None; copies={}; hashes={}

    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            with contextlib.suppress(OSError):
                while body:=self.request.recv(65536): self.request.sendall(body)
    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address=True; daemon_threads=True
    server=Server(('127.0.0.1',0),Echo)
    threading.Thread(target=server.serve_forever,daemon=True).start()

    def settings(section='backup'):
        click('.primary-nav button:nth-child(5)')
        wait_for('return !!document.querySelector("[data-settings-section='+section+']")')
        click('[data-settings-section='+section+']')
        wait_for('return !!document.querySelector("'+('#backup-open' if section=='backup' else '#otp-manager')+'")')

    def previews(): return js('return window.__legacyOtpAudit?.previews || []')
    def wait_preview(count):
        wait_for('return window.__legacyOtpAudit.previews.length > '+str(count))
        wait_for('return !!document.querySelector("#backup-confirm") && !document.querySelector("#backup-refresh").disabled')
        return previews()[-1]
    def open_file(path=None):
        count=len(previews()); ru=command('snapshot')['preferences']['language']=='ru'
        click('#backup-open')
        title='Открыть резервную копию' if ru else 'Open backup'
        try: file_dialog(title,path,opening=True)
        except AssertionError as error:
            if str(error)!='Native file chooser has no visible editable path field': raise
            # GTK can miss the first Ctrl+L during mapping. Retry only the
            # unchanged, PID-verified disposable chooser; no app action repeats.
            file_dialog(title,path,opening=True)
        wait_for('return !document.querySelector("#backup-open").disabled')
        return wait_preview(count) if path else None
    def close():
        click('#main-modal > .modal-head > button');wait_for('return !document.querySelector("dialog[open]")')
    def toggle(selector):
        count=len(previews());click(selector);return wait_preview(count)
    def refresh():
        count=len(previews());click('#backup-refresh');return wait_preview(count)
    def reject(token,code):
        try: command('restoreBackup',{'token':token})
        except RuntimeError as error: assert code in str(error) and not any(s in str(error) for s in secrets),str(error)
        else: raise AssertionError('Forbidden legacy OTP operation accepted')
    def apply():
        if not js('return document.querySelector("#backup-acknowledge").checked'): click('#backup-acknowledge')
        click('#backup-confirm');wait_for('return !document.querySelector("dialog[open]") && !!document.querySelector("#backup-notice")')
    def undo():
        click('#backup-undo');wait_for('return !!document.querySelector("#backup-confirm")');apply()
    def state(label):
        path=root/(label+'-'+str(time.monotonic_ns())+'.json');ru=command('snapshot')['preferences']['language']=='ru'
        click('#backup-save');file_dialog('Сохранить резервную копию' if ru else 'Save backup',path)
        wait_for('return !document.querySelector("#backup-save").disabled')
        deadline=time.monotonic()+5
        while not path.exists() and time.monotonic()<deadline: time.sleep(.05)
        return json.loads(path.read_text())['library'],path
    def safe(preview):
        value=json.dumps(preview,ensure_ascii=False)+js('return document.querySelector("#main-modal")?.textContent || ""')
        return not any(s in value for s in secrets) and '"secret"' not in value and 'otpauth://' not in value
    def echo(label):
        body=('legacy-otp-'+label).encode();connection.sendall(body);received=b''
        while len(received)<len(body):
            part=connection.recv(4096)
            if not part: break
            received+=part
        return received==body
    def save_current(name):
        return command('otpSave',{'id':'','revision':'','value':{'name':name,'issuer':'Current fixture','secret':'JBSWY3DPEHPK3PXP','type':'hotp','algorithm':'SHA1','counter':'9007199254740993','digits':6,'period':30}})
    def normalized(row):
        return {'name':row['name'],'issuer':row['issuer'],'secret':row['secret'].upper(),'algorithm':['SHA1','SHA256','SHA512'][row['algorithm']],'type':['totp','hotp'][row['type']],'digits':row['digits'],'period':row['period'],'counter':str(row['counter'])}

    with tempfile.TemporaryDirectory(prefix='thronium-legacy-otp-ui-') as temporary:
        root=Path(temporary)
        for source,source_manifest,prefix in [(SOURCE,manifest,''),(DIRECTORY,mixed_manifest,'mixed-')]:
            for name,digest in source_manifest['sha256'].items():
                assert hashlib.sha256((source/name).read_bytes()).hexdigest()==digest
                key=prefix+name;copies[key]=root/key;hashes[key]=digest;shutil.copyfile(source/name,copies[key])
        try:
            command('disconnect');command('preferences',{**initial['preferences'],'language':'en','theme':'dark'})
            wait_for('return document.documentElement.lang==="en"');settings()
            js('''const original=window.fetch;window.__legacyOtpAudit={original,previews:[]};window.fetch=function(input,options){let name=null;try{if(String(input).includes('/app_command'))name=JSON.parse(options?.body||'{}').name;}catch{}const result=original.apply(this,arguments);if(['readBackup','legacyBackupScopes','refreshBackupPreview','previewPreviousBackup'].includes(name))result.then(r=>r.clone().json()).then(v=>{const p=v?.preview||v;if(p?.token&&p?.current)window.__legacyOtpAudit.previews.push(p)}).catch(()=>{});return result;};''')
            baseline,baseline_path=state('baseline')
            with socket.socket() as available: available.bind(('127.0.0.1',0));port=available.getsockname()[1]
            command('preferences',{**command('snapshot')['preferences'],'inboundPort':port})
            command('connectionSettings',{'mode':'local','port':port})
            existing=command('saveProfile',{'name':'Current profile for OTP import','groupId':'personal','kind':'sing-box-outbound','config':{'type':'direct'}})['id']
            command('select',{'id':existing});save_current('Current OTP before import');before,_=state('before')
            open_file()
            check(not js('return !!document.querySelector("dialog[open]")') and state('cancelled-chooser')[0]==before,'cancelling native archive selection preserves the existing OTP and profile library')
            first=open_file(copies['valid.thrbackup'])
            check(first['legacy']['otpCount']==6 and first['legacy']['inventory']['parts']['otp'] and not first['legacy']['scopes']['otp'] and not first['legacy']['canApply'] and js('return !document.querySelector("#legacy-scope-otp").checked && document.querySelector("#legacy-scope-profiles").disabled && document.querySelector("#backup-confirm").disabled'),'actual Qt OTP-only archive reports six entries and starts with no section selected')
            reject(first['token'],'legacy_import_blocked')
            chosen=toggle('#legacy-scope-otp')
            check(chosen['legacy']['canApply'] and chosen['incoming']['otp']==7 and js('return document.querySelector("#legacy-otp-count").textContent.includes("6") && !document.querySelector("#backup-acknowledge").checked && document.querySelector("#backup-confirm").disabled'),'explicit OTP selection shows six planned entries plus the current one and still requires acknowledgement')
            check(safe(chosen) and all(set(i)=={'code','entity','sourceId','name'} for i in chosen['legacy']['issues']),'native review exposes counts and static issue metadata without OTP keys, URLs or configuration values')
            reject(first['token'],'backup_preview_expired');click('#backup-acknowledge');off=toggle('#legacy-scope-otp')
            check(not off['legacy']['canApply'] and js('return !document.querySelector("#backup-acknowledge").checked && document.querySelector("#backup-confirm").disabled'),'unchecking OTP resets acknowledgement and blocks the old prepared import')
            reject(off['token'],'legacy_import_blocked');chosen=toggle('#legacy-scope-otp')
            for language in ['en','ru']:
                command('preferences',{**command('snapshot')['preferences'],'language':language});wait_for('return document.documentElement.lang==='+json.dumps(language));chosen=refresh()
                h['request']('POST',h['base']+'/window/rect',{'width':390,'height':820})
                check(safe(chosen) and js('return document.querySelector("#legacy-otp-count").textContent.includes("6") && document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth+1 && document.querySelector(".modal-footer").getBoundingClientRect().bottom<=innerHeight+1'),'OTP scope, imported count and footer fit '+language+' review at 390 pixels')
                screenshot('legacy-otp-review-'+language)
            close();h['request']('POST',h['base']+'/window/rect',{'width':1280,'height':860});command('preferences',{**command('snapshot')['preferences'],'language':'en'});wait_for('return document.documentElement.lang==="en"')
            check(state('cancelled-review')[0]==before,'cancelling the OTP review leaves entries, profiles, current routing, DNS and preferences intact')

            command('connect',{'id':existing});connection=socket.create_connection(('127.0.0.1',port),timeout=5)
            target='127.0.0.1:'+str(server.server_address[1]);connection.sendall(f'CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n'.encode());headers=b''
            while b'\r\n\r\n' not in headers:
                part=connection.recv(4096);assert part;headers+=part
            assert b' 200 ' in headers.split(b'\r\n',1)[0]
            open_file(copies['valid.thrbackup']);active=toggle('#legacy-scope-otp');click('#backup-acknowledge')
            check(js('return document.querySelector("#backup-confirm").disabled') and echo('review') and command('snapshot')['running']==existing,'reviewing an OTP import preserves the existing real HTTP CONNECT and disables apply')
            reject(active['token'],'backup_disconnect_first')
            check(echo('refusal') and command('snapshot')['running']==existing,'backend active-session refusal keeps the same live core and socket')
            close();connection.close();connection=None;command('disconnect')
            open_file(copies['valid.thrbackup']);chosen=toggle('#legacy-scope-otp');click('#backup-acknowledge');save_current('Current OTP added during review')
            current_rows=command('otpList');click('#backup-confirm');wait_for('return document.querySelector("dialog .desktop-inline-error")?.textContent.includes("changed")')
            check(command('otpList')==current_rows,'stale preview refuses to overwrite an OTP entry added while review is open')
            updated=refresh()
            check(updated['token']!=chosen['token'] and updated['incoming']['otp']==8 and updated['legacy']['scopes']==chosen['legacy']['scopes'] and js('return !document.querySelector("#backup-acknowledge").checked'),'refresh rebases on current OTP, keeps section choice, rotates the token and requires fresh acknowledgement')
            reject(chosen['token'],'backup_preview_expired');apply();imported,_=state('imported');added=imported['otp'][len(current_rows):]
            check(len(added)==6 and imported['version']==2 and all(str(uuid.UUID(e['id']))==e['id'] and str(uuid.UUID(e['revision']))==e['revision'] and e['id']!=e['revision'] for e in added),'import adds exactly six entries with distinct UUID identities and revisions in library version 2')
            check([{k:v for k,v in e.items() if k not in ('id','revision')} for e in added]==[normalized(r) for r in expected],'import preserves Qt sort order, names, issuers, algorithms, inactive parameters and exact counters beyond JavaScript integer precision')
            before_apply=copy.deepcopy(imported);before_apply['otp']=imported['otp'][:len(current_rows)]
            unchanged=copy.deepcopy(before_apply);unchanged['otp']=before['otp']
            check(unchanged==before and command('snapshot')['running'] is None,'OTP-only import preserves all preexisting profiles, selection, current network settings and both current OTP entries')
            settings('otp');wait_for('return document.querySelectorAll("[data-otp-id]").length===8')
            check(js('return Array.from(document.querySelectorAll("[data-otp-id]")).map(e=>e.dataset.otpId)')==[e['id'] for e in imported['otp']],'real authenticator panel retains appended Qt ordering without silently sorting by name')
            for index,entry in enumerate(added):
                if entry['type']!='hotp': continue
                selector='[data-otp-id='+json.dumps(entry['id'])+'] [data-otp-code]';wanted=manifest['codeAt59'][index]
                wait_for('return document.querySelector('+json.dumps(selector)+')?.textContent==='+json.dumps(wanted))
                check(js('return document.querySelector(arguments[0]).textContent',selector)==wanted,'real authenticator generates the independent Qt/RFC HOTP code for '+entry['name'])
            check(command('otpList')==[{k:v for k,v in e.items() if k!='secret'} for e in imported['otp']] and not any(s in js('return document.querySelector("#otp-manager").textContent') for s in secrets),'code polling leaves HOTP counters unchanged and the default OTP list contains no keys')
            screenshot('legacy-otp-imported-codes');settings();undo()
            check(state('undone')[0]==before_apply,'Previous library exactly undoes OTP import while retaining the entry added during review')

            for name,code in [('blocked.thrbackup','legacy_otp_algorithm_invalid'),('unknown-column.thrbackup','legacy_otp_field_unsupported')]:
                opened=open_file(copies[name]);bad=toggle('#legacy-scope-otp')
                check(not bad['legacy']['canApply'] and code in {i['code'] for i in bad['legacy']['issues']} and safe(bad) and js('return document.querySelector("#backup-confirm").disabled'),'invalid or unknown OTP fields block the complete selected section safely: '+name)
                reject(bad['token'],'legacy_import_blocked');close()
            check(state('blocked-noop')[0]==before_apply,'all mixed valid and invalid OTP records remain unapplied after failed validation')
            excluded=open_file(copies['excluded-otp.thrbackup'])
            check(excluded['legacy']['otpCount']==0 and not excluded['legacy']['inventory']['parts']['otp'] and js('return document.querySelector("#legacy-scope-otp").disabled'),'an excluded OTP section stays unavailable even when its SQL rows are physically present')
            forged=command('legacyBackupScopes',{'token':excluded['token'],'scopes':{'profiles':False,'routes':False,'otp':True}})
            check(not forged['legacy']['canApply'] and 'legacy_otp_parts_required' in {i['code'] for i in forged['legacy']['issues']} and safe(forged),'forged IPC section choice cannot read excluded source OTP rows')
            reject(forged['token'],'legacy_import_blocked');close()

            mixed=open_file(copies['mixed-blocked-profiles.thrbackup']);both=toggle('#legacy-scope-otp')
            check(both['legacy']['canApply'] and both['legacy']['otpCount']==6 and 'legacy_profile_skipped' in {i['code'] for i in both['legacy']['issues']} and safe(both),'valid OTP stays importable with the supported profiles while unsupported profiles are named and left out')
            only=toggle('#legacy-scope-profiles')
            check(only['legacy']['canApply'] and only['incoming']['profiles']==only['current']['profiles'] and safe(only),'unchecking unsupported profiles allows the independent valid OTP section')
            apply();only_state,_=state('mixed-only-otp')
            check(len(only_state['otp'])==len(before_apply['otp'])+6 and only_state['profiles']==before_apply['profiles'],'mixed archive OTP-only apply leaves source profiles unapplied')
            undo();check(state('mixed-otp-undo')[0]==before_apply,'undo exactly restores current state after mixed archive OTP-only import')
            mixed=open_file(copies['mixed-blocked-otp.thrbackup'])
            check(mixed['legacy']['canApply'] and not mixed['legacy']['scopes']['otp'],'unsupported OTP does not block an unselected section in a valid profile import')
            bad=toggle('#legacy-scope-otp');reject(bad['token'],'legacy_import_blocked')
            check(not bad['legacy']['canApply'] and safe(bad),'selecting unsupported OTP cannot partially apply its otherwise valid profile batch')
            profiles=toggle('#legacy-scope-otp');apply();profiles_state,_=state('mixed-only-profiles')
            check(len(profiles_state['profiles'])==len(before_apply['profiles'])+13 and profiles_state['otp']==before_apply['otp'],'unchecking invalid OTP imports all thirteen profiles and preserves existing OTP exactly')
            undo();check(state('mixed-profiles-undo')[0]==before_apply,'undo restores current profiles and OTP after profile-only mixed import')
            old=open_file(copies['old-no-sort.thrbackup']);old=toggle('#legacy-scope-otp')
            check(old['legacy']['canApply'] and sum(i['code']=='legacy_otp_order_default' for i in old['legacy']['issues'])==6,'older Qt rows disclose the documented missing-sort-column fallback before import');close()
            open_file(baseline_path);apply()
            check(state('final-baseline')[0]==baseline and all(hashlib.sha256(path.read_bytes()).hexdigest()==hashes[name] for name,path in copies.items()),'restoring the baseline removes all test additions and source Qt archives stay byte-for-byte unchanged')
            audit={'previews':previews(),'sourceHashes':hashes,'heldConnectVerified':True,'importedHotpUiCodes':3,'sourceUnchanged':True}
        finally:
            with contextlib.suppress(Exception):
                if audit is None: audit={'previews':previews(),'sourceHashes':hashes,'failed':True}
                (Path(h['args'].artifacts)/'legacy-otp-review.json').write_text(json.dumps(audit,ensure_ascii=False,indent=2)+'\n')
            if connection: connection.close()
            with contextlib.suppress(Exception):
                if js('return !!document.querySelector("dialog[open]")'): close()
                command('disconnect');command('preferences',initial['preferences'])
                js('if(window.__legacyOtpAudit){window.fetch=window.__legacyOtpAudit.original;delete window.__legacyOtpAudit;}')
                click('.primary-nav button:nth-child(1)');h['request']('POST',h['base']+'/window/rect',geometry)
            server.shutdown();server.server_close()
