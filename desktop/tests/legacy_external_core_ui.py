"""Real Qt import is inert; only explicit Connect launches the owned SOCKS helper."""
import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import socket
import socketserver
import tempfile
import threading
import time
import uuid
from external_core_fixture import identity
from legacy_external_core_fixtures import DIRECTORY, DEFAULT_WRITER, PRIVATE, generate
from native_dialogs import file_dialog
from native_menu import NativeMenu
from native_processes import core_pids


def run(h):
    command,click,wait_for,js,check,screenshot=(h[k] for k in ('command','click','wait_for','js','check','screenshot'))
    initial=command('snapshot');geometry=h['request']('GET',h['base']+'/window/rect')
    artifacts=Path(h['args'].artifacts);application=Path(h['args'].application).resolve();core=application.with_name('ThroniumCore')
    assert hashlib.sha256(core.read_bytes()).hexdigest()!='2c893cb88a5a2fe4dc807ffa8b4a7cb8635a80e651f9eeb540967a6b097d54cc'
    menu=NativeMenu();assert Path('/proc',str(menu.pid),'exe').resolve()==application
    app_identity=identity(menu.pid);core_observations=[]
    def core_identity():
        assert identity(menu.pid)['starttime']==app_identity['starttime']
        result=[]
        for pid in core_pids(menu.pid):
            assert Path('/proc',pid,'exe').resolve()==core.resolve()
            node=identity(int(pid));result.append((node['pid'],node['starttime']))
        return sorted(result)
    expected_cores=core_identity()
    core_observations.append({'stage':'before-preview','identities':expected_cores})
    connections=[];audit={};copies={};hashes={};baseline_path=None
    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            with contextlib.suppress(OSError):
                while data:=self.request.recv(8192):self.request.sendall(data)
    class Server(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=True
    server=Server(('127.0.0.1',0),Echo);threading.Thread(target=server.serve_forever,daemon=True).start()
    def port():
        with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
    def until(predicate):
        end=time.monotonic()+10
        while time.monotonic()<end:
            if predicate():return
            time.sleep(.08)
        raise AssertionError('Legacy external fixture condition timed out')
    def settings():
        click('.primary-nav button:nth-child(5)');wait_for('return !!document.querySelector("[data-settings-section=backup]")');click('[data-settings-section=backup]');wait_for('return !!document.querySelector("#backup-open")')
    def close():click('#main-modal > .modal-head > button');wait_for('return !document.querySelector("dialog[open]")')
    def previews():return js('return window.__legacyExternalAudit?.previews || []')
    def wait_preview(count):
        wait_for('return window.__legacyExternalAudit.previews.length > '+str(count));wait_for('return !!document.querySelector("#backup-confirm") && !document.querySelector("#backup-refresh").disabled');return previews()[-1]
    def open_file(path=None):
        before_cores=core_identity()
        count=len(previews());ru=command('snapshot')['preferences']['language']=='ru';click('#backup-open');title='Открыть резервную копию' if ru else 'Open backup'
        try:file_dialog(title,path,opening=True)
        except AssertionError as error:
            if str(error)!='Native file chooser has no visible editable path field':raise
            file_dialog(title,path,opening=True)
        wait_for('return !document.querySelector("#backup-open").disabled');value=wait_preview(count) if path else None
        assert core_identity()==before_cores;core_observations.append({'stage':'open-or-cancel','identities':before_cores});return value
    def toggle(selector):
        before_cores=core_identity();count=len(previews());click(selector);value=wait_preview(count)
        assert core_identity()==before_cores;core_observations.append({'stage':'scope','identities':before_cores});return value
    def refresh():
        before_cores=core_identity();count=len(previews());click('#backup-refresh');value=wait_preview(count)
        assert core_identity()==before_cores;core_observations.append({'stage':'refresh','identities':before_cores});return value
    def apply():
        before_cores=core_identity()
        if not js('return document.querySelector("#backup-acknowledge").checked'):click('#backup-acknowledge')
        click('#backup-confirm');wait_for('return !document.querySelector("dialog[open]") && !!document.querySelector("#backup-notice")')
        assert core_identity()==before_cores;core_observations.append({'stage':'apply-or-undo','identities':before_cores})
    def undo():
        before_cores=core_identity();click('#backup-undo');wait_for('return !!document.querySelector("#backup-confirm")');apply()
        assert core_identity()==before_cores;core_observations.append({'stage':'preview-and-undo','identities':before_cores})
    def state():
        path=Path(os.environ['XDG_DATA_HOME']);assert 'thronium-native-test-' in str(path)
        return json.loads((path/'io.thronium.desktop/library.json').read_text())
    def reject(token,code):
        try:command('restoreBackup',{'token':token})
        except RuntimeError as error:assert code in str(error) and safe_text(str(error)),str(error)
        else:raise AssertionError('Forbidden legacy external import accepted')
    def safe_text(text):return not any(s in text for s in secrets)
    def safe(preview):return safe_text(json.dumps(preview,ensure_ascii=False)+js('return document.querySelector("#main-modal")?.textContent || ""'))
    def codes(preview):return {v['code'] for v in preview['legacy']['issues']}
    def events():return [json.loads(line) for line in marker.read_text().splitlines()] if marker.exists() else []
    def no_launch():
        with socket.socket() as s:s.bind(('127.0.0.1',external_port))
        return not events() and core_identity()==expected_cores
    def connect_socket():
        s=socket.create_connection(('127.0.0.1',inbound),timeout=5);connections.append(s)
        target='127.0.0.1:'+str(server.server_address[1]);s.sendall(f'CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n'.encode());headers=b''
        while b'\r\n\r\n' not in headers:
            part=s.recv(4096);assert part;headers+=part
        assert b' 200 ' in headers.split(b'\r\n',1)[0];return s
    def echo(s,label):
        value=('legacy-external-'+label).encode();s.sendall(value);result=b''
        while len(result)<len(value):
            part=s.recv(len(value)-len(result))
            if not part:return False
            result+=part
        return result==value
    def gone(node):
        try:return identity(node['pid'])['starttime']!=node['starttime']
        except (OSError,ValueError):return True
    def normalized(config):
        return {'name':'','socks_address':'127.0.0.1','extra_core_args':'','extra_core_conf':'','no_logs':False,**config}

    with tempfile.TemporaryDirectory(prefix='thronium-legacy-external-native-') as temporary:
        root=Path(temporary);marker=root/'launches.jsonl';helper=root/'owned external helper.py';shutil.copyfile(Path(__file__).with_name('external_core_fixture.py'),helper)
        # Its own interpreter copy: the external core's traffic leaves
        # directly by executable path, and the test client is python3 as well.
        executable=root/'owned-external-python';shutil.copy2(Path('/usr/bin/python3').resolve(),executable);inbound=port();external_port=port()
        literal='$(touch '+str(root/'must-not-exist')+') $HOME %d'
        args='  '+' '.join(shlex.quote(s) for s in [str(helper),'--config','%s','--literal','two words','--literal','','--literal',literal])+'  '
        raw=' \r\n'+json.dumps({'marker':str(marker),'port':external_port,'echoPort':server.server_address[1],'mode':'ready','secret':PRIVATE},ensure_ascii=False,indent=2)+'\r\n\t '
        config={'type':'extracore','name':'Legacy external 日本','socks_address':'127.0.0.1','socks_port':external_port,'extra_core_path':str(executable),'extra_core_args':args,'extra_core_conf':raw,'no_logs':False}
        secrets=[PRIVATE,str(root),str(helper),str(executable),'/absent/legacy external','extra_core_conf','extra_core_args','extra_core_path','SQLite format 3','CREATE TABLE','metadata-secret-fixture']
        manifest=generate(DEFAULT_WRITER,root/'runtime',config,['valid'])
        static=json.loads((DIRECTORY/'manifest.json').read_text())
        archive_artifacts=artifacts/'source-fixtures';archive_artifacts.mkdir()
        for source,m,prefix in [(root/'runtime',manifest,'runtime-'),(DIRECTORY,static,'')]:
            for name,digest in m['sha256'].items():
                assert hashlib.sha256((source/name).read_bytes()).hexdigest()==digest
                key=prefix+name;copies[key]=root/key;hashes[key]=digest;shutil.copyfile(source/name,copies[key]);shutil.copyfile(source/name,archive_artifacts/key)
            (archive_artifacts/(prefix+'manifest.json')).write_text(json.dumps(m,ensure_ascii=False,indent=2)+'\n')
        shutil.copyfile(helper,archive_artifacts/'external_core_fixture.py')
        try:
            command('disconnect');command('preferences',{**initial['preferences'],'language':'en','theme':'dark'});wait_for('return document.documentElement.lang==="en"');settings()
            baseline=state();baseline_path=root/'baseline.json';baseline_path.write_text(json.dumps({'format':'thronium-backup','version':1,'createdAt':int(time.time()),'library':baseline}))
            command('connectionSettings',{'mode':'local','port':inbound})
            existing=command('saveProfile',{'name':'Current direct before legacy external','groupId':'personal','kind':'sing-box-outbound','config':{'type':'direct'}})['id'];command('select',{'id':existing});before=state()
            js('''const original=window.fetch;window.__legacyExternalAudit={original,previews:[]};window.fetch=function(input,options){let name=null;try{if(String(input).includes('/app_command'))name=JSON.parse(options?.body||'{}').name}catch{}const result=original.apply(this,arguments);if(['readBackup','legacyBackupScopes','refreshBackupPreview','previewPreviousBackup'].includes(name))result.then(r=>r.clone().json()).then(v=>{const p=v?.preview||v;if(p?.token&&p?.current)window.__legacyExternalAudit.previews.push(p)}).catch(()=>{});return result;};''')
            open_file();check(state()==before and no_launch(),'cancelling the real Qt backup chooser changes no data and launches no program')
            first=open_file(copies['runtime-valid.thrbackup'])
            check(first['legacy']['canApply'] and first['legacy']['inventory']['profiles']==4 and first['legacy']['externalCoreCount']==3 and first['incoming']['profiles']==first['current']['profiles']+4 and not first['legacy']['scopes']['routes'] and not first['legacy']['scopes'].get('settings') and no_launch(),'actual Qt archive previews four profiles with only profiles selected and no execution or occupied SOCKS port')
            issues=first['legacy']['issues'];check(sum(v['code']=='legacy_external_launch_review' for v in issues)==3 and sum(v['code']=='legacy_external_runtime_subset' for v in issues)==3 and sum(v['code']=='legacy_external_output_enabled' for v in issues)==2 and {v['name'] for v in issues if v['code']=='legacy_external_launch_review'}=={'Legacy external 日本','Legacy fallback label','Legacy empty launch fields'} and safe(first),'review explains all three external launch profiles and preserves output-enabled defaults without showing paths or config')
            check(js('return !document.querySelector("#backup-acknowledge").checked && document.querySelector("#backup-confirm").disabled') and state()==before,'existing explicit acknowledgement is required and merely opening the archive preserves current selection and network')
            for language in ['en','ru']:
                command('preferences',{**command('snapshot')['preferences'],'language':language});wait_for('return document.documentElement.lang==='+json.dumps(language));current=refresh();h['request']('POST',h['base']+'/window/rect',{'width':390,'height':844})
                check(safe(current) and no_launch() and js('return document.querySelector("#legacy-external-count").textContent.includes("3") && document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth+1 && document.querySelector(".modal-footer").getBoundingClientRect().bottom<=innerHeight+1'),'external import explanation and acknowledgement fit '+language+' at 390 pixels');screenshot('legacy-external-review-'+language)
            close();h['request']('POST',h['base']+'/window/rect',geometry);command('preferences',{**command('snapshot')['preferences'],'language':'en'});wait_for('return document.documentElement.lang==="en"')
            check(state()==before and no_launch(),'cancelling review and changing its language leave the original library and executable untouched')
            first=open_file(copies['runtime-valid.thrbackup']);click('#backup-acknowledge');blocked=toggle('#legacy-scope-routes')
            check(not blocked['legacy']['canApply'] and 'legacy_route_target_unsupported' in codes(blocked) and safe(blocked) and js('return !document.querySelector("#backup-acknowledge").checked'),'selecting a route to external atomically blocks profiles plus routes and resets acknowledgement');reject(blocked['token'],'legacy_import_blocked')
            allowed=toggle('#legacy-scope-routes');check(allowed['legacy']['canApply'] and no_launch() and state()==before,'unchecking unsupported routes restores inert profiles-only import');close()

            command('connect',{'id':existing});expected_cores=core_identity();core_observations.append({'stage':'explicit-ordinary-connect','identities':expected_cores});held=connect_socket();settings();first=open_file(copies['runtime-valid.thrbackup']);click('#backup-acknowledge');wait_for('return document.querySelector("#backup-confirm").disabled')
            check(js('return document.querySelector("#backup-confirm").disabled') and echo(held,'review') and no_launch(),'legacy external review never launches a candidate while the existing ordinary CONNECT remains active')
            reject(first['token'],'backup_disconnect_first');check(echo(held,'backend-refusal') and command('snapshot')['running']==existing and no_launch(),'direct backend import refusal preserves the same existing TCP socket');close();command('disconnect')
            first=open_file(copies['runtime-valid.thrbackup']);click('#backup-acknowledge')
            late=command('saveProfile',{'name':'Current profile added during external review','groupId':'personal','kind':'sing-box-outbound','config':{'type':'direct'}})['id'];current=state();reject(first['token'],'backup_preview_stale')
            updated=refresh();check(updated['token']!=first['token'] and updated['incoming']['profiles']==len(current['profiles'])+4 and no_launch(),'refresh keeps a profile added during review and prepares the existing import without executing anything');reject(first['token'],'backup_preview_expired')
            apply();imported=state();added=imported['profiles'][len(current['profiles']):];expected=manifest['cases']['valid.thrbackup']
            check(len(added)==4 and [p['name'] for p in added]==[expected['names'][str(pid)] for pid in expected['order']] and all(str(uuid.UUID(p['id']))==p['id'] for p in added) and no_launch(),'apply adds four fresh UUID profiles in original display order and retains authoritative outbound names without launching')
            by_source=dict(zip(expected['order'],added));external=[p for p in added if p['kind']=='external-core']
            check(len(external)==3 and all(by_source[pid]['config']==normalized(expected['configs'][str(pid)]) for pid in [11,12,14]),'import preserves full raw argv and CR/LF config, explicit true/false no_logs and proven defaults including empty config name')
            unchanged=copy.deepcopy(imported);unchanged['profiles']=unchanged['profiles'][:len(current['profiles'])];unchanged['groups']=unchanged['groups'][:len(current['groups'])]
            check(unchanged==current and command('snapshot')['selected']==existing and no_launch(),'additive import preserves every existing profile, selected server, preferences, settings and current routing/DNS')
            pid=by_source[11]['id'];click('.primary-nav button:first-child');selector='[data-profile-menu='+json.dumps(pid)+']';wait_for('return !!document.querySelector('+json.dumps(selector)+')');js('document.querySelector(arguments[0]).scrollIntoView({block:"center"})',selector);click(selector);click('#menu-edit-profile');wait_for('return !!document.querySelector("#external-core-fields")')
            check(js('return [document.querySelector("#external-core-path").value,document.querySelector("#external-core-args").value,document.querySelector("#external-core-config").value,document.querySelector("#external-core-no-logs").value]')==[str(executable),args,raw.replace('\r\n','\n').replace('\r','\n'),'false'] and command('profile',{'id':pid})['config']['extra_core_conf']==raw and no_launch(),'the actual editor displays the imported text and enabled logging while the stored source CR/LF bytes remain exact');close()
            draft=command('profile',{'id':pid});command('checkProfile',{k:draft[k] for k in ['id','name','groupId','kind','config']});check(no_launch(),'separate explicit Check validates imported executable parameters without launching the program')
            command('connect',{'id':pid});tunnel=connect_socket();launch=next(e for e in events() if e['event']=='launch')
            check(echo(tunnel,'imported-runtime') and any(e['event']=='connect' and e['owner']==launch['identity']['pid'] for e in events()),'only explicit Connect starts the imported external helper and carries real SOCKS5 HTTP CONNECT traffic')
            check(launch['configSha256']==hashlib.sha256(raw.encode()).hexdigest() and launch['configMode']==0o600 and launch['literals']==['two words','',literal] and not (root/'must-not-exist').exists(),'the imported source bytes reach a private temporary file and literal shell tokens remain unexpanded')
            command('disconnect');until(lambda:gone(launch['identity']) and gone(launch['ancestors'][1]) and not Path(launch['configPath']).exists())
            with socket.socket() as probe:probe.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);probe.bind(('127.0.0.1',external_port))
            check(command('snapshot')['running'] is None,'disconnect removes the imported helper, guardian, owned listener and temporary configuration')
            settings();undo();check(state()==current and len(events())==2,'Previous library exactly undoes the imported profiles and groups without another execution')

            # After the one explicit runtime, track launches rather than expecting no marker.
            count=len(events())
            # F3b: an unusable external entry is left out with its reason and the
            # rest imports inert; a conflict in the database itself still blocks.
            for name,code,kept in [('relative-path','legacy_external_path_invalid',3),('unknown-field','legacy_profile_field_unsupported',3),('chain','legacy_chain_hop_unsupported',4),('containing-wrapper','legacy_group_chain_unsupported',1)]:
                bad=open_file(copies[name+'.thrbackup'])
                check(bad['legacy']['canApply'] and {code,'legacy_profile_skipped'}<=codes(bad) and bad['incoming']['profiles']==bad['current']['profiles']+kept and safe(bad),name+' leaves the unusable external entry out with its reason and keeps the rest')
                apply();check(len(state()['profiles'])==len(current['profiles'])+kept and len(events())==count,name+' imports the remaining profiles without launching anything');undo();check(state()==current,name+' undo is exact')
            bad=open_file(copies['empty-group-wrapper.thrbackup']);check(not bad['legacy']['canApply'] and 'legacy_group_chain_unsupported' in codes(bad) and safe(bad),'an external core in another group chain blocks the complete profile batch');reject(bad['token'],'legacy_import_blocked');close()
            check(state()==current and len(events())==count,'all refused external data and graph cases execute no additional helper')
            bad=open_file(copies['relative-path.thrbackup']);toggle('#legacy-scope-profiles');only=toggle('#legacy-scope-settings-logging')
            check(only['legacy']['canApply'] and only['incoming']['profiles']==only['current']['profiles'],'excluding invalid external profiles allows the independent supported logging setting');apply();only_expected=copy.deepcopy(current);only_expected['settings']['log_auto_scroll']=False
            check(state()==only_expected and len(events())==count,'settings-only apply neither imports nor launches the excluded invalid external program');undo();check(state()==current,'undo exactly restores the state before the independent settings import')
            excluded=open_file(copies['excluded-profiles.thrbackup']);check(not excluded['legacy']['inventory']['parts']['profiles'] and js('return document.querySelector("#legacy-scope-profiles").disabled'),'Parts excludes physical external rows from profile import')
            forged=command('legacyBackupScopes',{'token':excluded['token'],'scopes':{'profiles':True,'routes':False}});check(not forged['legacy']['canApply'] and safe(forged),'forged IPC cannot enable external rows excluded by source Parts');reject(forged['token'],'legacy_import_blocked');close()
            selected=open_file(copies['selector-member.thrbackup']);selected=toggle('#legacy-selector-snapshot');check(selected['legacy']['canApply'] and {'legacy_selector_member_unsupported','legacy_profile_skipped'}<=codes(selected) and selected['incoming']['profiles']==selected['current']['profiles']+4,'explicit last-built choice leaves out the selector with an external member and keeps its profiles');close()
            selected=open_file(copies['selector-pool.thrbackup']);selected=toggle('#legacy-selector-snapshot');check(selected['legacy']['canApply'] and safe(selected),'an external profile present only in historical pool does not become an active snapshot member');apply();pooled=state();pool=next(p for p in pooled['profiles'][len(current['profiles']):] if p['kind']=='auto-selector');members=[p for p in pooled['profiles'] if p['id'] in pool['config']['members']]
            check(len(members)==1 and members[0]['kind']=='sing-box-outbound' and len(events())==count,'imported snapshot contains only its saved ordinary member and does not launch pool-only external profiles');undo();check(state()==current,'undo removes selector and standalone externals together without affecting current data')
            open_file(copies['runtime-excluded-settings.thrbackup']);apply();parts=state();parts_added=parts['profiles'][len(current['profiles']):]
            check([p['config'] for p in parts_added]==[p['config'] for p in added] and len(events())==count,'excluding source settings leaves every external launch field and its local defaults unchanged');undo()
            open_file(baseline_path);apply();check(state()==baseline and all(hashlib.sha256(p.read_bytes()).hexdigest()==hashes[n] for n,p in copies.items()),'final native backup restore is exact and all real Qt source archives remain byte-for-byte unchanged')
            audit={'previews':previews(),'sourceHashes':hashes,'events':events(),'baselineRestored':True,'applicationSha256':hashlib.sha256(application.read_bytes()).hexdigest(),'coreSha256':hashlib.sha256(core.read_bytes()).hexdigest(),'qtRuntime':manifest['qtRuntime'],'noProviderTraffic':True,'sourceArchiveContainsExecutable':False,'coreObservations':core_observations}
        finally:
            with contextlib.suppress(Exception):
                if not audit:audit={'previews':previews(),'sourceHashes':hashes,'events':events(),'failed':True,'coreObservations':core_observations}
                (artifacts/'legacy-external-review.json').write_text(json.dumps(audit,ensure_ascii=False,indent=2)+'\n')
            for connection in connections:connection.close()
            with contextlib.suppress(Exception):
                if js('return !!document.querySelector("dialog[open]")'):close()
                command('disconnect');command('preferences',initial['preferences']);js('if(window.__legacyExternalAudit){window.fetch=window.__legacyExternalAudit.original;delete window.__legacyExternalAudit}')
                h['request']('POST',h['base']+'/window/rect',geometry)
    server.shutdown();server.server_close()
