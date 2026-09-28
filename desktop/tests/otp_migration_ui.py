"""Native Google OTP import/export with independent Qt links, no provider traffic."""
import base64
import contextlib
import copy
import hashlib
import json
from pathlib import Path
import socket
import socketserver
import tempfile
import threading
import time
from native_dialogs import file_dialog

FIXTURES = Path(__file__).resolve().parents[1] / 'engine/src/otp/fixtures/migration'


def run(h):
    command,click,fill,select,wait_for,js,check,screenshot=(h[k] for k in ('command','click','fill','select','wait_for','js','check','screenshot'))
    golden=json.loads((FIXTURES/'golden.json').read_text());cases={c['id']:c for c in golden['cases']}
    assert golden['qtRuntime']=='6.11.2' and len(cases)>=117
    ordered=cases['export-mixed-ordered'];part0=cases['batch-two-fragment-0'];part1=cases['batch-two-fragment-1']
    key=ordered['entries'][0]['secret'];initial=command('snapshot');geometry=h['request']('GET',h['base']+'/window/rect')
    original_clipboard=None;original_image=None;connection=None;audit={}
    try: original_clipboard=command('readClipboard')
    except RuntimeError:
        import gi
        gi.require_version('Gtk','3.0')
        from gi.repository import Gtk,Gdk
        original_image=Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD).wait_for_image()

    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            with contextlib.suppress(OSError):
                while value:=self.request.recv(8192): self.request.sendall(value)
    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address=True;daemon_threads=True
    server=Server(('127.0.0.1',0),Echo);threading.Thread(target=server.serve_forever,daemon=True).start()

    def settings(section='otp'):
        click('.primary-nav button:nth-child(5)');wait_for('return !!document.querySelector("[data-settings-section='+section+']")');click('[data-settings-section='+section+']')
        wait_for('return !!document.querySelector("'+('#otp-manager' if section=='otp' else '#backup-save')+'")')
    def close():
        click('dialog > .modal-head > .icon-button');wait_for('return !document.querySelector("dialog")')
    def rows(): return command('otpList')
    def drafts(): return [{k:v for k,v in command('otpGet',{'id':r['id']}).items() if k not in ('id','revision')} for r in rows()]
    def content(selector): return js('return document.querySelector(arguments[0])?.textContent || ""',selector)
    def input_text(): return js('return document.querySelector("#otp-import-text").value')
    def export_text(): return js('return document.querySelector("#otp-export-text").value')
    def refresh():
        click('#otp-refresh');wait_for('return !document.querySelector("#otp-refresh").disabled')
    def import_text(text):
        click('#otp-import');fill('#otp-import-text',text);click('#otp-import-confirm');wait_for('return !document.querySelector("dialog")')
    def commit_import():
        click('#otp-import-confirm');wait_for('return !document.querySelector("dialog")')
    def rejected(text,code):
        before=rows();click('#otp-import');fill('#otp-import-text',text);click('#otp-import-confirm');wait_for('return !!document.querySelector("dialog [role=alert]")')
        assert rows()==before and input_text()==text
        assert key not in content('dialog [role=alert]') and 'data=' not in content('dialog [role=alert]')
        try: command('otpImport',{'text':text})
        except RuntimeError as error: assert code in str(error) and key not in str(error) and 'data=' not in str(error)
        else: raise AssertionError('Malformed Google import accepted')
        close();return rows()==before
    def choose_format(value):
        select('#otp-export-format',value);wait_for('return !document.querySelector("#otp-export-format").disabled')
    def upload(path):
        element=h['element']('#otp-import-file');h['request']('POST',h['base']+'/element/'+element+'/value',{'text':str(path),'value':list(str(path))})
        wait_for('return !document.querySelector("#otp-import-file").disabled')
    def qr_file(text,name):
        image=command('exportQr',{'text':text,'destination':'preview'})['image']
        path=root/name;path.write_bytes(base64.b64decode(image.split(',',1)[1]));return path
    def echo(label):
        value=('migration-'+label).encode();connection.sendall(value);answer=b''
        while len(answer)<len(value):
            part=connection.recv(4096)
            if not part: break
            answer+=part
        return answer==value
    def backup(label):
        settings('backup');path=root/(label+'.json');click('#backup-save');file_dialog('Save backup',path);wait_for('return !document.querySelector("#backup-save").disabled')
        deadline=time.monotonic()+5
        while not path.exists() and time.monotonic()<deadline:time.sleep(.05)
        return json.loads(path.read_text())['library'],path

    with tempfile.TemporaryDirectory(prefix='thronium-otp-migration-ui-') as temporary:
        root=Path(temporary)
        try:
            command('disconnect');command('preferences',{**initial['preferences'],'language':'en','theme':'dark'});wait_for('return document.documentElement.lang==="en"')
            baseline,baseline_path=backup('baseline');settings()
            check(rows()==[],'Google migration suite starts in the isolated empty authenticator')
            click('#otp-import');fill('#otp-import-text',ordered['expected']['link']);close()
            check(rows()==[],'closing migration input discards the pending batch without adding any entry')
            import_text(ordered['expected']['link']);imported=rows()
            check(drafts()==ordered['entries'],'actual Qt migration link preserves ordered Unicode labels, whitespace, algorithms and large HOTP counter')
            hotp=imported[1];selector='[data-otp-id='+json.dumps(hotp['id'])+'] [data-otp-code]'
            wait_for('return document.querySelector('+json.dumps(selector)+')?.textContent==='+json.dumps(ordered['expected']['codesAt59'][1]))
            check(content(selector)==ordered['expected']['codesAt59'][1],'Google-imported HOTP displays the independent Qt/RFC code in the real panel')
            click('#otp-export-all');wait_for('return !!document.querySelector("#otp-export-format")')
            json_export=export_text()
            check(js('return document.querySelector("#otp-export-format").value==="json" && document.querySelector("#otp-export-format option[value=uri]").disabled') and json.loads(json_export)['otp']==ordered['entries'],'Export all opens lossless JSON and disables the single-entry otpauth format')
            choose_format('migration');migration=export_text()
            check(migration.startswith('otpauth-migration://offline?data=') and '\n' not in migration and drafts()==ordered['entries'],'Google format exports one complete packet without changing saved entries or counters')
            click('#otp-export-copy');wait_for('return !document.querySelector("#otp-export-copy").disabled')
            check(command('readClipboard')==migration,'native clipboard receives the exact selected Google migration packet')
            migration_path=root/'migration.txt';click('#otp-export-file');file_dialog('Save export',migration_path);wait_for('return !document.querySelector("#otp-export-file").disabled')
            check(migration_path.read_text()==migration and migration_path.stat().st_mode&0o777==0o600,'native migration text file preserves exact packet bytes with private permissions')
            click('#otp-show-qr');wait_for('return !!document.querySelector("#otp-qr-image")')
            image=js('return document.querySelector("#otp-qr-image").src')
            check(command('decodeQrImage',{'data':image.split(',',1)[1]})==[migration],'real migration QR decodes to the exact exported Google packet')
            click('.otp-qr .otp-toolbar button:first-child');wait_for('return !document.querySelector("#otp-show-qr").disabled')
            check(command('readQrClipboard')==[migration],'native image clipboard preserves the complete Google QR payload')
            choose_format('json')
            check(json.loads(export_text())['otp']==ordered['entries'] and not js('return !!document.querySelector("#otp-qr-image") || !!document.querySelector("#otp-show-qr")'),'switching to JSON removes the earlier QR and retains every OTP parameter')
            close();click('#otp-import');click('#otp-import-clipboard-qr');wait_for('return document.querySelector("#otp-import-text").value.startsWith("otpauth-migration://")')
            check(input_text()==migration,'actual clipboard QR enters the migration import editor intact')
            commit_import();check(drafts()==ordered['entries']*2,'reimporting exported migration QR preserves all fields and allocates new entries in order')

            # Real image decoding and text/clipboard staging assemble complete parts.
            p1=qr_file(part1['link'],'part1.png');p0=qr_file(part0['link'],'part0.png')
            click('#otp-import');upload(p1);wait_for('return document.querySelector("#otp-import-text").value==='+json.dumps(part1['link']))
            before=rows();click('#otp-import-confirm');wait_for('return !!document.querySelector("dialog [role=alert]")')
            check(rows()==before and input_text()==part1['link'],'an incomplete scanned batch remains editable and adds no partial OTP entries')
            upload(p1);check(input_text()==part1['link'],'rescanning the same QR deduplicates only that identical migration link')
            command('exportQr',{'text':part0['link'],'destination':'clipboard'});click('#otp-import-clipboard-qr');wait_for('return document.querySelector("#otp-import-text").value.split("\\n").length===2')
            check(input_text().splitlines()==[part1['link'],part0['link']],'a second actual clipboard QR appends to the existing migration fragment')
            command('writeClipboard',{'text':part0['link']});click('#otp-import-paste');wait_for('return !document.querySelector("#otp-import-paste").disabled')
            duplicate_file=root/'part0.txt';duplicate_file.write_text(part0['link']);upload(duplicate_file)
            check(input_text().splitlines()==[part1['link'],part0['link']],'paste and text-file rescans preserve the complete batch without exact duplicate links')
            for language in ['en','ru']:
                command('preferences',{**command('snapshot')['preferences'],'language':language});wait_for('return document.documentElement.lang==='+json.dumps(language));h['request']('POST',h['base']+'/window/rect',{'width':390,'height':820})
                check(js('return !!document.querySelector("#otp-import-clear") && !!document.querySelector("#otp-import-screen-qr") && document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth+1 && document.querySelector(".modal-footer").getBoundingClientRect().bottom<=innerHeight+1'),'complete Google batch and import actions fit '+language+' at 390 pixels')
                screenshot('otp-migration-import-'+language)
            h['request']('POST',h['base']+'/window/rect',{'width':1280,'height':860});command('preferences',{**command('snapshot')['preferences'],'language':'en'});wait_for('return document.documentElement.lang==="en"')
            commit_import();check(drafts()[-2:]==part0['expected']['parsed']+part1['expected']['parsed'],'complete reverse-scanned multipart import uses packet indexes to restore source order atomically')
            click('#otp-import');upload(p0);click('#otp-import-clear')
            check(input_text()=='' and js('return document.querySelector("#otp-import-confirm").disabled'),'Clear input discards staged migration parts and disables empty import');close()

            ordinary='otpauth://totp/Test?secret='+key
            for case,code in [('unknown-algorithm-99','otp_migration_enum_unsupported'),('one-valid-one-empty','otp_secret_empty'),('future-version','otp_migration_version'),('assembly-conflicting-size','otp_migration_batch_invalid'),('assembly-different-ids','otp_migration_batch_incomplete'),('assembly-conflicting-duplicate-index','otp_migration_batch_duplicate')]:
                fixture=cases[case];text='\n'.join(fixture['assemblyLinks']) if 'assemblyLinks' in fixture else fixture['link']
                check(rejected(text,code),'native import and backend atomically refuse '+case+' with a safe error')
            check(rejected(part0['link']+'\n'+ordinary,'otp_migration_mixed_input'),'Google fragments mixed with ordinary OTP links are rejected without partial import')
            conflict=cases['assembly-conflicting-duplicate-index']['assemblyLinks'];click('#otp-import');fill('#otp-import-text',conflict[0]);command('writeClipboard',{'text':conflict[1]});click('#otp-import-paste');wait_for('return !document.querySelector("#otp-import-paste").disabled')
            check(input_text().splitlines()==conflict[:2],'different payloads for the same packet index remain visible instead of being deduplicated');close()

            # Row URI fallback and explicit format choices retain otherwise lossy labels.
            click('[data-otp-id='+json.dumps(hotp['id'])+'] [data-otp-export]');wait_for('return !!document.querySelector("#otp-export-format")')
            check(js('return document.querySelector("#otp-export-format").value==="json"') and json.loads(export_text())['otp']==[ordered['entries'][1]],'a label that cannot fit an otpauth URI opens the row JSON fallback with exact content')
            choose_format('migration');check(export_text().startswith('otpauth-migration://'),'the same row supports Google migration without losing colon and Unicode labels');close()
            unsupported={**ordered['entries'][0],'name':'Nonstandard period fixture','period':17};command('otpSave',{'value':unsupported});refresh();click('#otp-export-all');wait_for('return !!document.querySelector("#otp-export-format")');good=export_text();choose_format('migration');wait_for('return !!document.querySelector("dialog [role=alert]")')
            check(export_text()==good and js('return document.querySelector("#otp-export-format").value==="json" && !document.querySelector("#otp-qr-image")'),'unsupported Google parameters keep the previous lossless JSON and format instead of silently changing period')
            close();last=rows()[-1];command('otpRemove',{'id':last['id'],'revision':last['revision']});refresh()
            oversized=[{**ordered['entries'][0],'name':str(i)+'-'+('q'*220)} for i in range(24)]
            command('otpImport',{'text':json.dumps({'version':1,'otp':oversized})});refresh();click('#otp-export-all');wait_for('return !!document.querySelector("#otp-export-format")');choose_format('migration');large_text=export_text();click('#otp-show-qr');wait_for('return !!document.querySelector("dialog [role=alert]")')
            check(len(large_text)>4000 and not js('return !!document.querySelector("#otp-qr-image")') and export_text()==large_text,'a migration packet beyond QR capacity retains its complete text export and reports a QR error');close()

            # OTP import/export is local work and leaves an existing VPN socket alive.
            with socket.socket() as available: available.bind(('127.0.0.1',0));port=available.getsockname()[1]
            command('preferences',{**command('snapshot')['preferences'],'inboundPort':port});command('connectionSettings',{'mode':'local','port':port})
            profile=command('saveProfile',{'name':'Migration held CONNECT','groupId':'personal','kind':'sing-box-outbound','config':{'type':'direct'}})['id'];command('connect',{'id':profile})
            connection=socket.create_connection(('127.0.0.1',port),timeout=5);target='127.0.0.1:'+str(server.server_address[1]);connection.sendall(f'CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n'.encode());headers=b''
            while b'\r\n\r\n' not in headers:
                part=connection.recv(4096);assert part;headers+=part
            assert b' 200 ' in headers.split(b'\r\n',1)[0]
            import_text(part1['link']+'\n'+part0['link'])
            check(echo('import') and command('snapshot')['running']==profile,'complete Google multipart import preserves the same running core and held loopback CONNECT')
            ids=[r['id'] for r in rows()[-2:]];command('otpExport',{'ids':ids,'format':'migration'})
            check(echo('export') and command('snapshot')['running']==profile,'Google export preserves the current network session and does not start another core')
            connection.close();connection=None;command('disconnect')
            check(key not in json.dumps(command('snapshot')) and key not in json.dumps(rows()),'ordinary application snapshots and OTP metadata never expose migration keys')
            settings('backup');click('#backup-open');file_dialog('Open backup',baseline_path,opening=True);wait_for('return !!document.querySelector("#backup-confirm")');click('#backup-acknowledge');click('#backup-confirm');wait_for('return !document.querySelector("dialog")')
            restored,_=backup('restored');check(restored==baseline,'full baseline restore removes all Google test entries and preserves the original library')
            audit={'qtCases':len(cases),'goldenSha256':hashlib.sha256((FIXTURES/'golden.json').read_bytes()).hexdigest(),'realFileAndClipboardQr':True,'screenCaptureExecuted':False,'heldConnectVerified':True,'publicMetadataSecretFree':True}
        finally:
            (Path(h['args'].artifacts)/'otp-migration-audit.json').write_text(json.dumps(audit or {'failed':True},indent=2)+'\n')
            if connection:connection.close()
            with contextlib.suppress(Exception):
                if js('return !!document.querySelector("dialog")'):close()
                command('disconnect');command('preferences',initial['preferences']);h['request']('POST',h['base']+'/window/rect',geometry)
                if original_image is not None:
                    import gi
                    gi.require_version('Gtk','3.0')
                    from gi.repository import Gtk,Gdk
                    clipboard=Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD);clipboard.set_image(original_image);clipboard.store()
                elif original_clipboard is not None:command('writeClipboard',{'text':original_clipboard})
            server.shutdown();server.server_close()
