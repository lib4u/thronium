"""Qt icon archive → native chooser → backup/undo → actual owned X11 icon pixels."""
import copy, hashlib, json, os, socket, time
from pathlib import Path
from Xlib import X, display
from native_dialogs import file_dialog
from native_menu import NativeMenu
from tray_ui import wait

def run(h):
    command,click,wait_for,js,check=(h[k] for k in ('command','click','wait_for','js','check'))
    artifacts=Path(h['args'].artifacts)
    fixtures=Path(__file__).resolve().parents[1]/'engine/src/legacy_backup/icons/fixtures'
    manifest=json.loads((fixtures/'manifest.json').read_text())
    for name,sha in manifest['sha256'].items(): assert hashlib.sha256((fixtures/name).read_bytes()).hexdigest()==sha
    root=Path(os.environ['XDG_DATA_HOME'])
    assert 'thronium-native-test-' in str(root)
    state=lambda:json.loads((root/'io.thronium.desktop/library.json').read_text())
    # A fresh Store stays in memory until its first commit.
    command('preferences',command('snapshot')['preferences'])
    initial=state()
    before_interfaces=Path('/proc/net/route').read_bytes()
    geometry=h['request']('GET',h['base']+'/window/rect')
    def settings():
        click('.primary-nav button:nth-child(5)')
        wait_for('return !!document.querySelector("[data-settings-section=backup]")')
        click('[data-settings-section=backup]')
        wait_for('return !!document.querySelector("#backup-open")')
    def open_file(path):
        click('#backup-open')
        language=command('snapshot')['preferences']['language']
        file_dialog('Open backup' if language=='en' else 'Открыть резервную копию',path,opening=True)
        wait_for('return !!document.querySelector("#backup-confirm")')
    def close():
        click('#main-modal > .modal-head > button')
        wait_for('return !document.querySelector("dialog[open]")')
    def choose():
        click('#legacy-scope-icons')
        wait_for('return document.querySelector("#legacy-scope-icons").checked && !document.querySelector("#backup-refresh").disabled')
    def apply():
        click('#backup-acknowledge');click('#backup-confirm')
        wait_for('return !document.querySelector("dialog[open]")')
    def set_system(**changes):
        settings=command('settings')['system']
        command('saveSettings',{'section':'system','values':{**settings,**changes},'previous':settings})
    def comparable(value):
        value=copy.deepcopy(value);value.pop('version',None);return value
    x=None
    baseline_file=artifacts/'icons-baseline.json'
    try:
        command('disconnect')
        command('preferences',{**command('snapshot')['preferences'],'language':'en'})
        wait_for('return document.documentElement.lang==="en"')
        settings()
        click('#backup-save');file_dialog('Save backup',baseline_file)
        wait_for('return !document.querySelector("#backup-save").disabled')
        before=state()
        open_file(fixtures/'valid.thrbackup')
        check(not js('return document.querySelector("#legacy-scope-icons").checked') and state()==before,'icons-only Qt archive remains inert until its own scope is selected')
        choose()
        wait_for('return !document.querySelector("#legacy-import-blocked")')
        check(js('return document.querySelector("[data-backup-incoming=icons]").textContent')=='6','review counts six valid status PNGs and reports the unused archive entry')
        check('not recognized' in js('return document.querySelector("#legacy-import-review").textContent'),'unknown archive files have a visible omission notice')
        h['request']('POST',h['base']+'/window/rect',{'width':390,'height':844})
        check(js('return document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth+1'),'English icon scope review fits a narrow window')
        h['screenshot']('legacy-icons-en-390')
        command('preferences',{**command('snapshot')['preferences'],'language':'ru'})
        wait_for('return document.documentElement.lang==="ru"')
        click('#backup-refresh');wait_for('return !document.querySelector("#backup-refresh").disabled')
        check('Значков для импорта' in js('return document.querySelector("#legacy-icons-review").textContent'),'Russian icon scope review is localized')
        h['screenshot']('legacy-icons-ru-390')
        apply()
        imported=state();check(len(imported['trayIcons'])==6 and imported['version']==5,'six validated icons persist inside the library with a reader boundary')
        check(imported['settings']==before['settings'] and not (root/'io.thronium.desktop/icons').exists(),'icon import preserves settings and extracts no archive paths')
        open_file(fixtures/'corrupt.thrbackup');choose()
        wait_for('return !!document.querySelector("#legacy-import-blocked")')
        check(js('return document.querySelector("#backup-confirm").disabled') and state()==imported,'one corrupt status icon rejects the entire scope without changing the current pack')
        close()
        open_file(fixtures/'missing-part.thrbackup')
        check(js('return document.querySelector("#legacy-scope-icons").disabled'),'retained icon bytes cannot override a missing archive part')
        close()
        settings();click('#backup-undo');wait_for('return !!document.querySelector("#backup-confirm")');apply()
        restored=state()
        check(not restored.get('trayIcons') and restored['version']==5,'Undo removes the imported pack while keeping the reader boundary')
        # Reimport, then check the real window icon to verify the native tray's shared image path.
        open_file(fixtures/'valid.thrbackup');choose();wait_for('return !document.querySelector("#legacy-import-blocked")');apply()
        set_system(use_custom_icons=True,follow_status_in_taskbar=True,custom_icon_directory='')
        menu=NativeMenu();x=display.Display()
        pid_atom=x.intern_atom('_NET_WM_PID');icon_atom=x.intern_atom('_NET_WM_ICON')
        def pixels():
            pending=list(x.screen().root.query_tree().children)
            while pending:
                window=pending.pop()
                try:
                    pid=window.get_full_property(pid_atom,X.AnyPropertyType)
                    if pid and int(pid.value[0])==menu.pid:
                        icon=window.get_full_property(icon_atom,X.AnyPropertyType)
                        if icon is not None:return list(icon.value)
                    pending.extend(window.query_tree().children)
                except Exception: pass
            return None
        def actual(status):
            r,g,b,a=manifest['colors'][status];expected=[32,32]+[(a<<24)|(r<<16)|(g<<8)|b]*(32*32)
            wait(lambda:pixels()==expected,'actual '+status+' window icon')
            check(True,'native '+status+' icon uses decoded pixels from the imported PNG')
        actual('Off')
        with socket.socket() as available: available.bind(('127.0.0.1',0));port=available.getsockname()[1]
        command('connectionSettings',{'mode':'local','port':port})
        profile=command('saveProfile',{'name':'Icons own direct','groupId':'personal','kind':'sing-box-outbound','config':{'type':'direct','udp_fragment':True}})['id']
        command('connect',{'id':profile});actual('Throne')
        command('disconnect');actual('Off')
        settings()
        saved=artifacts/'icons-export.json'
        click('#backup-save');file_dialog('Сохранить резервную копию',saved)
        wait_for('return !document.querySelector("#backup-save").disabled')
        check(json.loads(saved.read_text())['library']['trayIcons']==state()['trayIcons'],'native export writes the complete imported PNG pack into the backup')
    finally:
        command('disconnect')
        if x is not None:x.close()
        if js('return !!document.querySelector("dialog[open]")'):close()
        if baseline_file.exists():
            settings();open_file(baseline_file);apply()
        command('preferences',initial['preferences'])
        h['request']('POST',h['base']+'/window/rect',geometry)
        check(comparable(state())==comparable(initial),'cleanup restores the test library except its monotonic reader version')
        check(Path('/proc/net/route').read_bytes()==before_interfaces,'icon acceptance leaves host routes unchanged')
