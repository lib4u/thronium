"""Observe the existing fifteen backup assertions without changing their checks."""
import contextlib
import json
import time
import backups_ui
from rfd_dialog_fixture import file_dialog


def run(h):
    js = h['js']; audit={'chooser':[],'afterChooser':[]}
    js('''const original=window.fetch;window.__backupProbe={original,events:[]};window.fetch=function(input,options){let name=null;try{if(String(input).includes('/app_command'))name=JSON.parse(options?.body||'{}').name}catch{}const result=original.apply(this,arguments);if(['readBackup','exportBackup'].includes(name))result.then(r=>r.clone().json()).then(v=>window.__backupProbe.events.push({name,status:v?.status||null,hasPreview:!!v?.preview,failure:typeof v==='string'?v:null})).catch(()=>window.__backupProbe.events.push({name,transportError:true}));return result;};''')
    def state():
        return js('return {busy:document.querySelector("#backup-open")?.disabled,notice:document.querySelector("#backup-notice")?.textContent||null,failure:document.querySelector(".backup-panel > .desktop-inline-error")?.textContent||null,events:window.__backupProbe.events}')
    def observed(title,path=None,opening=False):
        file_dialog(title,path,opening,audit['chooser']);time.sleep(.5)
        value=state();value['requestedFileExists']=bool(path is not None and path.exists());audit['afterChooser'].append(value)
    original = backups_ui.file_dialog; backups_ui.file_dialog=observed
    try: backups_ui.run(h)
    finally:
        backups_ui.file_dialog=original
        with contextlib.suppress(Exception):audit['final']=state()
        (h['artifacts']/'backup-chooser-probe.json').write_text(json.dumps(audit,indent=2)+'\n')
