"""Real Tauri screenshot action against a portal started before GTK activation."""
import os
import json
import pathlib


def run(h):
    if not os.environ.get('_THRONIUM_QR_FIXTURE'):
        raise RuntimeError('Use --qr-only --private-tray-bus')
    root=pathlib.Path(os.environ['_THRONIUM_QR_FIXTURE'])
    click,wait_for,js,check=(h[k] for k in ['click','wait_for','js','check'])
    try:
        click('.add-connection');click('#add-choice-qr');click('#import-qr-screen')
        wait_for('return !document.querySelector("#import-qr-screen").disabled',20)
        state=json.loads((root/'state.json').read_text())
        check(js('return !!document.querySelector(".import-read-success")'), 'system screenshot imports its QR and restores the window')
        check(len(state['calls'])==1 and state['calls'][0]['interactive'] and not pathlib.Path(state['path']).exists(),'screen capture is interactive and its temporary image is removed')
        (root/'cancel').touch();click('#import-qr-screen');wait_for('return !document.querySelector("#import-qr-screen").disabled',20)
        check(js('return !document.querySelector("[role=alert]")&&!!document.querySelector("dialog:modal")&&!!document.querySelector(".import-read-success")'),'cancelling capture returns to the existing modal and retains its content')
    finally:
        if js('return !!document.querySelector("#main-modal")'):click('#main-modal>.modal-head>button')
