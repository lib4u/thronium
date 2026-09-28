"""Real GTK accepted/NULL callbacks, then ordinary Open/Save on one held VPN."""
import contextlib
import json
import os
from pathlib import Path
import socket
import socketserver
import threading
import time
from external_core_fixture import identity
from native_menu import NativeMenu
from native_processes import core_pids
from rfd_dialog_fixture import file_dialog


def run(h):
    if os.environ.get('_THRONIUM_RFD_BACKUPS_PROBE') == '1':
        from rfd_backup_probe import run as probe
        return probe(h)
    command, click, wait_for, js, check = (h[k] for k in ('command', 'click', 'wait_for', 'js', 'check'))
    initial = command('snapshot'); menu = NativeMenu(); owner = identity(menu.pid)
    application = Path(h['args'].application).resolve()
    assert Path('/proc', str(menu.pid), 'exe').resolve() == application
    root = Path(os.environ['_THRONIUM_RFD_ROOT']); nonce = os.environ['_THRONIUM_RFD_NONCE']
    xdg = Path(os.environ['XDG_DATA_HOME']); assert xdg.parent.name.startswith('thronium-native-test-')
    assert root.is_dir() and root.stat().st_mode & 0o077 == 0
    audit = {'chooser': [], 'rpc': [], 'appIdentity': owner}; connection = None
    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            with contextlib.suppress(OSError):
                while body := self.request.recv(8192): self.request.sendall(body)
    class Server(socketserver.ThreadingTCPServer): daemon_threads = True; allow_reuse_address = True
    server = Server(('127.0.0.1', 0), Echo)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def library(): return json.loads((xdg / 'io.thronium.desktop/library.json').read_text())
    def cores(): return [identity(int(pid)) for pid in core_pids(menu.pid)]
    def stable():
        return (identity(menu.pid)['starttime'] == owner['starttime'] and
                [(v['pid'], v['starttime']) for v in cores()] == [(v['pid'], v['starttime']) for v in core_before])
    def echo(label):
        body = ('rfd-native-' + label).encode(); connection.sendall(body); data = b''
        while len(data) < len(body):
            chunk = connection.recv(len(body) - len(data)); assert chunk; data += chunk
        return data == body
    def arm(mode):
        assert stable()
        fd = os.open(root / 'once.flag', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as out: out.write(f'{menu.pid}\n{xdg}\n{nonce}\n{mode}\n')
    def close():
        click('dialog > .modal-head > .icon-button'); wait_for('return !document.querySelector("dialog[open]")')
    def callback(mode, path=None, fault=False):
        if fault: arm(mode)
        before = js('return window.__rfdAudit.events.length')
        click('#backup-' + ('save' if mode == 'save' else 'open'))
        file_dialog('Save backup' if mode == 'save' else 'Open backup', path, opening=mode == 'open', audit=audit['chooser'])
        # The observer copies actual IPC responses; no response is substituted.
        wait_for('return window.__rfdAudit.events.length > ' + str(before), timeout=15)
        event = json.loads(js('return JSON.stringify(window.__rfdAudit.events.at(-1))')); audit['rpc'].append(event)
        wait_for('return !document.querySelector("#backup-open").disabled')
        return event

    try:
        command('disconnect'); command('preferences', {**initial['preferences'], 'language': 'en'})
        with socket.socket() as port_socket:
            port_socket.bind(('127.0.0.1', 0)); inbound = port_socket.getsockname()[1]
        command('preferences', {**command('snapshot')['preferences'], 'inboundPort': inbound})
        profile = command('saveProfile', {'name': 'RFD owned direct', 'groupId': 'personal', 'kind': 'sing-box-outbound', 'config': {'type': 'direct'}})['id']
        command('connect', {'id': profile}); core_before = cores(); assert len(core_before) == 1
        connection = socket.create_connection(('127.0.0.1', inbound), timeout=5)
        target = '127.0.0.1:' + str(server.server_address[1])
        connection.sendall(f'CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n'.encode()); headers = b''
        while b'\r\n\r\n' not in headers:
            part = connection.recv(4096); assert part; headers += part
        check(b' 200 ' in headers.split(b'\r\n', 1)[0] and echo('baseline'), 'owned HTTP CONNECT is established before native file callbacks')
        baseline = library(); source = root / 'input.json'
        source.write_text(json.dumps({'format': 'thronium-backup', 'version': 1, 'createdAt': int(time.time()), 'library': baseline}))
        js('''const original=window.fetch;window.__rfdAudit={original,events:[]};window.fetch=function(input,options){let name=null;try{if(String(input).includes('/app_command'))name=JSON.parse(options?.body||'{}').name}catch{}const result=original.apply(this,arguments);if(['readBackup','exportBackup'].includes(name))result.then(r=>r.clone().json()).then(v=>window.__rfdAudit.events.push({name,status:v?.status||null,hasPreview:!!v?.preview,error:typeof v==='string'?v:null})).catch(()=>window.__rfdAudit.events.push({name,transportError:true}));return result;};''')
        click('.primary-nav button:nth-child(5)'); wait_for('return !!document.querySelector("[data-settings-section=backup]")')
        click('[data-settings-section=backup]'); wait_for('return !!document.querySelector("#backup-save")')
        for mode, path in [('open', source), ('save', root / 'forced-save.json')]:
            event = callback(mode, path, fault=True)
            check(event['status'] == 'cancelled' and not event['hasPreview'] and not event['error'], f'accepted GTK {mode} with NULL filename returns actual cancelled IPC result')
            rows = [json.loads(line) for line in (root / 'audit.jsonl').read_text().splitlines()]
            row = rows[-1]
            check(row == {'pid': menu.pid, 'mode': mode, 'callerIsApp': True, 'originalWasNull': False, 'originalFreed': True, 'returnedNull': True} and not (root / 'once.flag').exists(), f'one-shot {mode} fault is scoped to the owned app caller and frees the original GLib string')
            check(library() == baseline and stable() and echo('null-' + mode), f'NULL {mode} preserves library, app/core identities and the same held HTTP CONNECT')
            check(not js('return !!document.querySelector("dialog[open]")') and (mode != 'save' or not path.exists()), f'NULL {mode} leaves no restore preview or backup output')
        exported = root / 'normal-save.json'; event = callback('save', exported)
        check(event['status'] == 'saved' and json.loads(exported.read_text())['library'] == baseline, 'ordinary native Save still writes the complete exact library after NULL callbacks')
        event = callback('open', exported)
        wait_for('return !!document.querySelector("#backup-confirm")')
        check(event['status'] == 'ready' and event['hasPreview'] and js('return document.querySelector("#backup-confirm").disabled && !!document.querySelector("#backup-connected")'), 'ordinary native Open returns a real restore review protected by the active connection')
        close(); check(stable() and echo('normal-open-save') and library() == baseline, 'normal file callbacks preserve the same running core, held socket and stored values')
        event = callback('open')
        check(event['status'] == 'cancelled' and not event['hasPreview'] and len((root / 'audit.jsonl').read_text().splitlines()) == 2, 'ordinary native cancellation has no injected fault and no new preview')
        check(stable() and echo('final') and library() == baseline, 'all native chooser operations finish with unchanged data and the original live connection')
        audit['coreIdentity'] = core_before; audit['libraryUnchanged'] = True
    finally:
        with contextlib.suppress(Exception):
            audit['pendingRpc'] = js('return window.__rfdAudit?.events||[]')
            audit['ui'] = json.loads(js('return JSON.stringify({busy:document.querySelector("#backup-open")?.disabled,notice:document.querySelector("#backup-notice")?.textContent||null,error:document.querySelector(".backup-panel > .desktop-inline-error")?.textContent||null})'))
        (h['artifacts'] / 'rfd-native-audit.json').write_text(json.dumps(audit, indent=2) + '\n')
        if connection: connection.close()
        with contextlib.suppress(Exception): command('disconnect')
        server.shutdown(); server.server_close()
