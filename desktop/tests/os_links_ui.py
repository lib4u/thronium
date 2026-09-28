"""Links and files the system opens with Thronium: a second launch and the desktop
handler deliver them to the running window, which asks before adding anything.
Fixture servers, addresses and files are synthetic and local."""
import base64
import contextlib
import http.server
import json
import os
import subprocess
import tempfile
import threading
from pathlib import Path


def run(h):
    command, click, wait_for, js, check, screenshot = (h[k] for k in ('command', 'click', 'wait_for', 'js', 'check', 'screenshot'))
    application = h['args'].application
    initial = command('snapshot')
    command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'light'})
    h['request']('POST', h['base'] + '/window/rect', {'width': 1280, 'height': 900})
    remote = {'route': {'final': 'direct', 'rules': [{'domain': ['remote.fixture.invalid'], 'action': 'route', 'outbound': 'direct'}]}}
    feed = 'vless://00000000-0000-4000-8000-000000000001@192.0.2.10:443?type=tcp&security=none#Fixture%20subscription'

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            content = json.dumps(remote).encode() if self.path == '/remote.json' else feed.encode() if self.path.startswith('/sub') else None
            self.send_response(200 if content else 404)
            self.send_header('Content-Length', str(len(content or b'')))
            self.end_headers()
            with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                self.wfile.write(content or b'')

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f'http://127.0.0.1:{server.server_port}'
    folder = Path(tempfile.mkdtemp(prefix='thronium-os-files-'))

    def launch(*arguments, cwd=None):
        subprocess.run([application, *arguments], check=True, timeout=15, cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def closed():
        wait_for('return !document.querySelector("dialog[open]")')

    def close_dialog():
        js('const all=[...document.querySelectorAll("dialog[open]")];all[all.length-1]?.querySelector(".modal-head>button")?.click()')
        closed()

    def save(section, **values):
        old = command('settings')[section]
        return command('saveSettings', {'section': section, 'previous': old, 'values': {**old, **values}})

    def link(kind, text):
        return f'throne://{kind}/' + base64.urlsafe_b64encode(text.encode()).decode().rstrip('=')

    def group(name):
        found = next(g for g in command('snapshot')['groups'] if g['name'] == name)
        return command('group', {'id': found['id']})['subscription']

    def imported_files(name):
        wait_for('return !!document.querySelector("#import-method-panel .import-read-success")')
        return js('return document.querySelector(".import-dropzone strong").textContent') == name

    try:
        save('system', url_scheme_auto_register=False)
        before = command('routing')
        throne = {'kind': 'throne-route-profile', 'v': 1, 'name': 'Linked route', 'default_outbound': 'direct',
                  'rules': [{'type': 'simple_address_bypass', 'name': 'Linked rule', 'domain_suffix': ['linked.fixture.invalid'], 'outbound': 'direct'}]}
        launch(link('route', json.dumps(throne)))
        wait_for('return document.querySelector("#route-import-name")?.value==="Linked route"')
        check(not js('return document.querySelector("#route-import-activate").checked') and command('routing')['revision'] == before['revision'],
              'a route link opens the routing loader, unsaved and not selected, also while the URL handler is not registered')
        screenshot('os-link-route-en')
        click('#route-import-save')
        closed()
        after = command('routing')
        linked = [p for p in after['profiles'] if p['name'] == 'Linked route']
        check(len(linked) == 1 and after['active'] == before['active'] and any(r['name'] == 'Linked rule' for r in linked[0]['rules']),
              'confirming a route link adds the converted profile without selecting it')

        launch(link('remoteroute', f'{base}/remote.json#Remote fixture\nftp://ignored.fixture.invalid/x\n{base}/missing.json#Missing fixture'))
        wait_for('return document.querySelectorAll("[data-route-remote]").length===2')
        check(js('return document.querySelector("#route-import-auto-update").checked'),
              'a remote route link lists its web profiles, skips other lines and offers them with automatic updates')
        screenshot('os-link-remoteroute-en')
        click('#route-import-add-all')
        wait_for('return !!document.querySelector("#route-import-failed")')
        loaded = [p for p in command('routing')['profiles'] if (p.get('source') or {}).get('url') == base + '/remote.json']
        check(len(loaded) == 1 and loaded[0]['name'] == 'Remote fixture' and loaded[0]['source'].get('autoUpdate') is True
              and command('routing')['active'] == before['active'],
              'adding all saves each loaded profile with its update source, without selecting it')
        check(js('const left=[...document.querySelectorAll("[data-route-remote]")];return left.length===1&&left[0].dataset.routeRemote==="Missing fixture"&&document.querySelector("#route-import-failed").textContent.includes("Missing fixture")&&!!document.querySelector("[role=alert]")'),
              'a profile that did not load stays listed with the reason')
        screenshot('os-link-remoteroute-failed-en')
        close_dialog()

        save('subscriptions', sub_auto_update=45)
        launch(link('addsub', f'{base}/sub-manual#Linked group'))
        wait_for('return document.querySelector("#import-subscription-name")?.textContent==="Linked group"')
        check(js('return document.querySelector("#import-subscription-url").textContent') == base + '/sub-manual'
              and js('return document.querySelector("#import-subscription-auto-update").checked'),
              'an addsub link shows the decoded name and address with automatic updates on')
        screenshot('os-link-addsub-en')
        click('#import-subscription-auto-update')
        click('#import-review')
        closed()
        manual = group('Linked group')
        check(manual['url'] == base + '/sub-manual' and manual['inheritDefaults'] is False and manual['intervalMinutes'] == 0
              and manual['userAgent'] == command('settings')['subscriptions']['user_agent'],
              'without automatic updates the subscription group is manual and keeps the global user agent')
        launch(link('addsub', f'{base}/sub-scheduled#Scheduled group'))
        wait_for('return document.querySelector("#import-subscription-name")?.textContent==="Scheduled group"')
        click('#import-review')
        closed()
        scheduled = group('Scheduled group')
        check(scheduled['inheritDefaults'] is True and scheduled['intervalMinutes'] == 45,
              'with automatic updates the subscription group follows the global schedule')

        (folder / 'fixture socks.json').write_text(json.dumps({'type': 'socks', 'tag': 'File socks', 'server': '192.0.2.20', 'server_port': 1080}))
        (folder / 'binary.json').write_bytes(b'{\x01}')
        launch('fixture socks.json', 'binary.json', 'missing.json', cwd=folder)
        check(imported_files('fixture socks.json') and js('return [...document.querySelectorAll("#import-file-problems li")].map(li=>li.textContent)') == ['binary.json: Could not read this file.'],
              'files from a launch open the file import relative to the launch directory, and an unreadable one is named in the dialog')
        screenshot('os-files-en')
        click('#import-review')
        wait_for('return !!document.querySelector("#import-save")')
        click('#import-save')
        closed()
        check(any(p['name'] == 'fixture socks' for p in command('snapshot')['profiles']), 'the opened configuration file is imported after review')
        launch(str(folder / 'binary.json'))
        wait_for('return !!document.querySelector("#import-file-problems")')
        check(not js('return !!document.querySelector(".import-read-success")') and js('return document.querySelector("#import-review").disabled'),
              'when no opened file is readable the dialog explains why and has nothing to review, like Qt\'s warning')
        close_dialog()

        save('system', url_scheme_auto_register=True)
        entry = Path(os.environ['XDG_DATA_HOME']) / 'applications' / 'Thronium-handler.desktop'
        lines = entry.read_text().splitlines()
        types = set(next(l for l in lines if l.startswith('MimeType=')).split('=', 1)[1].split(';'))
        check({'x-scheme-handler/throne', 'x-scheme-handler/thronium', 'application/json', 'application/yaml', 'text/yaml'} <= types
              and next(l for l in lines if l.startswith('Exec=')).endswith(' %U'),
              'the desktop handler lists both schemes and the configuration types, and accepts several files')
        # Like Qt, the types are only listed in the entry: no mimeapps.list default is written for them.
        defaults = ''.join(path.read_text() for path in [Path(os.environ['XDG_CONFIG_HOME']) / 'mimeapps.list', entry.parent / 'mimeapps.list'] if path.exists())
        registered = subprocess.check_output(['gio', 'mime', 'application/json'], text=True, env={**os.environ, 'LC_ALL': 'C'})
        check(entry.name in registered.split('Registered applications:', 1)[1]
              and not any(line.startswith(('application/json=', 'application/yaml=', 'text/yaml=')) and entry.name in line for line in defaults.splitlines()),
              'configuration files list Thronium among their applications without a default association being written')
        (folder / 'clash.yaml').write_text('proxies:\n  - name: Handler socks\n    type: socks5\n    server: 192.0.2.30\n    port: 1080\n')
        subprocess.run(['gio', 'launch', str(entry), (folder / 'clash.yaml').as_uri()], check=True, timeout=15, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        check(imported_files('clash.yaml'), 'a file opened through the desktop handler reaches the running window')
        click('#import-review')
        wait_for('return !!document.querySelector("#import-save")')
        click('#import-save')
        closed()
        check(any(p['name'] == 'Handler socks' for p in command('snapshot')['profiles']), 'the file opened through the handler is imported after review')
        save('system', url_scheme_auto_register=False)
    finally:
        server.shutdown()
        for path in folder.iterdir():
            path.unlink()
        folder.rmdir()
