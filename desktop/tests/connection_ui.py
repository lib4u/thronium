"""Connection rollback through the real window, core, HTTP and private GNOME settings."""
import copy
import contextlib
import http.client
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time
from gi.repository import Gio, GLib


def run(h):
    command, click, fill, wait_for, js, check, screenshot = (h[k] for k in ('command', 'click', 'fill', 'wait_for', 'js', 'check', 'screenshot'))
    initial = command('snapshot')
    observations = []
    def observe(stage):
        value=command('snapshot')
        observations.append({'stage':stage,'monotonic':time.monotonic(),'selected':value['selected'],'running':value['running'],'phase':value['phase'],'error':value['error'],'domProfile':js('return document.querySelector("[data-session-profile]")?.dataset.sessionProfile ?? null')})
    assert initial['running'] is None
    config = Path(os.environ['XDG_CONFIG_HOME'])
    assert os.environ.get('GSETTINGS_BACKEND') == 'keyfile' and 'thronium-native-test-' in str(config)
    schemas = [Gio.Settings.new('org.gnome.system.proxy' + ('.' + s if s else '')) for s in ('', 'http', 'https', 'socks', 'ftp')]

    def settings():
        # The keyfile backend notifies long-lived Gio readers asynchronously.
        # Read persisted OS values in a fresh process rather than its old cache.
        script = "from gi.repository import Gio; import json; schemas=[Gio.Settings.new('org.gnome.system.proxy'+('.'+s if s else '')) for s in ('','http','https','socks','ftp')]; print(json.dumps([(s.get_value(k).print_(True),s.get_user_value(k).print_(True) if s.get_user_value(k) is not None else None) for s in schemas for k in sorted(s.list_keys())]))"
        return json.loads(subprocess.check_output(['python3', '-c', script], text=True, timeout=3))

    def poll(fn, accept):
        until = time.monotonic() + 12
        while time.monotonic() < until:
            result = fn()
            if accept(result):
                return result
            time.sleep(.1)
        raise AssertionError('Connection state did not settle')

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            data = b'rollback-http'
            self.send_response(404 if self.path.endswith('missing.json') else 200)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *_):
            pass

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = f'http://127.0.0.1:{server.server_port}'
    guard = socket.socket()
    guard.bind(('127.0.0.1', 0))
    guard.listen()
    busy = guard.getsockname()[1]
    with socket.socket() as free:
        free.bind(('127.0.0.1', 0))
        port = free.getsockname()[1]
    ids = []
    original_routing = command('routing')
    original_settings = settings()

    def add(name, kind, value):
        pid = command('saveProfile', {'name': name, 'groupId': 'personal', 'kind': kind, 'config': value})['id']
        ids.append(pid)
        return pid

    def forward_http():
        client = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
        try:
            client.request('GET', origin + '/')
            response = client.getresponse()
            assert response.status == 200 and response.read() == b'rollback-http'
        finally:
            client.close()

    def reset_routing():
        previous = copy.deepcopy(original_routing)
        previous['revision'] = command('routing')['revision']
        command('saveRouting', previous)

    try:
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark', 'connectionMode': 'local', 'inboundPort': port})
        a = add('Rollback working', 'sing-box-outbound', {'type': 'direct'})
        bad = add('Rollback occupied', 'sing-box-config', {'inbounds': [{'type': 'mixed', 'tag': 'partial', 'listen': '127.0.0.1', 'listen_port': port}, {'type': 'mixed', 'tag': 'occupied', 'listen': '127.0.0.1', 'listen_port': busy}], 'outbounds': [{'type': 'direct'}]})
        command('select', {'id': a})
        click('.primary-nav button:first-child')
        wait_for('return document.documentElement.lang==="en"')
        observe('before-selected-profile-render')
        wait_for('return document.querySelector("[data-session-profile]")?.dataset.sessionProfile === ' + json.dumps(a))
        observe('after-selected-profile-render')
        click('.power-button')
        poll(lambda: command('snapshot')['running'], lambda p: p == a)
        forward_http()
        check(True, 'the real window starts a working loopback connection before a switch failure')
        fill('#client-search', 'Rollback occupied')
        wait_for('return document.querySelectorAll(".connection-row-button").length===1')
        click('.connection-row-button')
        wait_for('return document.querySelector(".desktop-error")?.textContent.includes("previous connection has been restored")')
        after = command('snapshot')
        check(after['running'] == a and after['selected'] == a and after['error'] == 'connection_restored', 'a UI switch that fails at Start returns to the previous running and selected profile')
        forward_http()
        check(True, 'restored connection forwards HTTP after the failed candidate opened a partial listener')
        wait_for('return !document.querySelector(".power-button").disabled')
        check(js('return document.querySelector(".live-indicator").textContent.includes("Active") && !document.querySelector(".power-button").disabled'), 'the window leaves its connecting state and reports the restored connection as active')
        screenshot('connection-restored-dark-en')
        command('preferences', {**after['preferences'], 'language': 'ru', 'theme': 'light'})
        wait_for('return document.querySelector(".desktop-error")?.textContent.includes("Прежнее подключение восстановлено")')
        h['request']('POST', h['base'] + '/window/rect', {'width': 390, 'height': 844})
        check(js('return document.querySelector(".desktop-error").scrollWidth<=document.querySelector(".desktop-error").clientWidth'), 'the rollback explanation is translated and fits the narrow Russian window')
        screenshot('connection-restored-narrow-ru')
        click('.power-button')
        poll(lambda: command('snapshot')['running'], lambda p: p is None)
        check(command('snapshot')['error'] is None, 'Disconnect clears the recovery notice and stops the restored connection')

        h['request']('POST', h['base'] + '/window/rect', {'width': 1280, 'height': 860})
        command('preferences', {**command('snapshot')['preferences'], 'language': 'en'})
        command('connectionSettings', {'mode': 'system-proxy', 'port': port})
        command('connect', {'id': a})
        applied = settings()
        status = command('snapshot')['systemProxy']
        (h['artifacts'] / 'connection-proxy-values.json').write_text(json.dumps({'status': status, 'original': original_settings, 'applied': applied}, indent=2)+'\n')
        check(status['active'] and applied != original_settings, 'the working session owns the isolated GNOME system proxy')
        next_routing = command('routing')
        active = next(p for p in next_routing['profiles'] if p['id'] == next_routing['active'])
        active['route']['rule_set'] = [{'type': 'remote', 'tag': 'missing-rollback', 'format': 'source', 'url': origin + '/missing.json', 'download_detour': 'direct'}]
        command('saveRouting', next_routing)
        click('.primary-nav button:nth-child(2)')
        click('#route-apply')
        wait_for('return document.querySelector(".desktop-error")?.textContent.includes("previous connection has been restored") && !document.querySelector("#route-apply")?.disabled')
        recovered = command('snapshot')
        check(recovered['running'] == a and recovered['routing']['pending'], 'failed Apply and reconnect retains the previous session and leaves new routing pending')
        check(recovered['systemProxy']['active'] and settings() == applied, 'rollback reapplies the GNOME proxy to the restored listener')
        forward_http()
        check(True, 'HTTP still passes through the system proxy listener after routing rollback')
        check((config / 'thronium-system-proxy/recovery.json').is_file(), 'proxy recovery journal remains available for the restored session')
        screenshot('connection-routing-restored-en')
        reset_routing()
        command('applyRouting')
        check(command('snapshot')['error'] is None and not command('snapshot')['routing']['pending'], 'a corrected routing retry clears the failure and pending state')
        command('disconnect')
        poll(settings, lambda value: value == original_settings)
        check(not (config / 'thronium-system-proxy/recovery.json').exists(), 'disconnect after rollback restores exact original GNOME values and removes its journal')
    finally:
        with contextlib.suppress(Exception):observe('before-cleanup')
        (h['artifacts']/'connection-observations.json').write_text(json.dumps(observations,indent=2)+'\n')
        command('disconnect')
        reset_routing()
        for pid in ids:
            command('delete', {'id': pid})
        command('preferences', initial['preferences'])
        if initial['selected']:
            command('select', {'id': initial['selected']})
        click('.primary-nav button:first-child')
        fill('#client-search', '')
        h['request']('POST', h['base'] + '/window/rect', {'width': 1280, 'height': 860})
        wait_for('return document.body.classList.contains("disconnected") && document.documentElement.lang===' + json.dumps(initial['preferences']['language']))
        guard.close()
        server.shutdown()
        server.server_close()
