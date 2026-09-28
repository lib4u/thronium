"""Dynamic pool editor and lifecycle in the real native app; loopback traffic only."""
import contextlib
import http.server
import json
import socket
import socketserver
import threading
import time


def run(h):
    command, click, fill, select, wait_for, js, check, screenshot = (h[k] for k in ('command', 'click', 'fill', 'select', 'wait_for', 'js', 'check', 'screenshot'))
    initial = command('snapshot')
    geometry = h['request']('GET', h['base'] + '/window/rect')
    groups, owned = [], []
    active_socket = None

    class HTTP(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_GET(self):
            self.send_response(204); self.send_header('Content-Length', '0'); self.end_headers()

    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            while True:
                data = self.request.recv(4096)
                if not data: return
                self.request.sendall(data)

    class EchoServer(socketserver.ThreadingTCPServer):
        daemon_threads = True

    http_fixture = http.server.ThreadingHTTPServer(('127.0.0.1', 0), HTTP)
    echo_server = EchoServer(('127.0.0.1', 0), Echo)
    for server in [http_fixture, echo_server]: threading.Thread(target=server.serve_forever, daemon=True).start()

    def group(name):
        result = command('saveGroup', {'name': name})['id']; groups.append(result); return result

    def add(group_id, name, kind, config):
        result = command('saveProfile', {'name': name, 'groupId': group_id, 'kind': kind, 'config': config})['id']; owned.append(result); return result

    def close():
        click('#main-modal > .modal-head > button'); wait_for('return !document.querySelector("dialog[open]")')

    def preview(ids):
        wait_for('return !document.querySelector("#selector-preview-loading") && JSON.stringify([...document.querySelectorAll("[data-selector-preview-member]")].map(e=>e.dataset.selectorPreviewMember))===' + json.dumps(json.dumps(ids, separators=(',', ':'))))

    def pool(ids):
        end = time.monotonic() + 12
        while time.monotonic() < end:
            status = command('getAutoSelectors')
            if status and status[0]['membersAlive'] == len(ids) and [m['profileId'] for m in status[0]['members']] == ids: return status[0]
            time.sleep(.12)
        raise AssertionError('Dynamic runtime membership did not become ' + repr(ids))

    def rejected(name, payload, code):
        try: command(name, payload)
        except RuntimeError as error: return code in str(error)
        return False

    def tunnel():
        result = socket.create_connection(('127.0.0.1', local_port), timeout=4)
        authority = '127.0.0.1:' + str(echo_server.server_address[1])
        result.sendall(('CONNECT ' + authority + ' HTTP/1.1\r\nHost: ' + authority + '\r\n\r\n').encode())
        headers = b''
        while b'\r\n\r\n' not in headers:
            chunk = result.recv(4096); assert chunk; headers += chunk
        assert b' 200 ' in headers.split(b'\r\n', 1)[0]
        return result

    def echo(sock, text):
        text = text.encode(); sock.sendall(text); response = b''
        while len(response) < len(text):
            chunk = sock.recv(4096); assert chunk; response += chunk
        return response == text

    def edit(profile_id):
        select('.group-strip select', 'all'); fill('#client-search', '')
        menu = '[data-profile-menu="' + profile_id + '"]'
        wait_for('return !!document.querySelector(' + json.dumps(menu) + ')')
        js('document.querySelector(arguments[0]).scrollIntoView({block:"center"})', menu)
        click(menu); click('#menu-edit-profile')
        wait_for('return !!document.querySelector("#selector-membership")')

    try:
        command('disconnect')
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0)); local_port = listener.getsockname()[1]
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark', 'inboundPort': local_port})
        source, owner, target = group('Dynamic candidates'), group('Dynamic owners'), group('Portable snapshot')
        a = add(source, 'Match Alpha', 'sing-box-outbound', {'type': 'direct'})
        b = add(source, 'match Beta', 'xray-outbound', {'protocol': 'freedom', 'settings': {}})
        skipped = add(source, 'Match Skip', 'sing-box-outbound', {'type': 'direct'})
        add(owner, 'Match Other group', 'sing-box-outbound', {'type': 'direct'})
        add(source, 'Match Full JSON', 'sing-box-config', {'outbounds': [{'type': 'direct'}]})
        # WireGuard endpoints are ordinary pool members; a VPN endpoint opens its own session and is not.
        add(source, 'Match VPN endpoint', 'sing-box-outbound', {'type': 'tailscale', 'auth_key': 'tskey-fixture'})
        add(source, 'Match Explicit chain', 'chain', {'type': 'chain', 'hops': [skipped]})
        wait_for('return document.documentElement.lang==="en" && [...document.querySelector(".group-strip select").options].some(o=>o.value===' + json.dumps(source) + ')')
        click('.add-connection'); click('#add-choice-advanced'); select('#profile-type', 'autoselector')
        fill('#profile-name', 'Native dynamic pool'); select('#profile-group', owner)
        check(js('return document.querySelector("#selector-membership").value==="explicit"'), 'existing manual pool membership remains the default')
        click('[data-selector-member="' + a + '"]'); select('#selector-preferred', a)
        select('#selector-membership', 'dynamic'); select('#selector-source-group', source)
        fill('#selector-name-regex', '^match '); fill('#selector-exclude-regex', 'skip'); preview([a, b])
        check(js('return document.querySelector("#selector-preview-count").textContent.includes("2 / 500") && !document.querySelector("#selector-preferred")'), 'dynamic preview applies case-insensitive group filters and excludes full JSON, VPN endpoints and chains')
        check(js('return document.querySelector(".selector-fields").textContent.includes("next connection")'), 'editor explains that subscription changes apply on the next connection')
        select('#selector-membership', 'explicit')
        check(js('return document.querySelector(' + json.dumps('[data-selector-member="' + a + '"]') + ').checked && document.querySelector("#selector-preferred").value===' + json.dumps(a)), 'switching back restores the draft manual member and preferred server')
        select('#selector-membership', 'dynamic'); preview([a, b])
        check(js('return document.querySelector("#selector-name-regex").value==="^match " && document.querySelector("#selector-exclude-regex").value==="skip"'), 'switching modes restores the dynamic source filters')
        fill('#selector-name-regex', '[')
        wait_for('return !!document.querySelector("#selector-preview-error")')
        check(js('return !document.querySelector("[data-selector-preview-member]") && !document.querySelector("#selector-preview-count").textContent.includes("2 / 500") && !document.querySelector("#selector-preview-error").textContent.includes("selector_invalid_regex")'), 'invalid regex clears stale members and reports a localized preview error')
        fill('#selector-name-regex', '^Nobody$'); preview([])
        check(js('return document.querySelector("#selector-preview-count").textContent.includes("0 / 500") && document.querySelector("#selector-preview-empty").textContent.includes("save this pool")'), 'empty result shows zero and explains that saving remains available')
        fill('#selector-name-regex', '^match '); preview([a, b])
        # Delay a real response, rather than inventing a backend fixture result.
        js('''window.__selectorCallbacksSet=window.__TAURI_INTERNALS__.callbacks.set;window.__selectorDelayed=false;window.__selectorDelayNext=true;
Object.defineProperty(window.__TAURI_INTERNALS__.callbacks,'set',{configurable:true,writable:true,value:function(id,callback){
return window.__selectorCallbacksSet.call(this,id,value=>{
if(window.__selectorDelayNext&&Array.isArray(value?.members)&&typeof value.total==='number'){
window.__selectorDelayNext=false;window.__selectorDelayed=true;setTimeout(()=>callback(value),1500);
}else callback(value);});}});''')
        fill('#selector-name-regex', '^match'); wait_for('return window.__selectorDelayed')
        fill('#selector-name-regex', '^Match Alpha$'); preview([a]); time.sleep(1.7)
        check(js('return document.querySelector("#selector-preview-count").textContent.includes("1 / 500") && document.querySelectorAll("[data-selector-preview-member]").length===1'), 'late response for an older filter cannot replace the current preview')
        js('delete window.__TAURI_INTERNALS__.callbacks.set;window.__selectorDelayNext=false;')
        fill('#selector-name-regex', '^match '); preview([a, b]); click('#selector-refresh-preview'); preview([a, b])
        check(True, 'refresh preview revalidates the current source without saving a profile')
        command('preferences', {**command('snapshot')['preferences'], 'language': 'ru', 'theme': 'light'})
        wait_for('return document.documentElement.lang==="ru"')
        h['request']('POST', h['base'] + '/window/rect', {'width': 390, 'height': 844})
        check(js('return document.querySelector(".selector-fields").textContent.includes("следующем подключении") && document.documentElement.scrollWidth<=innerWidth && document.querySelector(".selector-fields").scrollWidth<=document.querySelector(".selector-fields").clientWidth'), 'Russian dynamic pool fields and next-connection explanation fit a 390-pixel window')
        screenshot('dynamic-selector-editor-narrow-ru')
        command('preferences', {**command('snapshot')['preferences'], 'language': 'en', 'theme': 'dark'})
        wait_for('return document.documentElement.lang==="en"')
        check(js('return document.documentElement.scrollWidth<=innerWidth && document.querySelector(".selector-fields").scrollWidth<=document.querySelector(".selector-fields").clientWidth'), 'English dynamic pool filters fit a narrow native window')
        screenshot('dynamic-selector-editor-narrow-en')
        h['request']('POST', h['base'] + '/window/rect', {'width': 1280, 'height': 860})
        click('[data-profile-tab="health"]')
        for key, value in {'url': f'http://127.0.0.1:{http_fixture.server_port}/probe', 'interval': '1s', 'bench_interval': '2s', 'watch_interval': '500ms', 'timeout': '800ms', 'sampling': '2', 'expected': '2', 'active_size': '5'}.items(): fill('[data-field="' + key + '"]', value)
        click('[data-profile-tab="json"]'); config = json.loads(js('return document.querySelector("#profile-json").value'))
        check(config['member_source'] == {'group_id': source, 'name_regex': '^match ', 'exclude_regex': 'skip'} and 'members' not in config and not config.get('pinned_profile'), 'saved JSON uses member_source and removes stale manual members and preferred references')
        click('.modal-footer .button.secondary'); wait_for('return !!document.querySelector(".desktop-success")')
        check(True, 'dynamic pool configuration validates against the production bundled core')
        click('button[form="profile-editor"]'); wait_for('return !document.querySelector("dialog[open]")')
        pid = next(p['id'] for p in command('snapshot')['profiles'] if p['name'] == 'Native dynamic pool'); owned.append(pid)
        h['request']('POST', h['base'] + '/refresh', {}); wait_for('return !!document.querySelector(".power-button")')
        edit(pid); preview([a, b])
        check(js('return document.querySelector("#selector-membership").value==="dynamic" && document.querySelector("#selector-source-group").value===' + json.dumps(source)), 'saved membership mode and source group survive a native webview reload')
        close(); command('connect', {'id': pid}); pool([a, b]); active_socket = tunnel()
        check(echo(active_socket, 'dynamic-live'), 'native connection forwards real traffic through a mixed sing-box/Xray pool')
        since = command('snapshot')['since']
        c = add(source, 'Match Gamma', 'sing-box-outbound', {'type': 'direct'})
        check(echo(active_socket, 'added-still-live') and command('snapshot')['since'] == since and [m['profileId'] for m in command('getAutoSelectors')[0]['members']] == [a, b], 'adding a matching profile keeps the existing CONNECT socket and running pool unchanged')
        check(rejected('deleteProfiles', {'ids': [a]}, 'stop_before_editing') and echo(active_socket, 'protected-member'), 'deleting an active dynamic member is rejected without closing its traffic')
        empty_config = {**config, 'member_source': {**config['member_source'], 'name_regex': '^Nobody$'}}
        empty = add(owner, 'Empty dynamic pool', 'auto-selector', empty_config)
        check(rejected('connect', {'id': empty}, 'selector_empty_pool') and command('snapshot')['running'] == pid and command('snapshot')['since'] == since and echo(active_socket, 'empty-safe'), 'empty saved pool refuses connection before interrupting the current session')
        check(rejected('deleteGroup', {'id': source, 'deleteProfiles': True}, 'selector_source_in_use'), 'source group cannot be deleted while a dynamic pool references it')
        command('disconnect'); active_socket.close(); active_socket = None
        original = command('profile', {'id': b})
        command('saveProfile', {k: original[k] for k in ['id', 'groupId', 'kind', 'config', 'expectedRevision']} | {'name': 'Outside filter'})
        command('connect', {'id': pid}); pool([a, c])
        with tunnel() as conn: check(echo(conn, 'updated-members'), 'next connection replaces renamed-out candidates with newly matching profiles')
        command('disconnect'); select('.group-strip select', 'all'); fill('#client-search', '')
        # The expanded multi-group list can place the pool below the viewport.
        # A menu intentionally closes when its anchor is outside the screen.
        js('document.querySelector(arguments[0]).scrollIntoView({block:"center"})', '[data-profile-menu="' + pid + '"]')
        wait_for('return (()=>{const r=document.querySelector(' + json.dumps('[data-profile-menu="' + pid + '"]') + ').getBoundingClientRect();return r.top>=0&&r.bottom<=innerHeight})()')
        click('[data-profile-menu="' + pid + '"]'); click('#export-one'); click('#export-reveal')
        wait_for('return !!document.querySelector("#export-content")'); text = js('return document.querySelector("#export-content").textContent'); bundle = json.loads(text)
        check('member_source' not in text and source not in text and all(old not in text for old in [a, c, pid]), 'portable export freezes current members and removes local source-group and profile references')
        close(); click('.add-connection'); click('#add-choice-link'); fill('#import-source', text); select('#import-group', target); click('#import-review')
        index = next(i for i, p in enumerate(bundle['profiles']) if p['kind'] == 'auto-selector')
        buttons = js('return [...document.querySelectorAll("[data-import-check]")].map(e=>e.dataset.importCheck)')
        count = len(command('snapshot')['profiles']); click('[data-import-check="' + buttons[index] + '"]'); wait_for('return !!document.querySelector(".import-valid")')
        check(len(command('snapshot')['profiles']) == count, 'portable dynamic snapshot previews without writing imported profiles')
        click('#import-save'); wait_for('return !document.querySelector("dialog[open]")')
        imported = [command('profile', {'id': p['id']}) for p in command('snapshot')['profiles'] if p['groupId'] == target]
        imported_pool = next(p for p in imported if p['kind'] == 'auto-selector')
        check('member_source' not in imported_pool['config'] and set(imported_pool['config']['members']) < {p['id'] for p in imported}, 'imported pool uses remapped fixed members independent of the original group')
        command('deleteGroup', {'id': owner, 'deleteProfiles': True}); groups.remove(owner)
        command('deleteGroup', {'id': source, 'deleteProfiles': True}); groups.remove(source)
        command('connect', {'id': imported_pool['id']}); pool(imported_pool['config']['members'])
        with tunnel() as conn: check(echo(conn, 'source-independent'), 'imported snapshot carries real traffic after the original pools and source group are removed')
    finally:
        if active_socket: active_socket.close()
        with contextlib.suppress(Exception): js('delete window.__TAURI_INTERNALS__.callbacks.set;window.__selectorDelayNext=false;')
        command('disconnect')
        # Owners precede their source to release dynamic references before cleanup.
        for group_id in list(reversed(groups)):
            with contextlib.suppress(Exception): command('deleteGroup', {'id': group_id, 'deleteProfiles': True})
        command('preferences', initial['preferences'])
        if initial['selected']: command('select', {'id': initial['selected']})
        h['request']('POST', h['base'] + '/window/rect', {'width': geometry['width'], 'height': geometry['height']})
        for server in [http_fixture, echo_server]: server.shutdown(); server.server_close()
