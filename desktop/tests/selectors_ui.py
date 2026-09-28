"""Actual automatic pool editor, health reporting, pin/recheck and portable import."""
import http.server
import json
import socket
import threading
import time
import tempfile
from native_screenshot import capture
from selector_ranking_fixture import Fixture
from quick_select_ui import reconnect_checks


def run(h):
    command, click, fill, select, wait_for, js, check, screenshot = (h[k] for k in ('command', 'click', 'fill', 'select', 'wait_for', 'js', 'check', 'screenshot'))
    initial = command('snapshot')
    source = command('saveGroup', {'name': 'Automatic fixtures', 'subscription': None})['id']
    target = command('saveGroup', {'name': 'Imported pool', 'subscription': None})['id']
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_GET(self):
            time.sleep(.03); self.send_response(204); self.send_header('Content-Length', '0'); self.end_headers()
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    fixture_directory = tempfile.TemporaryDirectory(prefix='thronium-quick-select-')
    fixture = Fixture(fixture_directory.name)
    for peer in fixture.peers:
        peer.ports.append(server.server_port)
    def add(name, kind, config): return command('saveProfile', {'name': name, 'groupId': source, 'kind': kind, 'config': config})['id']
    def pool(predicate=lambda p: True):
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            for p in command('getAutoSelectors'):
                if predicate(p): return p
            time.sleep(.15)
        raise AssertionError('Automatic pool did not reach the expected state')
    def close(): click('.modal-head .icon-button'); wait_for('return !document.querySelector("dialog")')
    try:
        command('disconnect')
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark', 'inboundPort': port})
        a = add('Automatic sing-box', 'sing-box-outbound', {'type': 'socks', 'server': '127.0.0.1', 'server_port': fixture.info['ports'][0]})
        b = add('Automatic Xray', 'xray-outbound', {'protocol': 'socks', 'settings': {'servers': [{'address': '127.0.0.1', 'port': fixture.info['ports'][1]}]}})
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0)); unavailable = s.getsockname()[1]
        bad = add('Automatic unavailable', 'sing-box-outbound', {'type': 'socks', 'server': '127.0.0.1', 'server_port': unavailable, 'password': 'native-selector-private'})
        opaque = add('Excluded full config', 'sing-box-config', {'outbounds': [{'type': 'direct'}]})
        chain = add('Explicit chain', 'chain', {'type': 'chain', 'hops': [a]})
        wait_for('return document.documentElement.lang==="en" && [...document.querySelector(".group-strip select").options].some(o=>o.value===' + json.dumps(source) + ')')
        select('.group-strip select', source); fill('#client-search', '')
        # Always-on auto-select card (feature): shown above the groups with >= 2 eligible servers.
        check(command('snapshot')['autoSelectAvailable'] and js('return !!document.querySelector("#auto-select-card")'),
              'the auto-select card appears above the groups when enough eligible servers exist')
        screenshot('auto-select-card')
        click('[data-auto-select]')
        wait_for('return document.querySelector(".destination-city")?.textContent==="Auto-select"')
        check(command('snapshot')['selected'] == 'auto-select' and js('return document.querySelector("#auto-select-card").classList.contains("selected")'),
              'selecting the card marks the virtual pool as the active connection and names it')
        click('#auto-select-configure')
        wait_for('return !!document.querySelector("#auto-select-save")')
        check(js('return !!document.querySelector("#auto-select-interval") && !!document.querySelector("#auto-select-balance") && !!document.querySelector("#auto-select-balance_mode")'),
              'the configurator shows the checks and balancing settings from the schema')
        screenshot('auto-select-config')
        select('#auto-select-interval', '120s')
        click('#auto-select-save')
        wait_for('return !document.querySelector("#auto-select-save")')
        check(command('snapshot')['preferences']['autoSelect']['config']['interval'] == '120s',
              'saving the configurator writes the edited setting into preferences')
        appearance = command('settings')['appearance']
        command('saveSettings', {'section': 'appearance', 'previous': appearance, 'values': {**appearance, 'auto_select_enabled': False}})
        wait_for('return !document.querySelector("#auto-select-card")')
        check(not command('snapshot')['autoSelectAvailable'], 'the appearance toggle hides the auto-select card')
        appearance = command('settings')['appearance']
        command('saveSettings', {'section': 'appearance', 'previous': appearance, 'values': {**appearance, 'auto_select_enabled': True}})
        wait_for('return !!document.querySelector("#auto-select-card")')
        # Pressing Connect on auto-select sweeps every eligible member with the
        # pool's own URL/timeout/concurrency (never the shared ping settings),
        # orders the pool by that sweep, keeps the "Auto-select" title and shows
        # the current host member while connected; disconnect hides it.
        sweep_url = f'http://127.0.0.1:{server.server_port}/auto-select'
        prefs = command('snapshot')['preferences']
        command('preferences', {**prefs, 'ping': {**prefs['ping'], 'method': 'tcp', 'url': 'http://127.0.0.1:1/shared-ping'},
                                'autoSelect': {**prefs['autoSelect'], 'enabled': True, 'config': {**prefs['autoSelect']['config'], 'url': sweep_url, 'connectivity_url': sweep_url, 'timeout': '2s', 'concurrency': 2}}})
        click('[data-auto-select]'); click('.power-button')
        wait_for('return document.querySelector(".session-card") && !!document.querySelector(".session-auto-host strong")', timeout=25)
        host = js('return document.querySelector(".session-auto-host strong")?.textContent')
        sweep = command('snapshot')['urlTests'] or {'entries': []}
        swept = {e['profileId']: e for e in sweep['entries']}
        fastest = min((e for e in swept.values() if e['status'] == 'ok'), key=lambda e: e['latencyMs'], default=None)
        check(sweep.get('kind') == 'latency' and sweep.get('method') == 'http' and sweep.get('source') == 'auto-select' and sweep.get('url') == sweep_url and sweep.get('timeoutMs') == 2000
              and set(swept) == {a, b, bad, chain} and swept[bad]['status'] != 'ok' and fastest is not None,
              'connecting to auto-select sweeps every eligible member as its own source with the pool URL and timeout, not the shared ping: ' + json.dumps({swept[k]['name']: [swept[k]['status'], swept[k]['latencyMs']] for k in swept}))
        rows = {p['id']: p['measurement'] for p in command('snapshot')['profiles'] if p['id'] in swept}
        journal = [e for e in command('getMeasurementJournal')['entries'] if e['source'] == 'auto-select']
        check(not js('return !!document.querySelector("#ping-status")') and all(m is None for m in rows.values())
              and {e['profileId'] for e in journal} == set(swept),
              'the sweep stays out of the standard ping banner and server rows and is journaled as auto-select: ' + json.dumps({'rows': rows, 'journal': len(journal)}))
        running = command('connectionConfiguration', {'id': 'auto-select', 'active': True})['parts'][0]['config']
        pool_outbound = next((o for o in running.get('outbounds', []) if o.get('tag') == 'proxy'), {})
        check(fastest is not None and pool_outbound.get('outbounds') and fastest['profileId'] in pool_outbound['outbounds'][0],
              'the running pool lists the member the sweep found fastest first: ' + json.dumps(pool_outbound.get('outbounds')))
        check(js('return document.querySelector(".destination-city")?.textContent==="Auto-select"')
              and host in {e['name'] for e in swept.values() if e['status'] == 'ok'},
              'connected auto-select keeps the Auto-select title and its current host is a member the sweep found reachable: ' + json.dumps(host))
        screenshot('auto-select-connected')
        reconnect_checks(h, fixture, {a: 0, b: 1, chain: 0}, bad, source)
        command('preferences', {**command('snapshot')['preferences'], 'ping': prefs['ping']})
        command('disconnect')
        wait_for('return !document.querySelector(".session-auto-host")')
        check(not js('return !!document.querySelector(".session-auto-host")'), 'the current host line disappears after disconnect')
        # A complete Xray configuration is an eligible member (Qt parity); it is added after the
        # auto-select checks so the sweep above keeps its four members.
        fullx = add('Complete Xray member', 'xray-config', {'inbounds': [{'tag': 'user-in', 'protocol': 'socks', 'listen': '127.0.0.1', 'port': 1}], 'outbounds': [{'tag': 'exit', 'protocol': 'socks', 'settings': {'servers': [{'address': '127.0.0.1', 'port': fixture.info['ports'][1]}]}}], 'routing': {'rules': [{'type': 'field', 'inboundTag': ['user-in'], 'outboundTag': 'exit'}]}})
        click('.add-connection'); click('#add-choice-advanced'); select('#profile-type', 'autoselector'); fill('#profile-name', 'Native automatic pool'); select('#profile-group', source); select('#selector-group', source)
        # Direct fixture commands are observed by the next app snapshot, while
        # the real UI actions refresh immediately. Wait for the deleted fixture
        # profile to leave the picker before checking its eligible membership.
        expected_members = sorted([a, b, bad, chain, fullx])
        wait_for('return JSON.stringify([...document.querySelectorAll("[data-selector-member]")].map(e=>e.dataset.selectorMember).sort())===' + json.dumps(json.dumps(expected_members, separators=(',', ':'))))
        check(sorted(js('return [...document.querySelectorAll("[data-selector-member]")].map(e=>e.dataset.selectorMember)')) == expected_members, 'manual pool picker offers ordinary sing-box/Xray profiles, explicit chains and complete Xray configurations while excluding complete sing-box configurations')
        click('#selector-add-visible'); select('#selector-preferred', b)
        check(js('return document.querySelectorAll("[data-selector-member]:checked").length===5'), 'manual pool add-visible includes an eligible explicit chain and a complete Xray member')
        click('[data-selector-member="' + chain + '"]'); click('[data-selector-member="' + fullx + '"]')
        check(js('return document.querySelectorAll("[data-selector-member]:checked").length===3'), 'add-visible fills the explicit pool without adding hidden or unsupported profiles')
        click('[data-profile-tab="health"]')
        for key, value in {'url': f'http://127.0.0.1:{server.server_port}/probe', 'connectivity_url': f'http://127.0.0.1:{server.server_port}/probe', 'interval': '1s', 'bench_interval': '2s', 'watch_interval': '500ms', 'timeout': '500ms', 'sampling': '2', 'expected': '2', 'active_size': '3'}.items(): fill('[data-field="' + key + '"]', value)
        click('[data-profile-tab="balance"]'); select('[data-field="balance"]', 'true'); select('[data-field="balance_mode"]', 'connection')
        click('[data-profile-tab="json"]'); config = json.loads(js('return document.querySelector("#profile-json").value'))
        check(config['members'] == [a, b, bad] and config['pinned_profile'] == b and config['balance'] and config['balance_mode'] == 'connection', 'pool, preferred member and balancing fields retain the exact library references in JSON')
        click('.modal-footer .button.secondary')
        try:
            wait_for('return !!document.querySelector(".desktop-success")')
        except AssertionError:
            # The boundary shows only a code; the Core's reason is in the app log.
            raise AssertionError('pool validation failed: ' + json.dumps(command('getLogs', {'source': 'app'})['entries'][-5:]))
        check(True, 'structured automatic pool configuration validates with the real bundled core')
        click('button[form="profile-editor"]'); wait_for('return !document.querySelector("dialog")')
        pid = next(p['id'] for p in command('snapshot')['profiles'] if p['name'] == 'Native automatic pool')
        command('select', {'id': pid}); wait_for('return document.querySelector(".destination-city").textContent==="Native automatic pool"'); click('.power-button')
        state = pool(lambda p: p['membersAlive'] == 2)
        check(state['membersTotal'] == 3 and state['balance'] and state['balanceMode'] == 'connection' and state['pinned'].endswith(b), 'real core measures the pool, reports two live members and restores the configured preference')
        check('native-selector-private' not in json.dumps(state)
              and all(m['lastError'] == '' or m['lastError'].startswith('probe_') for m in state['members']),
              'automatic status reports names, measurements and failure codes without configuration credentials or raw core text: ' + json.dumps([m['lastError'] for m in state['members']]))
        wait_for('return document.querySelector(".selector-compact [data-selector-selected]")?.textContent==="Automatic Xray"')
        check(True, 'connection page displays the actually selected pool member')
        names_by_id = {p['id']: p['name'] for p in command('snapshot')['profiles']}
        click('.primary-nav button:nth-child(3)'); wait_for('return document.querySelectorAll("[data-selector-live-member]").length===3')
        check(js('return document.querySelector(".selector-panel").textContent.includes("Unavailable")'), 'diagnostics lists each measured pool member including the failed one')
        columns = js('return [...document.querySelectorAll("[data-selector-sort]")].map(e=>e.dataset.selectorSort)')
        check(columns == ['rank', 'name', 'state', 'latency', 'jitter', 'checks', 'dials', 'lastOk'],
              'the pool table offers every column Qt sorts by: ' + json.dumps(columns))
        order = lambda: js('return [...document.querySelectorAll("[data-selector-live-member]")].map(e=>e.dataset.selectorLiveMember)')
        by_rank = order()
        click('[data-selector-sort=name]')
        wait_for('return document.querySelector("[data-selector-sort=name]").getAttribute("aria-sort")==="ascending"')
        by_name = order()
        check(sorted(by_name) == sorted(by_rank) and by_name == sorted(by_rank, key=lambda i: names_by_id[i].lower()),
              'sorting by name reorders the same members: ' + json.dumps(by_name))
        click('[data-selector-sort=rank]')
        wait_for('return document.querySelector("[data-selector-sort=rank]").getAttribute("aria-sort")==="ascending"')
        check(order() == by_rank, 'sorting returns to the ranking Qt shows first')
        click('[data-selector-problems="proxy"]')
        wait_for('return document.querySelectorAll("[data-selector-live-member]").length<3')
        problems = order()
        states = js('return [...document.querySelectorAll("[data-selector-member-state]")].map(e=>e.dataset.selectorMemberState)')
        check(bad in problems and all(s in ('dead', 'cooldown', 'degraded') for s in states),
              'the problems filter keeps only members Qt calls problematic: ' + json.dumps(states))
        note = js('return document.querySelector("[data-selector-member-note]").textContent')
        check(note and 'dial' not in note.lower() and '192.' not in note,
              'a failed member explains itself in the interface language, never with core text: ' + json.dumps(note))
        click('[data-selector-problems="proxy"]')
        wait_for('return document.querySelectorAll("[data-selector-live-member]").length===3')
        check(js('return !!document.querySelector("[data-selector-rounds=proxy]")?.textContent'),
              'the pool line reports its measurement rounds')
        before = command('snapshot')['since']; click('[data-selector-pin="' + a + '"]')
        pool(lambda p: p['selected'].endswith(a) and p['pinned'].endswith(a))
        wait_for('return document.querySelector(' + json.dumps('[data-selector-pin="' + a + '"]') + ')?.disabled')
        check(command('snapshot')['since'] == before, 'pinning from diagnostics changes the core selection without restarting the session')
        # A running pool is measured through the member that carries traffic now (Qt's live test), not through the saved preference.
        # The app learns the switch from its next selector poll; the switch history says when it has.
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and not any(e['toName'] == 'Automatic sing-box' and e['fromName'] for e in command('getSwitchHistory')['entries']): time.sleep(.3)
        command('startIpTests', {'ids': [pid]})
        def running_member():
            rows = (command('snapshot').get('urlTests') or {}).get('entries') or []
            return rows[0] if rows and rows[0].get('memberOrigin') == 'running' else None
        issued = None
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline and issued is None:
            issued = running_member(); time.sleep(.3)
        rows = (command('snapshot').get('urlTests') or {}).get('entries') or []
        check(issued is not None and issued['memberId'] == a and issued['profileId'] == pid and command('snapshot')['since'] == before,
              'an IP test of the running pool goes through the member the core selected and names it as carrying traffic now: ' + json.dumps([{k: r.get(k) for k in ('status', 'error', 'memberId', 'memberName', 'memberOrigin')} for r in rows]) + ' selected=' + json.dumps([(p['selected'], p['pinned']) for p in command('getAutoSelectors')]))
        command('cancelUrlTests')
        while any(e['status'] in ('queued', 'testing') for e in ((command('snapshot').get('urlTests') or {}).get('entries') or [])): time.sleep(.2)
        command('clearUrlTests')
        click('[data-selector-auto="proxy"]'); pool(lambda p: not p['pinned'])
        check(True, 'release-pin returns the pool to automatic selection')
        rounds = pool()['roundsCompleted']; click('[data-selector-recheck="proxy"]'); pool(lambda p: p['roundsCompleted'] > rounds)
        check(command('snapshot')['since'] == before, 'recheck button starts another core measurement round while preserving the connection')
        h['request']('POST', h['base'] + '/refresh', {}); wait_for('return !!document.querySelector(".power-button")')
        check(command('snapshot')['running'] == pid and command('snapshot')['since'] == before and bool(pool()['members']), 'webview reload restores pool status while native measurements and forwarding continue')
        click('.primary-nav button:nth-child(3)'); command('preferences', {**command('snapshot')['preferences'], 'language': 'ru', 'theme': 'light'})
        wait_for('return document.documentElement.lang==="ru" && !!document.querySelector("[data-selector-recheck]")')
        h['request']('POST', h['base'] + '/window/rect', {'width': 390, 'height': 844})
        js('document.querySelector(".selector-panel").scrollIntoView()')
        check(js('return document.querySelector(".selector-panel").textContent.includes("Автовыбор") && document.documentElement.scrollWidth<=innerWidth && document.querySelector(".selector-panel").scrollWidth<=document.querySelector(".selector-panel").clientWidth'), 'Russian runtime selection controls and member diagnostics fit the narrow window')
        # WebKit's snapshot RPC can hang/reset during continuous core-log layout.
        # Capture the isolated native window; DOM/layout checks above stay unchanged.
        capture(h['artifacts'] / 'selector-status-narrow-ru.png')
        command('disconnect'); wait_for('return document.querySelector(".selector-panel").textContent.includes("не запущен")')
        check(command('getAutoSelectors') == [], 'disconnect clears automatic pool status instead of retaining old measurements')
        h['request']('POST', h['base'] + '/window/rect', {'width': 1280, 'height': 860}); click('.primary-nav button:nth-child(1)')
        command('preferences', {**command('snapshot')['preferences'], 'language': 'en'}); wait_for('return document.documentElement.lang==="en"')
        select('.group-strip select', source); fill('#client-search', 'Native automatic pool'); wait_for('return document.querySelectorAll(".connection-row").length===1')
        click('.row-more'); click('#export-one'); check(js('return document.querySelector("#export-format option[value=configurations]").disabled'), 'automatic pool export retains its complete portable graph')
        click('#export-reveal'); wait_for('return !!document.querySelector("#export-content")'); text = js('return document.querySelector("#export-content").textContent'); bundle = json.loads(text)
        check(len(bundle['profiles']) == 4 and all(old not in text for old in [a, b, bad, pid]), 'pool export includes all three members and replaces every local reference including the preferred server')
        close(); click('.add-connection'); click('#add-choice-link'); fill('#import-source', text); select('#import-group', target); click('#import-review')
        buttons = js('return [...document.querySelectorAll("[data-import-check]")].map(e=>e.dataset.importCheck)'); index = next(i for i, p in enumerate(bundle['profiles']) if p['kind'] == 'auto-selector')
        count = len(command('snapshot')['profiles']); click('[data-import-check="' + buttons[index] + '"]'); wait_for('return !!document.querySelector(".import-valid")')
        check(len(command('snapshot')['profiles']) == count, 'pool import preview validates its candidate graph without persisting any profiles')
        click('#import-save'); wait_for('return !document.querySelector("dialog")')
        imported = [command('profile', {'id': p['id']}) for p in command('snapshot')['profiles'] if p['groupId'] == target]
        imported_pool = next(p for p in imported if p['kind'] == 'auto-selector'); imported_ids = {p['id'] for p in imported}
        check(set(imported_pool['config']['members']) < imported_ids and imported_pool['config']['pinned_profile'] in imported_ids, 'pool import remaps all members and the saved preference to the new group atomically')
        command('deleteGroup', {'id': source, 'deleteProfiles': True}); source = None
        command('connect', {'id': imported_pool['id']}); pool(lambda p: p['membersAlive'] == 2)
        check(command('snapshot')['running'] == imported_pool['id'], 'imported automatic pool works after removing the entire original group')
    finally:
        command('disconnect')
        if source: command('deleteGroup', {'id': source, 'deleteProfiles': True})
        command('deleteGroup', {'id': target, 'deleteProfiles': True}); command('preferences', initial['preferences'])
        if initial['selected']: command('select', {'id': initial['selected']})
        click('.primary-nav button:nth-child(1)'); fill('#client-search', '')
        h['request']('POST', h['base'] + '/window/rect', {'width': 1280, 'height': 860})
        server.shutdown(); server.server_close()
        fixture.close(); fixture_directory.cleanup()
