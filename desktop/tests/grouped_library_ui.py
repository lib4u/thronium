"""Grouped subscription UX in the real WebKit window and native engine."""
import base64
import collections
import http.server
import json
import pathlib
import socket
import threading
import time


def poll(read, predicate, timeout=30):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = read()
        if predicate(value):
            return value
        time.sleep(.1)
    raise AssertionError('Native group operation did not finish')


def run(h):
    command, click, fill, select, wait_for, js, check, screenshot = (h[k] for k in ('command', 'click', 'fill', 'select', 'wait_for', 'js', 'check', 'screenshot'))
    initial = command('snapshot')
    calls = collections.Counter()
    source = {'announcement': 'Плановые работы в 03:00. Выберите другой сервер при необходимости.', 'fail': False}
    groups = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            calls[self.path] += 1
            if self.path == '/probe':
                body = b'ok'
                self.send_response(200)
            else:
                body = json.dumps([{'type': 'direct', 'tag': f'Group {self.path[1:].upper()} Server {n}'} for n in (10, 2)]).encode()
                self.send_response(503 if source['fail'] and self.path == '/a' else 200)
                if self.path == '/a':
                    self.send_header('profile-title', 'base64:' + base64.b64encode('Подписка A'.encode()).decode())
                    if source['announcement'] is not None:
                        self.send_header('announce', 'base64:' + base64.b64encode(source['announcement'].encode()).decode())
                    self.send_header('subscription-userinfo', 'upload=0; download=262144; total=1048576; expire=2000000000')
                else:
                    body = b'#profile-title: Provider B\n#announce: News from B\n#subscription-userinfo: download=2048; total=0\n' + body
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = f'http://127.0.0.1:{server.server_port}'

    def group(gid):
        return next(g for g in command('snapshot')['groups'] if g['id'] == gid)

    def members(gid):
        return [p for p in command('snapshot')['profiles'] if p['groupId'] == gid]

    def card(gid):
        return f'[data-library-group="{gid}"]'

    def rows(gid):
        return js('return [...document.querySelectorAll(arguments[0]+" .row-server-info strong")].map(e=>e.textContent)', card(gid))

    def create(name, path=None):
        gid = command('saveGroup', {'name': name, 'subscription': {'url': origin + path, 'headers': {}, 'viaProxy': False, 'intervalMinutes': 0} if path else None})['id']
        groups.append(gid)
        return gid

    def update(gid, status='updated'):
        click(f'[data-group-refresh="{gid}"]')
        result = poll(lambda: command('snapshot')['subscriptionJobs'], lambda jobs: any(j['groupId'] == gid and j['status'] in ('updated', 'unchanged', 'error', 'needs-review') for j in jobs))
        check(next(j for j in result if j['groupId'] == gid)['status'] == status, f'group update ends with {status}')
        command('clearSubscriptionJobs')

    def close():
        click('.modal-head .icon-button')
        wait_for('return !document.querySelector("dialog")')

    try:
        with socket.socket() as available:
            available.bind(('127.0.0.1', 0)); port = available.getsockname()[1]
        command('preferences', {**initial['preferences'], 'language': 'ru', 'theme': 'light', 'inboundPort': port, 'librarySort': 'original', 'librarySortDescending': False})
        a, b, local = create('127.0.0.1', '/a'), create('My B subscription', '/b'), create('Local group')
        local_id = command('saveProfile', {'name': 'Local direct', 'groupId': local, 'kind': 'sing-box-outbound', 'config': {'type': 'direct'}})['id']
        wait_for('return document.querySelectorAll("[data-group-refresh]").length===2')
        select('.group-strip select', 'all')
        update(a)
        check(len(members(a)) == 2 and not members(b) and calls['/a'] == 1 and calls['/b'] == 0, 'refresh in one card downloads only that subscription')
        update(b)
        wait_for('return document.querySelectorAll(".group-announcement").length===2')
        check(a != b and len(members(b)) == 2, 'different subscription paths on one host retain distinct groups')
        check(group(a)['displayName'] == 'Подписка A' and group(b)['displayName'] == 'My B subscription', 'provider title labels a default group while a custom name is preserved')
        check(group(a)['announcement'] == source['announcement'] and group(b)['announcement'] == 'News from B', 'HTTP Base64 and body-comment announcements reach their own cards')
        check(js('return document.querySelector(arguments[0]+" [role=progressbar]").getAttribute("aria-valuenow")', card(a)) == '25', 'quota bar reflects provider usage for its own group')
        check(js('const g=document.querySelector(arguments[0]);return !g.querySelector("[role=progressbar]")&&g.querySelector(".group-usage-track>span").getBoundingClientRect().width===0&&g.querySelector(".group-usage-track").getBoundingClientRect().width>0', card(b)) and 'Без лимита' in js('return document.querySelector(arguments[0]+" .group-usage").textContent', card(b)), 'unlimited subscription keeps an empty track with its usage and no invented percentage')
        check(not js('return !!document.querySelector(arguments[0]+" .group-usage")', card(local)), 'local profiles have no fabricated subscription quota')
        ap = members(a); bp = members(b)
        command('select', {'id': ap[0]['id']}); command('favorite', {'id': ap[0]['id']})
        check(rows(a) == ['Group A Server 10', 'Group A Server 2'] and rows(b) == ['Group B Server 10', 'Group B Server 2'], 'all-groups view partitions servers into provider cards in library order')
        screenshot('groups-expanded-light-ru')
        click(f'[data-group-collapse="{a}"]')
        wait_for('return document.querySelector(' + json.dumps(card(a) + ' [data-group-collapse]') + ').getAttribute("aria-expanded")=="false"')
        check(not rows(a) and len(rows(b)) == 2 and len(rows(local)) == 1, 'collapse hides only that group’s server rows')
        check(js('return !!document.querySelector(arguments[0]+" .group-announcement") && !!document.querySelector(arguments[0]+" .group-usage") && !document.querySelector(arguments[0]+" .group-announcement").hidden', card(a)), 'collapsed card retains its announcement and quota')
        check(group(a)['collapsed'] and command('snapshot')['selected'] == ap[0]['id'], 'collapse persists without changing the selected server')
        h['request']('POST', h['base'] + '/refresh', {})
        wait_for('return !!document.querySelector("[data-group-collapse]")')
        check(not rows(a) and group(a)['collapsed'], 'native collapsed preference survives webview reload')
        select('.group-strip select', b)
        check(js('return [...document.querySelectorAll("[data-library-group]")].map(e=>e.dataset.libraryGroup)') == [b], 'top selector limits the view to one complete group card')
        select('.group-strip select', 'all')
        fill('#client-search', 'Group A')
        wait_for('return document.querySelectorAll(".connection-row").length===2')
        check(len(rows(a)) == 2 and group(a)['collapsed'], 'search reveals matches inside a folded group without changing the stored preference')
        fill('#client-search', '')
        check(not rows(a), 'clearing search restores the previous collapsed state')
        click('#bulk-select-toggle'); click('#bulk-select-visible')
        checked = js('return [...document.querySelectorAll("[data-bulk-profile]:checked")].map(e=>e.dataset.bulkProfile)')
        expected = {p['id'] for p in initial['profiles']} | {p['id'] for p in bp} | {local_id}
        check(set(checked) == expected and not ({p['id'] for p in ap} & set(checked)), 'select-visible excludes servers inside collapsed cards')
        click('#bulk-select-toggle')
        click(f'[data-group-collapse="{a}"]')
        click('#library-sort'); click('#library-sort-name')
        wait_for('return !document.querySelector("#library-sort").disabled')
        check(rows(a) == ['Group A Server 2', 'Group A Server 10'] and rows(b) == ['Group B Server 2', 'Group B Server 10'], 'natural name sorting stays within group boundaries')
        click('.library-tabs button:nth-child(2)')
        check(rows(a) == ['Group A Server 10'] and not rows(b), 'favorites keep their group label and hide groups without matches')
        click('.library-tabs button:nth-child(1)')
        click(f'[data-group-menu="{b}"]'); click('[data-group-action="edit"]')
        wait_for('return !!document.querySelector("#group-name")')
        check(js('return document.querySelector("#group-name").value') == 'My B subscription' and js('return document.querySelector("#group-url").value') == origin + '/b', 'card menu opens the editor for the intended subscription')
        close()
        command('connect', {'id': ap[0]['id']})
        active = command('snapshot')
        command('savePingSettings', {'url': origin + '/probe', 'timeoutMs': 1000})
        click(f'[data-group-collapse="{b}"]'); click(f'[data-group-probe="{b}"]')
        check(not js('return !!document.querySelector("dialog")'), 'per-group ping starts immediately without a dialog, even while collapsed')
        probe = poll(lambda: command('snapshot')['urlTests'], lambda result: result and all(e['status'] not in ('queued', 'testing') for e in result['entries']))
        check({e['profileId'] for e in probe['entries']} == {p['id'] for p in bp} and all(e['status'] == 'ok' for e in probe['entries']), 'group probe runs real URL checks only for that group')
        check(command('snapshot')['running'] == active['running'] and command('snapshot')['since'] == active['since'], 'group actions preserve the active connection in a different group')
        command('clearUrlTests')
        source['announcement'] = '<img src=x onerror=alert(1)>\n' + 'Очень длинное объявление провайдера. ' * 20
        update(a, 'unchanged')
        wait_for('return !!document.querySelector(".group-announcement .text-button")')
        check(not js('return !!document.querySelector(".group-announcement img")') and '<img' in js('return document.querySelector(arguments[0]+" .group-announcement p").textContent', card(a)), 'provider announcement renders as escaped text')
        click(card(a) + ' .group-announcement .text-button')
        check(js('return document.querySelector(arguments[0]+" .group-announcement .text-button").getAttribute("aria-expanded")', card(a)) == 'true', 'long announcement can be expanded independently of the server list')
        check([p['id'] for p in members(a)] == [p['id'] for p in ap] and members(a)[0]['favorite'] and command('snapshot')['running'] == active['running'], 'metadata refresh preserves server IDs, favorites and active connection')
        source['fail'] = True
        update(a, 'error')
        check(group(a)['announcement'] == source['announcement'].strip() and len(members(a)) == 2, 'failed refresh preserves the last announcement and servers')
        source['fail'] = False; source['announcement'] = None
        update(a, 'unchanged')
        wait_for('return document.querySelectorAll(".group-announcement").length===1')
        check(group(a)['announcement'] is None and group(b)['announcement'] == 'News from B', 'successful response without announce clears only its previous announcement')
        command('preferences', {**command('snapshot')['preferences'], 'language': 'en', 'theme': 'dark'})
        wait_for('return document.documentElement.lang==="en"')
        screenshot('groups-collapsed-dark-en')
        h['request']('POST', h['base'] + '/window/rect', {'width': 390, 'height': 844})
        wait_for('return innerWidth===390')
        js('document.querySelector(".grouped-library").scrollIntoView({block:"start", behavior:"instant"})')
        wait_for('return document.querySelector(".library-group").getBoundingClientRect().top<300')
        check(js('return document.documentElement.scrollWidth<=innerWidth && [...document.querySelectorAll(".library-group")].every(e=>e.scrollWidth<=e.clientWidth)'), 'group cards, action buttons and announcement fit a narrow window')
        screenshot('groups-narrow-dark-en')
    finally:
        command('disconnect'); command('cancelUrlTests'); command('clearUrlTests'); command('cancelSubscriptionUpdates')
        for gid in groups:
            command('deleteGroup', {'id': gid, 'deleteProfiles': True})
        command('clearSubscriptionJobs'); command('preferences', initial['preferences'])
        if initial['selected']:
            command('select', {'id': initial['selected']})
        fill('#client-search', '')
        h['request']('POST', h['base'] + '/window/rect', {'width': 1280, 'height': 860})
        server.shutdown(); server.server_close()


def live(h, filename):
    """Opt-in metadata smoke; credentials stay in a private file and temp library."""
    from urllib.parse import urlsplit
    command, click, check, wait_for, js = (h[k] for k in ('command', 'click', 'check', 'wait_for', 'js'))
    url = pathlib.Path(filename).read_text().strip()
    gid = command('saveGroup', {'name': urlsplit(url).hostname, 'subscription': {'url': url, 'headers': {}, 'viaProxy': False, 'intervalMinutes': 0}})['id']
    wait_for('return !!document.querySelector("[data-group-refresh]")')
    click('[data-group-refresh]')
    snapshot = poll(lambda: command('snapshot'), lambda s: any(j['groupId'] == gid and j['status'] in ('updated', 'unchanged', 'error', 'needs-review') for j in s['subscriptionJobs']), timeout=100)
    job = next(j for j in snapshot['subscriptionJobs'] if j['groupId'] == gid)
    (h['artifacts'] / 'live-summary.json').write_text(json.dumps({'job': {key: job[key] for key in ('status', 'checked', 'total', 'error')}, 'profiles': len(snapshot['profiles'])}, indent=2))
    check(job['status'] == 'updated', 'authorized live subscription updates through the group card')
    group = next(g for g in snapshot['groups'] if g['id'] == gid)
    check(len(snapshot['profiles']) > 0, 'live subscription supplies validated servers')
    check(bool(group['announcement']) and bool(group['usage']) and group['displayName'] != group['name'], 'live provider title, announcement, traffic and expiry reach native storage')
    wait_for('return !!document.querySelector(".group-announcement")')
    check(js('return document.querySelector(".group-announcement p").textContent') == group['announcement'], 'live announcement appears unchanged as text')
    click('[data-group-collapse]')
    wait_for('return document.querySelector("[data-group-collapse]").getAttribute("aria-expanded")=="false"')
    check(js('return !document.querySelector(".connection-row") && !!document.querySelector(".group-announcement") && !!document.querySelector(".group-usage")'), 'collapsed live subscription retains announcement and quota')
    check(url not in json.dumps(snapshot), 'live source credentials are omitted from periodic snapshots')
