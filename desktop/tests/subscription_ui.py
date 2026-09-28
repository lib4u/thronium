"""Subscription/group scenarios shared by the full and focused native UI runs."""
import base64
import gzip
import http.server
import json
import threading
import time


def run(h):
    command, click, fill, select, wait_for, js, check, screenshot = (h[k] for k in ('command', 'click', 'fill', 'select', 'wait_for', 'js', 'check', 'screenshot'))
    request, base = h['request'], h['base']
    source = {'body': 'socks://alice:one@127.0.0.1:1081#Alpha\nsocks://alice:beta@127.0.0.1:1082#Beta', 'mode': 'base64'}
    received = []
    started = threading.Event()
    release = threading.Event()

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            received.append({k.lower(): v for k, v in self.headers.items()})
            started.set()
            mode = source['mode']
            if mode == 'delay':
                release.wait(15)
            self.send_response(403 if mode == 'http' else 200)
            self.send_header('Subscription-Userinfo', 'upload=1024; download=2048; total=1048576; expire=2000000000')
            body = source['body'].encode()
            if mode == 'base64':
                body = base64.b64encode(body)
            elif mode == 'gzip-large':
                body = gzip.compress(b'x' * (4 * 1024 * 1024 + 1))
                self.send_header('Content-Encoding', 'gzip')
            elif mode == 'empty':
                body = b''
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f'http://127.0.0.1:{server.server_port}/subscription?token=source-secret'

    def close():
        click('.modal-head .icon-button')
        wait_for('return !document.querySelector("dialog")')

    def group_snapshot(gid):
        return next(g for g in command('snapshot')['groups'] if g['id'] == gid)

    def members(gid):
        return [p for p in command('snapshot')['profiles'] if p['groupId'] == gid]

    def update():
        js('document.querySelector("[data-library-group] [data-group-menu]").scrollIntoView({block:"center"})')
        time.sleep(.15)
        click('[data-library-group] [data-group-menu]')
        click('#update-subscription')
        click('#subscription-load')
        wait_for('return !!document.querySelector("#subscription-reload")')

    try:
        initial = command('snapshot')
        command('preferences', {**initial['preferences'], 'language': 'ru'})
        wait_for('return document.documentElement.lang==="ru"')
        # A subscription pasted into the profile importer must reach the native
        # subscription flow instead of producing an invalid-address error.
        click('.add-connection'); click('#add-choice-link')
        fill('#import-source', url)
        check(js('return document.querySelector("#import-review").textContent.includes("Добавить подписку")'), 'pasted subscription URL offers subscription import instead of proxy parsing')
        check(not received and command('snapshot')['groups'] == initial['groups'], 'recognizing a subscription does not download or create a group before adding')
        close()
        click('.add-connection'); click('#add-choice-link')
        fill('#import-source', 'http://127.0.0.1:80');click('#import-review')
        check(js('return document.querySelectorAll(".import-select").length===1'), 'HTTP proxy addresses still import as individual profiles')
        close();click('.add-connection');click('#add-choice-link')
        fill('#import-source', f'http://127.0.0.1:{server.server_port}')
        check(js('return !!document.querySelector("#import-as-subscription")'), 'root subscription URLs offer the explicit subscription flow')
        close();click('.add-connection');click('#add-choice-link');fill('#import-source', url);fill('#import-title','Imported subscription');click('#import-review')
        wait_for('return !document.querySelector("dialog[open]")')
        imported_group = next(g['id'] for g in command('snapshot')['groups'] if g['name'] == 'Imported subscription')
        check(js('return !!document.querySelector("#subscription-empty") || document.querySelectorAll(".connection-row").length===2'), 'import remains visible as progress or actual servers when its dialog is closed')
        wait_for('return document.querySelectorAll(".connection-row").length===2', timeout=30)
        check(len(received) == 1, 'saving a subscription downloads once and adds its validated servers automatically')
        check(js('return document.querySelector(".group-strip select").value') == imported_group, 'automatic import selects the new subscription group')
        check(len(members(imported_group)) == 2 and command('group', {'id': imported_group})['subscription']['url'] == url, 'automatic import keeps the source and saves its servers without a separate apply step')
        screenshot('subscription-import-completed-ru')
        command('deleteGroup', {'id': imported_group, 'deleteProfiles': True})
        if initial['selected']: command('select', {'id': initial['selected']})
        command('clearSubscriptionJobs')
        received.clear()
        wait_for('return document.querySelector(".group-strip select").value==="all"')
        empty_group = command('saveGroup', {'name': 'Unfinished import', 'subscription': {'url': url, 'headers': {}, 'viaProxy': False}})['id']
        wait_for('return [...document.querySelector(".group-strip select").options].some(o=>o.value===' + json.dumps(empty_group) + ')')
        select('.group-strip select', empty_group)
        click('#subscription-empty-load')
        wait_for('return document.querySelectorAll(".connection-row").length===2', timeout=30)
        check(len(members(empty_group)) == 2, 'an existing empty subscription can load its servers from the library recovery button')
        command('deleteGroup', {'id': empty_group, 'deleteProfiles': True})
        command('clearSubscriptionJobs')
        if initial['selected']: command('select', {'id': initial['selected']})
        received.clear()
        wait_for('return document.querySelector(".group-strip select").value==="all"')
        click('.group-strip .icon-button')
        click('#group-new')
        fill('#group-name', 'Native provider')
        click('#group-subscribed')
        fill('#group-url', url)
        check(js('return document.querySelector("#group-url").type') == 'password', 'subscription URL is concealed in the group editor')
        click('.route-advanced summary')
        click('#group-inherit-settings')
        fill('#group-user-agent', 'Thronium-native-test')
        fill('#group-headers', '{"X-Token":"header-secret","Authorization":"Bearer fixture"}')
        screenshot('subscription-group-editor-ru')
        click('#group-save')
        wait_for('return !!document.querySelector("#group-new")')
        gid = next(g['id'] for g in command('snapshot')['groups'] if g['name'] == 'Native provider')
        check(group_snapshot(gid)['subscribed'], 'group form stores a subscription in the native backend')
        check('source-secret' not in json.dumps(command('snapshot')) and 'header-secret' not in json.dumps(command('snapshot')), 'periodic group snapshots omit the subscription URL and headers')
        check(command('group', {'id': gid})['subscription']['headers']['X-Token'] == 'header-secret', 'explicit group editing retains custom headers')
        click(f'[data-group-up="{gid}"]')
        check(command('snapshot')['groups'][-1]['id'] != gid, 'group move button changes persisted ordering')
        click(f'[data-group-down="{gid}"]')
        # The header intentionally ignores Close while the reorder is saving.
        wait_for('return !document.querySelector("#group-new").disabled')
        close()
        select('.group-strip select', gid)
        update()
        check(len(received) == 1, 'subscription load issues one native HTTP request')
        check(received[-1]['user-agent'] == 'Thronium-native-test' and received[-1]['x-token'] == 'header-secret', 'native download sends the configured user-agent and headers')
        check(js('return document.querySelectorAll("[data-subscription-action=added]").length') == 2, 'Base64 subscription shows both new profiles before saving')
        check(members(gid) == [], 'subscription preview does not change the saved library')
        click('#subscription-check')
        wait_for('return !!document.querySelector(".import-valid")')
        check(True, 'subscription configurations validate against the actual core')
        check(js('return document.querySelector("#subscription-apply").textContent.includes("Применить")'), 'subscription preview uses Russian labels')
        screenshot('subscription-preview-ru')
        click('#subscription-apply')
        wait_for('return !document.querySelector("dialog")')
        first = members(gid)
        check([p['name'] for p in first] == ['Alpha', 'Beta'], 'applying the preview stores profiles in provider order')
        alpha, beta = first
        usage = group_snapshot(gid)
        check(usage['updatedAt'] and usage['usage']['total'] == 1048576 and usage['usage']['download'] == 2048, 'subscription update persists real quota and timestamp')
        check(js('return document.querySelector(".group-usage-track[role=progressbar]").getAttribute("aria-valuetext").includes(" / 1,0 МиБ")'), 'group card displays the actual subscription quota')
        command('favorite', {'id': alpha['id']})
        command('select', {'id': alpha['id']})
        local = command('saveProfile', {'name': 'Manual subscription member', 'groupId': gid, 'kind': 'sing-box-outbound', 'config': {'type': 'direct'}})['id']
        source['body'] = 'socks://alice:two@127.0.0.1:1081#Renamed\nsocks://alice:gamma@127.0.0.1:1083#Gamma'
        update()
        check(js('return ["added","updated","removed"].every(a=>document.querySelectorAll(`[data-subscription-action=${a}]`).length===1)'), 'subscription preview distinguishes addition, credential rotation and removal')
        check(command('profile', {'id': alpha['id']})['config']['password'] == 'one', 'rotated credentials are not applied during preview')
        screenshot('subscription-changes-ru')
        click('#subscription-apply')
        wait_for('return !document.querySelector("dialog")')
        second = members(gid)
        check([p['name'] for p in second] == ['Renamed', 'Gamma', 'Manual subscription member'], 'subscription update preserves manually added group profiles')
        check(second[0]['id'] == alpha['id'] and second[0]['favorite'] and command('snapshot')['selected'] == alpha['id'], 'credential rotation preserves ID, favorite and selected profile')
        check(command('profile', {'id': alpha['id']})['config']['password'] == 'two' and all(p['id'] != beta['id'] for p in second), 'apply replaces credentials and removes the obsolete remote profile')

        before = members(gid)
        for mode, body, expected in [('plain', 'socks://127.0.0.1:1080#Valid\nunsupported://broken', 'В ответе есть ошибки'), ('empty', '', 'пустой ответ'), ('http', 'secret-error-body', 'HTTP 403'), ('gzip-large', '', '4 МиБ')]:
            source.update(mode=mode, body=body)
            update()
            check(js('return document.querySelector("#subscription-apply").disabled && document.querySelector(".desktop-inline-error").textContent.includes(arguments[0])', expected), f'{mode} subscription response prevents applying changes')
            close()
            check(members(gid) == before, f'{mode} subscription failure preserves every existing group profile')

        source.update(mode='delay', body='socks://127.0.0.1:1084#Late')
        started.clear()
        click('[data-library-group] [data-group-menu]')
        click('#update-subscription')
        click('#subscription-load')
        assert started.wait(3), 'server did not receive slow request'
        stamp = time.monotonic()
        check(command('snapshot')['running'] is None and time.monotonic() - stamp < 2, 'slow subscription request does not block native snapshots')
        close()
        release.set()
        check(members(gid) == before, 'closing an in-flight subscription download leaves saved profiles intact')

        source.update(mode='plain', body='socks://127.0.0.1:1084?unknown_field=omitted#Warning')
        update()
        check(js('return document.querySelector("#subscription-apply").disabled && !!document.querySelector("#subscription-acknowledge")'), 'untransferred subscription parameters require acknowledgement')
        click('#subscription-acknowledge')
        check(js('return !document.querySelector("#subscription-apply").disabled'), 'acknowledgement allows the reviewed subscription update')
        close()

        source.update(mode='plain', body='socks://alice:two@127.0.0.1:1081#Renamed\nsocks://alice:gamma@127.0.0.1:1083#Gamma')
        update()
        command('favorite', {'id': alpha['id']})
        after_edit = members(gid)
        click('#subscription-apply')
        wait_for('return !!document.querySelector(".desktop-inline-error")')
        check(js('return document.querySelector(".desktop-inline-error").textContent.includes("изменились")'), 'stale native preview reports concurrent profile edits')
        check(members(gid) == after_edit, 'stale preview cannot overwrite a newer favorite change')
        close()

        # Download through the actual local proxy controlled by this native app.
        proxy_profile = command('saveProfile', {'name': 'Subscription proxy', 'groupId': 'personal', 'kind': 'sing-box-outbound', 'config': {'type': 'direct'}})['id']
        command('connect', {'id': proxy_profile})
        click('.group-strip .icon-button')
        click(f'[data-group-edit="{gid}"]')
        click('.route-advanced summary')
        click('#group-via-proxy')
        click('#group-save')
        wait_for('return !!document.querySelector("#group-new")')
        close()
        update()
        check(js('return document.querySelectorAll("[data-subscription-action=unchanged]").length') == 2, 'subscription loads through the active real core HTTP proxy')
        check(command('snapshot')['running'] == proxy_profile, 'subscription download preserves the active connection')
        close()
        command('disconnect')
        command('delete', {'id': proxy_profile})
        update()
        wait_for('return !!document.querySelector(".desktop-inline-error")')
        check(js('return document.querySelector(".desktop-inline-error").textContent.includes("локальным HTTP-прокси")'), 'proxy download reports a disconnected local proxy')
        close()

        request('POST', base + '/refresh', {})
        wait_for('return !!document.querySelector(".group-strip select")')
        check(command('group', {'id': gid})['subscription']['viaProxy'] and len(members(gid)) == 3, 'subscription settings and profiles survive webview reload')
        storage = js('return Object.fromEntries(Object.keys(localStorage).map(key=>[key,localStorage.getItem(key)]))')
        group_ids = {g['id'] for g in command('snapshot')['groups']} | {'all'}
        check(set(storage) <= {'thronium-library-group'} and all(value in group_ids for value in storage.values()), 'subscription UI stores only the nonsecret library group selection in localStorage')
        command('preferences', {**command('snapshot')['preferences'], 'language': 'en', 'theme': 'dark'})
        wait_for('return document.documentElement.lang==="en"')
        click('.group-strip .icon-button')
        check(js('return document.querySelector("#group-new").textContent.includes("New group")'), 'group manager uses English labels')
        screenshot('subscription-groups-dark-en')
        request('POST', base + '/window/rect', {'width': 390, 'height': 844})
        check(js('return document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth'), 'group manager fits a narrow native window')
        screenshot('subscription-groups-narrow')
        click(f'[data-group-edit="{gid}"]')
        wait_for('return !!document.querySelector("#group-name") && !document.querySelector("#group-save").disabled')
        fill('#group-name', 'Renamed provider')
        click('.route-advanced summary')
        click('#group-via-proxy')
        check(js('return document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth && document.querySelector(".modal-footer").getBoundingClientRect().bottom<=innerHeight'), 'narrow subscription editor keeps fields and save button reachable')
        screenshot('subscription-editor-narrow')
        click('#group-save')
        wait_for('return !!document.querySelector("#group-new")')
        check(group_snapshot(gid)['name'] == 'Renamed provider', 'group name can be changed without replacing its profiles')
        close()
        select('.group-strip select', gid)
        update()
        check(js('return document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth && document.querySelector(".modal-footer").getBoundingClientRect().bottom<=innerHeight'), 'subscription review fits a narrow window with apply visible')
        screenshot('subscription-preview-narrow-en')
        close()
        request('POST', base + '/window/rect', {'width': 1280, 'height': 860})

        from subscription_recreation_ui import run as run_recreation
        run_recreation(h, gid, update, members, close)
        after_edit = members(gid)
        click('.group-strip .icon-button')
        click(f'[data-group-delete="{gid}"]')
        check(not js('return document.querySelector("#group-delete-profiles").checked'), 'deleting a group defaults to preserving its profiles')
        click('#group-delete-confirm')
        wait_for('return !!document.querySelector("#group-new")')
        check(all(command('profile', {'id': p['id']})['groupId'] == 'personal' for p in after_edit), 'delete-group UI moves every member to Personal')
        close()
        check(js('return document.querySelector(".group-strip select").value') == 'all', 'removing the selected group resets the library filter')
        for p in after_edit:
            command('delete', {'id': p['id']})
        command('preferences', initial['preferences'])
        if initial['selected']:
            command('select', {'id': initial['selected']})
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
