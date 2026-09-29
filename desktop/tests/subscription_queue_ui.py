"""FIFO, cancellation and scheduling through the native window and a local origin."""
import collections
import http.server
import json
import socket
import threading
import time


def run(h):
    command, click, fill, select, wait_for, js, check, screenshot = (h[k] for k in ('command', 'click', 'fill', 'select', 'wait_for', 'js', 'check', 'screenshot'))
    request, base = h['request'], h['base']
    calls = collections.Counter()
    slow_started, release = threading.Event(), threading.Event()
    bodies = {
        '/ok': 'socks://alice:one@127.0.0.1:1081#Queued%20one\nsocks://alice:two@127.0.0.1:1082#Queued%20two',
        '/warning': 'socks://127.0.0.1:1081?unhandled=value#Needs%20review',
        '/bad': 'unsupported://invalid',
        '/core-error': json.dumps({'type': 'nonexistent-test-protocol', 'server': '127.0.0.1', 'server_port': 443}),
        '/partial': 'socks://127.0.0.1:1083#Partial%20ok\nunsupported://broken',
        '/config': json.dumps({'outbounds': [
            {'type': 'selector', 'tag': 'auto', 'outbounds': ['Split one']},
            {'type': 'direct', 'tag': 'direct'},
            {'type': 'socks', 'tag': 'Split one', 'server': '127.0.0.1', 'server_port': 1081},
            {'type': 'socks', 'tag': 'Split two', 'server': '127.0.0.1', 'server_port': 1082},
        ], 'route': {'rules': []}}),
        '/slow': 'socks://127.0.0.1:1084#Late',
        '/auto': 'socks://127.0.0.1:1085#Scheduled',
    }

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            calls[self.path] += 1
            if self.path == '/slow':
                slow_started.set()
                release.wait(20)
            body = bodies[self.path].encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Subscription-Userinfo', 'upload=0; download=2048; total=1048576')
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    groups = []

    def create(name, path, interval=0):
        gid = command('saveGroup', {'name': name, 'subscription': {'url': f'http://127.0.0.1:{server.server_port}{path}', 'userAgent': 'Thronium-queue-test', 'headers': {}, 'viaProxy': False, 'inheritDefaults': False, 'intervalMinutes': interval}})['id']
        groups.append(gid)
        return gid

    def close():
        click('.modal-head .icon-button')
        wait_for('return !document.querySelector("dialog")')

    def open_queue():
        click('.group-strip .icon-button')
        click('#subscription-open-jobs')

    def jobs():
        return command('snapshot')['subscriptionJobs']

    def members(gid):
        return [p for p in command('snapshot')['profiles'] if p['groupId'] == gid]

    def clear_groups():
        command('cancelSubscriptionUpdates')
        for gid in groups:
            command('deleteGroup', {'id': gid, 'deleteProfiles': True})
        groups.clear()
        command('clearSubscriptionJobs')

    initial = command('snapshot')
    active_profile = None
    tunnel_sockets = []
    try:
        with socket.socket() as available:
            available.bind(('127.0.0.1', 0))
            proxy_port = available.getsockname()[1]
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark', 'inboundPort': proxy_port})
        active_profile = command('saveProfile', {'name': 'Queue active connection', 'groupId': 'personal', 'kind': 'sing-box-outbound', 'config': {'type': 'direct'}})['id']
        command('connect', {'id': active_profile})
        active_since = command('snapshot')['since']
        origin = socket.socket()
        tunnel_sockets.append(origin)
        origin.settimeout(3)
        origin.bind(('127.0.0.1', 0))
        origin.listen()
        client = socket.create_connection(('127.0.0.1', proxy_port), timeout=3)
        tunnel_sockets.append(client)
        address = '127.0.0.1:' + str(origin.getsockname()[1])
        client.sendall(f'CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n\r\n'.encode())
        upstream, _ = origin.accept()
        tunnel_sockets.append(upstream)
        upstream.settimeout(3)
        assert b'200' in client.recv(1024)
        wait_for('return document.documentElement.lang==="en"')
        good = create('Queue · valid subscription', '/ok')
        warning = create('Queue · untransferred parameters', '/warning')
        bad = create('Queue · invalid response', '/bad')
        rejected = create('Queue · rejected configuration', '/core-error')
        open_queue()
        click('#subscription-update-all')
        wait_for('return document.querySelectorAll("[data-job-status=updated]").length===1 && document.querySelectorAll("[data-job-status=needs-review]").length===1 && document.querySelectorAll("[data-job-status=error]").length===2', timeout=30)
        first = jobs()
        check([j['groupId'] for j in first] == [good, warning, bad, rejected], 'update-all processes groups in their saved FIFO order')
        check([j['status'] for j in first] == ['updated', 'needs-review', 'error', 'error'], 'queue reports independent success, review and error outcomes')
        check(first[0]['checked'] == first[0]['total'] == 2, 'automatic update validates both added profiles with the real core')
        check(len(members(good)) == 2 and len(members(warning)) == 1 and not any(members(gid) for gid in (bad, rejected)), 'untransferred parameters no longer discard the update: the server is imported and the group stays under review')
        check(first[1]['counts']['warned'] == 1 and first[1]['counts']['skipped'] == 0, 'the queue counts the rows that need review instead of failing the group')
        check(js(f'return document.querySelector(\'[data-job-counts="{first[1]["id"]}"]\').textContent.includes("With warnings: 1")'), 'the queue names what needs review next to the applied counts')
        check(first[-1]['error'] == 'subscription_configuration_rejected', 'core rejection is recorded without dumping its configuration')
        check(calls == {'/ok': 1, '/warning': 1, '/bad': 1, '/core-error': 1}, 'one native request per queued group')
        active = command('snapshot')
        check(active['running'] == active_profile and active['since'] == active_since, 'background validation and rejected profiles preserve the active core session')
        client.sendall(b'queue-still-connected')
        check(upstream.recv(1024) == b'queue-still-connected', 'an established proxy tunnel survives all background subscription validations')
        upstream.sendall(b'queue-reply')
        check(client.recv(1024) == b'queue-reply', 'the active proxy tunnel still receives bytes after a rejected queued configuration')
        screenshot('subscription-queue-results-en')
        old = members(good)
        command('favorite', {'id': old[0]['id']})
        bodies['/ok'] = 'socks://alice:rotated@127.0.0.1:1081#Queued%20renamed\nsocks://alice:two@127.0.0.1:1082#Queued%20two'
        click('#subscription-update-all')
        wait_for('return document.querySelectorAll("[data-subscription-job]").length===8 && document.querySelectorAll("[data-job-status=queued],[data-job-status=downloading],[data-job-status=geodata],[data-job-status=checking]").length===0', timeout=30)
        second = jobs()[4:]
        check(second[0]['checked'] == second[0]['total'] == 1, 'queue checks changed configurations and skips an unchanged profile')
        updated = members(good)
        check(updated[0]['id'] == old[0]['id'] and updated[0]['favorite'] and command('profile', {'id': old[0]['id']})['config']['password'] == 'rotated', 'automatic credential rotation preserves profile IDs and favorites')
        click(f'[data-job-review="{warning}"]')
        check(js('return !!document.querySelector("#subscription-load")'), 'queue warning opens the existing manual review flow')
        close()
        time.sleep(.6)
        check(not js('return !!document.querySelector("dialog")'), 'viewed completion notices do not reopen the queue after manual review closes')
        clear_groups()

        partial = create('Queue · partly unreadable', '/partial')
        whole = create('Queue · whole configuration', '/config')
        open_queue()
        click('#subscription-update-all')
        wait_for('return document.querySelectorAll("[data-job-status=needs-review]").length===1 && document.querySelectorAll("[data-job-status=updated]").length===1', timeout=30)
        partial_job, config_job = jobs()[-2:]
        check(len(members(partial)) == 1 and partial_job['counts']['skipped'] == 1, 'one unreadable line no longer discards the servers that did parse')
        check(members(partial)[0]['name'] == 'Partial ok' and partial_job['status'] == 'needs-review', 'the imported server keeps its name and the group reports what was left out')
        check(sorted(p['name'] for p in members(whole)) == ['Split one', 'Split two'], 'a configuration answer becomes one profile per server outbound, without its selector and direct outbounds')
        check(config_job['status'] == 'updated' and config_job['counts']['added'] == 2, 'splitting a configuration reports plain added servers, not a review')
        screenshot('subscription-queue-partial-en')
        close()
        clear_groups()

        slow = create('Queue · slow subscription', '/slow')
        later = create('Queue · next subscription', '/ok')
        before_ok = calls['/ok']
        open_queue()
        click('#subscription-update-all')
        assert slow_started.wait(3), 'slow request was not received'
        stamp = time.monotonic()
        command('snapshot')
        check(time.monotonic() - stamp < 2, 'queued network download leaves native snapshots responsive')
        check(command('startSubscriptionUpdates')['queued'] == 0, 'repeated update-all does not duplicate active or waiting groups')
        close()
        check(any(j['status'] == 'downloading' for j in jobs()), 'closing the queue dialog keeps the background download running')
        click('#subscription-job-status')
        click('#subscription-cancel-jobs')
        wait_for('return document.querySelectorAll("[data-job-status=cancelled]").length===2')
        release.set()
        check(not members(slow) and not members(later) and calls['/ok'] == before_ok, 'cancel stops the current request and prevents the next group from downloading')
        check(all(j['status'] == 'cancelled' for j in jobs()), 'cancelled jobs cannot be completed by late worker responses')
        close()
        clear_groups()

        auto = create('Scheduled subscription', '/auto', 60)
        # No update button is pressed: the root worker picks up the native schedule.
        wait_for('return !!document.querySelector("#subscription-job-status")')
        click('#subscription-job-status')
        wait_for('return document.querySelectorAll("[data-job-status=updated]").length===1', timeout=20)
        auto_job = jobs()[0]
        check(auto_job['scheduled'] and len(members(auto)) == 1 and calls['/auto'] == 1, 'an enabled overdue schedule downloads and applies without a manual update')
        group = next(g for g in command('snapshot')['groups'] if g['id'] == auto)
        check(group['nextUpdateAt'] == group['lastUpdate']['at'] + 3600, 'next scheduled update is based on the persisted attempt time')
        close()
        request('POST', base + '/refresh', {})
        wait_for('return !!document.querySelector(".group-strip select")')
        check(calls['/auto'] == 1 and len(members(auto)) == 1, 'webview reload does not repeat an already completed scheduled update')
        click('.group-strip .icon-button')
        click(f'[data-group-edit="{auto}"]')
        wait_for('return !!document.querySelector("#group-auto-update")')
        check(js('return document.querySelector("#group-auto-update").checked && document.querySelector("#group-update-interval").value==="60"'), 'group editor restores the saved automatic-update interval')
        fill('#group-update-interval', '')
        check(js('return document.querySelector("#group-update-interval").value===""'), 'the interval field can be cleared before typing a new value')
        fill('#group-update-interval', '1')
        fill('#group-update-interval', '15')
        check(js('return document.querySelector("#group-update-interval").value==="15"'), 'retyping after clearing keeps exactly the typed interval')
        request('POST', base + '/window/rect', {'width': 390, 'height': 844})
        check(js('return document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth && document.querySelector(".modal-footer").getBoundingClientRect().bottom<=innerHeight'), 'scheduled-group editor fits a narrow native window')
        screenshot('subscription-schedule-narrow-en')
        click('#group-save')
        wait_for('return !!document.querySelector("#group-new")')
        check(command('group', {'id': auto})['subscription']['intervalMinutes'] == 15, 'editing an interval persists the new schedule')
        click('#subscription-open-jobs')
        check(js('return document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth && document.querySelector(".modal-footer").getBoundingClientRect().bottom<=innerHeight'), 'update queue keeps its action buttons visible at narrow width')
        screenshot('subscription-queue-narrow-en')
        close()
        request('POST', base + '/window/rect', {'width': 1280, 'height': 860})
        command('preferences', {**command('snapshot')['preferences'], 'language': 'ru'})
        wait_for('return document.documentElement.lang==="ru"')
        open_queue()
        check(js('return document.querySelector("#subscription-update-all").textContent.includes("Обновить все")'), 'update queue uses Russian labels')
        screenshot('subscription-queue-ru')
        close()
        clear_groups()
        command('disconnect')
        command('delete', {'id': active_profile})
        active_profile = None
        command('preferences', initial['preferences'])
        if initial['selected']:
            command('select', {'id': initial['selected']})
    finally:
        for stream in tunnel_sockets:
            stream.close()
        if active_profile:
            command('disconnect')
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
