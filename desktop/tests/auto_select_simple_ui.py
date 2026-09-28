"""Simple auto-select UX and real forwarding through source-scoped owned proxies."""
import http.server
import json
import socket
import subprocess
import tempfile
import threading
import time

from selector_ranking_fixture import Fixture


def run(h):
    command, click, fill, select, wait_for, js, check, screenshot = (
        h[k] for k in ('command', 'click', 'fill', 'select', 'wait_for', 'js', 'check', 'screenshot'))
    initial = command('snapshot')
    groups = []
    evidence = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_HEAD(self):
            self.send_response(204); self.send_header('Content-Length', '0'); self.end_headers()
        def do_GET(self):
            body = b'owned-auto-select-traffic'
            self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers()
            self.wfile.write(body)

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    directory = tempfile.TemporaryDirectory(prefix='thronium-simple-select-')
    fixture = Fixture(directory.name)
    for peer in fixture.peers:
        peer.ports.append(server.server_port)
    origin = f'http://127.0.0.1:{server.server_port}'

    def mode(index, value):
        peer = fixture.peers[index]
        with peer.lock: peer.state['downloadMode'] = value

    def add_group(name, subscription=None):
        gid = command('saveGroup', {'name': name, 'subscription': subscription})['id']
        groups.append(gid)
        return gid

    def add(gid, name, peer):
        return command('saveProfile', {'name': name, 'groupId': gid, 'kind': 'sing-box-outbound',
                       'config': {'type': 'socks', 'server': '127.0.0.1', 'server_port': fixture.info['ports'][peer]}})['id']

    def prefs(): return command('snapshot')['preferences']['autoSelect']
    def configure():
        click('#auto-select-configure')
        wait_for('return document.activeElement?.id==="auto-select-source"')
    def save():
        click('#auto-select-save')
        wait_for('return !document.querySelector("#auto-select-save")')
    def configure_until(script, timeout=10):
        # The UI polls its snapshot once a second and a dialog keeps the values it opened with.
        deadline = time.monotonic() + timeout
        while True:
            configure()
            if js(script): return True
            click('#auto-select-cancel')
            wait_for('return !document.querySelector("#auto-select-save")')
            if time.monotonic() > deadline: return False
            time.sleep(.3)
    def pool(count):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            states = command('getAutoSelectors')
            if states and len(states[0]['members']) == count and states[0]['selected']:
                return states[0]
            time.sleep(.15)
        raise AssertionError(f'Expected a running pool with {count} members: {states}')
    def chosen(state): return next(m['profileId'] for m in state['members'] if m['tag'] == state['selected'])
    def batch_ids(): return {e['profileId'] for e in command('snapshot')['urlTests']['entries']}
    def traffic(port):
        result = subprocess.run(['curl', '--silent', '--show-error', '--fail', '--max-time', '5',
                                 '--noproxy', '', '--proxy', f'http://127.0.0.1:{port}', origin + '/traffic'],
                                capture_output=True, timeout=8)
        check(result.returncode == 0 and result.stdout == b'owned-auto-select-traffic',
              'the current auto-select pool forwards real HTTP through the owned proxy')

    try:
        command('disconnect')
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0)); port = listener.getsockname()[1]
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark', 'inboundPort': port,
                'autoSelect': {**initial['preferences']['autoSelect'], 'enabled': True, 'failover': True, 'sourceGroupId': None}})
        wait_for('return document.documentElement.lang==="en" && !!document.querySelector("#auto-select-card")')
        check(command('snapshot')['autoSelectMemberCount'] == 0
              and js('return document.querySelector("[data-auto-select]").disabled && !document.querySelector("#auto-select-configure").disabled'),
              'an empty library keeps the disabled card and its working settings entry')
        configure()
        check(js('return !document.querySelector("#auto-select-advanced").open && !!document.querySelector(".auto-select-info")'),
              'the dialog focuses the source, keeps advanced settings collapsed and always explains reconnect behavior')
        click('#auto-select-cancel')
        outside = add_group('Other servers')
        source = add_group('Owned subscription', {'url': origin + '/subscription', 'headers': {}, 'viaProxy': False, 'intervalMinutes': 0})
        a, b = add(source, 'Fast owned server', 0), add(source, 'Reserve owned server', 1)
        add(outside, 'Outside source', 0)
        command('saveProfile', {'name': 'Excluded direct', 'groupId': source, 'kind': 'sing-box-outbound', 'config': {'type': 'direct'}})
        wait_for('return document.querySelector(".auto-select-count").textContent.includes("3 servers")')
        check(command('snapshot')['autoSelectMemberCount'] == 3 and js('return document.querySelector(".auto-select-badge").textContent==="Recommended"'),
              'the card counts eligible servers across groups and shows the recommendation badge')
        configure()
        options = js('return [...document.querySelector("#auto-select-source").options].map(o=>({id:o.value,name:o.textContent}))')
        check(options[0]['id'] == '' and options[1] == {'id': source, 'name': 'Owned subscription'}
              and any(o['id'] == outside for o in options), 'sources show All groups and display names with subscriptions first')
        select('#auto-select-source', source)
        select('#auto-select-reuse_ttl', '30m'); select('#auto-select-interval', '5m')
        click('#auto-select-advanced > summary')
        fill('#auto-select-url', origin + '/health'); fill('#auto-select-connectivity_url', origin + '/connectivity')
        fill('#auto-select-timeout', '2s'); fill('#auto-select-concurrency', '2')
        check(js('return document.querySelectorAll("#auto-select-interval").length===1 && document.querySelectorAll("#auto-select-reuse_ttl").length===1 && document.querySelector("#auto-select-advanced").contains(document.querySelector("#auto-select-reset"))'),
              'advanced settings contain health, balancing and reset without duplicate basic controls')
        save()
        check(prefs()['sourceGroupId'] == source and prefs()['config']['interval'] == '5m' and prefs()['config']['reuse_ttl'] == '30m',
              'the source and duration presets save together')
        wait_for('return document.querySelector(".auto-select-count").textContent.includes("2 servers") && !document.querySelector("[data-auto-select]").disabled')
        fill('#client-search', 'no matching server')
        check(js('return !!document.querySelector("#auto-select-card")'), 'library search does not hide or restrict the global auto-select card')
        fill('#client-search', '')
        click('[data-auto-select]')
        screenshot('auto-select-card')
        configure(); screenshot('auto-select-config')
        click('#auto-select-advanced > summary')
        wait_for('return document.querySelector("#auto-select-advanced").open')
        js('document.querySelector("#auto-select-advanced > summary").scrollIntoView({block:"start"})'); time.sleep(.3)
        screenshot('auto-select-config-advanced'); click('#auto-select-cancel')
        mode(1, 'slow')
        click('.power-button')
        state = pool(2)
        evidence['failoverOn'] = {'pool': state, 'batch': command('snapshot')['urlTests']}
        check(batch_ids() == {a, b} and {m['profileId'] for m in state['members']} == {a, b},
              'connecting measures exactly the two source candidates and starts a two-member Core pool')
        traffic(port)
        configure(); click('#auto-select-failover')
        check(js('return document.querySelector("#auto-select-interval").disabled && document.querySelector("#auto-select-interval").value==="5m"'),
              'disabling failover disables the interval while preserving its saved value')
        save()
        wait_for('return !!document.querySelector("#auto-select-reconnect-notice") && document.querySelector(".auto-select-text small").textContent.includes("when you connect")')
        check(len(pool(2)['members']) == 2 and command('snapshot')['running'] == 'auto-select',
              'changing failover defers the pool change until reconnect and updates the card hint')
        command('disconnect'); command('connect', {'id': 'auto-select'})
        state = pool(1)
        evidence['failoverOff'] = {'pool': state, 'batch': command('snapshot')['urlTests']}
        check(batch_ids() == {a, b} and chosen(state) == a and command('snapshot')['autoSelectMemberCount'] == 2,
              'failover off still measures both candidates but runs only the best member while counting both')
        traffic(port)
        command('disconnect'); command('connect', {'id': 'auto-select'})
        check(batch_ids() == {a} and chosen(pool(1)) == a,
              'a reconnect within TTL rechecks the remembered server and retains the one-member pool')
        command('disconnect'); mode(0, 'http-error')
        command('connect', {'id': 'auto-select'})
        check(batch_ids() == {a, b} and chosen(pool(1)) == b,
              'a failed remembered server triggers a full source sweep and selects the reachable replacement')
        traffic(port)
        command('disconnect'); mode(0, 'ok'); mode(1, 'ok')

        before = prefs()['config']
        custom = {**before, 'interval': '47s', 'reuse_ttl': '17m'}
        command('saveAutoSelectSettings', {'previous': before, 'config': custom})
        custom_shown = ('return document.querySelector("#auto-select-interval").selectedOptions[0].textContent.includes("Other: 47s")'
                        ' && document.querySelector("#auto-select-reuse_ttl").selectedOptions[0].textContent.includes("Other: 17m")')
        check(configure_until(custom_shown),
              'custom saved durations appear as Other options even when failover is disabled')
        current = command('snapshot')['preferences']
        command('preferences', {**current, 'librarySortDescending': not current['librarySortDescending']})
        save()
        check(prefs()['config'] == custom and command('snapshot')['preferences']['librarySortDescending'] != current['librarySortDescending'],
              'saving preserves custom durations and an unrelated preference changed while the dialog was open')
        configure()
        command('saveAutoSelectSettings', {'previous': custom, 'config': custom, 'failover': True})
        click('#auto-select-save')
        wait_for('return !!document.querySelector("#auto-select-config-error")')
        check(prefs()['failover'], 'a stale modal cannot overwrite a newer failover choice even with unchanged config')
        click('#auto-select-cancel')
        rejected = False
        try:
            command('saveAutoSelectSettings', {'previous': custom, 'config': custom, 'sourceGroupId': 'missing-native-source'})
        except RuntimeError as error:
            rejected = 'auto_select_source_missing' in str(error)
        check(rejected and prefs()['sourceGroupId'] == source, 'IPC rejects an unknown source without losing the saved selection')
        configure(); click('#auto-select-advanced > summary'); click('#auto-select-reset')
        check(js('return document.querySelector("#auto-select-source").value==="" && document.querySelector("#auto-select-failover").checked && document.querySelector("#auto-select-interval").value==="120s" && document.querySelector("#auto-select-reuse_ttl").value==="30m"'),
              'reset restores the source, failover and all duration defaults in the draft')
        click('#auto-select-cancel')
        check(prefs()['sourceGroupId'] == source and prefs()['config'] == custom, 'Cancel discards the reset draft')
        command('delete', {'id': b})
        wait_for('return document.querySelector("[data-auto-select]").disabled && !!document.querySelector("#auto-select-unavailable")')
        check(command('snapshot')['autoSelectMemberCount'] == 1 and not command('snapshot')['autoSelectAvailable'],
              'one eligible source member disables selection and explains the two-server minimum')
        configure(); click('#auto-select-cancel')
        command('preferences', {**command('snapshot')['preferences'], 'language': 'ru', 'theme': 'light'})
        wait_for('return document.documentElement.lang==="ru"')
        h['request']('POST', h['base'] + '/window/rect', {'width': 390, 'height': 844})
        js('document.querySelector("#auto-select-card").scrollIntoView()')
        check(js('return document.documentElement.scrollWidth<=innerWidth && document.querySelector(".auto-select-count").textContent.includes("1 сервер")'),
              'the disabled Russian card fits a narrow window and uses singular server wording')
        screenshot('auto-select-card-narrow-ru')
        configure()
        check(js('return document.documentElement.scrollWidth<=innerWidth && document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth'),
              'the Russian configurator fits a narrow window')
        screenshot('auto-select-config-narrow-ru'); click('#auto-select-cancel')
        command('deleteGroup', {'id': source, 'deleteProfiles': False}); groups.remove(source)
        check(prefs()['sourceGroupId'] is None and command('snapshot')['autoSelectMemberCount'] == 2,
              'deleting the source group moves its profiles and resets auto-select to all groups')
        # Moved source profiles now belong to personal; remove only owned fixtures.
        for row in command('snapshot')['profiles']:
            if row['id'] not in {p['id'] for p in initial['profiles']} and row['groupId'] == 'personal':
                command('delete', {'id': row['id']})
        (h['artifacts'] / 'mechanics.json').write_text(json.dumps(evidence, indent=2) + '\n')
    finally:
        command('disconnect')
        for gid in groups: command('deleteGroup', {'id': gid, 'deleteProfiles': True})
        command('preferences', initial['preferences'])
        if initial['selected']: command('select', {'id': initial['selected']})
        h['request']('POST', h['base'] + '/window/rect', {'width': 1280, 'height': 860})
        server.shutdown(); server.server_close(); fixture.close(); directory.cleanup()
