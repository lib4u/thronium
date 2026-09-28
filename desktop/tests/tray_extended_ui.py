"""Grouped native actions and close-to-background with real loopback traffic."""
import http.client
import os
from pathlib import Path
import subprocess
import sys
import time
from gi.repository import GLib
from tray_ui import wait
from window_ui import primary
from native_processes import core_pids


def run(h, call, service, path, event, good, bad, port, server):
    command, check, click, select, fill, js, wait_for = (h[k] for k in ('command', 'check', 'click', 'select', 'fill', 'js', 'wait_for'))
    initial = command('snapshot')
    groups = []; added = []; host = None
    connection, window, pid = primary()
    from Xlib import X, protocol
    def tree(): return call(service, path, 'com.canonical.dbusmenu', 'GetLayout', '(iias)', (0, -1, []))[1]
    def walk(node):
        yield node
        for child in node[2]: yield from walk(child)
    def find(label, parent=None):
        return next((n for n in walk(parent or tree()) if n[1].get('label') == label), None)
    def ready(label): return wait(lambda: find(label), 'tray ' + label)
    def activate(node): call(service, path, 'com.canonical.dbusmenu', 'Event', '(isvu)', (node[0], 'clicked', GLib.Variant('s', ''), 0))
    def checked(label):
        rows = [n for n in walk(tree()) if n[1].get('label') == label]
        return bool(rows) and all(n[1].get('toggle-state') == 1 for n in rows)
    def traffic():
        client = http.client.HTTPConnection('127.0.0.1', port, timeout=4)
        client.request('GET', f'http://127.0.0.1:{server.server_port}/background')
        response = client.getresponse(); body = response.read(); client.close()
        return response.status == 200 and body == b'thronium-tray-loopback'
    def wm_close():
        # A native WM close also works while a web modal makes chrome inert.
        window.send_event(protocol.event.ClientMessage(window=window, client_type=connection.intern_atom('WM_PROTOCOLS'), data=(32, [connection.intern_atom('WM_DELETE_WINDOW'), X.CurrentTime, 0, 0, 0])), event_mask=0)
        connection.sync()
    def minimized():
        state = window.get_full_property(connection.intern_atom('_NET_WM_STATE'), X.AnyPropertyType)
        return state is not None and connection.intern_atom('_NET_WM_STATE_HIDDEN') in state.value
    def listed():
        clients = connection.screen().root.get_full_property(connection.intern_atom('_NET_CLIENT_LIST'), X.AnyPropertyType)
        return clients is not None and window.id in clients.value
    def reopen():
        result = subprocess.run([h['args'].application], env=os.environ.copy(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=12)
        assert result.returncode == 0
        wait(lambda: listed() and not minimized(), 'reopened background window')
    def dismiss_error():
        import pyatspi
        def dialog():
            for app in pyatspi.Registry.getDesktop(0):
                if app.get_process_id() == pid:
                    return pyatspi.findDescendant(app, lambda n: n.getRole() in (pyatspi.ROLE_DIALOG, pyatspi.ROLE_ALERT) and n.name == 'Thronium')
        d = wait(dialog, 'native connection error')
        pyatspi.findDescendant(d, lambda n: n.getRole() == pyatspi.ROLE_PUSH_BUTTON and n.name in ('OK', 'Ok')).queryAction().doAction(0)
    try:
        check(initial['preferences']['closeBehavior'] == 'quit', 'legacy default keeps Close as a full quit until the user changes it')
        group = command('saveGroup', {'name': 'Tray group', 'subscription': None})['id']; groups.append(group)
        empty = command('saveGroup', {'name': 'Tray empty', 'subscription': None})['id']; groups.append(empty)
        drafts = [{'name': f'Tray paged {i:02}', 'groupId': group, 'kind': 'sing-box-outbound', 'config': {'type': 'direct'}} for i in range(51)]
        profiles = command('importProfiles', {'profiles': drafts})['ids']; added.extend(profiles)
        command('favorite', {'id': profiles[50]})
        command('collapseGroup', {'id': group, 'collapsed': True})
        ready('Tray group (51)'); ready('Tray empty (0)'); ready('Favorites')
        page = find('Tray group (51)')
        check([n[1]['label'] for n in page[2]] == ['1–50', '51–51'] and len([n for n in walk(page) if n[1].get('toggle-type')]) == 51, 'large and collapsed library groups expose every server in paged native submenus')
        check(find('No servers', find('Tray empty (0)'))[1].get('enabled') is False and find('Tray paged 50', find('Favorites')) is not None, 'empty groups are explicit and Favorites offers a second route to its servers')
        activate(find('Tray paged 50', find('Favorites')))
        wait(lambda: command('snapshot')['running'] == profiles[50], 'favorite switch')
        wait(lambda: checked('Tray paged 50'), 'active favorite checks')
        check(traffic() and command('snapshot')['selected'] == profiles[50], 'clicking a favorite switches the real connection and checks both copies of its menu item')
        since = command('snapshot')['since']; cores = core_pids(pid)
        activate(find('Tray paged 50', find('Favorites')))
        time.sleep(1.3)
        check(command('snapshot')['since'] == since and core_pids(pid) == cores and checked('Tray paged 50'), 'clicking the active server does not restart it or lose the checked marker')
        activate(ready('Tray invalid')); dismiss_error()
        wait(lambda: checked('Tray paged 50') and not checked('Tray invalid'), 'valid marker after error')
        check(command('snapshot')['running'] == profiles[50] and traffic() and not checked('Tray invalid'), 'invalid tray switches preserve the working VPN and restore check marks after failure')
        stale = ready('Tray paged 00')
        command('delete', {'id': profiles[0]}); added.remove(profiles[0])
        ready('Tray group (50)')
        try: activate(stale)
        except GLib.Error as error:
            if 'does not refer to a menu item' not in str(error): raise
        time.sleep(.2)
        check(command('snapshot')['running'] == profiles[50] and find('Tray paged 00') is None, 'a stale native event after profile deletion cannot connect another server')
        command('saveGroup', {'id': group, 'name': 'Tray renamed', 'subscription': None})
        command('moveProfiles', {'ids': [profiles[1]], 'groupId': empty})
        command('favorite', {'id': profiles[50]})
        ready('Tray renamed (49)'); ready('Tray empty (1)')
        check(find('Tray paged 01', find('Tray empty (1)')) is not None and (find('Favorites') is None or find('Tray paged 50', find('Favorites')) is None), 'group rename, profile moves and favorite removal refresh the native menu')
        command('preferences', {**command('snapshot')['preferences'], 'language': 'ru'})
        ready('Подключиться к серверу'); ready('Личные (2)' if len(initial['profiles']) == 2 else 'Личные (' + str(sum(p['groupId'] == 'personal' for p in initial['profiles'])) + ')')
        check(find('Отключить') is not None, 'server submenus and Personal group follow the current Russian language')
        command('preferences', {**command('snapshot')['preferences'], 'language': 'en'})
        ready('Open Thronium')
        # Settings mutate only the close field even when other preferences change.
        click('.primary-nav button:nth-child(5)'); click('[data-settings-section=system]'); wait_for('return !!document.querySelector("#close-behavior")')
        select('#close-behavior', 'background')
        prefs = command('snapshot')['preferences']; command('preferences', {**prefs, 'theme': 'dark'})
        click('#settings-save'); wait(lambda: command('snapshot')['preferences']['closeBehavior'] == 'background', 'saved background mode')
        check(command('snapshot')['preferences']['theme'] == 'dark', 'Window settings save independently and preserve concurrently changed preferences')
        h['screenshot']('tray-settings-dark-en')
        h['request']('POST', h['base'] + '/refresh', {}); wait_for('return !!document.querySelector(".add-connection")')
        check(command('snapshot')['preferences']['closeBehavior'] == 'background', 'close behavior persists through webview reload')
        # Test system-proxy lifetime as well as the core listener in background.
        command('disconnect'); command('connectionSettings', {'mode': 'system-proxy', 'port': port}); command('connect', {'id': good})
        wait(lambda: checked('Tray direct 🦊'), 'active original server')
        since = command('snapshot')['since']; cores = core_pids(pid)
        click('[data-window-action=close]')
        if command('windowBehavior')['trayAvailable']: wait(lambda: not listed(), 'hidden window')
        else: wait(lambda: listed() and minimized(), 'taskbar fallback')
        check(core_pids(pid) == cores and command('snapshot')['since'] == since and command('snapshot')['systemProxy']['active'] and traffic(), 'Close preserves the same core, live traffic and system proxy while making the window nonvisible')
        reopen()
        check(command('snapshot')['running'] == good and core_pids(pid) == cores, 'launching Thronium again restores the background window without reconnecting')
        click('.add-connection'); click('#add-choice-advanced'); fill('#profile-name', 'Background unsaved draft')
        wm_close(); wait(lambda: minimized() or not listed(), 'native close with editor')
        event('Open Thronium'); wait(lambda: listed() and not minimized(), 'tray restores editor')
        check(js('return document.querySelector("#profile-name").value') == 'Background unsaved draft', 'native Close and tray Open preserve the unsaved editor and modal layer')
        click('#main-modal > .modal-head .icon-button'); click('[data-confirm-accept]'); wait_for('return !document.querySelector("#main-modal")')
        if os.environ.get('_THRONIUM_TEST_BUS'):
            check(not command('windowBehavior')['trayAvailable'], 'private desktop without a tray host uses the reachable taskbar fallback')
            host = subprocess.Popen([sys.executable, str(Path(__file__).with_name('tray_host_fixture.py'))], env=os.environ.copy(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            assert host.stdout.readline().strip() == 'READY'
            wait(lambda: command('windowBehavior')['trayAvailable'], 'tray host registration')
            click('[data-window-action=close]'); wait(lambda: not listed(), 'close hides in registered tray')
            check(traffic() and core_pids(pid) == cores, 'a registered tray host enables true hide-to-tray without stopping VPN')
            event('Open Thronium'); wait(lambda: listed() and not minimized(), 'show hidden window')
            check(command('snapshot')['since'] == since, 'Open from the native tray restores a hidden window and keeps the session')
            click('[data-window-action=close]'); wait(lambda: not listed(), 'hide before host loss')
            host.terminate(); host.wait(timeout=5); host = None
            wait(lambda: listed() and minimized(), 'host loss restores taskbar access')
            check(not command('windowBehavior')['trayAvailable'] and traffic(), 'losing the tray host returns the hidden window to the taskbar and preserves traffic')
            reopen()
        command('preferences', {**command('snapshot')['preferences'], 'language': 'ru'})
        click('.primary-nav button:nth-child(5)'); click('[data-settings-section=system]'); wait_for('return document.documentElement.lang==="ru" && !!document.querySelector("#close-behavior")')
        h['request']('POST', h['base'] + '/window/rect', {'width': 390, 'height': 760})
        h['screenshot']('tray-settings-narrow-ru')
        check(js('const p=document.querySelector("#settings-form");return p.textContent.includes("Оставлять в трее") && p.scrollWidth<=p.clientWidth+1'), 'Russian background settings fit a narrow window')
    finally:
        if host: host.terminate(); host.wait(timeout=5)
        if not listed() or minimized(): reopen()
        connection.close()
        command('disconnect'); command('connectionSettings', {'mode': initial['preferences']['connectionMode'], 'port': port})
        for profile in added: command('delete', {'id': profile})
        for group in groups: command('deleteGroup', {'id': group, 'deleteProfiles': True})
        command('preferences', initial['preferences'])
        command('connect', {'id': good})
        h['request']('POST', h['base'] + '/window/rect', {'width': 1280, 'height': 860})
        click('.primary-nav button:first-child')
