"""Exercise frameless window geometry and actual window-manager actions on X11."""
import os
import pathlib
import socket
import subprocess
import time
from native_screenshot import connect
from native_processes import core_pids
from tray_ui import wait


def primary():
    # Window titles may contain a localized connection status. Identify the main
    # window by its disposable process scope and lack of a transient parent.
    from Xlib import X
    connection = connect()
    root = connection.screen().root
    clients = root.get_full_property(connection.intern_atom('_NET_CLIENT_LIST'), X.AnyPropertyType)
    found = []
    for wid in clients.value:
        window = connection.create_resource_object('window', int(wid))
        owner = window.get_full_property(connection.intern_atom('_NET_WM_PID'), X.AnyPropertyType)
        if owner is None: continue
        pid = int(owner.value[0]); proc = pathlib.Path('/proc', str(pid))
        try:
            scope = os.environ['XDG_DATA_HOME']
            if 'thronium-native-test-' not in scope: raise AssertionError('Disposable data directory is required')
            if proc.joinpath('comm').read_text().strip() == 'Thronium' and b'XDG_DATA_HOME=' + scope.encode() in proc.joinpath('environ').read_bytes().split(b'\0') and window.get_wm_transient_for() is None: found.append((window, pid))
        except OSError: pass
    if len(found) != 1: connection.close(); raise AssertionError('Expected one disposable native window')
    return connection, *found[0]


def run(h):
    from Xlib import X, protocol
    command, js, check, click, request = (h[k] for k in ('command', 'js', 'check', 'click', 'request'))
    initial = command('snapshot')['preferences']
    geometry = request('GET', h['base'] + '/window/rect')
    connection, window, pid = primary()
    root = connection.screen().root
    def state(name):
        prop = window.get_full_property(connection.intern_atom('_NET_WM_STATE'), X.AnyPropertyType)
        return prop is not None and connection.intern_atom(name) in prop.value
    maximized = lambda: state('_NET_WM_STATE_MAXIMIZED_VERT') and state('_NET_WM_STATE_MAXIMIZED_HORZ')
    def resize(width, height=800):
        request('POST', h['base'] + '/window/rect', {'width': width, 'height': height})
        h['wait_for']('return innerWidth === ' + str(width))
    def fills():
        return js('const r=document.querySelector(".app-shell").getBoundingClientRect();return r.x===0&&r.y===0&&r.width===innerWidth&&r.height>=innerHeight&&getComputedStyle(document.querySelector(".app-shell")).borderRadius==="0px"&&document.documentElement.scrollWidth===innerWidth;')
    try:
        hints = window.get_full_property(connection.intern_atom('_MOTIF_WM_HINTS'), X.AnyPropertyType)
        check(hints is not None and hints.value[0] & 2 and hints.value[2] == 0, 'the native window disables the system titlebar and decorations')
        for language in ('ru', 'en'):
            command('preferences', {**initial, 'language': language})
            for width in (390, 800, 1100, 1280):
                resize(width)
                check(fills() and js('return [...document.querySelectorAll(".window-button,.topbar-actions button,.primary-nav button")].every(e=>{const r=e.getBoundingClientRect();return r.x>=0&&r.right<=innerWidth&&r.width>=20&&r.height>=20;})'), f'{language} at {width}px fills the window without an outer card or clipped header controls')
            h['screenshot']('window-' + language)
        command('preferences', {**initial, 'theme': 'dark', 'language': 'ru'})
        h['wait_for']('return document.documentElement.dataset.theme==="dark"')
        h['screenshot']('window-dark-ru')
        check(fills(), 'dark appearance uses the same continuous window surface')
        resize(1000, 760)
        click('[data-window-action="maximize"]'); wait(maximized, 'native maximized state')
        h['wait_for']('return document.querySelector("[data-window-action=maximize]").getAttribute("aria-label")==="Восстановить окно"')
        check(js('return !document.querySelector(".window-resize")') and fills(), 'Maximize fills the work area, shows Restore and removes inactive resize edges')
        click('[data-window-action="maximize"]'); wait(lambda: not maximized(), 'restored native size')
        h['wait_for']('return innerWidth===1000')
        check(js('return document.querySelectorAll(".window-resize").length===8'), 'Restore returns to the previous width and enables all eight native resize directions')
        js('document.querySelector(".topbar").dispatchEvent(new MouseEvent("mousedown",{bubbles:true,button:0,detail:2}))')
        wait(maximized, 'double-click maximize')
        js('document.querySelector(".topbar").dispatchEvent(new MouseEvent("mousedown",{bubbles:true,button:0,detail:2}))')
        wait(lambda: not maximized(), 'double-click restore')
        h['wait_for']('return innerWidth===1000')
        check(True, 'double-clicking the header toggles the real native window state')
        click('.primary-nav button:nth-child(5)')
        check(not maximized(), 'navigation controls remain clickable inside the draggable header')
        click('.primary-nav button:first-child')
        click('[data-window-action="minimize"]'); wait(lambda: state('_NET_WM_STATE_HIDDEN'), 'custom minimize button')
        result = subprocess.run([h['args'].application], env=os.environ.copy(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=12)
        if result.returncode: raise AssertionError('Reopen did not exit successfully')
        wait(lambda: not state('_NET_WM_STATE_HIDDEN'), 'reopen custom-minimized window')
        check(command('snapshot')['running'] is None, 'Minimize hides the native window and reopening restores it without connecting')
    finally:
        if state('_NET_WM_STATE_HIDDEN'):
            root.send_event(protocol.event.ClientMessage(window=window, client_type=connection.intern_atom('_NET_ACTIVE_WINDOW'), data=(32, [2, X.CurrentTime, 0, 0, 0])), event_mask=X.SubstructureRedirectMask | X.SubstructureNotifyMask)
            connection.sync()
        # A right click belongs to this window, not to the web engine: its page
        # menu (back, reload, inspector) never opens, while a text field keeps
        # the menu that edits it.
        from profile_order_input import OwnedInput
        pointer = OwnedInput(h)

        def popups():
            found = []
            for child in root.query_tree().children:
                attributes = child.get_attributes()
                if attributes.override_redirect and attributes.map_state == X.IsViewable:
                    found.append(child.id)
            return found

        before = popups()
        pointer.secondary_click('.workspace')
        # A menu that was going to open has had its chance by now.
        time.sleep(1)
        check(popups() == before, 'the page menu of the web engine never opens on a right click')
        pointer.secondary_click('#client-search')
        opened = wait(lambda: len(popups()) > len(before) or None, 'the editing menu of a text field', timeout=5)
        check(bool(opened), 'a text field keeps the menu that edits it')
        pointer.key('Escape')
        wait(lambda: popups() == before, 'the editing menu closes again', timeout=5)
        if maximized(): click('[data-window-action="maximize"]'); wait(lambda: not maximized(), 'cleanup restore')
        connection.close()
        command('preferences', initial)
        request('POST', h['base'] + '/window/rect', geometry)


def close(h, port):
    connection, _window, pid = primary()
    connection.close()
    cores = core_pids(pid)
    if not cores: raise AssertionError('Close cleanup requires a running core')
    # Let WebDriver acknowledge scheduling before the webview is destroyed.
    h['js']('setTimeout(()=>document.querySelector("[data-window-action=close]").click(),150)')
    wait(lambda: not pathlib.Path('/proc', str(pid)).exists(), 'custom window close', timeout=15)
    h['closed_session'] = True
    with socket.socket() as listener: closed = listener.connect_ex(('127.0.0.1', port)) != 0
    h['check'](closed and all(not pathlib.Path('/proc', p).exists() for p in cores), 'the custom Close button completes shutdown with no owned core or listening proxy')
