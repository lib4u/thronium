"""Qt's tray toggles, restarts and hotkeys in the real app: private DBusMenu,
XTest global shortcuts, the connection mode chooser and a program restart.
Profiles are local `direct` outbounds; nothing leaves the machine."""
import os
import time
from pathlib import Path
from gi.repository import GLib
from native_menu import NativeMenu
from native_processes import core_pids
from tray_ui import wait


def press(*names):
    from Xlib import X, XK, display
    from Xlib.ext import xtest
    screen = display.Display()
    codes = [screen.keysym_to_keycode(XK.string_to_keysym(name)) for name in names]
    for code in codes:
        xtest.fake_input(screen, X.KeyPress, code)
    screen.sync()
    time.sleep(.05)
    for code in reversed(codes):
        xtest.fake_input(screen, X.KeyRelease, code)
    screen.sync()
    screen.close()


def run(h):
    command, check, js, wait_for = h['command'], h['check'], h['js'], h['wait_for']
    menu = NativeMenu()
    initial = command('snapshot')
    command('preferences', {**initial['preferences'], 'language': 'en'})
    labels = ['Start at login', 'Connect to the last server on startup', 'Allow connections from the local network',
              'Connection mode', 'Local proxy', 'System proxy', 'TUN', 'Restart connection', 'Restart Thronium']
    wait(lambda: all(menu.find(label) for label in labels), 'tray system items')
    order = [n[1].get('label') for n in menu.tree()[2] if n[1].get('type') != 'separator']
    check(order.index('Open Thronium') < order.index('Start at login') < order.index('Allow connections from the local network')
          < order.index('Connection mode') < order.index('Restart connection') < order.index('Restart Thronium') < order.index('Quit'),
          'the tray lists Qt\'s startup and LAN toggles, the connection mode and both restarts in Qt\'s order')
    menu.ready('Restart connection', enabled=False)
    menu.save(Path(h['args'].artifacts) / 'tray-system-menu.json')

    def settings(section):
        return command('settings')[section]

    def toggle(label, section, key, expected):
        menu.activate(menu.ready(label))
        wait(lambda: settings(section)[key] == expected and menu.checked(label) == (expected in (True, '::')), label)

    toggle('Connect to the last server on startup', 'system', 'remember_enable', True)
    toggle('Start at login', 'system', 'autostart', True)
    entries = list((Path(os.environ['XDG_CONFIG_HOME']) / 'autostart').glob('*.desktop'))
    check(len(entries) == 1 and 'Exec=' in entries[0].read_text(), 'start at login from the tray registers the desktop autostart entry')
    toggle('Start at login', 'system', 'autostart', False)
    check(not list((Path(os.environ['XDG_CONFIG_HOME']) / 'autostart').glob('*.desktop')), 'turning it off removes the autostart entry')
    toggle('Allow connections from the local network', 'inbound', 'inbound_address', '::')
    toggle('Allow connections from the local network', 'inbound', 'inbound_address', '127.0.0.1')
    check(True, 'LAN access and the last-server toggle change the same settings as the Settings page')

    snapshot = command('snapshot')
    other = 'tun' if snapshot['tunSupported'] else 'system-proxy'
    label = {'tun': 'TUN', 'system-proxy': 'System proxy'}[other]
    menu.activate(menu.ready(label))
    wait(lambda: command('snapshot')['preferences']['connectionMode'] == other and menu.checked(label) and not menu.checked('Local proxy'), 'tray mode')
    menu.activate(menu.ready('Local proxy'))
    wait(lambda: command('snapshot')['preferences']['connectionMode'] == 'local' and menu.checked('Local proxy'), 'tray local mode')
    check(True, 'the connection mode submenu switches between local proxy and ' + label)

    profile = command('saveProfile', {'name': 'Tray system direct', 'groupId': 'personal', 'kind': 'sing-box-outbound', 'config': {'type': 'direct'}})['id']
    pid = menu.pid

    def starts():
        return sum(entry.get('code') == 'connection_started' for entry in command('getLogs')['entries'])

    def restarted(before, condition=lambda: True):
        return wait(lambda: starts() > before and command('snapshot')['running'] == profile and command('snapshot')['phase'] == 'connected' and condition(), 'reconnected', timeout=25)

    command('connect', {'id': profile})
    wait(lambda: core_pids(pid) and command('snapshot')['phase'] == 'connected', 'connected')
    before = starts()
    menu.activate(menu.ready('Restart connection'))
    restarted(before)
    check(True, 'restart connection starts the same profile again')
    before = starts()
    menu.activate(menu.ready('Allow connections from the local network'))
    restarted(before, lambda: settings('inbound')['inbound_address'] == '::')
    check(True, 'allowing LAN while connected saves the listener and reconnects the same profile')
    before = starts()
    menu.activate(menu.ready('Allow connections from the local network'))
    restarted(before, lambda: settings('inbound')['inbound_address'] == '127.0.0.1')
    command('disconnect')

    system = settings('system')
    command('saveSettings', {'section': 'system', 'previous': system, 'values': {**system, 'hotkey_group': 'Ctrl+Alt+Shift+F9', 'hotkey_system_proxy_menu': 'Ctrl+Alt+Shift+F10'}})
    press('Control_L', 'Alt_L', 'Shift_L', 'F9')
    wait_for('return !!document.querySelector(".groups-modal")')
    check(True, 'the group hotkey opens group management, as in Qt')
    js('document.querySelector(".groups-modal .modal-head>button")?.click()')
    wait_for('return !document.querySelector("dialog[open]")')
    press('Control_L', 'Alt_L', 'Shift_L', 'F10')
    wait_for('return !!document.querySelector("#connection-mode") && document.querySelector("[data-settings-section=inbound]")?.getAttribute("aria-current")==="page"'
             ' && document.activeElement.closest("details")?.contains(document.querySelector("#connection-mode"))===true')
    check(True, 'the system proxy hotkey opens the connection mode chooser, whose modes the tray menu also offers')

    menu.activate(menu.ready('Restart Thronium'))
    wait(lambda: not Path('/proc', str(pid)).exists(), 'old process exit', timeout=20)
    h['closed_session'] = True
    restarted_menu = None
    for _ in range(3):
        try:
            restarted_menu = NativeMenu()
            break
        except AssertionError:
            continue
    assert restarted_menu, 'the restarted process did not publish its tray menu'
    check(restarted_menu.pid != pid and restarted_menu.ready('Restart Thronium') and restarted_menu.find('Tray system direct') is not None,
          'restart Thronium shuts down and starts a new process with the same library')
    try:
        restarted_menu.activate(restarted_menu.ready('Quit'))
    except GLib.Error:
        pass
    wait(lambda: not Path('/proc', str(restarted_menu.pid)).exists(), 'restarted process exit', timeout=20)
