"""Launch actual secondary processes; only the runner's disposable data is used."""
import hashlib
import http.client
import fcntl
import json
import os
import pathlib
import socket
import subprocess
import tempfile
import time
from gi.repository import Gio, GLib
from native_screenshot import connect
from tray_ui import wait


def run(h):
    command, check = h['command'], h['check']
    data = pathlib.Path(os.environ['XDG_DATA_HOME'])
    if 'thronium-native-test-' not in str(data): raise AssertionError('Instance tests require the isolated runner')
    binary = pathlib.Path(h['args'].application)
    library = data / 'io.thronium.desktop/library.json'
    def candidates():
        found = []
        for p in pathlib.Path('/proc').iterdir():
            if not p.name.isdigit(): continue
            try:
                if p.joinpath('comm').read_text().strip() == 'Thronium' and b'XDG_DATA_HOME=' + str(data).encode() in p.joinpath('environ').read_bytes().split(b'\0'): found.append(int(p.name))
            except OSError: pass
        return found
    pids = candidates()
    if len(pids) != 1: raise AssertionError('Expected one primary disposable application')
    pid = pids[0]
    from native_processes import core_pids as owned_core_pids
    def core_pids(): return owned_core_pids(pid)
    initial = command('snapshot'); profile = None
    command('disconnect')
    with socket.socket() as s: s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]
    command('preferences', {**initial['preferences'], 'inboundPort': port})
    opened = []
    connection = connect()
    from Xlib import X, Xutil, protocol
    root = connection.screen().root
    clients = root.get_full_property(connection.intern_atom('_NET_CLIENT_LIST'), X.AnyPropertyType)
    windows = []
    for wid in clients.value:
        window = connection.create_resource_object('window', int(wid))
        owner = window.get_full_property(connection.intern_atom('_NET_WM_PID'), X.AnyPropertyType)
        if owner is not None and int(owner.value[0]) == pid and window.get_wm_transient_for() is None: windows.append(window)
    if len(windows) != 1: raise AssertionError('Expected one primary native window')
    window = windows[0]
    def minimized():
        state = window.get_full_property(connection.intern_atom('_NET_WM_STATE'), X.AnyPropertyType)
        return state is not None and connection.intern_atom('_NET_WM_STATE_HIDDEN') in state.value
    def minimize():
        root.send_event(protocol.event.ClientMessage(window=window, client_type=connection.intern_atom('WM_CHANGE_STATE'), data=(32, [Xutil.IconicState, 0, 0, 0, 0])), event_mask=X.SubstructureRedirectMask | X.SubstructureNotifyMask)
        connection.sync(); wait(minimized, 'primary window minimized')
    def launch(executable=binary, env=None, cwd=None, args=()):
        p = subprocess.Popen([str(executable), *args], env=env or os.environ.copy(), cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        opened.append(p); return p
    def exits(p):
        stdout, stderr = p.communicate(timeout=12)
        if p.returncode != 0: raise AssertionError('Secondary instance did not exit successfully')
        if b'private-reopen-secret' in stdout + stderr: raise AssertionError('Command-line data appeared in secondary output')
    def unchanged(before, since, cores):
        snapshot = command('snapshot')
        return library.read_bytes() == before and snapshot['running'] == profile and snapshot['since'] == since and core_pids() == cores
    try:
        profile = command('saveProfile', {'name': 'Instance direct', 'groupId': 'personal', 'kind': 'sing-box-outbound', 'config': {'type': 'direct'}})['id']
        # Discard actual successful replies, then verify recovery never repeats a toggle.
        original_raw = h['raw_request']
        lost = False
        dropped_reads = 0
        def drop_reply(method, path, payload=None):
            nonlocal lost, dropped_reads
            if lost and dropped_reads < 4 and path.endswith('/execute/sync') and '?.receipts[' in payload['script']:
                dropped_reads += 1
                raise http.client.RemoteDisconnected('simulated unavailable receipt')
            result = original_raw(method, path, payload)
            if not lost and path.endswith('/execute/async'):
                lost = True
                raise http.client.RemoteDisconnected('simulated lost reply')
            return result
        h['raw_request'] = drop_reply
        try: command('favorite', {'id': profile})
        finally: h['raw_request'] = original_raw
        check(next(p for p in command('snapshot')['profiles'] if p['id'] == profile)['favorite'], 'a lost native-command reply is recovered without replaying the favorite mutation')
        lost = False
        def drop_before_send(method, path, payload=None):
            nonlocal lost
            if not lost and path.endswith('/execute/async'):
                lost = True
                raise http.client.RemoteDisconnected('simulated lost request')
            return original_raw(method, path, payload)
        h['raw_request'] = drop_before_send
        try: command('favorite', {'id': profile})
        finally: h['raw_request'] = original_raw
        check(not next(p for p in command('snapshot')['profiles'] if p['id'] == profile)['favorite'], 'a request lost before dispatch is safely resubmitted under the same operation ticket')
        command('favorite', {'id': profile})
        command('select', {'id': profile})
        h['select']('.group-strip select', 'all'); h['fill']('#client-search', ''); h['click']('.library-tabs button:first-child')
        favorite_selector = '.favorite-button[aria-label$=": Instance direct"]'
        h['wait_for']('return document.querySelector(' + json.dumps(favorite_selector) + ')?.getAttribute("aria-pressed")==="true"')
        lost = False
        def drop_click_reply(method, path, payload=None):
            nonlocal lost
            result = original_raw(method, path, payload)
            if not lost and path.endswith('/execute/sync') and 'document.querySelector(arguments[0]).click()' in payload['script']:
                lost = True
                raise http.client.RemoteDisconnected('simulated lost reply')
            return result
        h['raw_request'] = drop_click_reply
        try: h['click'](favorite_selector)
        finally: h['raw_request'] = original_raw
        h['wait_for']('return document.querySelector(' + json.dumps(favorite_selector) + ')?.getAttribute("aria-pressed")==="false"')
        check(not next(p for p in command('snapshot')['profiles'] if p['id'] == profile)['favorite'], 'a lost DOM-click reply is recovered without dispatching a second click')
        command('connect', {'id': profile}); before = library.read_bytes(); since = command('snapshot')['since']; cores = core_pids()
        if len(cores) != 1: raise AssertionError('The connected instance must own exactly one core')
        minimize()
        with tempfile.TemporaryDirectory(prefix='thronium-instance-test-') as tmp:
            folder = pathlib.Path(tmp)
            p = launch(cwd=folder, args=('--from-test', 'https://example.invalid/private-reopen-secret')); exits(p)
            check(candidates() == [pid], 'a second launch exits successfully while the original app keeps its process and sole library ownership')
            wait(lambda: not minimized(), 'original window restored by second launch')
            check(True, 'a second launch restores the minimized original window from a different working directory')
            check(unchanged(before, since, cores), 'reopening preserves the running VPN, its core PID, session start and exact library bytes')
            check(len(command('snapshot')['profiles']) == len(initial['profiles']) + 1, 'command-line URLs do not import profiles or alter the library when reopening')
            alias = folder / 'Thronium-alias'; alias.symlink_to(binary)
            minimize(); exits(launch(executable=alias)); wait(lambda: not minimized(), 'executable alias focus')
            check(unchanged(before, since, cores), 'launching through an executable symlink focuses the same running instance')
            data_alias = folder / 'data-alias'; data_alias.symlink_to(data, target_is_directory=True)
            exits(launch(env={**os.environ, 'XDG_DATA_HOME': str(data_alias)}))
            check(unchanged(before, since, cores), 'a symlink to the same library resolves to the same Linux instance identity')
            burst = [launch() for _ in range(3)]
            for child in burst: exits(child)
            check(unchanged(before, since, cores) and candidates() == [pid], 'simultaneous repeated launches leave one original process and do not restart its connection')
            # A genuinely separate temporary library is allowed to start independently.
            scope = folder / 'separate'; scope.mkdir()
            env = {**os.environ, 'XDG_DATA_HOME': str(scope / 'data'), 'XDG_CONFIG_HOME': str(scope / 'config'), 'XDG_CACHE_HOME': str(scope / 'cache')}
            peers = [launch(env=env), launch(env=env)]
            wait(lambda: sum(p.poll() is None for p in peers) == 1, 'single owner after simultaneous first launch', timeout=15)
            alive = next(p for p in peers if p.poll() is None); stopped = next(p for p in peers if p.poll() is not None); exits(stopped)
            second_library = scope / 'data/io.thronium.desktop/library.json'
            lock = second_library.with_name('library.lock')
            def held():
                if not lock.exists(): return False
                with lock.open('rb') as file:
                    try: fcntl.flock(file, fcntl.LOCK_EX | fcntl.LOCK_NB); return False
                    except BlockingIOError: return True
            wait(held, 'independent library writer lock')
            check(alive.poll() is None and not second_library.exists(), 'two simultaneous first launches create one independent owner without fabricating profiles')
            check(unchanged(before, since, cores), 'a distinct data directory runs independently without affecting the original VPN or library')
            alive.terminate(); alive.communicate(timeout=8)
            separate_before = json.dumps({'version': 1, 'profiles': [], 'groups': [{'id': 'personal', 'name': 'Personal'}], 'selected': None, 'preferences': initial['preferences']}).encode()
            second_library.write_bytes(separate_before); second_library.chmod(0o600)
            replacement = launch(env=env); wait(held, 'reopened library writer lock')
            check(replacement.poll() is None and second_library.read_bytes() == separate_before, 'the Linux instance name is released after process exit so the same library can reopen')
            replacement.terminate(); replacement.communicate(timeout=8)
            command('disconnect'); minimize(); exits(launch()); wait(lambda: not minimized(), 'idle instance focus')
            check(command('snapshot')['running'] is None, 'reopening an idle application opens its window without automatically connecting')
            bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
            names = bus.call_sync('org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'ListNames', None, None, Gio.DBusCallFlags.NONE, 2000, None).unpack()[0]
            digest = hashlib.sha256(library.parent.resolve().as_posix().encode()).hexdigest()
            check(f'io.thronium.desktop.Library_{digest}.SingleInstance' in names and not any(str(data) in name for name in names), 'Linux instance identity uses a stable library hash instead of disclosing its local path')
    finally:
        for p in opened:
            if p.poll() is None:
                p.terminate()
                try: p.communicate(timeout=8)
                except subprocess.TimeoutExpired: p.kill(); p.communicate()
        if minimized():
            root.send_event(protocol.event.ClientMessage(window=window, client_type=connection.intern_atom('_NET_ACTIVE_WINDOW'), data=(32, [2, X.CurrentTime, 0, 0, 0])), event_mask=X.SubstructureRedirectMask | X.SubstructureNotifyMask)
            connection.sync()
        connection.close()
        command('disconnect')
        if initial['selected']: command('select', {'id': initial['selected']})
        if profile: command('delete', {'id': profile})
        command('preferences', initial['preferences'])
