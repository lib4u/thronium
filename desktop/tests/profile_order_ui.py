"""Manual profile ordering through trusted native input and real Engine IPC."""
import contextlib
import copy
import hashlib
import http.server
import json
import os
from pathlib import Path
import socket
import socketserver
import threading
import time

from native_processes import core_pids
from profile_order_input import OwnedInput

SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'


def run(h):
    command, click, fill, select, wait_for, js, check = (h[k] for k in ('command', 'click', 'fill', 'select', 'wait_for', 'js', 'check'))
    initial = command('snapshot'); initial_route = command('routing')
    initial_rect = h['request']('GET', h['base'] + '/window/rect')
    root = Path(os.environ['XDG_DATA_HOME']); assert 'thronium-native-test-' in str(root)
    library = root / 'io.thronium.desktop/library.json'
    artifacts = Path(h['args'].artifacts)
    groups = []; otp = None; held = None; native = None
    audit = {'events': [], 'geometry': {}, 'moves': [], 'wholeProtoRequestEqualityClaimed': False,
             'trustedNativePointerRequired': True, 'serverRequests': []}
    unused_vpn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); unused_vpn.bind(('127.0.0.1', 0))
    provider = [{'type': 'direct', 'tag': 'Provider Alpha'}, {'type': 'direct', 'tag': 'Provider Beta'}, {'type': 'direct', 'tag': 'Provider Gamma'}]

    class Http(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_GET(self):
            assert self.path == '/profiles'
            audit['serverRequests'].append(self.path)
            body = json.dumps(provider).encode(); self.send_response(200)
            self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Http)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            with contextlib.suppress(OSError):
                while body := self.request.recv(4096): self.request.sendall(body)
    class EchoServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = True; daemon_threads = True
    echo_server = EchoServer(('127.0.0.1', 0), Echo)
    threading.Thread(target=echo_server.serve_forever, daemon=True).start()

    def until(fn, timeout=12):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = fn()
            if value: return value
            time.sleep(.08)
        raise AssertionError('Profile-order observation timed out')
    def state(): return json.loads(library.read_text())
    def normalized(value):
        value = copy.deepcopy(value); value['profiles'].sort(key=lambda p: p['id']); return value
    def order(gid): return [p['id'] for p in state()['profiles'] if p['groupId'] == gid]
    def visible(gid): return js('return [...document.querySelectorAll(arguments[0]+" [data-order-profile]")].map(e=>e.dataset.orderProfile)', '[data-library-group="' + gid + '"]')
    def handle(id): return '[data-profile-drag="' + id + '"]'
    def row(id): return '[data-order-profile="' + id + '"]'
    def scroll(selector):
        js('document.querySelector(arguments[0]).scrollIntoView({block:"center",behavior:"instant"})', selector); time.sleep(.12)
    def close_menu():
        if js('return !!document.querySelector("[role=menu]")'):
            native.key('Escape'); wait_for('return !document.querySelector("[role=menu]")')
    def add(name, gid, config=None):
        return command('saveProfile', {'name': name, 'groupId': gid, 'kind': 'sing-box-outbound', 'config': config or {'type': 'direct', 'udp_fragment': True}})['id']
    def nodes():
        return [{'pid': int(pid), 'starttime': Path('/proc', pid, 'stat').read_text().rsplit(')', 1)[1].split()[19]} for pid in core_pids(native.pid)]
    def echo():
        held.sendall(b'profile-order-owned-held'); return held.recv(128) == b'profile-order-owned-held'
    def active_parts(): return command('connectionConfiguration', {'id': main, 'active': True})
    def active_unchanged():
        now = command('snapshot')
        return (now['running'] == active['running'] and now['selected'] == active['selected'] and now['since'] == active['since']
                and now['vpn'] == active['vpn'] and now['routing']['pending'] and nodes() == active_nodes and active_parts() == active_config and echo())
    def move_and_check(source, target, after):
        before = state(); expected = order(a); expected.remove(source); expected.insert(expected.index(target) + int(after), source)
        start = len(native.events()); scroll(handle(source)); native.start_drag(handle(source))
        wait_for('return document.querySelector(' + json.dumps(row(source)) + ')?.dataset.profileDragging==="true"')
        native.drag_to(native.point(row(target), 'after' if after else 'before'))
        wait_for('return document.querySelector(' + json.dumps(row(target)) + ')?.dataset.profileDrop===' + json.dumps('after' if after else 'before'))
        if not audit['moves']: h['screenshot']('profile-order-trusted-drag-before-en')
        native.release(); until(lambda: order(a) == expected); until(lambda: visible(a) == expected)
        events = native.events()[start:]; audit['events'].extend(events)
        audit['moves'].append({'source': source, 'target': target, 'after': after, 'expected': expected})
        assert normalized(state()) == normalized(before) and active_unchanged()
        assert all(state()['profiles'][i] == profile for i, profile in enumerate(before['profiles']) if profile['groupId'] != a)
        assert all(e['trusted'] for e in events if e['type'] in ('pointerdown', 'pointermove', 'pointerup', 'gotpointercapture', 'lostpointercapture'))
        assert {'pointerdown', 'pointermove', 'pointerup'} <= {e['type'] for e in events}
        assert any(e['type']=='pointerup' and e['hitRow']==target for e in events)
        return expected
    def menu(id):
        wait_for('return !!document.querySelector(' + json.dumps(handle(id)) + ')&&!document.querySelector(' + json.dumps(handle(id)) + ').disabled')
        scroll(handle(id)); time.sleep(.32); native.click(handle(id)); wait_for('return !!document.querySelector("#profile-move-up")')
    def disabled():
        return js('return document.querySelectorAll("[data-order-profile]").length>0&&[...document.querySelectorAll("[data-profile-drag]")].every(e=>e.disabled)')
    def redraw():
        wait_for('return !!document.querySelector(' + json.dumps(handle(main)) + ')')
    def snapshot_geometry(language):
        # Leave the titled handle so GTK dismisses its separate tooltip window
        # before XGetImage reads the App; do not alter DOM, CSS or screenshot pixels.
        native.move(native.point("[role=menu]")); time.sleep(.35)
        samples = []
        for _ in range(3):
            samples.append(js('''const menu=document.querySelector('[role=menu]');const r=menu.getBoundingClientRect();return {width:innerWidth,height:innerHeight,left:r.left,right:r.right,top:r.top,bottom:r.bottom,scroll:document.documentElement.scrollWidth,client:document.documentElement.clientWidth,menuScroll:menu.scrollWidth,menuClient:menu.clientWidth};''')); time.sleep(.15)
        audit['geometry'][language] = samples
        assert samples[0] == samples[1] == samples[2]
        assert all(s['width'] == 390 and s['left'] >= 0 and s['right'] <= 390 and s['top'] >= 0 and s['bottom'] <= s['height'] and s['scroll'] <= s['client'] + 1 and s['menuScroll'] <= s['menuClient'] + 1 for s in samples)
        h['screenshot']('profile-order-' + language + '-390')
        return True

    try:
        command('disconnect'); command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark', 'librarySort': 'original', 'librarySortDescending': False})
        h['request']('POST', h['base'] + '/window/rect', {'width': 1280, 'height': 900})
        for name in ['Profile order local', 'Foreign fixed slots', 'Owned order subscription']:
            groups.append(command('saveGroup', {'name': name, 'subscription': None})['id'])
        a, b, remote = groups
        main = add('Order Alpha active', a); foreign = add('Foreign one', b); beta = add('Order Beta favorite', a)
        foreign2 = add('Foreign two', b); gamma = add('Order Gamma', a)
        bound = add('Order bound HOTP', a, {'type': 'openvpn-client', 'server': '127.0.0.1', 'server_port': unused_vpn.getsockname()[1], 'username': 'unused', 'password': 'unused', 'static_challenge': 'Code', 'system': False})
        otp = command('otpSave', {'value': {'name': 'Order preserved HOTP', 'secret': SECRET, 'type': 'hotp', 'algorithm': 'SHA1', 'counter': '9007199254740993', 'period': 30, 'digits': 6}})
        binding = command('getVpnOtpBinding', {'profileId': bound})
        command('saveVpnOtpBinding', {'profileId': bound, 'editToken': binding['editToken'], 'otpId': otp['id'], 'otpRevision': otp['revision']})
        command('favorite', {'id': beta})
        command('saveGroup', {'id': remote, 'name': 'Owned order subscription', 'subscription': {'url': f'http://127.0.0.1:{server.server_port}/profiles', 'headers': {}, 'viaProxy': False, 'intervalMinutes': 0}})
        wait_for('return [...document.querySelector(".group-strip select").options].some(o=>o.value===' + json.dumps(a) + ')')
        select('.group-strip select', a); fill('#client-search', '')
        native = OwnedInput(h); native.activate()
        with socket.socket() as free: free.bind(('127.0.0.1', 0)); port = free.getsockname()[1]
        command('connectionSettings', {'mode': 'local', 'port': port}); command('connect', {'id': main}); command('select', {'id': foreign})
        held = socket.create_connection(('127.0.0.1', port), timeout=5)
        address = '127.0.0.1:' + str(echo_server.server_address[1]); held.sendall(f'CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n\r\n'.encode())
        headers = b''
        while b'\r\n\r\n' not in headers: headers += held.recv(4096)
        assert b' 200 ' in headers
        pending = copy.deepcopy(command('routing')); current = next(p for p in pending['profiles'] if p['id'] == pending['active'])
        current['rules'] = [{'id': 'order-pending-reject', 'name': 'Saved pending reject', 'enabled': True, 'config': {'network': 'tcp', 'action': 'reject'}}]
        command('saveRouting', pending)
        active = command('snapshot'); active_nodes = nodes(); active_config = active_parts(); baseline = state()
        wait_for('return document.querySelectorAll("[data-profile-drag]:not(:disabled)").length===4')
        check(visible(a) == [main, beta, gamma, bound] and echo(), 'Original single-group view enables handles without changing the active selection')
        first = move_and_check(gamma, main, False)
        check(first == [gamma, main, beta, bound], 'trusted native drag inserts before the current target ID')
        check(normalized(state()) == normalized(baseline) and active_unchanged(), 'reorder preserves complete metadata/HOTP, active configuration parts, Core identity and held CONNECT')
        last = move_and_check(gamma, bound, True)
        check(last == [main, beta, bound, gamma], 'trusted native drag inserts after the current target ID')
        check(all(e['trusted'] for e in audit['events']) and any(e['type'] == 'pointerup' for e in audit['events']), 'native reorder contains actual trusted pointer movement and release')
        before = state(); menu(beta)
        check(state() == before and active_unchanged() and js('return [...document.querySelectorAll("[role=menuitem]")].map(e=>e.id)').index('profile-move-up') < js('return [...document.querySelectorAll("[role=menuitem]")].map(e=>e.id)').index('export-one'), 'clicking the handle opens the existing menu without selecting or reconnecting')
        native.click('#profile-move-up'); until(lambda: order(a) == [beta, main, bound, gamma])
        check(active_unchanged(), 'native menu Move up reorders the intended profile without connection changes')
        for name, expected in [('Down', [main, beta, bound, gamma]), ('Up', [beta, main, bound, gamma])]:
            wait_for('return !document.querySelector(' + json.dumps(handle(beta)) + ').disabled')
            scroll(handle(beta)); js('document.querySelector(arguments[0]).focus()', handle(beta)); assert js('return document.activeElement===document.querySelector(arguments[0])', handle(beta)); count = len(native.events()); native.key(name, alt=True)
            until(lambda: order(a) == expected)
            events = native.events()[count:]; audit['events'].extend(events)
            check(any(e['type'] == 'keydown' and e['trusted'] and e['alt'] and e['handle'] == beta for e in events) and active_unchanged(), 'Alt+' + name + ' targets the focused stable-ID handle with a trusted event')
        menu(beta); first_disabled = js('return document.querySelector("#profile-move-up").disabled&&!document.querySelector("#profile-move-down").disabled'); close_menu()
        menu(gamma); last_disabled = js('return !document.querySelector("#profile-move-up").disabled&&document.querySelector("#profile-move-down").disabled'); close_menu()
        check(first_disabled and last_disabled, 'first/last profiles disable only the unavailable boundary direction')
        for cancellation in ['Escape', 'blur']:
            before = state(); scroll(handle(gamma)); native.start_drag(handle(gamma)); native.drag_to(native.point(row(main), 'before'))
            wait_for('return !!document.querySelector("[data-profile-drop]")')
            if cancellation == 'Escape': native.key('Escape')
            else:
                with native.blur(): wait_for('return !document.querySelector("[data-profile-drop]")')
            native.release(); wait_for('return !document.querySelector("[data-profile-drop]")')
            check(state() == before and active_unchanged(), 'real native ' + cancellation + ' cancels the drag without persisting an order')
        scroll(handle(gamma)); native.start_drag(handle(gamma)); native.drag_to(native.point(row(main), 'before'))
        wait_for('return !!document.querySelector("[data-profile-drop]")&&document.querySelector(' + json.dumps(row(gamma)) + ')?.dataset.profileDragging==="true"')
        extra = add('Order added during drag', a); after_add = state(); wait_for('return !document.querySelector("[data-profile-drop]")'); native.release()
        check(state() == after_add and active_unchanged(), 'a real membership change cancels an old drag instead of restoring captured profiles')
        select('.group-strip select', 'all'); scroll(handle(gamma)); before = state(); cross_start = len(native.events()); native.start_drag(handle(gamma))
        wait_for('return document.querySelector(' + json.dumps(row(gamma)) + ')?.dataset.profileDragging==="true"')
        native.drag_to(native.point(row(foreign), 'before')); native.release(); time.sleep(.35)
        cross_events = native.events()[cross_start:]; audit['events'].extend(cross_events)
        assert {'pointerdown', 'pointermove', 'pointerup'} <= {e['type'] for e in cross_events if e['trusted']}
        assert any(e['type']=='pointerup' and e['hitRow']==foreign for e in cross_events)
        check(state() == before and active_unchanged(), 'trusted cross-group drop cannot move a profile or start a connection')
        for target, code in [(foreign, 'invalid_profile_order'), ('missing-order-target', 'profile_not_found')]:
            before = library.read_bytes()
            try: command('reorderProfile', {'id': gamma, 'targetId': target, 'after': False})
            except RuntimeError as error: assert error.args == ({'ok': False, 'error': {'code': code}},)
            else: raise AssertionError('Invalid order command unexpectedly succeeded')
            check(library.read_bytes() == before and active_unchanged(), 'stale/cross-group API refusal preserves all current profile values: ' + code)
        select('.group-strip select', a)
        for mode in ['name', 'latency', 'address', 'protocol']:
            click('#library-sort'); click('#library-sort-' + mode); wait_for('return !document.querySelector("#library-sort").disabled&&document.querySelector("#library-sort").title.endsWith(' + json.dumps('By ' + mode) + ')')
            before = library.read_bytes(); check(disabled() and library.read_bytes() == before, 'presentation sort ' + mode + ' disables manual ordering')
        click('#library-sort'); click('#library-sort-original'); wait_for('return !document.querySelector("#library-sort").disabled&&document.querySelector("#library-sort").title.endsWith("Library order")')
        for query in [' ', 'Order Beta']:
            fill('#client-search', query); wait_for('return document.querySelectorAll("[data-order-profile]").length>0')
            until(disabled)
            check(disabled(), 'nonempty row search disables ordering, including ' + ('whitespace' if query == ' ' else 'a named match'))
        fill('#client-search', ''); click('#library-filter')
        wait_for('return !!document.querySelector("[role=menuitemradio][id^=library-filter-]:not(#library-filter-all)")')
        filter_id = js('return document.querySelector("[role=menuitemradio][id^=library-filter-]:not(#library-filter-all)").id'); click('#' + filter_id)
        wait_for('return document.querySelector("#library-filter").classList.contains("has-filter")')
        check(disabled(), 'protocol row filtering disables ordering'); click('#library-filter'); click('#library-filter-all')
        click('.library-tabs button:nth-child(2)'); wait_for('return document.querySelector(".library-tabs button:nth-child(2)").getAttribute("aria-pressed")==="true"'); check(disabled(), 'favorites-only filtering disables ordering'); click('.library-tabs button:first-child')
        click('#bulk-select-toggle'); wait_for('return document.querySelector("#bulk-select-toggle").getAttribute("aria-pressed")==="true"'); check(disabled(), 'bulk selection disables the ordering handle'); click('#bulk-select-toggle')
        js('''const original=window.fetch;const a=window.__profileOrderHold={original,armed:true,backendDone:false};window.fetch=function(input,options){let name;try{if(String(input).includes('/app_command'))name=JSON.parse(options?.body||'{}').name}catch{}const promise=original.apply(this,arguments);if(name==='reorderProfile'&&a.armed){a.armed=false;return promise.then(async response=>{a.httpStatus=response.status;a.bodyIsNull=(await response.clone().json())===null;a.backendDone=true;return new Promise(resolve=>a.release=()=>resolve(response))})}return promise};''')
        order_before_busy=order(a);menu(gamma); native.click('#profile-move-up'); wait_for('return window.__profileOrderHold.backendDone')
        check(js('return window.__profileOrderHold.httpStatus===200&&window.__profileOrderHold.bodyIsNull') and order(a)!=order_before_busy and disabled() and active_unchanged(), 'an observed successful IPC reply held in the WebView keeps ordering disabled until UI completion')
        js('window.__profileOrderHold.release();window.fetch=window.__profileOrderHold.original'); wait_for('return !document.querySelector("#library-sort").disabled')
        select('.group-strip select', remote); click('[data-group-menu="' + remote + '"]'); click('#update-subscription'); click('#subscription-load')
        wait_for('return !!document.querySelector("#subscription-apply:not(:disabled)")'); click('#subscription-apply'); wait_for('return !document.querySelector("dialog")')
        remote_ids = order(remote); assert len(remote_ids) == 3
        menu(remote_ids[1]); hint = js('return document.querySelector(arguments[0]).title', handle(remote_ids[1])); close_menu()
        check('provider' in hint.lower() and len(audit['serverRequests']) == 1, 'a real owned subscription import exposes the provider-order refresh hint')
        click('[data-group-menu="' + remote + '"]'); click('#update-subscription'); click('#subscription-load'); wait_for('return !!document.querySelector("#subscription-apply:not(:disabled)")')
        command('reorderProfile', {'id': remote_ids[2], 'targetId': remote_ids[0], 'after': False}); after_move = state(); click('#subscription-apply')
        wait_for('return !!document.querySelector(".subscription-modal [role=alert]")')
        check(state() == after_move, 'a subscription preview captured before reorder refuses stale apply without changing the library')
        click('#main-modal > .modal-head > button'); wait_for('return !document.querySelector("dialog")')
        click('[data-group-menu="' + remote + '"]'); click('#update-subscription'); click('#subscription-load'); wait_for('return !!document.querySelector("#subscription-apply:not(:disabled)")')
        click('#subscription-apply'); wait_for('return !document.querySelector("dialog")')
        check(order(remote) == remote_ids and active_unchanged(), 'a fresh owned HTTP subscription refresh restores provider order with stable UUIDs and main traffic')
        for language in ['ru', 'en']:
            command('preferences', {**command('snapshot')['preferences'], 'language': language})
            wait_for('return document.documentElement.lang===' + json.dumps(language))
            h['request']('POST', h['base'] + '/window/rect', {'width': 390, 'height': 844}); wait_for('return innerWidth===390')
            menu(remote_ids[1]); check(snapshot_geometry(language), language + ' order menu, original actions and handle fit actual390 geometry'); close_menu()
        restart_nodes = nodes(); command('disconnect'); held.close(); held = None; before_restart = state(); old_pid, old_start = native.pid, native.starttime
        audit['events'].extend(native.events()); native.close(); native = None
        h['request']('DELETE', h['base']); until(lambda: not Path('/proc', str(old_pid)).exists())
        until(lambda: all(not Path('/proc', str(n['pid'])).exists() for n in restart_nodes))
        session = h['request']('POST', '/session', {'capabilities': {'alwaysMatch': {'tauri:options': {'application': h['args'].application}}}})['sessionId']
        h['session'] = session; h['base'] = '/session/' + session
        wait_for('return !!document.querySelector(".add-connection")'); native = OwnedInput(h)
        audit['restart'] = {'oldPid': old_pid, 'oldStarttime': old_start, 'newPid': native.pid, 'newStarttime': native.starttime}
        check(native.pid != old_pid and state() == before_restart and command('snapshot')['running'] is None, 'a different real App process reopens the same private library with exact persisted manual order')
        audit['passed'] = True
    finally:
        try:
            if not audit.get('passed'): h['screenshot']('profile-order-failure-before-cleanup')
            if native:
                with contextlib.suppress(Exception): audit['events'].extend(native.events())
                native.close()
            with contextlib.suppress(Exception): js('if(window.__profileOrderHold){window.__profileOrderHold.release?.();window.fetch=window.__profileOrderHold.original}')
            if held: held.close()
            command('disconnect')
            for gid in groups: command('deleteGroup', {'id': gid, 'deleteProfiles': True})
            if otp: command('otpRemove', {'id': otp['id'], 'revision': command('otpGet', {'id': otp['id']})['revision']})
            command('saveRouting', {**command('routing'), 'active': initial_route['active'], 'profiles': initial_route['profiles']})
            command('preferences', initial['preferences'])
            if initial['selected']: command('select', {'id': initial['selected']})
            h['request']('POST', h['base'] + '/window/rect', initial_rect)
        finally:
            server.shutdown(); server.server_close(); echo_server.shutdown(); echo_server.server_close(); unused_vpn.close()
            (artifacts / 'profile-order-audit.json').write_text(json.dumps(audit, indent=2) + '\n')
