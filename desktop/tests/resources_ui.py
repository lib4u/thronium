"""Native process metrics over owned processes and an uninterrupted loopback tunnel."""
import contextlib
import json
import math
import os
import pathlib
import signal
import socket
import socketserver
import threading
import time
from native_processes import core_pids
from tray_ui import wait
from window_ui import primary


def process_tree(root):
    """Independent observer: enumerate children from every thread, not names."""
    result, queue = set(), [int(root)]
    while queue:
        pid = queue.pop()
        if pid in result:
            continue
        result.add(pid)
        for task in pathlib.Path('/proc', str(pid), 'task').glob('*/children'):
            try:
                queue.extend(int(child) for child in task.read_text().split())
            except OSError:
                pass
    return result


def rss(pids):
    total = 0
    for pid in pids:
        try:
            total += int(pathlib.Path('/proc', str(pid), 'statm').read_text().split()[1]) * os.sysconf('SC_PAGE_SIZE')
        except (OSError, ValueError, IndexError):
            pass
    return total


def finite_cpu(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and 0 <= value <= 100


def run(h):
    command, click, wait_for, js, check, screenshot = (h[key] for key in ('command', 'click', 'wait_for', 'js', 'check', 'screenshot'))
    request, base = h['request'], h['base']
    initial = command('snapshot')
    geometry = request('GET', base + '/window/rect')
    display, window, pid = primary()
    root = display.screen().root
    from Xlib import X, protocol
    group = None
    connection = None
    audit = None
    readings = []

    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                while data := self.request.recv(65536):
                    self.request.sendall(data)
            except (ConnectionResetError, BrokenPipeError, OSError):
                pass

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    server = Server(('127.0.0.1', 0), Echo)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def metrics(**payload):
        value = command('processMetrics', {'_nativeResourceCheck': True, **payload})
        readings.append(value)
        return value

    def calls():
        return js('return (window.__resourceAudit?.calls || []).filter(row=>!row.manual)')

    def samples():
        return js('return Number(document.querySelector("#process-resources")?.dataset.samples || 0)')

    def value(selector):
        return js('return document.querySelector(arguments[0])?.textContent || ""', selector)

    def resume_window():
        root.send_event(protocol.event.ClientMessage(window=window, client_type=display.intern_atom('_NET_ACTIVE_WINDOW'), data=(32, [2, X.CurrentTime, 0, 0, 0])), event_mask=X.SubstructureRedirectMask | X.SubstructureNotifyMask)
        display.sync()

    def minimized():
        prop = window.get_full_property(display.intern_atom('_NET_WM_STATE'), X.AnyPropertyType)
        return prop is not None and display.intern_atom('_NET_WM_STATE_HIDDEN') in prop.value

    def connect_tunnel():
        client = socket.create_connection(('127.0.0.1', port), timeout=5)
        address = '127.0.0.1:' + str(server.server_address[1])
        client.sendall(f'CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n\r\n'.encode())
        headers = b''
        while b'\r\n\r\n' not in headers:
            data = client.recv(4096)
            assert data, 'Core closed CONNECT before response headers'
            headers += data
        assert b' 200 ' in headers.split(b'\r\n', 1)[0]
        return client

    def echo(client, token):
        body = ('resources-' + token).encode()
        client.sendall(body)
        received = b''
        while len(received) < len(body):
            data = client.recv(len(body) - len(received))
            if not data:
                break
            received += data
        return received == body

    def assert_rss(value, label):
        owned = set(int(p) for p in core_pids(pid))
        core_tree = set().union(*(process_tree(p) for p in owned)) if owned else set()
        app_tree = process_tree(pid) - core_tree
        expected = {'app': rss(app_tree), 'core': rss(core_tree)}
        for kind in ('app', 'core'):
            reading = value[kind]
            if kind == 'core' and not owned:
                assert reading['status'] == 'inactive'
                continue
            assert reading['status'] == 'ok', reading
            assert reading['processes'] >= 1 and reading['rssBytes'] > 0, reading
            # Processes can allocate/free pages between the independent read and
            # backend sample. The bounds still catch wrong roots/double counting.
            assert abs(reading['rssBytes'] - expected[kind]) <= max(expected[kind] * .35, 24 * 1024 * 1024), (kind, reading, expected)
        check(True, label)

    try:
        command('disconnect')
        if core_pids(pid):
            raise AssertionError('Resource suite must start with a fresh disposable app and no core')
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark'})
        wait_for('return document.documentElement.lang==="en" && document.documentElement.dataset.theme==="dark"')
        with socket.socket() as available:
            available.bind(('127.0.0.1', 0)); port = available.getsockname()[1]
        command('connectionSettings', {'mode': 'local', 'port': port})
        first = metrics(reset=True)
        check(first['supported'] is True and isinstance(first['logicalCpus'], int) and first['logicalCpus'] > 0 and first['app']['cpuPercent'] is None and first['intervalMs'] is None, 'the first native CPU sample is explicitly unknown and reports the logical-processor capacity')
        check(first['coreInstance'] is None and first['core'] == {'status': 'inactive', 'cpuPercent': None, 'rssBytes': None, 'processes': 0, 'reason': None}, 'a fresh disconnected application reports no core instead of fabricated zero CPU or RAM')
        assert_rss(first, 'application RSS matches its actual process tree before any core has been launched')
        time.sleep(.2)
        sampled = metrics()
        check(finite_cpu(sampled['app']['cpuPercent']) and sampled['intervalMs'] >= 100 and core_pids(pid) == [], 'native process sampling produces a finite CPU value without launching a core')
        foreign = metrics(pid=os.getpid(), corePid=1, processId=1)
        assert_rss(foreign, 'user-supplied PID fields cannot redirect metrics to the test driver or system processes')
        check(not any(key in json.dumps(foreign) for key in ('cmdline', 'executable', 'processName', '"pid"', '"pids"')), 'the metrics response contains counts and usage without process paths, command lines or arbitrary PID lists')
        # Observe real calls/replies only; do not mock native metrics or inject
        # sample values. Restore the original invocation function in finally.
        js('''window.__resourceAudit={calls:[],fetch:window.fetch};
window.fetch=function(input,options){
 const audit=window.__resourceAudit;let data;
 try{data=JSON.parse(options?.body)}catch{}
 if(data?.name!=='processMetrics'||!String(input).includes('/app_command'))return audit.fetch.apply(this,arguments);
 const row={at:performance.now(),manual:!!data?.payload?._nativeResourceCheck,reset:!!data?.payload?.reset,done:false};audit.calls.push(row);
 return audit.fetch.apply(this,arguments).then(response=>{
   response.clone().json().then(value=>{row.done=true;if(response.headers.get('Tauri-Response')==='ok')row.value=value;else{row.failed=true;row.error=value}},()=>{row.done=true;row.failed=true});
   return response;
 },error=>{row.done=true;row.failed=true;throw error});
};''')
        click('.primary-nav button:nth-child(3)')
        wait_for('return !!document.querySelector("#process-resources") && window.__resourceAudit.calls.some(row=>!row.manual&&row.done)')
        initial_poll = next(row for row in calls() if row['done'])
        check(initial_poll['reset'] and initial_poll['value']['app']['cpuPercent'] is None and value('#resource-core-cpu') == '—' and value('#resource-core-ram') == '—', 'opening diagnostics starts a fresh CPU interval and displays an absent core as em dashes')
        check(value('#resource-core-status') == 'Core is not running' and 'Application' in value('[data-resource-process=app]') and 'CPU and memory' in value('#process-resources h2'), 'the resource panel explains inactive core state and labels the application in English')
        wait_for('return Number(document.querySelector("#process-resources").dataset.samples)>=3', 8)
        ui = calls()
        measured = [row for row in ui if row['done'] and finite_cpu(row.get('value', {}).get('app', {}).get('cpuPercent'))]
        check(len(measured) >= 1 and len(ui) <= 6 and '%' in value('#resource-app-cpu') and value('#resource-app-ram') not in ('', '—'), 'the visible panel updates approximately once per second with real CPU and RSS samples')
        check(js('return [...document.querySelectorAll("#process-resources svg path")].every(p=>!/(NaN|Infinity)/.test(p.getAttribute("d"))) && document.querySelectorAll("#process-resources svg path.resource-app").length>0'), 'native resource charts contain finite paths built from actual app samples')
        group = command('saveGroup', {'name': 'Resources fixture', 'subscription': None})['id']
        profile = command('saveProfile', {'name': 'Resources loopback', 'groupId': group, 'kind': 'sing-box-outbound', 'config': {'type': 'direct'}})['id']
        command('connect', {'id': profile})
        wait_for('return document.querySelector("[data-resource-process=core]")?.dataset.status==="ok" && document.querySelector("#resource-core-ram").textContent!=="—"', 8)
        # Back-to-back snapshots keep Engine busy with core calls, as a live
        # connection's one-second poll does; the panel must not reset or flicker.
        wait_for('return document.querySelector("#resource-app-cpu").textContent.includes("%")', 8)
        before = len(calls()); frames = []
        js('window.__resourceHammer=true;(async()=>{while(window.__resourceHammer){try{await window.__TAURI_INTERNALS__.invoke("app_command",{name:"snapshot",payload:{}})}catch{}}})()')
        try:
            for _ in range(20):
                frames.append(js('return {cpu:document.querySelector("#resource-app-cpu").textContent,status:document.querySelector("#resource-status").textContent,samples:Number(document.querySelector("#process-resources").dataset.samples)}'))
                time.sleep(.25)
        finally:
            js('window.__resourceHammer=false')
        contended = [row for row in calls()[before:] if row['done']]
        check(len(contended) >= 3 and not any(row.get('failed') for row in contended) and all('%' in f['cpu'] and f['status'] == 'Updating every second' for f in frames) and all(b['samples'] >= a['samples'] for a, b in zip(frames, frames[1:])), 'short Engine holds by the snapshot poll neither fail samples nor reset the shown CPU and history')
        owned = core_pids(pid)
        check(len(owned) == 1, 'the connection creates exactly one owned core for the fixture')
        active = metrics(reset=True)
        instance = active['coreInstance']
        check(isinstance(instance, str) and instance and instance != owned[0] and active['core']['cpuPercent'] is None and active['core']['rssBytes'] > 0, 'new core identity is opaque and its first CPU interval is unknown while RSS is immediately available')
        assert_rss(active, 'application and core RSS match separate process trees without counting the core twice')
        connection = connect_tunnel()
        running = command('snapshot'); held_core = owned[:]
        wait_for('return document.querySelector("#resource-core-cpu").textContent.includes("%")', 8)
        wait(lambda: any(row.get('done') and finite_cpu(row.get('value', {}).get('app', {}).get('cpuPercent')) and finite_cpu(row.get('value', {}).get('core', {}).get('cpuPercent')) for row in calls()), 'measured native app and core CPU')
        live = next(row['value'] for row in reversed(calls()) if row.get('done') and finite_cpu(row.get('value', {}).get('app', {}).get('cpuPercent')) and finite_cpu(row.get('value', {}).get('core', {}).get('cpuPercent')))
        check(finite_cpu(live['app']['cpuPercent']) and finite_cpu(live['core']['cpuPercent']), 'both real application and core CPU values stay within the normalized 0 to 100 percent range')
        check(echo(connection, 'polling') and core_pids(pid) == held_core and command('snapshot')['since'] == running['since'], 'polling resource usage preserves the same core and an already-open CONNECT tunnel')
        click('#resource-pause')
        wait_for('return document.querySelector("#resource-pause").getAttribute("aria-pressed")==="true"')
        count = len(calls()); frozen = js('return {samples:document.querySelector("#process-resources").dataset.samples,cpu:document.querySelector("#resource-app-cpu").textContent,ram:document.querySelector("#resource-core-ram").textContent}')
        time.sleep(2.2)
        check(len(calls()) == count and frozen == js('return {samples:document.querySelector("#process-resources").dataset.samples,cpu:document.querySelector("#resource-app-cpu").textContent,ram:document.querySelector("#resource-core-ram").textContent}') and value('#resource-status') == 'Updates paused', 'pause stops native metrics calls and preserves the displayed values and history')
        check(echo(connection, 'paused'), 'pausing the resource panel keeps the existing proxy tunnel usable')
        click('#resource-pause')
        wait(lambda: any(row.get('done') for row in calls()[count:]), 'resume resource sample')
        resumed = calls()[count:]
        check(resumed[0]['reset'] and resumed[0].get('value', {}).get('app', {}).get('cpuPercent') is None and samples() <= 2, 'resume starts a new CPU baseline and clears pre-pause chart history')
        wait_for('return Number(document.querySelector("#process-resources").dataset.samples)>=3', 8)
        click('.primary-nav button:first-child')
        wait_for('return !document.querySelector("#process-resources")')
        count = len(calls()); time.sleep(2.2)
        check(len(calls()) == count and echo(connection, 'navigation'), 'leaving diagnostics stops native resource polling without interrupting the tunnel')
        click('.primary-nav button:nth-child(3)')
        wait(lambda: any(row.get('done') for row in calls()[count:]), 'resource page return')
        returned = calls()[count:]
        check(returned[0]['reset'] and samples() <= 2, 'returning to diagnostics starts a fresh chart instead of connecting stale history points')
        wait_for('return Number(document.querySelector("#process-resources").dataset.samples)>=2', 6)
        click('[data-window-action=minimize]')
        wait(minimized, 'resource test window minimized')
        try:
            wait_for('return document.hidden', 5)
            count = len(calls()); time.sleep(2.2)
            check(len(calls()) == count and echo(connection, 'hidden'), 'a genuinely hidden native window stops resource requests and preserves live traffic')
        finally:
            resume_window(); wait(lambda: not minimized(), 'resource window restored')
        wait_for('return !document.hidden')
        count = len(calls())
        wait_for('return Number(document.querySelector("#process-resources").dataset.samples)>=2', 6)
        check(echo(connection, 'restored') and command('snapshot')['since'] == running['since'], 'restoring the window restarts resource sampling while preserving the connection')
        request('POST', base + '/window/rect', {'width': 1280, 'height': 860})
        js('document.querySelector("#process-resources").scrollIntoView({block:"start"})')
        screenshot('resources-dark-en')
        for language, theme in [('ru', 'light'), ('en', 'dark')]:
            command('preferences', {**command('snapshot')['preferences'], 'language': language, 'theme': theme})
            wait_for('return document.documentElement.lang===' + json.dumps(language))
            request('POST', base + '/window/rect', {'width': 390, 'height': 844})
            js('document.querySelector("#process-resources").scrollIntoView({block:"start"})')
            check(js('const p=document.querySelector("#process-resources");return p.scrollWidth<=p.clientWidth+1 && document.documentElement.scrollWidth<=innerWidth+1 && [...p.querySelectorAll("button")].every(b=>b.getBoundingClientRect().right<=innerWidth)') and (('CPU и память' if language == 'ru' else 'CPU and memory') in value('#process-resources h2')), f'real CPU and RAM controls fit the 390-pixel {language} native window')
            screenshot('resources-narrow-' + language)
        connection.close(); connection = None
        click('.primary-nav button:first-child')
        command('disconnect')
        idle = metrics(reset=True)
        check(command('snapshot')['running'] is None and core_pids(pid) == held_core and idle['coreInstance'] == instance and idle['core']['rssBytes'] > 0, 'disconnect retains the existing idle core process and its truthful memory/identity reading')
        command('connect', {'id': profile})
        reused = metrics(reset=True)
        check(reused['coreInstance'] == instance and core_pids(pid) == held_core, 'normal reconnect reuses the same core identity instead of fabricating a new process')
        # Only terminate this disposable application's exact owned direct child.
        owned = core_pids(pid)
        assert owned == held_core and len(owned) == 1 and 'thronium-native-test-' in os.environ['XDG_DATA_HOME']
        victim = int(owned[0])
        parent = int(pathlib.Path('/proc', str(victim), 'stat').read_text().rsplit(')', 1)[1].split()[1])
        assert parent == pid and pathlib.Path('/proc', str(victim), 'comm').read_text().strip() == 'ThroniumCore'
        os.kill(victim, signal.SIGTERM)
        wait(lambda: command('snapshot')['running'] is None and not core_pids(pid), 'owned core exit')
        gone = metrics(reset=True)
        check(gone['coreInstance'] is None and gone['core']['status'] == 'inactive' and gone['core']['cpuPercent'] is None and gone['core']['rssBytes'] is None, 'an exited owned core becomes inactive with unavailable CPU and RAM instead of a zero sample')
        command('connect', {'id': profile})
        replaced = metrics(reset=True)
        check(replaced['coreInstance'] != instance and isinstance(replaced['coreInstance'], str) and replaced['core']['cpuPercent'] is None and replaced['core']['rssBytes'] > 0, 'the replacement core receives a new opaque identity and a fresh CPU baseline')
        with connect_tunnel() as replacement:
            check(echo(replacement, 'replacement'), 'the connection remains usable after the controlled core-restart metrics scenario')
        click('.primary-nav button:nth-child(3)')
        wait_for('return document.querySelector("[data-resource-process=core]")?.dataset.status==="ok"', 8)
        check('—' != value('#resource-core-ram') and js('return [...document.querySelectorAll("#process-resources svg path")].every(p=>!/(NaN|Infinity)/.test(p.getAttribute("d")))'), 'the panel displays the replacement core without invalid chart coordinates')
        audit = calls()
        pathlib.Path(h['args'].artifacts, 'resource-readings.json').write_text(json.dumps({'api': readings, 'ui': audit}, ensure_ascii=False, indent=2))
    except BaseException:
        failure = {'api': readings}
        with contextlib.suppress(Exception):
            failure['ui'] = calls()
            failure['panel'] = js('const p=document.querySelector("#process-resources");return p?{samples:p.dataset.samples,text:p.textContent,hidden:document.hidden}:null')
        pathlib.Path(h['args'].artifacts, 'resource-readings-failure.json').write_text(json.dumps(failure, ensure_ascii=False, indent=2))
        raise
    finally:
        if minimized():
            resume_window(); wait(lambda: not minimized(), 'resource cleanup window restore')
        if connection:
            connection.close()
        with contextlib.suppress(Exception):
            js('if(window.__resourceAudit){window.fetch=window.__resourceAudit.fetch;delete window.__resourceAudit}')
        command('disconnect')
        if group:
            command('deleteGroup', {'id': group, 'deleteProfiles': True})
        command('preferences', initial['preferences'])
        if initial['selected']:
            command('select', {'id': initial['selected']})
        click('.primary-nav button:first-child')
        request('POST', base + '/window/rect', geometry)
        display.close()
        server.shutdown(); server.server_close(); thread.join(timeout=2)
