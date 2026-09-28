"""Real GNOME settings in a private keyfile backend; the user's proxy is never written."""
import http.client
import http.server
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import threading
import time
from urllib.parse import urlsplit
from gi.repository import Gio, GLib
from native_processes import core_pids
from window_ui import primary
from system_proxy_guardian_fixture import Guardians
from external_core_fixture import identity
from Xlib import X,protocol


def run(h):
    command, click, fill, select, wait_for, js, check, screenshot = (h[k] for k in ('command', 'click', 'fill', 'select', 'wait_for', 'js', 'check', 'screenshot'))
    config = Path(os.environ['XDG_CONFIG_HOME'])
    assert os.environ.get('GSETTINGS_BACKEND') in ['keyfile','dconf'] and 'thronium-native-test-' in str(config), 'Private GNOME backend is required'
    if os.environ.get('GSETTINGS_BACKEND')=='dconf':
        assert Path(os.environ['DCONF_PROFILE']).parent==config.parent
        assert Path('/proc',os.environ['_THRONIUM_PRIVATE_DCONF_PID'],'exe').resolve()==Path('/usr/libexec/dconf-service')
    schemas = [Gio.Settings.new('org.gnome.system.proxy' + ('.' + s if s else '')) for s in ('', 'http', 'https', 'socks', 'ftp')]
    keys = [(s, k) for s in schemas for k in s.list_keys()]
    def read():
        Gio.Settings.sync()
        return [(s.get_value(k).print_(True), s.get_user_value(k).print_(True) if s.get_user_value(k) is not None else None) for s, k in keys]
    def write(values):
        for (s, k), (_, user) in zip(keys, values):
            if user is None: s.reset(k)
            else: s.set_value(k, GLib.Variant.parse(s.get_value(k).get_type(), user, None, None))
        Gio.Settings.sync()
    def poll(fn, accept, timeout=12):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            while GLib.MainContext.default().pending(): GLib.MainContext.default().iteration(False)
            value = fn()
            if accept(value): return value
            time.sleep(.1)
        raise AssertionError('System proxy state did not settle')
    initial = command('snapshot'); original = read(); ids = []
    guards=Guardians(h['args'].application,config,Path(h['args'].artifacts)/'proxy-guardians.json')
    connection,_window,owner_pid=primary();connection.close()
    original_command=command
    def command(name,*args):
        result=original_command(name,*args)
        if name=='connect':
            connection,_window,pid=primary();connection.close()
            if original_command('snapshot')['systemProxy']['active']:guards.one(pid)
            else:assert not guards.children(pid)
        return result
    def restart():
        h['closed_session'] = True
        try: h['request']('DELETE', h['base'])
        except RuntimeError: pass
        created = h['request']('POST', '/session', {'capabilities': {'alwaysMatch': {'tauri:options': {'application': h['args'].application}}}})
        h['session'] = created['sessionId']; h['base'] = '/session/' + h['session']; h['closed_session'] = False
        wait_for('return !!document.querySelector(".add-connection")')
    def kill_core(pid):
        node=identity(int(pid));path=Path('/proc',str(pid));fd=os.pidfd_open(int(pid))
        try:
            assert path.joinpath('exe').resolve()==guards.app.with_name('ThroniumCore') and node['ppid']==owner_pid
            assert b'XDG_CONFIG_HOME='+str(config).encode() in path.joinpath('environ').read_bytes().split(b'\0')
            assert identity(int(pid))['starttime']==node['starttime']
            signal.pidfd_send_signal(fd,signal.SIGKILL,None,0)
        finally:os.close(fd)
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_GET(self):
            body = b'thronium-system-proxy'
            self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
    server = http.server.ThreadingHTTPServer(('127.0.0.2', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = f'http://127.0.0.2:{server.server_port}/proxy-test'
    def add(name, kind, value):
        pid = command('saveProfile', {'name': name, 'groupId': 'personal', 'kind': kind, 'config': value})['id']; ids.append(pid); return pid
    try:
        check(initial['systemProxy']['available'] and not initial['systemProxy']['active'], 'GNOME capability is detected without enabling the system proxy')
        schemas[0].set_string('mode', 'auto'); schemas[0].set_string('autoconfig-url', 'http://127.0.0.1:9/previous.pac'); schemas[0].set_strv('ignore-hosts', ['localhost', '127.0.0.1', '::1'])
        schemas[1].set_string('host', 'previous.proxy.test'); schemas[1].set_int('port', 3128); schemas[1].set_boolean('use-authentication', True)
        Gio.Settings.sync(); previous = read()
        with socket.socket() as s: s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark'})
        a = add('System proxy direct', 'sing-box-outbound', {'type': 'direct'})
        b = add('System proxy replacement', 'sing-box-outbound', {'type': 'direct'})
        bad = add('System proxy rejected', 'sing-box-outbound', {'type': 'vless', 'server': '127.0.0.1', 'server_port': 9, 'uuid': 'synthetic-invalid-uuid', 'transport': {'type': 'not-a-real-transport'}})
        opaque = add('System proxy opaque', 'sing-box-config', {'inbounds': [], 'outbounds': [{'type': 'direct'}]})
        command('select', {'id': a})
        wait_for('return document.documentElement.lang==="en"')
        click('.connection-options .network-mode[title="Local proxy"]')
        wait_for('return document.activeElement.id==="connection-mode"')
        check(js('return document.querySelector("#connection-mode").value==="local"'), 'connection mode link opens its settings and preserves the default local mode')
        select('#connection-mode', 'system-proxy'); fill('#proxy-port', str(port)); click('#settings-save')
        poll(lambda: command('snapshot')['preferences'], lambda p: p['connectionMode'] == 'system-proxy')
        check(read() == previous, 'saving System proxy mode does not change OS settings before a successful connection')
        screenshot('system-proxy-settings-dark-en')
        click('.primary-nav button:first-child'); click('.power-button')
        connected = poll(lambda: command('snapshot'), lambda s: s['systemProxy']['active'])
        guard=guards.one(owner_pid)
        journal=config/'thronium-system-proxy/recovery.json'
        token=json.loads(journal.read_text())['token']
        check(len(token)==32 and journal.stat().st_mode&0o077==0, 'a private token binds the independent recovery process to this system proxy lease')
        applied = poll(read, lambda values: schemas[0].get_string('mode') == 'manual')
        check(connected['running'] == a and all(s.get_string('host') == '127.0.0.1' and s.get_int('port') == port for s in schemas[1:]), 'a successful UI connection sets HTTP, HTTPS, FTP and SOCKS to the live mixed listener')
        fresh=json.loads(subprocess.check_output(['python3','-c','from gi.repository import Gio; import json; print(json.dumps([Gio.Settings.new("org.gnome.system.proxy.http").get_boolean("use-authentication"),Gio.Settings.new("org.gnome.system.proxy").get_string("autoconfig-url")]))'],text=True))
        (Path(h['args'].artifacts)/'proxy-values-at-connect.json').write_text(json.dumps({'before':previous,'applied':applied,'freshAuthenticationAndPac':fresh,'cachedAuthenticationAndPac':[schemas[1].get_boolean('use-authentication'),schemas[0].get_string('autoconfig-url')]},indent=2)+'\n')
        check(not schemas[1].get_boolean('use-authentication') and schemas[0].get_string('autoconfig-url') == 'http://127.0.0.1:9/previous.pac', 'managed proxy disables stale HTTP authentication while preserving the prior PAC URL')
        assert (config / 'thronium-system-proxy/recovery.json').is_file()
        proxies = json.loads(subprocess.check_output(['python3', '-c', 'from gi.repository import Gio; import json,sys; print(json.dumps(Gio.ProxyResolver.get_default().lookup(sys.argv[1],None)))', origin], text=True))
        endpoint = urlsplit(proxies[0]); assert endpoint.hostname == '127.0.0.1' and endpoint.port == port
        client = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=5); client.request('GET', origin); response = client.getresponse()
        check(response.status == 200 and response.read() == b'thronium-system-proxy', 'a real GNOME proxy resolver routes HTTP through the connected ThroneCore'); client.close()
        command('startUrlTests', {'ids': [a], 'url': origin, 'timeoutMs': 1000})
        result = poll(lambda: command('snapshot')['urlTests'], lambda b: b and all(e['status'] not in ('testing','queued') for e in b['entries']))
        check(result['entries'][0]['status'] == 'ok' and read() == applied, 'isolated HTTP ping leaves the active system proxy settings unchanged')
        for pid in (bad, opaque):
            try: command('connect', {'id': pid}); raise AssertionError('Expected invalid profile rejection')
            except RuntimeError: pass
        after = command('snapshot')
        check(after['running'] == a and after['since'] == connected['since'] and after['systemProxy']['active'] and read() == applied, 'invalid and incompatible profiles preserve the existing VPN and system proxy')
        try: command('connectionSettings', {'mode': 'local', 'port': port}); raise AssertionError('Expected active mode edit rejection')
        except RuntimeError: pass
        click('.primary-nav button:nth-child(5)'); click('[data-settings-section=inbound]')
        check(js('return document.querySelector("#connection-mode").matches(":disabled") && document.querySelector("#proxy-port").matches(":disabled")'), 'connection settings cannot change mode or listener while a VPN is active')
        command('preferences', {**command('snapshot')['preferences'], 'language': 'ru', 'theme': 'light'})
        wait_for('return document.documentElement.lang==="ru"')
        h['request']('POST', h['base'] + '/window/rect', {'width': 390, 'height': 844})
        js('document.querySelector("#settings-form").scrollIntoView({block:"center"})')
        check(js('return document.querySelector("#settings-form").scrollWidth<=document.querySelector("#settings-form").clientWidth && document.querySelector("#settings-form").textContent.includes("Системный прокси включён")'), 'system proxy settings show actual state in Russian and fit a narrow window')
        screenshot('system-proxy-settings-narrow-ru')
        h['request']('POST', h['base'] + '/window/rect', {'width': 1280, 'height': 860})
        click('.primary-nav button:first-child')
        command('connect', {'id': b})
        replacement_guard=guards.one(owner_pid)
        check(guards.gone(guard) and replacement_guard['pid']!=guard['pid'] and json.loads(journal.read_text())['token']!=token, 'switching profiles disarms and reaps the old guardian before arming a new lease')
        check(command('snapshot')['systemProxy']['active'] and read() == applied, 'switching profiles reapplies the system proxy while retaining the original recovery values')
        h['request']('POST', h['base'] + '/refresh', {})
        wait_for('return !!document.querySelector(".power-button")')
        check(command('snapshot')['systemProxy']['active'] and read() == applied, 'system proxy ownership survives a webview reload')
        click('.power-button'); poll(lambda: command('snapshot')['running'], lambda p: p is None)
        poll(read, lambda values: values == previous)
        check(not command('snapshot')['systemProxy']['active'] and not (config / 'thronium-system-proxy/recovery.json').exists(), 'Disconnect restores exact previous values and defaults and removes the recovery journal')
        check(guards.gone(replacement_guard) and not guards.children(owner_pid), 'Disconnect also reaps the independent guardian')
        command('connectionSettings', {'mode': 'local', 'port': port}); command('connect', {'id': a}); command('disconnect')
        check(read() == previous, 'local-only connections leave system settings untouched')
        command('connectionSettings', {'mode': 'system-proxy', 'port': port}); command('connect', {'id': a})
        schemas[1].set_string('host', 'external.proxy.test'); Gio.Settings.sync(); external = read()
        poll(lambda: command('snapshot')['systemProxy'], lambda s: s['error'] == 'system_proxy_changed')
        command('disconnect')
        check(read() == external, 'an external proxy change is preserved as a whole when Thronium disconnects')
        wait_for('return !!document.querySelector("#system-proxy-notice")')
        click('#system-proxy-restore'); poll(lambda: command('snapshot')['systemProxy']['error'], lambda e: e is None)
        write(previous)
        command('connect', {'id': a})
        lost_guard=guards.one(owner_pid)
        js('''const original=window.fetch;window.__proxyGuardianPoll={original,queue:[],forwarded:0};window.fetch=function(input,options){let name;try{if(String(input).includes('/app_command'))name=JSON.parse(options?.body||'{}').name}catch{}if(name==='snapshot')return new Promise((resolve,reject)=>window.__proxyGuardianPoll.queue.push({input,options,resolve,reject}));return original.apply(this,arguments);};''')
        click('[data-window-action=minimize]');wait_for('return document.hidden');time.sleep(.25)
        guards.send(lost_guard,signal.SIGKILL)
        poll(read,lambda values:values==previous)
        check(guards.gone(lost_guard) and not journal.exists() and js('return document.hidden && window.fetch!==window.__proxyGuardianPoll.original'), 'the backend restores GNOME after guardian death while the window is hidden and WebKit status requests are suspended')
        js('''const s=window.__proxyGuardianPoll;window.fetch=s.original;for(const q of s.queue.splice(0))s.original(q.input,q.options).then(q.resolve,q.reject);''')
        connection,window,pid=primary()
        try:
            connection.screen().root.send_event(protocol.event.ClientMessage(window=window,client_type=connection.intern_atom('_NET_ACTIVE_WINDOW'),data=(32,[2,X.CurrentTime,0,0,0])),event_mask=X.SubstructureRedirectMask|X.SubstructureNotifyMask);connection.sync()
        finally:connection.close()
        wait_for('return !document.hidden')
        lost=poll(lambda:command('snapshot'),lambda s:s['systemProxy']['error']=='system_proxy_guardian_failed')
        poll(read,lambda values:values==previous)
        check(not lost['systemProxy']['active'] and lost['running']==a and guards.gone(lost_guard) and not journal.exists(), 'guardian failure restores the system proxy, keeps the local connection alive and reports the loss of protection')
        wait_for('return document.querySelector("#system-proxy-notice")?.textContent.includes("Защита восстановления")')
        screenshot('system-proxy-guardian-error-ru')
        command('connect', {'id': a})
        stopped_guard=guards.one(owner_pid);guards.send(stopped_guard,signal.SIGSTOP)
        started=time.monotonic();command('disconnect')
        check(time.monotonic()-started<5 and guards.gone(stopped_guard) and read()==previous, 'Disconnect restores settings and bounds cleanup even when its own guardian is stopped')
        command('connect', {'id': a})
        core_guard=guards.one(owner_pid)
        connection, _window, pid = primary(); connection.close(); children = core_pids(pid); assert len(children) == 1
        kill_core(children[0])
        replacement=poll(lambda:core_pids(pid),lambda ids:len(ids)==1 and ids!=children)
        recovered=poll(lambda:command('snapshot'),lambda s:s['phase']=='connected')
        check(recovered['systemProxy']['active'] and guards.one(pid)['pid']==core_guard['pid'], 'automatic Core recovery retains the same independent guardian and proxy lease')
        kill_core(replacement[0])
        stopped = poll(lambda: command('snapshot'), lambda s: s['running'] is None and not s['systemProxy']['active'])
        poll(read, lambda values: values == previous)
        check(stopped['error'] == 'core_restart_limited', 'rapid repeated Core exits restore the previous system proxy and report the restart limit')
        check(guards.gone(core_guard), 'an unrecoverable Core exit also disarms and reaps its proxy guardian')
        if h['args'].system_proxy_only:
            command('connect', {'id': a})
            connection, _window, pid = primary(); connection.close(); children = core_pids(pid)
            crash_guard=guards.one(pid);parent=identity(pid)
            guards.send(parent,signal.SIGKILL)
            poll(lambda: Path('/proc', str(pid)).exists(), lambda alive: not alive)
            poll(read, lambda values: values == previous)
            poll(lambda:journal.exists() or not guards.gone(crash_guard),lambda pending:not pending)
            check(True, 'SIGKILL of the real GUI restores exact previous GNOME settings and reaps its guardian before any application restart')
            guards.events.append({'event':'gui-crash-recovered-before-restart','parent':parent,'guardian':crash_guard,'journalRemoved':not journal.exists()})
            # Replace only the disposable WebDriver session; reuse its private settings and library.
            restart()
            recovered = command('snapshot')
            poll(read, lambda values: values == previous)
            check(not recovered['systemProxy']['active'] and recovered['running'] is None and not journal.exists(), 'relaunching the real application preserves the already restored proxy and stays disconnected')
            poll(lambda: [p for p in children if Path('/proc', p).exists()], lambda remaining: not remaining)
            check(True, 'the old test core also exits after its parent application is killed')
            command('connect',{'id':a})
            connection,_window,pid=primary();connection.close();parent=identity(pid);foreign_guard=guards.one(pid);children=core_pids(pid)
            guards.send(parent,signal.SIGSTOP)
            try:
                schemas[1].set_string('host','external-after-gui-stop.example');Gio.Settings.sync();foreign=read()
            finally:guards.send(parent,signal.SIGKILL)
            poll(lambda:journal.exists() or not guards.gone(foreign_guard),lambda pending:not pending)
            poll(lambda:[p for p in children if Path('/proc',p).exists()],lambda pending:not pending)
            check(read()==foreign, 'after GUI death the guardian reads current GNOME values and preserves an external change made while the GUI was stopped')
            guards.events.append({'event':'foreign-proxy-preserved-after-gui-crash','parent':parent,'guardian':foreign_guard,'journalRemoved':not journal.exists()})
            write(previous);restart()
            if os.environ.get('GSETTINGS_BACKEND')=='dconf':
                command('connect',{'id':a})
                connection,_window,pid=primary();connection.close();parent=identity(pid);blocked_guard=guards.one(pid)
                service=int(os.environ['_THRONIUM_PRIVATE_DCONF_PID']);service_node=identity(service)
                service_path=Path('/proc',str(service))
                assert service_path.joinpath('exe').resolve()==Path('/usr/libexec/dconf-service')
                assert b'XDG_CONFIG_HOME='+str(config).encode() in service_path.joinpath('environ').read_bytes().split(b'\0')
                service_fd=os.pidfd_open(service)
                try:
                    assert identity(service)['starttime']==service_node['starttime']
                    signal.pidfd_send_signal(service_fd,signal.SIGSTOP,None,0)
                    began=time.monotonic();guards.send(parent,signal.SIGKILL)
                    poll(lambda:guards.gone(blocked_guard),lambda gone:gone,timeout=14)
                    elapsed=time.monotonic()-began
                    check(9<=elapsed<14 and journal.exists(), 'a stalled private dconf service cannot keep recovery alive indefinitely; the guardian exits at its deadline and retains the journal')
                    guards.events.append({'event':'blocked-dconf-deadline','seconds':elapsed,'guardian':blocked_guard,'journalRetained':journal.exists()})
                finally:
                    signal.pidfd_send_signal(service_fd,signal.SIGCONT,None,0);os.close(service_fd)
                restart();poll(read,lambda values:values==previous)
                check(not journal.exists() and not command('snapshot')['systemProxy']['active'], 'after the settings service resumes, application startup completes recovery from the retained journal')
    finally:
        command('disconnect'); command('cancelUrlTests'); command('clearUrlTests')
        for pid in ids: command('delete', {'id': pid})
        command('preferences', initial['preferences'])
        if initial['selected']: command('select', {'id': initial['selected']})
        write(original)
        click('.primary-nav button:first-child'); fill('#client-search', '')
        h['request']('POST', h['base'] + '/window/rect', {'width': 1280, 'height': 860})
        server.shutdown(); server.server_close()
        guards.finish()
