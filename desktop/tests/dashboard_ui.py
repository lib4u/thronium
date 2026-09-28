"""Install and operate dashboard assets in the native application, on owned services."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import uuid


def run(h):
    command, click, fill, wait_for, js, check, screenshot = (h[k] for k in ('command', 'click', 'fill', 'wait_for', 'js', 'check', 'screenshot'))
    fixture = json.loads(Path(os.environ['_THRONIUM_DASHBOARD_FIXTURE']).read_text())
    initial = command('snapshot'); original = command('settings'); pending = set(); audit = {'errors': [], 'latencies': []}
    group = command('saveGroup', {'name': 'Owned dashboard fixtures'})['id']
    launcher = Path(os.environ['_THRONIUM_DASHBOARD_URL_FILE'])
    def port():
        with socket.socket() as s: s.bind(('127.0.0.1', 0)); return s.getsockname()[1]
    def admin(**values):
        req = urllib.request.Request(fixture['admin'], data=json.dumps(values).encode() if values else None, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=3) as response: return json.load(response)
    def poll(predicate, timeout=5):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if predicate(): return
            time.sleep(.05)
        raise AssertionError('Dashboard fixture state timeout')
    def save(section, **values):
        old = command('settings')[section]; return command('saveSettings', {'section': section, 'previous': old, 'values': {**old, **values}})
    def rejected(name, payload, expected):
        value = json.loads(h['request']('POST', h['base'] + '/execute/async', {'script': "const done=arguments[arguments.length-1];window.__TAURI_INTERNALS__.invoke('app_command',{name:arguments[0],payload:arguments[1]}).then(value=>done(JSON.stringify({ok:true,value}))).catch(error=>done(JSON.stringify({ok:false,error})));", 'args': [name, payload]}))
        assert not value['ok'] and value['error'].get('code') == expected, str(value.get('error', 'unexpected success')); audit['errors'].append(expected); return True
    def begin(identifier):
        pending.add(identifier)
        js("window.__dashboard62??={};const id=arguments[0];window.__dashboard62[id]={done:false};window.__TAURI_INTERNALS__.invoke('app_command',{name:'installDashboard',payload:{requestId:id}}).then(value=>window.__dashboard62[id]={done:true,ok:true,value}).catch(error=>window.__dashboard62[id]={done:true,ok:false,error});", identifier)
    def finish(identifier, error=None):
        wait_for('return window.__dashboard62?.[' + json.dumps(identifier) + ']?.done', 12)
        result = json.loads(js('return JSON.stringify(window.__dashboard62[arguments[0]])', identifier)); pending.discard(identifier)
        assert result['ok'] == (error is None), str(result.get('error', 'unexpected success'))
        if error:
            assert result['error'].get('code') in (error if isinstance(error, tuple) else (error,)), result['error']
            audit['errors'].append(result['error'].get('code'))
        return result.get('value')
    def token(): return str(uuid.uuid4())
    def tools(): click('.primary-nav button:nth-child(4)'); wait_for('return !!document.querySelector("#dashboard-card")')
    def ready(): wait_for('return !document.querySelector("#dashboard-cancel") && !document.querySelector("#dashboard-install").disabled', 20)
    def pids():
        target = Path(h['args'].application).with_name('ThroniumCore').resolve(); found = []
        for proc in Path('/proc').iterdir():
            if proc.name.isdigit():
                with contextlib.suppress(OSError):
                    if (proc/'exe').resolve() == target: found.append(int(proc.name))
        return sorted(found)
    def page(api_port, path='index.html'):
        with urllib.request.urlopen('http://127.0.0.1:%d/dashboard/%s' % (api_port, path), timeout=3) as response: return response.read()
    def opened(api_port, secret):
        launcher.unlink(missing_ok=True); click('#dashboard-open'); poll(launcher.exists)
        urls = json.loads(launcher.read_text()); assert len(urls) == 1
        url = urllib.parse.urlsplit(urls[0]); assert url.netloc == '127.0.0.1:'+str(api_port) and url.path == '/thronium-dashboard.html' and not url.query and urllib.parse.parse_qs(url.fragment) == {'secret': [secret], 'language': ['en']}
        return True
    api_port, next_port, inbound = port(), port(), port(); secret = 'owned-api62-a&#=+'; next_secret = 'owned-api62-b#&'
    try:
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark', 'connectionMode': 'local', 'inboundPort': inbound})
        h['request']('POST', h['base'] + '/window/rect', {'width': 1280, 'height': 900}); wait_for('return document.documentElement.lang==="en"'); tools()
        status = command('dashboardStatus'); check(status['installed'] is None and not status['canOpen'] and not pids(), 'disconnected dashboard status does not start Core or install assets')
        count = len(admin()['requests']); check(rejected('installDashboard', {'requestId': token(), 'url': 'https://untrusted.invalid'}, 'dashboard_invalid_request') and rejected('openDashboard', {}, 'dashboard_disconnected') and len(admin()['requests']) == count, 'invalid install and disconnected open do not launch a browser or contact the network')
        save('network', net_use_proxy=True); check(rejected('installDashboard', {'requestId': token()}, 'dashboard_proxy_unavailable') and len(admin()['requests']) == count and not pids(), 'requested unavailable application proxy never falls back to a direct download')
        save('network', net_use_proxy=False)
        cancelled = token(); command('cancelDashboardInstallation', {'requestId': cancelled}); check(rejected('installDashboard', {'requestId': cancelled}, 'dashboard_request_finished') and len(admin()['requests']) == count, 'cancel-before-start prevents late installation')
        direct = command('saveProfile', {'name': 'Owned direct dashboard', 'groupId': group, 'kind': 'sing-box-outbound', 'config': {'type': 'direct'}})['id']
        save('core', core_box_api_enabled=True, core_box_api_dashboard=True, core_box_api_port=api_port, core_box_api_secret=secret)
        command('connect', {'id': direct})
        check(b'data-thronium-page="placeholder"' in page(api_port) and b'THRONIUM_MESSAGES' in page(api_port, 'thronium-bootstrap.js') and len(admin()['requests']) == count and command('dashboardStatus')['reason'] == 'dashboard_not_installed', 'enabling API before installation serves a local placeholder and suppresses automatic Core downloads')
        command('disconnect'); save('core', core_box_api_enabled=False, core_box_api_dashboard=False); idle_pids = pids()
        click('#dashboard-install'); ready(); status = command('dashboardStatus'); assert status['installed'], js('return document.querySelector("#dashboard-error")?.textContent')
        first = status['installed']; check(pids() == idle_pids and command('snapshot')['running'] is None and not command('settings')['core']['core_box_api_enabled'] and len(admin()['requests']) == count + 2, 'official archive follows the owned GitHub redirect and installs without enabling API or starting Core')
        screenshot('dashboard-installed-en-1280')
        click('#dashboard-settings'); wait_for('return !!document.querySelector("#setting-core_box_api_enabled")')
        js('document.querySelector("#setting-core_box_api_enabled").closest("details").open=true')
        click('#setting-core_box_api_enabled'); fill('#setting-core_box_api_port', str(api_port)); fill('#setting-core_box_api_secret', secret)
        if not js('return document.querySelector("#setting-core_box_api_dashboard").checked'): click('#setting-core_box_api_dashboard')
        click('#settings-save'); wait_for('return document.querySelector("#settings-save").disabled && !!document.querySelector("[data-setting]:enabled")')
        check(command('settings')['core']['core_box_api_secret'] == secret and pids() == idle_pids and command('snapshot')['running'] is None, 'API settings button leads to editable settings saved explicitly without connection side effects')
        command('connect', {'id': direct}); active_pids = pids(); assert active_pids; tools(); wait_for('return !document.querySelector("#dashboard-open").disabled')
        html = page(api_port); check(b'<html' in html and b'/thronium-dashboard.js' in page(api_port, 'thronium.html') and page(api_port, 'sw.js').startswith(b'if(!self.define)'), 'actual adjacent Core serves the official dashboard and original worker from the installed generation')
        check(opened(api_port, secret), 'Open uses the running API authority and sends the secret only in the browser URL fragment')
        desktop = Path(__file__).resolve().parents[1]
        browser = subprocess.run([sys.executable,str(desktop/'tests/dashboard_browser.py'),'--artifacts',str(Path(h['args'].artifacts)/'live-browser'),'--archive',os.environ['_THRONIUM_DASHBOARD_ARCHIVE'],'--bootstrap-dir',str(desktop/'engine/src/dashboard'),'--active-url-file',str(launcher)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=70)
        (Path(h['args'].artifacts)/'live-browser.log').write_text(browser.stdout)
        check(browser.returncode == 0, 'owned browser opens the actual Core dashboard with cold and warm Service Worker state')
        save('core', core_box_api_port=next_port, core_box_api_secret=next_secret)
        check(opened(api_port, secret) and pids() == active_pids, 'pending saved port and secret do not replace the active connection browser target')
        for mode, error in [('http-error','dashboard_download_rejected'),('malformed','dashboard_invalid_archive'),('traversal','dashboard_invalid_archive'),('oversize','dashboard_archive_too_large'),('chunked','dashboard_archive_too_large'),('foreign','dashboard_download_failed'),('downgrade','dashboard_download_failed')]:
            admin(mode=mode); before = len(admin()['requests']); check(rejected('installDashboard', {'requestId': token()}, error) and len(admin()['requests']) == before + 1 and command('dashboardStatus')['installed'] == first and page(api_port) == html and pids() == active_pids, mode+' preserves the active assets and connection, with no retry or foreign redirect')
        admin(mode='hold'); identifier = token(); begin(identifier); poll(lambda: admin()['active'] == 1)
        started = time.monotonic(); command('snapshot'); elapsed = time.monotonic() - started; audit['latencies'].append({'snapshot':elapsed})
        check(elapsed < 2 and rejected('installDashboard', {'requestId': token()}, 'dashboard_busy'), 'held download leaves the application responsive and rejects concurrent installation')
        command('cancelDashboardInstallation', {'requestId': token()}); assert not js('return window.__dashboard62[arguments[0]].done', identifier)
        command('cancelDashboardInstallation', {'requestId': identifier}); finish(identifier, 'dashboard_cancelled'); admin(release=True); poll(lambda: admin()['active'] == 0)
        check(command('dashboardStatus')['installed'] == first and page(api_port) == html and rejected('installDashboard', {'requestId': identifier}, 'dashboard_request_finished'), 'matching cancellation keeps the previous generation and prevents request replay')
        save('network', network_timeout=5); admin(mode='hold'); identifier = token(); begin(identifier); poll(lambda: admin()['active'] == 1); finish(identifier, 'dashboard_timeout'); admin(release=True); poll(lambda: admin()['active'] == 0)
        check(command('dashboardStatus')['installed'] == first and pids() == active_pids, 'network timeout preserves installed files and the running Core')
        admin(mode='hold'); click('#dashboard-install'); poll(lambda: admin()['active'] == 1); click('#dashboard-cancel'); ready(); admin(release=True); poll(lambda: admin()['active'] == 0)
        check(command('dashboardStatus')['installed'] == first, 'visible Cancel button leaves the previous dashboard usable')
        admin(mode='hold'); click('#dashboard-install'); poll(lambda: admin()['active'] == 1); click('.primary-nav button:first-child'); admin(release=True); poll(lambda: admin()['active'] == 0); tools(); ready()
        check(command('dashboardStatus')['installed'] == first, 'leaving Tools cancels installation ownership without updating a remounted card')
        admin(mode='updated'); click('#dashboard-install'); ready(); second = command('dashboardStatus')['installed']
        check(second and second['archiveSha256'] != first['archiveSha256'] and b'Owned updated dashboard' in page(api_port) and pids() == active_pids, 'successful update switches the served generation without restarting Core')
        command('disconnect'); command('connect', {'id': direct}); tools(); wait_for('return !document.querySelector("#dashboard-open").disabled')
        check(opened(next_port, next_secret), 'reconnecting uses the newly saved API port and secret')
        command('disconnect')
        xray = command('saveProfile', {'name': 'Owned Xray dashboard', 'groupId': group, 'kind': 'xray-outbound', 'config': {'protocol': 'freedom'}})['id']
        command('connect', {'id': xray})
        check(command('dashboardStatus')['canOpen'] and b'Owned updated dashboard' in page(next_port), 'generated Xray profile retains the surrounding sing-box API dashboard')
        command('disconnect'); proxy = command('saveProfile', {'name': 'Owned download SOCKS hop', 'groupId': group, 'kind': 'sing-box-outbound', 'config': {'type': 'socks', 'server': '127.0.0.1', 'server_port': fixture['socksPort']}})['id']; command('connect', {'id': proxy})
        save('network', net_use_proxy=True); admin(mode='ok'); count = len(admin()['proxyConnections']); identifier = token(); begin(identifier); restored = finish(identifier)
        check(restored['archiveSha256'] == first['archiveSha256'] and len(admin()['proxyConnections']) == count + 2 and b'<html' in page(next_port), 'application proxy carries both HTTPS hosts and reinstalls the official archive')
        admin(mode='hold'); identifier = token(); begin(identifier); poll(lambda: admin()['active'] == 1); started = time.monotonic(); command('disconnect'); elapsed = time.monotonic() - started; audit['latencies'].append({'disconnect':elapsed}); command('cancelDashboardInstallation', {'requestId': identifier}); finish(identifier, ('dashboard_cancelled', 'dashboard_download_failed')); admin(release=True); poll(lambda: admin()['active'] == 0)
        check(elapsed < 2 and command('snapshot')['running'] is None and command('dashboardStatus')['installed'] == restored, 'Disconnect remains responsive during a held proxy download')
        save('network', net_use_proxy=False); h['request']('POST', h['base'] + '/refresh', {}); wait_for('return !!document.querySelector(".add-connection")'); tools(); ready()
        check(command('dashboardStatus')['installed'] == restored and js('return document.querySelector("#dashboard-open").disabled'), 'installed generation survives webview restart and disconnected Open stays disabled')
        command('preferences', {**command('snapshot')['preferences'], 'language': 'ru'}); wait_for('return document.documentElement.lang==="ru"'); admin(mode='http-error'); click('#dashboard-install'); ready()
        check(js('return !!document.querySelector("#dashboard-error") && !document.querySelector("#dashboard-error").textContent.includes("dashboard_")'), 'download rejection is translated in the Russian UI')
        for width in [1280,390]:
            h['request']('POST', h['base'] + '/window/rect', {'width':width,'height':900}); js('document.querySelector("#dashboard-card").scrollIntoView({block:"center"})')
            check(js('return document.documentElement.scrollWidth<=innerWidth+1'), 'dashboard controls fit Russian '+str(width)+'px layout'); screenshot('dashboard-ru-'+str(width))
        logs = command('getLogs'); assert logs['entries']; check(not any(value in json.dumps(logs) for value in [secret,next_secret,'private-dashboard-response62']), 'nonempty connection logs contain neither API secrets nor rejected response bodies')
        audit.update({'firstArchive': first['archiveSha256'], 'restoredArchive': restored['archiveSha256'], 'requestCount':len(admin()['requests']), 'proxyCount':len(admin()['proxyConnections']), 'logEntries':len(logs['entries'])})
    finally:
        with contextlib.suppress(Exception): audit['lastUIError'] = js('return document.querySelector("#dashboard-error")?.textContent')
        for identifier in pending:
            with contextlib.suppress(Exception): command('cancelDashboardInstallation', {'requestId':identifier})
        admin(release=True, mode='ok')
        with contextlib.suppress(Exception): command('disconnect')
        for section in ('network','core'):
            with contextlib.suppress(Exception): command('saveSettings', {'section':section,'previous':command('settings')[section],'values':original[section]})
        with contextlib.suppress(Exception): command('deleteGroup', {'id':group})
        (Path(h['args'].artifacts)/'dashboard-audit.json').write_text(json.dumps(audit,indent=2)+'\n')
