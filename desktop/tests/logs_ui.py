"""Real core output, sanitized CheckConfig errors, log controls and file export."""
import http.client
import http.server
import json
import pathlib
import socket
import tempfile
import threading
import time
from native_dialogs import file_dialog


def run(h):
    command, click, fill, select, wait_for, js, check, screenshot = (h[k] for k in ('command', 'click', 'fill', 'select', 'wait_for', 'js', 'check', 'screenshot'))
    initial=command('snapshot')
    if initial['running']: raise AssertionError('Log scenarios require the isolated suite to be disconnected')
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self,*_):pass
        def do_GET(self):
            self.send_response(200);self.send_header('Content-Length','7');self.end_headers();self.wfile.write(b'log-ok!')
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    group=command('saveGroup',{'name':'Log fixtures','subscription':None})['id']
    with socket.socket() as available:available.bind(('127.0.0.1',0));port=available.getsockname()[1]
    profile=command('saveProfile',{'name':'Log transport','groupId':group,'kind':'sing-box-config','config':{'log':{'level':'info','disabled':False},'inbounds':[{'type':'mixed','listen':'127.0.0.1','listen_port':port,'tag':'log-in'}],'outbounds':[{'type':'direct','tag':'direct'}],'route':{'final':'direct'}}})['id']
    bad={'name':'Log invalid','groupId':group,'kind':'sing-box-outbound','config':{'type':'does-not-exist','password':'diagnostic-secret'}}
    original_clipboard=None
    try:
        try:original_clipboard=command('readClipboard')
        except RuntimeError:pass
        command('preferences',{**initial['preferences'],'language':'en','theme':'dark'})
        command('clearLogs');command('connect',{'id':profile});active=command('snapshot')
        connection=http.client.HTTPConnection('127.0.0.1',port,timeout=5)
        connection.request('GET',f'http://127.0.0.1:{server.server_port}/log-fixture')
        response=connection.getresponse();assert response.read()==b'log-ok!';connection.close()
        click('.primary-nav button:nth-child(3)')
        wait_for('return document.querySelectorAll("[data-log-id]").length>1')
        view=command('getLogs')
        check(any(e['source'] in ('stdout','stderr') and ('outbound/direct' in e['text'] or 'sing-box started' in e['text']) for e in view['entries']), 'the diagnostic log captures actual stdout/stderr from the core carrying loopback traffic')
        check('logs' not in active and 'diagnostic-secret' not in json.dumps(active), 'ordinary state snapshots do not include raw log messages or configuration credentials')
        try:command('checkProfile',bad)
        except RuntimeError:pass
        wait_for('return document.querySelectorAll("[data-log-level=error]").length>0')
        view=command('getLogs')
        check(any('CheckConfig:' in e['text'] for e in view['entries']) and 'diagnostic-secret' not in json.dumps(view), 'configuration errors appear in the log without the upstream full-config credential dump')
        from probe_logs_ui import run as run_probe_logs
        run_probe_logs(h, group, active)
        select('#log-level','error');select('#log-source','app');fill('#log-search','CheckConfig')
        wait_for('return document.querySelectorAll("[data-log-id]").length>0 && [...document.querySelectorAll("[data-log-id]")].every(e=>e.dataset.logLevel==="error" && e.dataset.logCode==="check_config_failed" && e.textContent.includes("Configuration check failed:"))')
        check(True,'level, source and text filters isolate the expected diagnostic errors')
        click('#log-pause');time.sleep(.25)
        before=js('return [...document.querySelectorAll("[data-log-id]")].map(e=>e.dataset.logId)')
        try:command('checkProfile',bad)
        except RuntimeError:pass
        time.sleep(1.2)
        check(js('return [...document.querySelectorAll("[data-log-id]")].map(e=>e.dataset.logId)')==before,'pausing the log keeps the visible messages stable while native capture continues')
        click('#log-pause')
        wait_for('return document.querySelectorAll("[data-log-id]").length>'+str(len(before)))
        check(command('snapshot')['running']==profile and command('snapshot')['since']==active['since'],'reading, filtering and pausing diagnostics preserve the active connection')
        if original_clipboard is not None:
            click('#log-copy');wait_for('return document.querySelector("#log-notice")?.textContent.includes("copied")')
            copied=command('readClipboard')
            check('CheckConfig:' in copied and 'Connection started' not in copied and 'diagnostic-secret' not in copied,'copy-visible contains the filtered log with sanitized configuration errors')
        with tempfile.TemporaryDirectory(prefix='thronium-log-') as directory:
            path=pathlib.Path(directory)/'saved.log'
            click('#log-save');file_dialog('Save export',path)
            wait_for('return document.querySelector("#log-notice")?.textContent.includes("saved")')
            exported=path.read_text()
            check('CheckConfig:' in exported and 'Connection started' not in exported,'native log export saves the currently visible filtered entries')
        fill('#log-search','');select('#log-level','all');select('#log-source','all')
        command('preferences',{**command('snapshot')['preferences'],'language':'ru','theme':'light'})
        wait_for('return document.documentElement.lang==="ru"')
        h['request']('POST',h['base']+'/window/rect',{'width':390,'height':844})
        js('document.querySelector("#core-logs").scrollIntoView({block:"start"})')
        check(js('return document.querySelector("#core-logs h2").textContent==="Журнал ядра" && document.querySelector("#core-logs").scrollWidth<=document.querySelector("#core-logs").clientWidth'),'log controls and long messages fit the narrow native window in Russian')
        screenshot('core-log-narrow-ru')
        click('#log-clear');wait_for('return !document.querySelector("[data-log-id]")')
        check(command('getLogs')['total']==0 and command('snapshot')['running']==profile,'clearing diagnostics clears only the log buffer and keeps the core running')
        command('disconnect')
        wait_for('return [...document.querySelectorAll("[data-log-code=connection_stopped]")].some(e=>e.textContent.includes("Подключение остановлено"))')
        check(True,'connection stop events remain available after disconnection')
    finally:
        command('disconnect')
        if original_clipboard is not None:command('writeClipboard',{'text':original_clipboard})
        command('deleteGroup',{'id':group,'deleteProfiles':True});command('preferences',initial['preferences'])
        if initial['selected']:command('select',{'id':initial['selected']})
        click('.primary-nav button:nth-child(1)')
        h['request']('POST',h['base']+'/window/rect',{'width':1280,'height':860})
        server.shutdown();server.server_close();thread.join(timeout=2)
