"""Shared diagnostics capture real disposable cores without replacing the live core."""
import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import time


def run(h, group, active):
    command, select, fill, wait_for, check = (h[k] for k in ('command', 'select', 'fill', 'wait_for', 'check'))
    preferences = command('snapshot')['preferences']
    testing = command('settings')['testing']
    entered, release = threading.Event(), threading.Event()
    ids = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == '/slow':
                entered.set(); release.wait(10)
            with contextlib.suppress(OSError):
                body = b'p' * 65536
                self.send_response(200); self.send_header('Content-Length', str(len(body)))
                self.end_headers(); self.wfile.write(body)
        def log_message(self, *_): pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = f'http://127.0.0.1:{server.server_port}'

    def until(predicate, seconds=20):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            result = predicate()
            if result: return result
            time.sleep(.1)
        raise AssertionError('Disposable log observation timed out')
    def completed():
        b = command('snapshot')['urlTests']
        return b if b and all(e['status'] not in ('queued', 'testing') for e in b['entries']) else None
    def rows(): return command('getLogs', {'scope':'tests'})['entries']
    def settings(**values):
        previous = command('settings')['testing']
        command('saveSettings', {'section':'testing', 'previous':previous, 'values':{**previous, **values}})

    try:
        command('preferences', {**preferences, 'ping':{**preferences['ping'], 'method':'http'}})
        for name in ('Log test Alpha', 'Log test Beta'):
            ids.append(command('saveProfile', {'name':name, 'groupId':group, 'kind':'sing-box-outbound', 'config':{'type':'direct'}})['id'])
        command('startUrlTests', {'ids':ids, 'url':origin+'/latency', 'timeoutMs':1500})
        result = until(completed)
        assert all(e['status']=='ok' for e in result['entries'])
        until(lambda:len({e['probe']['runId'] for e in rows() if e['source']=='stdout'})==2)
        http_rows = rows()
        check({e['probe']['profileId'] for e in http_rows}==set(ids) and all(e['probe']['kind']=='http' for e in http_rows), 'concurrent HTTP cores retain distinct runs and exact profile identity in the shared log')
        check(any('Core Has Successfully Connected' in e['text'] for e in http_rows), 'test logs include actual disposable Core stdout rather than only synthetic progress messages')

        settings(speed_test_mode='simple', speed_test_timeout_ms=1000, simple_dl_url=origin+'/speed')
        command('testSpeed', {'id':ids[0]})
        command('startSpeedTests', {'ids':[ids[1]]}); until(completed)
        until(lambda:len({e['probe']['runId'] for e in rows() if e['probe']['kind']=='speed' and e['text']=='Test completed'})==2)
        check(True, 'both dialog and batch speed tests publish separate completed runs through the same capture path')

        command('startUrlTests', {'ids':[ids[0]], 'url':origin+'/slow', 'timeoutMs':3000})
        assert entered.wait(5)
        command('cancelUrlTests'); until(completed)
        until(lambda:any(e['text']=='Test cancelled' for e in rows()))
        release.set()
        check(True, 'cancelled checks leave a terminal message and keep captured Core output available')
        view = command('getLogs', {'scope':'session'})
        check(view['entries'] and all('probe' not in e for e in view['entries']), 'session filtering excludes test records while retaining the connection log')
        select('#log-scope','tests'); fill('#log-search','Log test Beta')
        wait_for('return document.querySelectorAll("[data-log-id]").length>0 && [...document.querySelectorAll("[data-log-id]")].every(e=>e.textContent.includes("Log test Beta"))')
        visible = command('getLogs', {'scope':'tests','search':'Log test Beta'})
        check(all(e['probe']['profileId']==ids[1] for e in visible['entries']), 'native context and profile-name filters isolate one profile across its test runs')
        h['screenshot']('probe-logs-en')
        snapshot = command('snapshot')
        check(snapshot['running']==active['running'] and snapshot['since']==active['since'] and 'logs' not in snapshot, 'test capture and log filtering preserve the active Core and keep raw messages out of snapshots')
        (h['artifacts']/'probe-log-audit.json').write_text(json.dumps({'entries':rows(),'httpBatch':result},indent=2)+'\n')
    finally:
        release.set()
        with contextlib.suppress(Exception):
            command('cancelUrlTests'); until(completed); command('clearUrlTests')
            current = command('settings')['testing']
            command('saveSettings', {'section':'testing','previous':current,'values':testing})
            command('preferences',preferences)
            for id in ids: command('delete',{'id':id})
            select('#log-scope','all'); fill('#log-search','')
        server.shutdown(); server.server_close()
