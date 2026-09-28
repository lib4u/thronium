"""Opt-in scheduler through native settings, a real Core and owned HTTP traffic."""
import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import threading
import time


def run(h):
    command, click, fill, select, wait_for, js, check = (h[k] for k in ('command', 'click', 'fill', 'select', 'wait_for', 'js', 'check'))
    root = Path(os.environ['XDG_DATA_HOME'])
    assert root.parent.name.startswith('thronium-native-test-')
    initial = command('snapshot')
    assert not initial['profiles'] and initial['running'] is None
    old_testing = command('settings')['testing']
    geometry = h['request']('GET', h['base'] + '/window/rect')
    ids = []
    requests = []
    lock = threading.Lock()
    audit = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            with lock:
                requests.append(time.monotonic())
            body = b'x' * 8192
            self.send_response(200)
            self.send_header('Content-Length', str(len(body) * 256))
            self.end_headers()
            with contextlib.suppress(OSError):
                for _ in range(256):
                    self.wfile.write(body)
                    self.wfile.flush()
                    time.sleep(.005)
        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def settings(**values):
        previous = command('settings')['testing']
        return command('saveSettings', {'section': 'testing', 'previous': previous, 'values': {**previous, **values}})

    def saved():
        wait_for('return document.querySelector("#settings-save")?.disabled && !!document.querySelector("#setting-periodic_tests_kind:not(:disabled)")')

    def until(predicate, timeout=90):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(.25)
        raise AssertionError('Periodic probe deadline expired')

    try:
        command('preferences', {**initial['preferences'], 'language': 'en'})
        settings(speed_test_mode='simple', speed_test_timeout_ms=1500, simple_dl_url=f'http://127.0.0.1:{server.server_port}/speed', periodic_tests_enabled=False)
        for name in ('Scheduled favourite', 'Not scheduled'):
            ids.append(command('saveProfile', {'name': name, 'groupId': 'personal', 'kind': 'sing-box-outbound', 'config': {'type': 'direct'}})['id'])
        command('favorite', {'id': ids[0]})
        click('.primary-nav button:nth-child(5)')
        click('[data-settings-section=testing]')
        wait_for('return !!document.querySelector("#setting-periodic_tests_kind")')
        js('document.querySelector("#setting-periodic_tests_kind").closest("details").open=true')
        check(js('return [...document.querySelector("#setting-periodic_tests_kind").options].map(o=>o.value)') == ['latency', 'ip', 'speed'], 'periodic settings offer latency, exit IP and connection speed')
        check(not command('settings')['testing']['periodic_tests_enabled'] and not requests, 'periodic traffic is disabled by default')
        select('#setting-periodic_tests_kind', 'speed')
        fill('#setting-periodic_tests_interval_min', '1')
        click('#setting-periodic_tests_enabled')
        enabled_at = time.monotonic()
        click('#settings-save'); saved()
        check(command('settings')['testing']['periodic_tests_kind'] == 'speed', 'native Save persists the explicit choice to measure speed')
        h['request']('POST', h['base'] + '/window/rect', {'width': 390, 'height': 844})
        js('document.querySelector("#setting-periodic_tests_kind").scrollIntoView({block:"center"})')
        check(js('return document.documentElement.scrollWidth<=innerWidth+1'), 'periodic controls and the traffic explanation fit a narrow English window')
        h['screenshot']('periodic-speed-en-390')
        command('preferences', {**command('snapshot')['preferences'], 'language': 'ru'})
        wait_for('return document.documentElement.lang==="ru"')
        h['screenshot']('periodic-speed-ru-390')
        check(js('return document.querySelector("#setting-periodic_tests_kind").selectedOptions[0].textContent') == 'Скорость подключения', 'the periodic speed choice is translated into Russian')
        check(not requests, 'saving and changing interface language do not start an immediate speed burst')

        def completed():
            batch = command('snapshot')['urlTests']
            return batch if batch and batch['source'] == 'periodic' and all(row['status'] not in ('queued', 'testing') for row in batch['entries']) else None
        batch = until(completed)
        elapsed = time.monotonic() - enabled_at
        check(elapsed >= 59 and len(batch['entries']) == 1 and batch['entries'][0]['profileId'] == ids[0], 'the real host timer waits the full interval and measures only the favourite')
        row = batch['entries'][0]
        check(row['status'] == 'ok' and row['download'] and requests, 'periodic speed transfers actual HTTP data through the disposable Core')
        journal = command('getMeasurementJournal')['entries']
        result = next(entry for entry in journal if entry['source'] == 'periodic' and entry['profileId'] == ids[0])
        check(result['kind'] == 'speed' and result['download'] == row['download'] and command('snapshot')['running'] is None, 'the shared history records measured speed without starting the main connection')
        audit.update(elapsedSeconds=elapsed, batch=batch, journal=result, requests=len(requests))

        # A schedule edit must not cancel an independently started manual run.
        manual = command('startSpeedTests', {'ids': [ids[0]]})['id']
        settings(periodic_tests_enabled=False, periodic_tests_kind='ip')
        def manual_completed():
            current = command('snapshot')['urlTests']
            return current if current and current['id'] == manual and all(r['status'] not in ('queued', 'testing') for r in current['entries']) else None
        finished = until(manual_completed, 15)
        check(finished['source'] == 'manual' and finished['entries'][0]['status'] == 'ok', 'disabling the schedule and changing its type preserve a manual speed measurement')
        check(not command('settings')['testing']['periodic_tests_enabled'], 'periodic checks remain disabled after the manual result')
    finally:
        with contextlib.suppress(Exception):
            settings(periodic_tests_enabled=False)
            command('cancelUrlTests'); command('clearUrlTests')
            command('clearMeasurementJournal')
            for id in ids:
                command('delete', {'id': id})
            previous = command('settings')['testing']
            command('saveSettings', {'section': 'testing', 'previous': previous, 'values': old_testing})
            command('preferences', initial['preferences'])
            h['request']('POST', h['base'] + '/window/rect', geometry)
        server.shutdown(); server.server_close()
        (h['artifacts'] / 'periodic-speed-audit.json').write_text(json.dumps(audit, indent=2) + '\n')
