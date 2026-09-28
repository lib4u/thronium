"""Qt's traffic statistics in the real window: what the running profile carried,
what left directly, the period selector, the chart and the two breakdowns, plus
the source and speed columns of the connection list. Everything is loopback; no
address outside 127.0.0.0/8 is contacted."""
import http.client
import http.server
import ipaddress
import json
from select import select as wait_ready
import socket
import socketserver
import struct
import threading
import time

BODY = b'traffic-stats-fixture' + bytes(65536)


def run(h):
    command, click, select, wait_for, js, check, screenshot = (
        h[k] for k in ('command', 'click', 'select', 'wait_for', 'js', 'check', 'screenshot'))
    initial = command('snapshot')
    original_routing = command('routing')
    servers, sockets, clients = [], [], []

    class Handler(http.server.BaseHTTPRequestHandler):
        # Keep-alive, so the connection the window lists is still open.
        protocol_version = 'HTTP/1.1'

        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-Length', str(len(BODY)))
            self.end_headers()
            self.wfile.write(BODY)

        def log_message(self, *_):
            pass

    class Hop(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    class Socks(socketserver.BaseRequestHandler):
        """The one real server of this fixture, so the profile carries traffic
        of its own instead of dialling the destination directly."""

        def handle(self):
            incoming, upstream = self.request, None

            def read(count):
                data = b''
                while len(data) < count:
                    chunk = incoming.recv(count - len(data))
                    if not chunk:
                        raise EOFError()
                    data += chunk
                return data

            try:
                incoming.settimeout(8)
                version, count = read(2)
                if version != 5:
                    raise ValueError('SOCKS version')
                read(count)
                incoming.sendall(b'\x05\x00')
                version, operation, reserved, kind = read(4)
                if operation != 1:
                    raise ValueError('SOCKS operation')
                host = read(read(1)[0]).decode() if kind == 3 else str(
                    ipaddress.ip_address(read(4 if kind == 1 else 16)))
                port = struct.unpack('!H', read(2))[0]
                if not host.startswith('127.') or port != self.server.destination:
                    incoming.sendall(b'\x05\x05\x00\x01' + b'\x00' * 6)
                    return
                upstream = socket.create_connection((host, port), timeout=8)
                incoming.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
                while True:
                    ready, _, _ = wait_ready([incoming, upstream], [], [], 8)
                    if not ready:
                        return
                    for source in ready:
                        data = source.recv(65536)
                        if not data:
                            return
                        (upstream if source is incoming else incoming).sendall(data)
            except (OSError, EOFError, ValueError):
                pass
            finally:
                if upstream:
                    upstream.close()

    def poll(fn, accept, timeout=25, what='traffic'):
        until = time.monotonic() + timeout
        value = None
        while time.monotonic() < until:
            value = fn()
            if accept(value):
                return value
            time.sleep(.2)
        raise AssertionError('the window never reported ' + what + ': ' + json.dumps(value)[:600]
                             + ' connections=' + json.dumps([{k: c[k] for k in ('outbound', 'chain', 'destination')}
                                                             for c in command('snapshot')['connections']]))

    def stats(days=1):
        return command('trafficStats', {'days': days, 'utcOffsetMinutes': 0})

    def fetch(host, port, proxy_port):
        """One request through the app's own proxy, kept open afterwards so the
        window still lists the connection it counted."""
        client = http.client.HTTPConnection('127.0.0.1', proxy_port, timeout=8)
        clients.append(client)
        client.set_tunnel(host, port)
        client.request('GET', '/bytes')
        response = client.getresponse()
        return response.status == 200 and response.read() == BODY

    try:
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            proxy_port = probe.getsockname()[1]
        server = http.server.ThreadingHTTPServer(('0.0.0.0', 0), Handler)
        server.daemon_threads = True
        http_port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        hop = Hop(('127.0.0.1', 0), Socks)
        hop.destination = http_port
        threading.Thread(target=hop.serve_forever, daemon=True).start()
        servers.append(hop)
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark',
                                'connectionMode': 'local', 'inboundPort': proxy_port})
        wait_for('return document.documentElement.lang==="en"')
        settings = command('settings')['logging']
        command('saveSettings', {'section': 'logging', 'previous': settings,
                                 'values': {**settings, 'disable_traffic_aggregation': False,
                                            'disable_traffic_stats': False}})
        # One address is carried by the profile, the other leaves without it.
        routing = command('routing')
        active = next(p for p in routing['profiles'] if p['id'] == routing['active'])
        active['rules'] = [{'id': 'traffic-direct', 'name': 'Counted directly', 'enabled': True,
                            'config': {'ip_cidr': ['127.0.0.2/32'], 'action': 'route', 'outbound': 'direct'}}]
        command('saveRouting', routing)
        profile = command('saveProfile', {'name': 'Counted server', 'groupId': 'personal',
                                          'kind': 'sing-box-outbound',
                                          'config': {'type': 'socks', 'server': '127.0.0.1',
                                                     'server_port': hop.server_address[1]}})['id']
        command('connect', {'id': profile})
        poll(lambda: command('snapshot')['phase'], lambda p: p == 'connected', what='a running connection')
        check(fetch('127.0.0.1', http_port, proxy_port), 'the request the profile carries reaches the fixture')
        check(fetch('127.0.0.2', http_port, proxy_port), 'the request routed past the profile reaches the fixture')
        live = poll(lambda: command('snapshot')['connections'], lambda c: len(c) >= 2, what='two listed connections')
        check(sorted({c['outbound'] for c in live}) == ['direct', 'proxy'],
              'the window lists one connection through the profile and one past it: ' + json.dumps([{k: c[k] for k in ('outbound', 'destination')} for c in live]))
        # Both legs are counted on the session's own schedule, so wait for each.
        counted = poll(stats, lambda s: any(r['id'] == profile and r['download'] > 0 for r in s['profiles']['rows']),
                       what='bytes credited to the running profile')
        by_id = {row['id']: row for row in counted['profiles']['rows']}
        check(profile in by_id and by_id[profile]['name'] == 'Counted server' and by_id[profile]['download'] > 0,
              'the running profile is credited by name with what it carried: ' + json.dumps(counted['profiles']['rows']) + ' connections=' + json.dumps([{k: c[k] for k in ('outbound', 'chain', 'destination', 'upload', 'download')} for c in command('snapshot')['connections']]))
        direct = poll(stats, lambda s: any(r['direct'] and r['download'] > 0 for r in s['profiles']['rows']),
                      what='direct bytes')
        direct_row = next(r for r in direct['profiles']['rows'] if r['direct'])
        check(direct_row['id'] == 'direct' and direct_row['name'] == '' and not direct_row['other'],
              'what left without the profile is counted apart, as Qt counts Direct')
        check(sum(r['upload'] for r in direct['profiles']['rows']) == direct['profiles']['upload']
              and sum(r['download'] for r in direct['applications']['rows']) == direct['applications']['download'],
              'both breakdowns hold exactly the bytes of their own table')
        def covers(period):
            series = period['profiles']['series']
            size, first, last = period['bucketSeconds'], series[0], series[-1]
            return (first['bucket'] <= period['from'] < first['bucket'] + size
                    and last['bucket'] < period['to'] <= last['bucket'] + size
                    and all(b['bucket'] - a['bucket'] == size
                            for a, b in zip(series, series[1:])))
        check(counted['bucketSeconds'] == 3600 and covers(counted),
              'a day of statistics is read hour by hour, every hour of the window present')
        for days in (7, 30, 90):
            period = stats(days)
            check(period['bucketSeconds'] == 86400 and covers(period)
                  and period['to'] - period['from'] == days * 86400,
                  'a period of ' + str(days) + ' days is read day by day')
        try:
            command('trafficStats', {'days': 5, 'utcOffsetMinutes': 0})
        except RuntimeError as error:
            assert 'invalid_command_payload' in str(error), str(error)
        else:
            raise AssertionError('the engine accepted a period it does not offer')

        click('.primary-nav button:nth-child(3)')
        wait_for('return !!document.querySelector("[data-traffic-stats] [data-traffic-chart]")')
        check(js('return document.querySelectorAll("[data-traffic-chart] [data-traffic-bucket]").length')
              == len(stats()['profiles']['series']),
              'the window draws every hour of the day, including the empty ones')
        totals = js('return document.querySelector("[data-traffic-totals]").textContent')
        check(totals.count('·') == 2 and any(c.isdigit() for c in totals),
              'the window states downloaded, uploaded and total for the period: ' + totals)
        rows = js('return [...document.querySelectorAll("[data-traffic-table=profiles] tbody tr td:first-child")].map(e=>e.textContent)')
        check('Counted server' in rows and 'Direct' in rows,
              'the server breakdown names the profile and the direct row')
        screenshot('traffic-stats-day-en')
        select('#traffic-period', '7')
        wait_for('return document.querySelectorAll("[data-traffic-chart] [data-traffic-bucket]").length==='
                 + str(len(stats(7)['profiles']['series'])))
        check(True, 'choosing another period redraws the chart for its own buckets')
        click('[data-traffic-tab=applications]')
        wait_for('return !!document.querySelector("[data-traffic-table=applications]")')
        check(js('return document.querySelectorAll("[data-traffic-table=applications] tbody tr").length') > 0,
              'the application breakdown lists what used the connection')

        speeds = js('return [...document.querySelectorAll("[data-connection-speed]")].map(e=>e.textContent.trim())')
        headers = js('return [...document.querySelectorAll(".feature-table thead th")].map(e=>e.textContent)')
        check('Source' in headers and 'Speed' in headers,
              'the connection list carries Qt\'s source and speed columns')
        check(all('/' in text for text in speeds), 'every listed connection shows its own rate')
        command('preferences', {**command('snapshot')['preferences'], 'language': 'ru'})
        wait_for('return document.documentElement.lang==="ru"')
        h['request']('POST', h['base'] + '/window/rect', {'width': 390, 'height': 844})
        wait_for('return !!document.querySelector("[data-traffic-stats]")')
        check(js('return document.querySelector("[data-traffic-stats]").scrollWidth <= document.querySelector("[data-traffic-stats]").clientWidth + 1'),
              'the statistics panel fits a 390px window in Russian')
        screenshot('traffic-stats-week-ru')
        (h['artifacts'] / 'traffic-stats.json').write_text(json.dumps(
            {'day': counted, 'week': stats(7)}, indent=2) + '\n')
    finally:
        h['request']('POST', h['base'] + '/window/rect', {'width': 1280, 'height': 900})
        with __import__('contextlib').suppress(Exception):
            command('disconnect')
        command('saveRouting', {**original_routing, 'revision': command('routing')['revision']})
        command('preferences', initial['preferences'])
        for found in command('snapshot')['profiles']:
            if found['name'] == 'Counted server':
                command('deleteProfiles', {'ids': [found['id']]})
        command('clearTrafficHistory')
        for server in servers:
            server.shutdown()
            server.server_close()
        for opened in sockets:
            opened.close()
        for client in clients:
            with __import__('contextlib').suppress(Exception):
                client.close()
