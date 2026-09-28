"""An actual OpenConnect (CSTP) tunnel in the real window: the server asks its
own form, the window shows what the server built, traffic goes through it, and
the same endpoint carries a chain to an exit that only the tunnel can reach.
Loopback and the private tunnel network of this namespace only."""
import contextlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import socket
import time


def run(h):
    command, click, fill, wait_for, js, check, screenshot = (
        h[k] for k in ('command', 'click', 'fill', 'wait_for', 'js', 'check', 'screenshot'))
    ready = json.loads(Path(os.environ['_THRONIUM_OPENCONNECT_CSTP_READY']).read_text())
    initial = command('snapshot')
    profiles, clients = [], []
    network = ipaddress.ip_network(ready['network'])

    def endpoints():
        return command('snapshot')['vpn']['endpoints']

    def until(accept, timeout=90, what='the endpoint'):
        end = time.monotonic() + timeout
        last = None
        while time.monotonic() < end:
            last = endpoints()
            row = next((row for row in last if accept(row)), None)
            if row:
                return row
            time.sleep(.3)
        raise AssertionError(what + ' never settled: ' + json.dumps(last))

    def openconnect(credentials):
        result = {'type': 'openconnect', 'server': ready['server'], 'flavor': 'anyconnect',
                  'system': False, 'no_udp': True,
                  'tls': {'certificate_authority_path': ready['certificate']}}
        if credentials:
            result.update(username=ready['user'], password=ready['password'])
        return result

    def add(name, config, kind='sing-box-outbound'):
        identifier = command('saveProfile', {'name': name, 'groupId': 'personal',
                                             'kind': kind, 'config': config})['id']
        profiles.append(identifier)
        return identifier

    def fetch(host, port, path):
        """One request through the app's own proxy; the answer states the
        address the fixture saw it arrive from."""
        client = http.client.HTTPConnection('127.0.0.1', proxy_port, timeout=20)
        clients.append(client)
        client.set_tunnel(host, port)
        client.request('GET', path)
        response = client.getresponse()
        body = response.read()
        # Left open, so the window still lists the connection it carried.
        return {'ok': response.status == 200 and len(body) == ready['body'],
                'remote': response.headers.get('X-Fixture-Remote')}

    def carrying(tag, timeout=20):
        end = time.monotonic() + timeout
        listed = []
        while time.monotonic() < end:
            listed = command('snapshot')['connections']
            if any(row['outbound'] == tag for row in listed):
                return listed
            time.sleep(.3)
        return listed

    try:
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            proxy_port = probe.getsockname()[1]
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark',
                                'connectionMode': 'local', 'inboundPort': proxy_port})
        wait_for('return document.documentElement.lang==="en"')

        # A profile the server has to ask about: the window shows the actual
        # form of the server and the answers go back over its own HTTPS session.
        asked = add('OpenConnect CSTP', openconnect(False))
        command('connect', {'id': asked})
        row = until(lambda r: r['challengeId'], what='a server form')
        tag = row['tag']
        current = {'sessionId': command('snapshot')['vpn']['sessionId'],
                   'endpointTag': tag, 'challengeId': row['challengeId']}
        check(row['protocol'] == 'openconnect' and row['state'] == 'auth-pending',
              'the window holds the connection while the OpenConnect server asks: ' + json.dumps(row['state']))
        wait_for('return !!document.querySelector(' + json.dumps('[data-vpn-open=' + json.dumps(tag) + ']') + ')')
        click('[data-vpn-open=' + json.dumps(tag) + ']')
        wait_for('return !!document.querySelector("#vpn-auth-form")')
        details = command('vpnChallenge', current)
        kinds = [item['kind'] for item in details['fields']]
        check(kinds == ['text', 'password'],
              'the form is the one the server sent, field for field: ' + json.dumps(details['fields']))
        password_key = next(item['submissionKey'] for item in details['fields'] if item['kind'] == 'password')
        check(js('return document.querySelector(arguments[0]).type==="password"',
                 '[data-vpn-field=' + json.dumps(password_key) + ']'),
              'the password the server asks for stays masked in the window')
        screenshot('openconnect-cstp-form-en')
        for item in details['fields']:
            fill('[data-vpn-field=' + json.dumps(item['submissionKey']) + ']',
                 ready['password'] if item['kind'] == 'password' else ready['user'])
        click('#vpn-auth-submit')
        row = until(lambda r: r['state'] == 'connected', what='an answered CSTP tunnel')
        wait_for('return !document.querySelector(".vpn-auth-modal")')

        # What the server built: the address out of its own pool, the route and
        # the resolver it pushed.
        tunnel = row['tunnel']
        check(tunnel is not None and all(ipaddress.ip_interface(value).ip in network for value in tunnel['ipv4']),
              'the tunnel holds the address the server handed out: ' + json.dumps(tunnel))
        check(ready['network'] in tunnel['routes'] and ready['serverAddress'] in tunnel['dns'],
              'the window states the route and the resolver of the server: ' + json.dumps(tunnel))
        wait_for('return !!document.querySelector(' + json.dumps('[data-vpn-endpoint=' + json.dumps(tag) + '] [data-vpn-tunnel]') + ')')
        shown = js('return [...document.querySelectorAll("[data-vpn-tunnel] .desktop-details div")]'
                   '.map(e=>e.querySelector("dd").textContent)')
        check(any(tunnel['ipv4'][0] in text for text in shown)
              and any(ready['serverAddress'] in text for text in shown),
              'the endpoint card shows the address and the resolver of the tunnel: ' + json.dumps(shown))
        screenshot('openconnect-cstp-connected-en')

        # Actual traffic: the file behind the server is fetched through the
        # tunnel, and the fixture sees the request arrive from the tunnel.
        carried_in = fetch(ready['serverAddress'], ready['httpPort'], '/through-tunnel')
        check(carried_in['ok'] and ipaddress.ip_address(carried_in['remote']) in network,
              'a request through the connection reaches the service behind the server, '
              'arriving from inside the tunnel: ' + json.dumps(carried_in))
        carried = carrying(tag)
        check(any(c['outbound'] == tag for c in carried),
              'the window lists the request as carried by the OpenConnect endpoint: '
              + json.dumps([{k: c[k] for k in ('outbound', 'destination')} for c in carried]))
        command('disconnect')
        idle = time.monotonic() + 20
        while command('snapshot')['vpn']['endpoints'] and time.monotonic() < idle:
            time.sleep(.3)

        # The same server as a node of a chain: the exit is a hop that only the
        # tunnel can reach, so the chain is carried by the CSTP session.
        hop = add('OpenConnect CSTP hop', openconnect(True))
        exit_profile = add('Hop behind the tunnel', {'type': 'socks', 'server': ready['serverAddress'],
                                                     'server_port': ready['socksPort']})
        chain = add('Chain through OpenConnect', {'type': 'chain', 'hops': [hop, exit_profile]}, 'chain')
        command('connect', {'id': chain})
        row = until(lambda r: r['state'] == 'connected', what='a chain node')
        check(row['tag'] != 'proxy' and row['tunnel'] is not None,
              'the OpenConnect endpoint is a node of the chain, not its exit: ' + row['tag'])
        # The exit of the chain refuses everything that does not come from the
        # tunnel, so an answer at all is the proof the node carried it.
        through = fetch('127.0.0.1', ready['httpPort'], '/through-chain')
        check(through['ok'],
              'the chain reaches its exit through the OpenConnect node and carries the answer back: '
              + json.dumps(through))
        check(command('profile', {'id': hop})['config']['password'] == ready['password'],
              'the node signs in with the credentials of its own profile, unasked')
        command('preferences', {**command('snapshot')['preferences'], 'language': 'ru'})
        wait_for('return document.documentElement.lang==="ru"')
        h['request']('POST', h['base'] + '/window/rect', {'width': 390, 'height': 844})
        wait_for('return !!document.querySelector("[data-vpn-tunnel]")')
        check(js('const e=document.querySelector(".vpn-endpoints");'
                 'return e.scrollWidth<=e.clientWidth+1'),
              'the endpoint card with the tunnel details fits a 390px window in Russian')
        screenshot('openconnect-cstp-chain-ru-390')
        (h['artifacts'] / 'openconnect-cstp.json').write_text(json.dumps(
            {'server': ready['version'], 'tunnel': tunnel, 'fields': details['fields']}, indent=2) + '\n')
    finally:
        h['request']('POST', h['base'] + '/window/rect', {'width': 1280, 'height': 900})
        with contextlib.suppress(Exception):
            command('disconnect')
        for client in clients:
            with contextlib.suppress(Exception):
                client.close()
        for identifier in reversed(profiles):
            with contextlib.suppress(Exception):
                command('deleteProfiles', {'ids': [identifier]})
        command('preferences', initial['preferences'])
