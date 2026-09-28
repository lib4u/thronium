"""Deep-link import of TrustTunnel profiles and real HTTP/2 and HTTP/3 tunnels to an owned endpoint."""
import http.client
import json
import os
from pathlib import Path
import socket
import urllib.request

WARNING = 'Link parameter not applied by the app: '


def run(h):
    command, check, click, fill, select, wait_for, js = (h[k] for k in ('command', 'check', 'click', 'fill', 'select', 'wait_for', 'js'))
    fixture = json.loads(Path(os.environ['_THRONIUM_TRUSTTUNNEL_FIXTURE']).read_text())
    links, order, ports = fixture['links'], fixture['order'], fixture['ports']
    initial = command('snapshot'); assert not initial['profiles']
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0)); proxy_port = reservation.getsockname()[1]
    command('preferences', {**initial['preferences'], 'language': 'en', 'connectionMode': 'local', 'inboundPort': proxy_port})
    group = command('saveGroup', {'name': 'Owned TrustTunnel endpoint', 'subscription': None})['id']
    audit = {'transfers': [], 'review': None}
    host, port = fixture['target'][len('http://'):].split(':')
    try:
        socket.create_connection((host, int(port)), timeout=2).close(); reachable = True
    except OSError:
        reachable = False
    check(not reachable, 'the origin address is unreachable without the endpoint route')

    # Every link goes through the dialog users paste links into, in one paste.
    click('.primary-nav button:first-child'); click('.add-connection'); click('#add-choice-link')
    fill('#import-source', '\n'.join(links[name] for name in order))
    wait_for('return [...document.querySelector("#import-group").options].some(o=>o.value===' + json.dumps(group) + ')')
    select('#import-group', group); click('#import-review')
    wait_for('return document.querySelectorAll(".import-select").length===' + str(len(order)))
    rows = js('return [...document.querySelectorAll(".import-row")].map(r=>({name:r.querySelector(".import-name").value,'
              'summary:r.querySelector("small").textContent,warnings:[...r.querySelectorAll(".import-warnings li")].map(e=>e.textContent),'
              'error:r.classList.contains("has-error")}))')
    audit['review'] = rows
    check([r['name'] for r in rows] == [fixture['names'][n] for n in order], 'review shows each link name, including Unicode, in paste order')
    check(not any(r['error'] for r in rows), 'every deep link is recognized')
    check([r['summary'] for r in rows] == ['trusttunnel · 127.0.0.1'] * len(order), 'review shows the type and the dialed address taken from the link')
    warned = {n: r['warnings'] for n, r in zip(order, rows) if r['warnings']}
    check(warned == {'full': [WARNING + n for n in ('addresses', 'anti_dpi', 'client_random_prefix', 'dns_upstreams', 'tag_14')]},
          'only unsupported link parameters are listed, by name')
    check(js('return !!document.querySelector("#import-acknowledge") && document.querySelector("#import-save").disabled'),
          'unapplied link parameters require acknowledgement before import')
    click('#import-acknowledge'); click('#import-save')
    wait_for('return !document.querySelector("dialog[open]")')
    profiles = {p['name']: p['id'] for p in command('snapshot')['profiles']}
    check(len(profiles) == len(order), 'all deep links are saved as profiles')
    ids = {n: profiles[fixture['names'][n]] for n in order}

    configs = {n: command('profile', {'id': ids[n]})['config'] for n in order}
    h2 = {'type': 'trusttunnel', 'server': '127.0.0.1', 'server_port': ports['any'], 'username': fixture['username'],
          'password': fixture['password'], 'tls': {'enabled': True, 'server_name': fixture['serverName'], 'certificate': fixture['certificatePem']}}
    check(configs['h2'] == h2, 'HTTP/2 link maps hostname to SNI, address to server and the DER chain to PEM lines')
    check(configs['h3'] == {**h2, 'server_port': ports['udp'], 'quic': True}, 'HTTP/3 upstream selects QUIC towards the UDP listener')
    check(configs['old'] == h2, 'old tt:// spelling without ? decodes identically')
    check(configs['insecure'] == {**h2, 'tls': {'enabled': True, 'server_name': '127.0.0.1', 'insecure': True}},
          'skip-verification link sets insecure and carries no certificate')
    check(configs['full'] == h2, 'extra addresses, anti-DPI, prefix, DNS upstreams and unknown tags do not change the profile')
    check(configs['wrong']['password'] not in (fixture['password'], '') and configs['h2udp']['server_port'] == ports['udp'],
          'negative profiles keep their own credentials and listener')
    rejected = None
    try:
        command('checkProfile', command('profile', {'id': ids['h2']}))
    except RuntimeError as error:
        rejected = str(error)
    check(rejected is None, 'the real core accepts the imported TrustTunnel configuration')

    def records():
        with urllib.request.urlopen(fixture['records'], timeout=3) as response: return json.load(response)

    def transfer(name, expect, reason):
        command('connect', {'id': ids[name]})
        check(command('snapshot')['running'] == ids[name], name + ': the real core starts with the imported profile')
        before = len(records()); path = '/tt/' + name
        client = http.client.HTTPConnection('127.0.0.1', proxy_port, timeout=8)
        try:
            client.request('GET', fixture['target'] + path)
            response = client.getresponse(); outcome = (response.status, response.read().decode('utf-8', 'replace'))
        except (OSError, http.client.HTTPException) as error:
            outcome = ('error', type(error).__name__)
        finally:
            client.close()
        new = records()[before:]
        command('disconnect')
        audit['transfers'].append({'name': name, 'outcome': list(outcome), 'records': new})
        if expect:
            check(outcome == (200, 'tt-origin:' + path) and len(new) == 1 and new[0]['path'] == path and new[0]['host'] == host + ':' + port,
                  name + ': ' + reason)
        else:
            check(outcome[0] != 200 and not new, name + ': ' + reason)

    transfer('h2', True, 'HTTP/2 over TLS pinned by the link certificate reaches the origin behind the endpoint route')
    transfer('h3', True, 'HTTP/3 over QUIC reaches the origin through the UDP-only listener')
    transfer('insecure', True, 'skip-verification link tunnels without a pinned certificate')
    transfer('old', True, 'old spelling tunnels like the current one')
    transfer('full', True, 'first address is dialed; ignored parameters do not break the tunnel')
    transfer('wrong', False, 'wrong password is refused by the endpoint and nothing reaches the origin')
    transfer('h2udp', False, 'HTTP/2 towards the UDP-only listener cannot connect')
    check(command('snapshot')['running'] is None, 'stand ends disconnected')
    (Path(h['artifacts']) / 'trusttunnel-audit.json').write_text(json.dumps(audit, indent=2, ensure_ascii=False) + '\n')
