"""The window against an actual OpenVPN 2.7 server that parks the client in
`client-pending-auth`. Every flow of the protocol is driven from the server:
a text challenge, a notice with nothing to answer, a link to open, a deadline
that lapses, and the dynamic CRV1 challenge a refusal carries. The established
tunnel then shows what the server pushed. Loopback and synthetic values only."""
import json
import os
from pathlib import Path
import time
import urllib.request


def run(h):
    command, click, fill, wait_for, js, check, screenshot = (
        h[k] for k in ('command', 'click', 'fill', 'wait_for', 'js', 'check', 'screenshot'))
    ready = json.loads(Path(os.environ['_THRONIUM_OPENVPN_PENDING_READY']).read_text())
    initial = command('snapshot')
    profiles = []

    def admin(**values):
        request = urllib.request.Request(ready['admin'],
                                         data=json.dumps(values).encode() if values else None,
                                         headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.load(response)

    def config(**extra):
        return {'type': 'openvpn-client', 'tag': 'proxy', 'server': '127.0.0.1',
                'server_port': ready['openvpnPort'], 'network': 'udp', 'system': False,
                'username': ready['user'], 'password': ready['password'],
                'tls': {'certificate_path': ready['certificate'],
                        'server_name': ready['serverName']},
                **extra}

    def add(name, **extra):
        identifier = command('saveProfile', {'name': name, 'groupId': 'personal',
                                             'kind': 'sing-box-outbound',
                                             'config': config(**extra)})['id']
        profiles.append(identifier)
        return identifier

    def endpoint():
        return next((row for row in command('snapshot')['vpn']['endpoints']
                     if row['tag'] == 'proxy'), None)

    def until(accept, timeout=40, what='the endpoint'):
        end = time.monotonic() + timeout
        last = None
        while time.monotonic() < end:
            last = endpoint()
            if last and accept(last):
                return last
            time.sleep(.25)
        raise AssertionError(what + ' never settled: ' + json.dumps(last))

    def open_dialog():
        wait_for('return !!document.querySelector("[data-vpn-open=proxy]")')
        click('[data-vpn-open=proxy]')
        wait_for('return !!document.querySelector(".vpn-auth-modal")')

    def stop():
        command('disconnect')
        until(lambda row: True, timeout=5, what='a stopped endpoint') if endpoint() else None

    try:
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark',
                                'connectionMode': 'local'})
        wait_for('return document.documentElement.lang==="en"')

        # A text challenge the server sends while the client waits.
        admin(case='text', clear=True)
        text_profile = add('Pending text')
        command('connect', {'id': text_profile})
        row = until(lambda r: r['challengeKind'] == 'secret', what='a text challenge')
        check(row['state'] == 'auth-pending',
              'an OpenVPN 2.7 server parks the client and the window says so')
        open_dialog()
        check(ready['textChallenge'] in js('return document.querySelector(".vpn-auth-modal").textContent'),
              'the text the server sent is shown to the person answering it')
        check(js('return !!document.querySelector("#vpn-auth-deadline")'),
              'the deadline the server set is shown with the challenge')
        # The server asked for the answer to be echoed, so it is not masked.
        check(js('return document.querySelector("#vpn-auth-secret").type') == 'text',
              'the echo flag of the challenge decides whether the answer is masked')
        screenshot('openvpn-pending-text-en')
        fill('#vpn-auth-secret', ready['answer'])
        click('#vpn-auth-submit')
        row = until(lambda r: r['state'] in ('connected', 'error'), what='a finished sign-in')
        check(row['state'] == 'connected', 'answering the challenge establishes the tunnel')
        tunnel = row['tunnel']
        check(tunnel and tunnel['cipher'] and tunnel['mtu'] > 0 and tunnel['ipv4'],
              'the established tunnel reports its own cipher, MTU and address: ' + json.dumps(tunnel))
        check('10.79.9.1' in tunnel['dns'] and any('10.79.8.0' in route for route in tunnel['routes']),
              'the DNS server and route the server pushed are reported as its own: ' + json.dumps(tunnel))
        wait_for('return !!document.querySelector("[data-vpn-tunnel]")')
        shown = js('return document.querySelector("[data-vpn-tunnel]").textContent')
        check(tunnel['cipher'] in shown and '10.79.9.1' in shown,
              'the window shows what the server built, as Qt shows endpoint details')
        screenshot('openvpn-pending-tunnel-en')
        stop()

        # A notice has nothing to answer; acknowledging it lets the client in.
        admin(case='notice', clear=True)
        command('connect', {'id': add('Pending notice')})
        row = until(lambda r: r['challengeKind'] == 'message', what='a notice')
        open_dialog()
        check(ready['notice'] in js('return document.querySelector(".vpn-auth-modal").textContent')
              and not js('return !!document.querySelector("#vpn-auth-secret")'),
              'a notice is shown without asking for an answer')
        click('#vpn-auth-submit')
        check(until(lambda r: r['state'] in ('connected', 'error'))['state'] == 'connected',
              'acknowledging the notice finishes the sign-in')
        stop()

        # A link the person is asked to open; the window never navigates itself.
        admin(case='url', clear=True)
        command('connect', {'id': add('Pending link')})
        until(lambda r: r['challengeKind'] == 'open-url', what='a link challenge')
        open_dialog()
        # The link arrives with the challenge details the dialog asks for.
        wait_for('return !!document.querySelector("#vpn-auth-url")')
        check(js('return document.querySelector("#vpn-auth-url").textContent') == ready['openUrl'],
              'the link the server sent is shown as text for the person to open')
        check(js('return !!document.querySelector("#vpn-auth-browser") && !document.querySelector("#vpn-auth-submit")'),
              'a link is offered to open, not an answer to type')
        screenshot('openvpn-pending-url-en')
        # The person follows the link outside the tunnel; the window only waits.
        click('#vpn-auth-close')
        wait_for('return !document.querySelector(".vpn-auth-modal")')
        check(until(lambda r: r['state'] in ('connected', 'error'))['state'] == 'connected',
              'the sign-in finishes once the server sees the link was followed')
        stop()

        # A deadline the server sets and nobody answers.
        admin(case='expired', clear=True)
        command('connect', {'id': add('Pending deadline')})
        pending = until(lambda r: r['challengeKind'] == 'secret',
                        what='a challenge with a deadline')
        started = time.monotonic()
        # Nobody answers: the server withdraws the challenge when its own
        # deadline passes and the client is left to start over.
        row = until(lambda r: r['challengeId'] != pending['challengeId'], timeout=60,
                    what='a lapsed challenge')
        check(time.monotonic() - started >= ready['expirySeconds'] - 1,
              'the challenge stands until the deadline the server set has passed')
        check(row['state'] != 'connected' and not row['tunnel'],
              'a challenge nobody answered never becomes a tunnel: ' + json.dumps(row))
        stop()

        # The dynamic challenge a refusal carries (CRV1).
        admin(case='crv1', clear=True)
        command('connect', {'id': add('Pending CRV1')})
        row = until(lambda r: r['challengeKind'] == 'secret', what='a dynamic challenge')
        open_dialog()
        check(ready['crv1Text'] in js('return document.querySelector(".vpn-auth-modal").textContent'),
              'the dynamic challenge of the refusal is shown as its own question')
        fill('#vpn-auth-secret', ready['answer'])
        click('#vpn-auth-submit')
        check(until(lambda r: r['state'] in ('connected', 'error'))['state'] == 'connected',
              'the answer packed for the dynamic challenge is accepted by the server')
        observed = admin()
        check(any(entry.get('crResponse') or entry.get('answered') for entry in observed['seen'])
              or 'client-auth-nt' in observed['sent'],
              'the server itself confirms it accepted the answer: ' + json.dumps(observed)[:400])
        stop()
        (h['artifacts'] / 'openvpn-pending.json').write_text(json.dumps(
            {'openvpnVersion': ready['openvpnVersion'], 'observed': observed}, indent=2) + '\n')
    finally:
        with __import__('contextlib').suppress(Exception):
            command('disconnect')
        for identifier in profiles:
            with __import__('contextlib').suppress(Exception):
                command('deleteProfiles', {'ids': [identifier]})
        command('preferences', initial['preferences'])
