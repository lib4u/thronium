"""Against an actual OpenVPN 2.7 server that refuses a login: the connection is
started again with a one-time code of its own until the server accepts, and a
VPN node that is not the exit of the connection can be signed in to again.
Loopback and synthetic values only."""
import contextlib
import json
import os
from pathlib import Path
import time
import urllib.request

SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'


def run(h):
    command, click, fill, wait_for, js, check, screenshot = (
        h[k] for k in ('command', 'click', 'fill', 'wait_for', 'js', 'check', 'screenshot'))
    ready = json.loads(Path(os.environ['_THRONIUM_OPENVPN_PENDING_READY']).read_text())
    initial = command('snapshot')
    profiles, entries = [], []

    def admin(**values):
        request = urllib.request.Request(ready['admin'],
                                         data=json.dumps(values).encode() if values else None,
                                         headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.load(response)

    def openvpn(username, password):
        return {'type': 'openvpn-client', 'server': '127.0.0.1',
                'server_port': ready['openvpnPort'], 'network': 'udp', 'system': False,
                'username': username, 'password': password,
                'tls': {'certificate_path': ready['certificate'],
                        'server_name': ready['serverName']}}

    def add(name, config, kind='sing-box-outbound'):
        identifier = command('saveProfile', {'name': name, 'groupId': 'personal',
                                             'kind': kind, 'config': config})['id']
        profiles.append(identifier)
        return identifier

    def endpoints():
        return command('snapshot')['vpn']['endpoints']

    def until(accept, timeout=90, what='the endpoint'):
        end = time.monotonic() + timeout
        last = None
        while time.monotonic() < end:
            last = endpoints()
            if last and accept(last[0]):
                return last[0]
            time.sleep(.3)
        raise AssertionError(what + ' never settled: ' + json.dumps(last))

    def journal():
        return [entry.get('code') for entry in command('getLogs', {})['entries']]

    try:
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark',
                                'connectionMode': 'local'})
        wait_for('return document.documentElement.lang==="en"')

        # A server that refuses the first codes: the connection comes back with
        # digits it has not used yet until the server is satisfied.
        admin(case='restart', clear=True)
        code = command('otpSave', {'value': {'name': 'Restart fixture', 'issuer': 'Owned VPN fixture',
                                             'secret': SECRET, 'algorithm': 'SHA1', 'type': 'hotp',
                                             'digits': 6, 'period': 30, 'counter': '0'}})
        entries.append(code['id'])
        baked = add('Restarting OpenVPN', openvpn(ready['user'], '{otp}'))
        view = command('getVpnOtpBinding', {'profileId': baked})
        command('saveVpnOtpBinding', {'profileId': baked, 'editToken': view['editToken'],
                                      'otpId': code['id'],
                                      'otpRevision': command('otpGet', {'id': code['id']})['revision'],
                                      'mode': 'auto-start'})
        command('connect', {'id': baked})
        row = until(lambda r: r['state'] == 'connected', what='a connection after refused codes')
        observed = admin()
        check(observed['distinctCodes'] >= 3 and observed['codeCount'] == observed['distinctCodes'],
              'every attempt carried a code of its own and none was sent twice: ' + json.dumps(observed))
        check('vpn_otp_restarted' in journal(),
              'the journal records that the connection was started again for a fresh code')
        check(row['tunnel'] is not None,
              'the connection the server finally accepted is a tunnel like any other')
        screenshot('vpn-restart-connected-en')
        command('disconnect')

        # A VPN node that is not the exit: the person signs in to it again.
        admin(case='relogin', clear=True)
        hop = add('Chained OpenVPN', openvpn('wrong-user', ready['password']))
        # The exit only has to be a valid hop: the sign-in of the first one is
        # what this case is about, and no traffic reaches the exit before it.
        exit_profile = add('Chain exit', {'type': 'socks', 'server': '127.0.0.1',
                                          'server_port': 1080})
        chain = add('VPN hop chain', {'type': 'chain', 'hops': [hop, exit_profile]}, 'chain')
        try:
            command('connect', {'id': chain})
        except RuntimeError as error:
            raise AssertionError('connecting the chain failed: ' + str(error) + ' journal='
                                 + json.dumps(journal()[-12:])) from error
        row = until(lambda r: r['authFailed'], what='a refused hop')
        tag = row['tag']
        check(tag != 'proxy', 'the refused endpoint is a hop of the chain, not its exit: ' + tag)
        wait_for('return !!document.querySelector(' + json.dumps('[data-vpn-credentials=' + tag + ']') + ')')
        click('[data-vpn-credentials=' + tag + ']')
        wait_for('return !!document.querySelector("#vpn-credentials-username")')
        check(js('return document.querySelector("#vpn-credentials-username").value') == 'wrong-user',
              'the dialog starts from the user the profile holds')
        screenshot('vpn-relogin-hop-en')
        fill('#vpn-credentials-username', ready['reloginUser'])
        fill('#vpn-credentials-password', ready['password'])
        stored = command('profile', {'id': hop})['config']
        click('#vpn-credentials-submit')
        row = until(lambda r: r['state'] == 'connected', what='a hop signed in to again')
        check(row['tag'] == tag and row['tunnel'] is not None,
              'the hop of the chain is connected with the new sign-in')
        check(command('profile', {'id': hop})['config'] == stored,
              'signing in again never writes the temporary answers into the profile')
        command('disconnect')

        # A code baked before Start for a node the chain carries, not its exit.
        admin(case='accept', clear=True)
        composite_code = command('otpSave', {'value': {
            'name': 'Composite fixture', 'issuer': 'Owned VPN fixture', 'secret': SECRET,
            'algorithm': 'SHA1', 'type': 'hotp', 'digits': 6, 'period': 30, 'counter': '0'}})
        entries.append(composite_code['id'])
        inner = add('Chained OpenVPN with a code', openvpn(ready['user'], '{otp}'))
        binding = command('getVpnOtpBinding', {'profileId': inner})
        command('saveVpnOtpBinding', {'profileId': inner, 'editToken': binding['editToken'],
                                      'otpId': composite_code['id'],
                                      'otpRevision': command('otpGet', {'id': composite_code['id']})['revision'],
                                      'mode': 'auto-start'})
        composite = add('Chain with a bound hop', {'type': 'chain', 'hops': [inner, exit_profile]}, 'chain')
        command('connect', {'id': composite})
        row = until(lambda r: r['state'] == 'connected', what='a bound hop of a chain')
        check(row['tag'] != 'proxy' and command('otpGet', {'id': composite_code['id']})['counter'] == '1',
              'a hop of the chain receives its own code before Start and connects: ' + row['tag'])
        check('{otp}' in json.dumps(command('profile', {'id': inner})['config']),
              'the code is never written into the profile of the hop')
        command('disconnect')

        # The same chain measured by a manual URL test. The code is baked
        # into the node the chain carries, so the disposable test box brings the
        # tunnel up without any question to the person.
        before = command('otpGet', {'id': composite_code['id']})['counter']
        batch = command('startUrlTests', {'ids': [composite], 'method': 'http',
                                          'url': 'http://127.0.0.1:1/probe', 'timeoutMs': 4000})['id']
        end = time.monotonic() + 90
        measured = None
        while time.monotonic() < end:
            entries = (command('snapshot').get('urlTests') or {'entries': []})['entries']
            if entries and entries[0]['status'] not in ('queued', 'testing'):
                measured = entries[0]
                break
            time.sleep(.3)
        spent = command('otpGet', {'id': composite_code['id']})['counter']
        check(measured is not None and measured['status'] == 'connected-only',
              'the measured chain brought its bound node up: ' + json.dumps(measured))
        check(int(spent) == int(before) + 1,
              'the test spent exactly one step of the code: ' + before + ' -> ' + spent)
        check('{otp}' in json.dumps(command('profile', {'id': inner})['config']),
              'a measured chain never writes the code into the node it carries')
        (h['artifacts'] / 'vpn-restart.json').write_text(json.dumps(
            {'openvpnVersion': ready['openvpnVersion'], 'restart': observed,
             'relogin': admin(), 'composite': {'batch': batch, 'entry': measured}}, indent=2) + '\n')
    finally:
        with contextlib.suppress(Exception):
            command('disconnect')
        for identifier in reversed(profiles):
            with contextlib.suppress(Exception):
                command('deleteProfiles', {'ids': [identifier]})
        for identifier in entries:
            with contextlib.suppress(Exception):
                command('otpRemove', {'id': identifier,
                                      'revision': command('otpGet', {'id': identifier})['revision']})
        command('preferences', initial['preferences'])
