"""Qt's library maintenance in the real window: removing unavailable, invalid and
insecure servers, replacing names with addresses, the group setting that prunes
after a test and resetting traffic. Fixtures are local or documentation
addresses; no server is contacted except a closed loopback port."""
import json
import time

UUID = '00000000-0000-4000-8000-000000000001'


def run(h):
    command, click, fill, select, wait_for, js, check, screenshot = (
        h[k] for k in ('command', 'click', 'fill', 'select', 'wait_for', 'js', 'check', 'screenshot'))
    initial = command('snapshot')
    group = command('saveGroup', {'name': 'Maintenance fixtures', 'subscription': None})['id']

    def add(name, config):
        return command('saveProfile', {'name': name, 'groupId': group, 'kind': 'sing-box-outbound', 'config': config})['id']

    def profile(name):
        return next((p for p in command('snapshot')['profiles'] if p['name'] == name), None)

    def shown():
        return js('return [...document.querySelectorAll(".row-server-info strong")].map(e=>e.textContent).sort()')

    def listed():
        return js('return [...document.querySelectorAll("#maintenance-list [data-maintenance-profile] strong")].map(e=>e.textContent).sort()')

    def open_action(action):
        click('#library-more')
        wait_for('return !!document.querySelector("#library-' + action + '")')
        click('#library-' + action)
        wait_for('return !!document.querySelector("#maintenance-confirm")')

    def close_dialog():
        js('const all=[...document.querySelectorAll("dialog[open]")];all[all.length-1]?.querySelector(".modal-head>button")?.click()')
        wait_for('return !document.querySelector("dialog[open]")')

    def tested(name, status, timeout=25):
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            found = profile(name)
            if found and (found.get('measurement') or {}).get('status') == status:
                return found
            time.sleep(.2)
        raise AssertionError('server ' + name + ' never reported ' + status)

    try:
        command('disconnect')
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'light', 'librarySort': 'original'})
        h['request']('POST', h['base'] + '/window/rect', {'width': 1280, 'height': 900})
        testing = command('settings')['testing']
        command('saveSettings', {'section': 'testing', 'previous': testing,
                                 'values': {**testing, 'ping_method': 'tcp', 'url_test_timeout_ms': 1500}})
        unreachable = add('Unreachable server', {'type': 'socks', 'server': '192.0.2.20', 'server_port': 1080})
        tls = {'enabled': True, 'server_name': 'example.test'}
        insecure = add('Plain vless', {'type': 'vless', 'server': '192.0.2.10', 'server_port': 443, 'uuid': UUID})
        secure = add('Secure vless', {'type': 'vless', 'server': '192.0.2.11', 'server_port': 443, 'uuid': UUID, 'tls': tls})
        named = add('Named server', {'type': 'vless', 'server': 'localhost', 'server_port': 443, 'uuid': UUID, 'tls': tls})
        invalid = add('Broken transport', {'type': 'vless', 'server': '192.0.2.12', 'server_port': 443, 'uuid': UUID,
                                          'tls': tls, 'transport': {'type': 'not-a-real-transport'}})
        wait_for('return document.documentElement.lang==="en" && [...document.querySelector(".group-strip select").options].some(o=>o.value===' + json.dumps(group) + ')')
        select('.group-strip select', group)
        wait_for('return document.querySelectorAll(".connection-row").length===5')

        command('startPing', {'ids': [unreachable]})
        tested('Unreachable server', 'error')
        # The window polls its snapshot, so wait until the row itself shows the failure.
        wait_for('return document.querySelectorAll("[data-probe-status=error]").length===1')
        open_action('unavailable')
        check(listed() == ['Unreachable server'], 'remove unavailable lists the server whose test failed and nothing else')
        screenshot('library-unavailable-en')
        click('#maintenance-confirm')
        wait_for('return !document.querySelector("dialog[open]") && document.querySelectorAll(".connection-row").length===4')
        check(profile('Unreachable server') is None and profile('Plain vless') is not None,
              'confirming removes exactly the unavailable servers')

        open_action('insecure')
        check(listed() == ['Plain vless'], 'remove insecure lists servers without encryption, not the ones behind TLS')
        click('#maintenance-confirm')
        wait_for('return !document.querySelector("dialog[open]") && document.querySelectorAll(".connection-row").length===3')
        check(profile('Plain vless') is None and profile('Secure vless') is not None,
              'confirming removes exactly the insecure servers')

        open_action('invalid')
        wait_for('return !document.querySelector("#maintenance-progress")')
        check(listed() == ['Broken transport'], 'remove invalid asks the core about every displayed server and lists the refused one')
        screenshot('library-invalid-en')
        click('#maintenance-confirm')
        wait_for('return !document.querySelector("dialog[open]") && document.querySelectorAll(".connection-row").length===2')
        check(profile('Broken transport') is None, 'confirming removes the server the core refused')

        open_action('resolve')
        check(listed() == ['Named server'], 'replacing domains lists only servers addressed by name')
        click('#maintenance-confirm')
        wait_for('return !document.querySelector("dialog[open]")')
        resolved = profile('Named server')
        loopback = ['127.0.0.1', '::1']
        check(resolved and resolved['address'] in loopback and command('profile', {'id': named})['config']['server'] in loopback
              and 'Addresses replaced: 1 of 1' in js('return document.querySelector(".toast").textContent'),
              'the resolved address replaces the name in the stored configuration and the window reports it')

        click('#bulk-select-toggle')
        click('#bulk-select-visible')
        wait_for('return !document.querySelector("#bulk-reset-traffic").disabled')
        click('#bulk-reset-traffic')
        wait_for('return !!document.querySelector(".toast")')
        check('Traffic reset' in js('return document.querySelector(".toast").textContent'),
              'the selection can forget its counted traffic, as Qt resets it')
        click('#bulk-select-toggle')

        check(command('group', {'id': group}).get('subscription') is None,
              'a group without a subscription is read back by the window instead of failing the contract')
        click('.group-strip .icon-button')
        wait_for('return !!document.querySelector(' + json.dumps('[data-group-edit="' + group + '"]') + ')')
        click('[data-group-edit="' + group + '"]')
        wait_for('return !!document.querySelector("#group-auto-clear-unavailable")')
        click('#group-auto-clear-unavailable')
        screenshot('library-group-auto-clear-en')
        click('#group-save')
        wait_for('return !!document.querySelector("#group-new")')
        close_dialog()
        check(command('group', {'id': group})['autoClearUnavailable'] is True,
              'the group form saves Qt\'s setting that prunes unavailable servers after a test')
        again = add('Unreachable again', {'type': 'socks', 'server': '192.0.2.21', 'server_port': 1080})
        command('startPing', {'ids': [again]})
        until = time.monotonic() + 30
        while time.monotonic() < until and profile('Unreachable again'):
            time.sleep(.2)
        check(profile('Unreachable again') is None, 'a finished test removes the unavailable servers of an opted-in group')
        check(profile('Secure vless') is not None, 'servers that answered are kept')
    finally:
        command('preferences', initial['preferences'])
        for name in ['Unreachable server', 'Plain vless', 'Secure vless', 'Named server', 'Broken transport', 'Unreachable again']:
            found = profile(name)
            if found:
                command('deleteProfiles', {'ids': [found['id']]})
        command('deleteGroup', {'id': group, 'deleteProfiles': True})
