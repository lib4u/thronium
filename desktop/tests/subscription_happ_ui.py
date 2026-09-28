"""Happ FakeDNS, IPOnDemand and chunked lists through the native subscription flow."""
import contextlib
import json
import socket
import uuid

from subscription_happ_fixture import Server


def run(h):
    command, click, wait_for, js, check, screenshot = (
        h[k] for k in ('command', 'click', 'wait_for', 'js', 'check', 'screenshot')
    )
    initial = command('snapshot')
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        socks_port = reservation.getsockname()[1]
    server = Server(socks_port)
    groups = []

    def close():
        if js('return !!document.querySelector("dialog[open]")'):
            click('#main-modal > .modal-head > button')
            wait_for('return !document.querySelector("dialog[open]")')

    def subscribe(name, variant, use_routing):
        server.variant = variant
        group = command('saveGroup', {'name': name, 'subscription': {
            'url': server.url, 'headers': {}, 'viaProxy': False, 'intervalMinutes': 0,
            'useProviderRouting': use_routing, 'inheritDefaults': False}})['id']
        groups.append(group)
        response = command('fetchSubscription', {'id': group, 'requestId': str(uuid.uuid4())})
        member = {'name': 'Happ member', 'groupId': group, 'kind': 'sing-box-outbound',
                  'config': {'type': 'socks', 'server': '127.0.0.1', 'server_port': socks_port, 'version': '5'}}
        command('previewSubscription', {'ticket': response['ticket'], 'profiles': [member]})
        return group, response

    def parts(profile_id):
        return {p['name']: p['config'] for p in command('connectionConfiguration', {'id': profile_id, 'active': False})['parts']}

    def member(group):
        return next(p['id'] for p in command('snapshot')['profiles'] if p['groupId'] == group)

    def reject(name, payload, code):
        try:
            command(name, payload)
        except RuntimeError as error:
            assert code in str(error), str(error)
        else:
            raise AssertionError(f'{name} accepted {code}')

    try:
        command('disconnect')
        command('preferences', {**initial['preferences'], 'language': 'en'})
        wait_for('return document.documentElement.lang==="en"')
        group, response = subscribe('Happ FakeDNS', 'fakedns', True)
        check(response['providerRouting']['fakeDns'] is True and response['providerRouting']['enabled'] is True,
              'the downloaded policy summary reports FakeDNS without exposing provider addresses')
        check('192.0.2.7' not in json.dumps(response['providerRouting']), 'the routing summary keeps DNS hosts private')
        command('applySubscription', {'ticket': response['ticket'], 'useProviderRouting': True})
        fake = member(group)
        core = parts(fake)['sing-box']
        servers = core['dns']['servers']
        check(any(s['type'] == 'fakeip' and s['tag'] == 'dns-fake' and s['inet4_range'] == '198.18.0.0/15' for s in servers),
              'Happ FakeDNS compiles into a sing-box FakeIP server with the Throne ranges')
        rules = core['dns']['rules']
        check(rules[0]['server'] == 'dns-hosts' and rules[1]['server'] == 'dns-fake' and rules[2]['server'] in ('dns-remote', 'dns-direct'),
              'FakeIP answers follow the provider hosts and precede the site rules')
        check(core['dns'].get('independent_cache') is True and core['route']['rules'][0]['action'] == 'sniff',
              'FakeIP keeps an independent cache and sniffing recovers the domain for routing')
        command('checkProfile', command('profile', {'id': fake}))
        check(True, 'the real Core accepts the FakeIP policy of the subscription')
        # The subscription dialog explains the translation before applying.
        # The group was applied over IPC; the window sees it on its next snapshot poll.
        menu = f'[data-group-menu="{group}"]'
        wait_for(f'return !!document.querySelector({json.dumps(menu)})')
        js(f'document.querySelector({json.dumps(menu)}).scrollIntoView({{block:"center"}})')
        click(menu)
        click('#update-subscription')
        click('#subscription-load')
        wait_for('return !!document.querySelector("#subscription-routing-fakeip")')
        check('FakeIP' in js('return document.querySelector("#subscription-routing-fakeip").textContent')
              and js('return document.querySelector("#subscription-use-routing").checked'),
              'the subscription review names the FakeIP translation and keeps the routing choice enabled')
        screenshot('subscription-happ-fakeip-en')
        command('preferences', {**command('snapshot')['preferences'], 'language': 'ru'})
        wait_for('return document.documentElement.lang==="ru"')
        check('FakeIP' in js('return document.querySelector("#subscription-routing-fakeip").textContent'),
              'the Russian review carries the same FakeIP note')
        screenshot('subscription-happ-fakeip-ru')
        close()
        command('preferences', {**command('snapshot')['preferences'], 'language': 'en'})
        wait_for('return document.documentElement.lang==="en"')

        group, response = subscribe('Happ IPOnDemand', 'ondemand', True)
        command('applySubscription', {'ticket': response['ticket'], 'useProviderRouting': True})
        demand = member(group)
        route_rules = parts(demand)['sing-box']['route']['rules']
        actions = [r.get('action', 'route') + ('-ip' if 'ip_cidr' in r else '') for r in route_rules]
        first_ip = actions.index('route-ip')
        check(actions[first_ip - 1] == 'resolve' and actions.count('resolve') == 1,
              'IPOnDemand resolves once, immediately before the first IP rule in RouteOrder position')
        command('checkProfile', command('profile', {'id': demand}))

        group, response = subscribe('Happ chunked', 'chunked', True)
        # Apply compiles the provider policy before publishing it, so an
        # unusable policy is refused there rather than on the first connect.
        reject('applySubscription', {'ticket': response['ticket'], 'useProviderRouting': True}, 'subscription_chunk_files_unsupported')
        check(command('snapshot')['running'] is None and not any(p['groupId'] == group for p in command('snapshot')['profiles']),
              'chunked provider lists are refused before the policy is published or any Core starts')
        command('applySubscription', {'ticket': response['ticket'], 'useProviderRouting': False})
        chunked = member(group)
        command('checkProfile', command('profile', {'id': chunked}))
        check(True, 'the same servers import and pass the real Core once provider routing is off')

        group, response = subscribe('Happ onadd', 'onadd', False)
        check(response['providerRouting']['enabled'] is True and response['providerRouting']['fakeDns'] is False,
              'a first `onadd` policy is offered enabled even when the group was created without provider routing')
        command('applySubscription', {'ticket': response['ticket'], 'useProviderRouting': False})
        response = command('fetchSubscription', {'id': group, 'requestId': str(uuid.uuid4())})
        check(response['providerRouting']['enabled'] is False, 'an explicit user choice survives later `onadd` downloads')
        command('discardSubscription', {'ticket': response['ticket']})
        (h['artifacts'] / 'subscription-happ-audit.json').write_text(json.dumps({'requests': len(server.requests), 'groups': len(groups)}, indent=2) + '\n')
    finally:
        with contextlib.suppress(Exception):
            close()
            command('disconnect')
            for group in groups:
                command('deleteGroup', {'id': group, 'deleteProfiles': True})
            command('clearSubscriptionJobs')
            command('preferences', initial['preferences'])
        server.close()
