"""TUN settings and permission refusal in an ordinary unprivileged native window."""
import copy
import base64
import json
import os
from pathlib import Path
import socket


def run(h):
    command, click, fill, wait_for, js, check, screenshot = (h[k] for k in ('command', 'click', 'fill', 'wait_for', 'js', 'check', 'screenshot'))
    initial = command('snapshot')
    assert initial['running'] is None
    # This suite must never have permission to change the host network.
    caps = next(line.split()[1] for line in Path('/proc/self/status').read_text().splitlines() if line.startswith('CapEff:'))
    assert not int(caps, 16) & (1 << 12) and os.geteuid() != 0
    ids = []

    def rejects(name, payload, expected):
        try:
            command(name, payload)
        except RuntimeError as error:
            assert expected in str(error), str(error)
        else:
            raise AssertionError('Expected ' + expected)

    def select(selector, value):
        h['select'](selector, value)

    try:
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark'})
        click('.primary-nav button:last-child'); click('[data-settings-section=tun]')
        wait_for('return !!document.querySelector("#tun-mtu") && document.documentElement.lang==="en"')
        check(js('return !document.querySelector("#tun-mtu").disabled && !!document.querySelector("#settings-form")'), 'Linux window exposes experimental TUN settings')
        check(js('return document.querySelector("#settings-form").textContent.includes("rights through a system dialog")'), 'TUN explains its system permission request')
        check(js('return document.querySelector("#tun-reconnect").checked'), 'automatic TUN reconnect is enabled by default and exposed in settings')
        click('#tun-reconnect')
        click('#tun-permission')
        fill('#tun-mtu', '1279')
        check(js('return !document.querySelector("#tun-mtu").checkValidity()'), 'native form rejects an MTU below the supported IPv6 minimum')
        fill('#tun-mtu', '1420')
        select('#tun-stack', 'mixed')
        click('#tun-ipv6')
        click('#tun-strict')
        fill('#tun-excludes', '192.168.1.1/24')
        click('#settings-save')
        wait_for('return document.querySelector("#settings-form [role=alert]")?.textContent.includes("valid network CIDRs")')
        check(command('snapshot')['preferences']['connectionMode'] == initial['preferences']['connectionMode'], 'invalid CIDR is rejected atomically without changing the saved connection mode')
        fill('#tun-excludes', '192.168.0.0/16\n2001:db8::/32')
        click('#settings-save')
        wait_for('return document.querySelector("#settings-form [role=status]")?.textContent.includes("Saved")')
        saved = command('snapshot')['preferences']
        check(saved['connectionMode'] == initial['preferences']['connectionMode'] and saved['tun'] == {'autoReconnect': False, 'requestPermission': False, 'mtu': 1420, 'stack': 'mixed', 'ipv6': True, 'strictRoute': True, 'dnsHijack': True, 'systemDns': 'disabled', 'excludeAddresses': ['192.168.0.0/16', '2001:db8::/32']}, 'all TUN settings round-trip through the real Rust backend')
        select('[data-setting=tun_system_dns]', 'resolved')
        click('#settings-save')
        wait_for('return document.querySelector("#settings-form [role=status]")?.textContent.includes("Saved")')
        check(command('snapshot')['preferences']['tun']['systemDns'] == 'resolved', 'systemd-resolved mode persists through the actual settings backend')
        select('[data-setting=tun_system_dns]', 'resolvconf')
        click('#settings-save')
        wait_for('return document.querySelector("#settings-form [role=status]")?.textContent.includes("Saved")')
        check(command('snapshot')['preferences']['tun']['systemDns'] == 'resolvconf', 'openresolv mode persists through the actual settings backend')
        check(js('return document.querySelector("[data-setting=tun_system_dns] option:checked").textContent==="resolvconf (openresolv)"'), 'the DNS option names its required installed manager')
        click('#tun-dns')
        click('#settings-save')
        wait_for('return document.querySelector("#settings-form [role=alert]")?.textContent.includes("Enable DNS capture")')
        check(command('snapshot')['preferences']['tun']['dnsHijack'], 'system DNS cannot be saved without DNS interception')
        click('#tun-dns')
        select('[data-setting=tun_system_dns]', 'disabled')
        click('#settings-save')
        wait_for('return document.querySelector("#settings-form [role=status]")?.textContent.includes("Saved")')
        h['request']('POST', h['base'] + '/refresh', {})
        wait_for('return !!document.querySelector(".primary-nav")')
        click('.primary-nav button:last-child'); click('[data-settings-section=tun]')
        wait_for('return document.querySelector("#tun-mtu")?.value==="1420"')
        check(js('return document.querySelector("#tun-stack").value==="mixed" && document.querySelector("#tun-ipv6").checked && !document.querySelector("#tun-reconnect").checked'), 'saved TUN options survive a webview reload')
        js('document.querySelector("#settings-form").scrollIntoView({block:"start"})')
        screenshot('tun-settings-dark-en')
        for field, value in [('mtu', 9001), ('excludeAddresses', ['::/129'])]:
            invalid = copy.deepcopy(saved)
            invalid['tun'][field] = value
            rejects('preferences', invalid, 'invalid_tun_settings')
        check(command('snapshot')['preferences']['tun'] == saved['tun'], 'direct command callers cannot bypass TUN validation')
        with socket.socket() as free:
            free.bind(('127.0.0.1', 0))
            port = free.getsockname()[1]
        command('connectionSettings', {'mode': 'tun', 'port': port})
        pid = command('saveProfile', {'name': 'TUN permission fixture', 'groupId': 'personal', 'kind': 'sing-box-outbound', 'config': {'type': 'direct'}})['id']
        ids.append(pid)
        command('select', {'id': pid})
        click('.primary-nav button:first-child')
        wait_for('return !!document.querySelector(".connection-options .network-mode[title=TUN]")')
        click('.power-button')
        wait_for('return document.querySelector(".desktop-error")?.textContent.includes("Enable permission requests")')
        after = command('snapshot')
        check(after['running'] is None and after['phase'] == 'disconnected' and not after['systemProxy']['active'], 'unprivileged TUN fails before starting a listener or changing the system proxy')
        check(not Path('/sys/class/net/thronium-tun').exists(), 'permission refusal leaves no TUN interface on the host')
        screenshot('tun-permission-en')
        command('preferences', {**after['preferences'], 'language': 'ru', 'theme': 'light'})
        wait_for('return document.querySelector(".desktop-error")?.textContent.includes("Включите запрос прав")')
        click('.primary-nav button:last-child'); click('[data-settings-section=tun]')
        h['request']('POST', h['base'] + '/window/rect', {'width': 390, 'height': 844})
        wait_for('return window.innerWidth<=410 && !!document.querySelector("#settings-form") && document.querySelector("#settings-form").clientWidth<400')
        check(js('return document.querySelector("#settings-form").scrollWidth<=document.querySelector("#settings-form").clientWidth'), 'Russian TUN fields and limits fit the narrow native window')
        js('document.querySelector("#settings-form").scrollIntoView({block:"start"})')
        wait_for('return document.querySelector("#settings-form").getBoundingClientRect().top<200')
        # X11's backing pixmap can still contain the pre-resize frame. Snapshot
        # this viewport through WebKit, after its narrow layout has settled.
        image = h['request']('GET', h['base'] + '/screenshot')
        (h['artifacts'] / 'tun-settings-narrow-ru.png').write_bytes(base64.b64decode(image))
        command('connectionSettings', {'mode': 'local', 'port': port})
        command('connect', {'id': pid})
        changed = copy.deepcopy(command('snapshot')['preferences'])
        changed['tun']['mtu'] = 1500
        rejects('preferences', changed, 'stop_before_editing')
        wait_for('return document.querySelector("#tun-mtu").matches(":disabled")')
        check(True, 'active connection locks both native controls and direct TUN preference changes')
        command('disconnect')
        command('connectionSettings', {'mode': 'tun', 'port': port})
        raw = command('saveProfile', {'name': 'TUN opaque fixture', 'groupId': 'personal', 'kind': 'sing-box-config', 'config': {'outbounds': [{'type': 'direct'}]}})['id']
        ids.append(raw)
        try:
            command('connect', {'id': raw})
        except RuntimeError as error:
            # On an unprivileged host the managed TUN permission guard runs
            # before profile compilation; privileged/fixture runs reach the
            # more specific full-JSON incompatibility check.
            message = str(error)
            assert 'tun_permission_required' in message or 'tun_incompatible' in message, message
        else:
            raise AssertionError('Expected TUN permission or compatibility refusal')
        check(command('snapshot')['running'] is None, 'full JSON profile is refused without starting a connection')
    finally:
        command('disconnect')
        command('preferences', initial['preferences'])
        for pid in ids:
            command('delete', {'id': pid})
        if initial['selected']:
            command('select', {'id': initial['selected']})
        h['request']('POST', h['base'] + '/window/rect', {'width': 1280, 'height': 860})
        click('.primary-nav button:first-child')
        wait_for('return document.body.classList.contains("disconnected") && document.documentElement.lang===' + json.dumps(initial['preferences']['language']))
