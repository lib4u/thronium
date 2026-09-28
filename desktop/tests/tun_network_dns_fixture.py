"""Network DNS changes with actual Core, resolver and native recovery; owned netns only."""
import json
import time
from pathlib import Path


def run(h, dns, current_worker, forward_http):
    from openresolv_fixture import call
    command, check = h['command'], h['check']
    assert dns.local_probe and dns.next_server
    audit = {}
    old = current_worker()
    call(['-a', 'eth0.dhcp'], '# renewed now\nsearch old.test\nnameserver 192.0.2.53\n')
    time.sleep(11)
    check(current_worker() == old, 'a DHCP renewal with unchanged DNS does not restart the active worker')

    call(['-a', 'eth0.dhcp'], 'search new.test\nnameserver 198.51.100.53\n')
    started = time.monotonic()
    while time.monotonic() - started < 25:
        state = command('snapshot')
        try:
            if current_worker() != old and state['phase'] == 'connected':
                break
        except (ValueError, FileNotFoundError):
            pass
        time.sleep(.2)
    else:
        (h['artifacts'] / 'network-dns-failure.json').write_text(json.dumps({'phase': state['phase'], 'logs': command('getLogs')}, indent=2) + '\n')
        raise AssertionError('network DNS change did not reconnect')
    fresh = current_worker()
    audit['reconnectSeconds'] = round(time.monotonic() - started, 3)
    check(fresh != old and '172.19.0.2' in Path('/etc/resolv.conf').read_text(), 'changed network DNS replaces the worker and reapplies its owned TUN policy')
    dns.expected_address = '198.18.0.81'
    before = dns.server_counts.get('198.51.100.53', 0)
    dns.query('After physical DNS change')
    forward_http()
    check(dns.server_counts.get('198.51.100.53', 0) > before, 'real DNS uses the new physical server and HTTP resumes after network recovery')
    time.sleep(11)
    check(current_worker() == fresh, 'the refreshed network baseline prevents a reconnect loop')

    # The recovery preference is scoped to a connection. Reconnect explicitly
    # with it off before changing DHCP again; existing sockets stay with worker.
    command('disconnect')
    preferences = command('snapshot')['preferences']
    command('preferences', {**preferences, 'tun': {**preferences['tun'], 'autoReconnect': False}})
    command('connect', {'id': command('snapshot')['selected']})
    h['wait_for']('return document.querySelector(".live-indicator").textContent.includes("Active")')
    disabled_worker = current_worker()
    call(['-a', 'eth0.dhcp'], 'search old.test\nnameserver 192.0.2.53\n')
    time.sleep(11)
    check(current_worker() == disabled_worker and command('snapshot')['phase'] == 'connected', 'disabled automatic recovery preserves the worker after a physical DNS change')
    dns.query('Recovery disabled')
    command('disconnect')
    command('preferences', preferences)
    command('connect', {'id': command('snapshot')['selected']})
    h['wait_for']('return document.querySelector(".live-indicator").textContent.includes("Active")')
    dns.expected_address = '198.18.0.80'
    dns.query('Explicit reconnect')
    audit.update(oldWorker=old, refreshedWorker=fresh, serverQueries=dns.server_counts, disabledPreferenceRespected=True, renewedRecordDidNotRestart=True, noReconnectLoop=True)
    (h['artifacts'] / 'network-dns-audit.json').write_text(json.dumps(audit, indent=2) + '\n')
