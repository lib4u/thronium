"""Managed live and before-Start OTP lifecycle checks in guarded private namespaces."""
import contextlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time

from native_menu import NativeMenu
from native_processes import core_pids
from vpn_otp_fixture import SECRET, USER, code_at


def run(h):
    command, check = h['command'], h['check']
    ns = {kind: os.readlink('/proc/self/ns/' + kind) for kind in ['net', 'mnt', 'user']}
    assert os.geteuid() == 0 and all(value != os.environ['THRONIUM_TEST_ORIGINAL_' + kind.upper() + 'NS'] for kind, value in ns.items())
    assert not Path('/run/dbus/system_bus_socket').exists()
    ready = json.loads(Path(os.environ['_THRONIUM_VPN_OTP_READY']).read_text())
    app = Path(h['args'].application).resolve()
    core = app.with_name('ThroniumCore')
    menu = NativeMenu()
    assert Path('/proc', str(menu.pid), 'exe').resolve() == app
    assert os.readlink('/proc/' + str(menu.pid) + '/ns/net') == ns['net']
    initial = command('snapshot')
    audit = {'snapshots': [], 'kills': [], 'stale': [], 'namespaces': ns,
             'hostPolkitTested': False, 'authViaManagedWorker': True,
             'vpnDataTunnelHttpTested': False, 'hiddenWithoutPollingTested': False}
    xdg = Path(os.environ['XDG_DATA_HOME'])
    assert xdg.parent.name.startswith('thronium-native-test-')
    library = xdg / 'io.thronium.desktop/library.json'
    group = command('saveGroup', {'name': 'Managed automatic OTP namespace fixture', 'subscription': None})['id']
    otp_id = None
    start_otp_ids = []
    exited = False

    def until(predicate, timeout=18):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            value = predicate()
            if value:
                return value
            time.sleep(.07)
        raise AssertionError('managed OTP condition timed out')

    def ip(*args):
        return json.loads(subprocess.check_output(['ip', '-j', *args], text=True))

    def network():
        return {'links': [(row['ifindex'], row['ifname']) for row in ip('link')],
                'rules4': ip('-4', 'rule'), 'rules6': ip('-6', 'rule'),
                'routes4': ip('-4', 'route', 'show', 'table', 'all'),
                'routes6': ip('-6', 'route', 'show', 'table', 'all')}

    baseline = network()

    def journals():
        return {str(path): path.read_bytes() for path in Path('/run/thronium-tun').glob('net-*.json')}

    def lease_available():
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as lease:
            try:
                lease.bind('\0thronium-tun-18900')
                return True
            except OSError:
                return False

    def active_network():
        return socket.if_nametoindex('thronium-tun') > 0 and bool(journals()) and not lease_available()

    def snapshot():
        value = command('snapshot')
        assert SECRET not in json.dumps(value), 'private OTP key in public snapshot'
        audit['snapshots'].append({'running': value['running'], 'phase': value['phase'], 'vpn': value['vpn']})
        return value

    def entry():
        return command('otpGet', {'id': otp_id})

    def events():
        path = Path(ready['events'])
        return [row for line in path.read_text().splitlines() if (row := json.loads(line))['case'] == '/otp/hotp-two'] if path.exists() else []

    def verified():
        return [row for row in events() if row.get('otpExact')]

    def request():
        def current():
            state = snapshot()['vpn']
            row = next((row for row in state['endpoints'] if row['tag'] == 'proxy' and row['challengeId']), None)
            return row and {'sessionId': state['sessionId'], 'endpointTag': 'proxy', 'challengeId': row['challengeId']}
        return until(current)

    def identity(pid):
        row = Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()
        assert row[0] not in ('Z', 'X')
        return {'pid': int(pid), 'ppid': int(row[1]), 'starttime': int(row[19])}

    def worker_ids(guardian_pid):
        children = set()
        for task in Path('/proc', str(guardian_pid), 'task').glob('*/children'):
            with contextlib.suppress(OSError):
                children.update(int(child) for child in task.read_text().split())
        return {child for child in children if Path('/proc', str(child), 'exe').resolve() == core}

    def pair():
        pairs = []
        for pid in core_pids(menu.pid):
            guardian = identity(pid)
            assert guardian['ppid'] == menu.pid and Path('/proc', str(pid), 'exe').resolve() == core
            for child in worker_ids(pid):
                worker = identity(child)
                assert worker['ppid'] == int(pid)
                assert os.readlink('/proc/' + str(child) + '/ns/net') == ns['net']
                pairs.append((guardian, worker))
        assert len(pairs) == 1, 'expected exactly one owned guardian/worker'
        return pairs[0]

    def stale(name, payload):
        try:
            command(name, payload)
        except RuntimeError as error:
            assert 'vpn_auth_stale' in str(error) and SECRET not in str(error)
            audit['stale'].append(name)
            return
        raise AssertionError('old managed OTP session accepted')

    try:
        command('disconnect')
        command('preferences', {**initial['preferences'], 'language': 'en', 'connectionMode': 'tun'})
        otp_id = command('otpSave', {'value': {'name': 'Managed next HOTP', 'issuer': 'Owned namespace',
            'secret': SECRET, 'algorithm': 'SHA1', 'type': 'hotp', 'digits': 6, 'period': 30, 'counter': '0'}})['id']
        config = dict(ready['endpoints']['hotp-two'])
        config.pop('tag', None)
        profile = command('saveProfile', {'name': 'Managed generated HOTP C1/C2', 'groupId': group,
            'kind': 'sing-box-outbound', 'config': config})['id']
        view = command('getVpnOtpBinding', {'profileId': profile})
        command('saveVpnOtpBinding', {'profileId': profile, 'editToken': view['editToken'],
            'otpId': otp_id, 'otpRevision': entry()['revision']})
        command('connect', {'id': profile})
        until(lambda: len(verified()) == 2)
        old = request()
        guardian, worker = pair()
        check([row['counter'] for row in verified()] == ['1', '2'] and entry()['counter'] == '2' and active_network(),
              'a real managed worker sends exact generated HOTP C1/C2 through HTTPS while namespace TUN, journal and lease are active')
        before_journal = journals()
        fd = os.pidfd_open(worker['pid'])
        try:
            assert identity(worker['pid']) == worker
            signal.pidfd_send_signal(fd, signal.SIGKILL, None, 0)
        finally:
            os.close(fd)
        audit['kills'].append({'guardian': guardian, 'worker': worker})
        until(lambda: snapshot()['vpn']['sessionId'] not in (None, old['sessionId']))
        until(lambda: len(verified()) >= 3)
        current = request()
        new_guardian, new_worker = pair()
        check(new_guardian == guardian and new_worker != worker and current['sessionId'] != old['sessionId']
              and [row['counter'] for row in verified()] == ['1', '2', '3'] and entry()['counter'] == '3' and active_network(),
              'killing only the verified owned worker creates a new session that consumes C3 without reusing C1/C2 or replacing its guardian')
        audit['journalRetainedAcrossRestart'] = before_journal == journals()
        before_responses = len([row for row in events() if row.get('response')])
        stale('vpnChallenge', old)
        stale('submitVpnChallenge', {**old, 'username': '', 'password': '', 'formValues': {}, 'secret': code_at(1)})
        stale('cancelVpnChallenge', old)
        time.sleep(1.2)
        check(entry()['counter'] == '3' and len([row for row in events() if row.get('response')]) == before_responses and request() == current,
              'old session Query/Submit/Cancel cannot answer the replacement form or consume another HOTP step')
        command('cancelVpnChallenge', current)
        until(lambda: any(row['tag'] == 'proxy' and row['state'] == 'error' for row in snapshot()['vpn']['endpoints']))
        time.sleep(2.2)
        check(active_network() and pair() == (new_guardian, new_worker) and entry()['counter'] == '3'
              and len([row for row in events() if row.get('response')]) == before_responses,
              'manual Cancel ends the actual managed auth attempt without removing TUN or refunding the consumed counter')
        command('disconnect')
        until(lambda: network() == baseline and not journals() and lease_available())
        until(lambda: not Path('/proc', str(new_worker['pid'])).exists())
        idle = snapshot()
        assert idle['running'] is None and idle['vpn']['sessionId'] is None
        assert identity(new_guardian['pid']) == new_guardian, 'successful managed Stop should retain its idle guardian'
        saved = library.read_bytes()
        assert entry()['counter'] == '3' and json.loads(saved)['version'] == 3
        audit['afterDisconnect'] = {'workerReaped': True, 'idleGuardianRetained': new_guardian,
            'networkRestored': True, 'journalRemoved': True, 'leaseReleased': True, 'counter': '3'}
        # Initial OpenVPN OTP must never be replayed by the managed guardian.
        start_config = {**ready['openvpnStart'], 'username': USER, 'password': '{otp}'}
        start_config.pop('tag', None)
        for connection_mode in ('tun', 'system-proxy'):
            command('preferences', {**command('snapshot')['preferences'], 'connectionMode': connection_mode})
            start_otp = command('otpSave', {'value': {'name': 'Before Start ' + connection_mode,
                'secret': SECRET, 'algorithm': 'SHA1', 'type': 'hotp', 'digits': 6, 'period': 30, 'counter': '0'}})['id']
            start_otp_ids.append(start_otp)
            start_profile = command('saveProfile', {'name': 'Before Start ' + connection_mode, 'groupId': group,
                'kind': 'sing-box-outbound', 'config': start_config})['id']
            view = command('getVpnOtpBinding', {'profileId': start_profile})
            command('saveVpnOtpBinding', {'profileId': start_profile, 'editToken': view['editToken'],
                'otpId': start_otp, 'otpRevision': command('otpGet', {'id': start_otp})['revision'], 'mode': 'auto-start'})
            command('checkProfile', command('profile', {'id': start_profile}))
            check(command('otpGet', {'id': start_otp})['counter'] == '0', 'real Core Check preserves before-Start HOTP in ' + connection_mode)
            command('connect', {'id': start_profile})
            until(lambda: any(row['tag'] == 'proxy' and row['state'] == 'connected' for row in snapshot()['vpn']['endpoints']))
            check(command('otpGet', {'id': start_otp})['counter'] == '1' and (active_network() if connection_mode == 'tun' else snapshot()['systemProxy']['active']),
                  'actual OpenVPN server accepts before-Start HOTP C1 with ' + connection_mode + ' active')
            if connection_mode == 'tun':
                start_guardian, start_worker = pair()
                fd = os.pidfd_open(start_worker['pid'])
                try:
                    assert identity(start_worker['pid']) == start_worker
                    signal.pidfd_send_signal(fd, signal.SIGKILL, None, 0)
                finally:
                    os.close(fd)
                audit['kills'].append({'guardian': start_guardian, 'worker': start_worker, 'beforeStart': True})
                until(lambda: snapshot()['running'] is None and network() == baseline and not journals() and lease_available())
                time.sleep(1.2)
                remaining = core_pids(menu.pid)
                audit['afterStartWorkerDeath'] = {'cores': remaining, 'workers': sorted(worker_ids(start_guardian['pid']))}
                check(command('otpGet', {'id': start_otp})['counter'] == '1'
                      and {int(pid) for pid in remaining}.issubset({start_guardian['pid']}) and not worker_ids(start_guardian['pid'])
                      and snapshot()['preferences']['tun']['autoReconnect'],
                      'guardian does not replay spent initial OTP after worker death; Engine cleans TUN while saved recovery preference stays enabled')
            else:
                command('disconnect')
                until(lambda: not snapshot()['systemProxy']['active'])
                check(command('otpGet', {'id': start_otp})['counter'] == '1' and network() == baseline,
                      'SystemProxy disconnect restores private settings without spending another initial OTP')
        saved = library.read_bytes()
        assert json.loads(saved)['version'] == 4
        menu.activate(menu.ready('Quit'))
        until(lambda: not Path('/proc', str(menu.pid)).exists())
        exited = True
        h['closed_session'] = True
        until(lambda: all(not Path('/proc', str(row['pid'])).exists() for row in [new_guardian, new_worker]))
        check(network() == baseline and not journals() and lease_available() and library.read_bytes() == saved,
              'Disconnect restores private TUN/proxy state; native Quit reaps owned cores and preserves all saved HOTP counters')
        audit['verifiedCounters'] = [row['counter'] for row in verified()]
    except Exception:
        with contextlib.suppress(Exception):
            audit['failureSnapshot'] = command('snapshot')
        raise
    finally:
        if not exited:
            with contextlib.suppress(Exception):
                command('disconnect')
                command('deleteGroup', {'id': group, 'deleteProfiles': True})
                for start_otp in start_otp_ids:
                    command('otpRemove', {'id': start_otp, 'revision': command('otpGet', {'id': start_otp})['revision']})
                if otp_id:
                    command('otpRemove', {'id': otp_id, 'revision': entry()['revision']})
                command('preferences', initial['preferences'])
        (h['artifacts'] / 'vpn-otp-managed-audit.json').write_text(json.dumps(audit, indent=2) + '\n')
