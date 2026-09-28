#!/usr/bin/env python3
"""One stand for what a provider policy really does: a tunnel that answers DNS
with fake addresses, a Happ subscription that asks for them, and an auxiliary
OpenVPN endpoint beside the connection. Private user, network, mount and PID
namespaces; the host network is never touched."""
import argparse
import json
from pathlib import Path
import select
import subprocess
import sys

from namespace_stand import DESKTOP, child_env, interfaces, prepare_child, run_outer, run_suite


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('application', 'artifacts', 'display-runner', 'accessibility-runner'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--namespace-child', action='store_true')
    args = parser.parse_args()
    out = args.artifacts.resolve()
    if args.namespace_child:
        root = prepare_child('thronium-fakeip82')
        record = {'onlyOwnedInterfaces': interfaces() == {'lo', 'uplink'}}
        (root / 'openvpn').mkdir(mode=0o700)
        fixture = subprocess.Popen(
            [sys.executable, str(DESKTOP / 'tests/openvpn_pending_fixture.py'), str(root / 'openvpn')],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
            stderr=(out / 'openvpn-stderr.log').open('w'))
        try:
            assert select.select([fixture.stdout], [], [], 60)[0], 'openvpn_ready_timeout'
            line = fixture.stdout.readline()
            assert line, 'openvpn_start_failed'
            ready = json.loads(line)
            ready_file = out / 'openvpn-ready.json'
            ready_file.write_text(json.dumps(ready, indent=2) + '\n')
            record['openvpnVersion'] = ready['openvpnVersion']
            env = child_env(root, {'_THRONIUM_OPENVPN_PENDING_READY': str(ready_file)})
            record['exitCode'] = run_suite(args, out, env, '--fakeip-batch-only')
        finally:
            fixture.stdin.close()
            try:
                record['fixtureExitCode'] = fixture.wait(timeout=20)
            except subprocess.TimeoutExpired:
                fixture.terminate()
                record['fixtureExitCode'] = fixture.wait(timeout=10)
            for name in ('openvpn.log', 'observations.json'):
                if (root / 'openvpn' / name).exists():
                    (out / ('fixture-' + name)).write_bytes((root / 'openvpn' / name).read_bytes())
            record['tunnelRemoved'] = not any(name.startswith('thronium-tun') for name in interfaces())
            (out / 'namespace.json').write_text(json.dumps(record, indent=2) + '\n')
        assert record['onlyOwnedInterfaces'] and record['tunnelRemoved']
        assert record['fixtureExitCode'] == 0, record
        return record['exitCode']
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    tracked = [Path(__file__), DESKTOP / 'tests/fakeip_batch_ui.py',
               DESKTOP / 'tests/subscription_happ_fixture.py',
               DESKTOP / 'tests/openvpn_pending_fixture.py', DESKTOP / 'scripts/test_native.py',
               DESKTOP / 'tests/native_smoke.py', DESKTOP / 'scripts/namespace_stand.py']
    return run_outer(args, out, __file__, [], tracked, timeout=1500)


if __name__ == '__main__':
    raise SystemExit(main())
