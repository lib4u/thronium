#!/usr/bin/env python3
"""The window against an actual OpenConnect server (ocserv): a CSTP tunnel that
carries traffic, and the same endpoint as a node of a chain. Private user,
network, mount and PID namespaces; nothing of the host network is touched."""
import argparse
import json
from pathlib import Path
import sys

from namespace_stand import DESKTOP, child_env, interfaces, prepare_child, run_outer, run_suite

TOOLS = DESKTOP / '.tools/ocserv-root'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('application', 'artifacts', 'display-runner', 'accessibility-runner'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--namespace-child', action='store_true')
    args = parser.parse_args()
    out = args.artifacts.resolve()
    if args.namespace_child:
        sys.path.insert(0, str(DESKTOP / 'tests'))
        from openconnect_cstp_fixture import Fixture
        root = prepare_child('thronium-cstp12')
        record = {'onlyOwnedInterfaces': interfaces() == {'lo', 'uplink'}}
        # A unix socket path is bounded well below a temporary directory name.
        short = Path('/run/oc')
        short.mkdir(mode=0o700)
        fixture = Fixture(root / 'ocserv', TOOLS)
        ready_file = out / 'fixture-ready.json'
        ready = fixture.start(short)
        ready_file.write_text(json.dumps(ready, indent=2) + '\n')
        record['ocserv'] = ready['version']
        env = child_env(root, {'_THRONIUM_OPENCONNECT_CSTP_READY': str(ready_file)})
        try:
            record['exitCode'] = run_suite(args, out, env, '--openconnect-cstp-only')
        finally:
            record['fixture'] = fixture.close()
            (out / 'fixture-observations.json').write_text(fixture.observations())
            for name in ('ocserv.log', 'ocserv.conf'):
                if (fixture.root / name).exists():
                    (out / ('fixture-' + name)).write_bytes((fixture.root / name).read_bytes())
            record['tunnelDeviceRemoved'] = 'oc-cstp' not in interfaces()
            (out / 'namespace.json').write_text(json.dumps(record, indent=2) + '\n')
        assert record['onlyOwnedInterfaces'] and record['tunnelDeviceRemoved']
        # The hop behind the server was only ever reached from inside the
        # tunnel, and the file was fetched through it: the stand proves the
        # CSTP session carried the traffic, not the namespace around it.
        assert record['fixture']['tunnelled'], record['fixture']
        return record['exitCode']
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    server = TOOLS / 'usr/bin/ocserv'
    assert server.exists(), 'this stand needs ' + str(server) + ' (see the note of F12)'
    tracked = [Path(__file__), DESKTOP / 'tests/openconnect_cstp_fixture.py',
               DESKTOP / 'tests/openconnect_cstp_ui.py', DESKTOP / 'scripts/test_native.py',
               DESKTOP / 'tests/native_smoke.py', DESKTOP / 'scripts/namespace_stand.py']
    return run_outer(args, out, __file__, [], tracked, timeout=1200)


if __name__ == '__main__':
    raise SystemExit(main())
