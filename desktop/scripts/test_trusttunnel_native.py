#!/usr/bin/env python3
"""Deep-link import and HTTP/2, HTTP/3 tunnels to an owned TrustTunnel endpoint; no external or host network changes."""
import argparse
import json
from pathlib import Path
import shutil
import sys
import tempfile

from namespace_stand import DESKTOP, child_env, interfaces, prepare_child, run_outer, run_suite, sha


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('application', 'artifacts', 'display-runner', 'accessibility-runner'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--namespace-child', action='store_true')
    parser.add_argument('--peer-root', type=Path)
    args = parser.parse_args(); out = args.artifacts.resolve()
    if args.namespace_child:
        root = prepare_child('thronium-tt86')
        sys.path.insert(0, str(DESKTOP / 'tests'))
        from trusttunnel_fixture import Fixture
        fixture = Fixture(root / 'endpoint', args.peer_root)
        record = {'onlyOwnedInterfaces': interfaces() == {'lo', 'uplink'}}
        try:
            record['exitCode'] = run_suite(args, out, child_env(root, {'_THRONIUM_TRUSTTUNNEL_FIXTURE': str(fixture.path)}), '--trusttunnel-only')
        finally:
            record['fixture'] = fixture.close(); (out / 'namespace.json').write_text(json.dumps(record, indent=2) + '\n')
        assert record['onlyOwnedInterfaces'] and all(record['fixture'][key] for key in (
            'serverCoreAliveUntilStop', 'serverCoreReaped', 'originThreadReaped', 'originSocketClosed'))
        return record['exitCode']
    # The fixture's Core needs an owned parent executable named Thronium next to it.
    peer = tempfile.TemporaryDirectory(prefix='thronium-tt86-peer-')
    peer_root = Path(peer.name)
    shutil.copy2(Path(sys.executable).resolve(), peer_root / 'Thronium')
    shutil.copy2(args.application.with_name('ThroniumCore'), peer_root / 'ThroniumCore')
    assert sha(peer_root / 'ThroniumCore') == sha(args.application.with_name('ThroniumCore'))
    tracked = [Path(__file__), DESKTOP / 'tests/trusttunnel_ui.py', DESKTOP / 'tests/trusttunnel_fixture.py',
               DESKTOP / 'scripts/test_native.py', DESKTOP / 'tests/native_smoke.py', DESKTOP / 'scripts/namespace_stand.py']
    try:
        return run_outer(args, out, __file__, ['--peer-root', str(peer_root)], tracked, timeout=600, executable=peer_root / 'Thronium')
    finally:
        peer.cleanup()


if __name__ == '__main__':
    raise SystemExit(main())
