#!/usr/bin/env python3
"""Real TUN with WireGuard and AmneziaWG endpoints on every stack; independent peers, private namespaces, no host network changes."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

from namespace_stand import DESKTOP, child_env, interfaces, prepare_child, run_outer, run_suite, sha
from wireguard_fixture import build


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('application', 'artifacts', 'display-runner', 'accessibility-runner'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--namespace-child', action='store_true')
    parser.add_argument('--wg-fixture', type=Path)
    parser.add_argument('--awg-fixture', type=Path)
    args = parser.parse_args(); out = args.artifacts.resolve()
    if args.namespace_child:
        root = prepare_child('thronium-tun76')
        record = {'onlyOwnedInterfaces': interfaces() == {'lo', 'uplink'}}
        env = child_env(root, {'_THRONIUM_TUN_ENDPOINT_WG_FIXTURE': str(args.wg_fixture), '_THRONIUM_TUN_ENDPOINT_AWG_FIXTURE': str(args.awg_fixture)})
        record['exitCode'] = run_suite(args, out, env, '--tun-endpoint-only')
        record['tunRemoved'] = 'thronium-tun' not in interfaces()
        (out / 'namespace.json').write_text(json.dumps(record, indent=2) + '\n')
        assert record['onlyOwnedInterfaces'] and record['tunRemoved']
        return record['exitCode']
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    wg_binary, wg_sources, wg_manifest = build(DESKTOP, out / 'wg-fixture-build.log')
    awg_dir = out / 'awg-fixture-build'; awg_dir.mkdir()
    for name in ('go.mod', 'go.sum', 'server.go', 'bind.go'):
        shutil.copy2(DESKTOP / 'tests/fixtures/awg-live' / name, awg_dir / name)
    awg_binary = awg_dir / 'awg-fixture'
    with (out / 'awg-fixture-build.log').open('w') as log:
        subprocess.run(['go', 'build', '-mod=readonly', '-race', '-p', '2', '-o', str(awg_binary), 'server.go', 'bind.go'], cwd=awg_dir,
                       env={**os.environ, 'GOWORK': 'off', 'GOTOOLCHAIN': 'local'}, stdout=log, stderr=subprocess.STDOUT, check=True)
    tracked = wg_sources + [Path(__file__), DESKTOP / 'tests/tun_endpoint_ui.py', DESKTOP / 'tests/wireguard_topology_ui.py',
                            DESKTOP / 'scripts/test_native.py', DESKTOP / 'tests/native_smoke.py', DESKTOP / 'scripts/namespace_stand.py',
                            *DESKTOP.joinpath('tests/fixtures/awg-live').glob('*.go')]
    return run_outer(args, out, __file__, ['--wg-fixture', str(wg_binary), '--awg-fixture', str(awg_binary)], tracked,
                     record_extra={'wgFixture': wg_manifest, 'awgFixtureSha256': sha(awg_binary)})


if __name__ == '__main__':
    raise SystemExit(main())
