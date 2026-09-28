#!/usr/bin/env python3
"""Verify a pinned App/Core pair against independent WG peers on an owned display.

Run inside a private X display/session bus, as with test_native.py. The peer
build cache is persistent; changed Go sources/modules alone invalidate it.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

from wireguard_fixture import build, digest


def main():
    desktop = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--application', type=Path, required=True)
    parser.add_argument('--application-sha256', required=True)
    parser.add_argument('--core-sha256', required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--outer-family', choices=['4', '6'], default='4')
    args = parser.parse_args()
    app = args.application.resolve()
    core = app.with_name('ThroniumCore')
    assert digest(app) == args.application_sha256 and digest(core) == args.core_sha256
    out = args.artifacts.resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    binary, fixture_sources, fixture_manifest = build(desktop, out / 'fixture-build.log')
    tracked = fixture_sources + [Path(__file__), desktop / 'tests/wireguard_topology_ui.py',
                                desktop / 'scripts/test_native.py', desktop / 'tests/native_smoke.py',
                                desktop / 'scripts/wireguard_fixture.py']
    before = {str(p.relative_to(desktop.parent)): digest(p) for p in tracked}
    record = {'sources': before, 'fixture': fixture_manifest,
              'applicationSha256': digest(app), 'coreSha256': digest(core), 'outerFamily': args.outer_family}
    (out / 'inputs.json').write_text(json.dumps(record, indent=2) + '\n')
    env = {**os.environ, '_THRONIUM_WG_TOPOLOGY_FIXTURE': str(binary),
           '_THRONIUM_WG_TOPOLOGY_OUTER': '127.0.0.1' if args.outer_family == '4' else '::1'}
    command = [sys.executable, str(desktop / 'scripts/test_native.py'), '--wireguard-topology-only',
               '--application', str(app), '--artifacts', str(out)]
    with (out / 'native.log').open('w') as log:
        result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
    changes = [str(p.relative_to(desktop.parent)) for p in tracked if digest(p) != before[str(p.relative_to(desktop.parent))]]
    pins = digest(app) == args.application_sha256 and digest(core) == args.core_sha256
    summary = {'passed': result.returncode == 0 and not changes and pins,
               'nativeExit': result.returncode, 'sourceChanges': changes, 'pinsUnchanged': pins,
               'fixtureRaceDetector': True, 'outerFamily': args.outer_family}
    (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary), flush=True)
    if not summary['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
