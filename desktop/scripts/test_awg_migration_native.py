#!/usr/bin/env python3
"""Verify a pinned App/Core pair against independent official AWG peers on an owned display.

Run inside a private X display/session bus, as with test_native.py. The official
peer is built with the Go race detector and its pinned, read-only modules.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

from wireguard_fixture import digest


def main():
    desktop = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--application', type=Path, required=True)
    parser.add_argument('--application-sha256', required=True)
    parser.add_argument('--core-sha256', required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    args = parser.parse_args()
    app = args.application.resolve()
    core = app.with_name('ThroniumCore')
    assert digest(app) == args.application_sha256 and digest(core) == args.core_sha256
    out = args.artifacts.resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    fixture = desktop / 'tests/fixtures/awg-live'
    fixture_sources = [fixture / name for name in ['server.go', 'bind.go', 'go.mod', 'go.sum']]
    tracked = fixture_sources + [Path(__file__), desktop / 'tests/awg_migration_ui.py',
                                desktop / 'scripts/test_native.py', desktop / 'tests/native_smoke.py',
                                desktop / 'scripts/wireguard_fixture.py']
    before = {str(p.relative_to(desktop.parent)): digest(p) for p in tracked}
    binary = out / 'awg-fixture'
    with (out / 'fixture-build.log').open('w') as log:
        subprocess.run(['go', 'build', '-mod=readonly', '-race', '-p', '2', '-o', str(binary), 'server.go', 'bind.go'], cwd=fixture, stdout=log, stderr=subprocess.STDOUT, check=True, env={**os.environ, 'GOWORK': 'off', 'GOTOOLCHAIN': 'local'})
    fixture_manifest = {'binarySha256': digest(binary)}
    record = {'sources': before, 'fixture': fixture_manifest,
              'applicationSha256': digest(app), 'coreSha256': digest(core)}
    (out / 'inputs.json').write_text(json.dumps(record, indent=2) + '\n')
    env = {**os.environ, '_THRONIUM_AWG_MIGRATION_FIXTURE': str(binary)}
    command = [sys.executable, str(desktop / 'scripts/test_native.py'), '--awg-migration-only',
               '--application', str(app), '--artifacts', str(out)]
    with (out / 'native.log').open('w') as log:
        result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
    changes = [str(p.relative_to(desktop.parent)) for p in tracked if digest(p) != before[str(p.relative_to(desktop.parent))]]
    pins = digest(app) == args.application_sha256 and digest(core) == args.core_sha256
    summary = {'passed': result.returncode == 0 and not changes and pins,
               'nativeExit': result.returncode, 'sourceChanges': changes, 'pinsUnchanged': pins,
               'fixtureRaceDetector': True}
    (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary), flush=True)
    if not summary['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
