#!/usr/bin/env python3
"""Accept the simple auto-select UX using a pinned App/Core and owned SOCKS peers.

Run on a private X display/session bus, like test_native.py.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()


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
    tracked = [Path(__file__), desktop / 'scripts/test_native.py', desktop / 'tests/native_smoke.py',
               desktop / 'tests/auto_select_simple_ui.py', desktop / 'tests/selector_ranking_fixture.py',
               desktop / 'tests/selector_country_fixture.py', desktop / 'tests/diagnostics_fixture.py']
    before = {str(p.relative_to(desktop.parent)): digest(p) for p in tracked}
    (out / 'inputs.json').write_text(json.dumps({'sources': before, 'applicationSha256': digest(app),
                                   'coreSha256': digest(core)}, indent=2) + '\n')
    with (out / 'native.log').open('w') as log:
        result = subprocess.run([sys.executable, str(desktop / 'scripts/test_native.py'),
                '--auto-select-simple-only', '--application', str(app), '--artifacts', str(out)],
                stdout=log, stderr=subprocess.STDOUT)
    changes = [str(p.relative_to(desktop.parent)) for p in tracked if digest(p) != before[str(p.relative_to(desktop.parent))]]
    pins = digest(app) == args.application_sha256 and digest(core) == args.core_sha256
    summary = {'passed': result.returncode == 0 and not changes and pins,
               'nativeExit': result.returncode, 'sourceChanges': changes, 'pinsUnchanged': pins}
    (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary), flush=True)
    if not summary['passed']: raise SystemExit(1)


if __name__ == '__main__': main()
