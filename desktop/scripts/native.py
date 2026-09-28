#!/usr/bin/env python3
"""Run native GUI suites against a built Thronium on a private display.

    npm run native -- settings tray-system recovery-core
    python3 scripts/native.py --list
    python3 scripts/native.py tun-endpoint -- --wg-fixture /path/to/fixture

Each suite runs on a copy of the application and its core, on an Xvfb display
this run owns (`tests/harness/run_owned_display.py`), with its own session and
accessibility buses (`tests/harness/owned_accessibility.py`). Suites that need
their own wrapper are listed in `tests/harness/suites.json`; the others are
`scripts/test_native.py --<suite>-only`. Arguments after `--` go to every
wrapper of this run. Results: `<artifacts>/<suite>` and `summary.json`.
"""
import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

DESKTOP = Path(__file__).resolve().parents[1]
HARNESS = DESKTOP / 'tests/harness'
DISPLAY = HARNESS / 'run_owned_display.py'
ACCESSIBILITY = HARNESS / 'owned_accessibility.py'
REGISTRY = json.loads((HARNESS / 'suites.json').read_text())['suites']


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def plain_suites():
    """Suites test_native.py runs by itself, from its --<suite>-only flags."""
    text = (DESKTOP / 'scripts/test_native.py').read_text()
    return sorted(set(re.findall(r"'--([a-z0-9-]+)-only'", text)))


def default_core(application):
    beside = application.with_name('ThroniumCore')
    if beside.exists():
        return beside
    host = next(line.removeprefix('host: ') for line in subprocess.check_output(
        ['rustc', '-vV'], text=True).splitlines() if line.startswith('host: '))
    return DESKTOP / 'src-tauri/binaries' / f'ThroniumCore-{host}'


def command(suite, application, core, out, extra):
    """The command for one suite and whether it needs the owned display."""
    entry = REGISTRY.get(suite)
    inside = ['python3', str(DISPLAY), '--artifacts', f'{out}-display', '--']
    buses = ['dbus-run-session', '--', 'python3', str(ACCESSIBILITY), f'{out}-accessibility']
    if entry is None:
        return inside + buses + ['python3', str(DESKTOP / 'scripts/test_native.py'), f'--{suite}-only',
                                 '--application', str(application), '--artifacts', str(out), *extra]
    wrapper = ['python3', str(DESKTOP / entry['wrapper']), *entry.get('args', [])]
    kind = entry['kind']
    if kind == 'namespace':
        own = ['--application', str(application)] if entry.get('application', True) else []
        return wrapper + [*own, '--artifacts', str(out),
                          '--display-runner', str(DISPLAY), '--accessibility-runner', str(ACCESSIBILITY),
                          *extra]
    if kind == 'app':
        return inside + buses + wrapper + ['--application', str(application), '--artifacts', str(out), *extra]
    hashes = ['--application', str(application), '--application-sha256', sha(application),
              '--core-sha256', sha(core), '--artifacts', str(out), *extra]
    if kind == 'hash-display':
        return inside + wrapper + hashes
    return inside + buses + wrapper + hashes


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('suites', nargs='*')
    parser.add_argument('--application', type=Path, default=DESKTOP / 'src-tauri/target/debug/Thronium')
    parser.add_argument('--core', type=Path, help='default: beside the application, else the built sidecar')
    parser.add_argument('--artifacts', type=Path, help='default: test-results/native/<time>')
    parser.add_argument('--timeout', type=int, default=900, help='seconds per suite')
    parser.add_argument('--list', action='store_true')
    arguments, extra = parser.parse_known_args()
    extra = extra[1:] if extra[:1] == ['--'] else extra
    if arguments.list:
        for name in sorted({*plain_suites(), *REGISTRY}):
            print(name, f"({REGISTRY[name]['kind']})" if name in REGISTRY else '')
        return 0
    if not arguments.suites:
        parser.error('name at least one suite (--list shows them)')
    if platform.system() != 'Linux':
        parser.error('native suites run on Linux')
    known = {*plain_suites(), *REGISTRY}
    unknown = [s for s in arguments.suites if s not in known]
    if unknown:
        parser.error('unknown suites: ' + ', '.join(unknown))
    application = arguments.application.resolve()
    core = (arguments.core or default_core(application)).resolve()
    for binary in (application, core):
        if not binary.is_file():
            parser.error(f'{binary} is missing; build with npm run core:build && npm run desktop:build')
    root = (arguments.artifacts or DESKTOP / 'test-results/native' / time.strftime('%Y%m%d-%H%M%S')).resolve()
    root.mkdir(parents=True, exist_ok=False)
    env = {**os.environ, 'GSETTINGS_BACKEND': 'memory', 'ATSPI_DBUS_IMPLEMENTATION': 'dbus-daemon'}
    results = []
    for suite in arguments.suites:
        out = root / suite
        with tempfile.TemporaryDirectory(prefix='thronium-native-') as directory:
            copy = Path(directory)
            shutil.copy2(application, copy / 'Thronium')
            shutil.copy2(core, copy / 'ThroniumCore')
            run_env = {**env, '_THRONIUM_RECOVERY_ROOT': str(copy)}
            started = time.monotonic()
            with Path(f'{out}.log').open('w') as log:
                try:
                    code = subprocess.run(command(suite, copy / 'Thronium', copy / 'ThroniumCore', out, extra),
                                          cwd=DESKTOP.parent, env=run_env, stdout=log, stderr=subprocess.STDOUT,
                                          timeout=arguments.timeout).returncode
                except subprocess.TimeoutExpired:
                    code = 'timeout'
        result = {'suite': suite, 'exitCode': code, 'seconds': round(time.monotonic() - started, 1)}
        results.append(result)
        print(json.dumps(result), flush=True)
    (root / 'summary.json').write_text(json.dumps(results, indent=2) + '\n')
    failed = [r['suite'] for r in results if r['exitCode'] != 0]
    print(f'{len(results) - len(failed)} passed, {len(failed)} failed' + (': ' + ', '.join(failed) if failed else ''))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
