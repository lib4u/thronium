#!/usr/bin/env python3
"""Run native DoQ import against an owned fixture and process-private CA."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import sys

DESKTOP = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--application', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--prepare-only', action='store_true', help='Prepare fixtures without opening an application')
    args = parser.parse_args()
    application = args.application.resolve()
    core = application.with_name('ThroniumCore')
    assert application.is_file() and core.is_file()
    output = args.artifacts.resolve()
    output.mkdir(parents=True, exist_ok=False)
    sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    source = DESKTOP / 'engine/tests/fixtures/legacy-quic/runtime_fixture.go'
    paths = [Path(__file__).resolve(), DESKTOP / 'tests/legacy_quic_dns_ui.py',
             DESKTOP / 'tests/legacy_quic_fixtures.py', source]
    before = {str(p.relative_to(DESKTOP)): sha(p) for p in paths}
    build = ['go', 'build', '-modfile=' + str(DESKTOP / '.tools/core-overlay/go.mod'),
             '-o', str(output / 'dns-fixture'), str(source)]
    result = subprocess.run(build, cwd=DESKTOP.parent / 'core/server',
                            env={**os.environ, 'GOPROXY': 'off', 'GOSUMDB': 'off'},
                            capture_output=True, text=True, timeout=300)
    (output / 'fixture-build.log').write_text(result.stdout + result.stderr)
    result.check_returncode()
    sys.path.insert(0, str(DESKTOP / 'tests'))
    from legacy_quic_fixtures import generate
    status = None
    info = None
    fixture = None
    error = None
    try:
        with (output / 'fixture.log').open('w') as log:
            fixture = subprocess.Popen([str(output / 'dns-fixture'), str(output / 'fixture')],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=log, text=True)
            with selectors.DefaultSelector() as ready:
                ready.register(fixture.stdout, selectors.EVENT_READ)
                assert ready.select(10), 'Owned DoQ fixture did not become ready'
            info = json.loads(fixture.stdout.readline())
            info_file = output / 'fixture-info.json'
            info_file.write_text(json.dumps(info, indent=2) + '\n')
            generate(output / 'archives', info)
            environment = {**os.environ, 'SSL_CERT_FILE': info['ca'],
                           'THRONIUM_LEGACY_QUIC_NATIVE_INFO': str(info_file),
                           'THRONIUM_LEGACY_QUIC_NATIVE_ARCHIVES': str(output / 'archives')}
            command = [sys.executable, str(DESKTOP / 'scripts/test_native.py'),
                       '--application', str(application), '--artifacts', str(output / 'native'),
                       '--legacy-quic-dns-only']
            (output / 'commands.json').write_text(json.dumps({'build': build, 'native': command,
                'privateEnvironment': {k: environment[k] for k in ['SSL_CERT_FILE',
                    'THRONIUM_LEGACY_QUIC_NATIVE_INFO', 'THRONIUM_LEGACY_QUIC_NATIVE_ARCHIVES']}}, indent=2) + '\n')
            if not args.prepare_only:
                with (output / 'native.log').open('w') as native_log:
                    result = subprocess.run(command, env=environment, stdout=native_log,
                                            stderr=subprocess.STDOUT, timeout=400)
                status = result.returncode
                result.check_returncode()
            else:
                status = 0
    except Exception as caught:
        error = str(caught)
        raise
    finally:
        if fixture is not None:
            fixture.stdin.close()
            try:
                fixture.wait(timeout=10)
            except subprocess.TimeoutExpired:
                fixture.kill()
                fixture.wait()
        after = {str(p.relative_to(DESKTOP)): sha(p) for p in paths}
        for path in paths:
            target = output / 'sources' / path.relative_to(DESKTOP)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
        results_file = output / 'native/results.json'
        native = json.loads(results_file.read_text()) if results_file.exists() else None
        summary = {'passed': status == 0 and fixture is not None and fixture.returncode == 0 and before == after,
                   'prepareOnly': args.prepare_only, 'exitCode': status, 'error': error,
                   'fixtureExitCode': fixture.returncode if fixture else None,
                   'nativeChecks': native.get('count') if native else None,
                   'binaries': {'Thronium': sha(application), 'ThroniumCore': sha(core),
                                'dns-fixture': sha(output / 'dns-fixture')},
                   'sourceSHA256': before, 'sourceChanges': [k for k in before if before[k] != after[k]],
                   'trust': 'SSL_CERT_FILE belongs to the disposable application/core environment only; no host trust or imported JSON overrides'}
        (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    assert summary['passed'], 'Native DoQ fixture cleanup or source verification failed'
    print('Native DoQ report:', output / 'summary.json', flush=True)


if __name__ == '__main__':
    main()
