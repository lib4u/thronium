#!/usr/bin/env python3
"""Run diagnostics with a real production sidecar and loopback-only SOCKS/TLS fixtures."""
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

desktop = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(desktop / 'tests'))
from diagnostics_fixture import Fixture

artifacts = desktop / 'test-results/diagnostics-validation'
artifacts.mkdir(parents=True, exist_ok=True)
log_path = artifacts / 'diagnostics-core.log'
host = next(line[6:] for line in subprocess.check_output(['rustc', '-vV'], text=True).splitlines() if line.startswith('host: '))
suffix = '.exe' if 'windows' in host else ''
core = desktop / 'src-tauri/binaries' / f'ThroniumCore-{host}{suffix}'
if not core.is_file():
    raise SystemExit('Build the sidecar first: npm run core:build')

def invoke(command, log, *, env=None, timeout=180):
    log.write('$ ' + ' '.join(map(str, command)) + '\n')
    log.flush()
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, env=env, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        output = error.stdout or ''
        if isinstance(output, bytes):
            output = output.decode(errors='replace')
        log.write(output + f'\nFAILED: command exceeded {timeout} seconds\n')
        log.flush()
        print(output, end='', flush=True)
        raise
    log.write(result.stdout)
    log.flush()
    print(result.stdout, end='', flush=True)
    result.check_returncode()
    return result.stdout

with log_path.open('w') as log:
    (artifacts / 'diagnostics-core-summary.json').unlink(missing_ok=True)
    invoke(['cargo', 'build', '--locked', '--manifest-path', str(desktop / 'engine/Cargo.toml'),
            '--bin', 'diagnostics-smoke', '-j', '2'], log)
    with tempfile.TemporaryDirectory(prefix='thronium-diagnostics-core-') as folder:
        folder = pathlib.Path(folder)
        shutil.copy2(core, folder / ('ThroniumCore' + suffix))
        shutil.copy2(desktop / 'engine/target/debug' / ('diagnostics-smoke' + suffix), folder / ('Thronium' + suffix))
        hashes = {name: hashlib.sha256((folder / (name + suffix)).read_bytes()).hexdigest()
                  for name in ['Thronium', 'ThroniumCore']}
        (artifacts / 'diagnostics-core-binaries.json').write_text(json.dumps(hashes, indent=2) + '\n')
        fixture = Fixture(folder / 'fixture')
        try:
            environment = os.environ.copy()
            environment['SSL_CERT_FILE'] = str(fixture.cert)
            # The TLS certificate is trusted by this test child only.
            output = invoke([str(folder / ('Thronium' + suffix)), str(fixture.path)],
                            log, env=environment, timeout=180)
            passed = [line for line in output.splitlines() if line.startswith('PASS ') and not line.startswith('PASS TOTAL:')]
            (artifacts / 'diagnostics-core-summary.json').write_text(json.dumps({
                'checks': len(passed), 'passed': passed, 'loopbackOnly': True,
                'binaries': hashes, 'log': str(log_path)
            }, indent=2) + '\n')
        finally:
            fixture.close()
print(f'Diagnostics core report: {log_path}')
