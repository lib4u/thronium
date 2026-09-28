#!/usr/bin/env python3
"""Real-core dynamic selector integration with only isolated loopback fixtures."""
import hashlib
import json
import pathlib
import shutil
import subprocess
import tempfile

desktop = pathlib.Path(__file__).resolve().parents[1]
artifacts = desktop / 'test-results/dynamic-selectors-validation'
artifacts.mkdir(parents=True, exist_ok=True)
host = next(line[6:] for line in subprocess.check_output(['rustc', '-vV'], text=True).splitlines() if line.startswith('host: '))
suffix = '.exe' if 'windows' in host else ''
core = desktop / 'src-tauri/binaries' / f'ThroniumCore-{host}{suffix}'
if not core.is_file():
    raise SystemExit('Build the sidecar first: npm run core:build')
summary = artifacts / 'dynamic-selectors-core-summary.json'
summary.unlink(missing_ok=True)
with (artifacts / 'dynamic-selectors-core.log').open('w') as log:
    def invoke(command, timeout=240):
        log.write('$ ' + ' '.join(map(str, command)) + '\n'); log.flush()
        try:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            output = error.stdout or ''
            if isinstance(output, bytes): output = output.decode(errors='replace')
            log.write(output + f'\nFAILED: timeout after {timeout} seconds\n'); log.flush()
            print(output, end='', flush=True)
            raise
        log.write(result.stdout); log.flush(); print(result.stdout, end='', flush=True)
        result.check_returncode()
        return result.stdout
    invoke(['cargo', 'build', '--locked', '--manifest-path', str(desktop / 'engine/Cargo.toml'), '--bin', 'dynamic-selector-smoke', '-j', '2'])
    with tempfile.TemporaryDirectory(prefix='thronium-dynamic-selectors-') as folder:
        folder = pathlib.Path(folder)
        shutil.copy2(core, folder / ('ThroniumCore' + suffix))
        shutil.copy2(desktop / 'engine/target/debug' / ('dynamic-selector-smoke' + suffix), folder / ('Thronium' + suffix))
        hashes = {name: hashlib.sha256((folder / (name + suffix)).read_bytes()).hexdigest() for name in ['Thronium', 'ThroniumCore']}
        (artifacts / 'dynamic-selectors-core-binaries.json').write_text(json.dumps(hashes, indent=2) + '\n')
        output = invoke([str(folder / ('Thronium' + suffix))], timeout=180)
        passed = [line for line in output.splitlines() if line.startswith('PASS ')]
        summary.write_text(json.dumps({'checks': len(passed), 'passed': passed, 'loopbackOnly': True, 'binaries': hashes}, indent=2) + '\n')
print(f'Dynamic selector report: {summary}')
