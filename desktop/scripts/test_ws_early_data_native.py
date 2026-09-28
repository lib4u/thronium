#!/usr/bin/env python3
"""Pinned native Xray WS editor checks with private application state."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

DESKTOP = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sources():
    dispatch = {DESKTOP / 'scripts/test_native.py', DESKTOP / 'tests/native_smoke.py'}
    pending = list(dispatch) + [Path(__file__).resolve()] + [DESKTOP / 'tests' / name for name in (
        'ws_early_data_ui.py', 'native_transport.py', 'native_screenshot.py',
        'native_processes.py', 'window_ui.py', 'tray_ui.py')]
    found = set()
    while pending:
        path = pending.pop()
        if path in found:
            continue
        assert path.is_file(), str(path)
        found.add(path)
        if path in dispatch:
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            modules = [node.module] if isinstance(node, ast.ImportFrom) and node.module else [a.name for a in node.names] if isinstance(node, ast.Import) else []
            for module in modules:
                for folder in ['tests', 'scripts']:
                    candidate = DESKTOP / folder / (module.replace('.', '/') + '.py')
                    if candidate.is_file():
                        pending.append(candidate)
    return sorted(found)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--application', type=Path, required=True)
    parser.add_argument('--application-sha256', required=True)
    parser.add_argument('--core-sha256', required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--transport', choices=['ws','httpupgrade'], default='ws')
    args = parser.parse_args()
    app = args.application.resolve(); core = app.with_name('ThroniumCore')
    assert sha(app) == args.application_sha256 and sha(core) == args.core_sha256
    out = args.artifacts.resolve(); out.mkdir(parents=True, exist_ok=False)
    files = sources(); before = {str(p.relative_to(DESKTOP)): sha(p) for p in files}
    for path in files:
        target = out / 'test-sources' / path.relative_to(DESKTOP)
        target.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(path, target)
    (out / 'before-run.json').write_text(json.dumps({'applicationSha256': sha(app), 'coreSha256': sha(core), 'testSources': before}, indent=2) + '\n')
    cmd = [sys.executable, str(DESKTOP / 'scripts/test_native.py'), '--application', str(app), ('--ws-early-data-only' if args.transport=='ws' else '--httpupgrade-early-data-only'), '--private-tray-bus', '--artifacts', str(out)]
    env = {k: v for k, v in os.environ.items() if k.lower() not in ('http_proxy', 'https_proxy', 'all_proxy', 'no_proxy')}
    (out / 'command.json').write_text(json.dumps(cmd, indent=2) + '\n')
    status = {'passed': False, 'expectedChecks': 32, 'transport': args.transport}; started = time.monotonic()
    try:
        with (out / 'native.log').open('w') as log:
            result = subprocess.run(cmd, env=env, stdout=log, stderr=subprocess.STDOUT)
        status['nativeExitCode'] = result.returncode
        result.check_returncode()
        completed = json.loads((out / 'results.json').read_text())
        status['checks'] = completed['count']
        assert completed['count'] == len(completed['checks']) == 32
        audit = json.loads((out / ('early-data-'+args.transport+'-audit.json')).read_text())
        assert audit['passed'] and audit['cleanupCompleted']
        status['passed'] = True
    finally:
        status.update(seconds=round(time.monotonic() - started, 3), applicationSha256=sha(app), coreSha256=sha(core),
                      pinnedInputsUnchanged=sha(app) == args.application_sha256 and sha(core) == args.core_sha256,
                      testSourcesUnchanged=before == {str(p.relative_to(DESKTOP)): sha(p) for p in files})
        status['passed'] = status['passed'] and status['pinnedInputsUnchanged'] and status['testSourcesUnchanged']
        (out / ('summary.json' if status['passed'] else 'attempt-status.json')).write_text(json.dumps(status, indent=2) + '\n')
        assert status['pinnedInputsUnchanged'] and status['testSourcesUnchanged']
    print(status['checks'], 'PASS')


if __name__ == '__main__':
    main()
