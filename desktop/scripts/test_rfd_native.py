#!/usr/bin/env python3
"""Test one pinned app's RFD NULL boundary with a guarded, one-shot interposer."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid

desktop = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--application', type=Path, required=True)
parser.add_argument('--application-sha256', required=True)
parser.add_argument('--core-sha256', required=True)
parser.add_argument('--artifacts', type=Path, required=True)
parser.add_argument('--backups-probe', action='store_true', help='Observe the existing 15 backup checks with an unarmed interposer')
args = parser.parse_args()
app = args.application.resolve(); core = app.with_name('ThroniumCore')
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
assert sha(app) == args.application_sha256 and sha(core) == args.core_sha256
artifacts = args.artifacts.resolve(); artifacts.mkdir(parents=True, exist_ok=False)
sources = artifacts / 'test-sources'; sources.mkdir()
paths = [Path(__file__), desktop / 'tests/rfd_null_filename.c', desktop / 'tests/rfd_dialogs_ui.py',
         desktop / 'tests/rfd_dialog_fixture.py', desktop / 'tests/native_menu.py', desktop / 'tests/native_processes.py',
         desktop / 'tests/rfd_backup_probe.py', desktop / 'tests/backups_ui.py',
         desktop / 'tests/native_dialogs.py', desktop / 'tests/native_smoke.py', desktop / 'tests/native_transport.py',
         desktop / 'scripts/test_native.py']
for path in paths: shutil.copy2(path, sources / path.name)
(artifacts / 'before-run.json').write_text(json.dumps(dict(applicationSha256=sha(app), coreSha256=sha(core),
    testSources={str(path.relative_to(desktop)): sha(path) for path in paths}), indent=2) + '\n')
with tempfile.TemporaryDirectory(prefix='thronium-rfd-native-') as directory:
    directory = Path(directory); library = directory / 'rfd-null.so'
    build = ['cc', '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-fPIC', '-shared',
             str(desktop / 'tests/rfd_null_filename.c'), '-o', str(library), '-ldl']
    compiled = subprocess.run(build, capture_output=True, text=True)
    (artifacts / 'interposer-build.log').write_text(compiled.stdout + compiled.stderr)
    compiled.check_returncode(); shutil.copy2(library, artifacts / library.name)
    env = {**os.environ, 'LD_PRELOAD': str(library), '_THRONIUM_RFD_APP': str(app),
           '_THRONIUM_RFD_ROOT': str(directory), '_THRONIUM_RFD_NONCE': str(uuid.uuid4())}
    if args.backups_probe: env['_THRONIUM_RFD_BACKUPS_PROBE']='1'
    command = ['python3', str(desktop / 'scripts/test_native.py'), '--application', str(app),
               '--rfd-dialogs-only', '--private-tray-bus', '--artifacts', str(artifacts)]
    (artifacts / 'commands.json').write_text(json.dumps(dict(build=build, run=command,
        interposerSha256=sha(library), scope='Exact executable + caller module + disposable XDG + PID + nonce; one-shot NULL only at an accepted application RFD callback.'), indent=2) + '\n')
    try:
        with (artifacts / 'native.log').open('w') as log:
            result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
    finally:
        for name in ['audit.jsonl', 'once.flag']:
            if (directory / name).exists(): shutil.copy2(directory / name, artifacts / ('interposer-' + name))
    result.check_returncode()
    checks = json.loads((artifacts / 'results.json').read_text())
    (artifacts / 'summary.json').write_text(json.dumps(dict(passed=True, exitCode=result.returncode,
        checks=checks['count'], applicationSha256=sha(app), coreSha256=sha(core),
        interposerSha256=sha(library), faultBoundary='unarmed; original backup suite observed' if args.backups_probe else 'gtk_file_chooser_get_filename at application caller only'), indent=2) + '\n')
    print(checks['count'], 'PASS')
