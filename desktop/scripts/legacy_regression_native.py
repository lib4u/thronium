"""Pin/source guard for the unchanged historical native legacy import suites."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

DESKTOP = Path(__file__).resolve().parents[1]

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def main(suite, wrapper):
    assert suite in ('backup', 'otp')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--application', type=Path, required=True)
    parser.add_argument('--application-sha256', required=True)
    parser.add_argument('--core-sha256', required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    args = parser.parse_args()
    app = args.application.resolve(); core = app.with_name('ThroniumCore')
    assert sha(app) == args.application_sha256 and sha(core) == args.core_sha256
    out = args.artifacts.resolve(); out.mkdir(parents=True, exist_ok=False)
    files = {Path(__file__).resolve(), Path(wrapper).resolve(), *[DESKTOP / file for file in [
        'tests/legacy_backup_fixtures.py', 'scripts/test_native.py', 'tests/native_smoke.py',
        'tests/native_transport.py', 'tests/native_screenshot.py', 'tests/native_dialogs.py', 'tests/rfd_dialog_fixture.py']]}
    files.add(DESKTOP / ('tests/legacy_backup_ui.py' if suite == 'backup' else 'tests/legacy_otp_ui.py'))
    folders = [DESKTOP / 'tests/fixtures/legacy-import']
    if suite == 'otp':
        files.add(DESKTOP / 'tests/legacy_otp_fixtures.py')
        folders += [DESKTOP / 'tests/fixtures/legacy-otp', DESKTOP / 'engine/src/legacy_backup/otp/fixtures']
    for folder in folders: files.update(p for p in folder.rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    before = {str(path.relative_to(DESKTOP)): sha(path) for path in sorted(files)}
    for path in files:
        target = out / 'test-sources' / path.relative_to(DESKTOP)
        target.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(path, target)
    (out / 'before-run.json').write_text(json.dumps({'applicationSha256': sha(app), 'coreSha256': sha(core), 'testSources': before}, indent=2) + '\n')
    flag = '--legacy-backup-only' if suite == 'backup' else '--legacy-otp-only'
    cmd = [sys.executable, str(DESKTOP / 'scripts/test_native.py'), '--application', str(app), flag, '--artifacts', str(out)]
    env = os.environ.copy()
    for key in ['http_proxy', 'https_proxy', 'all_proxy', 'no_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY']: env.pop(key, None)
    (out / 'command.json').write_text(json.dumps(cmd, indent=2) + '\n')
    status = {'passed': False, 'suite': suite, 'historicalAssertionsUnchanged': True}
    started = time.monotonic()
    try:
        with (out / 'native.log').open('w') as log: result = subprocess.run(cmd, env=env, stdout=log, stderr=subprocess.STDOUT)
        status['nativeExitCode'] = result.returncode
        result.check_returncode()
        status['checks'] = json.loads((out / 'results.json').read_text())['count']
        assert status['checks'] == 36
        status['passed'] = True
    finally:
        status.update(seconds=round(time.monotonic()-started,3),applicationSha256=sha(app),coreSha256=sha(core),
            pinnedInputsUnchanged=sha(app)==args.application_sha256 and sha(core)==args.core_sha256,
            testSourcesUnchanged=before=={str(path.relative_to(DESKTOP)):sha(path) for path in sorted(files)})
        if not status['pinnedInputsUnchanged'] or not status['testSourcesUnchanged']:status['passed']=False
        (out/('summary.json' if status['passed'] else 'attempt-status.json')).write_text(json.dumps(status,indent=2)+'\n')
        assert status['pinnedInputsUnchanged'] and status['testSourcesUnchanged']
    print('PASS',status['checks'])
