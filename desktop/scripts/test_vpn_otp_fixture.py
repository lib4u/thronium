#!/usr/bin/env python3
"""Actual manual Core smoke for the independent generated-code VPN fixture."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import tempfile

desktop = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--core', type=Path, required=True)
parser.add_argument('--core-sha256', required=True)
parser.add_argument('--artifacts', type=Path, required=True)
args = parser.parse_args()
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
core = args.core.resolve()
assert sha(core) == args.core_sha256
out = args.artifacts.resolve()
out.mkdir(parents=True, exist_ok=False)
sources = out / 'test-sources'
sources.mkdir()
files = [Path(__file__), desktop / 'tests/vpn_otp_fixture.py', desktop / 'tests/vpn_auth_fixture.py']
hashes = {str(path.relative_to(desktop)): sha(path) for path in files}
for path in files:
    shutil.copy2(path, sources / path.name)
status = {'passed': False, 'testSources': hashes, 'coreSha256': sha(core)}
try:
    with tempfile.TemporaryDirectory(prefix='vpn-otp-') as directory:
        root = Path(directory)
        root.chmod(0o700)
        shutil.copy2(Path(sys.executable).resolve(), root / 'Thronium')
        shutil.copy2(core, root / 'ThroniumCore')
        with (out / 'fixture-stderr.log').open('w') as log:
            process = subprocess.Popen([str(root / 'Thronium'), str(sources / 'vpn_otp_fixture.py'), str(root), '--self-check'],
                env={**os.environ, 'PYTHONHOME': sys.prefix}, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=log, text=True)
            try:
                assert select.select([process.stdout], [], [], 15)[0], 'fixture_ready_timeout'
                ready = process.stdout.readline()
                assert ready, 'fixture_ready_failed'
                (out / 'ready.json').write_text(json.dumps(json.loads(ready), indent=2) + '\n')
                assert select.select([process.stdout], [], [], 40)[0], 'fixture_smoke_timeout'
                result = process.stdout.readline()
                assert result, 'fixture_smoke_failed'
                status['observations'] = json.loads(result)
            finally:
                process.stdin.close()
                try:
                    status['exitCode'] = process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    status['exitCode'] = process.wait(timeout=5)
                for name in ['events.jsonl', 'server-core.log', 'client-core.log']:
                    if (root / name).exists():
                        shutil.copy2(root / name, out / name)
            assert status['exitCode'] == 0
            status['passed'] = True
finally:
    status['pinnedCoreUnchanged'] = sha(core) == args.core_sha256
    status['testSourcesUnchanged'] = hashes == {str(path.relative_to(desktop)): sha(path) for path in files}
    (out / ('summary.json' if status['passed'] else 'attempt-status.json')).write_text(json.dumps(status, indent=2) + '\n')
    assert status['pinnedCoreUnchanged'] and status['testSourcesUnchanged']
print('PASS actual generated-code fixture')
