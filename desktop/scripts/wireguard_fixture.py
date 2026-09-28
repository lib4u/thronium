"""Build or reuse the independent WireGuard peer fixture with the race detector.

The build cache is persistent; changed Go sources or modules alone invalidate it.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def build(desktop, log_path=None):
    desktop = Path(desktop)
    sources = [*desktop.joinpath('engine/tests/fixtures/wireguard-live').glob('*.go'),
               desktop.parent / 'core/server/go.mod', desktop.parent / 'core/server/go.sum']
    inputs = {p.name: digest(p) for p in sources}
    inputs['goVersion'] = subprocess.check_output(['go', 'version'], text=True).strip()
    cache = desktop / '.tools/wg-topology78'
    cache.mkdir(parents=True, exist_ok=True)
    binary = cache / 'wg-fixture'
    manifest = cache / 'fixture-build.json'
    previous = json.loads(manifest.read_text()) if manifest.exists() else {}
    if previous.get('inputs') != inputs or not binary.exists() or previous.get('sha256') != digest(binary):
        for source in sources:
            shutil.copy2(source, cache / source.name)
        cmd = ['go', 'build', '-race', '-p', '2', '-o', str(binary), 'server.go', 'bind.go']
        env = {**os.environ, 'GOWORK': 'off', 'GOTOOLCHAIN': 'local'}
        if log_path:
            with Path(log_path).open('w') as log:
                subprocess.run(cmd, cwd=cache, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        else:
            subprocess.run(cmd, cwd=cache, env=env, check=True)
        assert all(digest(cache / p.name) == inputs[p.name] for p in sources)
        manifest.write_text(json.dumps({'inputs': inputs, 'sha256': digest(binary)}, indent=2) + '\n')
    return binary, sources, json.loads(manifest.read_text())
