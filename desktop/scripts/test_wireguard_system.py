#!/usr/bin/env python3
"""Pinned Core running a WireGuard endpoint on its own system interface, in a
private user/net namespace."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from wireguard_fixture import digest


def main():
    desktop = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core', required=True, type=Path)
    parser.add_argument('--core-sha256', required=True)
    parser.add_argument('--wg', required=True, type=Path)
    parser.add_argument('--artifacts', required=True, type=Path)
    args = parser.parse_args()
    core, wg, out = args.core.resolve(), args.wg.resolve(), args.artifacts.resolve()
    assert digest(core) == args.core_sha256
    out.mkdir(parents=True, mode=0o700, exist_ok=False)
    fixture = desktop / 'tests/wireguard_system_fixture.py'
    tracked = [Path(__file__), fixture, desktop / 'tests/vpn_auth_fixture.py', desktop / 'scripts/wireguard_fixture.py']
    hashes = {str(p.relative_to(desktop.parent)): digest(p) for p in tracked}
    original = os.readlink('/proc/self/ns/net')
    with tempfile.TemporaryDirectory(prefix='thronium-wg79-', dir='/tmp') as folder:
        root = Path(folder)
        shutil.copy2(core, root / 'ThroniumCore')
        shutil.copy2(sys.executable, root / 'Thronium')
        command = ['unshare', '-Urn', str(root / 'Thronium'), str(fixture), str(root), str(wg), str(out / 'system.json')]
        with (out / 'run.log').open('w') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=180,
                                    env={**os.environ, 'THRONIUM_TEST_ORIGINAL_NETNS': original, 'PYTHONPATH': str(desktop / 'tests')})
        for log in root.glob('*.log'):
            shutil.copy2(log, out / log.name)
        pinned = digest(core) == args.core_sha256 and all(digest(p) == hashes[str(p.relative_to(desktop.parent))] for p in tracked)
    interfaces = json.loads(subprocess.check_output(['ip', '-j', 'link'], text=True))
    summary = {'passed': result.returncode == 0 and pinned and os.readlink('/proc/self/ns/net') == original,
               'exit': result.returncode, 'pinsUnchanged': pinned, 'coreSha256': digest(core), 'wgSha256': digest(wg),
               'sources': hashes, 'hostNamespace': original, 'fixtureDirectoryRemoved': not root.exists(),
               'hostInterfaces': sorted(link['ifname'] for link in interfaces)}
    (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary), flush=True)
    assert summary['passed'] and summary['fixtureDirectoryRemoved']


if __name__ == '__main__':
    main()
