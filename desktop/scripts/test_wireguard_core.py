#!/usr/bin/env python3
"""Run WireGuard loopback, custom-fragmentation and Core regressions in a private dependency overlay."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from build_core import TAGS
from core_overlay import prepare

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--cache', type=Path, help='Reuse a private dependency overlay and Go build paths between blocks')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    core = root / 'core/server'
    out = args.artifacts.resolve()
    out.mkdir(parents=True, exist_ok=False)
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    files = [*core.rglob('*.go'), core/'go.mod', core/'go.sum',
             *Path(__file__).parent.glob('*.py'),
             *Path(__file__).parent.joinpath('overlays').rglob('*.go'),
             root/'desktop/tests/external_core_fixture.py']
    before = {str(p.relative_to(root)): sha(p) for p in files}
    (out/'source-sha256.json').write_text(json.dumps(before, indent=2)+'\n')
    env = {**os.environ, 'CGO_ENABLED': '1', 'GOMAXPROCS': '2', 'CC': 'clang'}
    cache = args.cache.resolve() if args.cache else out / 'cache'
    modfile, overlay_hash = prepare(core, cache, env)
    module = Path(subprocess.check_output(
        ['go', 'list', '-modfile', str(modfile), '-m', '-f', '{{.Dir}}',
         'github.com/sagernet/sing-box'], cwd=core, env=env, text=True).strip())
    (module/'common/dialer').chmod(0o755)
    for name in ['fragment_test.go', 'default_fragment_test.go']:
        shutil.copy2(Path(__file__).parent/'overlays/sing-box'/name,
                     module/'common/dialer'/('thronium_'+name))
    for name in ['loopback', 'start']:
        shutil.copy2(Path(__file__).parent/('overlays/sing-box/wireguard_'+name+'_test.go'), module/('transport/wireguard/thronium_'+name+'_test.go'))
    wgmodule = Path(subprocess.check_output(['go','list','-modfile',str(modfile),'-m','-f','{{.Dir}}','github.com/sagernet/wireguard-go'],cwd=core,env=env,text=True).strip())
    for folder,name in [('device','awg_startup_test.go'),('device','awg_layout_test.go'),('conn','awg_bind_test.go')]:
        (wgmodule/folder).chmod(0o755)
        shutil.copy2(Path(__file__).parent/'overlays/wireguard'/name,wgmodule/folder/('thronium_'+name))
    linker = shutil.which('ld.lld')
    if not linker:
        sysroot = subprocess.check_output(['rustc', '--print', 'sysroot'], text=True).strip()
        host = next(s[6:] for s in subprocess.check_output(['rustc', '-vV'], text=True).splitlines() if s.startswith('host: '))
        linker = str(Path(sysroot)/'lib/rustlib'/host/'bin/gcc-ld/ld.lld')
    assert Path(linker).is_file(), 'LLVM linker required, as for the full Core build'
    flags = f'-checklinkname=0 -extld=clang -extldflags=-fuse-ld={linker} -X ThroneCore/parentcheck.expectedParentName=Thronium'
    command = ['go', 'test', '-race', '-json', '-count=1', '-timeout=180s',
               '-p', '2', '-modfile', str(modfile), '-tags', TAGS,
               '-ldflags', flags, '.', './test_utils',
               'github.com/sagernet/sing-box/common/dialer', 'github.com/sagernet/sing-box/transport/wireguard', 'github.com/sagernet/wireguard-go/device', 'github.com/sagernet/wireguard-go/conn']
    (out/'command.json').write_text(json.dumps(command, indent=2)+'\n')
    start = time.monotonic()
    with (out/'tests.jsonl').open('w') as log, (out/'stderr.log').open('w') as error_log:
        result = subprocess.run(command, cwd=core, env=env, stdout=log, stderr=error_log)
    after = {str(p.relative_to(root)): sha(p) for p in files}
    changes = {p: [before.get(p), after.get(p)] for p in before.keys() | after.keys() if before.get(p) != after.get(p)}
    events = [json.loads(line) for line in (out/'tests.jsonl').read_text().splitlines()]
    top = [e for e in events if e.get('Test') and '/' not in e['Test']]
    summary = {'passed': result.returncode == 0 and not changes,
               'exitCode': result.returncode, 'race': True, 'parentName': 'Thronium',
               'topLevelPass': sum(e['Action']=='pass' for e in top),
               'topLevelSkip': sum(e['Action']=='skip' for e in top),
               'packages': {e['Package']: e['Action'] for e in events if not e.get('Test') and e['Action'] in ['pass', 'fail']},
               'sourceChanges': changes, 'inputCount': len(before),
               'overlaySha256': overlay_hash, 'seconds': round(time.monotonic()-start, 2)}
    (out/'summary.json').write_text(json.dumps(summary, indent=2)+'\n')
    print(json.dumps(summary), flush=True)
    if not summary['passed'] or summary['topLevelSkip']:
        raise SystemExit(1)

if __name__ == '__main__':
    main()
