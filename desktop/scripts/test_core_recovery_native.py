#!/usr/bin/env python3
"""Run crash/recovery only against owned copies of a pinned application and core."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

desktop=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--application',type=Path,required=True);p.add_argument('--application-sha256',required=True)
p.add_argument('--core-sha256',required=True);p.add_argument('--artifacts',type=Path,required=True)
p.add_argument('--suite',choices=['core','system-proxy','kde'],default='core')
args=p.parse_args();original=args.application.resolve();core=original.with_name('ThroniumCore')
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
assert sha(original)==args.application_sha256 and sha(core)==args.core_sha256
out=args.artifacts.resolve();out.mkdir(parents=True,exist_ok=False);sources=out/'test-sources';sources.mkdir()
files=[Path(__file__),*[desktop/name for name in ['tests/core_recovery_ui.py','tests/native_smoke.py','scripts/test_native.py','tests/native_menu.py','tests/native_processes.py','tests/external_core_fixture.py','tests/native_transport.py','tests/window_ui.py','tests/native_screenshot.py','tests/tray_ui.py']]]
if args.suite=='kde':files.extend([desktop/'tests/kde_proxy_ui.py',desktop/'tests/system_proxy_guardian_fixture.py',desktop/'scripts/test_kde_proxy_native.py'])
if args.suite=='system-proxy':files.extend([desktop/'tests/system_proxy_recovery_ui.py',desktop/'scripts/test_system_proxy_recovery_native.py'])
for path in files:shutil.copy2(path,sources/path.name)
(out/'before-run.json').write_text(json.dumps(dict(applicationSha256=sha(original),coreSha256=sha(core),testSources={str(path.relative_to(desktop)):sha(path) for path in files}),indent=2)+'\n')
with tempfile.TemporaryDirectory(prefix='thronium-core-recovery-native-') as directory:
    root=Path(directory);app=root/'Thronium';copied=root/'ThroniumCore';shutil.copy2(original,app);shutil.copy2(core,copied)
    assert sha(app)==args.application_sha256 and sha(copied)==args.core_sha256
    env={**os.environ,'_THRONIUM_RECOVERY_ROOT':str(root)}
    flag='--kde-proxy-only' if args.suite=='kde' else '--system-proxy-recovery-only' if args.suite=='system-proxy' else '--core-recovery-only'
    command=['python3',str(desktop/'scripts/test_native.py'),'--application',str(app),flag,'--private-tray-bus','--artifacts',str(out)]
    (out/'command.json').write_text(json.dumps(dict(command=command,scope='Only copied executable/core; owned app child identity + pidfd for SIGKILL; private XDG/DBus; loopback traffic.'),indent=2)+'\n')
    with (out/'native.log').open('w') as log:result=subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT)
    assert sha(original)==args.application_sha256 and sha(core)==args.core_sha256,'Pinned inputs must remain unchanged'
    result.check_returncode();checks=json.loads((out/'results.json').read_text())
    (out/'summary.json').write_text(json.dumps(dict(passed=True,checks=checks['count'],exitCode=0,applicationSha256=sha(original),coreSha256=sha(core),pinnedInputsUnchanged=True),indent=2)+'\n')
    print(checks['count'],'PASS')
