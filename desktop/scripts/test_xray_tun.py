#!/usr/bin/env python3
"""Two isolated network namespaces: managed TUN client and real Xray server."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile

desktop = Path(__file__).resolve().parents[1]
artifacts = desktop / 'test-results/xray-tun'
artifacts.mkdir(parents=True, exist_ok=True)
(artifacts / 'results.json').unlink(missing_ok=True)
subprocess.run(['cargo','build','--locked','--manifest-path',str(desktop/'engine/Cargo.toml'),'--bin','xray-tun-smoke','-j','2'],check=True)
host = next(line[6:] for line in subprocess.check_output(['rustc','-vV'],text=True).splitlines() if line.startswith('host: '))
core = desktop/'src-tauri/binaries'/f'ThroniumCore-{host}'
before = hashlib.sha256(Path('/etc/resolv.conf').read_bytes()).hexdigest()
with tempfile.TemporaryDirectory(prefix='thronium-xray-tun-') as folder:
    root=Path(folder);shutil.copy2(core,root/'ThroniumCore');shutil.copy2(desktop/'engine/target/debug/xray-tun-smoke',root/'Thronium')
    env={**os.environ,'THRONIUM_TEST_ORIGINAL_NETNS':os.readlink('/proc/self/ns/net'),'DBUS_SYSTEM_BUS_ADDRESS':'unix:path='+str(root/'no-system-bus'),'DBUS_SESSION_BUS_ADDRESS':'unix:path='+str(root/'no-session-bus')}
    with (artifacts/'core.log').open('w+') as log:
        process=subprocess.Popen(['unshare','--user','--map-root-user','--net','--mount','sh','-c','mount --make-rprivate / && mount -t tmpfs -o mode=755 tmpfs /run && exec "$@"','sh',str(root/'Thronium')],env=env,start_new_session=True,stdout=log,stderr=subprocess.STDOUT)
        try:
            code=process.wait(timeout=150);log.flush();output=(artifacts/'core.log').read_text();print(output,end='')
            if code:raise SystemExit(code)
            assert hashlib.sha256(Path('/etc/resolv.conf').read_bytes()).hexdigest()==before
            (artifacts/'results.json').write_text(json.dumps({'checks':[s[5:] for s in output.splitlines() if s.startswith('PASS ')],'coreSha256':hashlib.sha256(core.read_bytes()).hexdigest(),'hostResolvConfUnchanged':True},indent=2)+'\n')
        finally:
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            process.wait()
