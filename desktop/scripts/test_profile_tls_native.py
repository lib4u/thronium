#!/usr/bin/env python3
"""Pinned native TLS tests using an owned certificate-verified loopback fixture."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import subprocess

desktop=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--application',type=Path,required=True);p.add_argument('--application-sha256',required=True);p.add_argument('--core-sha256',required=True);p.add_argument('--artifacts',type=Path,required=True)
args=p.parse_args();app=args.application.resolve();core=app.with_name('ThroniumCore');sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
assert sha(app)==args.application_sha256 and sha(core)==args.core_sha256
out=args.artifacts.resolve();out.mkdir(parents=True,exist_ok=False);sources=out/'test-sources';sources.mkdir()
fixture=desktop/'engine/tests/fixtures/profile-tls/server.go';assert sha(fixture)=='9fb5803f7591b982cfd96dd6c43288b08653acdb9a333300ffd00cefa21a52f1'
files=[Path(__file__),fixture,*[desktop/name for name in ['tests/profile_tls_ui.py','tests/native_smoke.py','scripts/test_native.py','tests/native_transport.py','tests/native_screenshot.py','tests/native_processes.py','tests/native_menu.py','tests/tray_ui.py','tests/window_ui.py']]]
for path in files:shutil.copy2(path,sources/path.name)
source_hashes={str(path.relative_to(desktop)):sha(path) for path in files}
(out/'before-run.json').write_text(json.dumps({'applicationSha256':sha(app),'coreSha256':sha(core),'testSources':source_hashes},indent=2)+'\n')
binary=out/'tls-fixture';compile_command=['go','build','-o',str(binary),str(fixture)]
with (out/'fixture-build.log').open('w') as log:subprocess.run(compile_command,env={**os.environ,'GOWORK':'off','GOTOOLCHAIN':'local'},stdout=log,stderr=subprocess.STDOUT,check=True)
with (out/'fixture-stderr.log').open('w') as fixture_log:
    process=subprocess.Popen([str(binary),str(out/'fixture')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=fixture_log,text=True)
    try:
        assert select.select([process.stdout],[],[],10)[0],'Fixture did not become ready'
        ready=json.loads(process.stdout.readline());ready_path=out/'fixture-ready.json';ready_path.write_text(json.dumps(ready,indent=2)+'\n')
        command=['python3',str(desktop/'scripts/test_native.py'),'--application',str(app),'--profile-tls-only','--private-tray-bus','--artifacts',str(out)]
        env={**os.environ,'SSL_CERT_FILE':ready['ca'],'_THRONIUM_PROFILE_TLS_READY':str(ready_path)}
        (out/'command.json').write_text(json.dumps({'native':command,'fixtureBuild':compile_command,'fixtureSha256':sha(binary),'scope':'Private CA and XDG, own loopback HTTP CONNECT server; no external profile traffic or raw-socket spoof Start.'},indent=2)+'\n')
        with (out/'native.log').open('w') as log:result=subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT)
    finally:
        process.stdin.close()
        try:fixture_exit=process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.terminate();fixture_exit=process.wait(timeout=5)
    assert sha(app)==args.application_sha256 and sha(core)==args.core_sha256
    assert source_hashes=={str(path.relative_to(desktop)):sha(path) for path in files},'Test source changed during the pinned run'
    if result.returncode:
        (out/'attempt-status.json').write_text(json.dumps({'passed':False,'exitCode':result.returncode,'fixtureExitCode':fixture_exit,'pinnedInputsUnchanged':True},indent=2)+'\n');result.check_returncode()
    assert fixture_exit==0
    count=json.loads((out/'results.json').read_text())['count']
    (out/'summary.json').write_text(json.dumps({'passed':True,'checks':count,'exitCode':0,'fixtureExitCode':fixture_exit,'applicationSha256':sha(app),'coreSha256':sha(core),'testSourcesUnchanged':True,'pinnedInputsUnchanged':True},indent=2)+'\n')
    print(count,'PASS')
