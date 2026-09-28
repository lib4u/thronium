#!/usr/bin/env python3
"""Run portable launch scenarios only on an owned desktop and network namespace."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess

p=argparse.ArgumentParser(description=__doc__)
for name in ['application','artifacts','display-runner','accessibility-runner']:p.add_argument('--'+name,type=Path,required=True)
p.add_argument('--namespace-child',action='store_true');a=p.parse_args();out=a.artifacts.resolve();desktop=Path(__file__).resolve().parents[1]
if a.namespace_child:
    assert os.getpid()==1 and os.geteuid()==0 and os.readlink('/proc/self/ns/net')!=os.environ['THRONIUM_TEST_ORIGINAL_NETNS']
    subprocess.run(['mount','--make-rprivate','/'],check=True);subprocess.run(['mount','-t','tmpfs','-o','mode=755','tmpfs','/run'],check=True);subprocess.run(['ip','link','set','lo','up'],check=True)
    root=Path('/run/thronium-portable63');root.mkdir(mode=0o700)
    env={**os.environ,'_THRONIUM_PORTABLE_ROOT':str(root/'copies'),'ATSPI_DBUS_IMPLEMENTATION':'dbus-daemon','GSETTINGS_BACKEND':'memory','XDG_RUNTIME_DIR':str(root),'DBUS_SYSTEM_BUS_ADDRESS':'unix:path=/run/no-host-system-bus'}
    for key in list(env):
        if key.lower() in ('http_proxy','https_proxy','all_proxy','no_proxy','appimage','appdir'):env.pop(key)
    no_routes=not subprocess.check_output(['ip','route','show','default'],text=True).strip()
    cmd=['python3',str(a.display_runner),'--artifacts',str(out/'display'),'--','dbus-run-session','--','python3',str(a.accessibility_runner),str(out/'accessibility'),'python3',str(desktop/'scripts/test_native.py'),'--portable-only','--application',str(a.application),'--artifacts',str(out/'native')]
    result=subprocess.run(cmd,cwd=desktop.parent,env=env)
    (out/'namespace.json').write_text(json.dumps({'exitCode':result.returncode,'noExternalRoutes':no_routes,'privatePIDNamespace':True},indent=2)+'\n');assert no_routes;raise SystemExit(result.returncode)
out.mkdir(parents=True,exist_ok=False);sha=lambda path:hashlib.sha256(Path(path).read_bytes()).hexdigest();before={name:sha(name) for name in ['/etc/hosts','/etc/resolv.conf']}
env={**os.environ,'THRONIUM_TEST_ORIGINAL_NETNS':os.readlink('/proc/self/ns/net')}
cmd=['unshare','--user','--map-root-user','--map-auto','--net','--mount','--pid','--fork','--kill-child=SIGKILL','--mount-proc','python3',str(Path(__file__).resolve()),'--namespace-child']
for name in ['application','artifacts','display_runner','accessibility_runner']:cmd+=['--'+name.replace('_','-'),str(getattr(a,name).resolve())]
with (out/'runtime.log').open('w') as log:
    process=subprocess.Popen(cmd,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
    try:code=process.wait(timeout=420)
    finally:
        try:os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        process.wait()
record={'exitCode':code,'hostNetworkFilesUnchanged':all(sha(name)==value for name,value in before.items()),'privatePIDNamespaceExited':process.poll() is not None,'applicationSha256':sha(a.application),'coreSha256':sha(a.application.with_name('ThroniumCore'))}
(out/'summary.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record),flush=True);assert code==0 and record['hostNetworkFilesUnchanged']
