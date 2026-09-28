from pathlib import Path
import subprocess,os,sys
import argparse
p=argparse.ArgumentParser();p.add_argument('--artifacts',type=Path,required=True);p.add_argument('--archive',type=Path,required=True);p.add_argument('--display-runner',type=Path,required=True);p.add_argument('--accessibility-runner',type=Path,required=True);p.add_argument('--child',action='store_true');a=p.parse_args();b=a.artifacts.resolve();desktop=Path(__file__).resolve().parents[1]
if a.child:
 assert os.getpid()==1
 subprocess.run(['mount','--make-rprivate','/'],check=True);subprocess.run(['mount','-t','tmpfs','-o','mode=755','tmpfs','/run'],check=True);subprocess.run(['ip','link','set','lo','up'],check=True)
 root=Path('/run/dashboard-browser62');root.mkdir(mode=0o700)
 env={**os.environ,'XDG_RUNTIME_DIR':str(root),'XDG_DATA_HOME':str(root/'data'),'XDG_CONFIG_HOME':str(root/'config'),'DBUS_SYSTEM_BUS_ADDRESS':'unix:path=/run/no-system-bus','GSETTINGS_BACKEND':'memory','ATSPI_DBUS_IMPLEMENTATION':'dbus-daemon'}
 for k in list(env):
  if k.lower() in ('http_proxy','https_proxy','all_proxy','no_proxy'):env.pop(k)
 raise SystemExit(subprocess.call(['python3',str(a.display_runner),'--artifacts',str(b/'display'),'--','dbus-run-session','--','python3',str(a.accessibility_runner),str(b/'accessibility'),'python3',str(desktop/'tests/dashboard_browser.py'),'--artifacts',str(b/'browser'),'--archive',str(a.archive),'--bootstrap-dir',str(desktop/'engine/src/dashboard')],env=env))
b.mkdir(parents=True,exist_ok=False)
env={**os.environ,'THRONIUM_TEST_ORIGINAL_NETNS':os.readlink('/proc/self/ns/net')}
with (b/'runtime.log').open('w') as log:
 r=subprocess.run(['unshare','--user','--map-root-user','--map-auto','--net','--mount','--pid','--fork','--kill-child=SIGKILL','--mount-proc','python3',__file__,*sys.argv[1:],'--child'],env=env,stdout=log,stderr=subprocess.STDOUT,timeout=150)
print('browser exit',r.returncode);raise SystemExit(r.returncode)
