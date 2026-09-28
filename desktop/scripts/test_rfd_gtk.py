#!/usr/bin/env python3
from pathlib import Path
import argparse,hashlib,json,os,socket,subprocess,tempfile,time
root=Path(__file__).resolve().parents[2]
parser=argparse.ArgumentParser(description='Check the patched rfd GTK filename boundary with a private Broadway display.')
parser.add_argument('--artifacts',type=Path,required=True)
args=parser.parse_args()
art=args.artifacts.resolve();art.mkdir(parents=True,exist_ok=False)
build=['cargo','test','--offline','--locked','--manifest-path',str(root/'desktop/vendor/rfd/Cargo.toml'),'--no-default-features','--features','gtk3','--lib','--target-dir',str(root/'desktop/src-tauri/target'),'--no-run','--message-format=json']
result=subprocess.run(build,capture_output=True,text=True,timeout=300,env={**os.environ,'CARGO_BUILD_JOBS':'2'})
(art/'build.log').write_text(result.stdout+result.stderr);result.check_returncode()
items=[json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
binary=Path(next(item['executable'] for item in items if item.get('reason')=='compiler-artifact' and item.get('executable') and item['target']['name']=='rfd'))
with (art/'unit.log').open('w') as log:
    unit=subprocess.run([str(binary),'backend::gtk3::file_dialog::dialog_ffi::tests','--test-threads=1'],stdout=log,stderr=subprocess.STDOUT,timeout=30)
unit.check_returncode()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
with tempfile.TemporaryDirectory(prefix='thronium-rfd-gtk-') as directory:
    work=Path(directory)
    for name in ['data','config','cache','runtime']:(work/name).mkdir(mode=0o700)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
    display=100+os.getpid()%30000
    env={**os.environ,'XDG_DATA_HOME':str(work/'data'),'XDG_CONFIG_HOME':str(work/'config'),'XDG_CACHE_HOME':str(work/'cache'),'XDG_RUNTIME_DIR':str(work/'runtime'),'GDK_BACKEND':'broadway','BROADWAY_DISPLAY':f':{display}','GTK_USE_PORTAL':'0','GSETTINGS_BACKEND':'memory','NO_AT_BRIDGE':'1','GIO_USE_VFS':'local'}
    with (art/'broadway.log').open('w') as log:
        server=subprocess.Popen(['broadwayd','--address=127.0.0.1',f'--port={port}',f':{display}'],env=env,stdout=log,stderr=subprocess.STDOUT)
        try:
            deadline=time.monotonic()+5
            while True:
                assert server.poll() is None, 'Owned Broadway server exited'
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.2):break
                except OSError:
                    if time.monotonic()>deadline:raise
                    time.sleep(.05)
            command=[str(binary),'backend::gtk3::file_dialog::dialog_ffi::tests::real_gtk_chooser_without_a_selection_returns_none','--exact','--ignored','--nocapture','--test-threads=1']
            with (art/'real-gtk.log').open('w') as log:
                result=subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=30)
            print((art/'real-gtk.log').read_text())
            (art/'real-gtk-summary.json').write_text(json.dumps({'exitCode':result.returncode,'binarySHA256':sha(binary),'sourceSHA256':sha(root/'desktop/vendor/rfd/src/backend/gtk3/file_dialog/dialog_ffi.rs'),'displayBackend':'private Broadway on loopback','chooserShown':False,'unitPassed':3,'gtkPassed':1,'buildCommand':build,'command':command},indent=2)+'\n')
            result.check_returncode()
        finally:
            server.terminate()
            try:server.wait(timeout=5)
            except subprocess.TimeoutExpired:server.kill();server.wait(timeout=5)
            assert server.poll() is not None
