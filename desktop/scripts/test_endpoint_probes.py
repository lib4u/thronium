#!/usr/bin/env python3
"""Real TCP/ICMP against a veth peer with an intentionally unusable active VPN."""
import os,pathlib,subprocess,tempfile,shutil,json
desktop=pathlib.Path(__file__).resolve().parents[1]
subprocess.run(['cargo','build','--locked','--manifest-path',str(desktop/'engine/Cargo.toml'),'--bin','endpoint-probe-smoke','-j','2'],check=True)
with tempfile.TemporaryDirectory(prefix='thronium-endpoint-test-') as folder:
 root=pathlib.Path(folder)
 shutil.copy2(desktop/'engine/target/debug/endpoint-probe-smoke',root/'Thronium')
 shutil.copy2(desktop/'src-tauri/binaries/ThroniumCore-x86_64-unknown-linux-gnu',root/'ThroniumCore')
 env={**os.environ,'THRONIUM_TEST_ORIGINAL_NETNS':os.readlink('/proc/self/ns/net'),'DBUS_SYSTEM_BUS_ADDRESS':'unix:path='+str(root/'no-bus'),'DBUS_SESSION_BUS_ADDRESS':'unix:path='+str(root/'no-session')}
 result=subprocess.run(['unshare','--user','--map-root-user','--net','--mount','sh','-c','mount --make-rprivate / && mount -t tmpfs -o mode=755 tmpfs /run && sysctl -q -w net.ipv4.ping_group_range="0 0" && exec "$@"','sh','python3',str(desktop/'tests/l3_fixture.py'),str(root/'Thronium')],env=env,timeout=60,capture_output=True,text=True)
 artifacts=desktop/'test-results/endpoint-probes';artifacts.mkdir(parents=True,exist_ok=True)
 output=result.stdout+result.stderr;(artifacts/'namespace.log').write_text(output);print(output,end='')
 result.check_returncode()
 (artifacts/'results.json').write_text(json.dumps({'checks':[line[5:] for line in output.splitlines() if line.startswith('PASS ')]},indent=2)+'\n')
