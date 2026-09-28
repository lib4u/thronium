"""Run only inside dbus-run-session on an owned X display."""
from pathlib import Path
import json,os,signal,subprocess,sys,tempfile,time
from gi.repository import Gio,GLib
assert os.environ['DISPLAY'].startswith(':') and os.environ.get('XAUTHORITY','').startswith('/tmp/thronium-private-x11-')
args=sys.argv[1:];out=Path(args[0]);out.mkdir(parents=True,exist_ok=False)
with tempfile.TemporaryDirectory(prefix='thronium-private-accessibility-') as directory:
 env={**os.environ,'XDG_RUNTIME_DIR':directory};env.pop('AT_SPI_BUS_ADDRESS',None)
 with (out/'launcher.log').open('w') as log:
  launcher=subprocess.Popen(['/usr/libexec/at-spi-bus-launcher','--launch-immediately'],env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
  registry=None
  status={'launcherPid':launcher.pid,'privateRuntime':directory,'hostDisplayUsed':False}
  try:
   bus=Gio.bus_get_sync(Gio.BusType.SESSION,None)
   for _ in range(100):
    names=bus.call_sync('org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus','ListNames',None,None,Gio.DBusCallFlags.NONE,1000,None).unpack()[0]
    if 'org.a11y.Bus' in names:break
    assert launcher.poll() is None,'Owned accessibility launcher exited';time.sleep(.05)
   else:raise AssertionError('Owned accessibility launcher did not register')
   address=bus.call_sync('org.a11y.Bus','/org/a11y/bus','org.a11y.Bus','GetAddress',None,None,Gio.DBusCallFlags.NONE,2000,None).unpack()[0]
   assert directory in address,address
   env['AT_SPI_BUS_ADDRESS']=address;status['address']=address
   registry=subprocess.Popen(['/usr/libexec/at-spi2-registryd'],env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
   access=Gio.DBusConnection.new_for_address_sync(address,Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT|Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION,None,None)
   for _ in range(100):
    names=access.call_sync('org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus','ListNames',None,None,Gio.DBusCallFlags.NONE,1000,None).unpack()[0]
    if 'org.a11y.atspi.Registry' in names:break
    assert registry.poll() is None,'Owned accessibility registry exited';time.sleep(.05)
   else:raise AssertionError('Owned accessibility registry did not register')
   status['registryPid']=registry.pid
   # Reuse this owned bus, including its accessibility Status service. The
   # native runner must not create a second bus without the Status service.
   env['_THRONIUM_TEST_BUS']=env['DBUS_SESSION_BUS_ADDRESS']
   bus.call_sync('org.a11y.Bus','/org/a11y/bus','org.freedesktop.DBus.Properties','Set',GLib.Variant('(ssv)',('org.a11y.Status','IsEnabled',GLib.Variant('b',True))),None,Gio.DBusCallFlags.NONE,2000,None)
   bus.call_sync('org.a11y.Bus','/org/a11y/bus','org.freedesktop.DBus.Properties','Set',GLib.Variant('(ssv)',('org.a11y.Status','ScreenReaderEnabled',GLib.Variant('b',True))),None,Gio.DBusCallFlags.NONE,2000,None)
   command=[arg for arg in args[1:] if arg!='--private-tray-bus']
   status['command']=command
   result=subprocess.run(command,env=env);status['exitCode']=result.returncode
  finally:
   if registry:
    try:os.killpg(registry.pid,signal.SIGTERM)
    except ProcessLookupError:pass
    try:registry.wait(timeout=5)
    except subprocess.TimeoutExpired:os.killpg(registry.pid,signal.SIGKILL);registry.wait(timeout=5)
    status['registryReaped']=registry.poll() is not None and not Path('/proc',str(registry.pid)).exists()
   try:os.killpg(launcher.pid,signal.SIGTERM)
   except ProcessLookupError:pass
   try:launcher.wait(timeout=5)
   except subprocess.TimeoutExpired:os.killpg(launcher.pid,signal.SIGKILL);launcher.wait(timeout=5)
   status['launcherReaped']=launcher.poll() is not None and not Path('/proc',str(launcher.pid)).exists()
   (out/'summary.json').write_text(json.dumps(status,indent=2)+'\n')
 assert status['launcherReaped']
 raise SystemExit(status['exitCode'])
