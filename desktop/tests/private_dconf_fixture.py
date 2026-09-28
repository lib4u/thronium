"""Own dconf explicitly on the disposable bus; never autoactivate a user service."""
import json
import os
from pathlib import Path
import subprocess
import time
from gi.repository import Gio,GLib


class PrivateDconf:
    def __init__(self,root,env,artifacts):
        assert root.name.startswith('thronium-native-test-')
        assert env['DBUS_SESSION_BUS_ADDRESS']==env['_THRONIUM_TEST_BUS']
        assert env['DISPLAY'].startswith(':') and env['XAUTHORITY'].startswith('/tmp/thronium-private-x11-')
        self.output=Path(artifacts);self.output.mkdir(parents=True,exist_ok=True)
        self.bus=Gio.DBusConnection.new_for_address_sync(env['_THRONIUM_TEST_BUS'],Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT|Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION,None,None)
        assert not self.call('NameHasOwner','(s)',('ca.desrt.dconf',)), 'A dconf service already owns this bus; refuse to use it'
        profile=root/'dconf-profile';profile.write_text('user-db:thronium_proxy_test\n');profile.chmod(0o600)
        Path(env['XDG_CONFIG_HOME']).mkdir(parents=True,exist_ok=True,mode=0o700)
        env.update(DCONF_PROFILE=str(profile),GSETTINGS_BACKEND='dconf')
        self.log=(self.output/'private-dconf.log').open('w')
        self.child=subprocess.Popen(['/usr/libexec/dconf-service'],env=env,stdout=self.log,stderr=subprocess.STDOUT)
        try:
            for _ in range(100):
                assert self.child.poll() is None
                if self.call('NameHasOwner','(s)',('ca.desrt.dconf',)):break
                time.sleep(.03)
            assert self.call('GetConnectionUnixProcessID','(s)',('ca.desrt.dconf',))==self.child.pid
        except BaseException:self.close();raise
        env['_THRONIUM_PRIVATE_DCONF_PID']=str(self.child.pid)
        self.env={k:env[k] for k in ['XDG_CONFIG_HOME','DCONF_PROFILE','DBUS_SESSION_BUS_ADDRESS']}
    def call(self,name,signature,args):
        return self.bus.call_sync('org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus',name,GLib.Variant(signature,args),None,Gio.DBusCallFlags.NO_AUTO_START,1000,None).unpack()[0]
    def close(self):
        if self.child.poll() is None:
            self.child.terminate()
            try:self.child.wait(timeout=3)
            except subprocess.TimeoutExpired:self.child.kill();self.child.wait(timeout=3)
        self.log.close()
        self.bus.close_sync(None)
        (self.output/'private-dconf-cleanup.json').write_text(json.dumps({'pid':self.child.pid,'reaped':not Path('/proc',str(self.child.pid)).exists(),'environment':getattr(self,'env',{})},indent=2)+'\n')
