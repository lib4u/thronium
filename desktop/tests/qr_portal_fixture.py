"""Private screenshot portal fixture; never touches the user's portal."""
import pathlib
import shutil
import tempfile
import threading
import json
import os
import sys
import time
import signal
from gi.repository import Gio, GLib

class ScreenshotPortal:
    def __init__(self, address, fixture, control=None):
        self.control=pathlib.Path(control) if control else None
        self.directory=tempfile.TemporaryDirectory(prefix='thronium-qr-portal-')
        self.path=pathlib.Path(self.directory.name)/'screenshot.png';self.fixture=fixture;self.cancel=False;self.calls=[]
        self.connection=Gio.DBusConnection.new_for_address_sync(address,Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT|Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION,None,None)
        self.connection.call_sync('org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus','RequestName',GLib.Variant('(su)',('org.freedesktop.portal.Desktop',0)),None,Gio.DBusCallFlags.NONE,2000,None)
        info=Gio.DBusNodeInfo.new_for_xml('<node><interface name="org.freedesktop.portal.Screenshot"><property name="version" type="u" access="read"/><method name="Screenshot"><arg type="s" direction="in"/><arg type="a{sv}" direction="in"/><arg type="o" direction="out"/></method></interface></node>')
        self.registration=self.connection.register_object('/org/freedesktop/portal/desktop',info.interfaces[0],self.call,lambda *args:GLib.Variant('u',2),None)
        self.loop=GLib.MainLoop();self.thread=threading.Thread(target=self.loop.run,daemon=True);self.thread.start()
    def call(self, connection, sender, path, interface, method, parameters, invocation):
        _,options=parameters.unpack();self.calls.append(options)
        request='/org/freedesktop/portal/desktop/request/'+sender[1:].replace('.','_')+'/'+options['handle_token']
        if self.control:
            self.cancel=(self.control/'cancel').exists()
            (self.control/'state.json').write_text(json.dumps({'calls':self.calls,'path':str(self.path)}))
        if not self.cancel:shutil.copyfile(self.fixture,self.path)
        invocation.return_value(GLib.Variant('(o)',(request,)))
        def respond():
            connection.emit_signal(sender,request,'org.freedesktop.portal.Request','Response',GLib.Variant('(ua{sv})',(1 if self.cancel else 0,{} if self.cancel else {'uri':GLib.Variant('s',self.path.as_uri())})))
            return False
        GLib.timeout_add(80,respond)
    def close(self):
        self.connection.unregister_object(self.registration);self.connection.close_sync(None);self.loop.quit();self.thread.join(timeout=2);self.directory.cleanup()

if __name__=='__main__':
    control=pathlib.Path(sys.argv[1]);control.mkdir(parents=True,exist_ok=True)
    portal=ScreenshotPortal(os.environ['DBUS_SESSION_BUS_ADDRESS'],pathlib.Path(__file__).parent/'fixtures/import-qr.png',control)
    (control/'state.json').write_text(json.dumps({'calls':[],'path':str(portal.path)}))
    signal.signal(signal.SIGTERM, lambda *args: sys.exit(0))
    print('ready',flush=True)
    try:
        while True:time.sleep(1)
    finally:portal.close()
