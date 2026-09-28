"""Minimal StatusNotifierHost, exclusively on the runner's private bus."""
import os
from gi.repository import Gio, GLib

address = os.environ['DBUS_SESSION_BUS_ADDRESS']
assert address == os.environ.get('_THRONIUM_TEST_BUS') and 'thronium-native-test-' in address
bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
name = 'org.kde.StatusNotifierWatcher'
code = bus.call_sync('org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'RequestName', GLib.Variant('(su)', (name, 4)), None, Gio.DBusCallFlags.NONE, 1000, None).unpack()[0]
assert code == 1, 'Never replace an existing watcher'
node = Gio.DBusNodeInfo.new_for_xml('''<node><interface name="org.kde.StatusNotifierWatcher">
<method name="RegisterStatusNotifierItem"><arg type="s" direction="in"/></method>
<method name="RegisterStatusNotifierHost"><arg type="s" direction="in"/></method>
<property name="IsStatusNotifierHostRegistered" type="b" access="read"/>
<property name="RegisteredStatusNotifierItems" type="as" access="read"/>
<property name="ProtocolVersion" type="i" access="read"/>
<signal name="StatusNotifierItemRegistered"><arg type="s"/></signal>
<signal name="StatusNotifierHostRegistered"/>
</interface></node>''')
items = []
def method(connection, sender, path, interface, member, params, invocation):
    if member == 'RegisterStatusNotifierItem':
        value = params.unpack()[0]
        items.append(sender + value if value.startswith('/') else value)
        connection.emit_signal(None, path, interface, 'StatusNotifierItemRegistered', GLib.Variant('(s)', (items[-1],)))
    invocation.return_value(GLib.Variant('()', ()))
def property_value(connection, sender, path, interface, prop):
    return {'IsStatusNotifierHostRegistered': GLib.Variant('b', True), 'RegisteredStatusNotifierItems': GLib.Variant('as', items), 'ProtocolVersion': GLib.Variant('i', 0)}[prop]
bus.register_object('/StatusNotifierWatcher', node.interfaces[0], method, property_value, None)
print('READY', flush=True)
GLib.MainLoop().run()
