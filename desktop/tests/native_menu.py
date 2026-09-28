"""Read and activate DBusMenu only for the application in this test's private bus."""
import json
import os
from pathlib import Path
import xml.etree.ElementTree as ET
from gi.repository import Gio, GLib
from tray_ui import wait


class NativeMenu:
    def __init__(self):
        assert os.environ.get('_THRONIUM_TEST_BUS'), 'Use --private-tray-bus'
        self.bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        self.service, self.path, self.pid = wait(self.discover, 'isolated native menu')

    def call(self, service, path, interface, method, signature, args):
        return self.bus.call_sync(service, path, interface, method, GLib.Variant(signature, args), None, Gio.DBusCallFlags.NONE, 2000, None).unpack()

    def discover(self):
        names = self.call('org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'ListNames', '()', ())[0]
        for name in names:
            if not name.startswith(':'): continue
            try:
                pid = self.call('org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'GetConnectionUnixProcessID', '(s)', (name,))[0]
                proc = Path('/proc', str(pid))
                if proc.joinpath('comm').read_text().strip() != 'Thronium': continue
                expected = b'XDG_DATA_HOME=' + os.environ['XDG_DATA_HOME'].encode()
                if b'thronium-native-test-' not in expected or expected not in proc.joinpath('environ').read_bytes().split(b'\0'): continue
                paths = ['/']
                for path in paths:
                    node = ET.fromstring(self.call(name, path, 'org.freedesktop.DBus.Introspectable', 'Introspect', '()', ())[0])
                    if any(i.attrib['name'] == 'com.canonical.dbusmenu' for i in node.findall('interface')): return name, path, pid
                    paths.extend(path.rstrip('/') + '/' + child.attrib['name'] for child in node.findall('node'))
            except (GLib.Error, OSError): continue
        return None

    def tree(self):
        return self.call(self.service, self.path, 'com.canonical.dbusmenu', 'GetLayout', '(iias)', (0, -1, []))[1]

    def nodes(self, node=None):
        node = self.tree() if node is None else node
        yield node
        for child in node[2]: yield from self.nodes(child)

    def find(self, label):
        return next((n for n in self.nodes() if n[1].get('label') == label), None)

    def ready(self, label, enabled=True):
        return wait(lambda: (n := self.find(label)) and n[1].get('enabled', True) == enabled and n, label)

    def checked(self, label):
        node = self.find(label)
        return node is not None and node[1].get('toggle-state') == 1

    def activate(self, node):
        try:
            self.call(self.service, self.path, 'com.canonical.dbusmenu', 'AboutToShow', '(i)', (0,))
            self.call(self.service, self.path, 'com.canonical.dbusmenu', 'Event', '(isvu)', (node[0], 'clicked', GLib.Variant('s', ''), 0))
        except GLib.Error as error:
            if 'does not refer to a menu item' not in str(error): raise

    def save(self, path):
        Path(path).write_text(json.dumps(self.tree(), ensure_ascii=False, indent=2) + '\n')

    def dismiss_error(self, expected=None):
        import pyatspi
        def matches(node):
            return node.getRole() in (pyatspi.ROLE_DIALOG, pyatspi.ROLE_ALERT) and pyatspi.findDescendant(node, lambda n: n.getRole() == pyatspi.ROLE_LABEL and (expected is None or expected in n.name)) and pyatspi.findDescendant(node, lambda n: n.getRole() == pyatspi.ROLE_PUSH_BUTTON and n.name in ('OK','Ok'))
        def dialog():
            for app in pyatspi.Registry.getDesktop(0):
                if app.get_process_id() == self.pid:
                    # GTK can expose Information as the accessible alert name.
                    # Bind to the owned PID and message/button, not its title.
                    nodes=pyatspi.findAllDescendants(app,matches)
                    return nodes[0] if len(nodes)==1 else None
        node = wait(dialog, 'native error dialog')
        text = ' '.join(n.name for n in pyatspi.findAllDescendants(node, lambda n: n.getRole() == pyatspi.ROLE_LABEL))
        pyatspi.findDescendant(node, lambda n: n.getRole() == pyatspi.ROLE_PUSH_BUTTON and n.name in ('OK', 'Ok')).queryAction().doAction(0)
        return text
