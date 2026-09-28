"""Capture only the disposable X11 test window, without WebKit snapshot RPCs."""
from pathlib import Path
import os
import json
import re
import stat


def private_display_server():
    """Permit composited capture only on our ancestor's private Xvfb server."""
    screen = re.fullmatch(r':(\d+)(?:\.0)?', os.environ.get('DISPLAY', ''))
    authority = Path(os.environ.get('XAUTHORITY', '/missing-authority'))
    if not screen or not authority.parent.name.startswith('thronium-private-x11-'):
        return None
    try:
        info = authority.stat()
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            return None
        pid = int(Path('/tmp', '.X'+screen[1]+'-lock').read_text().strip())
        process = Path('/proc', str(pid))
        executable = process.joinpath('exe').resolve()
        args = process.joinpath('cmdline').read_bytes().split(b'\0')
        if executable.name != 'Xvfb' or process.stat().st_uid != os.getuid():
            return None
        if (':'+screen[1]).encode() not in args:
            return None
        if b'-auth' not in args or args[args.index(b'-auth')+1] != os.fsencode(authority):
            return None
        fields = process.joinpath('stat').read_text().rsplit(')', 1)[1].split()
        owner = int(fields[1])
        ancestor = os.getppid()
        while ancestor > 1 and ancestor != owner:
            ancestor = int(Path('/proc', str(ancestor), 'stat').read_text().rsplit(')', 1)[1].split()[1])
        if ancestor != owner:
            return None
        return {'pid': pid, 'starttime': fields[19], 'exe': str(executable), 'owner': owner}
    except (OSError, ValueError, IndexError):
        return None


def connect():
    import socket
    from Xlib import X, display, xauth
    from Xlib.support import unix_connect
    # Mutter can write FamilyWild entries with an empty display number.
    # libX11 accepts those; python-xlib's exact-number lookup does not.
    original_auth = unix_connect.get_auth
    def local_auth(sock, dname, protocol, host, dno):
        result = original_auth(sock, dname, protocol, host, dno)
        if result[0] or sock.family != socket.AF_UNIX: return result
        for family, _address, number, name, data in xauth.Xauthority().entries:
            if family == 65535 and number in (b'', str(dno).encode()) and name == b'MIT-MAGIC-COOKIE-1':
                return name, data
        return result
    unix_connect.get_auth = local_auth
    try:
        connection = display.Display()
    finally:
        unix_connect.get_auth = original_auth
    return connection


def capture(path):
    from Xlib import X
    from PIL import Image
    connection = connect()
    try:
        root = connection.screen().root
        clients = root.get_full_property(connection.intern_atom('_NET_CLIENT_LIST'), X.AnyPropertyType)
        candidates = []
        for wid in clients.value if clients is not None else []:
            window = connection.create_resource_object('window', int(wid))
            pid = window.get_full_property(connection.intern_atom('_NET_WM_PID'), X.AnyPropertyType)
            if pid is None or not len(pid.value): continue
            try:
                process = Path('/proc') / str(int(pid.value[0]))
                if (process / 'comm').read_text().strip() != 'Thronium': continue
                environment = (process / 'environ').read_bytes().split(b'\0')
                scopes = [v for v in environment if v.startswith(b'XDG_DATA_HOME=') and b'thronium-native-test-' in v]
                expected = os.environ.get('XDG_DATA_HOME', '')
                if not scopes or ('thronium-native-test-' in expected and b'XDG_DATA_HOME=' + expected.encode() not in scopes): continue
            except OSError: continue
            if window.get_attributes().map_state == X.IsViewable: candidates.append(window)
        if len(candidates) != 1:
            raise AssertionError('Expected exactly one visible disposable Thronium window')
        window = candidates[0]
        geometry = window.get_geometry()
        private = private_display_server()
        if private:
            # GetImage on a WebKit client window can omit composited text/input
            # layers. Read the displayed pixels, bounded to the verified client
            # rectangle, only on our private Xvfb. Never capture the host root.
            origin = root.translate_coords(window, 0, 0)
            bounds = root.get_geometry()
            if origin.x < 0 or origin.y < 0 or origin.x + geometry.width > bounds.width or origin.y + geometry.height > bounds.height:
                raise AssertionError('Owned window is partly outside the private screen')
            pixels = root.get_image(origin.x, origin.y, geometry.width, geometry.height, X.ZPixmap, 0xffffffff)
            if private_display_server() != private:
                raise AssertionError('Private display ownership changed during capture')
        else:
            pixels = window.get_image(0, 0, geometry.width, geometry.height, X.ZPixmap, 0xffffffff)
        if pixels is None or pixels.depth != 24:
            raise AssertionError('The X11 screenshot requires a 24-bit test display')
        Image.frombytes('RGB', (geometry.width, geometry.height), pixels.data, 'raw', 'BGRX').save(path)
        Path(path).with_suffix('.capture.json').write_text(json.dumps({
            'mode': 'owned-private-composited' if private else 'owned-client-window',
            'clientWindow': window.id, 'width': geometry.width, 'height': geometry.height,
            'privateServer': private,
        }, indent=2)+'\n')
    finally:
        connection.close()
