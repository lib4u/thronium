"""Independent RFD chooser diagnostic; original interactions, observed action state."""
import pathlib
import os
import time


def file_dialog(title, path=None, opening=False, audit=None, wait_ready=False):
    import pyatspi
    deadline = time.monotonic() + 12
    dialog = None
    while time.monotonic() < deadline and dialog is None:
        for app in pyatspi.Registry.getDesktop(0):
            if app.name != 'Thronium': continue
            try:
                environment = (pathlib.Path('/proc') / str(app.get_process_id()) / 'environ').read_bytes()
                expected = os.environ.get('XDG_DATA_HOME', '')
                scopes = [v for v in environment.split(b'\0') if v.startswith(b'XDG_DATA_HOME=') and b'thronium-native-test-' in v]
                if not scopes or ('thronium-native-test-' in expected and b'XDG_DATA_HOME=' + expected.encode() not in scopes): continue
                dialog = pyatspi.findDescendant(app, lambda n: n.name == title and n.getRole() in (pyatspi.ROLE_DIALOG, pyatspi.ROLE_FILE_CHOOSER) and n.getState().contains(pyatspi.STATE_SHOWING))
                if dialog: break
            except (OSError, RuntimeError): pass
        if dialog is None: time.sleep(.1)
    if dialog is None: raise AssertionError('Native file chooser did not open in the isolated application')
    if path is not None:
        if opening:
            # Send Ctrl+L directly to the verified disposable GTK chooser.
            # AT-SPI synthesized keyboard events can be ignored under Xwayland.
            from Xlib import X, XK, protocol
            from native_screenshot import connect
            connection = connect()
            try:
                matches = []
                mapped_deadline = time.monotonic() + 5
                while time.monotonic() < mapped_deadline:
                    clients = connection.screen().root.get_full_property(connection.intern_atom('_NET_CLIENT_LIST'), X.AnyPropertyType)
                    matches = []
                    for wid in clients.value if clients is not None else []:
                        window = connection.create_resource_object('window', int(wid))
                        pid = window.get_full_property(connection.intern_atom('_NET_WM_PID'), X.AnyPropertyType)
                        if pid is None or int(pid.value[0]) != dialog.get_process_id():
                            continue
                        # ICCCM WM_NAME may be legacy STRING/COMPOUND_TEXT;
                        # modern GTK publishes its actual Unicode title here.
                        window_title = window.get_full_text_property(connection.intern_atom('_NET_WM_NAME'), connection.intern_atom('UTF8_STRING')) or window.get_wm_name()
                        if window_title == title and window.get_attributes().map_state == X.IsViewable:
                            matches.append(window)
                    if len(matches) == 1: break
                    time.sleep(.05)
                if len(matches) != 1: raise AssertionError('Expected one mapped disposable native file chooser')
                window = matches[0]
                for event in (protocol.event.KeyPress, protocol.event.KeyRelease):
                    window.send_event(event(time=X.CurrentTime, root=connection.screen().root, window=window,
                        child=X.NONE, root_x=0, root_y=0, event_x=0, event_y=0, state=X.ControlMask,
                        detail=connection.keysym_to_keycode(XK.string_to_keysym('l')), same_screen=1), propagate=True)
                connection.sync()
            finally: connection.close()
        entry_deadline = time.monotonic() + 3
        entries = []
        while time.monotonic() < entry_deadline:
            entries = pyatspi.findAllDescendants(dialog, lambda n: n.getRole() == pyatspi.ROLE_TEXT and n.getState().contains(pyatspi.STATE_EDITABLE) and n.getState().contains(pyatspi.STATE_SHOWING))
            if entries: break
            time.sleep(.05)
        if not entries: raise AssertionError("Native file chooser has no visible editable path field")
        named = [e for e in entries if 'name' in e.name.lower() or 'имя' in e.name.lower()]
        entry = named[0] if named else entries[0]
        entry.queryComponent().grabFocus()
        entry.queryEditableText().setTextContents(str(path))
        time.sleep(.15)
    labels = ('Open', '_Open', 'Открыть') if path is not None and opening else ('Save', '_Save', 'Сохранить') if path is not None else ('Cancel', '_Cancel', 'Отмена')
    button = pyatspi.findDescendant(dialog, lambda n: n.getRole() == pyatspi.ROLE_PUSH_BUTTON and n.name in labels)
    if button is None: raise AssertionError('Native save/cancel button is missing')
    if wait_ready:
        ready_deadline = time.monotonic() + 5
        while time.monotonic() < ready_deadline:
            state = button.getState()
            if state.contains(pyatspi.STATE_ENABLED) and state.contains(pyatspi.STATE_SENSITIVE) and (path is None or entry.queryText().getText(0, -1) == str(path)):
                break
            time.sleep(.05)
        else:
            raise AssertionError('Native chooser action did not become enabled with the exact path')
    info = {'title': title, 'opening': opening, 'hasPath': path is not None,
            'buttonEnabled': button.getState().contains(pyatspi.STATE_ENABLED),
            'buttonSensitive': button.getState().contains(pyatspi.STATE_SENSITIVE),
            'buttonShowing': button.getState().contains(pyatspi.STATE_SHOWING)}
    if path is not None:
        info['entryMatchesRequestedPath'] = entry.queryText().getText(0, -1) == str(path)
    info['actionAccepted'] = bool(button.queryAction().doAction(0))
    if audit is not None: audit.append(info)
    if wait_ready:
        closed_deadline = time.monotonic() + 5
        while time.monotonic() < closed_deadline:
            try:
                if not dialog.getState().contains(pyatspi.STATE_SHOWING):
                    break
            except (RuntimeError, LookupError):
                break
            time.sleep(.05)
        else:
            info['chooserStillShowingAfterAction'] = True
            info['buttonSensitiveAfterAction'] = button.getState().contains(pyatspi.STATE_SENSITIVE)
            info['entryStillMatches'] = path is None or entry.queryText().getText(0, -1) == str(path)
