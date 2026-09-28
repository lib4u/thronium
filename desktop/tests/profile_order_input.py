"""Trusted X11 input confined to the verified disposable Thronium client window."""
import contextlib
import os
from pathlib import Path
import time

from window_ui import primary


class OwnedInput:
    def __init__(self, h):
        from Xlib import X
        self.h = h
        self.display, self.window, self.pid = primary()
        self.root = self.display.screen().root
        self.process = Path('/proc', str(self.pid))
        self.starttime = self.process.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19]
        self.executable = Path(h['args'].application).resolve()
        self.pressed = False
        self.keys_down = []
        self.pointer = self.root.query_pointer()
        assert self.display.has_extension('XTEST'), 'Trusted drag requires the XTEST extension'
        self.verify()
        self.h['js']('''window.__profileOrderInput={events:[]};
        const a=window.__profileOrderInput;a.observe=e=>{
          const handle=e.target instanceof Element?e.target.closest('[data-profile-drag]'):null;
          const row=e.target instanceof Element?e.target.closest('[data-order-profile]'):null;
          a.events.push({type:e.type,trusted:e.isTrusted,key:e.key??null,alt:e.altKey??false,
            handle:handle?.dataset.profileDrag??null,row:row?.dataset.orderProfile??null,
            x:e.clientX??null,y:e.clientY??null,pointerId:e.pointerId??null,buttons:e.buttons??null,hitRow:document.elementFromPoint(e.clientX??-1,e.clientY??-1)?.closest('[data-order-profile]')?.dataset.orderProfile??null,types:e.dataTransfer?[...e.dataTransfer.types]:[]});
        };a.types=['pointerdown','pointermove','pointerup','gotpointercapture','lostpointercapture','mousedown','mouseup','click','dragstart','dragover','drop','dragend','keydown','blur'];
        a.types.forEach(type=>document.addEventListener(type,a.observe,true));window.addEventListener('blur',a.observe,true);''')

    def verify(self):
        assert self.process.joinpath('exe').resolve() == self.executable
        assert self.process.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19] == self.starttime
        scope = os.environ['XDG_DATA_HOME']
        assert 'thronium-native-test-' in scope
        assert b'XDG_DATA_HOME=' + scope.encode() in self.process.joinpath('environ').read_bytes().split(b'\0')

    def activate(self):
        from Xlib import X, protocol
        self.verify()
        self.root.send_event(protocol.event.ClientMessage(window=self.window,
            client_type=self.display.intern_atom('_NET_ACTIVE_WINDOW'),
            data=(32, [2, X.CurrentTime, 0, 0, 0])),
            event_mask=X.SubstructureRedirectMask | X.SubstructureNotifyMask)
        self.display.sync()
        end = time.monotonic() + 3
        while time.monotonic() < end:
            active = self.root.get_full_property(self.display.intern_atom('_NET_ACTIVE_WINDOW'), X.AnyPropertyType)
            if active is not None and len(active.value) and int(active.value[0]) == self.window.id:
                return
            time.sleep(.05)
        raise AssertionError('The owned test window did not become active')

    def screen_point(self, point):
        self.verify()
        native = self.window.get_geometry()
        viewport = self.h['js']('return {width:innerWidth,height:innerHeight}')
        assert native.width == viewport['width'] and native.height == viewport['height'], 'Native/client geometry mismatch'
        x, y = round(point['x']), round(point['y'])
        assert 0 <= x < native.width and 0 <= y < native.height, 'Pointer target outside owned client window'
        origin = self.root.translate_coords(self.window, 0, 0)
        return origin.x + x, origin.y + y

    def point(self, selector, edge='center'):
        return self.h['js']('''const e=document.querySelector(arguments[0]);if(!e)throw new Error('Missing input target');
        const r=e.getBoundingClientRect();return {x:r.left+r.width/2,y:arguments[1]==='before'?r.top+7:arguments[1]==='after'?r.bottom-7:r.top+r.height/2};''', selector, edge)

    def move(self, point):
        from Xlib import X
        from Xlib.ext import xtest
        x, y = self.screen_point(point)
        xtest.fake_input(self.display, X.MotionNotify, root=self.root.id, x=x, y=y)
        self.display.sync()

    def click(self, selector):
        from Xlib import X
        from Xlib.ext import xtest
        self.activate()
        self.move(self.point(selector))
        xtest.fake_input(self.display, X.ButtonPress, 1)
        self.pressed = True
        self.display.sync()
        time.sleep(.04)
        self.release()

    def secondary_click(self, selector):
        """The press that asks a window for its context menu."""
        from Xlib import X
        from Xlib.ext import xtest
        self.activate()
        self.move(self.point(selector))
        xtest.fake_input(self.display, X.ButtonPress, 3)
        self.display.sync()
        time.sleep(.04)
        xtest.fake_input(self.display, X.ButtonRelease, 3)
        self.display.sync()

    def start_drag(self, selector):
        from Xlib import X
        from Xlib.ext import xtest
        self.activate()
        start = self.point(selector)
        self.move(start)
        xtest.fake_input(self.display, X.ButtonPress, 1)
        self.pressed = True
        self.display.sync()
        time.sleep(.08)
        # Cross GTK's native drag threshold within the owned row.
        for step in range(1, 7):
            self.move({'x': start['x'] + step * 2, 'y': start['y'] + step})
            time.sleep(.03)

    def drag_to(self, point):
        assert self.pressed
        current = self.window.query_pointer()
        for step in range(1, 13):
            self.move({'x': current.win_x + (point['x'] - current.win_x) * step / 12,
                       'y': current.win_y + (point['y'] - current.win_y) * step / 12})
            time.sleep(.025)

    def release(self):
        from Xlib import X
        from Xlib.ext import xtest
        if self.pressed:
            xtest.fake_input(self.display, X.ButtonRelease, 1)
            self.display.sync()
            self.pressed = False

    def key(self, name, alt=False):
        from Xlib import X, XK
        from Xlib.ext import xtest
        self.verify()
        active = self.root.get_full_property(self.display.intern_atom('_NET_ACTIVE_WINDOW'), X.AnyPropertyType)
        assert active is not None and int(active.value[0]) == self.window.id, 'Keyboard target is not the owned active window'
        codes = ([self.display.keysym_to_keycode(XK.string_to_keysym('Alt_L'))] if alt else [])
        codes.append(self.display.keysym_to_keycode(XK.string_to_keysym(name)))
        assert all(codes)
        try:
            for code in codes:
                xtest.fake_input(self.display, X.KeyPress, code)
                self.keys_down.append(code)
            self.display.sync()
            time.sleep(.04)
        finally:
            for code in reversed(self.keys_down): xtest.fake_input(self.display, X.KeyRelease, code)
            self.keys_down.clear()
            self.display.sync()

    @contextlib.contextmanager
    def blur(self):
        from Xlib import X
        self.verify()
        # A tiny owned X window supplies a real focus change; no foreign app is focused.
        origin = self.root.translate_coords(self.window, 0, 0)
        target = self.root.create_window(origin.x + 2, origin.y + 2, 1, 1, 0,
            self.display.screen().root_depth, X.InputOutput, X.CopyFromParent,
            override_redirect=True, event_mask=X.FocusChangeMask)
        try:
            target.map()
            self.display.sync()
            target.set_input_focus(X.RevertToParent, X.CurrentTime)
            self.display.sync()
            time.sleep(.15)
            yield
        finally:
            target.destroy()
            self.window.set_input_focus(X.RevertToParent, X.CurrentTime)
            self.display.sync()
            self.activate()

    def events(self):
        return self.h['js']('return window.__profileOrderInput.events')

    def close(self):
        from Xlib import X
        from Xlib.ext import xtest
        with contextlib.suppress(Exception):
            self.release()
            for code in reversed(self.keys_down): xtest.fake_input(self.display, X.KeyRelease, code)
            self.keys_down.clear()
            self.h['js']('''const a=window.__profileOrderInput;if(a){a.types.forEach(type=>document.removeEventListener(type,a.observe,true));window.removeEventListener('blur',a.observe,true);delete window.__profileOrderInput}''')
        # Restore pointer position with motion only; never click a foreign window.
        xtest.fake_input(self.display, X.MotionNotify, root=self.root.id, x=self.pointer.root_x, y=self.pointer.root_y)
        self.display.sync()
        self.display.close()
