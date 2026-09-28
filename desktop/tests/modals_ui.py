"""Dialog stacking, focus, centering and draft protection in actual WebKitGTK."""


def run(h):
    command, click, fill, select, wait_for, js, check, screenshot = (h[k] for k in ('command', 'click', 'fill', 'select', 'wait_for', 'js', 'check', 'screenshot'))
    request, base = h['request'], h['base']
    initial = command('snapshot')
    routing = command('routing')

    def resize(width, height):
        request('POST', base + '/window/rect', {'width': width, 'height': height})
        wait_for(f'return innerWidth==={width} && innerHeight==={height}')

    def centered(selector):
        return js('const e=document.querySelector(arguments[0]),r=e.getBoundingClientRect();return r.width>0&&Math.abs(r.x+r.width/2-innerWidth/2)<2&&Math.abs(r.y+r.height/2-innerHeight/2)<2&&r.x>=0&&r.y>=0&&r.right<=innerWidth&&r.bottom<=innerHeight&&e.scrollWidth<=e.clientWidth', selector)

    def opened():
        wait_for('return document.querySelectorAll("dialog[open]").length===2 && !!document.querySelector(".confirmation-modal")')
        return centered('.confirmation-modal') and js('return document.querySelectorAll("dialog:modal").length===2 && document.querySelector(".confirmation-modal").parentElement===document.body && !document.querySelector("#main-modal").contains(document.querySelector(".confirmation-modal"))')

    def no_confirmation():
        wait_for('return document.querySelectorAll("dialog[open]").length===1 && !document.querySelector(".confirmation-modal")')

    def close_draft():
        click('#main-modal > .modal-head .icon-button')
        click('[data-confirm-accept]')
        wait_for('return !document.querySelector("dialog")')

    def key(value):
        # WebKitWebDriver cannot send keys to buttons. Send a native X11 event
        # only to the verified disposable application (never the user's window).
        from Xlib import X, XK, protocol
        from window_ui import primary
        count = js('return window.__modalKeys.length')
        connection, window, _pid = primary()
        try:
            for event in (protocol.event.KeyPress, protocol.event.KeyRelease):
                window.send_event(event(time=X.CurrentTime, root=connection.screen().root, window=window,
                    child=X.NONE, root_x=0, root_y=0, event_x=0, event_y=0, state=0,
                    detail=connection.keysym_to_keycode(XK.string_to_keysym(value)), same_screen=1), propagate=True)
            connection.sync()
        finally:
            connection.close()
        wait_for('return window.__modalKeys.length>' + str(count))

    try:
        js('window.__modalKeys=[];window.__modalKeyObserver=e=>window.__modalKeys.push({key:e.key,trusted:e.isTrusted});document.addEventListener("keydown",window.__modalKeyObserver,true)')
        command('preferences', {**initial['preferences'], 'language': 'ru', 'theme': 'light'})
        wait_for('return document.documentElement.lang==="ru"')
        resize(1280, 860)
        click('.add-connection'); click('#add-choice-advanced'); select('#profile-type', 'amneziawg'); fill('#profile-name', 'Modal draft')
        click('[data-profile-tab="json"]')
        before = js('const d=document.querySelector("#main-modal");return {rect:d.getBoundingClientRect().toJSON(),text:document.querySelector("#profile-json").value,scroll:d.querySelector(".modal-body").scrollTop}')
        click('#main-modal > .modal-head .icon-button')
        check(opened(), 'unsaved profile confirmation is a separate centered top-layer dialog above the editor')
        check(js('return document.querySelector("#main-modal").getBoundingClientRect().toJSON()') == before['rect'], 'opening confirmation does not move or resize its underlying editor')
        check(js('return document.activeElement.matches("[data-confirm-cancel]")'), 'confirmation initially focuses Keep editing instead of discarding')
        check(js('const ids=[...document.querySelectorAll("[id]")].map(e=>e.id);return ids.length===new Set(ids).size && [...document.querySelectorAll("dialog")].every(d=>document.getElementById(d.getAttribute("aria-labelledby"))?.closest("dialog")===d)'), 'stacked dialogs have unique IDs and their own accessible titles')
        check(js('const d=document.querySelector(".confirmation-modal"),r=d.getBoundingClientRect();return d.contains(document.elementFromPoint(r.x+r.width/2,r.y+r.height/2)) && !document.querySelector("#main-modal").contains(document.elementFromPoint(5,5))'), 'confirmation and its backdrop receive hits above the parent window')
        js('document.querySelector("#profile-json").focus()')
        check(js('return document.activeElement.closest(".confirmation-modal")!==null'), 'the obscured editor cannot take keyboard focus')
        for _ in range(5): key('Tab')
        check(js('return document.activeElement.closest(".confirmation-modal")!==null'), 'native Tab navigation stays inside the top confirmation')
        check(js('return window.__modalKeys.length===5 && window.__modalKeys.every(e=>e.key==="Tab"&&e.trusted)'), 'keyboard checks use actual native events in the isolated webview')
        screenshot('modal-discard-over-editor-light-ru')
        key('Escape')
        no_confirmation()
        check(js('return document.querySelector("#profile-json").value') == before['text'], 'Escape cancels only confirmation and preserves the parent draft')
        check(js('return document.activeElement.closest("#main-modal")!==null'), 'closing confirmation returns keyboard focus to the editor')
        for width, height in ((390, 844), (768, 600), (1280, 600)):
            resize(width, height)
            js('document.querySelector("#main-modal .modal-body").scrollTop=99999')
            click('#main-modal > .modal-head .icon-button')
            check(opened(), f'confirmation stays centered at {width}x{height} after editor scrolling')
            check(js('const d=document.querySelector(".confirmation-modal");return [...d.querySelectorAll(".modal-footer button")].every(e=>{const r=e.getBoundingClientRect();return r.top>=0&&r.bottom<=innerHeight&&r.left>=0&&r.right<=innerWidth})'), f'confirmation actions remain visible at {width}x{height}')
            if width == 390: screenshot('modal-discard-narrow-ru')
            click('.confirmation-modal > .modal-head .icon-button'); no_confirmation()
        resize(1280, 860)
        command('preferences', {**command('snapshot')['preferences'], 'language': 'en', 'theme': 'dark'})
        wait_for('return document.documentElement.lang==="en"')
        click('#main-modal > .modal-head .icon-button')
        check(opened() and js('return document.querySelector(".confirmation-modal h2").textContent.includes("Discard")'), 'English dark confirmation uses the same centered layout')
        screenshot('modal-discard-over-editor-dark-en')
        click('[data-confirm-accept]')
        wait_for('return !document.querySelector("dialog")')
        check(command('snapshot')['profiles'] == initial['profiles'], 'explicit discard closes both dialogs without saving a profile')

        click('.add-connection'); click('#add-choice-advanced'); select('#profile-type', 'amneziawg')
        fill('[data-field="private_key"]', 'existing-fixture-key')
        click('.editor-keygen > .button')
        check(opened(), 'replacing a WireGuard key asks in the top centered dialog')
        click('[data-confirm-cancel]'); no_confirmation()
        check(js('return document.querySelector("[data-field=private_key]").value') == 'existing-fixture-key', 'cancelling key replacement retains the previous key')
        click('.editor-keygen > .button'); click('[data-confirm-accept]'); no_confirmation()
        check(js('return document.querySelector("[data-field=private_key]").value.length===44'), 'confirmed key generation updates only the draft and returns to its editor')
        close_draft()

        click('.primary-nav button:nth-child(2)'); click('#route-add-rule'); fill('#rule-name', 'Modal rule draft')
        click('#main-modal > .modal-head .icon-button')
        check(opened(), 'unsaved routing-rule confirmation overlays its editor')
        click('[data-confirm-cancel]'); no_confirmation()
        check(js('return document.querySelector("#rule-name").value') == 'Modal rule draft', 'returning from routing confirmation preserves unfinished input')
        close_draft()
        click('[data-route-tab="dns"]'); click('#dns-add-server'); fill('#resource-tag', 'modal-dns-draft')
        click('#main-modal > .modal-head .icon-button')
        check(opened(), 'unsaved DNS/resource confirmation overlays its editor')
        click('[data-confirm-cancel]'); no_confirmation()
        check(js('return document.querySelector("#resource-tag").value') == 'modal-dns-draft', 'returning from DNS confirmation preserves unfinished input')
        close_draft()
        check(command('routing') == routing, 'discarded routing and DNS drafts do not alter persisted routing')
        click('[data-route-tab="rules"]'); click('#route-profiles'); fill('#route-profile-name', 'Modal temporary route'); click('#route-profile-save')
        wait_for('return document.querySelector("#route-profile-name").value===""')
        created = command('routing')
        added = next(p['id'] for p in created['profiles'] if p['name'] == 'Modal temporary route')
        click(f'[data-route-delete="{added}"]')
        check(opened(), 'routing-profile deletion overlays the profile manager and names its target')
        click('[data-confirm-cancel]'); no_confirmation()
        check(any(p['id'] == added for p in command('routing')['profiles']), 'cancelling nested deletion keeps the routing profile')
        click(f'[data-route-delete="{added}"]'); click('#route-profile-delete-confirm'); no_confirmation()
        check(command('routing') == {**created, 'revision': created['revision'] + 1, 'profiles': [p for p in created['profiles'] if p['id'] != added]}, 'confirmed nested deletion returns to the manager and removes only its target')
        click('#main-modal > .modal-head .icon-button')
        wait_for('return !document.querySelector("dialog")')
    finally:
        js('document.removeEventListener("keydown",window.__modalKeyObserver,true);delete window.__modalKeyObserver;delete window.__modalKeys')
        command('preferences', initial['preferences'])
        request('POST', base + '/window/rect', {'width': 1280, 'height': 860})
        if not js('return !!document.querySelector("dialog")'):
            click('.primary-nav button:first-child')
