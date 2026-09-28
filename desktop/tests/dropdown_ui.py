"""Anchored library actions, real keyboard navigation and existing workflows."""
import http.server
import json
from pathlib import Path
import threading
import time


def run(h):
    command, click, fill, select, wait_for, js, check, screenshot = (h[k] for k in ('command', 'click', 'fill', 'select', 'wait_for', 'js', 'check', 'screenshot'))
    request, base = h['request'], h['base']
    initial = command('snapshot'); geometry = request('GET', base + '/window/rect')
    groups = []; profiles = []; calls = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_GET(self):
            calls.append(self.path)
            body = b'ok' if self.path == '/ping' else b'[{"type":"direct","tag":"Downloaded fixture"}]'
            self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = f'http://127.0.0.1:{server.server_port}'

    def key(value):
        from Xlib import X, XK, protocol
        from window_ui import primary
        count = js('return window.__dropdownKeys.length')
        connection, window, _pid = primary()
        try:
            for event in (protocol.event.KeyPress, protocol.event.KeyRelease):
                window.send_event(event(time=X.CurrentTime, root=connection.screen().root, window=window, child=X.NONE,
                    root_x=0, root_y=0, event_x=0, event_y=0, state=0,
                    detail=connection.keysym_to_keycode(XK.string_to_keysym(value)), same_screen=1), propagate=True)
            connection.sync()
        finally: connection.close()
        wait_for('return window.__dropdownKeys.length>' + str(count))

    def open_menu(selector):
        js('document.querySelector(arguments[0]).scrollIntoView({block:"nearest"})', selector)
        # Finish the scroll event before opening the anchored menu.
        time.sleep(.08)
        click(selector); wait_for('return !!document.querySelector("[role=menu]")')

    def fits():
        return js('const m=document.querySelector("[role=menu]"),r=m.getBoundingClientRect();return r.x>=0&&r.y>=0&&r.right<=innerWidth&&r.bottom<=innerHeight&&m.scrollWidth<=m.clientWidth')

    def labels_fit():
        return js('return [...document.querySelectorAll("[role=menu] button")].every(b=>{const i=b.querySelector(".icon-host").getBoundingClientRect(),l=b.querySelector(".dropdown-label").getBoundingClientRect(),s=getComputedStyle(b);return Math.abs(i.width-15)<1&&Math.abs(l.left-i.right-parseFloat(s.columnGap))<1&&l.height<=parseFloat(s.lineHeight)+1})')

    def close_dialog():
        click('#main-modal > .modal-head .icon-button'); wait_for('return !document.querySelector("dialog")')

    try:
        js('window.__dropdownKeys=[];window.__dropdownKeyObserver=e=>window.__dropdownKeys.push({key:e.key,trusted:e.isTrusted});document.addEventListener("keydown",window.__dropdownKeyObserver,true)')
        command('preferences', {**initial['preferences'], 'language': 'ru', 'theme': 'light'})
        command('savePingSettings', {'url': origin + '/ping', 'timeoutMs': 2000})
        request('POST', base + '/window/rect', {'width': 1280, 'height': 860})
        select('.group-strip select', 'personal')
        wait_for('return document.querySelector("[data-group-probe=personal]")?.disabled && document.querySelectorAll("[data-library-group]").length===1')
        open_menu('[data-group-menu="personal"]')
        check(js('return document.activeElement.matches("[role=menu]")&&[...document.querySelectorAll("[role=menuitem]")].every(e=>e.disabled)'), 'an empty protected group keeps keyboard focus even when every action is disabled')
        key('Escape'); wait_for('return !document.querySelector("[role=menu]")'); select('.group-strip select', 'all')
        local = command('saveGroup', {'name': 'Локальная группа', 'subscription': None})['id']; groups.append(local)
        remote = command('saveGroup', {'name': 'Подписка для меню', 'subscription': {'url': origin + '/private-fixture', 'headers': {}, 'viaProxy': False, 'intervalMinutes': 0}})['id']; groups.append(remote)
        for name, group in [('Сервер A', local), ('Сервер B', local), ('Личный сервер', 'personal')]:
            profiles.append(command('saveProfile', {'name': name, 'groupId': group, 'kind': 'sing-box-outbound', 'config': {'type': 'direct'}})['id'])
        wait_for('return document.querySelectorAll("[data-profile-menu]").length===3')
        first = f'[data-profile-menu="{profiles[0]}"]'; second = f'[data-profile-menu="{profiles[1]}"]'; remote_button = f'[data-group-menu="{remote}"]'
        selected = command('snapshot')['selected']
        open_menu(first)
        check(js('return document.querySelectorAll("[role=menu]").length===1&&!document.querySelector("dialog")&&document.querySelector("[role=menu]").parentElement===document.body'), 'server actions open a non-modal dropdown outside the scrolling list')
        check(fits() and js('const a=document.querySelector("[aria-expanded=true][data-profile-menu]").getBoundingClientRect(),m=document.querySelector("[role=menu]").getBoundingClientRect();return m.width<300&&Math.abs(a.right-m.right)<2&&(Math.abs(m.top-a.bottom-5)<2||Math.abs(a.top-m.bottom-5)<2)'), 'server dropdown is compact and anchored to the clicked ellipsis')
        check(command('snapshot')['selected'] == selected and not calls, 'opening actions neither selects a server nor downloads a subscription')
        check(js('return document.activeElement.id==="diagnostics-one"&&JSON.stringify(Array.from(document.querySelectorAll("[role=menuitem]"),n=>n.id))===JSON.stringify(["diagnostics-one","probe-one","menu-edit-profile","menu-clone-profile","profile-move-up","profile-move-down","export-one","menu-delete-profile"])'), 'all six existing server actions plus the two order actions remain in exact order and the first receives focus')
        check(js('return document.querySelector(arguments[0]).getAttribute("aria-controls") === document.querySelector("[role=menu]").id', first), 'the trigger references this menu instance through a unique ID')
        screenshot('dropdown-server-light-ru')
        check(labels_fit(), 'server menu keeps fixed-width icons and single-line labels aligned beside them')
        key('Down'); check(js('return document.activeElement.id==="probe-one"'), 'native ArrowDown moves from diagnostics to the next latency action')
        key('End'); key('Down'); check(js('return document.activeElement.id==="diagnostics-one"'), 'End and ArrowDown wrap through all available actions')
        key('Escape'); wait_for('return !document.querySelector("[role=menu]")')
        check(js('return document.activeElement.matches(arguments[0])', first), 'Escape closes the menu and returns focus to its trigger')
        open_menu('#library-sort')
        check(labels_fit() and fits(), 'sort menu aligns labels with fixed icons and checkmarks without wrapping')
        screenshot('dropdown-sort-light-ru');key('Escape');js('document.querySelector(arguments[0]).focus()',first)
        key('Up'); wait_for('return !!document.querySelector("[role=menu]")')
        check(js('return document.activeElement.id==="menu-delete-profile"'), 'ArrowUp on the trigger opens with the last action focused')
        key('Tab'); wait_for('return !document.querySelector("[role=menu]")')
        check(js('return !document.activeElement.closest("[role=menu]")'), 'Tab dismisses the menu and resumes page navigation')
        open_menu(first); click(first); wait_for('return !document.querySelector("[role=menu]")')
        check(js('return document.querySelector(arguments[0]).getAttribute("aria-expanded")==="false"', first), 'clicking the same ellipsis toggles the menu closed')
        open_menu(first); click(second)
        check(js('return document.querySelectorAll("[role=menu]").length===1&&document.querySelector("[role=menu]").getAttribute("aria-label").includes("Сервер B")'), 'opening another ellipsis replaces the existing menu')
        js('document.querySelector("#client-search").dispatchEvent(new PointerEvent("pointerdown",{bubbles:true}));document.querySelector("#client-search").focus()')
        check(js('return !document.querySelector("[role=menu]")&&document.activeElement.id==="client-search"'), 'outside pointer closes without stealing focus from the clicked input')
        open_menu(first); click('#menu-edit-profile')
        wait_for('return !!document.querySelector("#profile-name")')
        check(js('return !document.querySelector("[role=menu]")&&document.querySelectorAll("dialog:modal").length===1&&document.querySelector("#profile-name").value==="Сервер A"'), 'Edit dismisses the dropdown and opens the intended profile editor')
        close_dialog(); open_menu(first); click('#menu-clone-profile')
        wait_for('return document.querySelectorAll("[data-profile-menu]").length===4')
        check(len(command('snapshot')['profiles']) == len(initial['profiles']) + 4 and not js('return !!document.querySelector("dialog")'), 'Clone runs immediately and adds one profile without an action dialog')
        open_menu(first); click('#export-one'); wait_for('return !!document.querySelector("#configuration-json")')
        check(js('return !document.querySelector("[role=menu]")&&document.querySelectorAll("dialog:modal").length===1'), 'Export opens its existing dialog after closing the dropdown')
        close_dialog(); open_menu(first); click('#menu-delete-profile')
        check(js('return !document.querySelector("[role=menu]")&&!!document.querySelector("dialog:modal")') and any(p['id'] == profiles[0] for p in command('snapshot')['profiles']), 'Delete still requires confirmation before changing the library')
        close_dialog(); open_menu(first); click('#probe-one')
        wait_for('return document.querySelector(arguments[0])?.dataset.probeStatus==="ok"'.replace('arguments[0]', json.dumps(f'[data-profile-latency="{profiles[0]}"]')))
        check(not js('return !!document.querySelector("dialog,[role=menu]")') and '/ping' in calls, 'server ping starts the real HTTP test immediately with saved settings')
        command('clearUrlTests')
        open_menu(remote_button)
        check(fits() and js('return !!document.querySelector("#menu-update-group")&&!!document.querySelector("#update-subscription")&&document.querySelector("#menu-probe-group").disabled&&document.querySelector("#menu-group-down").disabled&&!document.querySelector("dialog")'), 'subscription menu preserves review and ordering, with unavailable actions disabled')
        screenshot('dropdown-group-light-ru')
        key('End'); key('Up')
        check(js('return document.activeElement.id==="menu-group-up"'), 'keyboard navigation skips disabled actions in a group menu')
        key('Escape'); open_menu(remote_button); click('#update-subscription')
        wait_for('return !!document.querySelector("#subscription-load")')
        check(not js('return !!document.querySelector("[role=menu]")'), 'manual subscription review remains available from the dropdown')
        close_dialog(); open_menu(remote_button); click('#menu-update-group')
        wait_for('return !!document.querySelector("[data-group-refresh]")&&!document.querySelector("[data-group-refresh]").disabled')
        deadline=time.monotonic()+20
        while not any(p['groupId'] == remote for p in command('snapshot')['profiles']) and time.monotonic()<deadline: time.sleep(.1)
        update_snapshot=command('snapshot')
        if update_snapshot.get('subscriptionNotifications'):
            wait_for('return !!document.querySelector("#subscription-clear-jobs")')
        update_audit={'remoteGroup':remote,'profileGroups':[p['groupId'] for p in update_snapshot['profiles']],'jobs':update_snapshot['subscriptionJobs'],'httpPaths':calls[:],'dialogs':js('return Array.from(document.querySelectorAll("dialog"),d=>({title:d.querySelector(".modal-title,h1,h2")?.textContent,ids:Array.from(d.querySelectorAll("[id]"),e=>e.id)}))')}
        (Path(h['args'].artifacts)/'dropdown-update-audit.json').write_text(json.dumps(update_audit,ensure_ascii=False,indent=2)+'\n')
        imported=[p for p in update_snapshot['profiles'] if p['groupId']==remote]
        jobs=[j for j in update_snapshot['subscriptionJobs'] if j['groupId']==remote]
        expected_notice=js('return !document.querySelector("[role=menu]")&&(!document.querySelector("dialog")||(document.querySelectorAll("dialog").length===1&&!!document.querySelector("dialog #subscription-clear-jobs")))')
        check(len(imported)==1 and '/private-fixture' in calls and len(jobs)==1 and jobs[0]['status']=='updated' and jobs[0]['counts']['added']==1 and expected_notice, 'Update imports only the chosen subscription and preserves the configured completion notification')
        if js('return !!document.querySelector("dialog #subscription-clear-jobs")'):close_dialog()
        open_menu(remote_button); click('#menu-probe-group')
        deadline=time.monotonic()+20
        while time.monotonic()<deadline:
            snap=command('snapshot'); entries=(snap.get('urlTests') or {}).get('entries', [])
            if entries and all(e['status'] not in ('queued','testing') for e in entries): break
            time.sleep(.1)
        check(len(entries)==1 and entries[0]['status']=='ok' and next(p for p in snap['profiles'] if p['id']==entries[0]['profileId'])['groupId']==remote, 'group menu ping tests only profiles belonging to that group')
        command('clearUrlTests'); command('clearSubscriptionJobs')
        open_menu(remote_button); click('#menu-edit-group'); wait_for('return !!document.querySelector("#group-name")')
        check(js('return document.querySelector("#group-name").value==="Подписка для меню"&&!document.querySelector("[role=menu]")'), 'group Edit opens the intended group form')
        close_dialog(); open_menu(remote_button); click('#menu-delete-group')
        wait_for('return !!document.querySelector("#group-delete-confirm")')
        check(js('return !!document.querySelector("#group-delete-confirm")&&!document.querySelector("[role=menu]")') and any(g['id']==remote for g in command('snapshot')['groups']), 'group Delete preserves its confirmation and existing profiles')
        close_dialog(); open_menu(remote_button); click('#menu-group-up')
        wait_for('return !document.querySelector("[role=menu]")')
        check([g['id'] for g in command('snapshot')['groups']].index(remote)<[g['id'] for g in command('snapshot')['groups']].index(local), 'Move up reorders the intended group without a modal')
        open_menu('[data-group-menu="personal"]')
        check(js('return !document.querySelector("#menu-delete-group")&&!document.querySelector("#menu-edit-group")&&document.querySelector("#menu-group-up").disabled'), 'Personal retains protected actions and first-position ordering rules')
        key('Escape')
        command('preferences', {**command('snapshot')['preferences'], 'theme': 'dark', 'language': 'en'})
        wait_for('return document.documentElement.lang==="en"')
        open_menu(first); screenshot('dropdown-server-dark-en')
        check(js('return document.querySelector("#menu-edit-profile").textContent.trim()==="Edit"') and fits(), 'dropdown uses English labels and dark theme')
        key('Escape'); select('.group-strip select', local)
        # Add enough real rows to exercise the clipped scrolling list.
        for n in range(10): command('saveProfile', {'name': f'Overflow {n}', 'groupId': local, 'kind': 'sing-box-outbound', 'config': {'type': 'direct'}})
        wait_for('return document.querySelectorAll("[data-profile-menu]").length===13')
        for width,height in ((768,600),(390,600)):
            request('POST',base+'/window/rect',{'width':width,'height':height})
            last='[data-library-group] .connection-row:last-child .row-more'
            open_menu(last)
            check(fits() and js('return document.querySelector("[role=menu]").dataset.placement==="top"'), f'dropdown flips above the last visible row and fits at {width}x{height}')
            screenshot(f'dropdown-narrow-{width}')
            # The rows may fit the window; a scroll of their container is what closes the menu either way.
            js('const row=document.querySelector("[data-library-group] .connection-row:last-child .row-more");let e=row.parentElement;while(e&&e!==document.body&&e.scrollHeight<=e.clientHeight)e=e.parentElement;const target=e&&e!==document.body?e:row.closest(".library-pane");if(target.scrollHeight>target.clientHeight)target.scrollTop+=target.scrollTop>0?-25:25;target.dispatchEvent(new Event("scroll"))')
            wait_for('return !document.querySelector("[role=menu]")')
        check(True, 'scrolling the library dismisses the dropdown instead of leaving a detached menu')
        check(js('return window.__dropdownKeys.length>0&&window.__dropdownKeys.every(e=>e.trusted)'), 'dropdown keyboard checks use native events in the isolated application')
    finally:
        js('document.removeEventListener("keydown",window.__dropdownKeyObserver,true);delete window.__dropdownKeys;delete window.__dropdownKeyObserver')
        if js('return !!document.querySelector("[role=menu]")'): js('document.querySelector("#client-search").focus()')
        if js('return !!document.querySelector("dialog")'): close_dialog()
        for gid in groups: command('deleteGroup', {'id': gid, 'deleteProfiles': True})
        for pid in profiles:
            if any(p['id']==pid for p in command('snapshot')['profiles']): command('delete', {'id': pid})
        command('clearUrlTests'); command('clearSubscriptionJobs'); command('preferences',initial['preferences'])
        if initial['selected']: command('select',{'id':initial['selected']})
        select('.group-strip select','all'); request('POST',base+'/window/rect',geometry)
        server.shutdown();server.server_close()
