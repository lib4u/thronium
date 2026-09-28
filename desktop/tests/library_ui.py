"""Persistent server ordering and reviewed exact duplicate removal in native UI."""
import json
import time


def run(h):
    command, click, fill, select, wait_for, js, check, screenshot = (h[k] for k in ('command', 'click', 'fill', 'select', 'wait_for', 'js', 'check', 'screenshot'))
    initial = command('snapshot'); initial_appearance = command('settings')['appearance']
    source = command('saveGroup', {'name': 'Library fixtures', 'subscription': None})['id']
    other = command('saveGroup', {'name': 'Separate copies', 'subscription': None})['id']
    def add(name, config, group=source):
        return command('saveProfile', {'name': name, 'groupId': group, 'kind': 'sing-box-outbound', 'config': config})['id']
    def names(): return js('return [...document.querySelectorAll(".row-server-info strong")].map(e=>e.textContent)')
    def close(): click('.modal-head .icon-button'); wait_for('return !document.querySelector("dialog")')
    try:
        command('disconnect')
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark', 'librarySort': 'original', 'librarySortDescending': False})
        ids = [add(name, {'type': 'direct'}) for name in ['Server 10', 'Server 2', 'Server 20', 'Server 1']]
        different = add('Different configuration', {'type': 'direct', 'bind_interface': 'lo'})
        separate = add('Separate group copy', {'type': 'direct'}, other)
        command('select', {'id': ids[0]}); command('favorite', {'id': ids[1]})
        wait_for('return document.documentElement.lang==="en" && [...document.querySelector(".group-strip select").options].some(o=>o.value===' + json.dumps(source) + ')')
        select('.group-strip select', source); fill('#client-search', 'Server')
        wait_for('return document.querySelectorAll(".connection-row").length===4')
        check(names() == ['Server 10', 'Server 2', 'Server 20', 'Server 1'], 'default server view retains the existing library order')
        click('#library-sort'); click('#library-sort-name'); wait_for('return !document.querySelector("#library-sort").disabled && document.querySelector(".row-server-info strong").textContent==="Server 1"')
        check(names() == ['Server 1', 'Server 2', 'Server 10', 'Server 20'], 'name sorting uses numeric order inside server names')
        click('#library-sort'); click('#library-sort-descending'); wait_for('return !document.querySelector("#library-sort").disabled && document.querySelector(".row-server-info strong").textContent==="Server 20"')
        check(names() == ['Server 20', 'Server 10', 'Server 2', 'Server 1'], 'reverse sorting changes the visible order')
        h['request']('POST', h['base'] + '/refresh', {}); wait_for('return document.querySelector("#library-sort")?.title.includes("name")')
        check(command('snapshot')['preferences']['librarySortDescending'] and command('snapshot')['preferences']['librarySort']=='name', 'sort key and direction survive a native reload')
        check([p['id'] for p in command('snapshot')['profiles'] if p['groupId'] == source] == ids + [different], 'view sorting preserves storage order, profile IDs and selected connection')
        select('.group-strip select', source); fill('#client-search', '')
        js('document.querySelector("#library-more").scrollIntoView({block:"center"})'); time.sleep(.15)
        click('#library-more'); click('#library-duplicates'); wait_for('return document.querySelectorAll("[data-duplicate-remove]").length===2')
        check(js('return [...document.querySelectorAll("[data-duplicate-keep]")].map(e=>e.dataset.duplicateKeep)') == ids[:2], 'duplicate preview keeps both selected and favorite copies')
        check(js('return [...document.querySelectorAll("[data-duplicate-remove]")].map(e=>e.dataset.duplicateRemove)') == ids[2:], 'preview lists only exact removable copies from the current filtered group')
        close(); check(len(command('snapshot')['profiles']) == len(initial['profiles']) + 6, 'closing duplicate preview leaves all profiles intact')
        js('document.querySelector("#library-more").scrollIntoView({block:"center"})'); time.sleep(.15)
        click('#library-more'); click('#library-duplicates'); wait_for('return !document.querySelector("#duplicates-confirm").disabled')
        command('favorite', {'id': different}); click('#duplicates-confirm')
        wait_for('return document.querySelector(".desktop-inline-error")?.textContent.includes("changed")')
        check(len(command('snapshot')['profiles']) == len(initial['profiles']) + 6, 'a stale duplicate preview cannot delete profiles after a library change')
        click('#duplicates-reload'); wait_for('return !document.querySelector("#duplicates-confirm").disabled')
        command('preferences', {**command('snapshot')['preferences'], 'language': 'ru', 'theme': 'light'})
        wait_for('return document.documentElement.lang==="ru"'); click('#duplicates-reload'); wait_for('return !document.querySelector("#duplicates-confirm").disabled')
        h['request']('POST', h['base'] + '/window/rect', {'width': 390, 'height': 844})
        check(js('return document.querySelector("#modal-title").textContent.includes("дубликатов") && document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth && document.querySelector(".modal-footer").getBoundingClientRect().bottom<=innerHeight'), 'duplicate review and confirmation fit the narrow Russian native window')
        screenshot('duplicates-narrow-ru'); click('#duplicates-confirm'); wait_for('return !document.querySelector("dialog")')
        remaining = {p['id'] for p in command('snapshot')['profiles']}
        check(set(ids[:2] + [different, separate]) <= remaining and not set(ids[2:]) & remaining, 'confirmed removal retains selected, favorite, different and other-group profiles')
        check(command('snapshot')['selected'] == ids[0], 'duplicate removal preserves the selected connection')
        js('document.querySelector("#library-more").scrollIntoView({block:"center"})'); time.sleep(.15)
        click('#library-more'); click('#library-duplicates'); wait_for('return !!document.querySelector("#duplicates-empty")')
        check(js('return document.querySelector("#duplicates-confirm").disabled'), 'protected remaining copies produce a clear empty result'); close()
        click('#library-sort'); click('#library-sort-original'); wait_for('return !document.querySelector("#library-sort").disabled')
        click('#library-sort')
        check(js('return document.querySelector(".library-toolbar-tools").scrollWidth<=document.querySelector(".library-toolbar-tools").clientWidth&&document.querySelector("#library-sort-descending").disabled'), 'sort controls fit a narrow window and original order disables reversal')
        js('document.querySelector("[role=menu]").dispatchEvent(new KeyboardEvent("keydown",{key:"Escape",bubbles:true}))')
        # Displayed data: global switches of the Interface → Server list group feed one row component.
        appearance = command('settings')['appearance']
        insecure = add('Insecure trojan', {'type': 'trojan', 'server': 'weak.example', 'server_port': 8443, 'password': 'fixture', 'tls': {'enabled': True, 'insecure': True}})
        def row(pid): return '[data-order-profile=' + json.dumps(pid) + ']'
        def subtitle(pid): return js('return document.querySelector(arguments[0]+" .row-server-info > small")?.textContent', row(pid))
        def stats(pid): return js('return document.querySelector(arguments[0]+" .row-stats")?.textContent ?? null', row(pid))
        command('saveSettings', {'section': 'appearance', 'previous': appearance, 'values': {**appearance, 'list_show_port': True, 'list_show_ip': True, 'list_show_traffic': True, 'show_config_security': True}})
        wait_for('return document.querySelector(' + json.dumps(row(insecure) + ' .row-server-info > small') + ')?.textContent==="weak.example:8443 · trojan · TLS"')
        check(subtitle(ids[0]) == 'direct' and js('return !!document.querySelector(arguments[0]+" .row-security-warn") && !document.querySelector(arguments[1]+" .row-security-warn")', row(insecure), row(ids[0])), 'port and security details appear in every row while the warning glyph marks only the row without certificate verification')
        check(stats(insecure) is None and stats(ids[0]) is None, 'the stats line is absent until an IP, speed or traffic value exists')
        command('startIpTests', {'ids': [ids[0]]})
        for _ in range(120):
            batch = command('snapshot')['urlTests']
            if batch and all(e['status'] not in ('queued', 'testing') for e in batch['entries']): break
            time.sleep(.5)
        measured = next(p for p in command('snapshot')['profiles'] if p['id'] == ids[0])['ipMeasurement']
        wait_for('return document.querySelector(' + json.dumps(row(ids[0]) + ' .row-stats') + ')!==null')
        check(measured is not None and (measured['status'] != 'ok' or measured['ip'] in stats(ids[0])), 'the finished IP check is published in the snapshot and shown in the stats line of its row only')
        check(stats(insecure) is None, 'rows without a result keep no stats line')
        command('clearUrlTests')
        command('saveSettings', {'section': 'appearance', 'previous': command('settings')['appearance'], 'values': {**command('settings')['appearance'], 'list_show_latency': False}})
        wait_for('return !document.querySelector(' + json.dumps(row(insecure) + ' .row-ping') + ') && !!document.querySelector(' + json.dumps(row(insecure) + ' .row-server-info') + ')')
        click('#library-sort'); wait_for('return !!document.querySelector("#library-sort-traffic")')
        check(js('return !!document.querySelector("#library-sort-security") && !!document.querySelector("#library-sort-traffic")'), 'security and traffic sort keys are offered while their data is displayed')
        js('document.querySelector("[role=menu]").dispatchEvent(new KeyboardEvent("keydown",{key:"Escape",bubbles:true}))')
        wait_for('return innerWidth===390 && document.documentElement.lang==="ru"')
        check(js('return document.documentElement.scrollWidth<=innerWidth && [...document.querySelectorAll(".connection-row")].every(e=>e.scrollWidth<=e.clientWidth)'), 'rows with port, security and stats fit the narrow Russian window without horizontal scrolling')
        screenshot('library-data-narrow-ru')
        command('preferences', {**command('snapshot')['preferences'], 'language': 'en', 'theme': 'dark'})
        h['request']('POST', h['base'] + '/window/rect', {'width': 1280, 'height': 860})
        wait_for('return document.documentElement.lang==="en" && innerWidth>=1200')
        screenshot('library-data-en')
        js('document.querySelector("#library-more").scrollIntoView({block:"center"})'); time.sleep(.15)
        click('#library-more'); click('#library-displayed-data')
        wait_for('return document.querySelector("[data-settings-section=appearance]")?.getAttribute("aria-current")==="page" && document.activeElement.id==="setting-list_show_traffic"')
        check(js('return document.querySelector("#setting-list_show_traffic").closest("details").open'), 'the library menu opens the server list settings group with the displayed-data switches expanded and focused')
        click('.primary-nav button:first-child'); wait_for('return !!document.querySelector(".add-connection")')
        command('saveSettings', {'section': 'appearance', 'previous': command('settings')['appearance'], 'values': appearance})
        wait_for('return document.querySelector(' + json.dumps(row(insecure) + ' .row-server-info > small') + ')?.textContent==="weak.example · trojan" && !!document.querySelector(' + json.dumps(row(insecure) + ' .row-ping') + ')')
        click('#library-sort'); wait_for('return !!document.querySelector("#library-sort-name")')
        check(js('return !document.querySelector("#library-sort-security") && !document.querySelector("#library-sort-traffic")'), 'hidden data removes its sort keys from the menu')
        js('document.querySelector("[role=menu]").dispatchEvent(new KeyboardEvent("keydown",{key:"Escape",bubbles:true}))')
    finally:
        command('disconnect'); command('cancelUrlTests'); command('clearUrlTests')
        command('deleteGroup', {'id': source, 'deleteProfiles': True}); command('deleteGroup', {'id': other, 'deleteProfiles': True})
        command('preferences', initial['preferences'])
        command('saveSettings', {'section': 'appearance', 'previous': command('settings')['appearance'], 'values': initial_appearance})
        if initial['selected']: command('select', {'id': initial['selected']})
        fill('#client-search', '')
        h['request']('POST', h['base'] + '/window/rect', {'width': 1280, 'height': 860})
