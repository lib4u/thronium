"""Selection, atomic move/delete and selected-profile probe entry in the real window."""
import json
import socket


def run(h):
    command, click, fill, select, wait_for, js, check, screenshot = (h[k] for k in ('command', 'click', 'fill', 'select', 'wait_for', 'js', 'check', 'screenshot'))
    initial = command('snapshot')
    source = command('saveGroup', {'name': 'Bulk source', 'subscription': None})['id']
    target = command('saveGroup', {'name': 'Bulk target', 'subscription': None})['id']
    ids = []
    def add(name, group):
        pid = command('saveProfile', {'name': name, 'groupId': group, 'kind': 'sing-box-outbound', 'config': {'type': 'direct'}})['id']
        ids.append(pid)
        return pid
    def close():
        click('.modal-head .icon-button')
        wait_for('return !document.querySelector("dialog")')
    try:
        with socket.socket() as available:
            available.bind(('127.0.0.1', 0)); port = available.getsockname()[1]
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark', 'inboundPort': port})
        a, b, c = [add('Bulk ' + name, source) for name in ('Alpha', 'Beta', 'Gamma')]
        command('favorite', {'id': b}); command('select', {'id': c})
        wait_for('return document.documentElement.lang==="en" && [...document.querySelector(".group-strip select").options].some(o=>o.value===' + json.dumps(source) + ')')
        select('.group-strip select', source)
        wait_for('return document.querySelectorAll(".connection-row").length===3')
        click('#bulk-select-toggle')
        click('.connection-row-button')
        check(command('snapshot')['selected'] == c and js('return document.querySelector("#bulk-count").textContent.includes("1")'), 'clicking a row in selection mode selects it without changing the connection profile')
        click(f'[data-bulk-profile="{b}"]')
        fill('#client-search', 'Gamma')
        wait_for('return document.querySelectorAll(".connection-row").length===1')
        check(js('return document.querySelector("#bulk-count").textContent.includes("2")'), 'bulk selection keeps hidden selected profiles when search changes')
        click('#bulk-select-visible'); fill('#client-search', '')
        wait_for('return document.querySelectorAll(".connection-row").length===3')
        check(js('return document.querySelector("#bulk-select-visible").checked && document.querySelector("#bulk-count").textContent.includes("3")'), 'select-visible adds the filtered results to the existing selection')
        click('#bulk-move'); select('#batch-group', target); click('#batch-confirm')
        wait_for('return !document.querySelector("dialog") && document.querySelector(".group-strip select").value===' + json.dumps(target))
        snap = command('snapshot')
        check(all(p['groupId'] == target for p in snap['profiles'] if p['id'] in ids) and snap['selected'] == c and next(p for p in snap['profiles'] if p['id'] == b)['favorite'], 'bulk move preserves IDs, favorite and selected profile while switching the library to the destination group')
        check(js('return document.querySelector("#bulk-count").textContent.includes("0")'), 'successful bulk move clears the completed selection')
        command('savePingSettings', {'url': f'http://127.0.0.1:{port}/', 'timeoutMs': 100})
        click(f'[data-bulk-profile="{a}"]'); click('#bulk-probe')
        wait_for('return !!document.querySelector("#ping-status")')
        check([e['profileId'] for e in command('snapshot')['urlTests']['entries']] == [a] and not js('return !!document.querySelector("dialog")'), 'selected-profile ping starts immediately for exactly the chosen profiles')
        command('cancelUrlTests'); command('clearUrlTests')
        click(f'[data-bulk-profile="{b}"]'); click('#bulk-delete')
        check(js('return document.querySelectorAll(".batch-profile-list li").length===2'), 'bulk delete displays the complete selection before deletion')
        close()
        check(len([p for p in command('snapshot')['profiles'] if p['id'] in ids]) == 3, 'closing bulk delete leaves every selected profile intact')
        click('#bulk-delete'); click('#batch-confirm')
        wait_for('return !document.querySelector("dialog") && document.querySelectorAll(".connection-row").length===1')
        check([p['id'] for p in command('snapshot')['profiles'] if p['id'] in ids] == [c], 'bulk delete removes exactly the selected profiles in one operation')
        d = add('Bulk Delta', target)
        command('connect', {'id': c}); active = command('snapshot')
        wait_for('return document.querySelectorAll(".connection-row").length===2')
        click('#bulk-select-visible'); click('#bulk-delete'); click('#batch-confirm')
        wait_for('return !!document.querySelector("dialog .desktop-inline-error")')
        check(len([p for p in command('snapshot')['profiles'] if p['id'] in (c, d)]) == 2, 'a connected member blocks the entire bulk delete, including otherwise deletable profiles')
        close(); click('#bulk-move'); select('#batch-group', source); click('#batch-confirm')
        wait_for('return !!document.querySelector("dialog .desktop-inline-error")')
        snap = command('snapshot')
        check(snap['running'] == c and snap['since'] == active['since'] and all(p['groupId'] == target for p in snap['profiles'] if p['id'] in (c, d)), 'failed bulk move preserves every group assignment and the active core')
        command('preferences', {**snap['preferences'], 'language': 'ru', 'theme': 'light'})
        wait_for('return document.documentElement.lang==="ru"')
        h['request']('POST', h['base'] + '/window/rect', {'width': 390, 'height': 844})
        check(js('return document.querySelector("#modal-title").textContent.includes("Перенести") && !document.querySelector("dialog .desktop-inline-error").textContent.includes("Disconnect") && document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth'), 'bulk dialog and existing error are localized and fit a narrow native window')
        screenshot('bulk-move-narrow-ru'); close()
        js('document.querySelector(".library-batch-toolbar").scrollIntoView({block:"center"})')
        check(js('return document.querySelector(".library-batch-toolbar").scrollWidth<=document.querySelector(".library-batch-toolbar").clientWidth'), 'bulk toolbar wraps its actions within a narrow library')
        screenshot('bulk-toolbar-narrow-ru')
        click('#bulk-select-toggle')
        check(js('return !document.querySelector("[data-bulk-profile]")'), 'leaving selection mode restores ordinary server rows')
    finally:
        command('cancelUrlTests'); command('clearUrlTests')
        command('disconnect')
        for group in (source, target): command('deleteGroup', {'id': group, 'deleteProfiles': True})
        command('preferences', initial['preferences'])
        if initial['selected']: command('select', {'id': initial['selected']})
        fill('#client-search', '')
        h['request']('POST', h['base'] + '/window/rect', {'width': 1280, 'height': 860})
