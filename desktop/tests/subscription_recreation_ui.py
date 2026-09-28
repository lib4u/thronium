"""Recreation through the shared settings form and native subscription preview."""
import json


def run(h, gid, update, members, close):
    command, click, select, wait_for, js, check, screenshot = (h[k] for k in ('command', 'click', 'select', 'wait_for', 'js', 'check', 'screenshot'))
    original = command('settings')['subscriptions']
    before = members(gid)
    remote = set(command('group', {'id': gid})['subscription']['managedIds'])
    manual = [p['id'] for p in before if p['id'] not in remote]
    try:
        click('.primary-nav button:last-child')
        wait_for('return !!document.querySelector("#settings-search")')
        click('[data-settings-section="subscriptions"]')
        wait_for('return !!document.querySelector("#setting-sub_update_mode")')
        check(js('return document.querySelector("#setting-sub_update_mode").value') == 'reconcile', 'existing libraries default to reconciliation')
        select('#setting-sub_update_mode', 'recreate')
        check(js('return document.querySelector("#setting-sub_clear").disabled'), 'recreation disables only the inapplicable stale-row toggle')
        click('#settings-save')
        wait_for('return document.querySelector("#settings-save").disabled && !document.querySelector(".desktop-inline-error")')
        check(command('settings')['subscriptions']['sub_update_mode'] == 'recreate', 'shared settings form persists explicit recreation mode')
        screenshot('subscription-recreation-settings-en')
        click('.primary-nav button:first-child')
        wait_for('return !!document.querySelector(".group-strip select")')
        select('.group-strip select', gid)
        update()
        check(js('return document.querySelectorAll("[data-subscription-action=added]").length') == len(remote), 'recreation previews fresh records even for unchanged content')
        check(js('return document.querySelectorAll("[data-subscription-action=removed]").length') == len(remote), 'recreation previews removal of all eligible remote records')
        check(members(gid) == before, 'recreation preview leaves saved profiles intact')
        screenshot('subscription-recreation-preview-en')
        click('#subscription-apply')
        wait_for('return !document.querySelector("dialog[open]")')
        after = members(gid)
        check(not remote.intersection(p['id'] for p in after), 'native apply replaces remote IDs atomically')
        check(all(any(p['id'] == id for p in after) for id in manual), 'native recreation preserves manually created group profiles')
        settings = command('settings')['subscriptions']
        command('saveSettings', {'section': 'subscriptions', 'previous': settings, 'values': original})
        update()
        check(js('return document.querySelectorAll("[data-subscription-action=unchanged]").length') == len(remote), 'returning to reconciliation retains the new IDs')
        close()
    finally:
        settings = command('settings')['subscriptions']
        if settings != original:
            command('saveSettings', {'section': 'subscriptions', 'previous': settings, 'values': original})
