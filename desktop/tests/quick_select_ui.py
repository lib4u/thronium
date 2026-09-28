"""Quick reconnect memory exercised through the real host and owned proxies."""
import json


def reconnect_checks(h, fixture, peers, bad, group):
    command, click, fill, select, wait_for, js, check, screenshot = (
        h[k] for k in ('command', 'click', 'fill', 'select', 'wait_for', 'js', 'check', 'screenshot'))

    def selected():
        pool = next(p for p in command('getAutoSelectors') if p['tag'] == 'proxy')
        return next(m['profileId'] for m in pool['members'] if m['tag'] == pool['selected'])

    def batch():
        return command('snapshot')['urlTests']

    def mode(index, value):
        peer = fixture.peers[index]
        with peer.lock:
            peer.state['downloadMode'] = value

    remembered = selected()
    command('disconnect')
    command('connect', {'id': 'auto-select'})
    value = batch()
    check(value['source'] == 'auto-select' and len(value['entries']) == 1
          and value['entries'][0]['profileId'] == remembered and value['entries'][0]['status'] == 'ok',
          'reconnect inside TTL measures only the remembered server through its actual proxy')
    wait_for('return !!document.querySelector(".session-auto-host strong")')
    screenshot('auto-select-reused')

    # Changing the snapshot every second must not continually restart the poll.
    alternate = next(pid for pid in peers if peers[pid] != peers[remembered])
    command('autoSelectorAction', {'tag': 'proxy', 'action': 'select',
                                 'member': 'thronium-selector-proxy-' + alternate})
    alternate_name = command('profile', {'id': alternate})['name']
    wait_for('return document.querySelector(".session-auto-host strong")?.textContent===' + json.dumps(alternate_name), 12)
    check(selected() == alternate, 'the session host follows a Core selection while snapshots keep arriving')
    command('disconnect')
    mode(peers[alternate], 'http-error')
    try:
        command('connect', {'id': 'auto-select'})
        value = batch()
        check(len(value['entries']) == len(peers) + 1
              and any(e['status'] == 'ok' and peers.get(e['profileId']) != peers[alternate] for e in value['entries'])
              and value['entries'][0]['profileId'] in peers | {bad: -1},
              'a failed remembered server triggers the full bounded sweep and finds a reachable replacement')
        journal = command('getMeasurementJournal')['entries']
        check(any(e['source'] == 'auto-select' and e['profileId'] == alternate and e['status'] == 'error' for e in journal),
              'the failed recheck is recorded as auto-select, independently of manual ping results')
    finally:
        mode(peers[alternate], 'ok')

    # Settings are scoped and guarded, and an active pool shows deferred changes.
    before = command('snapshot')['preferences']['autoSelect']['config']
    updated = {**before, 'reuse_ttl': '0s'}
    command('saveAutoSelectSettings', {'previous': before, 'config': updated})
    wait_for('return !!document.querySelector("#auto-select-reconnect-notice")')
    check(command('snapshot')['running'] == 'auto-select', 'saving settings preserves the active connection and marks reconnect pending')
    rejected = False
    try:
        command('saveAutoSelectSettings', {'previous': before, 'config': before})
    except RuntimeError as error:
        rejected = 'settings_changed' in str(error)
    check(rejected, 'a stale configurator cannot overwrite newer auto-select settings')
    command('disconnect')
    command('connect', {'id': 'auto-select'})
    check(len(batch()['entries']) == len(peers) + 1, 'TTL zero disables reuse and measures every member again')
    wait_for('return !document.querySelector("#auto-select-reconnect-notice")')

    # Every server down: preserve the existing Core instead of starting an empty pool.
    prior = command('connectionConfiguration', {'id': 'auto-select', 'active': True})
    for index in range(2):
        mode(index, 'http-error')
    try:
        failed = False
        try:
            command('connect', {'id': 'auto-select'})
        except RuntimeError as error:
            failed = 'auto_select_no_reachable' in str(error)
        check(failed and command('snapshot')['running'] == 'auto-select'
              and command('connectionConfiguration', {'id': 'auto-select', 'active': True}) == prior,
              'a full failed sweep reports no reachable servers and leaves the previous connection request intact')
    finally:
        for index in range(2):
            mode(index, 'ok')
    command('disconnect')

    # Actual form validation plus a scoped save while an unrelated preference changes.
    click('#auto-select-configure')
    wait_for('return !!document.querySelector("#auto-select-reuse_ttl")')
    click('#auto-select-advanced > summary')
    fill('#auto-select-timeout', 'invalid5s')
    click('#auto-select-save')
    wait_for('return !!document.querySelector("#auto-select-config-error")')
    check(command('snapshot')['preferences']['autoSelect']['config']['timeout'] == before['timeout'],
          'invalid durations are rejected before preferences are stored')
    fill('#auto-select-timeout', before['timeout'])
    select('#auto-select-reuse_ttl', '30m')
    prefs = command('snapshot')['preferences']
    command('preferences', {**prefs, 'librarySortDescending': not prefs['librarySortDescending']})
    click('#auto-select-save')
    wait_for('return !document.querySelector("#auto-select-save")')
    current = command('snapshot')['preferences']
    check(current['librarySortDescending'] != prefs['librarySortDescending'] and current['autoSelect']['config']['reuse_ttl'] == '30m',
          'saving TTL keeps an unrelated preference changed while the configurator was open')
    command('preferences', {**current, 'librarySortDescending': prefs['librarySortDescending']})

    direct = command('saveProfile', {'groupId': group, 'name': 'Explicit Direct', 'kind': 'sing-box-outbound',
                                     'config': {'type': 'direct'}})['id']
    try:
        command('connect', {'id': 'auto-select'})
        check(direct not in {e['profileId'] for e in batch()['entries']},
              'an explicitly saved Direct profile is never a quick-pool candidate')
    finally:
        command('disconnect')
        command('delete', {'id': direct})

    from warp_select_ui import run as warp_checks
    warp_checks(h)
