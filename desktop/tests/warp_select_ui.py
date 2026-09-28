"""Settings WARP wraps the quick pool without losing its server identity."""
import json
import socket


def run(h):
    command, wait_for, check, screenshot = (h[k] for k in ('command', 'wait_for', 'check', 'screenshot'))
    original = command('settings')['intercept']
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.bind(('127.0.0.1', 0))
        settings = {**original, 'enable_warp': True, 'warp_ep': f'127.0.0.1:{peer.getsockname()[1]}',
                    'warp_private_key': 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=',
                    'warp_public_key': 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=',
                    'warp_ifc_addrs': ['10.77.0.2/32']}
        try:
            command('saveSettings', {'section': 'intercept', 'previous': original, 'values': settings})
            command('connect', {'id': 'auto-select'})
            wait_for('return !!document.querySelector(".session-auto-host strong")')
            pool = next(p for p in command('getAutoSelectors') if p['profileId'] == 'auto-select')
            check(pool['tag'] == 'settings-warp-base' and all(m['profileId'] for m in pool['members']),
                  'settings WARP preserves the quick pool and member library IDs in real IPC')
            wait_for('return !document.querySelector(".selector-panel")?.textContent.includes("settings-warp-base") && !document.querySelector(".selector-panel")?.textContent.includes("thronium-selector-")')
            screenshot('auto-select-warp-current-server')
            check(True, 'WARP-wrapped quick selection displays server names instead of internal tags')
            member = next(m for m in pool['members'] if m['state'] in ('ok', 'degraded'))
            command('autoSelectorAction', {'tag': pool['tag'], 'action': 'select', 'member': member['tag']})
            wait_for('return [...document.querySelectorAll(".session-auto-host strong")].some(e=>e.textContent===' + json.dumps(member['name']) + ')')
            pool = next(p for p in command('getAutoSelectors') if p['profileId'] == 'auto-select')
            selected_tag = pool['selectedUdp'] or pool['selected']
            remembered = next(m['profileId'] for m in pool['members'] if m['tag'] == selected_tag)
            command('disconnect')
            command('connect', {'id': 'auto-select'})
            entries = command('snapshot')['urlTests']['entries']
            check(len(entries) == 1 and entries[0]['profileId'] == remembered and entries[0]['status'] == 'ok',
                  'reconnecting a WARP-wrapped pool rechecks only its remembered carrier within TTL')
            current = command('settings')['intercept']
            command('saveSettings', {'section': 'intercept', 'previous': current, 'values': original})
            wait_for('return !!document.querySelector("#auto-select-reconnect-notice") && !!document.querySelector(".session-auto-host strong")')
            pool = next(p for p in command('getAutoSelectors') if p['profileId'] == 'auto-select')
            check(pool['tag'] == 'settings-warp-base' and pool['needsReconnect'],
                  'disabling WARP for the next connection keeps the current server identity and shows reconnect pending')
        finally:
            command('disconnect')
            current = command('settings')['intercept']
            if current != original:
                command('saveSettings', {'section': 'intercept', 'previous': current, 'values': original})
