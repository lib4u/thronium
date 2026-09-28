"""Opt-in live subscription check in the native runner's disposable library.

The URL is read from a private file, never embedded in fixtures or reports.
No screenshots or raw provider/configuration/error dumps are produced.
"""
import collections
import http.client
import json
import pathlib
import ssl
import socket
import time


def run(h, source_file):
    command, click, fill, wait_for, js, check = (h[k] for k in ('command', 'click', 'fill', 'wait_for', 'js', 'check'))
    url = pathlib.Path(source_file).read_text().strip()
    report = {'source': 'user-supplied (redacted)', 'warnings': [], 'protocols': {}, 'probes': []}

    def save():
        (h['artifacts'] / 'live-summary.json').write_text(json.dumps(report, ensure_ascii=False, indent=2))

    def failure(stage, code):
        report['failedStage'] = stage
        report['error'] = code
        save()
        raise RuntimeError(f'Live subscription check failed at {stage}; see the redacted summary.')

    try:
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        command('preferences', {**command('snapshot')['preferences'], 'inboundPort': port})
        click('.add-connection'); click('#add-choice-link')
        fill('#import-source', url)
        fill('#import-title', 'Temporary live subscription')
        click('#import-review')
        wait_for('return !document.querySelector("dialog[open]")')
        deadline = time.monotonic() + 150
        while time.monotonic() < deadline:
            snapshot = command('snapshot')
            if snapshot['subscriptionJobs'] and snapshot['subscriptionJobs'][-1]['status'] in ('updated', 'unchanged', 'error', 'needs-review', 'cancelled'):
                break
            time.sleep(.25)
        else:
            failure('automatic import', 'timeout')
        job = snapshot['subscriptionJobs'][-1]
        report['job'] = {key: job[key] for key in ('status', 'checked', 'total', 'error')}
        report['recognized'] = len(snapshot['profiles'])
        if job['status'] != 'updated': failure('automatic import', job['error'] or 'not_applied')
        check(report['recognized'] > 0, 'live subscription pasted into import automatically downloads and saves servers')
        check(job['checked'] == job['total'] == report['recognized'], 'every automatically imported live configuration passes the real core')
        report['protocols'] = dict(collections.Counter(p['protocol'] for p in snapshot['profiles']))
        provider = next((g.get('providerRouting') for g in snapshot['groups'] if g.get('providerRouting')), None)
        report['providerRouting'] = provider
        check(provider is not None and provider['enabled'] and provider['hasDns'] and not provider.get('error'), 'live subscription retains and enables its routing header and DNS metadata')
        runtime = command('connectionConfiguration', {'id': snapshot['profiles'][0]['id'], 'active': False})
        compiled = runtime['parts'][0]['config']
        check(any(s.get('tag') == 'dns-remote' for s in compiled['dns']['servers']) and bool(compiled['route'].get('rule_set')), 'live provider DNS and converted geodata are present in the effective configuration')
        wait_for('return document.querySelectorAll(".connection-row").length===' + str(report['recognized']))
        check(True, 'all live subscription servers are visible in the actual library after import')
        command('select', {'id': snapshot['profiles'][0]['id']})
        wait_for('return /Из подписки|Subscription/.test(document.querySelector(".connection-option .network-mode")?.textContent||"")')
        check(True, 'the connection window identifies the subscription as the routing source')
        # Exercise distinct VLESS transports/security modes, without reporting endpoints or keys.
        candidates = []
        seen = set()
        for p in snapshot['profiles']:
            if 'vless' not in p['protocol'].lower():
                continue
            config = command('profile', {'id': p['id']})['config']
            stream = config.get('streamSettings', {})
            key = (p['kind'], stream.get('network', config.get('transport', {}).get('type', 'tcp')), stream.get('security', 'reality' if config.get('tls', {}).get('reality', {}).get('enabled') else 'tls' if config.get('tls', {}).get('enabled') else 'none'))
            if key not in seen:
                candidates.append({**p, 'testedTransport': key[1], 'testedSecurity': key[2]})
                seen.add(key)
            if len(candidates) == 3:
                break
        report['vlessCandidatesTested'] = len(candidates)
        if not candidates:
            failure('connection', 'no_vless_profiles')
        for index, profile in enumerate(candidates, 1):
            probe = {'entry': index, 'transport': profile['testedTransport'], 'security': profile['testedSecurity'], 'connected': False, 'https': []}
            try:
                command('connect', {'id': profile['id']})
                active = command('snapshot')
                probe['connected'] = active['running'] == profile['id']
                address = active['localProxy']
                host, port = address.rsplit(':', 1)
                for target, path, expected in [('www.gstatic.com', '/generate_204', 204), ('example.com', '/', 200)]:
                    connection = http.client.HTTPSConnection(host.strip('[]'), int(port), timeout=12, context=ssl.create_default_context())
                    started = time.monotonic()
                    try:
                        connection.set_tunnel(target, 443)
                        connection.request('GET', path, headers={'Host': target, 'User-Agent': 'Thronium-connectivity-check'})
                        response = connection.getresponse()
                        response.read(1024)
                        probe['https'].append({'target': target, 'status': response.status, 'expected': expected, 'seconds': round(time.monotonic()-started, 2), 'ok': response.status == expected})
                    except Exception as error:
                        probe['https'].append({'target': target, 'ok': False, 'errorType': type(error).__name__})
                    finally:
                        connection.close()
                traffic = command('snapshot')
                probe['trafficMeasured'] = traffic['trafficUp'] > 0 and traffic['trafficDown'] > 0
                command('startUrlTests', {'ids': [profile['id']], 'url': 'https://www.gstatic.com/generate_204', 'timeoutMs': 6000})
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    state = command('snapshot')
                    entry = state['urlTests']['entries'][0]
                    if entry['status'] not in ('queued', 'testing'):
                        probe['urlTest'] = {key: entry[key] for key in ('status', 'latencyMs', 'error')}
                        probe['urlTest']['activeConnectionPreserved'] = state['running'] == profile['id'] and state['since'] == active['since']
                        break
                    time.sleep(.2)
                else:
                    probe['urlTest'] = {'status': 'runner-timeout'}
                    command('cancelUrlTests')
            except Exception as error:
                probe['errorType'] = type(error).__name__
            finally:
                command('disconnect')
                report['probes'].append(probe)
                save()
        passed = sum(any(r.get('ok') for r in p['https']) for p in report['probes'])
        report['vlessConnectionsPassed'] = passed
        save()
        check(passed > 0, 'live VLESS forwards certificate-verified public HTTPS through the real core')
        url_passed = sum(p.get('urlTest', {}).get('status') == 'ok' for p in report['probes'])
        report['vlessUrlTestsPassed'] = url_passed
        save()
        check(url_passed > 0, 'native URL probes measure real VLESS latency to public HTTPS')
        check(all(p.get('urlTest', {}).get('activeConnectionPreserved') for p in report['probes']), 'live VLESS URL tests preserve the primary connected core')
        check(command('snapshot')['running'] is None, 'live test disconnects the profile after the HTTPS checks')
    finally:
        command('cancelUrlTests')
        command('disconnect')
        save()
