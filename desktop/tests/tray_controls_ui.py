"""Native AdBlock/WARP actions: local SRS enforcement, rollback and a local WG peer."""
import contextlib
import copy
import hashlib
import http.client
import http.server
import json
from pathlib import Path
import socket
import threading
import time
from native_menu import NativeMenu
from native_processes import core_pids
from tray_ui import wait


def run(h):
    command, check = h['command'], h['check']
    menu = NativeMenu()
    initial = command('snapshot')
    original = command('settings')['intercept']
    profiles = []
    requests = []
    traffic_results = []
    binary = Path(__file__).parent.joinpath('fixtures/tray-controls/loopback.srs').read_bytes()
    assert binary.startswith(b'SRS')
    class HTTP(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_GET(self):
            requests.append(self.path)
            body = binary if self.path == '/good.srs' else b'not-an-srs' if self.path == '/bad.srs' else b'tray-echo'
            self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers()
            with contextlib.suppress(OSError): self.wfile.write(body)
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), HTTP)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = f'127.0.0.1:{server.server_port}'
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); udp.bind(('127.0.0.1', 0)); udp.settimeout(5)
    held = None
    adblock, warp = 'Block advertisements', 'WARP through the selected server'

    def settings(): return command('settings')['intercept']
    def save(refresh=True, **changes):
        previous = menu.ready(adblock)
        before = settings()
        result = command('saveSettings', {'section': 'intercept', 'previous': before, 'values': {**before, **changes}})
        if refresh and any(before.get(key) != value for key, value in changes.items()):
            wait(lambda: (node := menu.find(adblock)) and node[0] != previous[0], 'menu includes saved settings')
        return result
    def flag(label, key, desired):
        previous = menu.ready(label)
        menu.activate(previous)
        # GTK toggles a CheckMenuItem before the handler saves and republishes
        # its target. Wait for the new generation before the next click.
        wait(lambda: settings()[key] == desired and (node := menu.find(label))
             and node[0] != previous[0] and node[1].get('enabled', True)
             and (node[1].get('toggle-state') == 1) == desired, label + ' saved and menu refreshed')
    def settled():
        wait(lambda: command('snapshot')['running'] == main and not command('snapshot')['routing']['pending'], 'saved flags applied')
        menu.ready('Saved routing is applied', False)
    def traffic(destination=origin):
        client = http.client.HTTPConnection('127.0.0.1', port, timeout=2)
        try:
            client.request('GET', f'http://{destination}/echo')
            response = client.getresponse()
            body = response.read()
            traffic_results.append({'destination': destination, 'status': response.status, 'body': body.decode(errors='replace')[:512]})
            return response.status == 200 and body == b'tray-echo'
        except (OSError, http.client.HTTPException) as error:
            traffic_results.append({'destination': destination, 'error': str(error)})
            return False
        finally: client.close()
    def tunnel():
        connection = socket.create_connection(('127.0.0.1', port), timeout=4)
        connection.sendall(f'CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\n\r\n'.encode())
        headers = b''
        while b'\r\n\r\n' not in headers:
            part = connection.recv(4096); assert part; headers += part
        assert b' 200 ' in headers.split(b'\r\n', 1)[0]
        return connection
    def active(): return command('connectionConfiguration', {'id': main, 'active': True})['parts'][0]['config']

    try:
        command('disconnect')
        with socket.socket() as free: free.bind(('127.0.0.1', 0)); port = free.getsockname()[1]
        command('preferences', {**initial['preferences'], 'language': 'en', 'inboundPort': port})
        command('connectionSettings', {'mode': 'local', 'port': port})
        menu.ready(adblock); menu.ready(warp)
        check(not menu.checked(adblock) and not menu.checked(warp), 'native quick flags reflect the initial saved settings')
        before = core_pids(menu.pid)
        flag(adblock, 'adblock_enable', True)
        check(command('snapshot')['running'] is None and core_pids(menu.pid) == before, 'a flag can be saved in an empty library without launching a core')
        flag(adblock, 'adblock_enable', False)
        stale = menu.ready(adblock)
        save(refresh=False, adblock_ruleset_url=f'http://{origin}/bad.srs')
        menu.activate(stale); time.sleep(1.2)
        check(not settings()['adblock_enable'], 'a stale menu event cannot overwrite newer interception settings')
        main = command('saveProfile', {'name': 'Tray controls loopback', 'groupId': 'personal', 'kind': 'sing-box-outbound', 'config': {'type': 'direct'}})['id']; profiles.append(main)
        command('connect', {'id': main}); settled()
        check(traffic(), 'baseline traffic reaches the owned HTTP fixture')
        held = tunnel(); current = active()
        menu.activate(menu.ready(warp)); error = menu.dismiss_error('Could not save')
        check('Could not save' in error and not settings()['enable_warp'] and active() == current, 'missing WARP credentials reject the native action before replacing the live configuration')
        held.sendall(f'GET /echo HTTP/1.0\r\nHost: {origin}\r\n\r\n'.encode())
        result = b''
        while part := held.recv(4096): result += part
        check(result.endswith(b'tray-echo'), 'a held CONNECT survives the rejected WARP action')
        held.close(); held = None
        menu.activate(menu.ready(adblock)); error = menu.dismiss_error()
        wait(lambda: command('snapshot')['running'] == main, 'rollback to prior connection')
        check('saved, but' in error and settings()['adblock_enable'] and command('snapshot')['routing']['pending'] and traffic(), 'a failed rule-set download restores traffic and leaves the saved flag visibly pending')
        menu.ready('Apply saved changes'); check(not any(s.get('tag') == 'settings-adblock' for s in (active().get('route', {}).get('rule_set') or [])), 'active configuration still describes the restored request without the pending blocklist')
        flag(adblock, 'adblock_enable', False); settled()
        save(adblock_ruleset_url=f'http://{origin}/good.srs')
        flag(adblock, 'adblock_enable', True); settled()
        check('/good.srs' in requests and not traffic(), 'enabling AdBlock from the native tray downloads the owned SRS and blocks real loopback traffic')
        flag(adblock, 'adblock_enable', False); settled()
        check(traffic(), 'disabling AdBlock restores real HTTP traffic')
        own = command('generateWgKeys'); peer = command('generateWgKeys')
        save(warp_private_key=own['privateKey'], warp_public_key=peer['publicKey'], warp_ep=f'127.0.0.1:{udp.getsockname()[1]}', warp_ifc_addrs=['10.77.0.2/32'])
        flag(warp, 'enable_warp', True); settled()
        running = active(); endpoints = (running.get('endpoints') or [])
        base_outbound = next(o for o in running['outbounds'] if o.get('tag') == 'settings-warp-base')
        check(base_outbound.get('udp_fragment') is True and any(e.get('type') == 'wireguard' and e.get('detour') == 'settings-warp-base' for e in endpoints), 'WARP through a plain direct profile preserves its outbound and makes the original UDP fragmentation default explicit')
        # Use a documentation-only target inside WG; the UDP peer stays local.
        assert running['route']['final'] == 'proxy'
        assert endpoints[-1]['peers'][0]['address'] == '127.0.0.1'
        worker = threading.Thread(target=traffic, args=('192.0.2.1:80',), daemon=True); worker.start()
        packet, address = udp.recvfrom(2048); worker.join(timeout=3)
        check(len(packet) == 148 and packet[:4] == b'\x01\x00\x00\x00' and address[0] == '127.0.0.1', 'the WARP path sends a real WireGuard initiation only to the owned local UDP peer')
        Path(h['args'].artifacts).joinpath('wireguard-initiation.json').write_text(json.dumps({
            'length': len(packet), 'messageType': int.from_bytes(packet[:4], 'little'),
            'sha256': hashlib.sha256(packet).hexdigest(), 'source': address,
            'localPeer': udp.getsockname(), 'innerTarget': '192.0.2.1:80',
            'completedHandshake': False,
        }, indent=2))
        serialized = json.dumps(menu.tree())
        check(own['privateKey'] not in serialized and peer['publicKey'] not in serialized, 'native menu properties do not expose WARP credentials')
        flag(warp, 'enable_warp', False); settled()
        check(traffic(), 'disabling WARP restores the original HTTP path')
        command('disconnect')
        full = command('saveProfile', {'name': 'Owned full config', 'groupId': 'personal', 'kind': 'sing-box-config', 'config': {'outbounds': [{'type': 'direct'}]}})['id']; profiles.append(full)
        command('select', {'id': full})
        check(menu.ready(adblock, False) and menu.ready(warp, False), 'full configurations disable the quick flags that do not apply to them')
        command('select', {'id': main})
        command('preferences', {**command('snapshot')['preferences'], 'language': 'ru'})
        menu.ready('Блокировать рекламу'); menu.ready('WARP после выбранного сервера')
        flag('Блокировать рекламу', 'adblock_enable', True)
        check(command('snapshot')['running'] is None, 'Russian native labels change the same saved flag without connecting')
        flag('Блокировать рекламу', 'adblock_enable', False)
        menu.save(Path(h['args'].artifacts) / 'tray-controls-menu.json')
        Path(h['args'].artifacts).joinpath('traffic-results.json').write_text(json.dumps(traffic_results, indent=2))
    except BaseException:
        menu.save(Path(h['args'].artifacts) / 'tray-controls-failure-menu.json')
        Path(h['args'].artifacts).joinpath('traffic-results.json').write_text(json.dumps(traffic_results, indent=2))
        Path(h['args'].artifacts).joinpath('core-log.json').write_text(json.dumps(command('getLogs'), indent=2))
        if profiles and command('snapshot')['running'] == main:
            details = active()
            for endpoint in details.get('endpoints') or []: endpoint.pop('private_key', None)
            Path(h['args'].artifacts).joinpath('active-redacted.json').write_text(json.dumps(details, indent=2))
        raise
    finally:
        if held: held.close()
        command('disconnect')
        for profile in profiles: command('delete', {'id': profile})
        before = settings(); command('saveSettings', {'section': 'intercept', 'previous': before, 'values': original})
        command('preferences', initial['preferences'])
        server.shutdown(); server.server_close(); udp.close()
