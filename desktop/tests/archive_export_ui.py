"""Real native ZIP saves: complete WG/AWG files and scannable URI QR PNGs."""
import base64
import json
import pathlib
import re
import socket
import socketserver
import tempfile
import threading
import zipfile

from native_dialogs import file_dialog


def run(h):
    command, click, fill, select, wait_for, js, check, screenshot = (
        h[k] for k in ('command', 'click', 'fill', 'select', 'wait_for', 'js', 'check', 'screenshot'))
    request, base = h['request'], h['base']
    initial = command('snapshot')
    geometry = request('GET', base + '/window/rect')
    groups = []
    active_id = None
    tunnel = None
    server = None
    language = 'en'

    def group(name):
        gid = command('saveGroup', {'name': name, 'subscription': None})['id']
        groups.append(gid)
        return gid

    def save(gid, name, config, kind='sing-box-outbound'):
        return command('saveProfile', {'name': name, 'groupId': gid, 'kind': kind, 'config': config})['id']

    def show(gid, format):
        count = sum(p['groupId'] == gid for p in command('snapshot')['profiles'])
        wait_for('return [...document.querySelector(".group-strip select").options].some(o=>o.value===' + json.dumps(gid) + ')')
        select('.group-strip select', gid)
        wait_for('return document.querySelector(".group-strip select").selectedOptions[0].textContent.endsWith(' + json.dumps('· ' + str(count)) + ')')
        fill('#client-search', '')
        click('#library-more')
        click('#library-export')
        wait_for('return !!document.querySelector("#export-format")')
        select('#export-format', format)

    def close():
        click('#main-modal > .modal-head > button')
        wait_for('return !document.querySelector("dialog[open]")')

    def preview():
        click('#export-reveal')
        wait_for('return !!document.querySelector("#export-content")')
        return js('return document.querySelector("#export-content").textContent')

    def done():
        wait_for('return !!document.querySelector("#export-save") && !document.querySelector("#export-save").disabled && !document.querySelector("#archive-progress")', 25)

    def archive(path):
        click('#export-save')
        file_dialog('Сохранить архив' if language == 'ru' else 'Save archive', path)
        wait_for('return !!document.querySelector("#export-status")', 25)
        check(path.is_file() and path.stat().st_mode & 0o777 == 0o600, 'native archive save writes the chosen ZIP with private permissions')
        return zipfile.ZipFile(path)

    def safe_names(names, extension):
        return len(set(names)) == len(names) and all(
            name == pathlib.PurePosixPath(name).name and name.endswith(extension)
            and len(name.encode('utf-8')) <= 255
            and re.match(r'^\d{3}-', name) and not re.search(r'[\\/<>:"|?*\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069]', name)
            for name in names)

    def import_conf(text, target):
        click('.add-connection')
        click('#add-choice-link')
        fill('#import-source', text)
        select('#import-group', target)
        click('#import-review')
        check(js('return document.querySelectorAll(".import-select").length===1 && !document.querySelector(".import-acknowledge")'), 'archived WG configuration reimports without loss warnings')
        click('#import-save')
        wait_for('return !document.querySelector("dialog[open]")')

    def roundtrip():
        tunnel.sendall(b'archive-fixture-echo')
        data = b''
        while len(data) < len(b'archive-fixture-echo'):
            chunk = tunnel.recv(1024)
            if not chunk:
                return False
            data += chunk
        return data == b'archive-fixture-echo'

    try:
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark'})
        wait_for('return document.documentElement.lang==="en"')
        wg_group, qr_group, mixed_group, target = [group(n) for n in ('Archive WG', 'Archive QR', 'Archive mixed', 'Archive imported')]
        key = base64.b64encode(bytes([7]) * 32).decode()
        second_key = base64.b64encode(bytes([8]) * 32).decode()
        wg = {'type': 'wireguard', 'private_key': key, 'address': ['10.0.0.2/32', 'fd00::2/128'], 'mtu': 1380,
              'amnezia_wg': {'jc': 3, 'jmin': 40, 'jmax': 70, 's1': 32, 's2': 64, 'h1': '1-100'},
              'peers': [{'public_key': key, 'pre_shared_key': second_key, 'address': '127.0.0.1', 'port': 51820,
                         'allowed_ips': ['0.0.0.0/0'], 'persistent_keepalive_interval': 25},
                        {'public_key': second_key, 'address': '::1', 'port': 51821, 'allowed_ips': ['::/0']}]}
        wg2 = {**wg, 'private_key': second_key, 'address': ['10.0.0.3/32', 'fd00::3/128']}
        unsafe = '../..\\ Duplicate:*?"<>| \u202e🦊'
        save(wg_group, unsafe, wg)
        save(wg_group, unsafe, wg2)
        vless = {'type': 'vless', 'server': '127.0.0.1', 'server_port': 443,
                 'uuid': 'bf422fe4-1a5c-4b64-bc33-43c18a1b9dd1', 'tls': {'enabled': True, 'server_name': 'example.test'}}
        save(qr_group, unsafe, vless)
        save(qr_group, unsafe, {**vless, 'server_port': 8443})
        save(qr_group, '🦊' * 128, {**vless, 'server_port': 9443})
        save(mixed_group, 'Supported WG', wg)
        save(mixed_group, 'Unsupported VLESS for WG', vless)

        # A retained CONNECT tunnel checks actual traffic while the save dialog
        # awaits input, as well as after compression, QR rendering and cancellation.
        class Echo(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(300)
                try:
                    while True:
                        data = self.request.recv(4096)
                        if not data:
                            break
                        self.request.sendall(data)
                except (OSError, TimeoutError):
                    pass

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        server = Server(('127.0.0.1', 0), Echo)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        running_group = group('Archive active')
        active_id = save(running_group, 'Archive active connection', {'type': 'direct'})
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        command('preferences', {**command('snapshot')['preferences'], 'inboundPort': port})
        command('connect', {'id': active_id})
        active = command('connectionConfiguration', {'id': active_id, 'active': True})
        tunnel = socket.create_connection(('127.0.0.1', port), 5)
        authority = '127.0.0.1:' + str(server.server_address[1])
        tunnel.sendall(('CONNECT ' + authority + ' HTTP/1.1\r\nHost: ' + authority + '\r\n\r\n').encode())
        response = b''
        while b'\r\n\r\n' not in response:
            chunk = tunnel.recv(4096)
            assert chunk, 'Proxy closed the fixture CONNECT socket'
            response += chunk
        check(b' 200 ' in response.split(b'\r\n')[0] and roundtrip(), 'a real core CONNECT tunnel is established before archive work')

        with tempfile.TemporaryDirectory(prefix='thronium-archive-files-') as folder:
            folder = pathlib.Path(folder)
            show(wg_group, 'wireguard-archive')
            check(js('return document.querySelector("#export-copy").disabled && !document.querySelector("#export-content") && !document.querySelector("#export-qr")'), 'archive format supports saving and keeps private configuration content hidden')
            names = preview().splitlines()
            check(len(names) == 2 and safe_names(names, '.conf') and key not in '\n'.join(names), 'archive preview lists two unique safe filenames without keys')
            path = folder / 'wireguard.zip'
            with archive(path) as output:
                check(output.namelist() == names and output.testzip() is None, 'saved ZIP contains exactly every previewed WireGuard file with valid CRCs')
                configs = [output.read(name).decode() for name in names]
                check(all(text.count('[Peer]') == 2 and 'Jc = 3' in text and 'H1 = 1-100' in text
                          and 'Endpoint = [::1]:51821' in text and 'PresharedKey = ' + second_key in text
                          and 'PersistentKeepalive = 25' in text for text in configs), 'each archived WG file contains all peers, IPv6, preshared key and Amnezia fields')
            previous = path.read_bytes()
            click('#export-save')
            check(command('snapshot')['running'] == active_id and roundtrip(), 'native save dialog does not hold the engine lock or interrupt an existing tunnel')
            file_dialog('Save archive')
            done()
            check(not js('return !!document.querySelector("#export-status")') and path.read_bytes() == previous,
                  'cancelling an archive save leaves the existing ZIP unchanged and reports no saved file')
            close()
            for text in configs:
                import_conf(text, target)
            imported = [command('profile', {'id': p['id']})['config'] for p in command('snapshot')['profiles'] if p['groupId'] == target]
            check(imported == [wg, wg2], 'actual archived .conf reimport preserves every source WireGuard and Amnezia parameter')

            show(qr_group, 'links')
            links = preview().splitlines()
            select('#export-format', 'qr-archive')
            check(js('return !document.querySelector("#export-content") && document.querySelector("#export-copy").disabled'), 'changing from URI text to QR archive hides the previous links')
            qr_names = preview().splitlines()
            with archive(folder / 'qr.zip') as output:
                check(output.namelist() == qr_names and safe_names(qr_names, '.png') and output.testzip() is None,
                      'QR ZIP preserves safe unique filenames and contains exactly the selected profiles')
                decoded = []
                for name in qr_names:
                    png = output.read(name)
                    check(png.startswith(b'\x89PNG\r\n\x1a\n'), 'archived QR entry is an actual PNG image')
                    values = command('decodeQrImage', {'data': base64.b64encode(png).decode()})
                    assert len(values) == 1
                    decoded.append(values[0])
                check(decoded == links, 'every archived PNG decodes to the exact complete native URI from the existing exporter')
            close()

            show(mixed_group, 'wireguard-archive')
            click('#export-save')
            wait_for('return !!document.querySelector("dialog [role=alert]")')
            done()
            check(js('return !document.querySelector("#export-status") && !document.querySelector("#export-content") && document.querySelector("dialog [role=alert]").textContent.includes("WireGuard")'),
                  'mixed unsupported WG batch fails before any save dialog instead of silently skipping profiles')
            close()

            unknown_group = group('Archive loss checks')
            save(unknown_group, 'Valid URI', vless)
            save(unknown_group, 'Unknown URI fields', {**vless, 'future': {'private': 'hidden-archive-fixture'}})
            show(unknown_group, 'qr-archive')
            click('#export-save')
            wait_for('return !!document.querySelector("dialog [role=alert]")')
            done()
            check(js('const t=document.querySelector("dialog [role=alert]").textContent; return t.includes("future.private")&&!t.includes("hidden-archive-fixture")&&!document.querySelector("#export-status")'),
                  'QR batch rejects unrepresentable fields before rendering or saving and hides their values')
            close()

            cancel_group = group('Archive cancellation')
            drafts = [{'name': 'Cancel ' + str(i), 'groupId': cancel_group, 'kind': 'sing-box-outbound', 'config': vless} for i in range(100)]
            command('importProfiles', {'profiles': drafts})
            show(cancel_group, 'qr-archive')
            click('#export-save')
            wait_for('return !!document.querySelector("#archive-progress")')
            click('#archive-cancel')
            wait_for('return !!document.querySelector("dialog [role=alert]")')
            done()
            check(js('return document.querySelector("dialog [role=alert]").textContent.includes("cancelled")&&!document.querySelector("#export-status")'),
                  'cancelling a real 100-profile QR generation stops before saving a partial archive')
            close()
            save(cancel_group, 'Limit 101', vless)
            show(cancel_group, 'qr-archive')
            click('#export-save')
            wait_for('return !!document.querySelector("dialog [role=alert]")')
            done()
            check(js('return document.querySelector("dialog [role=alert]").textContent.includes("100")&&!document.querySelector("#export-status")'),
                  '101-profile archive is rejected as a whole rather than truncated')
            close()

            for language, theme in [('ru', 'light'), ('en', 'dark')]:
                command('preferences', {**command('snapshot')['preferences'], 'language': language, 'theme': theme})
                wait_for('return document.documentElement.lang===' + json.dumps(language))
                show(qr_group, 'qr-archive')
                preview()
                request('POST', base + '/window/rect', {'width': 390, 'height': 720})
                check(js('const d=document.querySelector("dialog"),b=d.querySelector(".modal-body");return b.scrollWidth<=b.clientWidth+1&&d.getBoundingClientRect().bottom<=innerHeight+1&&d.querySelector(".modal-footer").getBoundingClientRect().bottom<=innerHeight+1'),
                      'archive filename preview and save controls fit a 390px native window in ' + language)
                screenshot('archive-' + language + '-390')
                if language == 'ru':
                    click('#export-save')
                    file_dialog('Сохранить архив')
                    done()
                    check(not js('return !!document.querySelector("#export-status")'), 'Russian native archive chooser cancels without claiming a saved file')
                close()
                request('POST', base + '/window/rect', {'width': 1280, 'height': 860})

            for payload, expected in [({'data': 'bad-sensitive-fixture', 'format': 'qr-archive'}, 'archive_invalid_data'),
                                      ({'data': base64.b64encode(b'PK\x05\x06empty').decode(), 'format': 'qr-archive'}, 'archive_invalid_data'),
                                      ({'data': '', 'format': '../unsafe.zip'}, 'invalid_command_payload')]:
                try:
                    command('exportArchive', payload)
                    raise AssertionError('Invalid archive request accepted')
                except RuntimeError as error:
                    detail = error.args[0] if error.args else ''
                    code = (detail.get('error') or {}).get('code') if isinstance(detail, dict) else str(detail)
                    check(code == expected, 'native archive command rejects malformed input with a safe error code')
            check(command('snapshot')['running'] == active_id and command('connectionConfiguration', {'id': active_id, 'active': True}) == active and roundtrip(),
                  'all archive saves, errors, cancellations and native reimports preserve the original active configuration and open tunnel')
    finally:
        if tunnel is not None:
            tunnel.close()
        if server is not None:
            server.shutdown()
            server.server_close()
        if command('snapshot')['running']:
            command('disconnect')
        for gid in reversed(groups):
            command('deleteGroup', {'id': gid, 'deleteProfiles': True})
        command('preferences', initial['preferences'])
        request('POST', base + '/window/rect', geometry)
