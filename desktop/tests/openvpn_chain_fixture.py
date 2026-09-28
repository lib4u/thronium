"""Owned OpenVPN server for chain hops: one pinned Core runs an openvpn-server
endpoint whose tunnel reaches this fixture's loopback origin.

Import-safe. CLI PRIVATE_ROOT requires an adjacent pinned Core and a copied
Python executable named Thronium; EOF on stdin closes the owned server. No OTP,
system TUN, trust-store or host routing operations. Synthetic values only.
"""
import http.server
import json
import os
from pathlib import Path
import socket
import sys
import threading

from vpn_auth_fixture import Rpc, field
from vpn_credentials_fixture import NEW_PASSWORD, NEW_USERNAME, openvpn_outbound, openvpn_server
from vpn_otp_fixture import certificate_files

TUNNEL = '10.79.80.1'
BODY = b'chained'


class Origin:
    """Answers every GET like the chain-smoke origin; only the tunnel server dials it."""
    def __init__(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *_):
                pass

            def do_GET(self):
                assert self.client_address[0] == '127.0.0.1'
                self.send_response(200)
                self.send_header('Content-Length', str(len(BODY)))
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(BODY)

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


def main():
    root = Path(sys.argv[1]).resolve()
    assert Path(sys.executable).resolve() == root / 'Thronium'
    assert root.stat().st_uid == os.getuid() and root.stat().st_mode & 0o077 == 0
    origin, rpc = None, None
    try:
        certificate, key = certificate_files(root)
        origin = Origin()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        endpoint = openvpn_server(certificate, key, port)
        endpoint['tag'] = 'chain-server'
        endpoint['address'] = [TUNNEL + '/24']
        endpoint['push'] = {'routes': [TUNNEL + '/32']}
        config = {'log': {'disabled': True}, 'endpoints': [endpoint],
                  'outbounds': [{'type': 'direct', 'tag': 'direct'}],
                  'route': {'final': 'direct'}}
        rpc = Rpc(root, 'chain-server')
        request = field(1, json.dumps(config)) + field(2, 1) + field(9, 0)
        rpc.call('CheckConfig', request)
        rpc.call('Start', request)
        profile = openvpn_outbound(certificate, port, NEW_USERNAME, NEW_PASSWORD)
        del profile['tag']
        print(json.dumps({'profile': profile, 'tunnel': TUNNEL,
                          'httpUrl': f'http://{TUNNEL}:{origin.port}/chain',
                          'serverCorePid': rpc.process.pid}), flush=True)
        for _ in sys.stdin:
            pass
    finally:
        if rpc:
            rpc.close()
        if origin:
            origin.close()


if __name__ == '__main__':
    main()
