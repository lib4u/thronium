"""Real userspace OpenVPN peer and private IP/Speedtest HTTPS services.

OpenConnect cases exercise authentication only; no CSTP tunnel is simulated.
The parent is an owned Python executable named Thronium, adjacent to its Core.
"""
import json
import os
from pathlib import Path
import socket
import sys

from diagnostics_services_fixture import Fixture as ServicesFixture, HOSTS
from vpn_auth_fixture import Rpc, field
from vpn_credentials_fixture import (
    CredentialsFormServer, Events, NEW_PASSWORD, NEW_USERNAME,
    openvpn_outbound, openvpn_server,
)
from vpn_otp_fixture import certificate_files

TUNNEL = '10.79.36.1'


class Fixture(ServicesFixture):
    def __init__(self, directory, peer_root):
        assert os.getpid() == 1
        assert Path(sys.executable).resolve() == peer_root / 'Thronium'
        super().__init__(directory, hosts=HOSTS)
        self.rpc = self.auth = None
        try:
            certificate, key = certificate_files(peer_root)
            events = Events(peer_root / 'auth-events.jsonl')
            self.auth = CredentialsFormServer(certificate, key, events)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
                reservation.bind(('127.0.0.1', 0)); port = reservation.getsockname()[1]
            endpoint = openvpn_server(certificate, key, port)
            endpoint.update(tag='probe-server', address=[TUNNEL + '/24'], push={'routes': [TUNNEL + '/32']})
            config = {'log': {'disabled': True}, 'endpoints': [endpoint],
                      'outbounds': [{'type': 'direct', 'tag': 'direct'}], 'route': {'final': 'direct'}}
            self.rpc = Rpc(peer_root, 'probe-server')
            payload = field(1, json.dumps(config)) + field(2, 1) + field(9, 0)
            self.rpc.call('CheckConfig', payload); self.rpc.call('Start', payload)
            self.info.update(
                openvpn=openvpn_outbound(certificate, port, NEW_USERNAME, NEW_PASSWORD),
                openvpnRejected=openvpn_outbound(certificate, port),
                openconnectForm=self.auth.add_case('diagnostics-form', NEW_USERNAME, NEW_PASSWORD),
                openconnectRejected=self.auth.add_case('diagnostics-rejected'),
                authEvents=str(events.path), serverCorePid=self.rpc.process.pid,
                systemTun=False, openconnectBoundary='auth-exchange-only-no-cstp',
                simpleUrl='http://' + TUNNEL + ':' + str(self.http.server_port) + '/speedtest/random1000x1000.jpg')
            self.path.write_text(json.dumps(self.info)); self.path.chmod(0o600)
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.rpc: self.rpc.close()
        if self.auth: self.auth.close()
        result = super().close()
        result.update(peerReaped=self.rpc is None or self.rpc.process.poll() is not None,
                      authThreadReaped=self.auth is None or not self.auth.thread.is_alive(),
                      authSocketClosed=self.auth is None or self.auth.server.socket.fileno() == -1)
        return result
