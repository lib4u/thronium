"""Owned TrustTunnel endpoint: a second Core serving the pinned inbound over TLS.

A loopback origin sits behind it at an address only the endpoint's route can
reach, so a served page proves the tunnel carried the request. Deep links are
built here from the DEEP_LINK.md TLV rules with synthetic credentials. The
parent is an owned Python executable named Thronium, adjacent to its Core.
"""
import base64
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import sys
import threading

from vpn_auth_fixture import Rpc, field
from vpn_otp_fixture import certificate_files

USER = 'tt-stand-user'
PASSWORD = 'tt-stand-password-51c3a'
SERVER_NAME = 'vpn.fixture.invalid'
# Loopback address nothing listens on; only the endpoint's route rewrites it.
TARGET = ('127.77.0.1', 8)
ORDER = ('h2', 'h3', 'insecure', 'old', 'full', 'wrong', 'h2udp')


def varint(value):
    if value <= 63:
        return bytes([value])
    if value <= 16383:
        return struct.pack('>H', value | 0x4000)
    if value <= 1073741823:
        return struct.pack('>I', value | 0x80000000)
    raise ValueError('varint too large')


def tlv(tag, value):
    if isinstance(value, bool):
        value = bytes([1 if value else 0])
    elif isinstance(value, int):
        value = bytes([value])
    elif isinstance(value, str):
        value = value.encode()
    elif isinstance(value, (list, tuple)):
        value = b''.join(varint(len(item.encode())) + item.encode() for item in value)
    return varint(tag) + varint(len(value)) + value


def deep_link(hostname, addresses, username, password, *, sni='', skip=False, certificate=b'', http3=False,
              anti_dpi=False, prefix='', name='', dns=(), old=False, extra=b''):
    # Same tag order as the reference builder: version, hostname, addresses,
    # custom SNI, credentials, prefix, skip, certificate, protocol, anti-DPI, name, DNS.
    body = tlv(0, 1) + tlv(1, hostname) + b''.join(tlv(2, address) for address in addresses)
    if sni: body += tlv(3, sni)
    body += tlv(5, username) + tlv(6, password)
    if prefix: body += tlv(11, prefix)
    if skip: body += tlv(7, True)
    if certificate: body += tlv(8, certificate)
    if http3: body += tlv(9, 2)
    if anti_dpi: body += tlv(10, True)
    if name: body += tlv(12, name)
    if dns: body += tlv(13, list(dns))
    return 'tt://' + ('' if old else '?') + base64.urlsafe_b64encode(body + extra).decode().rstrip('=')


class Fixture:
    def __init__(self, directory, peer_root):
        assert os.getpid() == 1
        assert Path(sys.executable).resolve() == peer_root / 'Thronium'
        directory = Path(directory); directory.mkdir(mode=0o700, parents=True)
        self.path = directory / 'ready.json'
        self.lock = threading.Lock(); self.records = []
        self.rpc = self.origin = self.thread = None
        try:
            certificate, key = certificate_files(peer_root)
            pem = certificate.read_text().strip()
            der = ssl.PEM_cert_to_DER_cert(pem)
            owner = self

            class Origin(http.server.BaseHTTPRequestHandler):
                protocol_version = 'HTTP/1.1'
                def log_message(self, *_): pass
                def do_GET(self):
                    if self.path == '/records':
                        with owner.lock: body = json.dumps(owner.records).encode()
                    else:
                        with owner.lock:
                            owner.records.append({'path': self.path, 'host': self.headers.get('Host'), 'remote': self.client_address[0]})
                        body = ('tt-origin:' + self.path).encode()
                    self.send_response(200); self.send_header('Content-Length', str(len(body)))
                    self.send_header('Connection', 'close'); self.end_headers(); self.wfile.write(body)

            self.origin = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Origin); self.origin.daemon_threads = True
            self.thread = threading.Thread(target=self.origin.serve_forever, daemon=True); self.thread.start()
            ports = {}
            for name, kind in (('any', socket.SOCK_STREAM), ('udp', socket.SOCK_DGRAM)):
                with socket.socket(socket.AF_INET, kind) as reservation:
                    reservation.bind(('127.0.0.1', 0)); ports[name] = reservation.getsockname()[1]
            tls = {'enabled': True, 'certificate_path': str(certificate), 'key_path': str(key)}
            users = [{'username': USER, 'password': PASSWORD}]
            def inbound(tag, port, **extra):
                return {'type': 'trusttunnel', 'tag': tag, 'listen': '127.0.0.1', 'listen_port': port, 'users': users, 'tls': tls, **extra}
            config = {'log': {'disabled': True},
                      # The pinned core's inbound TLS config keeps the ALPN list it was built with,
                      # so its HTTP/3 listener needs an explicit h3; the outbound is unaffected.
                      'inbounds': [inbound('tt-any', ports['any']),
                                   inbound('tt-udp', ports['udp'], network='udp', tls={**tls, 'alpn': ['h3']})],
                      'outbounds': [{'type': 'direct', 'tag': 'direct'}],
                      'route': {'final': 'direct', 'rules': [
                          {'ip_cidr': [TARGET[0] + '/32'], 'port': [TARGET[1]], 'action': 'route', 'outbound': 'direct',
                           'override_address': '127.0.0.1', 'override_port': self.origin.server_port}]}}
            self.rpc = Rpc(peer_root, 'tt-endpoint')
            payload = field(1, json.dumps(config)) + field(2, 1) + field(9, 0)
            self.rpc.call('CheckConfig', payload); self.rpc.call('Start', payload)
            any_address = ['127.0.0.1:' + str(ports['any'])]; udp_address = ['127.0.0.1:' + str(ports['udp'])]
            links = {
                'h2': deep_link(SERVER_NAME, any_address, USER, PASSWORD, certificate=der, name='Стенд · TrustTunnel h2'),
                'h3': deep_link(SERVER_NAME, udp_address, USER, PASSWORD, certificate=der, http3=True, name='Стенд · TrustTunnel h3'),
                'insecure': deep_link('127.0.0.1', any_address, USER, PASSWORD, skip=True, name='TrustTunnel insecure'),
                'old': deep_link(SERVER_NAME, any_address, USER, PASSWORD, certificate=der, old=True, name='TrustTunnel old spelling'),
                'full': deep_link(SERVER_NAME, any_address + ['[2001:db8::7]:443'], USER, PASSWORD, sni=SERVER_NAME, certificate=der,
                                  anti_dpi=True, prefix='16030100', name='TrustTunnel full', dns=('1.1.1.1', 'tls://dns.example'),
                                  extra=tlv(14, 'future')),
                'wrong': deep_link(SERVER_NAME, any_address, USER, 'not-the-stand-password', certificate=der, name='TrustTunnel wrong password'),
                'h2udp': deep_link(SERVER_NAME, udp_address, USER, PASSWORD, certificate=der, name='TrustTunnel h2 to udp-only'),
            }
            names = {name: link for name, link in (('h2', 'Стенд · TrustTunnel h2'), ('h3', 'Стенд · TrustTunnel h3'), ('insecure', 'TrustTunnel insecure'),
                                                    ('old', 'TrustTunnel old spelling'), ('full', 'TrustTunnel full'),
                                                    ('wrong', 'TrustTunnel wrong password'), ('h2udp', 'TrustTunnel h2 to udp-only'))}
            self.info = {'links': links, 'order': list(ORDER), 'names': names, 'ports': ports, 'target': 'http://%s:%d' % TARGET,
                         'records': 'http://127.0.0.1:%d/records' % self.origin.server_port, 'serverName': SERVER_NAME,
                         'certificatePem': pem.split('\n'), 'username': USER, 'password': PASSWORD, 'serverCorePid': self.rpc.process.pid}
            self.path.write_text(json.dumps(self.info)); self.path.chmod(0o600)
        except BaseException:
            self.close()
            raise

    def close(self):
        result = {}
        if self.rpc:
            result['serverCoreAliveUntilStop'] = self.rpc.process.poll() is None
            self.rpc.close(); result['serverCoreReaped'] = self.rpc.process.poll() is not None
        if self.origin:
            self.origin.shutdown(); self.origin.server_close()
            if self.thread: self.thread.join(timeout=3)
            result.update(originThreadReaped=not self.thread.is_alive(), originSocketClosed=self.origin.socket.fileno() == -1)
        with self.lock: result['originRequests'] = len(self.records)
        return result
