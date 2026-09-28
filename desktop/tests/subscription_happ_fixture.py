"""Loopback subscription whose `routing` header carries a Happ policy variant.
Synthetic only: loopback SOCKS members, RFC 5737 addresses, .invalid names.
"""
import base64
import http.server
import json
import threading

BASE = {
    'Name': 'Fixture provider',
    'GlobalProxy': True,
    'RemoteDNSType': 'DoU', 'RemoteDNSIP': '127.0.0.1',
    'DomesticDNSType': 'DoU', 'DomesticDNSIP': '127.0.0.1',
    'DnsHosts': {'pinned.fixture.invalid': '192.0.2.7'},
    'DirectSites': ['domain:direct.fixture.invalid'],
    'DirectIp': ['192.0.2.0/24'],
    'ProxySites': ['domain:proxy.fixture.invalid'],
    'ProxyIp': ['198.51.100.0/24'],
    'RouteOrder': 'proxy-direct-block',
}
VARIANTS = {
    'fakedns': {**BASE, 'FakeDNS': 'true'},
    'ondemand': {**BASE, 'DomainStrategy': 'IPOnDemand'},
    'chunked': {**BASE, 'UseChunkFiles': 'true'},
    'onadd': {**BASE, 'FakeDNS': 'false'},
}


def link(variant):
    action = 'onadd' if variant == 'onadd' else 'add'
    payload = base64.b64encode(json.dumps(VARIANTS[variant]).encode()).decode()
    return f'happ://routing/{action}/{payload}'


class Server:
    """One loopback HTTP server; `variant` selects the routing header per request."""

    def __init__(self, socks_port):
        fixture = self
        fixture.variant = 'fakedns'
        fixture.requests = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                fixture.requests.append(self.path)
                body = f'socks://127.0.0.1:{socks_port}#Happ%20member'.encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Routing', link(fixture.variant))
                self.end_headers()
                self.wfile.write(body)

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f'http://127.0.0.1:{self.server.server_port}/subscription'

    def close(self):
        self.server.shutdown()
        self.server.server_close()
