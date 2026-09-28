"""Owned VPN/HTTP probe fixtures. No OTP, host networking or protocol emulation."""
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import threading

from vpn_auth_fixture import Rpc, field
from vpn_credentials_fixture import (
    CredentialsFormServer, Events as AuthEvents, NEW_PASSWORD, NEW_USERNAME,
    openvpn_outbound, openvpn_server,
)
from vpn_otp_fixture import certificate_files

TUNNEL = "10.79.36.1"


class Events:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        path.touch(mode=0o600, exist_ok=False)

    def add(self, event):
        assert event in {
            "http-success", "https-success", "http-closed-before-headers",
            "http-held", "http-held-peer-closed", "http-hold-released",
            "http-handler-error",
        }
        with self.lock:
            with self.path.open("a") as output:
                output.write(json.dumps({"event": event}) + "\n")


class Http:
    def __init__(self, events, certificate=None, key=None):
        self.stop = threading.Event()
        self.release = threading.Event()
        owner = self

        class Server(http.server.ThreadingHTTPServer):
            daemon_threads = False

            def handle_error(self, *_):
                events.add("http-handler-error")

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_):
                pass

            def do_GET(self):
                assert self.client_address[0] == "127.0.0.1"
                if self.path == "/closed-before-headers":
                    events.add("http-closed-before-headers")
                    self.close_connection = True
                    self.connection.shutdown(socket.SHUT_RDWR)
                    return
                if self.path == "/hold":
                    events.add("http-held")
                    self.connection.settimeout(0.1)
                    while not owner.stop.is_set() and not owner.release.is_set():
                        try:
                            chunk = self.connection.recv(1)
                        except socket.timeout:
                            continue
                        except (ConnectionError, OSError):
                            chunk = b""
                        if not chunk:
                            events.add("http-held-peer-closed")
                            self.close_connection = True
                            return
                        raise AssertionError("unexpected_owned_hold_payload")
                    if owner.stop.is_set():
                        self.close_connection = True
                        return
                    events.add("http-hold-released")
                elif self.path == "/success":
                    events.add("https-success" if certificate else "http-success")
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()

        self.server = Server(("127.0.0.1", 0), Handler)
        if certificate:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certificate, key)
            self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.stop.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        assert not self.thread.is_alive(), "owned_http_fixture_cleanup_timeout"


def https_certificate(root):
    certificate, key = root / "https-certificate.pem", root / "https-key.pem"
    with (root / "https-generation-private.log").open("w") as output:
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(certificate), "-days", "1",
            "-subj", "/CN=owned-probe.fixture.invalid",
            "-addext", "subjectAltName=IP:" + TUNNEL,
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign",
            "-addext", "extendedKeyUsage=serverAuth",
        ], check=True, stdout=output, stderr=subprocess.STDOUT)
    key.chmod(0o600)
    return certificate, key


def main():
    root = Path(sys.argv[1]).resolve()
    assert Path(sys.executable).resolve() == root / "Thronium"
    assert root.stat().st_uid == os.getuid() and root.stat().st_mode & 0o077 == 0
    resources, rpc = [], None
    try:
        certificate, key = certificate_files(root)
        https_cert, https_key = https_certificate(root)
        events = Events(root / "http-events.jsonl")
        auth_events = AuthEvents(root / "auth-events.jsonl")
        http = Http(events)
        resources.append(http)
        https = Http(events, https_cert, https_key)
        resources.append(https)
        auth = CredentialsFormServer(certificate, key, auth_events)
        resources.append(auth)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        endpoint = openvpn_server(certificate, key, port)
        endpoint["tag"] = "probe-server"
        endpoint["address"] = [TUNNEL + "/24"]
        endpoint["push"] = {"routes": [TUNNEL + "/32"]}
        config = {"log": {"disabled": True}, "endpoints": [endpoint],
                  "outbounds": [{"type": "direct", "tag": "direct"}],
                  "route": {"final": "direct"}}
        rpc = Rpc(root, "probe-server")
        request = field(1, json.dumps(config)) + field(2, 1) + field(9, 0)
        rpc.call("CheckConfig", request)
        rpc.call("Start", request)
        ready = {
            "openvpn": openvpn_outbound(certificate, port, NEW_USERNAME, NEW_PASSWORD),
            "openvpnRejected": openvpn_outbound(certificate, port),
            "openconnectForm": auth.add_case("probe-form", NEW_USERNAME, NEW_PASSWORD),
            "openconnectRejected": auth.add_case("probe-rejected"),
            "httpUrl": f"http://{TUNNEL}:{http.port}/success",
            "closedUrl": f"http://{TUNNEL}:{http.port}/closed-before-headers",
            "holdUrl": f"http://{TUNNEL}:{http.port}/hold",
            "httpsUrl": f"https://{TUNNEL}:{https.port}/success",
            "httpsCertificate": str(https_cert),
            "events": str(events.path), "authEvents": str(auth_events.path),
            "serverCorePid": rpc.process.pid, "systemTun": False,
            "openconnectBoundary": "auth-exchange-only-no-cstp",
        }
        print(json.dumps(ready), flush=True)
        for line in sys.stdin:
            command = json.loads(line)
            assert command in ({"op": "release-holds"}, {"op": "reset-holds"})
            if command["op"] == "release-holds":
                http.release.set()
            else:
                http.release.clear()
            print(json.dumps({"done": True}), flush=True)
    finally:
        if rpc:
            rpc.close()
        for resource in reversed(resources):
            resource.close()


if __name__ == "__main__":
    main()
