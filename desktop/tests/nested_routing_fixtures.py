"""Independent handwritten truth rows and owned HTTP origins for native routing."""
import contextlib
import http.server
import json
from pathlib import Path
import socketserver
import threading

DIRECTORY = Path(__file__).resolve().parents[1] / 'engine/tests/fixtures/nested-routing'
MATRIX = json.loads((DIRECTORY / 'matrix.json').read_text())
ACTION_ONLY = set(json.loads((DIRECTORY / 'action_keys.json').read_text())['actionKeysUnion']) - {'network_type'}


def materialize(value, port):
    if value == '$destinationPort': return port
    if value == '$destinationRange': return f'{port}:{port}'
    if isinstance(value, dict): return {k: materialize(v, port) for k, v in value.items()}
    if isinstance(value, list): return [materialize(v, port) for v in value]
    return value


def listable(value):
    """Only pinned Listable network/port aliases used by the handwritten rows."""
    if isinstance(value, list): return [listable(v) for v in value]
    if not isinstance(value, dict): return value
    result={k:listable(v) for k,v in value.items()}
    for key in ['network','port']:
        if key in result and not isinstance(result[key],list):result[key]=[result[key]]
    return result


def condition(config): return {k:v for k,v in config.items() if k not in ACTION_ONLY}


def no_nested_actions(config):
    for child in config.get('rules',[]):
        if not isinstance(child,dict) or ACTION_ONLY.intersection(child) or not no_nested_actions(child):return False
    return True


class Origins:
    def __init__(self):
        self.events=[];self.lock=threading.Lock();self.servers=[]
        self.matched=self.origin('MATCHED');self.fallback=self.origin('FALLBACK')
        class Echo(socketserver.BaseRequestHandler):
            def handle(self):
                with contextlib.suppress(OSError):
                    while data:=self.request.recv(8192):self.request.sendall(data)
        class Server(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=True
        self.echo=Server(('127.0.0.1',0),Echo);self.start(self.echo)
    def start(self,server):
        self.servers.append(server);threading.Thread(target=server.serve_forever,daemon=True).start()
    def origin(self,label):
        owner=self
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version='HTTP/1.1'
            def do_GET(self):
                assert self.path.startswith('/native-nested/')
                with owner.lock:owner.events.append({'origin':label,'path':self.path})
                body=label.encode();self.send_response(200);self.send_header('Content-Length',str(len(body)));self.send_header('Connection','close');self.end_headers();self.wfile.write(body)
            def log_message(self,*args):pass
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);server.daemon_threads=True;self.start(server);return server
    def counts(self):
        with self.lock:return {name:sum(e['origin']==name for e in self.events) for name in ['MATCHED','FALLBACK']}
    def close(self):
        for server in self.servers:server.shutdown();server.server_close()
