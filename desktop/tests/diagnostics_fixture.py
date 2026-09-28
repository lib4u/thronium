"""Loopback SOCKS chain and TLS IP service. Its CA is trusted only by test children."""
import contextlib
import http.server
import ipaddress
import json
import pathlib
import select
import socket
import socketserver
import ssl
import struct
import subprocess
import threading
import time

class Fixture:
    def __init__(self, directory):
        directory=pathlib.Path(directory);directory.mkdir(parents=True,exist_ok=True)
        self.cert=directory/'ip-service.pem';key=directory/'ip-service.key'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(self.cert),'-days','1','-subj','/CN=api.ip2location.io','-addext','subjectAltName=DNS:api.ip2location.io','-addext','basicConstraints=critical,CA:TRUE'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.lock=threading.Lock();self.state={'ipMode':'ok','downloadMode':'ok','seen':[],'active':0};self.servers=[];self.sockets=set()
        fixture=self
        class HTTP(http.server.BaseHTTPRequestHandler):
            def log_message(self,*_):pass
            def do_GET(self):
                with fixture.lock:mode=fixture.state['ipMode' if getattr(self.server,'ip_service',False) else 'downloadMode']
                try:
                    if mode=='slow':time.sleep(1.2)
                    if getattr(self.server,'ip_service',False):
                        body={'ok':b'{"ip":"203.0.113.9","country_code":"JP"}','ipv6':b'{"ip":"2001:db8::9","country_code":"DE"}','unknown':b'{"ip":"203.0.113.9","country_code":"-"}','invalid':b'{"ip":"private.invalid/token","country_code":"US"}','oversize':b' '*65537}.get(mode,b'{"ip":"203.0.113.9","country_code":"JP"}')
                        self.send_response(429 if mode=='http-error' else 200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
                    elif mode=='http-error':self.send_response(503);self.end_headers();self.wfile.write(b'unavailable')
                    elif mode=='truncated':self.send_response(200);self.send_header('Content-Length','999999');self.end_headers();self.wfile.write(b'short')
                    elif mode=='empty':self.send_response(200);self.send_header('Content-Length','0');self.end_headers()
                    else:
                        body=b'x'*8192;chunks=2800 if mode=='long' else 30
                        self.send_response(200);self.send_header('Content-Length',str(len(body)*chunks));self.end_headers()
                        for _ in range(chunks):self.wfile.write(body);self.wfile.flush();time.sleep(.012)
                except (BrokenPipeError,ConnectionResetError,ssl.SSLError):pass
        self.http=http.server.ThreadingHTTPServer(('127.0.0.1',0),HTTP);self.servers.append(self.http)
        self.tls=http.server.ThreadingHTTPServer(('127.0.0.1',0),HTTP);self.tls.ip_service=True
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(self.cert,key);self.tls.socket=ctx.wrap_socket(self.tls.socket,server_side=True);self.servers.append(self.tls)
        class SOCKSServer(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=True
        class SOCKS(socketserver.BaseRequestHandler):
            def handle(self):
                incoming=self.request;upstream=None
                with fixture.lock:fixture.sockets.add(incoming);fixture.state['active']+=1
                def read(count):
                    data=b''
                    while len(data)<count:
                        chunk=incoming.recv(count-len(data))
                        if not chunk:raise EOFError()
                        data+=chunk
                    return data
                try:
                    incoming.settimeout(8);version,count=read(2)
                    if version!=5:raise ValueError('SOCKS version')
                    read(count);incoming.sendall(b'\x05\x00');version,operation,reserved,kind=read(4)
                    if operation!=1:raise ValueError('SOCKS operation')
                    host=read(read(1)[0]).decode() if kind==3 else str(ipaddress.ip_address(read(4 if kind==1 else 16)))
                    port=struct.unpack('!H',read(2))[0]
                    with fixture.lock:fixture.state['seen'].append([self.server.index,host,port])
                    if self.server.index==2 and port==443:destination=fixture.tls.server_port
                    elif host in ('127.0.0.1','localhost') and port in fixture.ports+[fixture.http.server_port]:destination=port
                    else:incoming.sendall(b'\x05\x05\x00\x01'+b'\x00'*6);return
                    upstream=socket.create_connection(('127.0.0.1',destination),timeout=8)
                    with fixture.lock:fixture.sockets.add(upstream)
                    incoming.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
                    while True:
                        ready,_,_=select.select([incoming,upstream],[],[],8)
                        if not ready:return
                        for source in ready:
                            data=source.recv(65536)
                            if not data:return
                            (upstream if source is incoming else incoming).sendall(data)
                except (OSError,EOFError,ValueError):pass
                finally:
                    with fixture.lock:
                        fixture.sockets.discard(incoming);fixture.sockets.discard(upstream);fixture.state['active']-=1
                    if upstream:upstream.close()
        self.ports=[]
        for i in range(3):
            server=SOCKSServer(('127.0.0.1',0),SOCKS);server.index=i;self.ports.append(server.server_address[1]);self.servers.append(server)
        class Admin(http.server.BaseHTTPRequestHandler):
            def log_message(self,*_):pass
            def do_GET(self):
                with fixture.lock:body=json.dumps(fixture.state).encode()
                self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            def do_POST(self):
                value=json.loads(self.rfile.read(int(self.headers.get('Content-Length',0))))
                with fixture.lock:
                    for key in ['ipMode','downloadMode']:
                        if key in value:fixture.state[key]=value[key]
                    if value.get('clear'):fixture.state['seen']=[]
                self.do_GET()
        self.admin=http.server.ThreadingHTTPServer(('127.0.0.1',0),Admin);self.servers.append(self.admin)
        for server in self.servers:threading.Thread(target=server.serve_forever,daemon=True).start()
        self.info={'ports':self.ports,'download':f'http://127.0.0.1:{self.http.server_port}/download','admin':f'http://127.0.0.1:{self.admin.server_port}/','cert':str(self.cert)}
        self.path=directory/'fixture.json';self.path.write_text(json.dumps(self.info))
    def close(self):
        with self.lock:sockets=list(self.sockets)
        for s in sockets:
            with contextlib.suppress(OSError):s.shutdown(socket.SHUT_RDWR)
            with contextlib.suppress(OSError):s.close()
        for server in self.servers:server.shutdown();server.server_close()
