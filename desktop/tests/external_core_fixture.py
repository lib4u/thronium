#!/usr/bin/env python3
"""Foreground SOCKS5 fixture. The app launches it; destinations stay on loopback.

Each invocation writes its own PID/starttime and the exact argv/config digest.
This file never discovers or signals other processes by name.
"""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import socketserver
import struct
import time


def identity(pid):
    text=(Path('/proc')/str(pid)/'stat').read_text()
    fields=text[text.rfind(')')+2:].split()
    return {'pid':pid,'starttime':fields[19],'ppid':int(fields[1]),'state':fields[0]}


def exact(sock,n):
    value=b''
    while len(value)<n:
        part=sock.recv(n-len(value))
        if not part:raise EOFError()
        value+=part
    return value


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--config',required=True)
    parser.add_argument('--literal',action='append',default=[])
    args=parser.parse_args()
    config_path=Path(args.config);raw=config_path.read_bytes();config=json.loads(raw)
    marker=Path(config['marker']);assert marker.parent.is_dir() and marker.name=='launches.jsonl'
    def event(data):
        # One O_APPEND write per line so handler threads cannot interleave JSON.
        fd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
        try:os.write(fd,(json.dumps(data,separators=(',',':'))+'\n').encode())
        finally:os.close(fd)
    ancestry=[];current=os.getpid()
    for _ in range(8):
        node=identity(current);ancestry.append(node)
        if node['ppid']<=1:break
        current=node['ppid']
    event({'event':'launch','identity':identity(os.getpid()),'ancestors':ancestry,
        'configPath':str(config_path),'configSha256':hashlib.sha256(raw).hexdigest(),
        'configMode':config_path.stat().st_mode&0o777,'literals':args.literal,
        'mode':config.get('mode','ready'),'port':config['port']})
    if config.get('mode')=='exit':return 31
    if config.get('child'):
        child=os.fork()
        if child==0:
            signal.signal(signal.SIGTERM,signal.SIG_IGN)
            while True:signal.pause()
        event({'event':'child','identity':identity(child),'owner':os.getpid()})
    if config.get('delay'):time.sleep(config['delay'])
    class Socks(socketserver.BaseRequestHandler):
        def handle(self):
            with contextlib.suppress(OSError,EOFError,ValueError):
                self.request.settimeout(10)
                version,count=exact(self.request,2)
                if version!=5 or 0 not in exact(self.request,count):return
                self.request.sendall(b'\x05\x00')
                # Readiness does only the greeting; no destination or traffic event.
                version,command,_,kind=exact(self.request,4)
                if version!=5 or command!=1:return
                if kind==1:host=socket.inet_ntop(socket.AF_INET,exact(self.request,4))
                elif kind==4:host=socket.inet_ntop(socket.AF_INET6,exact(self.request,16))
                elif kind==3:host=exact(self.request,exact(self.request,1)[0]).decode('ascii')
                else:return
                port=struct.unpack('!H',exact(self.request,2))[0]
                if host!='127.0.0.1' or port!=config['echoPort']:
                    self.request.sendall(b'\x05\x02\x00\x01'+b'\0'*6);return
                with socket.create_connection((host,port),timeout=5) as target:
                    self.request.sendall(b'\x05\x00\x00\x01'+b'\0'*6)
                    event({'event':'connect','owner':os.getpid(),'port':port})
                    while True:
                        readable,_,_=select.select([self.request,target],[],[],10)
                        if not readable:continue
                        for source in readable:
                            data=source.recv(8192)
                            if not data:return
                            (target if source is self.request else self.request).sendall(data)
    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address=True;daemon_threads=True
    with Server(('127.0.0.1',config['port']),Socks) as server:server.serve_forever(poll_interval=.1)
    return 0


if __name__=='__main__':raise SystemExit(main())
