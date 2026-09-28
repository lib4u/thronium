"""Owned OpenVPN data-plane fixture using immutable Core; no protocol imitation."""
import http.server
import json
import os
from pathlib import Path
import socket
import struct
import sys
import threading

from vpn_credentials_fixture import openvpn_server, openvpn_outbound, NEW_USERNAME, NEW_PASSWORD
from vpn_otp_fixture import certificate_files
from vpn_auth_fixture import Rpc, field

TUNNEL = '10.79.34.1'
class Events:
    def __init__(self, path):
        self.path=path;self.lock=threading.Lock();path.write_text('')
    def add(self, kind):
        with self.lock:
            with self.path.open('a') as f:f.write(json.dumps({'event':kind})+'\n')

class Http:
    def __init__(self, event, events):
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*_):pass
            def do_GET(self):
                assert self.client_address[0]=='127.0.0.1'
                if self.path!='/owned-policy34':self.send_error(404);return
                events.add(event)
                body=('policy34-'+event).encode()
                self.send_response(200);self.send_header('Content-Length',str(len(body)));self.send_header('Connection','close');self.end_headers();self.wfile.write(body)
        self.server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);self.server.daemon_threads=True
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.port=self.server.server_port
    def close(self):self.server.shutdown();self.server.server_close();self.thread.join(timeout=2)

class Dns:
    def __init__(self,event,address,events):
        self.socket=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);self.socket.bind(('127.0.0.1',0));self.socket.settimeout(.2)
        self.port=self.socket.getsockname()[1];self.stop=threading.Event();self.errors=[]
        def run():
            while not self.stop.is_set():
                try:data,peer=self.socket.recvfrom(2048)
                except socket.timeout:continue
                except OSError:
                    if self.stop.is_set():return
                    raise
                try:
                    assert peer[0]=='127.0.0.1' and len(data)>=17
                    identity,flags,qd,an,ns,ar=struct.unpack('!6H',data[:12]);assert qd==1 and not flags&0x8000
                    offset=12;labels=[]
                    while data[offset]:
                        n=data[offset];assert 0<n<=63;offset+=1;labels.append(data[offset:offset+n].decode('ascii'));offset+=n
                    offset+=1;qtype,qclass=struct.unpack('!HH',data[offset:offset+4]);offset+=4
                    name='.'.join(labels);assert name.endswith('.fixture.invalid') and qtype==1 and qclass==1
                    events.add(event)
                    response=struct.pack('!6H',identity,0x8180,1,1,0,0)+data[12:offset]+b'\xc0\x0c'+struct.pack('!HHIH',1,1,0,4)+socket.inet_aton(address)
                    self.socket.sendto(response,peer)
                except Exception as error:self.errors.append(type(error).__name__)
        self.thread=threading.Thread(target=run,daemon=True);self.thread.start()
    def close(self):self.stop.set();self.thread.join(timeout=2);self.socket.close();assert not self.errors,'policy_dns_fixture_invalid_query'

def main():
    root=Path(sys.argv[1]).resolve();assert Path(sys.executable).resolve()==root/'Thronium';assert root.stat().st_uid==os.getuid() and root.stat().st_mode&0o077==0
    events=Events(root/'safe-events.jsonl');resources=[];rpc=None
    try:
        certificate,key=certificate_files(root)
        for name in ['advertised-http','unadvertised-http','direct-http']:resources.append(Http(name,events))
        vpn_dns=Dns('vpn-dns',TUNNEL,events);resources.append(vpn_dns)
        direct_dns=Dns('direct-dns','192.0.2.34',events);resources.append(direct_dns)
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        endpoint=openvpn_server(certificate,key,port);endpoint['tag']='policy-server';endpoint['address']=[TUNNEL+'/24'];endpoint['push']={'routes':[TUNNEL+'/32'],'dns_servers':[{'priority':0,'addresses':[f'{TUNNEL}:{vpn_dns.port}'],'resolve_domains':['corp.fixture.invalid']}]}
        config={'log':{'disabled':True},'endpoints':[endpoint],'outbounds':[{'type':'direct','tag':'direct'}],'route':{'rules':[{'ip_cidr':['192.0.2.44/32'],'action':'route','outbound':'direct','override_address':'127.0.0.1'}],'final':'direct'}}
        rpc=Rpc(root,'policy-server');payload=field(1,json.dumps(config))+field(2,1)+field(9,0)
        rpc.call('CheckConfig',payload);rpc.call('Start',payload)
        ready={'endpoint':openvpn_outbound(certificate,port,NEW_USERNAME,NEW_PASSWORD),'certificate':str(certificate),'events':str(events.path),'serverCorePid':rpc.process.pid,'tunnelAddress':TUNNEL,'systemTun':False,'directDnsPort':direct_dns.port,'vpnDnsPort':vpn_dns.port}
        ready.update({name:resource.port for name,resource in zip(['advertisedHttpPort','unadvertisedHttpPort','directHttpPort'],resources)})
        print(json.dumps(ready),flush=True)
        for line in sys.stdin:
            command=json.loads(line);assert command['op']=='check' and len(command['configs'])==32
            checker=Rpc(root,'policy-check')
            try:
                for config in command['configs']:
                    checker.call('CheckConfig',field(1,json.dumps(config))+field(2,1)+field(9,0))
                checked_pid=checker.process.pid
            finally:checker.close()
            print(json.dumps({'checked':32,'checkerPid':checked_pid,'checkerReaped':True,'startCalls':0}),flush=True)
    finally:
        if rpc:rpc.close()
        for resource in reversed(resources):resource.close()
if __name__=='__main__':main()
