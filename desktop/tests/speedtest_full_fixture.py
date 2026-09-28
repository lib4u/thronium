"""Independent owned Speedtest.net discovery/ping/download/upload protocol fixture."""
import http.server
import json
import time
from full_xray_probes_fixture import Fixture as Transport

class Fixture(Transport):
    def __init__(self,directory,*,hosts=('www.speedtest.net','speed.peer.test')):
        super().__init__(directory,hosts=hosts)
        fixture=self
        self.state.update(downloadBytes=0,uploadBytes=0)
        class Origin(http.server.BaseHTTPRequestHandler):
            protocol_version='HTTP/1.1'
            def log_message(self,*_):pass
            def handle(self):
                try:super().handle()
                except OSError:pass  # Owned clients deliberately close during cancellation.
            def start(self,phase):
                with fixture.lock:
                    mode=fixture.state['mode'];fixture.state['active']+=1
                    row={'phase':phase,'method':self.command,'host':self.headers.get('Host'),'path':self.path,'mode':mode,'bytes':0};fixture.state['requests'].append(row)
                if mode=='hold-'+phase:fixture.release.wait(20)
                time.sleep(.03)
                return mode,row
            def end(self):
                with fixture.lock:fixture.state['active']-=1
            def send(self,status,body,kind='application/octet-stream'):
                self.send_response(status);self.send_header('Content-Length',str(len(body)));self.send_header('Content-Type',kind);self.send_header('Connection','close');self.end_headers();self.wfile.write(body)
            def do_GET(self):
                host=self.headers.get('Host','').split(':')[0]
                phase='api' if host=='www.speedtest.net' else 'latency' if self.path.split('?')[0].endswith('latency.txt') else 'download'
                mode,row=self.start(phase)
                try:
                    if phase=='api':
                        body=json.dumps([{'url':'https://speed.peer.test/speedtest/upload.php','lat':'0','lon':'0','name':'Owned70','country':'Test','sponsor':'Thronium fixture','id':'7001','host':'speed.peer.test:443','distance':1}]).encode()
                        if mode=='api-invalid':body=b'invalid server list'
                        if mode=='api-empty':body=b'[]'
                        self.send(503 if mode=='api-http' else 200,body,'application/json')
                    elif phase=='latency':self.send(503 if mode=='latency-http' else 200,b'test=test')
                    elif mode=='download-http':self.send(503,b'owned service unavailable')
                    else:
                        total=0 if mode=='download-empty' else 1024*1024
                        self.send_response(200);self.send_header('Content-Length',str(total+(1 if mode=='download-truncated' else 0)));self.send_header('Connection','close');self.end_headers()
                        for _ in range(total//65536):
                            self.wfile.write(b'x'*65536);self.wfile.flush()
                            with fixture.lock:row['bytes']+=65536;fixture.state['downloadBytes']+=65536
                            time.sleep(.03)
                except OSError:pass
                finally:self.end()
            def do_POST(self):
                mode,row=self.start('upload')
                try:
                    if mode=='upload-http':self.send(503,b'owned service unavailable');return
                    remaining=int(self.headers.get('Content-Length',0));assert 0<remaining<=16*1024*1024
                    self.connection.settimeout(3)
                    while remaining:
                        data=self.rfile.read(min(65536,remaining))
                        if not data:return
                        remaining-=len(data)
                        with fixture.lock:row['bytes']+=len(data);fixture.state['uploadBytes']+=len(data)
                        time.sleep(.03)
                    self.send(200,b'OK')
                except OSError:pass
                finally:self.end()
        class Admin(http.server.BaseHTTPRequestHandler):
            def log_message(self,*_):pass
            def do_GET(self):
                with fixture.lock:body=json.dumps(fixture.state).encode()
                self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            def do_POST(self):
                values=json.loads(self.rfile.read(int(self.headers.get('Content-Length',0))))
                with fixture.lock:
                    if 'mode' in values:
                        mode=values['mode'];assert mode in ('ok','api-http','api-invalid','api-empty','latency-http','download-http','upload-http','download-empty','download-truncated','hold-api','hold-download','hold-upload')
                        fixture.state['mode']=mode
                        if mode.startswith('hold-'):fixture.release.clear()
                        else:fixture.release.set()
                    if values.get('release'):fixture.release.set()
                    if values.get('clear'):
                        assert fixture.state['active']==0
                        fixture.state['requests']=[];fixture.state['dnsQueries']=[];fixture.state['downloadBytes']=fixture.state['uploadBytes']=0
                self.do_GET()
        self.api.RequestHandlerClass=Origin;self.http.RequestHandlerClass=Origin;self.admin.RequestHandlerClass=Admin
