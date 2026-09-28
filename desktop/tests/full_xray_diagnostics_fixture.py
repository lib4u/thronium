"""Owned TLS IP endpoint and byte-counted downloads behind full Xray client DNS."""
import http.server
import json
import time
from full_xray_probes_fixture import Fixture as Transport

class Fixture(Transport):
    def __init__(self, directory):
        super().__init__(directory, hosts=('api.ip2location.io','download.probe.test','blocked.probe.test'))
        fixture=self
        class Origin(http.server.BaseHTTPRequestHandler):
            protocol_version='HTTP/1.1'
            def log_message(self,*_):pass
            def do_GET(self):
                with fixture.lock:
                    mode=fixture.state['mode'];fixture.state['active']+=1
                    row={'host':self.headers.get('Host'),'path':self.path,'mode':mode,'bytes':0};fixture.state['requests'].append(row)
                try:
                    if mode=='hold':fixture.release.wait(20)
                    time.sleep(.03)
                    if self.headers.get('Host','').split(':')[0]=='api.ip2location.io':
                        body=json.dumps({'ip':'2001:db8::9' if mode=='ip-v6' else '203.0.113.9','country_code':'-' if mode=='ip-unknown' else 'DE' if mode=='ip-v6' else 'JP'}).encode()
                        if mode=='ip-invalid':body=b'{"ip":"not-an-ip","country_code":"JP"}'
                        if mode=='ip-oversize':body=b' '*65537
                        self.send_response(503 if mode=='http-error' else 200);self.send_header('Content-Length',str(len(body)));self.send_header('Connection','close');self.end_headers();self.wfile.write(body)
                        with fixture.lock:row['bytes']=len(body)
                    else:
                        chunks=0 if mode=='speed-empty' else 32
                        self.send_response(503 if mode=='http-error' else 200);self.send_header('Content-Length',str(chunks*8192+(1 if mode=='speed-truncated' else 0)));self.send_header('Connection','close');self.end_headers()
                        for _ in range(chunks):
                            self.wfile.write(b'x'*8192);self.wfile.flush()
                            with fixture.lock:row['bytes']+=8192
                            time.sleep(.012)
                except OSError:pass
                finally:
                    with fixture.lock:fixture.state['active']-=1
        class Admin(http.server.BaseHTTPRequestHandler):
            def log_message(self,*_):pass
            def do_GET(self):
                with fixture.lock:body=json.dumps(fixture.state).encode()
                self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            def do_POST(self):
                values=json.loads(self.rfile.read(int(self.headers.get('Content-Length',0))))
                with fixture.lock:
                    if 'mode' in values:
                        mode=values['mode'];assert mode in ('ok','hold','dns-fail','ip-v6','ip-unknown','ip-invalid','ip-oversize','http-error','speed-empty','speed-truncated')
                        fixture.state['mode']=mode
                        if mode=='hold':fixture.release.clear()
                        else:fixture.release.set()
                    if values.get('release'):fixture.release.set()
                    if values.get('clear'):fixture.state['requests']=[];fixture.state['dnsQueries']=[]
                self.do_GET()
        self.api.RequestHandlerClass=Origin;self.http.RequestHandlerClass=Origin;self.admin.RequestHandlerClass=Admin
