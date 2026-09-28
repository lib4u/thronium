"""Independent protobuf fixtures served over owned HTTPS in a private namespace."""
import http.server
import json
import ssl
from warp_registration_fixture import Fixture as Transport


def varint(value):
    out = bytearray()
    while value > 127: out.append((value & 127) | 128); value >>= 7
    out.append(value); return bytes(out)
def field(number, value): return varint(number * 8 + 2) + varint(len(value)) + value
def integer(number, value): return varint(number * 8) + varint(value)
def geosite(category='TEST', domain='blocked.assets.test'):
    item = integer(1, 2) + field(2, domain.encode()) + field(3, field(1, b'owned'))
    return field(1, field(1, category.encode()) + field(2, item))
def geoip(category='TEST'):
    cidr = field(1, bytes([192, 0, 2, 0])) + integer(2, 24)
    return field(1, field(1, category.encode()) + field(2, cidr))

class Fixture(Transport):
    def __init__(self, directory):
        super().__init__(directory, hosts=('assets.thronium.test', 'mirror.thronium.test'))
        fixture = self
        class API(http.server.BaseHTTPRequestHandler):
            protocol_version='HTTP/1.1'
            def log_message(self,*_): pass
            def do_GET(self):
                with fixture.lock:
                    mode=fixture.state['mode'];fixture.state['active']+=1
                    fixture.state['requests'].append({'path':self.path,'host':self.headers.get('Host'),'mode':mode})
                try:
                    if mode=='hold':fixture.release.wait(20)
                    kind='geoip' if self.path.endswith('/geoip.dat') else 'geosite'
                    category='MISSING' if mode=='missing-category' else 'TEST'
                    body=geoip(category) if kind=='geoip' else geosite(category, 'next.assets.test' if mode=='updated' else 'blocked.assets.test')
                    if mode=='malformed':body=b'private-geodata-response64'
                    if mode=='wrong-kind':body=geosite() if kind=='geoip' else geoip()
                    code=503 if mode=='http-error' else 200;location=None
                    if mode=='redirect' and self.headers.get('Host')=='assets.thronium.test':code=302;location='https://mirror.thronium.test'+self.path
                    if mode=='downgrade':code=302;location='http://assets.thronium.test'+self.path
                    if mode=='loop':code=302;location='https://assets.thronium.test'+self.path
                    if mode=='credentials':code=302;location='https://user:owned@mirror.thronium.test'+self.path
                    if location:body=b''
                    self.send_response(code);self.send_header('Connection','close')
                    if location:self.send_header('Location',location)
                    if mode=='chunked':
                        self.send_header('Transfer-Encoding','chunked');self.end_headers()
                        for _ in range(1025):self.wfile.write(b'10000\r\n'+b' '*65536+b'\r\n')
                        self.wfile.write(b'0\r\n\r\n')
                    else:
                        self.send_header('Content-Length',str(64*1024*1024+1 if mode=='oversize' else len(body)));self.end_headers()
                        if mode!='oversize':self.wfile.write(body)
                except (OSError,ssl.SSLError):pass
                finally:
                    with fixture.lock:fixture.state['active']-=1
        class Admin(http.server.BaseHTTPRequestHandler):
            def log_message(self,*_):pass
            def do_GET(self):
                with fixture.lock:body=json.dumps(fixture.state).encode()
                self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            def do_POST(self):
                value=json.loads(self.rfile.read(int(self.headers.get('Content-Length',0))))
                with fixture.lock:
                    if 'mode' in value:
                        assert value['mode'] in ('ok','updated','missing-category','hold','malformed','wrong-kind','http-error','oversize','chunked','redirect','downgrade','credentials','loop')
                        fixture.state['mode']=value['mode']
                        if value['mode']=='hold':fixture.release.clear()
                        else:fixture.release.set()
                    if value.get('release'):fixture.release.set()
                self.do_GET()
        self.api.RequestHandlerClass=API;self.admin.RequestHandlerClass=Admin
