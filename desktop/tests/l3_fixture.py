"""Run only inside the test runner's private user/network/mount namespace."""
import os,pathlib,subprocess,sys,json,tempfile
assert os.readlink('/proc/self/ns/net')!=os.environ['THRONIUM_TEST_ORIGINAL_NETNS']
def ip(*args):subprocess.run(['ip',*args],check=True,stdout=subprocess.DEVNULL)
ip('link','set','lo','up')
peer_code='''import sys,subprocess,http.server,socket,threading
print('started',flush=True);sys.stdin.readline()
def ip(*args):subprocess.run(['ip',*args],check=True)
ip('link','set','lo','up');ip('link','set','peer','addrgenmode','none');ip('link','set','peer','up')
ip('address','add','198.51.100.2/30','dev','peer');ip('-6','address','add','2001:db8:1::2/64','dev','peer','nodad')
ip('address','add','198.18.0.80/32','dev','lo');ip('-6','address','add','2001:db8:ff::80/128','dev','lo','nodad')
ip('route','add','default','via','198.51.100.1');ip('-6','route','add','default','via','2001:db8:1::1')
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  body=b'fixture-l3';self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
 def log_message(self,*args):pass
class V6(http.server.ThreadingHTTPServer):address_family=socket.AF_INET6
v4=http.server.ThreadingHTTPServer(('198.18.0.80',18080),Handler);v6=V6(('2001:db8:ff::80',18080),Handler)
threading.Thread(target=v4.serve_forever,daemon=True).start();threading.Thread(target=v6.serve_forever,daemon=True).start();print('ready',flush=True);sys.stdin.read()
'''
peer=subprocess.Popen(['unshare','--net',sys.executable,'-c',peer_code],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
try:
 assert peer.stdout.readline().strip()=='started'
 ip('link','add','uplink','type','veth','peer','name','peer');ip('link','set','peer','netns',str(peer.pid));ip('link','set','uplink','addrgenmode','none');ip('link','set','uplink','up')
 ip('address','add','198.51.100.1/30','dev','uplink');ip('-6','address','add','2001:db8:1::1/64','dev','uplink','nodad')
 ip('route','add','default','via','198.51.100.2');ip('-6','route','add','default','via','2001:db8:1::2')
 peer.stdin.write('go\n');peer.stdin.flush();assert peer.stdout.readline().strip()=='ready'
 def state():
  return [json.loads(subprocess.check_output(['ip',family,'-j',kind,*extra])) for family in ['-4','-6'] for kind,extra in [('rule',[]),('route',['show','table','all'])]]
 before=state()
 sysctls=[pathlib.Path('/proc/sys/net/ipv4/ip_forward'),*pathlib.Path('/proc/sys/net/ipv6/conf').glob('*/forwarding'),*pathlib.Path('/proc/sys/net/ipv6/conf').glob('*/accept_ra')]
 old={str(p):p.read_text() for p in sysctls}
 trace_file=tempfile.TemporaryFile(mode='w+')
 trace=subprocess.Popen(['tcpdump','-Z','root','-i','any','-nn','-l','tcp port 18080'],stdout=trace_file,stderr=trace_file) if os.environ.get('THRONIUM_L3_TRACE') else None
 try:subprocess.run([sys.argv[1]],check=True,timeout=40)
 finally:
  if trace:
   trace.terminate();trace.wait();trace_file.seek(0);print(trace_file.read()[:15000],flush=True)
  trace_file.close()
 after=state()
 assert before==after, 'L3 routes were not restored: '+json.dumps({'before':before,'after':after})
 assert all(pathlib.Path(p).read_text()==v for p,v in old.items()),'Forwarding sysctls were not restored'
 tables=subprocess.check_output(['nft','-j','list','tables'],text=True);assert 'thronium' not in tables
 print('PASS L3 restores policy rules, routes, firewall and forwarding sysctls',flush=True)
finally:
 peer.terminate();peer.wait(timeout=5)
