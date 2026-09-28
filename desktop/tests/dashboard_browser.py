from pathlib import Path
import argparse, http.server, threading, zipfile, json, time, os
import gi
gi.require_version('Gtk','3.0'); gi.require_version('WebKit2','4.1')
from gi.repository import Gtk, WebKit2, GLib
p=argparse.ArgumentParser();p.add_argument('--artifacts',type=Path,required=True);p.add_argument('--archive',type=Path,required=True);p.add_argument('--bootstrap-dir',type=Path,required=True);p.add_argument('--active-url-file',type=Path);a=p.parse_args();a.artifacts.mkdir(parents=True,exist_ok=False)
assert os.readlink('/proc/self/ns/net') != os.environ['THRONIUM_TEST_ORIGINAL_NETNS']
src=a.bootstrap_dir
with zipfile.ZipFile(a.archive) as z: files={n.split('/',1)[1]:z.read(n) for n in z.namelist() if '/' in n and not n.endswith('/')}
files['thronium.html']=(src/'bootstrap.html').read_bytes();files['thronium-bootstrap.js']=(src/'messages.js').read_bytes()+(src/'bootstrap.js').read_bytes()
# Model a pre-existing navigation fallback deterministically. The published UI
# remains untouched; legacy worker behavior is an explicit fixture, not assumed.
legacy_worker = b"""const legacyCache='thronium-owned-legacy62';
const legacyIndex=new URL('index.html',self.registration.scope).href;
self.addEventListener('install',e=>e.waitUntil(caches.open(legacyCache).then(c=>c.add(legacyIndex)).then(()=>self.skipWaiting())));
self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));
self.addEventListener('fetch',e=>{if(e.request.mode==='navigate')e.respondWith(caches.open(legacyCache).then(c=>c.match(legacyIndex)));});
"""
state={'requests':[]}
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*_):pass
 def do_GET(self):
  path=self.path.split('?',1)[0]; name={'/thronium-dashboard.html':'thronium.html','/thronium-dashboard.js':'thronium-bootstrap.js'}.get(path,path.removeprefix('/dashboard/') or 'index.html')
  state['requests'].append(path)
  body=legacy_worker if name=='sw.js' else files.get(name,b'{}')
  self.send_response(200);self.send_header('Content-Length',str(len(body)));self.send_header('Cache-Control','no-store')
  self.send_header('Content-Type','text/javascript' if name.endswith('.js') else 'text/html' if name.endswith('.html') else 'application/json' if name.endswith('.json') else 'application/octet-stream');self.end_headers()
  try:self.wfile.write(body)
  except (BrokenPipeError,ConnectionResetError):pass
server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever);thread.start()
manager=WebKit2.WebsiteDataManager(base_data_directory=str(a.artifacts/'data'),base_cache_directory=str(a.artifacts/'cache'))
context=WebKit2.WebContext.new_with_website_data_manager(manager);view=WebKit2.WebView.new_with_context(context);window=Gtk.Window();window.set_default_size(1000,720);window.add(view);window.show_all()
resources=[]
def resource_started(_view,resource,_request):
 def finished(res):
  response=res.get_response()
  if response:resources.append({'path':__import__('urllib.parse',fromlist=['urlsplit']).urlsplit(response.get_uri()).path,'status':response.get_status_code()})
 resource.connect('finished',finished)
view.connect('resource-load-started',resource_started)
checks=[];authority='127.0.0.1:'+str(server.server_port);base='http://'+authority+'/dashboard/'
def pump():
 while GLib.MainContext.default().pending():GLib.MainContext.default().iteration(False)
 time.sleep(.02)
def js(script,timeout=4):
 result=[]
 def done(v,r,*_):
  try:result.append((True,v.evaluate_javascript_finish(r).to_json(0)))
  except Exception as e:result.append((False,str(e)))
 view.evaluate_javascript(script,-1,None,None,None,done,None);end=time.monotonic()+timeout
 while not result and time.monotonic()<end:pump()
 assert result, 'JS timeout'
 if not result[0][0]:raise RuntimeError(result[0][1])
 return json.loads(result[0][1]) if result[0][1] is not None else None
read="JSON.stringify({href:location.href,stored:localStorage.getItem('sing-box-dashboard.servers'),controlled:!!navigator.serviceWorker.controller,title:document.title,body:document.body.innerText.slice(0,120)})"
def wait(predicate,timeout=30):
 end=time.monotonic()+timeout;last=None
 while time.monotonic()<end:
  pump()
  try:
   last=json.loads(js(read))
   if predicate(last):return last
  except Exception:pass
 raise AssertionError('timeout '+repr(last))
def secret(value):
 def ok(s):
  try:return json.loads(s['stored'])['servers'][-1]['secret']==value and s['href']==base
  except Exception:return False
 return ok
try:
 if a.active_url_file:
  import urllib.parse
  url=json.loads(a.active_url_file.read_text())[0];parts=urllib.parse.urlsplit(url)
  assert parts.scheme=='http' and parts.hostname in ('127.0.0.1','::1') and parts.path=='/thronium-dashboard.html' and not parts.query
  base=urllib.parse.urlunsplit((parts.scheme,parts.netloc,'/dashboard/','',''));expected=urllib.parse.parse_qs(parts.fragment)['secret'][0]
  view.load_uri(url);wait(secret(expected));wait(lambda s:s['controlled'])
  view.load_uri(url);result=wait(secret(expected));checks.append({'actualCoreColdAndWarmHandoff':True})
  end=time.monotonic()+8
  while time.monotonic()<end:pump()
  final=json.loads(js(read));assert final['href']==base
  body=js('document.body.innerText')
  assert 'Goroutines' in body and any(r['path']=='/daemon.StartedService/GetVersion' and r['status']==200 for r in resources), 'Actual API did not produce the dashboard status'
  checks.append({'actualAuthenticatedCoreStatus':True})
  (a.artifacts/'page.json').write_text(json.dumps({'body':body,'resources':resources},indent=2)+'\n')
  snapshot=[]
  def snapped(v,result,*_):
   try:v.get_snapshot_finish(result).write_to_png(str(a.artifacts/'actual-dashboard.png'));snapshot.append(True)
   except Exception as e:snapshot.append(str(e))
  view.get_snapshot(WebKit2.SnapshotRegion.VISIBLE,WebKit2.SnapshotOptions.NONE,None,snapped,None)
  end=time.monotonic()+5
  while not snapshot and time.monotonic()<end:pump()
  assert snapshot==[True], str(snapshot)
 else:
  view.load_uri(base); initial=wait(lambda s:s['controlled']); checks.append({'legacyFixtureWorkerControlled':True})
  count=state['requests'].count('/dashboard/thronium.html')
  view.load_uri(base+'thronium.html#secret=legacy-to-new62')
  intercepted=wait(lambda s:s['href'].startswith(base+'thronium.html') and s['controlled'] and 'sing-box' in s['body'])
  assert not intercepted['stored'] and state['requests'].count('/dashboard/thronium.html')==count, 'Legacy cache must actually intercept the handoff before testing repair'
  checks.append({'legacyNavigationFallbackReproduced':True})
  handoff='http://'+authority+'/thronium-dashboard.html#secret='
  view.load_uri(handoff+'legacy-to-new62')
  migrated=wait(secret('legacy-to-new62'),45);checks.append({'handoffEscapesLegacyWorker':True})
  view.load_uri(handoff+'warm-new62')
  wait(secret('warm-new62'));checks.append({'warmWorkerUpdatedSecret':True})
  js("localStorage.setItem('sing-box-dashboard.servers',JSON.stringify({servers:[{id:'other',name:'Other',url:'localhost:1',secret:'other62'}]}));true")
  view.load_uri(handoff+'special%26%23%3D%2B')
  result=wait(secret('special&#=+'));saved=json.loads(result['stored']);assert saved['servers'][0]['id']=='other';checks.append({'specialSecretAndOtherServerPreserved':True})
 (a.artifacts/'summary.json').write_text(json.dumps({'passed':True,'archiveSha256':__import__('hashlib').sha256(a.archive.read_bytes()).hexdigest(),'checks':checks,'requestPaths':state['requests']},indent=2)+'\n');print(json.dumps(checks),flush=True)
finally:
 window.destroy();server.shutdown();server.server_close();thread.join();(a.artifacts/'requests.json').write_text(json.dumps(state['requests'],indent=2)+'\n')
