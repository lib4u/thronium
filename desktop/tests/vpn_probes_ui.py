"""Real userspace VPN HTTP probes; no fake outcomes or host TUN activation."""
import collections
import contextlib
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import socketserver
import subprocess
import sys
import threading
import time
from native_menu import NativeMenu
from native_processes import core_pids

SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
POLICY = {'onlyAdvertisedRoutes': True, 'useTunnelDns': True, 'blockOutsideDns': False}


def run(h):
    command, click, fill, wait_for, js, check = (h[k] for k in ('command','click','fill','wait_for','js','check'))
    ready = json.loads(Path(os.environ['_THRONIUM_VPN_PROBES_READY']).read_text())
    control = Path(os.environ['_THRONIUM_VPN_PROBES_CONTROL'])
    assert ready['systemTun'] is False
    xdg = Path(os.environ['XDG_DATA_HOME']); config = Path(os.environ['XDG_CONFIG_HOME'])
    assert xdg.parent.name.startswith('thronium-native-test-') and config.parent == xdg.parent
    assert os.environ.get('GSETTINGS_BACKEND') == 'keyfile'
    # An isolated bus: either the harness's private bus under the test root or the owned display session's bus.
    assert os.environ['DBUS_SESSION_BUS_ADDRESS'].startswith('unix:path=' + str(xdg.parent)) or os.environ.get('_THRONIUM_TEST_BUS') == os.environ['DBUS_SESSION_BUS_ADDRESS']
    assert os.environ['SSL_CERT_FILE'] == ready['httpsCertificate']
    assert not list(Path(os.environ['SSL_CERT_DIR']).iterdir())
    library = xdg/'io.thronium.desktop/library.json'
    menu = NativeMenu(); app = Path(h['args'].application).resolve()
    assert Path('/proc',str(menu.pid),'exe').resolve() == app
    initial = command('snapshot'); initial_routing = command('routing')
    geometry = h['request']('GET',h['base']+'/window/rect')
    group = command('saveGroup',{'name':'Owned VPN HTTP probes','subscription':None})['id']
    audit = {'batches':[],'geometry':{},'processes':[],'authControls':{},'hostTun':False,'hostProxy':False,
             'openconnectCstpClaimed':False,'policyRouteGateClaimed':False}
    ids = []; held = None; otp = None
    journal = config/'thronium-system-proxy/recovery.json'; lock = journal.with_name('owner.lock')
    private = [SECRET, *[ready[key][field] for key in ('openvpn','openvpnRejected','openconnectForm','openconnectRejected')
                         for field in ('username','password')]]

    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            with contextlib.suppress(OSError):
                while body:=self.request.recv(4096):self.request.sendall(body)
    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address=True;daemon_threads=True
    origin=Server(('127.0.0.1',0),Echo)
    threading.Thread(target=origin.serve_forever,daemon=True).start()

    def until(predicate,timeout=25):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            result=predicate()
            if result:return result
            time.sleep(.08)
        raise AssertionError('VPN probe observation timed out')
    def state():return json.loads(library.read_text())
    def safe(value):return not any(word and word in json.dumps(value,ensure_ascii=False) for word in private)
    def snap():
        value=command('snapshot');assert safe(value),'probe snapshot leaked source credentials'
        return value
    def events():
        return collections.Counter(json.loads(line)['event'] for line in Path(ready['events']).read_text().splitlines())
    def auth_events():return Path(ready['authEvents']).read_bytes()
    def auth_rows():return [json.loads(line) for line in auth_events().splitlines()]
    def auth_control(start,accepted):
        delta=auth_rows()[start:];credentials=[r for r in delta if r['event']=='credentials']
        audit['authControls']['form' if accepted else 'rejected']=delta
        expected={'newExact':accepted,'oldExact':not accepted,'accepted':accepted,'httpStatus':200 if accepted else 403}
        exact=bool(credentials) and all(all(r[k]==v for k,v in expected.items()) for r in credentials)
        lockouts=[r for r in delta if r['event']=='initial-lockout']
        return exact and (not lockouts if accepted else any(r['accepted'] is False and r['httpStatus']==403 for r in lockouts))
    def release(operation):
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(5);client.connect(str(control));client.sendall(json.dumps({'op':operation}).encode()+b'\n')
            result=b''
            while b'\n' not in result:
                part=client.recv(1024);assert part;result+=part
            assert json.loads(result)=={'done':True}
    def processes():
        rows=[]
        for pid in core_pids(menu.pid):
            try:
                p=Path('/proc',pid);start=p.joinpath('stat').read_text().rsplit(')',1)[1].split()[19]
                assert p.joinpath('exe').resolve()==app.with_name('ThroniumCore')
                rows.append({'pid':int(pid),'starttime':start})
            except FileNotFoundError:pass
        return sorted(rows,key=lambda r:r['pid'])
    def record_processes(label):
        value=processes();audit['processes'].append({'label':label,'children':value});return value
    def add(name,configuration,kind='sing-box-outbound',**metadata):
        config_value=copy.deepcopy(configuration)
        if kind=='sing-box-outbound':config_value.pop('tag',None)
        id=command('saveProfile',{'name':name,'groupId':group,'kind':kind,'config':config_value,**metadata})['id']
        ids.append(id);return id
    def begin(chosen,url=None,timeout=700,method='http',row=False):
        url=url or ready['httpUrl']
        if method!='http' or row:
            command('savePingSettings',{'method':method,'url':url,'timeoutMs':timeout})
        if row:
            before=snap()['urlTests'];before_id=before['id'] if before else None
            button='[data-profile-menu='+json.dumps(chosen[0])+']'
            wait_for('return !!document.querySelector('+json.dumps(button)+')')
            js('document.querySelector(arguments[0]).scrollIntoView({block:"center",behavior:"instant"})',button)
            time.sleep(.2);click(button);click('#probe-one')
            return until(lambda:(batch:=snap()['urlTests']) and batch['id']!=before_id and batch)['id']
        return command('startPing' if method!='http' else 'startUrlTests',{'ids':chosen} if method!='http' else {'ids':chosen,'url':url,'timeoutMs':timeout})['id']
    def done(timeout=30):
        batch=until(lambda:(b:=snap()['urlTests']) and all(e['status'] not in ('queued','testing') for e in b['entries']) and b,timeout)
        audit['batches'].append(batch);return batch
    def rendered(batch):
        wait_for('return document.querySelector("#ping-status")?.dataset.pingBatch==='+json.dumps(batch['id'])+' && !document.querySelector("#probe-cancel")')
    def row(id):return next(r for r in snap()['profiles'] if r['id']==id)['measurement']
    def clean(before):
        return until(lambda:processes()==before,10)
    def status(id,wanted):
        selector='[data-profile-latency='+json.dumps(id)+']'
        wait_for('return document.querySelector('+json.dumps(selector)+')?.dataset.probeStatus==='+json.dumps(wanted))
        return js('const e=document.querySelector(arguments[0]);return {text:e.textContent,title:e.title,status:e.dataset.probeStatus}',selector)
    def echo():
        held.sendall(b'owned-main-probe-preserved');return held.recv(128)==b'owned-main-probe-preserved'
    def open_held():
        connection=socket.create_connection(('127.0.0.1',port),timeout=5)
        address='127.0.0.1:'+str(origin.server_address[1])
        connection.sendall(f'CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n\r\n'.encode());headers=b''
        while b'\r\n\r\n' not in headers:
            value=connection.recv(4096);assert value;headers+=value
        assert b' 200 ' in headers.split(b'\r\n',1)[0]
        return connection
    def fresh_settings():
        script='''from gi.repository import Gio
import json,os
from pathlib import Path
assert os.environ['GSETTINGS_BACKEND']=='keyfile'
assert Path(os.environ['XDG_CONFIG_HOME']).parent.name.startswith('thronium-native-test-')
rows=[]
for suffix in ('','http','https','socks','ftp'):
 s=Gio.Settings.new('org.gnome.system.proxy'+('.'+suffix if suffix else ''))
 for key in sorted(s.list_keys()):
  u=s.get_user_value(key);rows.append([suffix,key,s.get_value(key).unpack(),u.unpack() if u is not None else None])
print(json.dumps(rows))'''
        return json.loads(subprocess.check_output([sys.executable,'-c',script],text=True,timeout=5))
    def file_identity(path):
        if not path.exists():return None
        st=path.stat();return {'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'inode':st.st_ino,'mtime':st.st_mtime_ns}
    def lease():
        if not lock.exists():return False
        with lock.open('rb') as handle:
            try:fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:return True
            fcntl.flock(handle,fcntl.LOCK_UN);return False
    def proxy_state():return {'journal':file_identity(journal),'keyfile':file_identity(config/'glib-2.0/settings/keyfile'),'values':fresh_settings(),'leased':lease()}
    def geometry_ready(language):
        values=[];stable=0;previous=None;end=time.monotonic()+10
        while time.monotonic()<end:
            value=js('''const e=document.querySelector('#ping-status'),r=e.getBoundingClientRect();return {width:innerWidth,height:innerHeight,left:r.left,right:r.right,top:r.top,bottom:r.bottom,summaryScroll:e.scrollWidth,summaryClient:e.clientWidth,scroll:document.documentElement.scrollWidth,client:document.documentElement.clientWidth,text:e.textContent};''')
            values.append(value)
            valid=(value['width']==390 and value['left']>=0 and value['right']<=390 and value['top']>=0
                   and value['bottom']<=value['height'] and value['summaryScroll']<=value['summaryClient']+1
                   and value['scroll']<=value['client']+1)
            stable=stable+1 if valid and value==previous else (1 if valid else 0)
            if stable>=3:break
            previous=value;time.sleep(.15)
        audit['geometry'][language]=values
        assert stable>=3,'VPN probe summary does not fit actual390px viewport'
        h['screenshot']('vpn-probes-'+language+'-390')

    try:
        command('disconnect');command('preferences',{**initial['preferences'],'language':'en','theme':'dark'})
        wait_for('return document.documentElement.lang==="en"')
        with socket.socket() as free:free.bind(('127.0.0.1',0));port=free.getsockname()[1]
        command('connectionSettings',{'mode':'local','port':port})
        good=add('VPN probe successful HTTP',ready['openvpn'],vpnPolicy=POLICY)
        connected=add('VPN probe connected without HTTP',ready['openvpn'])
        rejected=add('VPN probe rejected password',ready['openvpnRejected'])
        form=add('VPN probe OpenConnect form',ready['openconnectForm'])
        oc_rejected=add('VPN probe OpenConnect rejected password',ready['openconnectRejected'])
        direct=add('Main direct connection',{'type':'direct','udp_fragment':True})
        command('connect',{'id':direct});held=open_held();main=snap();main_processes=record_processes('main-connected')
        assert len(main_processes)==1
        command('savePingSettings',{'method':'http','url':ready['httpUrl'],'timeoutMs':1000})
        before=state();counts=events();begin([good],timeout=1000,row=True);result=done();clean(main_processes)
        check(result['entries'][0]['status']=='ok' and result['entries'][0]['latencyMs']>=0 and events()['http-success']==counts['http-success']+2,
              'real profile-menu HTTP test traverses the owned OpenVPN tunnel for warmup and measured request')
        check(status(good,'ok')['text'].endswith('ms') and state()==before and echo() and snap()['since']==main['since'],
              'measured latency is shown without changing policy/configuration or the existing main CONNECT')
        counts=events();begin([good],ready['httpsUrl'],1500);result=done();clean(main_processes)
        check(result['entries'][0]['status']=='ok' and events()['https-success']==counts['https-success']+2,
              'certificate-verified HTTPS reaches the owned server through the VPN using only private App trust')
        begin([connected],ready['closedUrl']);result=done();clean(main_processes);entry=result['entries'][0]
        check(entry['status']=='connected-only' and entry['latencyMs'] is None and entry['error'] is None and events()['http-closed-before-headers']>0,
              'a genuine closed-before-headers response after VPN connect yields connected-only without invented latency')
        label=status(connected,'connected-only')
        rendered(result)
        check(label['text']=='VPN' and 'no HTTP' in label['title'] and '10' in label['title'],
              'connected-only row explains unavailable HTTP and bounded VPN-status wait instead of milliseconds')
        check('VPN without HTTP response: 1' in js('return document.querySelector("#ping-status").textContent'),
              'the actual connected-only batch has its own count distinct from HTTP success and sign-in requests')
        begin([rejected]);result=done();clean(main_processes)
        check(result['entries'][0]['status']=='auth-required' and result['entries'][0]['error']=='probe_vpn_auth_required' and result['entries'][0]['latencyMs'] is None,
              'real OpenVPN password refusal becomes auth-required without automatic credentials submission')
        auth_start=len(auth_rows());begin([form]);result=done();clean(main_processes)
        check(result['entries'][0]['status']=='auth-required' and status(form,'auth-required')['text']=='Sign in'
              and auth_control(auth_start,True) and snap()['vpn']==main['vpn'] and not js('return !!document.querySelector(".vpn-auth-modal")'),
              'a real OpenConnect server form terminates the disposable test and never enters the main VPN panel')
        auth_start=len(auth_rows());begin([oc_rejected]);result=done();clean(main_processes)
        check(result['entries'][0]['status']=='auth-required' and result['entries'][0]['error']=='probe_vpn_auth_required'
              and auth_control(auth_start,False) and echo(),
              'real OpenConnect terminal password rejection also becomes sign-in required while main traffic survives')
        for id,url in [(connected,ready['closedUrl']),(form,ready['httpUrl'])]:
            begin([id],url,method='auto');result=done();clean(main_processes);entry=result['entries'][0]
            check(entry['status'] in ('connected-only','auth-required') and [a['method'] for a in entry['attempts']]==['http'] and entry['effectiveMethod']=='http',
                  'Auto stops at the real terminal VPN outcome without TCP or ICMP fallback for '+('connected-only' if id==connected else 'auth-required'))
        # Restore the visible cache method after Auto; this is an explicit
        # preference mutation before freezing later no-write observations.
        command('savePingSettings',{'method':'http','url':ready['httpUrl'],'timeoutMs':1000})
        # One shared URL yields one real HTTP latency and two sign-in outcomes.
        begin([good,rejected,form]);result=done();clean(main_processes)
        check([e['status'] for e in result['entries']]==['ok','auth-required','auth-required'] and echo() and processes()==main_processes,
              'mixed queued profiles retain independent real outcomes and preserve the owned main Core')
        rendered(result)
        for language in ['en','ru']:
            command('preferences',{**snap()['preferences'],'language':language});wait_for('return document.documentElement.lang==='+json.dumps(language))
            h['request']('POST',h['base']+'/window/rect',{'width':390,'height':844})
            wait_for('return innerWidth===390')
            js('document.querySelector("#ping-status").scrollIntoView({block:"center",behavior:"instant"})')
            geometry_ready(language)
            text=js('return document.querySelector("#ping-status").textContent')
            colors=js('''const rows=arguments[0].map(id=>{const e=document.querySelector('[data-profile-latency="'+id+'"]');return {status:e.dataset.probeStatus,text:e.textContent,color:getComputedStyle(e).color}});return {rows,muted:getComputedStyle(document.querySelector('#ping-status')).color};''',[good,connected,form])
            audit.setdefault('verdictColors',{})[language]=colors
            success,vpn,auth=colors['rows']
            check(('Sign-in required: 2' if language=='en' else 'Требуется вход: 2') in text and status(form,'auth-required')['text']==('Sign in' if language=='en' else 'Вход')
                  and [item['status'] for item in colors['rows']]==['ok','connected-only','auth-required']
                  and vpn['color']==auth['color']==colors['muted'] and vpn['color']!=success['color'],
                  'real mixed batch count and muted VPN/sign-in labels fit '+language+' at390 distinctly from successful HTTP')
        h['request']('POST',h['base']+'/window/rect',geometry)
        command('preferences',{**snap()['preferences'],'language':'en'});wait_for('return document.documentElement.lang==="en"')

        # A bound profile is measured like Qt's test build. This live binding
        # has no template to fill, so the probe runs on the saved credentials and
        # spends nothing; a template without any binding has no code source.
        guarded=add('Bound VPN probe without a template',ready['openvpn'])
        otp=command('otpSave',{'value':{'name':'Probe guard HOTP','secret':SECRET,'type':'hotp','algorithm':'SHA1','counter':'19','period':30,'digits':6}})
        view=command('getVpnOtpBinding',{'profileId':guarded})
        command('saveVpnOtpBinding',{'profileId':guarded,'editToken':view['editToken'],'otpId':otp['id'],'otpRevision':otp['revision']})
        before=state();auth=auth_events();begin([guarded]);result=done()
        check(result['entries'][0]['status']=='ok' and result['entries'][0]['error'] is None
              and command('otpGet',{'id':otp['id']})['counter']=='19' and state()==before and auth_events()==auth and processes()==main_processes,
              'a bound live profile without a code template is measured through the real tunnel and its HOTP counter19 remains exact')
        for source,expected in [('openvpn','ok'),('openvpnRejected','auth-required')]:
            full=add('Full client VPN probe '+source,{
                'inbounds':[], 'outbounds':[{'type':'direct','tag':'direct'}],
                'endpoints':[{**ready[source],'tag':'client-vpn'}], 'route':{'final':'client-vpn'}
            },'sing-box-config')
            before=state();begin([full]);result=done();clean(main_processes)
            check(result['entries'][0]['status']==expected and state()==before and echo()
                  and processes()==main_processes and safe(snap()),
                  'a full client preserves its VPN endpoint and routes, reports '+expected+' and leaves the main connection intact')
        for label,configuration,kind,error in [
                ('placeholder',{**ready['openvpn'],'password':'{otp}'},'sing-box-outbound','probe_vpn_otp_binding_required'),
                ('provider',{**ready['openconnectForm'],'flavor':'fortinet'},'sing-box-outbound','probe_vpn_auth_unsupported'),
                ('system',{**ready['openvpn'],'system':True},'sing-box-outbound','probe_vpn_context_unsupported'),
                # A client's own listeners are replaced by the check, so what stays refused is
                # what the disposable core cannot own itself, such as an unowned rule-set file.
                ('full JSON with an external rule-set',{'outbounds':[{'type':'direct','tag':'direct'}],
                                          'route':{'rule_set':[{'type':'remote','tag':'unowned','format':'binary','url':'https://unowned.test/file.srs'}]}},
                 'sing-box-config','probe_full_config_unsupported')]:
            id=add('Unsupported probe '+label,configuration,kind);before=state();counts=events();begin([id]);result=done()
            check(result['entries'][0]['status']=='unsupported' and result['entries'][0]['error']==error and result['entries'][0]['latencyMs'] is None
                  and state()==before and events()==counts and processes()==main_processes,
                  'unsupported '+label+' configuration cannot be silently normalized or executed for a VPN HTTP test')
        release('reset-holds');count=events()['http-held'];before_processes=processes();begin([good,connected],ready['holdUrl'],5000)
        until(lambda:events()['http-held']>count);probe_processes=record_processes('held-probe')
        check(len(probe_processes)==len(before_processes)+1 and all(p in probe_processes for p in before_processes),
              'a held HTTP test owns a distinct disposable child alongside the unchanged main Core')
        before=state();wait_for('return !!document.querySelector("#probe-cancel")');click('#probe-cancel');result=done();clean(before_processes)
        record_processes('after-cancel-reap')
        audit['remotePeerEofAfterCancel']=events()['http-held-peer-closed']>0
        check(all(e['status']=='cancelled' for e in result['entries']) and state()==before and echo(),
              'native Cancel reaps only the owned disposable child, preserves main CONNECT and cancels remaining profiles')
        release('release-holds');time.sleep(.2)
        check(all(e['status']=='cancelled' for e in snap()['urlTests']['entries']) and processes()==before_processes,
              'late fixture release cannot publish cancelled results or start the remaining queued VPN')
        release('reset-holds');count=events()['http-held'];begin([good],ready['holdUrl'],5000);until(lambda:events()['http-held']>count)
        profile=command('profile',{'id':good});profile['vpnPolicy']={**POLICY,'blockOutsideDns':True};command('saveProfile',profile)
        release('release-holds');result=done();clean(main_processes)
        check(result['entries'][0]['status']=='stale' and row(good) is None and echo(),
              'changing policy while real HTTP is held invalidates the old measured result without disturbing the main socket')
        profile=command('profile',{'id':good});profile['vpnPolicy']=POLICY;command('saveProfile',profile)
        release('reset-holds');count=events()['http-held'];begin([good],ready['holdUrl'],5000);until(lambda:events()['http-held']>count)
        profile=command('profile',{'id':good});profile['name']='Renamed during measured HTTP';command('saveProfile',profile);command('select',{'id':connected})
        release('release-holds');result=done();clean(main_processes)
        check(result['entries'][0]['status']=='ok' and snap()['selected']==connected and echo(),
              'name-only edits and a different selected ID preserve the captured VPN request and valid measurement')

        held.close();held=None;command('disconnect');until(lambda:snap()['running'] is None)
        previous=fresh_settings();command('connectionSettings',{'mode':'system-proxy','port':port});command('connect',{'id':direct});held=open_held()
        until(lambda:snap()['systemProxy']['active']);applied=proxy_state();assert applied['leased']
        expected={('', 'mode'):'manual',('', 'use-same-proxy'):False,('http','enabled'):True,('http','use-authentication'):False}
        for suffix in ['http','https','socks','ftp']:expected[(suffix,'host')]='127.0.0.1';expected[(suffix,'port')]=port
        observed={(a,b):(c,d) for a,b,c,d in applied['values']}
        assert all(observed[key]==(value,value) for key,value in expected.items())
        before=state();proxy_processes=processes();start=snap()['since'];begin([good]);result=done();clean(proxy_processes)
        check(result['entries'][0]['status']=='ok' and proxy_state()==applied and state()==before and echo() and snap()['since']==start,
              'real VPN HTTP test preserves private GNOME values, exact journal/keyfile/lease and the main system-proxy CONNECT')
        held.close();held=None;command('disconnect')
        check(fresh_settings()==previous and not journal.exists() and not lease(),
              'Disconnect restores the exact private GNOME effective/user baseline and releases only its own journal')
        check(safe(snap()) and command('otpGet',{'id':otp['id']})['counter']=='19',
              'probe snapshots retain only safe finite outcomes and never consume the unrelated bound HOTP')
        audit['passed']=True
    finally:
        with contextlib.suppress(Exception):release('release-holds')
        if held:held.close()
        with contextlib.suppress(Exception):
            command('cancelUrlTests');command('disconnect');command('clearUrlTests')
            if not audit.get('passed'):h['screenshot']('vpn-probes-failure-before-cleanup')
        try:
            command('saveRouting',{**command('routing'),'active':initial_routing['active'],'profiles':initial_routing['profiles']})
            command('deleteGroup',{'id':group,'deleteProfiles':True})
            if otp:command('otpRemove',{'id':otp['id'],'revision':command('otpGet',{'id':otp['id']})['revision']})
            command('preferences',initial['preferences'])
            h['request']('POST',h['base']+'/window/rect',geometry)
            audit['libraryCleanupCompleted']=True
        except Exception as error:
            audit['libraryCleanupCompleted']=False
            audit['cleanupErrorType']=type(error).__name__
            if audit.get('passed'):raise
        finally:
            (Path(h['args'].artifacts)/'vpn-probes-audit.json').write_text(json.dumps(audit,ensure_ascii=False,indent=2)+'\n')
            origin.shutdown();origin.server_close()
