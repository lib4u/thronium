#!/usr/bin/env python3
"""Actual managed authentication in private user/network/mount namespaces only."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

DESKTOP = Path(__file__).resolve().parents[1]
REPOSITORY = DESKTOP.parent

def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def inside(root, out):
    assert os.geteuid() == 0
    for kind in ['net', 'mnt', 'user']:
        assert os.readlink('/proc/self/ns/' + kind) != os.environ['THRONIUM_HOST_' + kind.upper()]
    # statfs resolves the effective top mount; findmnt /run lists both stacked
    # tmpfs mounts and therefore does not produce a single filesystem name.
    assert subprocess.check_output(['stat', '-f', '-c', '%T', '/run'], text=True).strip() == 'tmpfs'
    spec = importlib.util.spec_from_file_location('managed_auth_fixture', root / 'vpn_auth_fixture.py')
    fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
    field, parse = fixture.field, fixture.parse
    value = lambda obj, key, default=b'': obj.get(key, [default])[0]
    text = lambda obj, key: value(obj, key).decode()
    def ip(*args):
        return subprocess.check_output(['ip', *map(str, args)], text=True)
    ip('link', 'set', 'lo', 'up')
    ip('link', 'add', 'auth-physical', 'type', 'dummy')
    ip('address', 'add', '198.18.0.1/24', 'dev', 'auth-physical')
    ip('link', 'set', 'auth-physical', 'up')
    ip('route', 'add', 'default', 'via', '198.18.0.254', 'dev', 'auth-physical')
    ip('rule', 'add', 'priority', '18912', 'to', '203.0.113.0/24', 'table', 'main')
    def rules(): return json.loads(ip('-j', 'rule'))
    def tun():
        try: return socket.if_nametoindex('thronium-tun') > 0
        except OSError: return False
    baseline_rules = rules(); baseline_routes = json.loads(ip('-j', 'route', 'show', 'table', 'all'))
    checks = []
    def mark(name):
        checks.append(name); print('PASS ' + name, flush=True)
    def settle(predicate, message, seconds=10):
        deadline=time.monotonic()+seconds
        while time.monotonic()<deadline:
            result=predicate()
            if result: return result
            time.sleep(.03)
        raise AssertionError(message)
    def children(pid):
        output=set()
        for path in Path(f'/proc/{pid}/task').glob('*/children'):
            try: output.update(map(int,path.read_text().split()))
            except FileNotFoundError: pass
        return sorted(output)
    def identity(pid):
        raw=Path(f'/proc/{pid}/stat').read_text();rest=raw[raw.rindex(')')+1:].split()
        return {'pid':pid,'ppid':int(rest[1]),'start':int(rest[19]),'netns':os.readlink(f'/proc/{pid}/ns/net'),'exe':os.readlink(f'/proc/{pid}/exe')}

    class Managed:
        def __init__(self):
            self.listener=socket.socket(socket.AF_UNIX);self.listener.bind(str(root/'managed.sock'));self.listener.listen();self.listener.settimeout(10)
            self.log=(out/'supervisor.log').open('w')
            self.process=subprocess.Popen([str(root/'ThroniumCore'),'--thronium-tun-supervisor',str(root/'managed.sock'),str(root)],stdin=subprocess.DEVNULL,stdout=self.log,stderr=self.log)
            self.socket,_=self.listener.accept();self.socket.settimeout(8)
            pid,uid,_=struct.unpack('3i',self.socket.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12));assert pid==self.process.pid and uid==0
            self.sequence=0
        def read(self,n):
            result=b''
            while len(result)<n:
                part=self.socket.recv(n-len(result));assert part,'supervisor EOF';result+=part
            return result
        def raw(self,method,payload=b''):
            self.sequence+=1;name=method.encode();self.socket.sendall(struct.pack('<IH',self.sequence,len(name))+name+struct.pack('<I',len(payload))+payload)
            identity,status,n=struct.unpack('<IBI',self.read(9));assert identity==self.sequence and n<=16*1024*1024
            return status,self.read(n)
        def call(self,method,payload=b''):
            status,body=self.raw(method,payload);assert status==0,'unexpected supervisor protocol error';return parse(body)
        def status(self): return self.call('ManagedTunStatus')
        def auth(self,generation,operation,payload):
            response=self.call('ManagedVPN',field(1,1)+field(2,generation)+field(operation,payload))
            assert value(response,1,0)==1
            return response
        def query(self,generation,tags):
            response=self.auth(generation,3,b''.join(field(1,tag) for tag in tags)+field(2,0))
            assert not text(response,3),text(response,3)
            assert value(response,2,0)==generation and 4 in response and 5 not in response
            return {text(row,1):row for row in map(parse,parse(value(response,4)).get(1,[]))}
        def wait(self,generation,tag,state,old_id=None):
            def probe():
                row=self.query(generation,[tag])[tag];challenge=parse(value(row,16)) if 16 in row else None
                if text(row,2)==state and (old_id is None or challenge and text(challenge,2)!=old_id):return row,challenge
            return settle(probe,'endpoint '+tag+' did not reach '+state,12)
        def action(self,generation,tag,challenge,cancel=False,form=False,ovpn=False):
            payload=field(1,tag)+field(2,text(challenge,2))
            if form:
                answers={'username':fixture.FORM_USER,'password':fixture.FORM_PASSWORD,'realm':'two','answer':fixture.FORM_ANSWER}
                for encoded in challenge[11]:
                    item=parse(encoded);payload+=field(6,field(1,text(item,1))+field(2,answers[text(item,2)]))
            if ovpn:payload+=field(3,fixture.USER)+field(4,fixture.PASSWORD)+field(5,fixture.ANSWER)
            response=self.auth(generation,5 if cancel else 4,payload)
            assert not text(response,3),text(response,3)
            assert value(response,2,0)==generation and 5 in response and 4 not in response
            assert not text(parse(value(response,5)),1),'worker action refused'
        def stop(self):assert not text(self.call('Stop'),1)
        def close(self):
            self.socket.close();self.listener.close();assert self.process.wait(timeout=10)==0;self.log.close()

    fixture_log=(out/'fixture-stderr.log').open('w')
    server=subprocess.Popen([str(root/'Thronium'),str(root/'vpn_auth_fixture.py'),str(root)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=fixture_log,text=True)
    rpc=None
    try:
        assert select.select([server.stdout],[],[],15)[0];line=server.stdout.readline();assert line,'fixture did not start';ready=json.loads(line)
        def events(path):
            return [row for row in map(json.loads,Path(ready['events']).read_text().splitlines()) if row['path']=='/form/'+path] if Path(ready['events']).exists() else []
        def oc(tag,path):return {'type':'openconnect','tag':tag,'server':f"https://127.0.0.1:{ready['openconnectPort']}/form/{path}",'flavor':'anyconnect','system':False,'no_udp':True,'tls':{'certificate_authority_path':ready['certificate']}}
        ovpn={'type':'openvpn-client','tag':'openvpn','server':'127.0.0.1','server_port':ready['openvpnPort'],'network':'udp','system':False,'static_challenge':'Synthetic answer','tls':{'certificate_path':ready['certificate'],'server_name':ready['serverName']}}
        with socket.socket() as reservation:reservation.bind(('127.0.0.1',0));port=reservation.getsockname()[1]
        def configuration(endpoints):
            return {'log':{'disabled':True},'endpoints':endpoints,'inbounds':[
                {'type':'tun','tag':'thronium-tun','interface_name':'thronium-tun','address':['172.19.0.1/30'],'mtu':1500,'stack':'gvisor','auto_route':True,'strict_route':False,'dns_mode':'disabled','iproute2_rule_index':18900,'route_exclude_address':['127.0.0.0/8']},
                {'type':'mixed','tag':'control-in','listen':'127.0.0.1','listen_port':port}],
                'outbounds':[{'type':'direct','tag':'control','udp_fragment':True}],'route':{'final':'control'}}
        def start(endpoints):
            config=configuration(endpoints);payload=field(1,json.dumps(config))+field(2,1)+field(9,0)
            assert not text(rpc.call('CheckConfig',payload),1),'actual Check refused'
            assert not text(rpc.call('Start',payload),1),'actual Start refused'
            status=rpc.status();assert text(status,1)=='connected' and value(status,5,0)==1
            assert tun();return value(status,3,0)
        def journal():
            paths=list(Path('/run/thronium-tun').glob('*.json'));assert len(paths)==1
            path=paths[0];return path,path.read_bytes(),path.stat().st_mtime_ns
        def same_journal(before):
            path,raw,mtime=before;assert path.read_bytes()==raw and path.stat().st_mtime_ns==mtime,'auth changed journal'
        def held():
            origin=socket.socket();origin.bind(('127.0.0.1',0));origin.listen();destination=origin.getsockname()[1]
            def echo():
                conn,_=origin.accept()
                with conn:
                    while True:
                        part=conn.recv(256)
                        if not part:break
                        conn.sendall(part)
                origin.close()
            thread=threading.Thread(target=echo,daemon=True);thread.start()
            conn=socket.create_connection(('127.0.0.1',port),timeout=3);conn.settimeout(3)
            conn.sendall(f'CONNECT 127.0.0.1:{destination} HTTP/1.1\r\nHost: 127.0.0.1:{destination}\r\n\r\n'.encode());head=b''
            while not head.endswith(b'\r\n\r\n'):head+=conn.recv(1);assert len(head)<4096
            assert head.startswith(b'HTTP/1.1 200');return conn,thread
        def exchange(conn,label):
            payload=label.encode();conn.sendall(payload);actual=b''
            while len(actual)<len(payload):actual+=conn.recv(len(payload)-len(actual))
            assert actual==payload
        rpc=Managed();guardian=rpc.process.pid
        status=rpc.status();assert text(status,1)=='idle' and value(status,5,0)==1 and value(status,3,0)==0
        assert children(guardian)==[]
        rejected=rpc.auth(0,3,field(1,'alpha'));assert text(rejected,3)=='managed_vpn_invalid_request' and children(guardian)==[]
        mark('capability1 and idle guarded query never spawns worker')
        assert not text(rpc.call('ManagedTunReady',field(1,1)),1)
        generation=start([oc('alpha','managed-alpha'),ovpn]);assert generation==1
        worker=children(guardian);assert len(worker)==1;worker1=identity(worker[0])
        assert worker1['ppid']==guardian and worker1['netns']==os.readlink('/proc/self/ns/net') and worker1['exe']==str(root/'ThroniumCore')
        saved=journal();initial_effective=rpc.raw('ManagedTunConfiguration')[1]
        initial=rpc.wait(generation,'alpha','auth-pending')[1];assert text(initial,2)=='1'
        pending_vpn=rpc.wait(generation,'openvpn','auth-pending')[1];assert text(pending_vpn,3)=='credentials'
        mark('real managed TUN created with userspace OpenConnect form and OpenVPN credentials')
        for method in ['QueryVPNStatus','SubmitVPNChallenge','CancelVPNChallenge']:
            status,body=rpc.raw(method);assert status==1 and body==b'unsupported managed method'
        assert identity(worker1['pid'])==worker1;same_journal(saved)
        mark('unguarded VPN RPC names refused without worker or journal mutation')
        connection,thread=held();exchange(connection,'before-form')
        rpc.action(generation,'openvpn',pending_vpn,ovpn=True);rpc.wait(generation,'openvpn','connected')
        mark('real managed OpenVPN TLS authentication reaches connected')
        rpc.action(generation,'alpha',initial,form=True);otp=rpc.wait(generation,'alpha','auth-pending',text(initial,2))[1]
        assert any(row['formExact'] for row in events('managed-alpha'))
        rpc.action(generation,'alpha',otp,form=True);pending=rpc.wait(generation,'alpha','auth-pending',text(otp,2))[1]
        assert any(row['otpExact'] for row in events('managed-alpha'))
        same_journal(saved);assert rpc.raw('ManagedTunConfiguration')[1]==initial_effective
        for secret in [fixture.PASSWORD,fixture.ANSWER,fixture.FORM_USER,fixture.FORM_PASSWORD,fixture.FORM_ANSWER]:assert secret.encode() not in saved[1] and secret.encode() not in initial_effective
        exchange(connection,'after-otp');connection.close();thread.join(timeout=3);assert not thread.is_alive()
        mark('exact form and OTP wire values accepted while held CONNECT and private Start bytes remain unchanged')
        # Capture a successful Query, then replace only the authenticated owned worker.
        rpc.query(generation,['alpha']);fd=os.pidfd_open(worker1['pid']);assert identity(worker1['pid'])==worker1
        signal.pidfd_send_signal(fd,signal.SIGKILL);os.close(fd)
        def replaced():
            state=rpc.status()
            return state if text(state,1)=='connected' and value(state,3,0)>generation else None
        state=settle(replaced,'managed worker failed to recover',12);next_generation=value(state,3,0);assert next_generation==2 and rpc.process.pid==guardian
        replacement=children(guardian);assert len(replacement)==1;worker2=identity(replacement[0]);assert worker2['pid']!=worker1['pid'] and worker2['ppid']==guardian
        fresh=rpc.wait(next_generation,'alpha','auth-pending')[1];assert text(fresh,2)=='1'
        initial_count=len(events('managed-alpha'))
        for operation in [3,4,5]:
            payload=field(1,'alpha') if operation==3 else field(1,'alpha')+field(2,text(fresh,2))
            if operation==4:payload+=field(5,'old-answer-never-forward')
            response=rpc.auth(generation,operation,payload);assert text(response,3)=='managed_vpn_stale_generation' and value(response,2,0)==next_generation and 4 not in response and 5 not in response
        assert len(events('managed-alpha'))==initial_count and text(rpc.wait(next_generation,'alpha','auth-pending')[1],2)=='1'
        mark('same guardian real worker replacement repeats OpenConnect ID1; old generation Query Submit Cancel cannot reach it')
        connection,thread=held();exchange(connection,'restored-connection')
        pending_vpn=rpc.wait(next_generation,'openvpn','auth-pending')[1]
        saved=journal();rpc.action(next_generation,'alpha',fresh,cancel=True);rpc.wait(next_generation,'alpha','error')
        count=len(events('managed-alpha'));until=time.monotonic()+2.2;polls=0
        while time.monotonic()<until:
            states=rpc.query(next_generation,['alpha','openvpn']);assert text(states['alpha'],2)=='error' and not value(states['alpha'],17,0) and 16 not in states['alpha'];assert text(states['openvpn'],2)=='auth-pending';assert len(events('managed-alpha'))==count;polls+=1;time.sleep(.07)
        rpc.action(next_generation,'openvpn',pending_vpn,ovpn=True);rpc.wait(next_generation,'openvpn','connected')
        exchange(connection,'after-terminal-cancel');same_journal(saved);connection.close();thread.join(timeout=3);assert not thread.is_alive()
        mark('terminal OpenConnect Cancel quiet2200ms; independent OpenVPN authenticates and same CONNECT survives')
        # Add a genuinely adjacent foreign rule during the active session, even
        # inside the reserved range. Exact cleanup must preserve it on Stop.
        ip('rule','add','priority','18905','to','192.0.2.0/24','table','main')
        expected_foreign=[row for row in rules() if row.get('priority') in [18905,18912]]
        rpc.stop();settle(lambda:not tun(),'TUN survived Stop');assert children(guardian)==[]
        assert [row for row in rules() if row.get('priority') in [18905,18912]]==expected_foreign
        assert not list(Path('/run/thronium-tun').glob('*.json'))
        assert text(rpc.auth(next_generation,3,field(1,'alpha')),3)=='managed_vpn_unavailable' and children(guardian)==[]
        time.sleep(1.2);assert children(guardian)==[] and len(events('managed-alpha'))==count
        mark('Stop removes owned TUN worker journal and retries while preserving both adjacent foreign rules')
        ip('rule','del','priority','18905','to','192.0.2.0/24','table','main')
        assert rules()==baseline_rules
        # A fresh explicit session proves GUI EOF cleanup independently of Stop.
        final_generation=start([oc('alpha','managed-eof')]);assert final_generation==3
        rpc.wait(final_generation,'alpha','auth-pending');rpc.close();rpc=None
        settle(lambda:not tun(),'GUI EOF left TUN');assert not list(Path('/run/thronium-tun').glob('*.json')) and rules()==baseline_rules
        assert json.loads(ip('-j','route','show','table','all'))==baseline_routes
        mark('GUI EOF reaps only owned worker and clears TUN journal without changing baseline routes')
        summary={'passed':True,'checks':checks,'count':len(checks),'coreSha256':digest(root/'ThroniumCore'),'generations':[generation,next_generation,final_generation],'workers':[worker1,worker2],'guardedStaleRefusals':3,'terminalCancelPolls':polls,'terminalCancelQuietMs':2200,'openvpnActualConnections':2,'openconnectExactForm':True,'openconnectExactOtp':True,'heldConnectExchanges':4,'privateNamespace':True,'foreignRulesPreserved':True,'journalUnchangedByAuth':True,'guiEofCleanup':True}
        (out/'namespace-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    finally:
        if rpc is not None:
            try:rpc.stop()
            finally:rpc.close()
        server.stdin.close();assert server.wait(timeout=10)==0;fixture_log.close()
        for name in ['events.jsonl','server-core.log']:
            if (root/name).exists():shutil.copy2(root/name,out/('fixture-'+name))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core',type=Path);parser.add_argument('--core-sha256');parser.add_argument('--artifacts',type=Path)
    parser.add_argument('--inside',type=Path);args=parser.parse_args()
    if args.inside:
        inside(args.inside.resolve(),args.artifacts.resolve());return
    core=args.core.resolve();out=args.artifacts.resolve();assert digest(core)==args.core_sha256;out.mkdir(parents=True,exist_ok=False)
    source_paths=[Path(__file__),DESKTOP/'tests/vpn_auth_fixture.py']
    sources={str(path.relative_to(REPOSITORY)):digest(path) for path in source_paths}
    for path in source_paths:shutil.copy2(path,out/path.name)
    (out/'source-before.json').write_text(json.dumps(sources,indent=2)+'\n')
    host={name:Path('/proc/net/'+name).read_bytes() for name in ['route','ipv6_route']};host_dns=digest('/etc/resolv.conf')
    with tempfile.TemporaryDirectory(prefix='thronium-managed-auth-run-') as temporary:
        root=Path(temporary);shutil.copy2(Path(sys.executable).resolve(),root/'Thronium');shutil.copy2(core,root/'ThroniumCore');shutil.copy2(DESKTOP/'tests/vpn_auth_fixture.py',root/'vpn_auth_fixture.py')
        environment={**os.environ,**{'THRONIUM_HOST_'+kind.upper():os.readlink('/proc/self/ns/'+kind) for kind in ['net','mnt','user']},'DBUS_SYSTEM_BUS_ADDRESS':'unix:path='+str(root/'no-system'),'DBUS_SESSION_BUS_ADDRESS':'unix:path='+str(root/'no-session'),'PYTHONHOME':sys.prefix}
        for key in ['HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy']:environment.pop(key,None)
        command=['unshare','--user','--map-root-user','--net','--mount','sh','-c','mount --make-rprivate / && mount -t tmpfs -o mode=700 tmpfs /run && exec "$@"','sh',str(root/'Thronium'),str(Path(__file__).resolve()),'--inside',str(root),'--artifacts',str(out)]
        (out/'command.json').write_text(json.dumps({'command':command,'coreSha256':digest(core)},indent=2)+'\n')
        with (out/'run.log').open('w') as log:
            result=subprocess.run(command,env=environment,stdout=log,stderr=subprocess.STDOUT,timeout=90)
        unchanged=all(Path('/proc/net/'+name).read_bytes()==data for name,data in host.items()) and digest('/etc/resolv.conf')==host_dns
        status={'passed':result.returncode==0 and unchanged,'exitCode':result.returncode,'hostRoutesAndResolvConfUnchanged':unchanged,'coreSha256':digest(core),'sourceChanges':{name:digest(REPOSITORY/name) for name,sha in sources.items() if digest(REPOSITORY/name)!=sha}}
        (out/'summary.json').write_text(json.dumps(status,indent=2)+'\n');print((out/'run.log').read_text());result.check_returncode();assert status['passed'] and not status['sourceChanges'];print(json.dumps(status,indent=2))

if __name__=='__main__':main()
