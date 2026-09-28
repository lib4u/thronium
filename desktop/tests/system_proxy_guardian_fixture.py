"""Identify and signal only the guardian of this disposable WebDriver app."""
import contextlib
import json
import os
from pathlib import Path
import signal
import time
from external_core_fixture import identity


class Guardians:
    def __init__(self, application, config, output, journal_directory="thronium-system-proxy"):
        self.journal_directory=journal_directory
        self.app=Path(application).resolve();self.config=Path(config);self.output=Path(output)
        self.records=[];self.signals=[];self.events=[]
    def children(self, parent):
        children=set()
        for path in Path('/proc',str(parent),'task').glob('*/children'):
            with contextlib.suppress(OSError):children.update(map(int,path.read_text().split()))
        result=[]
        for pid in children:
            with contextlib.suppress(OSError,ValueError):
                p=Path('/proc',str(pid));args=p.joinpath('cmdline').read_bytes().split(b'\0')
                if len(args)<3 or args[1]!=b'--thronium-proxy-guardian':continue
                assert p.joinpath('exe').resolve()==self.app
                node=identity(pid);assert node['ppid']==parent
                assert b'XDG_CONFIG_HOME='+str(self.config).encode() in p.joinpath('environ').read_bytes().split(b'\0')
                assert int(args[2])>=3
                node['channelFd']=int(args[2]);result.append(node)
        return result
    def one(self,parent):
        result=self.children(parent);assert len(result)==1,result
        node=result[0]
        if not any(r['pid']==node['pid'] and r['starttime']==node['starttime'] for r in self.records):self.records.append(node)
        # The recovery process must not keep the parent's flock alive on crash.
        targets=[]
        for fd in Path('/proc',str(node['pid']),'fd').iterdir():
            with contextlib.suppress(OSError):targets.append(os.readlink(fd))
        assert str(self.config/self.journal_directory/'owner.lock') not in targets
        return node
    def send(self,node,signum):
        fd=os.pidfd_open(node['pid'])
        try:
            current=identity(node['pid']);assert current['starttime']==node['starttime']
            assert Path('/proc',str(node['pid']),'exe').resolve()==self.app
            signal.pidfd_send_signal(fd,signum,None,0)
            self.signals.append({'pid':node['pid'],'starttime':node['starttime'],'signal':signum,'monotonic':time.monotonic()})
        finally:os.close(fd)
    def gone(self,node):
        try:return identity(node['pid'])['starttime']!=node['starttime']
        except (OSError,ValueError):return True
    def finish(self):
        self.output.write_text(json.dumps({'guardians':self.records,'signals':self.signals,'events':self.events,'allGuardiansReaped':all(self.gone(n) for n in self.records)},indent=2)+'\n')
