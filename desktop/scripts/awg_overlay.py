"""Guarded AWG startup/batch fix in a private copy of the pinned WireGuard fork."""
import hashlib
from pathlib import Path
import shutil
import subprocess

PINNED = {'device/send.go':'92edf4d09773b1aa8626b765764d5ef7279a391487b6245b5361c2da16f5e950',
          'conn/bind_std.go':'8329ee757f93cb031648912bfca27fdc60dde3a6c99ed2acc40aa7caa12ee797'}

def prepare(core, directory, modfile, env):
    source=Path(subprocess.check_output(['go','list','-m','-f','{{.Dir}}','github.com/sagernet/wireguard-go'],cwd=core,env=env,text=True).strip())
    texts={}
    for rel,digest in PINNED.items():
        data=(source/rel).read_bytes()
        if hashlib.sha256(data).hexdigest()!=digest:raise RuntimeError('Pinned AWG send code changed; review startup/batch fix')
        texts[rel]=data.decode()
    module=directory/source.name
    if not module.exists():shutil.copytree(source,module)
    text=texts['device/send.go']
    old='''			elem := elems[i]
			elem.packet = bufs[i][offset : offset+sizes[i]]
			elem.padding = padding
'''
    assert text.count(old)==1
    text=text.replace(old,'''			elem := elems[i]
            // Read may have blocked before the initial AWG IpcSet. Relayout
            // its payload using current S4, retaining room for the AEAD tag.
            if !prepareTUNOutbound(elem, offset, sizes[i], device.paddings.transport.Load()) {
                continue
            }
''')
    old='''	peer.timersAnyAuthenticatedPacketTraversal()
	peer.timersAnyAuthenticatedPacketSent()

	err := peer.SendBuffers(scratch)
'''
    assert text.count(old)==1
    text=text.replace(old,'''	// A batch containing only dropped encryption results carries no
    // authenticated traffic. Release it without touching timers or the bind.
    if len(scratch) == 0 {
        peer.queuedOutboundPackets.Add(-int32(len(elemsContainer.elems)))
        for _, elem := range elemsContainer.elems {
            device.PutOutboundBuffer(elem.buffer)
            device.PutOutboundElement(elem)
        }
        return
    }
	peer.timersAnyAuthenticatedPacketTraversal()
	peer.timersAnyAuthenticatedPacketSent()

	err := peer.SendBuffers(scratch)
''')
    texts['device/send.go']=text
    text=texts['conn/bind_std.go'];needle='func (s *StdNetBind) Send(bufs [][]byte, endpoint Endpoint, offset int) error {';assert text.count(needle)==1
    text=text.replace(needle,needle+'\n    // WriteBatch/sendmmsg requires at least one message on Linux.\n    if len(bufs) == 0 { return nil }\n')
    needle='''\tif err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
\t\t// Some hosts have IPv6 disabled'''
    assert text.count(needle)==1
    text=text.replace(needle, '''    // A configured IPv6 port in use is not an unsupported IPv6 stack.
    // Preserve the failure and release the already opened IPv4 listener.
    if uport != 0 && errors.Is(err, syscall.EADDRINUSE) {
        if v4conn != nil { v4conn.Close() }
        return nil, 0, err
    }
''' + needle)
    texts['conn/bind_std.go']=text
    outputs=[]
    for rel,text in texts.items():
        target=module/rel;target.chmod(0o644);target.write_text(text);outputs.append(target)
    helper=module/'device/thronium_tun_layout.go';helper.parent.chmod(0o755)
    if helper.exists():helper.chmod(0o644)
    helper.write_bytes((Path(__file__).parent/'overlays/wireguard/awg_tun_layout.go').read_bytes());outputs.append(helper)
    subprocess.run(['go','mod','edit','-modfile',str(modfile),'-replace=github.com/sagernet/wireguard-go='+str(module)],cwd=core,env=env,check=True)
    return outputs
