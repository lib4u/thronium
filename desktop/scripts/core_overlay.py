"""Apply a minimal dependency patch in a private copy of the pinned module.

The shared Go module cache is never modified. Other inbound tags retain the
upstream nftables table name; the supervisor owns only its private table.
"""
import hashlib
import pathlib
import shutil
import subprocess
from fragment_overlay import prepare as prepare_fragment
from wireguard_overlay import prepare as prepare_wireguard
from awg_overlay import prepare as prepare_awg
from dashboard_overlay import prepare as prepare_dashboard
from speedtest_overlay import prepare as prepare_speedtest
from openvpn_overlay import prepare as prepare_openvpn

def openconnect_cancel_terminal(content: str) -> str:
    # A user-canceled form is a terminal decision. The pinned supervisor omits
    # this sentinel and otherwise restarts authentication after its backoff.
    old = '\t\tErrAuthenticationFailed,\n'
    if (content.count('func classifyClientSessionError(err error) clientSessionErrorClass {') != 1 or
        content.count(old) != 1 or 'ErrAuthChallengeCanceled' in content):
        raise RuntimeError('Pinned OpenConnect authentication changed; review cancellation classification')
    return content.replace(old, old + '\t\tErrAuthChallengeCanceled,\n')

def network_started_atomic(content: str) -> str:
    # Actual -race Start/Stop tests found updateInterface reading this flag while
    # Start publishes it. Pin every access so a dependency update cannot receive
    # only half of the synchronization fix.
    replacements = [
        ('"sync"', '"sync"\n\t"sync/atomic"'),
        ('started                  bool', 'started                  atomic.Bool'),
        ('r.started = true', 'r.started.Store(true)'),
        ('if !r.started {', 'if !r.started.Load() {'),
    ]
    if content.count('r.started') != 2:
        raise RuntimeError('Pinned network lifecycle changed; review started synchronization')
    for old, new in replacements:
        if content.count(old) != 1:
            raise RuntimeError('Pinned network lifecycle changed; review started synchronization')
        content = content.replace(old, new)
    return content

def prepare(core: pathlib.Path, cache: pathlib.Path, env: dict):
    source_dir=pathlib.Path(subprocess.check_output(['go','list','-m','-f','{{.Dir}}','github.com/sagernet/sing-box'],cwd=core,env=env,text=True).strip())
    source=source_dir/'protocol/tun/inbound.go'; text=source.read_text()
    original='TableName:              "sing-box",'
    replacement='TableName:              func() string { if tag == "thronium-tun" { return "thronium-auto-redirect" }; return "sing-box" }(),'
    if text.count(original)!=1:
        raise RuntimeError('Pinned TUN dependency changed; review the firewall patch before building')
    directory=cache/'core-overlay';directory.mkdir(parents=True,exist_ok=True)
    module=directory/source_dir.name
    if not module.exists():shutil.copytree(source_dir,module)
    target=module/'protocol/tun/inbound.go';target.chmod(0o644);target.write_text(text.replace(original,replacement))
    modfile=directory/'go.mod';modfile.write_bytes((core/'go.mod').read_bytes());(directory/'go.sum').write_bytes((core/'go.sum').read_bytes())
    tun_source=pathlib.Path(subprocess.check_output(['go','list','-m','-f','{{.Dir}}','github.com/sagernet/sing-tun'],cwd=core,env=env,text=True).strip())
    tun_module=directory/tun_source.name
    if not tun_module.exists():shutil.copytree(tun_source,tun_module)
    route_text=(tun_source/'redirect_route_linux.go').read_text()
    patches=[
      ('r.redirectRouteTableIndex = int(rand.Uint32())','r.redirectRouteTableIndex = int(rand.Uint32())\n        if r.tableName == "thronium-auto-redirect" { r.redirectRouteTableIndex = r.tunOptions.IPRoute2TableIndex + 3 }'),
      ('if len(routeList) == 0 || fErr != nil {','if r.tableName == "thronium-auto-redirect" && (fErr != nil || len(routeList) > 0) { return E.New("managed redirect table occupied") }\n        if len(routeList) == 0 || fErr != nil {'),
      ('for _, route := range routes {','for _, route := range routes {\n        if r.tableName == "thronium-auto-redirect" && route.Protocol != 253 { continue }'),
      ('route := &routesToDelete[index]','route := &routesToDelete[index]\n        if r.tableName == "thronium-auto-redirect" && route.Protocol != 253 { continue }'),
      ('route := &routesToAdd[index]','route := &routesToAdd[index]\n        if r.tableName == "thronium-auto-redirect" { route.Protocol = 253 }'),
    ]
    for old,new in patches:
        if route_text.count(old)!=1:raise RuntimeError('Pinned redirect routes changed; review the managed cleanup patch')
        route_text=route_text.replace(old,new)
    route_target=tun_module/'redirect_route_linux.go';route_target.chmod(0o644);route_target.write_text(route_text)
    # The supervisor alone removes its reserved table. Do not modify Docker or
    # OpenWRT tables, whose recovery belongs to those services.
    bridge_patches={
      'protocol/bridge/backend.go': [('b.inet6Port = addressAt(bridgeInet6Base, index)', 'b.inet6Port = addressAt(bridgeInet6Base, index)\n if tag == "settings-l3-direct" { b.inet4Port=netip.MustParseAddr("198.19.255.2"); b.inet6Port=netip.MustParseAddr("fdfe:dcba:9877::2") }')],
      'protocol/bridge/backend_linux.go': [('b.tunName = tun.CalculateInterfaceName(b.bridgeName)', 'b.tunName = tun.CalculateInterfaceName(b.bridgeName)\n if b.tag == "settings-l3-direct" { b.tunName="thronium-br0" }'), ('func (b *backendLinux) WritePackets(packets [][]byte) error {','func (b *backendLinux) WritePackets(packets [][]byte) error {\n if b.tag == "settings-l3-direct" { for _,packet:=range packets { fixReturnChecksum(packet) } }')],
      'protocol/bridge/netfilter_linux.go': [
        ('func cleanupBridgeNftables(tableName string) {','func cleanupBridgeNftables(tableName string) {\n if tableName == "sing-box-thronium-br0" { return }'),
        ('func enableBridgeForwarding(logger logger.ContextLogger, tunName string, inet4 bool, inet6 bool) []sysctlState {', 'func enableBridgeForwarding(logger logger.ContextLogger, tunName string, inet4 bool, inet6 bool) []sysctlState {\n if tunName == "thronium-br0" { _ = os.WriteFile("/proc/sys/net/ipv4/conf/"+tunName+"/forwarding",[]byte("1"),0644); _ = os.WriteFile("/proc/sys/net/ipv6/conf/"+tunName+"/forwarding",[]byte("1"),0644); _ = os.WriteFile("/proc/sys/net/ipv4/conf/"+tunName+"/rp_filter",[]byte("2"),0644); return nil }'),
      ],
    }
    bridge_files=[]
    for filename,replacements in bridge_patches.items():
        content=(source_dir/filename).read_text()
        for old,new in replacements:
            if content.count(old)!=1:raise RuntimeError('Pinned bridge lifecycle changed; review managed ownership patch')
            content=content.replace(old,new)
        dest=module/filename;dest.chmod(0o644);dest.write_text(content);bridge_files.append(dest)
    more_patches={
      'redirect_nftables.go': [('r.stopDockerFirewallMonitor()', 'r.stopDockerFirewallMonitor()\n    if r.tableName == "thronium-auto-redirect" { return }')],
      'redirect_nftables_rules_openwrt.go': [('func (r *autoRedirect) configureOpenWRTFirewall4(nft *nftables.Conn, cleanup bool) error {', 'func (r *autoRedirect) configureOpenWRTFirewall4(nft *nftables.Conn, cleanup bool) error {\n    if r.tableName == "thronium-auto-redirect" { return nil }')],
      'redirect_nftables_docker.go': [('func (r *autoRedirect) configureDockerFirewall(cleanup bool) error {', 'func (r *autoRedirect) configureDockerFirewall(cleanup bool) error {\n    if r.tableName == "thronium-auto-redirect" { return nil }')],
    }
    network_target=module/'route/network.go'
    network_target.chmod(0o644)
    network_target.write_text(network_started_atomic((source_dir/'route/network.go').read_text()))
    auth_source=pathlib.Path(subprocess.check_output(['go','list','-m','-f','{{.Dir}}','github.com/sagernet/sing-openconnect'],cwd=core,env=env,text=True).strip())
    auth_module=directory/auth_source.name
    if not auth_module.exists():shutil.copytree(auth_source,auth_module)
    auth_target=auth_module/'client_supervisor.go'
    auth_target.chmod(0o644)
    auth_target.write_text(openconnect_cancel_terminal((auth_source/'client_supervisor.go').read_text()))
    patch_files=[target,route_target,network_target,auth_target]+bridge_files
    patch_files += prepare_dashboard(source_dir, module)
    patch_files += prepare_fragment(source_dir, module)
    patch_files += prepare_wireguard(source_dir, module)
    patch_files += prepare_awg(core, directory, modfile, env)
    patch_files += prepare_speedtest(core, directory, modfile, env)
    patch_files += prepare_openvpn(core, directory, modfile, env, source_dir, module)
    for filename,replacements in more_patches.items():
        content=(tun_source/filename).read_text()
        for old,new in replacements:
            if content.count(old)!=1:raise RuntimeError('Pinned firewall lifecycle changed; review managed ownership patch')
            content=content.replace(old,new)
        dest=tun_module/filename;dest.chmod(0o644);dest.write_text(content);patch_files.append(dest)
    subprocess.run(['go','mod','edit','-modfile',str(modfile),'-replace=github.com/sagernet/sing-tun='+str(tun_module)],cwd=core,env=env,check=True)
    subprocess.run(['go','mod','edit' ,'-modfile',str(modfile),'-replace=github.com/sagernet/sing-box='+str(module)],cwd=core,env=env,check=True)
    subprocess.run(['go','mod','edit','-modfile',str(modfile),'-replace=github.com/sagernet/sing-openconnect='+str(auth_module)],cwd=core,env=env,check=True)
    return modfile,hashlib.sha256(b''.join(p.read_bytes() for p in patch_files)).hexdigest()
