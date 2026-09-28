"""Preserve local peer destinations when selecting the WG UDP interface."""
import hashlib
from pathlib import Path

ORIGINAL_ENDPOINT = 'fa65a21fa8a0738b8c45cdc7fbe65312fbdfc32530403d65ff0cacadebb1449d'
ORIGINAL_PROTOCOL = 'ccd73002fb0cea395a2782751ee33e274b51120cb12c8dcfc2843987bd2dd58e'


def prepare(source: Path, module: Path):
    data = (source / 'transport/wireguard/endpoint.go').read_bytes()
    if hashlib.sha256(data).hexdigest() != ORIGINAL_ENDPOINT:
        raise RuntimeError('Pinned WireGuard endpoint changed; review loopback socket control patch')
    content = data.decode()
    old = '\t\tlistenerControl, egressEnabled := udpListener.UDPListenerControl()\n'
    assert content.count(old) == 1
    content = content.replace(old, old + '\t\tlistenerControl, egressEnabled = loopbackPeerListenerControl(listenerControl, egressEnabled, e.peers)\n')
    # A domain peer's keepalive is applied only after its resolver exists;
    # the TUN EventUp brings the device up asynchronously, and a keepalive
    # handshake fired before SetEndpointResolver has no endpoint until the
    # rekey retry.
    old = '\tif c.keepalive != "" {\n\t\tipcLines.WriteString("\\npersistent_keepalive_interval=" + c.keepalive)\n'
    assert content.count(old) == 1
    content = content.replace(old, '\tif c.keepalive != "" && !c.destination.IsDomain() {\n\t\tipcLines.WriteString("\\npersistent_keepalive_interval=" + c.keepalive)\n')
    old = '\te.device = wgDevice\n'
    assert content.count(old) == 1
    content = content.replace(old, '''\tif err := applyDeferredKeepalive(wgDevice, e.peers); err != nil {
        wgDevice.Close()
        return E.Cause(err, "setup wireguard keepalive")
    }
    if !e.options.System && e.options.ListenPort != 0 {
        if err := startFixedPortDevice(wgDevice, e.options.ListenPort); err != nil {
            wgDevice.Close()
            return E.Cause(err, "bind wireguard fixed port")
        }
    }
''' + old)
    old = 'return E.Cause(err, "setup wireguard: \\n", ipcConf.String())'
    assert content.count(old) == 1
    content = content.replace(old, 'return E.Cause(err, "setup wireguard")')
    target = module / 'transport/wireguard/endpoint.go'
    target.chmod(0o644)
    target.write_text(content)
    directory = target.parent
    directory.chmod(0o755)
    outputs = [target]
    for name in ['loopback', 'start']:
        helper = directory / ('thronium_' + name + '.go')
        if helper.exists(): helper.chmod(0o644)
        helper.write_bytes((Path(__file__).parent / ('overlays/sing-box/wireguard_' + name + '.go')).read_bytes())
        outputs.append(helper)
    protocol = source / 'protocol/wireguard/endpoint.go'
    data = protocol.read_bytes()
    if hashlib.sha256(data).hexdigest() != ORIGINAL_PROTOCOL:
        raise RuntimeError('Pinned WireGuard lifecycle changed; review fixed-port startup')
    content = data.decode()
    replacements = [
        ('\tstartErr       error\n', '\tstartErr       error\n\tstartFixedPort bool\n'),
        ('\t\tlocalAddresses: options.Address,\n', '''\t\tlocalAddresses: options.Address,
        startFixedPort: options.ListenPort != 0 && !options.System && len(options.Peers) > 0 &&
            !common.Any(options.Peers, func(peer option.WireGuardPeer) bool { return !M.ParseAddr(peer.Address).IsValid() && !wireguard.IsLocalhostName(peer.Address) }),
'''),
        ('func (w *Endpoint) Start(stage adapter.StartStage) error {\n', '''func (w *Endpoint) Start(stage adapter.StartStage) error {
    // Literal or localhost-named userspace peers with a fixed port cannot have a
    // detour (validated above), and bring-up only installs the name resolver
    // without invoking it, so opening their socket cannot re-enter
    // EndpointManager through DNS. Start after network/DNS initialization and
    // report bind errors to the application's existing rollback transaction.
    // Other contexts remain lazy.
    if stage == adapter.StartStatePostStart && w.startFixedPort {
        return w.ensureStarted()
    }
'''),
    ]
    for old, new in replacements:
        assert content.count(old) == 1
        content = content.replace(old, new)
    target = module / 'protocol/wireguard/endpoint.go'
    target.chmod(0o644)
    target.write_text(content)
    outputs.append(target)
    return outputs
