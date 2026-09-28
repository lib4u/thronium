package wireguard

import (
	"net/netip"
	"strings"
	"syscall"

	"github.com/sagernet/sing/common/control"
)

// IsLocalhostName reports an RFC 6761 loopback name: "localhost" or any name
// under it. Such a peer is local by definition, without a lookup that could
// re-enter the endpoint's own bring-up through the DNS router.
func IsLocalhostName(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	return name == "localhost" || strings.HasSuffix(name, ".localhost")
}

// A literal loopback endpoint or a localhost name; other domains stay unknown
// until resolved and keep the existing policy.
func localPeer(peer peerConfig) bool {
	if peer.endpoint.IsValid() {
		return peer.endpoint.Addr().IsLoopback()
	}
	return peer.destination.IsDomain() && IsLocalhostName(peer.destination.Fqdn)
}

// A wildcard WireGuard listener otherwise presents 0.0.0.0 or :: to the
// automatic interface selector, which chooses the external interface even for
// loopback peers. Retain the destination when all configured peers are local,
// including fixed-port, multi-peer and localhost-named clients. A mixed,
// unresolved or server-only configuration keeps the existing egress policy, as
// does explicit binding.
func loopbackPeerListenerControl(original control.Func, egress bool, peers []peerConfig) (control.Func, bool) {
	if !egress || original == nil || len(peers) == 0 {
		return original, egress
	}
	for _, peer := range peers {
		if !localPeer(peer) {
			return original, egress
		}
	}
	return func(network, _ string, raw syscall.RawConn) error {
		// Fixed-port sockets open both families, even with one IPv4 peer.
		// Keep each control invocation consistent with its actual socket family.
		for _, peer := range peers {
			if peer.endpoint.IsValid() && (network != "udp4" && network != "udp6" || peer.endpoint.Addr().Is6() == (network == "udp6")) {
				return original(network, peer.endpoint.String(), raw)
			}
		}
		address := netip.MustParseAddr("127.0.0.1")
		if network == "udp6" {
			address = netip.IPv6Loopback()
		}
		// A localhost name resolves to this family's loopback address; keep its port.
		var port uint16
		for _, peer := range peers {
			if !peer.endpoint.IsValid() {
				port = peer.destination.Port
				break
			}
		}
		return original(network, netip.AddrPortFrom(address, port).String(), raw)
	}, false
}
