package boxdns

import "net/netip"

// Windows keeps no separate record of what Thronium changed: the interface's
// IPv4 DNS list itself carries it. While set, the list is the local server,
// then the servers it had, then a mark saying whether they came from DHCP.
// These two functions are that encoding; they are kept outside the Windows
// file so they are tested everywhere.

const (
	localAddr    = "127.1.1.1"
	dhcpMarkAddr = "127.1.2.3"
	setMarkAddr  = "127.3.2.1"
)

var (
	localServer = netip.MustParseAddr(localAddr)
	dhcpMark    = netip.MustParseAddr(dhcpMarkAddr)
	setMark     = netip.MustParseAddr(setMarkAddr)
)

// ownedList is the list to publish on an interface whose current list is
// current; dhcp says whether its own servers come from DHCP. Setting twice
// keeps the first origin and never stacks the local server.
func ownedList(current []netip.Addr, dhcp bool) []netip.Addr {
	servers, wasDHCP, owned := originalList(current)
	mark := setMark
	if dhcp || (owned && wasDHCP) {
		mark = dhcpMark
	}
	list := append([]netip.Addr{localServer}, servers...)
	return append(list, mark)
}

// originalList undoes ownedList: the servers the interface had, whether they
// came from DHCP (then the list is to be emptied so DHCP applies again), and
// whether Thronium owned the list at all.
func originalList(current []netip.Addr) (servers []netip.Addr, dhcp bool, owned bool) {
	servers = make([]netip.Addr, 0, len(current))
	for _, server := range current {
		switch server {
		case setMark, dhcpMark:
			owned = true
			dhcp = server == dhcpMark
		default:
			servers = append(servers, server)
		}
	}
	if owned && len(servers) > 0 && servers[0] == localServer {
		servers = servers[1:]
	}
	return servers, dhcp, owned
}
