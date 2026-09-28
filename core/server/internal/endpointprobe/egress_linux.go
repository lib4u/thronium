//go:build linux

package endpointprobe

import (
	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
	"net"
	"syscall"
)

func socketMark(conn syscall.RawConn, mark uint32) error {
	if mark == 0 {
		// A TUN can start between queueing a standalone probe and opening its
		// socket. Refuse an unmarked probe instead of accepting TUN's TCP SYN-ACK.
		for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
			rules, err := netlink.RuleList(family)
			if err != nil {
				return errEgress
			}
			for _, r := range rules {
				if r.Priority == 18900 && r.Mark != 0 {
					return errEgress
				}
			}
		}
		return nil
	}
	var inner error
	err := conn.Control(func(fd uintptr) { inner = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark)) })
	if err != nil || inner != nil {
		return errEgress
	}
	return nil
}

// Read only the main/local tables: TUN policy tables must not select our path.
// Binding the socket's output interface also bypasses sing-tun's auto_route and
// policy routing. The managed worker additionally sets its own output mark.
// No routes or firewall rules are changed.
func directControl(_ string, address string, conn syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return errEgress
	}
	name, err := directInterface(ip)
	if err != nil {
		return errEgress
	}
	var bindErr error
	err = conn.Control(func(fd uintptr) { bindErr = unix.BindToDevice(int(fd), name) })
	if err != nil || bindErr != nil {
		return errEgress
	}
	return nil
}

func directInterface(ip net.IP) (string, error) {
	if ip.IsLoopback() {
		return "lo", nil
	}
	family := netlink.FAMILY_V6
	if ip.To4() != nil {
		family = netlink.FAMILY_V4
	}
	// Connecting to an address of this machine must retain local routing.
	local, err := netlink.RouteListFiltered(family, &netlink.Route{Table: unix.RT_TABLE_LOCAL}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return "", err
	}
	for _, r := range local {
		if r.Type == unix.RTN_LOCAL && r.Dst != nil && r.Dst.Contains(ip) {
			return "lo", nil
		}
	}
	routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return "", err
	}
	bestBits, bestMetric, name := -1, int(^uint(0)>>1), ""
	for _, r := range routes {
		if r.Type != unix.RTN_UNICAST {
			continue
		}
		bits := 0
		if r.Dst != nil {
			if !r.Dst.Contains(ip) {
				continue
			}
			bits, _ = r.Dst.Mask.Size()
		}
		if bits < bestBits || (bits == bestBits && r.Priority >= bestMetric) {
			continue
		}
		link, err := netlink.LinkByIndex(r.LinkIndex)
		if err != nil || link.Attrs().Flags&net.FlagUp == 0 {
			continue
		}
		switch link.Type() {
		case "tuntap", "tun", "wireguard":
			continue
		}
		if link.Attrs().Name == "thronium-tun" {
			continue
		}
		bestBits, bestMetric, name = bits, r.Priority, link.Attrs().Name
	}
	if name == "" {
		return "", errEgress
	}
	return name, nil
}
