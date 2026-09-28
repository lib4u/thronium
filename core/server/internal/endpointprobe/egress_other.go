//go:build !linux

package endpointprobe

import (
	"ThroneCore/internal/boxdns"
	"github.com/sagernet/sing/common/control"
	"net"
	"syscall"
)

func socketMark(syscall.RawConn, uint32) error { return nil }

func directControl(network, address string, conn syscall.RawConn) error {
	host, _, _ := net.SplitHostPort(address)
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	iface := boxdns.DefaultInterface()
	if iface == nil {
		return errEgress
	}
	if control.BindToInterface(control.NewDefaultInterfaceFinder(), iface.Name, iface.Index)(network, address, conn) != nil {
		return errEgress
	}
	return nil
}
