package endpointprobe

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
)

// The pure half of the Windows ICMP probe, kept outside the Windows file so it
// is tested everywhere.

const (
	ipSuccess     = 0
	ipReqTimedOut = 11010
)

var errNoEcho = errors.New("icmp echo not answered")

// sourceFor picks the default interface's address to send from: the
// destination's family, never loopback, and not link-local.
func sourceFor(addresses []netip.Prefix, destination netip.Addr) (netip.Addr, bool) {
	for _, prefix := range addresses {
		address := prefix.Addr().Unmap()
		if address.Is4() == destination.Is4() && !address.IsLoopback() && !address.IsLinkLocalUnicast() {
			return address, true
		}
	}
	return netip.Addr{}, false
}

// echoReply reads the first reply Windows writes into the buffer: an
// ICMP_ECHO_REPLY (address, then status) for IPv4, an ICMPV6_ECHO_REPLY for
// IPv6, whose packed 26-byte IPV6_ADDRESS_EX (port, flow, address, scope) puts
// the status at offset 28.
func echoReply(buffer []byte, v6 bool) (netip.Addr, uint32, bool) {
	if v6 {
		if len(buffer) < 32 {
			return netip.Addr{}, 0, false
		}
		return netip.AddrFrom16([16]byte(buffer[6:22])), binary.LittleEndian.Uint32(buffer[28:]), true
	}
	if len(buffer) < 8 {
		return netip.Addr{}, 0, false
	}
	return netip.AddrFrom4([4]byte(buffer[0:4])), binary.LittleEndian.Uint32(buffer[4:]), true
}

// echoVerdict turns what the send call returned into the errors the probe
// already maps: no reply in time, no echo from that address, or success.
func echoVerdict(buffer []byte, destination netip.Addr, replies uintptr, lastError uint32) error {
	if replies == 0 {
		if lastError == ipReqTimedOut {
			return context.DeadlineExceeded
		}
		return errNoEcho
	}
	address, status, ok := echoReply(buffer, destination.Is6())
	switch {
	case !ok:
		return errICMP
	case status == ipReqTimedOut:
		return context.DeadlineExceeded
	case status != ipSuccess || address != destination:
		return errNoEcho
	}
	return nil
}
