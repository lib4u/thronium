package endpointprobe

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

func TestSourceForTakesTheDestinationFamilyOffLoopbackAndLinkLocal(t *testing.T) {
	addresses := []netip.Prefix{
		netip.MustParsePrefix("127.0.0.1/8"),
		netip.MustParsePrefix("169.254.3.4/16"),
		netip.MustParsePrefix("fe80::1/64"),
		netip.MustParsePrefix("192.0.2.10/24"),
		netip.MustParsePrefix("2001:db8::10/64"),
	}
	for destination, want := range map[string]string{"198.51.100.1": "192.0.2.10", "2001:db8:1::1": "2001:db8::10"} {
		if got, ok := sourceFor(addresses, netip.MustParseAddr(destination)); !ok || got.String() != want {
			t.Fatal(destination, got)
		}
	}
	if _, ok := sourceFor(addresses[:3], netip.MustParseAddr("2001:db8:1::1")); ok {
		t.Fatal("link-local IPv6 chosen")
	}
	if got, ok := sourceFor([]netip.Prefix{netip.MustParsePrefix("::ffff:192.0.2.7/120")}, netip.MustParseAddr("198.51.100.1")); !ok || got.String() != "192.0.2.7" {
		t.Fatal("mapped address", got)
	}
}

func v4Reply(address string, status uint32) []byte {
	buffer := make([]byte, 64)
	ip := netip.MustParseAddr(address).As4()
	copy(buffer, ip[:])
	binary.LittleEndian.PutUint32(buffer[4:], status)
	return buffer
}

func v6Reply(address string, status uint32) []byte {
	buffer := make([]byte, 64)
	ip := netip.MustParseAddr(address).As16()
	copy(buffer[6:22], ip[:])
	binary.LittleEndian.PutUint32(buffer[28:], status)
	return buffer
}

func TestEchoVerdictMapsWindowsRepliesToProbeErrors(t *testing.T) {
	v4, v6 := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")
	for name, c := range map[string]struct {
		buffer      []byte
		destination netip.Addr
		replies     uintptr
		lastError   uint32
		want        error
	}{
		"v4 echo":          {v4Reply("192.0.2.1", ipSuccess), v4, 1, 0, nil},
		"v6 echo":          {v6Reply("2001:db8::1", ipSuccess), v6, 1, 0, nil},
		"no reply in time": {make([]byte, 64), v4, 0, ipReqTimedOut, context.DeadlineExceeded},
		"timed-out status": {v4Reply("192.0.2.1", ipReqTimedOut), v4, 1, 0, context.DeadlineExceeded},
		"host unreachable": {v4Reply("192.0.2.254", 11003), v4, 1, 0, errNoEcho},
		"other address":    {v4Reply("192.0.2.2", ipSuccess), v4, 1, 0, errNoEcho},
		"v6 other address": {v6Reply("2001:db8::2", ipSuccess), v6, 1, 0, errNoEcho},
		"send failed":      {make([]byte, 64), v4, 0, 1231, errNoEcho},
		"short v6 buffer":  {make([]byte, 31), v6, 1, 0, errICMP},
		"short v4 buffer":  {make([]byte, 7), v4, 1, 0, errICMP},
	} {
		if got := echoVerdict(c.buffer, c.destination, c.replies, c.lastError); !errors.Is(got, c.want) && got != c.want {
			t.Fatal(name, got)
		}
	}
	if errorCode(echoVerdict(make([]byte, 64), v4, 0, ipReqTimedOut), "icmp") != "probe_icmp_no_reply" ||
		errorCode(echoVerdict(v4Reply("192.0.2.254", 11003), v4, 1, 0), "icmp") != "probe_unreachable" {
		t.Fatal("probe codes")
	}
}
