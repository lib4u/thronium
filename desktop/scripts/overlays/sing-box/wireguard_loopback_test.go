package wireguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

func domainPeer(host string, port uint16) peerConfig {
	return peerConfig{destination: M.ParseSocksaddrHostPort(host, port)}
}

func TestIsLocalhostName(t *testing.T) {
	for name, want := range map[string]bool{
		"localhost": true, "LOCALHOST.": true, "wg.localhost": true, "a.b.localhost.": true,
		"localhost.example.com": false, "notlocalhost": false, "example.com": false, "": false,
	} {
		if IsLocalhostName(name) != want {
			t.Fatalf("%q: want %v", name, want)
		}
	}
}

func TestLoopbackPeerListenerControlLocalhostNames(t *testing.T) {
	for _, tc := range []struct {
		name, network, listen, destination string
		peers                              []peerConfig
	}{
		{"localhost4", "udp4", "127.0.0.1:0", "127.0.0.1:51830", []peerConfig{domainPeer("localhost", 51830)}},
		{"localhost6", "udp6", "[::1]:0", "[::1]:51830", []peerConfig{domainPeer("localhost", 51830)}},
		{"subdomain", "udp4", "127.0.0.1:0", "127.0.0.1:51831", []peerConfig{domainPeer("wg.localhost", 51831)}},
		{"literal-first", "udp4", "127.0.0.1:0", "127.0.0.2:51820", []peerConfig{domainPeer("localhost", 51830), {endpoint: netip.MustParseAddrPort("127.0.0.2:51820")}}},
		{"literal-other-family", "udp6", "[::1]:0", "[::1]:51830", []peerConfig{{endpoint: netip.MustParseAddrPort("127.0.0.2:51820")}, domainPeer("localhost", 51830)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			control, egress := loopbackPeerListenerControl(func(network, address string, raw syscall.RawConn) error {
				called = true
				if network != tc.network || address != tc.destination || raw == nil {
					t.Fatalf("wrong socket destination: %s %s", network, address)
				}
				return raw.Control(func(fd uintptr) {})
			}, true, tc.peers)
			if egress {
				t.Fatal("localhost peers still use external egress")
			}
			listener := net.ListenConfig{Control: control}
			packet, err := listener.ListenPacket(context.Background(), tc.network, tc.listen)
			if err != nil {
				t.Fatal(err)
			}
			packet.Close()
			if !called {
				t.Fatal("control was not called for the real UDP socket")
			}
		})
	}
}

func TestLoopbackPeerListenerControlActualSocket(t *testing.T) {
	for _, tc := range []struct{ network, listen, peer string }{
		{"udp4", "127.0.0.1:0", "127.0.0.1:51820"},
		{"udp6", "[::1]:0", "[::1]:51820"},
	} {
		t.Run(tc.network, func(t *testing.T) {
			called := false
			control, egress := loopbackPeerListenerControl(func(network, address string, raw syscall.RawConn) error {
				called = true
				if network != tc.network || address != tc.peer || raw == nil {
					t.Fatalf("socket control lost network, destination or descriptor: %q %q", network, address)
				}
				return raw.Control(func(fd uintptr) {})
			}, true, []peerConfig{{endpoint: netip.MustParseAddrPort(tc.peer)}})
			if egress {
				t.Fatal("loopback client still enables external egress members")
			}
			listener := net.ListenConfig{Control: control}
			packet, err := listener.ListenPacket(context.Background(), tc.network, tc.listen)
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Close()
			if !called {
				t.Fatal("real UDP socket did not invoke preserved control")
			}
		})
	}
}

func TestLoopbackPeerListenerControlKeepsOtherPolicies(t *testing.T) {
	local := peerConfig{endpoint: netip.MustParseAddrPort("127.0.0.1:51820")}
	for _, tc := range []struct {
		name   string
		egress bool
		peers  []peerConfig
	}{
		{"explicit-control", false, []peerConfig{local}},
		{"no-peers", true, nil},
		{"external-peer", true, []peerConfig{{endpoint: netip.MustParseAddrPort("192.0.2.1:51820")}}},
		{"external-ipv6", true, []peerConfig{{endpoint: netip.MustParseAddrPort("[2001:db8::1]:51820")}}},
		{"unresolved-domain", true, []peerConfig{{}}},
		{"external-domain", true, []peerConfig{domainPeer("example.com", 51820)}},
		{"localhost-lookalike", true, []peerConfig{domainPeer("localhost.example.com", 51820)}},
		{"mixed-localhost-external", true, []peerConfig{domainPeer("localhost", 51820), {endpoint: netip.MustParseAddrPort("192.0.2.1:51820")}}},
		{"mixed-local-external", true, []peerConfig{local, {endpoint: netip.MustParseAddrPort("192.0.2.1:51820")}}},
		{"mixed-resolved-unresolved", true, []peerConfig{local, {}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := errors.New("original socket policy")
			called := false
			control, egress := loopbackPeerListenerControl(func(network, address string, raw syscall.RawConn) error {
				called = true
				if network != "udp4" || address != "0.0.0.0:0" {
					t.Fatal("unrelated socket policy was rewritten")
				}
				return want
			}, tc.egress, tc.peers)
			if egress != tc.egress || !errors.Is(control("udp4", "0.0.0.0:0", nil), want) || !called {
				t.Fatal("original egress/control result changed")
			}
		})
	}
	control, egress := loopbackPeerListenerControl(nil, true, []peerConfig{local})
	if control != nil || !egress {
		t.Fatal("missing automatic control must not be invented")
	}
}

func TestLoopbackPeerListenerControlPropagatesSocketFailure(t *testing.T) {
	want := errors.New("fixture socket policy refused")
	control, _ := loopbackPeerListenerControl(func(_ string, _ string, _ syscall.RawConn) error { return want }, true, []peerConfig{{endpoint: netip.MustParseAddrPort("127.0.0.1:51820")}})
	listener := net.ListenConfig{Control: control}
	packet, err := listener.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
	if packet != nil {
		packet.Close()
		t.Fatal("socket started despite control failure")
	}
	if !errors.Is(err, want) {
		t.Fatalf("socket control failure was swallowed: %v", err)
	}
}

func TestLoopbackMultiplePeersAndSocketFamilies(t *testing.T) {
	local4 := peerConfig{endpoint: netip.MustParseAddrPort("127.0.0.2:51820")}
	local6 := peerConfig{endpoint: netip.MustParseAddrPort("[::1]:51821")}
	for _, tc := range []struct {
		name, network, listen, destination string
		peers                              []peerConfig
	}{
		{"two-ipv4", "udp4", "127.0.0.1:0", "127.0.0.2:51820", []peerConfig{local4, {endpoint: netip.MustParseAddrPort("127.0.0.3:51822")}}},
		{"mixed-family4", "udp4", "127.0.0.1:0", "127.0.0.2:51820", []peerConfig{local6, local4}},
		{"mixed-family6", "udp6", "[::1]:0", "[::1]:51821", []peerConfig{local4, local6}},
		{"single-v4-opens-v6", "udp6", "[::1]:0", "[::1]:0", []peerConfig{local4}},
		{"single-v6-opens-v4", "udp4", "127.0.0.1:0", "127.0.0.1:0", []peerConfig{local6}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			control, egress := loopbackPeerListenerControl(func(network, address string, raw syscall.RawConn) error {
				called = true
				if network != tc.network || address != tc.destination || raw == nil {
					t.Fatalf("wrong socket destination: %s %s", network, address)
				}
				return raw.Control(func(fd uintptr) {})
			}, true, tc.peers)
			if egress {
				t.Fatal("local-only peers still use external egress")
			}
			listener := net.ListenConfig{Control: control}
			packet, err := listener.ListenPacket(context.Background(), tc.network, tc.listen)
			if err != nil {
				t.Fatal(err)
			}
			packet.Close()
			if !called {
				t.Fatal("control was not called for the real UDP socket")
			}
		})
	}
}
