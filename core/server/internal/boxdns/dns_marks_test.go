package boxdns

import (
	"net/netip"
	"slices"
	"testing"
)

func addresses(texts ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(texts))
	for _, text := range texts {
		out = append(out, netip.MustParseAddr(text))
	}
	return out
}

func TestOwnedListRoundTripsStaticAndDHCPInterfaces(t *testing.T) {
	static := addresses("192.0.2.53", "198.51.100.53")
	set := ownedList(static, false)
	if !slices.Equal(set, addresses(localAddr, "192.0.2.53", "198.51.100.53", setMarkAddr)) {
		t.Fatal(set)
	}
	if servers, dhcp, owned := originalList(set); !owned || dhcp || !slices.Equal(servers, static) {
		t.Fatal(servers, dhcp, owned)
	}
	// A DHCP interface already has its DHCP servers in the list; on restore it
	// is emptied so DHCP takes over again.
	set = ownedList(addresses("192.0.2.1"), true)
	if !slices.Equal(set, addresses(localAddr, "192.0.2.1", dhcpMarkAddr)) {
		t.Fatal(set)
	}
	if _, dhcp, owned := originalList(set); !owned || !dhcp {
		t.Fatal("dhcp origin lost")
	}
}

func TestOwnedListSetTwiceKeepsTheFirstOrigin(t *testing.T) {
	once := ownedList(addresses("192.0.2.1"), true)
	// The second look at the interface sees Thronium's own static-looking list.
	twice := ownedList(once, false)
	if !slices.Equal(twice, once) {
		t.Fatal(twice)
	}
	static := ownedList(addresses("192.0.2.53"), false)
	if again := ownedList(static, false); !slices.Equal(again, static) {
		t.Fatal(again)
	}
}

func TestOriginalListLeavesForeignListsAlone(t *testing.T) {
	foreign := addresses(localAddr, "192.0.2.53")
	servers, _, owned := originalList(foreign)
	if owned || !slices.Equal(servers, foreign) {
		t.Fatal(servers, owned)
	}
}
