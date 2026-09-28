//go:build linux

package tunsession

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSystemDNSRequiresTheUnconditionalOwnedHijackRule(t *testing.T) {
	for _, test := range []struct {
		mode, route string
		valid       bool
	}{
		{"", "{}", true}, {"unknown", "{}", false}, {"resolved", "{}", false},
		{"resolved", `{"rules":[{"inbound":["thronium-tun"],"port":53,"action":"hijack-dns"}]}`, true},
		{"resolvconf", `{"rules":[{"inbound":["thronium-tun"],"port":53,"action":"hijack-dns"}]}`, true},
		{"resolvconf", `{}`, false},
		{"resolved", `{"rules":[{"inbound":["foreign"],"port":53,"action":"hijack-dns"}]}`, false},
		{"resolved", `{"rules":[{"inbound":["thronium-tun"],"port":53,"action":"hijack-dns","domain":["limited.invalid"]}]}`, false},
		{"resolved", `{"rules":[{"inbound":["thronium-tun"],"port":853,"action":"hijack-dns"}]}`, false},
	} {
		if validDNSRequest(test.mode, map[string]json.RawMessage{"route": json.RawMessage(test.route)}) != test.valid {
			t.Fatalf("wrong acceptance for %s %s", test.mode, test.route)
		}
	}
}
func TestDNSJournalValidatesIntentAndRecordedOwnership(t *testing.T) {
	j := &journal{DNSMode: "resolved", IPv4CIDR: "172.19.0.1/30", IPv6: true, IPv6CIDR: "fdfe:dcba:9876::1/126"}
	if !j.validDNS() {
		t.Fatal("initial intent rejected")
	}
	j.DNSIndex = 9
	j.DNSToken = strings.Repeat("a", 32)
	if !j.validDNS() {
		t.Fatal("owned intent rejected")
	}
	j.DNSMode = "resolvconf"
	if !j.validDNS() {
		t.Fatal("openresolv journal rejected")
	}
	spec, err := j.dnsSpec()
	if err != nil || spec.Servers[0].String() != "172.19.0.2" || spec.Servers[1].String() != "fdfe:dcba:9876::2" {
		t.Fatal("wrong virtual resolver addresses", spec, err)
	}
	for _, edit := range []func(*journal){func(j *journal) { j.DNSMode = "foreign" }, func(j *journal) { j.DNSMode = "" }, func(j *journal) { j.DNSIndex = -1 }, func(j *journal) { j.DNSToken = "bad" }, func(j *journal) { j.IPv4CIDR = "1.1.1.1/30" }, func(j *journal) { j.IPv6CIDR = "" }} {
		bad := *j
		edit(&bad)
		if bad.validDNS() {
			t.Fatal("untrusted DNS record accepted", bad)
		}
	}
}
func TestVirtualDNSAddressRemainsInsideSubnetAndDiffersFromInterface(t *testing.T) {
	for _, test := range [][2]string{{"172.19.0.1/30", "172.19.0.2"}, {"10.8.0.2/24", "10.8.0.1"}, {"fdfe:dcba:9876::1/126", "fdfe:dcba:9876::2"}} {
		address, err := virtualDNSAddress(test[0])
		if err != nil || address.String() != test[1] {
			t.Fatal(test, address, err)
		}
	}
}
