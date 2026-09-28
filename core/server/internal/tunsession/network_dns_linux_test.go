//go:build linux

package tunsession

import (
	"testing"
	"time"
)

func TestNetworkDNSWatchDebouncesAndForgetsCanceledChange(t *testing.T) {
	a, b, c := [32]byte{1}, [32]byte{2}, [32]byte{3}
	now := time.Unix(100, 0)
	var w networkDNSWatch
	if w.observe(a, now) || w.observe(b, now.Add(time.Second)) || w.observe(b, now.Add(5*time.Second)) {
		t.Fatal("early reconnect")
	}
	if !w.observe(b, now.Add(6*time.Second)) {
		t.Fatal("stable change ignored")
	}
	w.seed(a)
	if w.observe(b, now) || w.observe(a, now.Add(4*time.Second)) || w.observe(b, now.Add(5*time.Second)) || w.observe(b, now.Add(9*time.Second)) {
		t.Fatal("reverted change retained")
	}
	if w.observe(c, now.Add(10*time.Second)) || w.observe(c, now.Add(14*time.Second)) || !w.observe(c, now.Add(15*time.Second)) {
		t.Fatal("replacement not debounced")
	}
	w.seed(c)
	if w.observe(c, now.Add(time.Hour)) {
		t.Fatal("reconnect loop after refresh")
	}
}

func TestNetworkDNSWatchRespectsDisabledAndOtherDNSModes(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		s := &session{enabled: enabled, networkDNS: networkDNSWatch{ready: true, since: time.Now()}}
		if s.networkDNSChanged(time.Now()) || !s.networkDNS.since.IsZero() {
			t.Fatal("absent openresolv session watched")
		}
		if err := s.prepareNetworkDNS(); err != nil || s.networkDNS.ready {
			t.Fatal("inactive capture", err)
		}
	}
}
