//go:build linux

package tundns

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

type memoryClient struct {
	calls       []string
	dns         []DNS
	domains     []Domain
	route       bool
	tls, dnssec string
	fail        string
	wrong       bool
	after       func(string)
}

func (m *memoryClient) Call(ctx context.Context, name string, args ...any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.calls = append(m.calls, name)
	if name == m.fail {
		return errors.New("fixture refusal")
	}
	switch name {
	case "SetLinkDNS":
		m.dns = args[1].([]DNS)
	case "SetLinkDomains":
		m.domains = args[1].([]Domain)
	case "SetLinkDefaultRoute":
		m.route = args[1].(bool)
	case "SetLinkDNSOverTLS":
		m.tls = args[1].(string)
	case "SetLinkDNSSEC":
		m.dnssec = args[1].(string)
	case "RevertLink":
		m.dns = nil
		m.domains = nil
		m.route = false
		m.tls = ""
		m.dnssec = ""
	default:
		panic(name)
	}
	if m.after != nil {
		m.after(name)
	}
	return nil
}
func (m *memoryClient) Property(ctx context.Context, index int32, name string, target any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.fail == "Get"+name {
		return errors.New("fixture read error")
	}
	switch name {
	case "DNS":
		*target.(*[]DNS) = m.dns
	case "Domains":
		*target.(*[]Domain) = m.domains
	case "DefaultRoute":
		*target.(*bool) = m.route && !m.wrong
	case "DNSOverTLS":
		*target.(*string) = m.tls
	case "DNSSEC":
		*target.(*string) = m.dnssec
	default:
		panic(name)
	}
	return nil
}
func testSpec() Spec {
	return Spec{9, strings.Repeat("a", 32), []netip.Addr{netip.MustParseAddr("172.19.0.2"), netip.MustParseAddr("fdfe:dcba:9876::2")}}
}
func own(Spec) error { return nil }
func TestApplyReadbackAndCleanupOfOwnedPolicy(t *testing.T) {
	m := &memoryClient{}
	s := testSpec()
	if err := Apply(context.Background(), m, own, s); err != nil {
		t.Fatal(err)
	}
	if !Matches(context.Background(), m, own, s) {
		t.Fatal("incomplete applied policy")
	}
	if err := Revert(context.Background(), m, own, s); err != nil {
		t.Fatal(err)
	}
	if len(m.dns) != 0 || len(m.domains) != 0 || m.route || m.tls != "" || m.dnssec != "" {
		t.Fatal("owned policy remained")
	}
}
func TestEveryPartialApplyAndReadFailureReverts(t *testing.T) {
	for _, failure := range []string{"SetLinkDNS", "SetLinkDNSOverTLS", "SetLinkDNSSEC", "SetLinkDomains", "SetLinkDefaultRoute", "GetDNS", "GetDomains", "GetDefaultRoute", "GetDNSOverTLS", "GetDNSSEC"} {
		t.Run(failure, func(t *testing.T) {
			m := &memoryClient{fail: failure}
			expected := ErrApply
			if failure == "GetDNS" || failure == "GetDomains" {
				expected = ErrCleanup
			}
			if !errors.Is(Apply(context.Background(), m, own, testSpec()), expected) {
				t.Fatal("failure accepted")
			}
			if len(m.dns) > 0 || len(m.domains) > 0 || m.route {
				t.Fatal("partial policy retained")
			}
			if m.calls[len(m.calls)-1] != "RevertLink" {
				t.Fatal("partial mutation not reverted")
			}
		})
	}
}
func TestSuccessfulCallsWithoutMatchingReadbackAreNotAccepted(t *testing.T) {
	m := &memoryClient{wrong: true}
	if !errors.Is(Apply(context.Background(), m, own, testSpec()), ErrApply) {
		t.Fatal("readback mismatch accepted")
	}
	if len(m.dns) > 0 {
		t.Fatal("mismatched configuration remained")
	}
}
func TestForeignOrRecycledLinkNeverReceivesApplyOrRevert(t *testing.T) {
	for _, action := range []func(context.Context, Client, Verify, Spec) error{Apply, Revert} {
		m := &memoryClient{}
		if !errors.Is(action(context.Background(), m, func(Spec) error { return ErrOwnership }, testSpec()), ErrOwnership) {
			t.Fatal("foreign ownership accepted")
		}
		if len(m.calls) > 0 {
			t.Fatal("foreign link mutated")
		}
	}
	m := &memoryClient{}
	if Revert(context.Background(), m, func(Spec) error { return ErrGone }, testSpec()) != nil || len(m.calls) > 0 {
		t.Fatal("deleted link used stale index")
	}
}
func TestOwnershipLostMidApplyDoesNotTouchReplacement(t *testing.T) {
	lost := false
	m := &memoryClient{after: func(name string) {
		if name == "SetLinkDNS" {
			lost = true
		}
	}}
	err := Apply(context.Background(), m, func(Spec) error {
		if lost {
			return ErrOwnership
		}
		return nil
	}, testSpec())
	if !errors.Is(err, ErrCleanup) {
		t.Fatal("uncertain cleanup reported clean", err)
	}
	if len(m.calls) != 1 || m.calls[0] != "SetLinkDNS" {
		t.Fatal("recycled link mutated", m.calls)
	}
}
func TestCancellationCannotLeaveLatePolicyOrSkipCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := &memoryClient{after: func(name string) {
		if name == "SetLinkDomains" {
			cancel()
		}
	}}
	if !errors.Is(Apply(ctx, m, own, testSpec()), ErrApply) {
		t.Fatal("cancelled transaction accepted")
	}
	if len(m.dns) > 0 || len(m.domains) > 0 || m.route {
		t.Fatal("cancelled policy survived")
	}
	before := len(m.calls)
	if Apply(ctx, m, own, testSpec()) == nil || len(m.calls) != before {
		t.Fatal("pre-cancelled operation mutated link")
	}
}
func TestCleanupErrorCannotBeReportedAsCleanFailure(t *testing.T) {
	m := &memoryClient{fail: "RevertLink", wrong: true}
	if !errors.Is(Apply(context.Background(), m, own, testSpec()), ErrCleanup) {
		t.Fatal("cleanup error lost")
	}
}
func TestInvalidOwnershipAndAddressesRefuseBeforeIO(t *testing.T) {
	for _, edit := range []func(*Spec){func(s *Spec) { s.Index = 0 }, func(s *Spec) { s.Token = "foreign" }, func(s *Spec) { s.Token = strings.Repeat("A", 32) }, func(s *Spec) { s.Servers = nil }, func(s *Spec) { s.Servers[0] = netip.MustParseAddr("1.1.1.1") }, func(s *Spec) { s.Servers[0] = netip.MustParseAddr("127.0.0.1") }, func(s *Spec) { s.Servers[1] = netip.MustParseAddr("172.19.0.3") }} {
		s := testSpec()
		edit(&s)
		m := &memoryClient{}
		if !errors.Is(Apply(context.Background(), m, own, s), ErrInvalid) || len(m.calls) > 0 {
			t.Fatal("invalid specification reached resolver")
		}
	}
}

func TestSuccessfulRevertWithoutClearedReadbackIsNotAccepted(t *testing.T) {
	m := &memoryClient{}
	s := testSpec()
	if err := Apply(context.Background(), m, own, s); err != nil {
		t.Fatal(err)
	}
	m.after = func(name string) {
		if name == "RevertLink" {
			m.dns = addresses(s)
		}
	}
	if !errors.Is(Revert(context.Background(), m, own, s), ErrCleanup) {
		t.Fatal("unapplied revert reported clean")
	}
}
