//go:build linux

// Package tundns configures only the resolver policy of an owned TUN link.
package tundns

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"time"
)

var (
	ErrInvalid     = errors.New("invalid_tun_system_dns")
	ErrOwnership   = errors.New("tun_system_dns_owner_changed")
	ErrGone        = errors.New("tun_system_dns_link_gone")
	ErrApply       = errors.New("tun_system_dns_failed")
	ErrCleanup     = errors.New("tun_system_dns_cleanup_failed")
	ErrUnavailable = errors.New("tun_system_dns_unavailable")
)

const Timeout = 3 * time.Second

type Spec struct {
	Index   int32
	Token   string
	Servers []netip.Addr
}

func (s Spec) Alias() string { return "thronium-dns-" + s.Token }
func (s Spec) Validate() error {
	if s.Index <= 0 || len(s.Token) != 32 || len(s.Servers) < 1 || len(s.Servers) > 2 {
		return ErrInvalid
	}
	for _, c := range s.Token {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return ErrInvalid
		}
	}
	for i, server := range s.Servers {
		if !server.IsValid() || !server.IsPrivate() || server.Is4In6() || server.Zone() != "" || server.Is4() != (i == 0) {
			return ErrInvalid
		}
	}
	return nil
}

// Verify checks the current kernel link name, index and ownership alias. ErrGone
// is reserved for a removed link, not for an index now belonging to another link.
type Verify func(Spec) error

type DNS struct {
	Family  int32
	Address []byte
}
type Domain struct {
	Name      string
	RouteOnly bool
}

// Client is implemented by a connection pinned to one resolved service owner.
// Methods and properties passed by this package are a fixed, local allowlist.
type Client interface {
	Call(context.Context, string, ...any) error
	Property(context.Context, int32, string, any) error
}

func verify(ctx context.Context, owned Verify, spec Spec) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return owned(spec)
}
func addresses(spec Spec) []DNS {
	result := make([]DNS, 0, len(spec.Servers))
	for _, server := range spec.Servers {
		family := int32(2)
		if server.Is6() {
			family = 10
		}
		result = append(result, DNS{family, server.AsSlice()})
	}
	return result
}

// Matches reads back all DNS policy that Apply owns. A successful D-Bus call
// alone is not sufficient evidence that the resolver accepted the policy.
func Matches(parent context.Context, client Client, owned Verify, spec Spec) bool {
	ctx, cancel := context.WithTimeout(parent, Timeout)
	defer cancel()
	if spec.Validate() != nil || verify(ctx, owned, spec) != nil {
		return false
	}
	var servers []DNS
	var domains []Domain
	var defaultRoute bool
	var tls, dnssec string
	for _, property := range []struct {
		name   string
		target any
	}{
		{"DNS", &servers}, {"Domains", &domains}, {"DefaultRoute", &defaultRoute},
		{"DNSOverTLS", &tls}, {"DNSSEC", &dnssec},
	} {
		if verify(ctx, owned, spec) != nil || client.Property(ctx, spec.Index, property.name, property.target) != nil {
			return false
		}
	}
	expected := addresses(spec)
	return verify(ctx, owned, spec) == nil && len(servers) == len(expected) && slices.EqualFunc(servers, expected, func(a, b DNS) bool {
		return a.Family == b.Family && slices.Equal(a.Address, b.Address)
	}) && slices.Equal(domains, []Domain{{".", true}}) && defaultRoute && tls == "no" && dnssec == "no"
}

// Apply completes synchronously, with bounded cleanup on failure. TLS and DNSSEC
// on this virtual link are handled by the application's configured DNS transport.
// Physical links and global resolver settings are never edited.
func Apply(parent context.Context, client Client, owned Verify, spec Spec) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, Timeout)
	defer cancel()
	if err := verify(ctx, owned, spec); err != nil {
		return err
	}
	operations := []struct {
		name  string
		value any
	}{
		{"SetLinkDNS", addresses(spec)}, {"SetLinkDNSOverTLS", "no"}, {"SetLinkDNSSEC", "no"},
		{"SetLinkDomains", []Domain{{".", true}}}, {"SetLinkDefaultRoute", true},
	}
	failed := false
	for _, operation := range operations {
		if verify(ctx, owned, spec) != nil || client.Call(ctx, operation.name, spec.Index, operation.value) != nil {
			failed = true
			break
		}
	}
	if !failed && Matches(ctx, client, owned, spec) {
		return nil
	}
	cleanup, cancelCleanup := context.WithTimeout(context.Background(), Timeout)
	defer cancelCleanup()
	if Revert(cleanup, client, owned, spec) != nil {
		return ErrCleanup
	}
	return ErrApply
}

// Revert refuses a recycled or foreign link index. A deleted TUN has no policy
// to reset; the resolver follows the kernel link lifetime.
func Revert(parent context.Context, client Client, owned Verify, spec Spec) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, Timeout)
	defer cancel()
	err := verify(ctx, owned, spec)
	if errors.Is(err, ErrGone) {
		return nil
	}
	if err != nil {
		return ErrOwnership
	}
	if client.Call(ctx, "RevertLink", spec.Index) != nil {
		return ErrCleanup
	}
	if err := verify(ctx, owned, spec); errors.Is(err, ErrGone) {
		return nil
	} else if err != nil {
		return ErrOwnership
	}
	var servers []DNS
	var domains []Domain
	if client.Property(ctx, spec.Index, "DNS", &servers) != nil || client.Property(ctx, spec.Index, "Domains", &domains) != nil || len(servers) != 0 || len(domains) != 0 {
		return ErrCleanup
	}
	if err := verify(ctx, owned, spec); errors.Is(err, ErrGone) {
		return nil
	} else if err != nil {
		return ErrOwnership
	}
	return nil
}
