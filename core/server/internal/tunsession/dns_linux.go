//go:build linux

package tunsession

import (
	"ThroneCore/internal/tundns"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"

	"github.com/sagernet/netlink"
)

const systemDNSVersion = 2

func validDNSRequest(mode string, config map[string]json.RawMessage) bool {
	if mode == "" {
		return true
	}
	if mode != "resolved" && mode != "resolvconf" {
		return false
	}
	var route struct {
		Rules []map[string]json.RawMessage `json:"rules"`
	}
	if json.Unmarshal(config["route"], &route) != nil || len(route.Rules) == 0 {
		return false
	}
	first := route.Rules[0]
	if len(first) != 3 {
		return false
	}
	var inbound []string
	var port int
	var action string
	return json.Unmarshal(first["inbound"], &inbound) == nil && len(inbound) == 1 && inbound[0] == Interface && json.Unmarshal(first["port"], &port) == nil && port == 53 && json.Unmarshal(first["action"], &action) == nil && action == "hijack-dns"
}
func virtualDNSAddress(cidr string) (netip.Addr, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return netip.Addr{}, tundns.ErrInvalid
	}
	address := prefix.Masked().Addr().Next()
	if address == prefix.Addr() {
		address = address.Next()
	}
	if !prefix.Contains(address) || !address.IsPrivate() {
		return netip.Addr{}, tundns.ErrInvalid
	}
	return address, nil
}
func (j *journal) dnsSpec() (tundns.Spec, error) {
	spec := tundns.Spec{Index: j.DNSIndex, Token: j.DNSToken}
	address, err := virtualDNSAddress(j.IPv4CIDR)
	if err != nil {
		return spec, err
	}
	spec.Servers = append(spec.Servers, address)
	if j.IPv6 {
		address, err = virtualDNSAddress(j.IPv6CIDR)
		if err != nil {
			return spec, err
		}
		spec.Servers = append(spec.Servers, address)
	}
	return spec, spec.Validate()
}
func (j *journal) validDNS() bool {
	if j.DNSMode == "" {
		return j.DNSIndex == 0 && j.DNSToken == ""
	}
	if (j.DNSMode != "resolved" && j.DNSMode != "resolvconf") || !validInterfaceCIDR(j.IPv4CIDR, false) || j.IPv6 && !validInterfaceCIDR(j.IPv6CIDR, true) {
		return false
	}
	if j.DNSIndex == 0 && j.DNSToken == "" {
		return true
	}
	_, err := j.dnsSpec()
	return err == nil
}
func verifyDNSLink(spec tundns.Spec) error {
	link, err := netlink.LinkByIndex(int(spec.Index))
	if err != nil {
		var missing netlink.LinkNotFoundError
		if errors.As(err, &missing) {
			return tundns.ErrGone
		}
		return tundns.ErrOwnership
	}
	attrs := link.Attrs()
	if attrs.Name != Interface || attrs.Index != int(spec.Index) || attrs.Alias != spec.Alias() || link.Type() != "tuntap" {
		return tundns.ErrOwnership
	}
	return nil
}
func (j *journal) clearDNS() error {
	if j.DNSMode == "" || j.DNSIndex == 0 {
		return nil
	}
	spec, err := j.dnsSpec()
	if err != nil {
		return err
	}
	if j.DNSMode == "resolvconf" {
		client, err := tundns.OpenResolvInstalled(context.Background())
		if err != nil {
			return err
		}
		return client.Revert(context.Background(), spec)
	}
	err = verifyDNSLink(spec)
	if errors.Is(err, tundns.ErrGone) {
		return nil
	}
	if err != nil {
		return err
	}
	client, close, err := tundns.Open(context.Background())
	if err != nil {
		return err
	}
	defer close()
	return tundns.Revert(context.Background(), client, verifyDNSLink, spec)
}
func (s *session) activateDNS() error {
	j := s.owner.active
	if j.DNSMode == "" {
		return nil
	}
	var resolvconf *tundns.OpenResolv
	if j.DNSMode == "resolvconf" {
		var err error
		resolvconf, err = tundns.OpenResolvInstalled(context.Background())
		if err != nil {
			return err
		}
	}
	link, err := netlink.LinkByName(Interface)
	if err != nil || link.Type() != "tuntap" || link.Attrs().Alias != "" {
		return tundns.ErrOwnership
	}
	assigned, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return tundns.ErrOwnership
	}
	for _, cidr := range []string{j.IPv4CIDR, j.IPv6CIDR} {
		if cidr == "" {
			continue
		}
		found := false
		for _, address := range assigned {
			if address.IPNet != nil && address.IPNet.String() == cidr {
				found = true
				break
			}
		}
		if !found {
			return tundns.ErrOwnership
		}
	}
	var token [16]byte
	if _, err = rand.Read(token[:]); err != nil {
		return tundns.ErrInvalid
	}
	j.DNSIndex = int32(link.Attrs().Index)
	j.DNSToken = fmt.Sprintf("%x", token[:])
	spec, err := j.dnsSpec()
	if err != nil {
		return err
	}
	// Persist intent before alias or resolver policy can be changed.
	if err = s.owner.write(j); err != nil {
		return fmt.Errorf("tun_journal_failed: %w", err)
	}
	if err = netlink.LinkSetAlias(link, spec.Alias()); err != nil {
		return tundns.ErrOwnership
	}
	if j.DNSMode == "resolvconf" {
		if err = resolvconf.Apply(context.Background(), verifyDNSLink, spec); err != nil {
			return err
		}
		s.resolvconf = resolvconf
		return nil
	}
	life, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-s.gone:
			cancel()
		case <-life.Done():
		}
	}()
	client, close, err := tundns.Open(life)
	if err != nil {
		cancel()
		return err
	}
	stop := func() { close(); cancel() }
	if err = tundns.Apply(life, client, verifyDNSLink, spec); err != nil {
		stop()
		return err
	}
	s.dnsClient = client
	s.dnsClose = stop
	return nil
}
func (s *session) closeDNS() {
	if s.resolvconf != nil {
		if s.owner != nil && s.owner.active != nil {
			if spec, err := s.owner.active.dnsSpec(); err == nil {
				_ = s.resolvconf.Revert(context.Background(), spec)
			}
		}
		s.resolvconf = nil
	}
	if s.dnsClient == nil {
		return
	}
	if s.owner != nil && s.owner.active != nil {
		if spec, err := s.owner.active.dnsSpec(); err == nil {
			_ = tundns.Revert(context.Background(), s.dnsClient, verifyDNSLink, spec)
		}
	}
	s.dnsClose()
	s.dnsClient = nil
	s.dnsClose = nil
}
func (s *session) dnsCurrent() bool {
	if s.owner == nil || s.owner.active == nil || s.owner.active.DNSMode == "" {
		return true
	}
	if s.owner.active.DNSMode == "resolvconf" {
		spec, err := s.owner.active.dnsSpec()
		return err == nil && s.resolvconf != nil && s.resolvconf.Matches(context.Background(), verifyDNSLink, spec)
	}
	if s.dnsClient == nil {
		return false
	}
	spec, err := s.owner.active.dnsSpec()
	return err == nil && tundns.Matches(context.Background(), s.dnsClient, verifyDNSLink, spec)
}
func dnsCleanupError(err error) bool {
	for _, kind := range []error{tundns.ErrInvalid, tundns.ErrOwnership, tundns.ErrApply, tundns.ErrCleanup, tundns.ErrUnavailable} {
		if errors.Is(err, kind) {
			return true
		}
	}
	return false
}
