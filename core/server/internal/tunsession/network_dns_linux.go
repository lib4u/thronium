//go:build linux

package tunsession

import (
	"ThroneCore/internal/tundns"
	"context"
	"log"
	"time"
)

// Require the same changed records on two watchdog polls. Transient removal,
// replacement bursts and read errors never commit a pending network change.
type networkDNSWatch struct {
	baseline  [32]byte
	ready     bool
	candidate [32]byte
	since     time.Time
}

func (w *networkDNSWatch) seed(fingerprint [32]byte) {
	*w = networkDNSWatch{baseline: fingerprint, ready: true}
}

func (w *networkDNSWatch) observe(fingerprint [32]byte, now time.Time) bool {
	if !w.ready {
		w.seed(fingerprint)
		return false
	}
	if fingerprint == w.baseline {
		w.since = time.Time{}
		return false
	}
	if w.since.IsZero() || w.candidate != fingerprint {
		w.candidate, w.since = fingerprint, now
		return false
	}
	return now.Sub(w.since) >= 5*time.Second
}

// Capture before the worker snapshots /etc/resolv.conf, not after DNS activation.
// A DHCP update racing Start will therefore still be seen by a later watchdog.
func (s *session) prepareNetworkDNS() error {
	s.networkDNS = networkDNSWatch{}
	if !s.enabled || !s.pinSystemResolver() {
		return nil
	}
	c, err := tundns.OpenResolvInstalled(context.Background())
	if err != nil {
		return err
	}
	fingerprint, err := c.NetworkFingerprint(context.Background(), "")
	if err != nil {
		return err
	}
	s.networkDNS.seed(fingerprint)
	return nil
}

func (s *session) networkDNSChanged(now time.Time) bool {
	if !s.enabled || !s.pinSystemResolver() || s.resolvconf == nil || !s.networkDNS.ready {
		s.networkDNS.since = time.Time{}
		return false
	}
	fingerprint, err := s.resolvconf.NetworkFingerprint(context.Background(), s.owner.active.DNSToken)
	if err != nil {
		// Keep an otherwise healthy connection on an inconclusive observation.
		// dnsCurrent separately checks ownership and the actual active resolver.
		s.networkDNS.since = time.Time{}
		return false
	}
	if !s.networkDNS.observe(fingerprint, now) {
		return false
	}
	log.Print("TUN physical DNS records changed; scheduling automatic reconnect")
	return true
}
