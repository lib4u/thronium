//go:build linux

package tundns

import (
	"context"
	"os"
	"strings"
	"testing"
)

// Executed only by the namespace wrapper with pinned genuine openresolv scripts.
func TestOpenResolvInstalledIntegration(t *testing.T) {
	if os.Getenv("THRONIUM_OPENRESOLV_PRIVATE_FIXTURE") != "1" {
		t.Skip("requires private namespace fixture")
	}
	original := os.Getenv("THRONIUM_TEST_ORIGINAL_NETNS")
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil || original == "" || original == current || os.Geteuid() != 0 {
		t.Fatal("host execution forbidden")
	}
	c, err := OpenResolvInstalled(context.Background())
	if err != nil {
		t.Fatal("installed", err)
	}
	s := resolvSpec()
	s.Servers = s.Servers[:1]
	owned := func(Spec) error { return nil }
	call := func(body string, args ...string) {
		t.Helper()
		_, code, err := c.command(context.Background(), body, args...)
		if err != nil || code != 0 {
			t.Fatal(args, code, err)
		}
	}
	before, err := c.NetworkFingerprint(context.Background(), "")
	if err != nil {
		t.Fatal("network before", err)
	}
	if err = c.Apply(context.Background(), owned, s); err != nil {
		t.Fatal("apply", err)
	}
	t.Log("PASS installed genuine openresolv applies and verifies owned DNS")
	after, err := c.NetworkFingerprint(context.Background(), s.Token)
	if err != nil || before != after {
		t.Fatal("own record triggered network change", err)
	}
	call("search new.test\nnameserver 198.51.100.53\n", "-a", "eth0.dhcp")
	updated, err := c.NetworkFingerprint(context.Background(), s.Token)
	if err != nil || updated == before {
		t.Fatal("DHCP change not observed", err)
	}
	call("# DHCP renewal\nsearch new.test\nnameserver 198.51.100.53\n", "-a", "eth0.dhcp")
	renewed, err := c.NetworkFingerprint(context.Background(), s.Token)
	if err != nil || renewed != updated {
		t.Fatal("renewal comment changed DNS", err)
	}
	t.Log("PASS physical DNS fingerprint excludes owned exclusive record and renewal comments")
	if !c.Matches(context.Background(), owned, s) {
		t.Fatal("DHCP displaced owned DNS")
	}
	if err = c.Revert(context.Background(), s); err != nil {
		t.Fatal("revert", err)
	}
	body, _ := c.readResolver()
	if !strings.Contains(string(body), "198.51.100.53") || strings.Contains(string(body), "192.0.2.53") {
		t.Fatal("latest DHCP not restored")
	}
	t.Log("PASS removing own record restores current DHCP DNS and search")
	if err = c.Revert(context.Background(), s); err != nil {
		t.Fatal("second revert", err)
	}
	// Actual exclusive semantics, including a new VPN taking priority during use.
	if err = c.Apply(context.Background(), owned, s); err != nil {
		t.Fatal(err)
	}
	call("nameserver 203.0.113.53\n", "-x", "-a", "other.vpn")
	if c.Matches(context.Background(), owned, s) {
		t.Fatal("foreign exclusive change ignored")
	}
	if err = c.Revert(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	body, _ = c.readResolver()
	if !strings.Contains(string(body), "203.0.113.53") {
		t.Fatal("foreign DNS removed")
	}
	if err = c.Apply(context.Background(), owned, s); err != ErrOwnership {
		t.Fatal("competing exclusive accepted", err)
	}
	call("", "-f", "-d", "other.vpn")
	t.Log("PASS competing VPN keeps its record and prevents reasserting exclusive DNS")
	// Marked records are durable independently of a kernel interface lifetime.
	call(resolvBody(s), "-m", "0", "-x", "-a", resolvKey(s))
	fresh, err := OpenResolvInstalled(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err = fresh.Revert(context.Background(), s); err != nil {
		t.Fatal("reopened recovery", err)
	}
	t.Log("PASS new client recovers a durable record without requiring a kernel link")
	call("# replacement\nnameserver 192.0.2.88\n", "-a", resolvKey(s))
	if err = fresh.Revert(context.Background(), s); err != ErrOwnership {
		t.Fatal("foreign same-key deleted", err)
	}
	out, code, err := c.command(context.Background(), "", "-l", resolvKey(s))
	if err != nil || code != 0 || !strings.Contains(out, "# replacement") {
		t.Fatal("foreign record changed")
	}
	call("", "-f", "-d", resolvKey(s))
	t.Log("PASS modified token record survives attempted recovery")
	// A real subscriber failure removes the key but sets openresolv's error flag;
	// forced deletion on the next cleanup must retry generating the current file.
	if err = c.Apply(context.Background(), owned, s); err != nil {
		t.Fatal(err)
	}
	subscriber := "/run/thronium-openresolv/libexec/libc"
	originalSubscriber, err := os.ReadFile(subscriber)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(subscriber, []byte("#!/bin/sh\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err = c.Revert(context.Background(), s); err != ErrCleanup {
		t.Fatal("subscriber failure ignored", err)
	}
	if err = os.WriteFile(subscriber, originalSubscriber, 0755); err != nil {
		t.Fatal(err)
	}
	if err = fresh.Revert(context.Background(), s); err != nil {
		t.Fatal("subscriber recovery", err)
	}
	t.Log("PASS failed subscriber cleanup retries through openresolv's own error journal")
}
