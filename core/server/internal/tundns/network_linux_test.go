//go:build linux

package tundns

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestNetworkFingerprintExcludesOwnRecordAndRenewalComments(t *testing.T) {
	token := strings.Repeat("a", 32)
	keys := "eth0.dhcp thronium-tun.thronium-" + token + " wlan0:dhcp\n"
	body := "# resolv.conf from eth0.dhcp\nsearch old.test\nnameserver 192.0.2.53\n\n# resolv.conf from wlan0:dhcp\nnameserver 198.51.100.53\n"
	calls := 0
	c := &OpenResolv{command: func(_ context.Context, input string, args ...string) (string, int, error) {
		calls++
		if input != "" {
			t.Fatal("write")
		}
		if len(args) == 1 && args[0] == "-i" {
			return keys, 0, nil
		}
		if len(args) != 2 || args[0] != "-l" || (args[1] != "eth0.dhcp" && args[1] != "wlan0:dhcp") {
			t.Fatal("unsafe query", args)
		}
		return body, 0, nil
	}}
	first, err := c.NetworkFingerprint(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	keys = "wlan0:dhcp thronium-tun.thronium-" + token + " eth0.dhcp\n"
	body = strings.ReplaceAll(body, "nameserver ", "nameserver   ") + "# renewed now\n"
	same, err := c.NetworkFingerprint(context.Background(), token)
	if err != nil || same != first {
		t.Fatal("renewal changed fingerprint", err)
	}
	body = strings.ReplaceAll(body, "192.0.2.53", "203.0.113.53")
	next, err := c.NetworkFingerprint(context.Background(), token)
	if err != nil || next == first || calls != 9 {
		t.Fatal("DNS update missed", err, calls)
	}
}

func TestNetworkFingerprintBoundsAndReadFailures(t *testing.T) {
	for _, keys := range []string{"-a", "../file", "eth*", "eth0 eth0", "eth0;id", strings.Repeat("x", 257), strings.Repeat("eth0 ", 129)} {
		t.Run(keys[:min(len(keys), 20)], func(t *testing.T) {
			calls := 0
			c := &OpenResolv{command: func(context.Context, string, ...string) (string, int, error) { calls++; return keys, 0, nil }}
			if _, err := c.NetworkFingerprint(context.Background(), ""); err == nil || calls != 1 {
				t.Fatal("unsafe args dispatched", err, calls)
			}
		})
	}
	for _, step := range []string{"list-error", "read-error", "deleted", "oversize", "nul", "canceled"} {
		t.Run(step, func(t *testing.T) {
			c := &OpenResolv{command: func(ctx context.Context, _ string, args ...string) (string, int, error) {
				if ctx.Err() != nil {
					return "", -1, ctx.Err()
				}
				if args[0] == "-i" {
					if step == "list-error" {
						return "", 1, nil
					}
					return "eth0", 0, nil
				}
				switch step {
				case "read-error":
					return "", -1, errors.New("read")
				case "deleted":
					return "", 2, nil
				case "oversize":
					return strings.Repeat("x", 65537), 0, nil
				case "nul":
					return "bad\x00", 0, nil
				}
				return "nameserver 192.0.2.53", 0, nil
			}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if step == "canceled" {
				cancel()
			}
			if _, err := c.NetworkFingerprint(ctx, ""); err == nil {
				t.Fatal("inconclusive read accepted")
			}
		})
	}
	c := &OpenResolv{command: func(context.Context, string, ...string) (string, int, error) {
		t.Fatal("invalid token dispatched")
		return "", 0, nil
	}}
	if _, err := c.NetworkFingerprint(context.Background(), "wrong"); err == nil {
		t.Fatal("invalid token")
	}
}

func TestNetworkFingerprintPreservesPerKeyBoundaries(t *testing.T) {
	records := map[string]string{"eth0": "nameserver 192.0.2.53\n", "wlan0": "nameserver 198.51.100.53\n"}
	c := &OpenResolv{command: func(_ context.Context, _ string, args ...string) (string, int, error) {
		if args[0] == "-i" {
			return "eth0 wlan0", 0, nil
		}
		return "# resolv.conf from " + args[1] + "\n" + records[args[1]], 0, nil
	}}
	before, err := c.NetworkFingerprint(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	records["wlan0"] = records["eth0"] + records["wlan0"]
	records["eth0"] = ""
	after, err := c.NetworkFingerprint(context.Background(), "")
	if err != nil || before == after {
		t.Fatal("moving DNS between network keys was missed", err)
	}
}
