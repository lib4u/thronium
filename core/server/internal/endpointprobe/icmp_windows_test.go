//go:build windows

package endpointprobe

import (
	"context"
	"testing"
)

// Loopback needs no default interface, so this runs on any Windows machine.
func TestWindowsEchoAnswersFromLoopback(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		if _, code := Run(context.Background(), "icmp", host, 0, 2000); code != "" {
			t.Fatal(host, code)
		}
	}
}

func TestWindowsEchoCancellationAnswersAtOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, code := Run(ctx, "icmp", "127.0.0.1", 0, 2000); code != "probe_cancelled" {
		t.Fatal(code)
	}
}
