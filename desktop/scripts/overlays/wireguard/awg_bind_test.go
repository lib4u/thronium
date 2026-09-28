// SPDX-License-Identifier: MIT
package conn

import (
	"errors"
	"net"
	"syscall"
	"testing"
)

func TestThroniumEmptySendDoesNotRequireSocketOrEndpoint(t *testing.T) {
	bind := NewStdNetBind(nil)
	for _, buffers := range [][][]byte{nil, make([][]byte, 0)} {
		if err := bind.Send(buffers, nil, 8); err != nil {
			t.Fatal(err)
		}
	}
}

func TestThroniumFixedPortCollisionFailsAndReleasesSockets(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			address := "127.0.0.1:0"
			if network == "udp6" {
				address = "[::1]:0"
			}
			blocker, err := net.ListenPacket(network, address)
			if err != nil {
				t.Fatal(err)
			}
			defer blocker.Close()
			port := uint16(blocker.LocalAddr().(*net.UDPAddr).Port)
			bind := NewStdNetBind(nil)
			defer bind.Close()
			if _, _, err := bind.Open(port); !errors.Is(err, syscall.EADDRINUSE) {
				t.Fatalf("occupied %s port did not fail: %v", network, err)
			}
			blocker.Close()
			// The partially opened opposite-family socket must have been closed.
			_, actual, err := bind.Open(port)
			if err != nil || actual != port {
				t.Fatalf("retry after releasing the port failed: %d %v", actual, err)
			}
		})
	}
}
