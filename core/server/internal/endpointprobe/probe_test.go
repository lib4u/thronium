package endpointprobe

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestTCPConnectWithoutApplicationProtocol(t *testing.T) {
	for _, address := range []string{"127.0.0.1:0", "[::1]:0"} {
		t.Run(address, func(t *testing.T) {
			listener, err := net.Listen("tcp", address)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			host, port, _ := net.SplitHostPort(listener.Addr().String())
			p, _ := strconv.Atoi(port)
			ms, code := Run(context.Background(), "tcp", host, uint32(p), 500)
			if code != "" || ms < 0 {
				t.Fatalf("TCP: %d %s", ms, code)
			}
			conn, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetReadDeadline(time.Now().Add(time.Second))
			data := make([]byte, 16)
			if n, _ := conn.Read(data); n != 0 {
				t.Fatal("TCP probe sent application data")
			}
			listener.Close()
			_, code = Run(context.Background(), "tcp", host, uint32(p), 500)
			if code != "probe_connection_refused" {
				t.Fatalf("refused: %s", code)
			}
		})
	}
}

func TestICMPLoopback(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		ms, code := Run(context.Background(), "icmp", host, 0, 500)
		if code == "probe_icmp_unavailable" {
			t.Skip("OS disallows datagram ICMP sockets")
		}
		if code != "" || ms < 0 {
			t.Fatalf("%s: %d %s", host, ms, code)
		}
	}
}

func TestValidationAndCancellation(t *testing.T) {
	for _, c := range []struct {
		method, host  string
		port, timeout uint32
	}{
		{"http", "127.0.0.1", 80, 500}, {"tcp", "127.0.0.1", 0, 500}, {"tcp", "127.0.0.1", 65536, 500},
		{"icmp", "127.0.0.1", 0, 99}, {"icmp", "127.0.0.1", 0, 10001}, {"icmp", "https://secret@example.test", 0, 500},
	} {
		if _, code := Run(context.Background(), c.method, c.host, c.port, c.timeout); code != "probe_invalid_options" {
			t.Fatal(code)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, code := Run(ctx, "tcp", "127.0.0.1", 80, 10000)
	if code != "probe_cancelled" || time.Since(start) > time.Second {
		t.Fatalf("cancel: %s", code)
	}
}
