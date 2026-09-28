//go:build linux

package main

import (
	"ThroneCore/gen"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"testing"
)

func TestWireGuardFixedPortStartFailsBeforeTrafficAndCanRetry(t *testing.T) {
	// A localhost-named peer is local by definition and starts eagerly too.
	for _, tc := range []struct{ name, network, host string }{
		{"udp4", "udp4", "127.0.0.1"}, {"udp6", "udp6", "::1"}, {"localhost", "udp4", "localhost"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			_, _ = globalServer.Stop(ctx, &gen.EmptyReq{})
			t.Cleanup(func() { _, _ = globalServer.Stop(ctx, &gen.EmptyReq{}) })
			network, host := tc.network, tc.host
			address := "127.0.0.1:0"
			if network == "udp6" {
				address = "[::1]:0"
			}
			blocker, err := net.ListenPacket(network, address)
			if err != nil {
				t.Fatal(err)
			}
			defer blocker.Close()
			port := blocker.LocalAddr().(*net.UDPAddr).Port
			key, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			// A distinct peer key: wireguard-go silently drops a peer that carries
			// the device's own public key, which would hide the domain-peer path.
			peerKey, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			private := base64.StdEncoding.EncodeToString(key.Bytes())
			config, err := json.Marshal(map[string]any{
				"log": map[string]any{"disabled": true},
				"endpoints": []any{map[string]any{
					"type": "wireguard", "tag": "proxy", "system": false,
					"private_key": private, "listen_port": port,
					"address": []string{"10.177.43.2/32"},
					"peers": []any{map[string]any{"address": host, "port": 9,
						"public_key":  base64.StdEncoding.EncodeToString(peerKey.PublicKey().Bytes()),
						"allowed_ips": []string{"10.177.43.1/32"}}},
				}},
				"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
				"route":     map[string]any{"final": "proxy", "auto_detect_interface": true},
			})
			if err != nil {
				t.Fatal(err)
			}
			request := &gen.LoadConfigReq{CoreConfig: To(string(config)), NeedXray: To(false), DisableStats: To(true)}
			reply, _ := globalServer.Start(ctx, request)
			for _, secret := range []string{private, hex.EncodeToString(key.Bytes())} {
				if strings.Contains(reply.GetError(), secret) {
					t.Fatal("WireGuard Start error disclosed private key material")
				}
			}
			if reply.GetError() == "" || currentBox() != nil {
				t.Fatal("occupied fixed port was accepted before any traffic")
			}
			blocker.Close()
			reply, _ = globalServer.Start(ctx, request)
			if reply.GetError() != "" || currentBox() == nil {
				t.Fatalf("released fixed port could not start; failed candidate left resources or startup state: %s", reply.GetError())
			}
			reply, _ = globalServer.Stop(ctx, &gen.EmptyReq{})
			if reply.GetError() != "" {
				t.Fatal("WireGuard Stop failed")
			}
			listener, err := net.ListenPacket(network, net.JoinHostPort(host, strconv.Itoa(port)))
			if err != nil {
				t.Fatal("WireGuard Stop retained its fixed port")
			}
			listener.Close()
		})
	}
}
