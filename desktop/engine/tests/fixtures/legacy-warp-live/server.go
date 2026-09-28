package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".writing"
	if err = os.WriteFile(tmp, append(data, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
func run() error {
	if len(os.Args) != 3 {
		return errors.New("usage: wg-fixture NEW_DIRECTORY LOOPBACK_IP")
	}
	ip, err := netip.ParseAddr(os.Args[2])
	if err != nil || !ip.IsLoopback() {
		return errors.New("fixture requires literal loopback IP")
	}
	dir := os.Args[1]
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	clientKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	preShared := make([]byte, 32)
	// WARP has no PSK; the all-zero WireGuard PSK means disabled.
	tunnel, network, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.177.43.1"), netip.MustParseAddr("fd00:43::1")}, nil, 1420)
	if err != nil {
		return err
	}
	bind := &loopbackBind{ip: ip}
	vpn := device.NewDevice(tunnel, bind, device.NewLogger(device.LogLevelError, "owned-wg43: "))
	defer vpn.Close()
	settings := "private_key=" + hex.EncodeToString(serverKey.Bytes()) + "\nlisten_port=0\npublic_key=" + hex.EncodeToString(clientKey.PublicKey().Bytes()) + "\npreshared_key=" + hex.EncodeToString(preShared) + "\nallowed_ip=10.177.43.2/32\nallowed_ip=fd00:43::2/128\n"
	if err := vpn.IpcSet(settings); err != nil {
		return errors.New("configure owned WG server failed")
	}
	if err := vpn.Up(); err != nil {
		return err
	}
	var mu sync.Mutex
	requests := []map[string]string{}
	stats := func() error {
		mu.Lock()
		defer mu.Unlock()
		ipc, err := vpn.IpcGet()
		if err != nil {
			return err
		}
		metrics := map[string]int64{}
		for _, line := range strings.Split(ipc, "\n") {
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			switch key {
			case "rx_bytes", "tx_bytes", "last_handshake_time_sec", "last_handshake_time_nsec":
				n, err := strconv.ParseInt(value, 10, 64)
				if err != nil {
					return err
				}
				metrics[key] = n
			}
		}
		return writeJSON(filepath.Join(dir, "stats.json"), map[string]any{"metrics": metrics, "requests": requests, "receivedWirePacketTypes": bind.counts()})
	}
	stopStats, statsDone := make(chan struct{}), make(chan struct{})
	statsErrors := make(chan error, 1)
	go func() {
		defer close(statsDone)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopStats:
				return
			case <-ticker.C:
				if err := stats(); err != nil {
					statsErrors <- err
					return
				}
			}
		}
	}()
	defer func() { close(stopStats); <-statsDone }()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || !strings.HasPrefix(r.URL.Path, "/fixture/") {
			http.Error(w, "fixture request rejected", 400)
			return
		}
		mu.Lock()
		requests = append(requests, map[string]string{"path": r.URL.Path, "remote": r.RemoteAddr})
		mu.Unlock()
		if err := stats(); err != nil {
			http.Error(w, "fixture stats failed", 500)
			return
		}
		w.Header().Set("Connection", "close")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "wg43:"+r.URL.Path)
	})
	var servers []*http.Server
	var wg sync.WaitGroup
	defer func() {
		for _, s := range servers {
			s.Close()
		}
		wg.Wait()
	}()
	for _, ip := range []string{"10.177.43.1", "fd00:43::1"} {
		listener, err := network.ListenTCP(&net.TCPAddr{IP: net.ParseIP(ip), Port: 18080})
		if err != nil {
			return err
		}
		s := &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: time.Second}
		servers = append(servers, s)
		wg.Go(func() {
			if err := s.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				fmt.Fprintln(os.Stderr, "owned HTTP server:", err)
			}
		})
	}
	_, portText, err := net.SplitHostPort(bind.address())
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return err
	}
	encode := base64.StdEncoding.EncodeToString
	profile := map[string]any{"type": "wireguard", "private_key": encode(clientKey.Bytes()), "address": []string{"10.177.43.2/32", "fd00:43::2/128"}, "mtu": 1420, "system": false, "peers": []any{map[string]any{"address": ip.String(), "port": port, "public_key": encode(serverKey.PublicKey().Bytes()), "pre_shared_key": encode(preShared), "allowed_ips": []string{"10.177.43.1/32", "fd00:43::1/128"}}}}
	ready := map[string]any{"endpoint": bind.address(), "profile": profile, "http4": "http://10.177.43.1:18080", "http6": "http://[fd00:43::1]:18080", "stats": filepath.Join(dir, "stats.json")}
	if err := stats(); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "ready.json"), ready); err != nil {
		return err
	}
	fmt.Println(filepath.Join(dir, "ready.json"))
	_, err = io.Copy(io.Discard, os.Stdin)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, s := range servers {
		if err := s.Shutdown(ctx); err != nil {
			return err
		}
	}
	select {
	case err := <-statsErrors:
		return err
	default:
	}
	return stats()
}
