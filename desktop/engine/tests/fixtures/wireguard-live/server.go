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
	"golang.org/x/net/dns/dnsmessage"
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
	if len(os.Args) != 3 && len(os.Args) != 4 {
		return errors.New("usage: wg-fixture NEW_DIRECTORY LOOPBACK_IP [PRIVATE_OPTIONS_JSON]")
	}
	options := struct {
		NoPresharedKey   bool     `json:"noPresharedKey"`
		DNS              bool     `json:"dns"`
		Subnet           int      `json:"subnet"`
		ClientPrivateKey string   `json:"clientPrivateKey"`
		ListenPort       uint16   `json:"listenPort"`
		ForwardPorts     []uint16 `json:"forwardPorts"`
		Reserved         []uint8  `json:"reserved"`
	}{Subnet: 43}
	if len(os.Args) == 4 {
		data, err := os.ReadFile(os.Args[3])
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &options); err != nil || options.Subnet < 43 || options.Subnet > 254 || (len(options.Reserved) != 0 && len(options.Reserved) != 3) {
			return errors.New("invalid owned WG fixture options")
		}
	}
	server4 := fmt.Sprintf("10.177.%d.1", options.Subnet)
	server6 := fmt.Sprintf("fd00:%d::1", options.Subnet)
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
	if options.ClientPrivateKey != "" {
		data, decodeErr := base64.StdEncoding.DecodeString(options.ClientPrivateKey)
		if decodeErr != nil {
			return errors.New("invalid owned client key")
		}
		clientKey, err = ecdh.X25519().NewPrivateKey(data)
		if err != nil {
			return errors.New("invalid owned client key")
		}
	}
	preShared := make([]byte, 32)
	if _, err := rand.Read(preShared); err != nil {
		return err
	}
	if options.NoPresharedKey {
		clear(preShared)
	}
	tunnel, network, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(server4), netip.MustParseAddr(server6)}, nil, 1420)
	if err != nil {
		return err
	}
	bind := &loopbackBind{ip: ip}
	copy(bind.reserved[:], options.Reserved)
	vpn := device.NewDevice(tunnel, bind, device.NewLogger(device.LogLevelError, "owned-wg43: "))
	defer vpn.Close()
	settings := "private_key=" + hex.EncodeToString(serverKey.Bytes()) + "\nlisten_port=" + strconv.Itoa(int(options.ListenPort)) + "\npublic_key=" + hex.EncodeToString(clientKey.PublicKey().Bytes()) + "\npreshared_key=" + hex.EncodeToString(preShared) + "\nallowed_ip=10.177.43.2/32\nallowed_ip=fd00:43::2/128\n"
	if err := vpn.IpcSet(settings); err != nil {
		return errors.New("configure owned WG server failed")
	}
	if err := vpn.Up(); err != nil {
		return err
	}
	var mu sync.Mutex
	requests := []map[string]string{}
	dnsRequests := 0
	forwarded := map[string]int{}
	forwardedFrom := []string{}
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
		return writeJSON(filepath.Join(dir, "stats.json"), map[string]any{"metrics": metrics, "requests": requests, "dnsRequests": dnsRequests, "receivedWirePacketTypes": bind.counts(), "sentWirePacketTypes": bind.sentCounts(), "reservedSeen": bind.reservedSeen(), "receivedFrom": bind.senders(), "forwarded": forwarded, "forwardedFrom": forwardedFrom})
	}
	if options.DNS {
		listener, err := network.ListenUDP(&net.UDPAddr{IP: net.ParseIP(server4), Port: 53})
		if err != nil {
			return err
		}
		done := make(chan struct{})
		defer func() { listener.Close(); <-done }()
		go func() {
			defer close(done)
			buffer := make([]byte, 4096)
			for {
				n, addr, err := listener.ReadFrom(buffer)
				if err != nil {
					return
				}
				var query dnsmessage.Message
				if query.Unpack(buffer[:n]) != nil || len(query.Questions) != 1 {
					continue
				}
				question := query.Questions[0]
				response := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, RecursionAvailable: true}, Questions: query.Questions}
				if question.Name.String() == "warp.fixture.test." {
					if question.Type == dnsmessage.TypeA {
						response.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 1}, Body: &dnsmessage.AResource{A: netip.MustParseAddr(server4).As4()}}}
					}
				} else {
					response.RCode = dnsmessage.RCodeNameError
				}
				packet, err := response.Pack()
				if err != nil {
					continue
				}
				mu.Lock()
				dnsRequests++
				mu.Unlock()
				_, _ = listener.WriteTo(packet, addr)
			}
		}()
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
	for _, ip := range []string{server4, server6} {
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
	// Owned services outside the tunnel become reachable at the server's tunnel
	// addresses: every accepted in-tunnel connection is relayed to the same
	// port on loopback, and its inner source address is recorded.
	var forwarders []net.Listener
	relays := map[net.Conn]struct{}{}
	closeRelays := func() {
		mu.Lock()
		defer mu.Unlock()
		for _, l := range forwarders {
			l.Close()
		}
		for c := range relays {
			c.Close()
		}
	}
	defer closeRelays()
	for _, forwardPort := range options.ForwardPorts {
		for _, ip := range []string{server4, server6} {
			listener, err := network.ListenTCP(&net.TCPAddr{IP: net.ParseIP(ip), Port: int(forwardPort)})
			if err != nil {
				return err
			}
			forwarders = append(forwarders, listener)
			target := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(forwardPort)))
			key := strconv.Itoa(int(forwardPort))
			wg.Go(func() {
				for {
					client, err := listener.Accept()
					if err != nil {
						return
					}
					mu.Lock()
					forwarded[key]++
					forwardedFrom = append(forwardedFrom, client.RemoteAddr().String())
					relays[client] = struct{}{}
					mu.Unlock()
					wg.Go(func() {
						defer func() {
							client.Close()
							mu.Lock()
							delete(relays, client)
							mu.Unlock()
						}()
						upstream, err := net.DialTimeout("tcp", target, 3*time.Second)
						if err != nil {
							return
						}
						defer upstream.Close()
						mu.Lock()
						relays[upstream] = struct{}{}
						mu.Unlock()
						done := make(chan struct{})
						go func() { _, _ = io.Copy(upstream, client); close(done) }()
						_, _ = io.Copy(client, upstream)
						<-done
					})
				}
			})
		}
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
	profile := map[string]any{"type": "wireguard", "private_key": encode(clientKey.Bytes()), "address": []string{"10.177.43.2/32", "fd00:43::2/128"}, "mtu": 1420, "system": false, "peers": []any{map[string]any{"address": ip.String(), "port": port, "public_key": encode(serverKey.PublicKey().Bytes()), "pre_shared_key": encode(preShared), "allowed_ips": []string{server4 + "/32", server6 + "/128"}}}}
	ready := map[string]any{"endpoint": bind.address(), "profile": profile, "http4": "http://" + server4 + ":18080", "http6": "http://[" + server6 + "]:18080", "stats": filepath.Join(dir, "stats.json"), "tunnel4": server4, "tunnel6": server6, "forwardPorts": options.ForwardPorts}
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
	closeRelays()
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
