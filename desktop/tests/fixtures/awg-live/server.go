package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	if len(os.Args) != 4 {
		return errors.New("usage: awg-fixture NEW_DIRECTORY LOOPBACK_IP basic|protected|signatures|trailers|cookies")
	}
	mode := os.Args[3]
	if mode != "basic" && mode != "protected" && mode != "signatures" && mode != "trailers" && mode != "cookies" {
		return errors.New("unknown AWG fixture mode")
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
	if _, err := rand.Read(preShared); err != nil {
		return err
	}
	tunnel, network, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.177.43.1"), netip.MustParseAddr("fd00:43::1")}, nil, 1420)
	if err != nil {
		return err
	}
	bind := &loopbackBind{ip: ip}
	vpn := device.NewDevice(tunnel, bind, device.NewLogger(device.LogLevelError, "owned-awg51: "))
	defer vpn.Close()
	// Classify an untouched datagram with the independent peer's public parser.
	// These are decoded packet kinds, not unencrypted wire header values.
	bind.classify = func(packet []byte) (uint32, uint32) {
		if len(packet) < device.HeaderCipherNonceSize {
			return device.MessageUnknownType, 0
		}
		cipher, err := vpn.HeaderProtectionCipher(packet[:device.HeaderCipherNonceSize])
		if err != nil {
			return device.MessageUnknownType, 0
		}
		var mask [4]byte
		if cipher != nil {
			cipher.XORKeyStream(mask[:], mask[:])
		}
		_, kind, padding := vpn.DeterminePacketTypeAndPadding(packet, mask[:])
		return kind, padding
	}
	bind.hasMAC2 = func(packet []byte, padding uint32) bool {
		if len(packet) < int(padding)+device.MessageInitiationSize {
			return false
		}
		body := append([]byte(nil), packet[padding:padding+device.MessageInitiationSize]...)
		cipher, err := vpn.HeaderProtectionCipher(packet[:device.HeaderCipherNonceSize])
		if err != nil {
			return false
		}
		if cipher != nil {
			cipher.XORKeyStream(body, body)
		}
		for _, value := range body[len(body)-16:] {
			if value != 0 {
				return true
			}
		}
		return false
	}
	// basic: AmneziaWG 2.0 fields. signatures: 2.0 plus the five special junk
	// packets. protected: 3.x header protection and content padding. trailers:
	// the 3.1 client shape Amnezia hands out (single magic headers, one random
	// signature packet, fixed padding, random trailers). cookies: trailers plus
	// disabled cookies.
	awg := map[string]any{"jc": 3, "jmin": 40, "jmax": 70, "s1": 16, "s2": 32, "s3": 48, "s4": 64,
		"h1": "100001-100099", "h2": "200001-200099", "h3": "300001-300099", "h4": "400001-400099"}
	extra := "jc=3\njmin=40\njmax=70\ns1=16\ns2=32\ns3=48\ns4=64\nh1=100001-100099\nh2=200001-200099\nh3=300001-300099\nh4=400001-400099\n"
	if mode == "trailers" || mode == "cookies" {
		awg = map[string]any{"jc": 4, "jmin": 30, "jmax": 90, "s1": 72, "s2": 44, "s3": 88, "s4": 108,
			"h1": "1500000101", "h2": "1500000202", "h3": "1500000303", "h4": "1500000404"}
		extra = "jc=4\njmin=30\njmax=90\ns1=72\ns2=44\ns3=88\ns4=108\nh1=1500000101\nh2=1500000202\nh3=1500000303\nh4=1500000404\n"
	}
	if mode == "signatures" {
		for key, value := range map[string]string{"i1": "<r 96>", "i2": "<b 0x0a0b0c0d1e1f>", "i3": "<t>", "i4": "<rc 8>", "i5": "<rd 6>"} {
			awg[key] = value
			extra += key + "=" + value + "\n"
		}
	}
	if mode == "trailers" || mode == "cookies" {
		awg["i1"] = "<r 96>"
		extra += "i1=<r 96>\n"
	}
	if mode == "protected" || mode == "trailers" || mode == "cookies" {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return err
		}
		awg["header_protection_key"] = base64.StdEncoding.EncodeToString(key)
		padding := "7-14"
		if mode != "protected" {
			padding = "40"
		}
		// A plain value is a number in the profile, as the Amnezia container import stores it.
		if mode == "protected" {
			awg["content_padding_addition"] = padding
		} else {
			awg["content_padding_addition"] = 40
		}
		extra += "header_protection_key=" + hex.EncodeToString(key) + "\ncontent_padding_addition=" + padding + "\n"
	}
	if mode == "trailers" || mode == "cookies" {
		awg["random_trailers"] = true
		extra += "random_trailers=true\n"
	}
	if mode == "cookies" {
		awg["disable_cookies"] = true
		extra += "disable_cookies=true\n"
	}
	settings := extra + "private_key=" + hex.EncodeToString(serverKey.Bytes()) + "\nlisten_port=0\npublic_key=" + hex.EncodeToString(clientKey.PublicKey().Bytes()) + "\npreshared_key=" + hex.EncodeToString(preShared) + "\nallowed_ip=10.177.43.2/32\nallowed_ip=fd00:43::2/128\n"
	if err := vpn.IpcSet(settings); err != nil {
		return errors.New("configure owned AWG server failed")
	}
	if err := vpn.Up(); err != nil {
		return err
	}
	var mu sync.Mutex
	var loadPackets atomic.Uint64
	var loadSeen atomic.Bool
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
		if vpn.IsUnderLoad() {
			loadSeen.Store(true)
		}
		cookies, mac2 := bind.cookieProof()
		return writeJSON(filepath.Join(dir, "stats.json"), map[string]any{"metrics": metrics, "requests": requests, "decodedPacketTypes": bind.counts(), "wireSamples": bind.samples(), "mode": mode,
			"sentCookiePorts": cookies, "receivedMac2Ports": mac2, "loadPackets": loadPackets.Load(), "underLoadSeen": loadSeen.Load()})
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
		if (r.Method != "GET" && r.Method != "HEAD") || !strings.HasPrefix(r.URL.Path, "/fixture/") {
			http.Error(w, "fixture request rejected", 400)
			return
		}
		mu.Lock()
		requests = append(requests, map[string]string{"path": r.URL.Path, "remote": r.RemoteAddr, "method": r.Method})
		mu.Unlock()
		if err := stats(); err != nil {
			http.Error(w, "fixture stats failed", 500)
			return
		}
		w.Header().Set("Connection", "close")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "awg51:"+r.URL.Path)
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
	profile["amnezia_wg"] = awg
	ready := map[string]any{"endpoint": bind.address(), "profile": profile, "mode": mode, "http4": "http://10.177.43.1:18080", "http6": "http://[fd00:43::1]:18080", "stats": filepath.Join(dir, "stats.json")}
	if err := stats(); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "ready.json"), ready); err != nil {
		return err
	}
	fmt.Println(filepath.Join(dir, "ready.json"))
	// The optional load command sends bounded, MAC1-valid initiation datagrams
	// to this loopback peer only. Its unmodified official device decides when
	// the handshake queue is overloaded and sends real cookie replies.
	var loads sync.WaitGroup
	defer loads.Wait()
	loadErrors := make(chan error, 1)
	var loading atomic.Bool
	decoder := json.NewDecoder(os.Stdin)
	for {
		var command struct {
			Op string `json:"op"`
		}
		if err := decoder.Decode(&command); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return err
		}
		if command.Op != "load" {
			return errors.New("unknown fixture command")
		}
		if !loading.CompareAndSwap(false, true) {
			return errors.New("fixture load already running")
		}
		loads.Add(1)
		go func() {
			defer loads.Done()
			defer loading.Store(false)
			if err := handshakeLoad(vpn, bind.address(), serverKey.PublicKey().Bytes(), awg, &loadPackets); err != nil {
				select {
				case loadErrors <- err:
				default:
				}
			}
		}()
		fmt.Println(`{"started":true}`)
	}
	loads.Wait()
	select {
	case err := <-loadErrors:
		return err
	default:
	}
	// An accepted TCP connection may still be in HTTP StateNew when the core
	// disconnects. net/http waits five seconds before treating it as idle.
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
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

func handshakeLoad(vpn *device.Device, address string, public []byte, awg map[string]any, sent *atomic.Uint64) error {
	peer, err := net.Dial("udp", address)
	if err != nil {
		return err
	}
	defer peer.Close()
	var key device.NoisePublicKey
	copy(key[:], public)
	var generator device.CookieGenerator
	generator.Init(key)
	padding := awg["s1"].(int)
	first := strings.Split(awg["h1"].(string), "-")[0]
	header, err := strconv.ParseUint(first, 10, 32)
	if err != nil {
		return err
	}
	packet := make([]byte, padding+device.MessageInitiationSize)
	rand.Read(packet)
	body := packet[padding:]
	binary.LittleEndian.PutUint32(body, uint32(header))
	clear(body[len(body)-16:])
	generator.AddMacs(body)
	cipher, err := vpn.HeaderProtectionCipher(packet[:device.HeaderCipherNonceSize])
	if err != nil {
		return err
	}
	if cipher != nil {
		cipher.XORKeyStream(body, body)
	}
	deadline := time.Now().Add(10 * time.Second)
	for i := 0; i < 2000000 && time.Now().Before(deadline); i++ {
		if _, err := peer.Write(packet); err != nil {
			return err
		}
		sent.Add(1)
	}
	return nil
}
