package wireguard

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"sync"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/device"
	"github.com/sagernet/wireguard-go/tun"
)

// A TUN that never carries packets: enough to configure peers through UAPI.
type idleTUN struct {
	events chan tun.Event
	done   chan struct{}
	once   sync.Once
}

func (t *idleTUN) File() *os.File                               { return nil }
func (t *idleTUN) Read(_ [][]byte, _ []int, _ int) (int, error) { <-t.done; return 0, os.ErrClosed }
func (t *idleTUN) Write(_ [][]byte, _ int) (int, error)         { return 0, nil }
func (t *idleTUN) MTU() (int, error)                            { return 1420, nil }
func (t *idleTUN) Name() (string, error)                        { return "idle", nil }
func (t *idleTUN) Events() <-chan tun.Event                     { return t.events }
func (t *idleTUN) Close() error                                 { t.once.Do(func() { close(t.done) }); return nil }
func (t *idleTUN) BatchSize() int                               { return 1 }

func TestDomainPeerKeepaliveIsAppliedAfterTheResolverExists(t *testing.T) {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peer := peerConfig{destination: M.ParseSocksaddrHostPort("localhost", 51820), publicKeyHex: hex.EncodeToString(peerKey.PublicKey().Bytes()), keepalive: "1"}
	if strings.Contains(peer.GenerateIpcLines(), "persistent_keepalive") {
		t.Fatal("domain peer keepalive must not be part of the initial configuration")
	}
	literal := peer
	literal.destination = M.Socksaddr{}
	literal.endpoint = M.ParseSocksaddrHostPort("127.0.0.1", 51820).AddrPort()
	if !strings.Contains(literal.GenerateIpcLines(), "persistent_keepalive_interval=1") {
		t.Fatal("literal peer keepalive stays in the initial configuration")
	}
	wg := device.NewDevice(context.Background(), &idleTUN{events: make(chan tun.Event), done: make(chan struct{})}, conn.NewDefaultBind(nil), &device.Logger{Verbosef: func(string, ...any) {}, Errorf: func(string, ...any) {}}, 1)
	defer wg.Close()
	if err := wg.IpcSet("private_key=" + hex.EncodeToString(private.Bytes()) + peer.GenerateIpcLines() + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := applyDeferredKeepalive(wg, []peerConfig{peer}); err != nil {
		t.Fatal(err)
	}
	state, err := wg.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(state, "persistent_keepalive_interval=1") || strings.Count(state, "public_key=") != 1 {
		t.Fatal("deferred keepalive did not update the existing peer in place")
	}
}
