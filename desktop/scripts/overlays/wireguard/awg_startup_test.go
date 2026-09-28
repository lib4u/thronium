// SPDX-License-Identifier: MIT
package device_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/device"
	"github.com/sagernet/wireguard-go/tun"
	"sync"
	"testing"
	"time"
)

type awg51ReadGate struct {
	*testTUN
	first       sync.Once
	readStarted chan int
	received    chan []byte
}

func (g *awg51ReadGate) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	g.first.Do(func() { g.readStarted <- offset })
	return g.testTUN.Read(bufs, sizes, offset)
}
func (g *awg51ReadGate) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		select {
		case g.received <- append([]byte(nil), b[offset:]...):
		default:
		}
	}
	return len(bufs), nil
}
func awg51Device(t *testing.T, name string) (*device.Device, *awg51ReadGate) {
	t.Helper()
	g := &awg51ReadGate{testTUN: &testTUN{name: name, inbound: make(chan []byte, 1), events: make(chan tun.Event), done: make(chan struct{})}, readStarted: make(chan int, 1), received: make(chan []byte, 4)}
	d := device.NewDevice(context.Background(), g, conn.NewStdNetBind(nil), &device.Logger{Verbosef: func(string, ...any) {}, Errorf: t.Logf}, 1)
	t.Cleanup(d.Close)
	select {
	case offset := <-g.readStarted:
		if offset != device.MessageEncapsulatingTransportSize+device.MessageTransportHeaderSize {
			t.Fatalf("initial Read offset %d", offset)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("initial TUN Read did not block")
	}
	return d, g
}

// The first read is deliberately already blocked with S4=0 before IPC enables
// header protection. A real Noise exchange must deliver its very first payload.
func TestThroniumAWGFirstReadBeforeConfiguration(t *testing.T) {
	serverPriv, serverPub := generateTestKeyPair(t)
	clientPriv, clientPub := generateTestKeyPair(t)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	settings := "s1=16\ns2=32\ns3=48\ns4=64\nh1=100001-100099\nh2=200001-200099\nh3=300001-300099\nh4=400001-400099\nheader_protection_key=" + hex.EncodeToString(key) + "\ncontent_padding_addition=7-14\n"
	server, serverTUN := awg51Device(t, "awg51-server")
	if err := server.IpcSet(settings + "private_key=" + serverPriv + "\nlisten_port=0\npublic_key=" + clientPub + "\nallowed_ip=10.0.0.2/32\n"); err != nil {
		t.Fatal(err)
	}
	if err := server.Up(); err != nil {
		t.Fatal(err)
	}
	client, clientTUN := awg51Device(t, "awg51-client")
	if err := client.IpcSet(settings + "private_key=" + clientPriv + "\nlisten_port=0\npublic_key=" + serverPub + "\nallowed_ip=10.0.0.1/32\nendpoint=" + fmt.Sprintf("127.0.0.1:%d", devicePort(t, server)) + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := client.Up(); err != nil {
		t.Fatal(err)
	}
	packet := buildTestPacket()
	clientTUN.inbound <- packet
	select {
	case actual := <-serverTUN.received:
		if !bytes.Equal(actual, packet) {
			t.Fatal("first protected payload was corrupted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first protected payload was dropped after initial IPC configuration")
	}
}
