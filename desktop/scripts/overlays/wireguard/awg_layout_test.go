// SPDX-License-Identifier: MIT
package device

import (
	"bytes"
	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/tun"
	"math"
	"testing"
)

func TestThroniumTUNLayoutChangesPreservePayloadAndTagRoom(t *testing.T) {
	base := MessageEncapsulatingTransportSize + MessageTransportHeaderSize
	for _, change := range [][2]uint32{{0, 64}, {64, 0}, {64, 96}, {96, 16}} {
		elem := &QueueOutboundElement{buffer: make([]byte, 512), isKeepalive: true}
		payload := bytes.Repeat([]byte{0x45, 0x7f, 0xab, 0x11}, 32)
		offset := base + int(change[0])
		copy(elem.buffer[offset:], payload)
		if !prepareTUNOutbound(elem, offset, len(payload), change[1]) {
			t.Fatal("valid layout refused")
		}
		if !bytes.Equal(elem.packet, payload) || elem.padding != change[1] || elem.isKeepalive {
			t.Fatal("payload or metadata lost across padding change")
		}
		if &elem.packet[0] != &elem.buffer[base+int(change[1])] {
			t.Fatal("incorrect AEAD content offset")
		}
	}
	for _, bad := range []struct {
		offset, size int
		padding      uint32
	}{{-1, 10, 0}, {0, -1, 0}, {0, 0, 0}, {1000, 4, 0}, {500, 40, 0}, {0, 500, 64}, {0, 1, math.MaxUint32}} {
		elem := &QueueOutboundElement{buffer: make([]byte, 512)}
		if prepareTUNOutbound(elem, bad.offset, bad.size, bad.padding) {
			t.Fatal("invalid layout or missing tag space accepted")
		}
	}
}

type awg51NoIOBind struct{ conn.Bind }

func (*awg51NoIOBind) BatchSize() int                          { return 2 }
func (*awg51NoIOBind) Send([][]byte, conn.Endpoint, int) error { panic("drop-only batch reached bind") }

type awg51NoIOTUN struct{ tun.Device }

func (*awg51NoIOTUN) BatchSize() int { return 2 }
func TestThroniumDroppedBatchReturnsQueueWithoutAuthenticatedTimers(t *testing.T) {
	d := &Device{}
	d.net.bind = &awg51NoIOBind{}
	d.tun.device = &awg51NoIOTUN{}
	d.PopulatePools()
	peer := &Peer{device: d}
	peer.isRunning.Store(true)
	peer.queuedOutboundPackets.Store(2)
	container := d.GetOutboundElementsContainer()
	for i := 0; i < 2; i++ {
		elem := d.GetOutboundElement()
		elem.buffer = d.GetOutboundBuffer(128)
		elem.packet = nil
		container.elems = append(container.elems, elem)
	}
	// Deliberately uninitialized timers: dropped ciphertext is not activity.
	peer.processOutboundContainer(container, make([][]byte, 0, 2))
	if peer.queuedOutboundPackets.Load() != 0 {
		t.Fatal("dropped elements leaked queue capacity")
	}
}
