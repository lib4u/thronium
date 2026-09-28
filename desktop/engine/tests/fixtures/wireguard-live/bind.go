package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"golang.zx2c4.com/wireguard/conn"
	"net"
	"net/netip"
	"sync"
)

type loopbackBind struct {
	ip netip.Addr
	// Reserved bytes this peer stamps into every packet it sends and strips
	// from every packet it receives, like a WARP-style server would.
	reserved [3]byte
	mu       sync.Mutex
	socket   *net.UDPConn
	packets  map[uint32]int
	from     map[string]int
	seen     map[string]int
	sent     map[uint32]int
}

func (b *loopbackBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.socket != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	network := "udp4"
	if b.ip.Is6() {
		network = "udp6"
	}
	c, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(b.ip, port)))
	if err != nil {
		return nil, 0, err
	}
	b.socket = c
	b.packets = map[uint32]int{}
	b.from = map[string]int{}
	b.seen = map[string]int{}
	b.sent = map[uint32]int{}
	receive := func(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
		n, from, err := c.ReadFromUDPAddrPort(packets[0])
		if err != nil {
			return 0, err
		}
		if !from.Addr().IsLoopback() {
			return 0, errors.New("non-loopback sender rejected")
		}
		sizes[0] = n
		endpoints[0] = &conn.StdNetEndpoint{AddrPort: from}
		if n >= 4 {
			b.mu.Lock()
			if r := packets[0][1:4]; r[0] != 0 || r[1] != 0 || r[2] != 0 {
				b.seen[hex.EncodeToString(r)]++
			}
			if b.reserved != ([3]byte{}) {
				clear(packets[0][1:4])
			}
			b.packets[binary.LittleEndian.Uint32(packets[0][:4])]++
			b.from[from.String()]++
			b.mu.Unlock()
		}
		return 1, nil
	}
	return []conn.ReceiveFunc{receive}, c.LocalAddr().(*net.UDPAddr).AddrPort().Port(), nil
}
func (b *loopbackBind) Close() error {
	b.mu.Lock()
	c := b.socket
	b.socket = nil
	b.mu.Unlock()
	if c != nil {
		return c.Close()
	}
	return nil
}
func (b *loopbackBind) SetMark(mark uint32) error {
	if mark != 0 {
		return errors.New("fixture refuses routing marks")
	}
	return nil
}
func (b *loopbackBind) BatchSize() int { return 1 }
func (b *loopbackBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	a, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	if !a.Addr().IsLoopback() {
		return nil, errors.New("fixture refuses external endpoints")
	}
	return &conn.StdNetEndpoint{AddrPort: a}, nil
}
func (b *loopbackBind) Send(packets [][]byte, destination conn.Endpoint) error {
	to, ok := destination.(*conn.StdNetEndpoint)
	if !ok || !to.Addr().IsLoopback() {
		return errors.New("fixture refuses external destination")
	}
	b.mu.Lock()
	c := b.socket
	b.mu.Unlock()
	if c == nil {
		return net.ErrClosed
	}
	for _, packet := range packets {
		out := packet
		if len(packet) >= 4 {
			b.mu.Lock()
			b.sent[binary.LittleEndian.Uint32(packet[:4])]++
			b.mu.Unlock()
			if b.reserved != ([3]byte{}) {
				out = append([]byte(nil), packet...)
				copy(out[1:4], b.reserved[:])
			}
		}
		if _, err := c.WriteToUDPAddrPort(out, to.AddrPort); err != nil {
			return err
		}
	}
	return nil
}
func (b *loopbackBind) reservedSeen() map[string]int {
	b.mu.Lock()
	defer b.mu.Unlock()
	r := map[string]int{}
	for k, v := range b.seen {
		r[k] = v
	}
	return r
}
func (b *loopbackBind) sentCounts() map[uint32]int {
	b.mu.Lock()
	defer b.mu.Unlock()
	r := map[uint32]int{}
	for k, v := range b.sent {
		r[k] = v
	}
	return r
}
func (b *loopbackBind) address() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.socket.LocalAddr().String()
}
func (b *loopbackBind) counts() map[uint32]int {
	b.mu.Lock()
	defer b.mu.Unlock()
	r := map[uint32]int{}
	for k, v := range b.packets {
		r[k] = v
	}
	return r
}

func (b *loopbackBind) senders() map[string]int {
	b.mu.Lock()
	defer b.mu.Unlock()
	r := map[string]int{}
	for k, v := range b.from {
		r[k] = v
	}
	return r
}
