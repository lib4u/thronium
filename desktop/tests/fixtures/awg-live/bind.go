package main

import (
	"encoding/binary"
	"errors"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"net"
	"net/netip"
	"sync"
)

type loopbackBind struct {
	ip       netip.Addr
	mu       sync.Mutex
	socket   *net.UDPConn
	packets  map[uint32]int
	classify func([]byte) (uint32, uint32)
	wire     []map[string]uint32
	cookies  map[uint16]int
	mac2     map[uint16]int
	hasMAC2  func([]byte, uint32) bool
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
	b.cookies = map[uint16]int{}
	b.mac2 = map[uint16]int{}
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
			kind, padding := b.classify(packets[0][:n])
			b.packets[kind]++
			if kind == 1 && b.hasMAC2 != nil && b.hasMAC2(packets[0][:n], padding) {
				b.mac2[from.Port()]++
			}
			if len(b.wire) < 128 {
				sample := map[string]uint32{"bytes": uint32(n), "prefixWord": binary.LittleEndian.Uint32(packets[0][:4]), "decodedType": kind, "padding": padding}
				if int(padding)+4 <= n {
					sample["wireTypeField"] = binary.LittleEndian.Uint32(packets[0][padding : padding+4])
				}
				b.wire = append(b.wire, sample)
			}
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
		if _, err := c.WriteToUDPAddrPort(packet, to.AddrPort); err != nil {
			return err
		}
		kind, _ := b.classify(packet)
		if kind == 3 {
			b.mu.Lock()
			b.cookies[to.AddrPort.Port()]++
			b.mu.Unlock()
		}
	}
	return nil
}

func (b *loopbackBind) cookieProof() (map[uint16]int, map[uint16]int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	cookies, mac2 := map[uint16]int{}, map[uint16]int{}
	for port, count := range b.cookies {
		cookies[port] = count
	}
	for port, count := range b.mac2 {
		mac2[port] = count
	}
	return cookies, mac2
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

func (b *loopbackBind) samples() []map[string]uint32 {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]map[string]uint32, len(b.wire))
	for i, sample := range b.wire {
		out[i] = map[string]uint32{}
		for k, v := range sample {
			out[i][k] = v
		}
	}
	return out
}
