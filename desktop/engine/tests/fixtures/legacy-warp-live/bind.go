package main

import (
	"encoding/binary"
	"errors"
	"golang.zx2c4.com/wireguard/conn"
	"net"
	"net/netip"
	"sync"
)

type loopbackBind struct {
	ip      netip.Addr
	mu      sync.Mutex
	socket  *net.UDPConn
	packets map[uint32]int
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
			b.packets[binary.LittleEndian.Uint32(packets[0][:4])]++
			b.mu.Unlock()
		}
		// Record the actual wire header first, then remove the WARP reserved
		// bytes for the independent standard wireguard-go protocol decoder.
		if n >= 4 {
			if packets[0][1] != 0 || packets[0][2] != 128 || packets[0][3] != 255 {
				return 0, errors.New("unexpected WARP reserved bytes")
			}
			packets[0][1], packets[0][2], packets[0][3] = 0, 0, 0
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
	}
	return nil
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
