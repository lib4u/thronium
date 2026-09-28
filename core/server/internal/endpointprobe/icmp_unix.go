//go:build linux || darwin

package endpointprobe

import (
	"bytes"
	"context"
	"crypto/rand"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"
)

func echo(ctx context.Context, ip netip.Addr, control socketControl) (time.Duration, error) {
	family, protocol, network := unix.AF_INET, unix.IPPROTO_ICMP, "udp4"
	var requestType icmp.Type = ipv4.ICMPTypeEcho
	var replyType icmp.Type = ipv4.ICMPTypeEchoReply
	var local unix.Sockaddr = &unix.SockaddrInet4{}
	if ip.Is6() {
		family, protocol, network = unix.AF_INET6, unix.IPPROTO_ICMPV6, "udp6"
		requestType, replyType, local = ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply, &unix.SockaddrInet6{}
	}
	// Datagram ICMP sockets need no raw-socket capability. Never escalate or fall
	// back to raw sockets when the OS disallows them.
	fd, err := unix.Socket(family, unix.SOCK_DGRAM, protocol)
	if err != nil {
		return 0, errICMP
	}
	unix.CloseOnExec(fd)
	file := os.NewFile(uintptr(fd), "icmp-probe")
	defer file.Close()
	if err = configureICMP(fd, family); err != nil {
		return 0, errICMP
	}
	if err = unix.Bind(fd, local); err != nil {
		return 0, errICMP
	}
	conn, err := net.FilePacketConn(file)
	if err != nil {
		return 0, errICMP
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		return 0, err
	}
	rawConn, ok := conn.(syscall.Conn)
	if !ok {
		return 0, errICMP
	}
	raw, err := rawConn.SyscallConn()
	if err != nil {
		return 0, errICMP
	}
	if err = control(network, net.JoinHostPort(ip.String(), "0"), raw); err != nil {
		return 0, err
	}
	nonce := make([]byte, 24)
	if _, err = rand.Read(nonce); err != nil {
		return 0, err
	}
	packet, err := (&icmp.Message{Type: requestType, Body: &icmp.Echo{ID: 1, Seq: 1, Data: nonce}}).Marshal(nil)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	if _, err = conn.WriteTo(packet, &net.UDPAddr{IP: net.IP(ip.AsSlice())}); err != nil {
		return 0, err
	}
	buffer := make([]byte, 2048)
	for {
		n, source, err := conn.ReadFrom(buffer)
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		if err != nil {
			return 0, err
		}
		peer, ok := source.(*net.UDPAddr)
		if !ok || !peer.IP.Equal(net.IP(ip.AsSlice())) {
			continue
		}
		message, err := icmp.ParseMessage(protocol, buffer[:n])
		if err != nil || message.Type != replyType || message.Code != 0 {
			continue
		}
		echo, ok := message.Body.(*icmp.Echo)
		// Linux substitutes its socket identifier. Check sequence, nonce and peer.
		if ok && echo.Seq == 1 && bytes.Equal(echo.Data, nonce) {
			return time.Since(start), nil
		}
	}
}
