//go:build windows

package endpointprobe

import (
	"ThroneCore/internal/boxdns"
	"context"
	"crypto/rand"
	"encoding/binary"
	"net/netip"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi            = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	procIcmp6CreateFile = iphlpapi.NewProc("Icmp6CreateFile")
	procIcmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho2Ex = iphlpapi.NewProc("IcmpSendEcho2Ex")
	procIcmp6SendEcho2  = iphlpapi.NewProc("Icmp6SendEcho2")
)

// The ICMP helper API needs neither a raw socket nor privilege. There is no
// socket to bind, so the direct egress the Unix probe gets from binding comes
// from the source address instead: Windows sends from the interface that owns
// it, past a running TUN.
func echo(ctx context.Context, ip netip.Addr, _ socketControl) (time.Duration, error) {
	var source netip.Addr
	if !ip.IsLoopback() {
		iface := boxdns.DefaultInterface()
		if iface == nil {
			return 0, errEgress
		}
		var ok bool
		if source, ok = sourceFor(iface.Addresses, ip); !ok {
			return 0, errEgress
		}
	}
	deadline, _ := ctx.Deadline()
	wait := time.Until(deadline).Milliseconds()
	if wait < 1 {
		return 0, context.DeadlineExceeded
	}
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return 0, err
	}
	type outcome struct {
		elapsed time.Duration
		err     error
	}
	done := make(chan outcome, 1)
	// The call blocks until a reply or its own timeout. Cancellation answers
	// at once and leaves the call to finish within that timeout.
	go func() {
		elapsed, err := send(ip, source, nonce, uint32(wait))
		done <- outcome{elapsed, err}
	}()
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case result := <-done:
		return result.elapsed, result.err
	}
}

func send(destination, source netip.Addr, data []byte, timeout uint32) (time.Duration, error) {
	create := procIcmpCreateFile
	if destination.Is6() {
		create = procIcmp6CreateFile
	}
	handle, _, _ := create.Call()
	if handle == 0 || windows.Handle(handle) == windows.InvalidHandle {
		return 0, errICMP
	}
	defer procIcmpCloseHandle.Call(handle)
	// Room for the reply structure, the echoed data, an ICMP error and the
	// status block the API also writes there.
	reply := make([]byte, 1024)
	var replies uintptr
	var lastError error
	start := time.Now()
	if destination.Is4() {
		// IPAddr is a DWORD holding the address in network order.
		var from [4]byte
		if source.IsValid() {
			from = source.As4()
		}
		to := destination.As4()
		replies, _, lastError = procIcmpSendEcho2Ex.Call(handle, 0, 0, 0,
			uintptr(binary.LittleEndian.Uint32(from[:])), uintptr(binary.LittleEndian.Uint32(to[:])),
			uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), 0,
			uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(timeout))
	} else {
		from := windows.RawSockaddrInet6{Family: windows.AF_INET6}
		if source.IsValid() {
			from.Addr = source.As16()
		}
		to := windows.RawSockaddrInet6{Family: windows.AF_INET6, Addr: destination.As16()}
		replies, _, lastError = procIcmp6SendEcho2.Call(handle, 0, 0, 0,
			uintptr(unsafe.Pointer(&from)), uintptr(unsafe.Pointer(&to)),
			uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), 0,
			uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(timeout))
	}
	elapsed := time.Since(start)
	code := uint32(0)
	if errno, ok := lastError.(windows.Errno); ok {
		code = uint32(errno)
	}
	if err := echoVerdict(reply, destination, replies, code); err != nil {
		return 0, err
	}
	return elapsed, nil
}
