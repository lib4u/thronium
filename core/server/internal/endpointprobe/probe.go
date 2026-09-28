// Package endpointprobe measures direct TCP connect / ICMP echo, never VPN authentication.
// Runs in a disposable core or a managed background job; cancellation closes every socket.
package endpointprobe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var errEgress = errors.New("probe_direct_unavailable")
var errICMP = errors.New("probe_icmp_unavailable")

func Run(parent context.Context, method, host string, port, timeout uint32) (int32, string) {
	return RunWithMark(parent, method, host, port, timeout, 0)
}

func RunWithMark(parent context.Context, method, host string, port, timeout, mark uint32) (int32, string) {
	control := controlWithMark(mark)
	if (method != "tcp" && method != "icmp") || timeout < 100 || timeout > 10000 || len(host) == 0 || len(host) > 253 || strings.ContainsAny(host, "\x00 /\\?#@") || (method == "tcp" && (port == 0 || port > 65535)) {
		return 0, "probe_invalid_options"
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(timeout)*time.Millisecond)
	defer cancel()
	// The Go resolver honours hosts/resolv.conf; its network sockets use the same
	// direct egress binding as the measurement, including when TUN is running.
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{Control: control}).DialContext(ctx, network, address)
	}}
	addresses, err := resolver.LookupNetIP(ctx, "ip", strings.Trim(host, "[]"))
	if err != nil {
		if ctx.Err() == context.Canceled {
			return 0, "probe_cancelled"
		}
		return 0, "probe_dns_failed"
	}
	if len(addresses) == 0 {
		return 0, "probe_dns_failed"
	}
	// Race address families without counting DNS time in the displayed latency.
	// All candidates still share the original total deadline, including DNS.
	sort.SliceStable(addresses, func(i, j int) bool { return addresses[i].Unmap().Is4() && !addresses[j].Unmap().Is4() })
	if len(addresses) > 8 {
		addresses = addresses[:8]
	}
	deadline, _ := ctx.Deadline()
	step := min(50*time.Millisecond, max(0, time.Until(deadline))/time.Duration(len(addresses)*2))
	type result struct {
		ms  int32
		err error
	}
	results := make(chan result, len(addresses))
	for i, address := range addresses {
		go func(i int, ip netip.Addr) {
			timer := time.NewTimer(time.Duration(i) * step)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				results <- result{err: ctx.Err()}
				return
			case <-timer.C:
			}
			var elapsed time.Duration
			var err error
			if method == "tcp" {
				elapsed, err = tcp(ctx, ip.Unmap(), port, control)
			} else {
				elapsed, err = echo(ctx, ip.Unmap(), control)
			}
			results <- result{int32(elapsed.Milliseconds()), err}
		}(i, address)
	}
	code := "probe_unreachable"
	for range addresses {
		select {
		case <-ctx.Done():
			return 0, errorCode(ctx.Err(), method)
		case r := <-results:
			if r.err == nil {
				return r.ms, ""
			}
			next := errorCode(r.err, method)
			if code == "probe_unreachable" || next == "probe_timeout" || next == "probe_icmp_no_reply" || next == "probe_icmp_unavailable" || next == "probe_direct_unavailable" {
				code = next
			}
		}
	}
	return 0, code
}

type socketControl = func(string, string, syscall.RawConn) error

func controlWithMark(mark uint32) socketControl {
	return func(network, address string, conn syscall.RawConn) error {
		if err := socketMark(conn, mark); err != nil {
			return err
		}
		return directControl(network, address, conn)
	}
}

func tcp(ctx context.Context, ip netip.Addr, port uint32, control socketControl) (time.Duration, error) {
	// Binding/setup is excluded; the timer starts immediately before connect.
	var start time.Time
	dialer := net.Dialer{Control: func(network, address string, conn syscall.RawConn) error {
		if err := control(network, address, conn); err != nil {
			return err
		}
		start = time.Now()
		return nil
	}}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
	if err != nil {
		return 0, err
	}
	elapsed := time.Since(start)
	conn.Close()
	return elapsed, nil
}

// Windows reports a refused connection as WSAECONNREFUSED, which is not
// syscall.ECONNREFUSED there.
const wsaConnRefused = syscall.Errno(10061)

func errorCode(err error, method string) string {
	if errors.Is(err, errEgress) {
		return "probe_direct_unavailable"
	}
	if errors.Is(err, errICMP) {
		return "probe_icmp_unavailable"
	}
	if errors.Is(err, context.Canceled) {
		return "probe_cancelled"
	}
	var networkError net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &networkError) && networkError.Timeout()) {
		if method == "icmp" {
			return "probe_icmp_no_reply"
		}
		return "probe_timeout"
	}
	if method == "tcp" && (errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, wsaConnRefused)) {
		return "probe_connection_refused"
	}
	return "probe_unreachable"
}
