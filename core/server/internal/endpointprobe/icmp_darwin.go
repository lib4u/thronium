//go:build darwin

package endpointprobe

import "golang.org/x/sys/unix"

func configureICMP(fd, family int) error {
	if family == unix.AF_INET {
		return unix.SetsockoptInt(fd, unix.IPPROTO_IP, 23 /* IP_STRIPHDR */, 1)
	}
	return nil
}
