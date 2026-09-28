//go:build linux

package tunsession

import (
	"ThroneCore/internal/tundns"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"golang.org/x/sys/unix"
)

// startWithResolverView gives only this worker the pre-TUN resolver file. Both
// sing-box local DNS and Xray localhost reread /etc/resolv.conf, which would
// otherwise point back into their own DNS inbound after openresolv activates.
// Each reconnect takes a fresh snapshot after the old record has been removed.
func startWithResolverView(cmd *exec.Cmd) error {
	f, err := os.OpenFile("/etc/resolv.conf", os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return tundns.ErrUnavailable
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 65536 {
		f.Close()
		return tundns.ErrUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(f, 65537))
	f.Close()
	if err != nil || len(body) > 65536 {
		return tundns.ErrUnavailable
	}
	// newOwner already verified this supervisor's private root-owned journal dir.
	// Keep the temporary source inaccessible to the unprivileged GUI and worker.
	source, err := os.CreateTemp("/run/thronium-tun", ".resolver-")
	if err != nil {
		return tundns.ErrUnavailable
	}
	defer source.Close()
	defer os.Remove(source.Name())
	if _, err = source.Write(body); err != nil {
		return tundns.ErrUnavailable
	}
	if err = source.Chmod(0444); err != nil {
		return tundns.ErrUnavailable
	}
	run := func() error {
		// This goroutine never unlocks: Go destroys its OS thread on return, including
		// its private mount namespace. No supervisor thread changes namespace and no
		// namespace restoration can fail after a child has already been started.
		if err := unix.Unshare(unix.CLONE_NEWNS | unix.CLONE_FS); err != nil {
			log.Printf("TUN private resolver unshare failed: %v", err)
			return tundns.ErrUnavailable
		}
		if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
			log.Printf("TUN private resolver private propagation failed: %v", err)
			return tundns.ErrUnavailable
		}
		target, err := filepath.EvalSymlinks("/etc/resolv.conf")
		if err != nil {
			return tundns.ErrUnavailable
		}
		if err := unix.Mount(source.Name(), target, "", unix.MS_BIND, ""); err != nil {
			log.Printf("TUN private resolver bind file failed: %v", err)
			return tundns.ErrUnavailable
		}
		if err := unix.Mount("", target, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
			log.Printf("TUN private resolver read-only remount failed: %v", err)
			return tundns.ErrUnavailable
		}
		return cmd.Start()
	}

	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if unix.Gettid() == os.Getpid() {
			// Keep the process leader alive and in the supervisor namespace:
			// /proc/PID/exe and /proc/PID/ns must remain available to ownership
			// checks. Holding it locked forces the nested task to another thread.
			nested := make(chan error, 1)
			go func() { runtime.LockOSThread(); nested <- run() }()
			err := <-nested
			runtime.UnlockOSThread()
			done <- err
			return
		}
		done <- run()
	}()
	return <-done
}

func (s *session) pinSystemResolver() bool {
	return s.owner != nil && s.owner.active != nil && s.owner.active.DNSMode == "resolvconf"
}
