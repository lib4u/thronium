//go:build linux

package tundns

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// No user-selected executable, inherited environment, shell command string, or
// raw command diagnostics cross the privileged supervisor boundary.
func OpenResolvInstalled(parent context.Context) (*OpenResolv, error) {
	var path string
	var info os.FileInfo
	for _, candidate := range []string{"/usr/sbin/resolvconf", "/sbin/resolvconf"} {
		canonical, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			continue
		}
		got, err := trustedResolverExecutable(canonical)
		if err == nil {
			path, info = canonical, got
			break
		}
	}
	if path == "" {
		return nil, ErrUnavailable
	}
	command := func(ctx context.Context, body string, args ...string) (string, int, error) {
		current, err := trustedResolverExecutable(path)
		if err != nil || !os.SameFile(info, current) || info.Size() != current.Size() || info.ModTime() != current.ModTime() {
			return "", -1, ErrUnavailable
		}
		return runResolv(ctx, path, body, args...)
	}
	ctx, cancel := context.WithTimeout(parent, Timeout)
	defer cancel()
	version, code, err := command(ctx, "", "--version")
	if err != nil || code != 0 || !supportedOpenResolv(version) {
		return nil, ErrUnavailable
	}
	return &OpenResolv{command: command, readResolver: readSystemResolver}, nil
}
func supportedOpenResolv(body string) bool {
	first := strings.SplitN(body, "\n", 2)[0]
	if !strings.HasPrefix(first, "openresolv ") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(first, "openresolv "), ".")
	if len(parts) != 3 {
		return false
	}
	var numbers [3]int
	for i, p := range parts {
		if p == "" || strings.Trim(p, "0123456789") != "" {
			return false
		}
		n, e := strconv.Atoi(p)
		if e != nil {
			return false
		}
		numbers[i] = n
	}
	return numbers[0] == 3 && (numbers[1] > 17 || numbers[1] == 17 && numbers[2] >= 4)
}
func trustedResolverExecutable(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return nil, ErrUnavailable
	}
	for p := path; ; p = filepath.Dir(p) {
		st, err := os.Lstat(p)
		if err != nil {
			return nil, ErrUnavailable
		}
		raw, ok := st.Sys().(*syscall.Stat_t)
		if !ok || raw.Uid != 0 || st.Mode().Perm()&0022 != 0 || p != path && !st.IsDir() {
			return nil, ErrUnavailable
		}
		if p == "/" {
			break
		}
	}
	return info, nil
}
func readSystemResolver() ([]byte, error) {
	f, err := os.OpenFile("/etc/resolv.conf", os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 65536 {
		return nil, ErrUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(body) > 65536 {
		return nil, ErrUnavailable
	}
	return body, nil
}

type resolvOutput struct {
	sync.Mutex
	body     []byte
	overflow bool
}

func (b *resolvOutput) Write(p []byte) (int, error) {
	b.Lock()
	defer b.Unlock()
	n := len(p)
	left := 65536 - len(b.body)
	if n > left {
		p = p[:left]
		b.overflow = true
	}
	b.body = append(b.body, p...)
	return n, nil
}
func runResolv(parent context.Context, path, body string, args ...string) (string, int, error) {
	ctx, cancel := context.WithTimeout(parent, Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	cmd.Dir = "/"
	cmd.Stdin = strings.NewReader(body)
	var out, diagnostics resolvOutput
	cmd.Stdout = &out
	cmd.Stderr = &diagnostics
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	cmd.Cancel = func() error {
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			return err
		}
		return os.ErrProcessDone
	}
	cmd.WaitDelay = 250 * time.Millisecond
	if err := cmd.Start(); err != nil {
		return "", -1, ErrUnavailable
	}
	err := cmd.Wait()
	// Subscribers that leave a background process cannot outlive this invocation.
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if ctx.Err() != nil || out.overflow || diagnostics.overflow {
		return "", -1, ErrUnavailable
	}
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			return "", -1, ErrUnavailable
		}
		return string(out.body), exit.ExitCode(), nil
	}
	return string(out.body), 0, nil
}
