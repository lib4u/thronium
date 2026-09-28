//go:build linux

package tundns

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestResolvCommandBoundsOutputAndDoesNotInheritEnvironment(t *testing.T) {
	t.Setenv("THRONIUM_DNS_SHOULD_NOT_LEAK", "sensitive")
	out, code, err := runResolv(context.Background(), "/bin/sh", "", "-c", `printf '%s' "${THRONIUM_DNS_SHOULD_NOT_LEAK-unset}"`)
	if err != nil || code != 0 || out != "unset" {
		t.Fatal(out, code, err)
	}
	for _, redirect := range []string{"", ">&2"} {
		out, _, err = runResolv(context.Background(), "/bin/sh", "", "-c", "head -c 70000 /dev/zero "+redirect)
		if err == nil || out != "" {
			t.Fatal("unbounded output accepted")
		}
	}
}
func TestResolvTimeoutKillsOwnedSubscriberGroup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "child")
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err := runResolv(ctx, "/bin/sh", "", "-c", `sleep 60 & echo $! > "$1"; wait`, "sh", path)
	if err == nil || time.Since(start) > 2*time.Second {
		t.Fatal("timeout not bounded", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	// A killed orphan may remain a zombie briefly until the namespace/host reaper
	// consumes it; it must not be a live subscriber after this call returns.
	for n := 0; n < 40; n++ {
		state, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if os.IsNotExist(err) || err == nil && strings.Contains(string(state), ") Z ") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	t.Fatal("subscriber survived timeout")
}
func TestResolverExecutableRejectsWritableOrUntrustedPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolvconf")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := trustedResolverExecutable(path); err == nil {
		t.Fatal("writable executable accepted")
	}
}
