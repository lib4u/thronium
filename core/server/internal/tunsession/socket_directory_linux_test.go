//go:build linux

package tunsession

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkerSocketDirectory(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "worker-socket-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	for _, name := range []string{"short", strings.Repeat("long", 45)} {
		t.Run(name[:5], func(t *testing.T) {
			preferred := filepath.Join(root, name)
			if err := os.Mkdir(preferred, 0700); err != nil {
				t.Fatal(err)
			}
			directory, err := workerSocketDirectory(preferred)
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(directory)
			info, err := os.Stat(directory)
			if err != nil || info.Mode().Perm() != 0700 {
				t.Fatal("directory permissions", info, err)
			}
			if !filepath.IsAbs(directory) || (filepath.Dir(directory) == preferred) != (name == "short") {
				t.Fatal("unexpected location", directory)
			}
			path := filepath.Join(directory, workerSocketName)
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatal("real socket bind", err)
			}
			if err := listener.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.RemoveAll(directory); err != nil {
				t.Fatal(err)
			}
			entries, err := os.ReadDir(preferred)
			if err != nil || len(entries) != 0 {
				t.Fatal("leaked private directory", entries, err)
			}
		})
	}
	if _, err := workerSocketDirectory(filepath.Join(root, "missing")); !os.IsNotExist(err) {
		t.Fatal("invalid location was hidden", err)
	}
}
