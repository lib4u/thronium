//go:build linux

package tunsession

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const workerSocketName = "worker.sock"

// A worker may receive a long TMPDIR from the desktop. Keep that location when
// possible, but never pass a path exceeding sockaddr_un to ListenUnix. The
// worker changes cwd, so its socket path must also be absolute.
func workerSocketDirectory(preferred string) (string, error) {
	private := func(root string) (string, error) {
		root, err := filepath.EvalSymlinks(root)
		if err != nil {
			return "", err
		}
		root, err = filepath.Abs(root)
		if err != nil {
			return "", err
		}
		return os.MkdirTemp(root, "thronium-tun-worker-")
	}
	fits := func(directory string) bool {
		return len(filepath.Join(directory, workerSocketName)) < len(unix.RawSockaddrUnix{}.Path)
	}
	directory, err := private(preferred)
	if err != nil {
		return "", err
	}
	if fits(directory) {
		return directory, nil
	}
	if err := os.Remove(directory); err != nil {
		return "", err
	}
	directory, err = private("/tmp")
	if err != nil {
		return "", err
	}
	if !fits(directory) {
		_ = os.Remove(directory)
		return "", fmt.Errorf("core_socket_path")
	}
	return directory, nil
}
