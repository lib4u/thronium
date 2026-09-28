//go:build linux

package parentcheck

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func getParentExePath(pid int) (string, error) {
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", err
	}
	// Linux appends " (deleted)" when the binary has been replaced on disk
	return strings.TrimSuffix(path, " (deleted)"), nil
}

func resolveFinalPath(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	return path
}

// imageParent accepts, for the TUN supervisor only, a Thronium running from an
// AppImage: pkexec starts a copy of the core as root, and root cannot reach
// the image's FUSE mount where the application and the original core live,
// so the two can never share a directory. The supervisor still authenticates
// the application through the peer credentials of its socket.
func imageParent(parentPath string) bool {
	if os.Geteuid() != 0 || filepath.Base(parentPath) != expectedParentName {
		return false
	}
	_, err := os.Stat(parentPath)
	return unreachableForRoot(err)
}

func unreachableForRoot(err error) bool {
	return errors.Is(err, fs.ErrPermission)
}
