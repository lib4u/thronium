//go:build !debug

package parentcheck

import (
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Set by the fork's build script. Keep the same-directory and peer-PID checks.
// An upstream build still requires Throne; this is not a runtime environment override.
var expectedParentName = "Throne"
var ManagedWorker bool

// Fork reports a Thronium build, as opposed to an upstream core for Throne.
func Fork() bool { return expectedParentName == "Thronium" }

func ManagedAllowed() bool {
	return Fork() && (runtime.GOOS == "linux" || runtime.GOOS == "windows")
}

func CheckParentProcess() {
	// The worker authenticates the exact root parent through SO_PEERCRED before
	// accepting any RPC. Its dropped UID cannot inspect the root parent's /proc/exe.
	// On Windows its parent is the service, this same executable, which
	// verifyManagedParent checks instead of Thronium.exe.
	if ManagedWorker && ManagedAllowed() {
		return
	}
	parentPath, err := getParentExePath(ParentPID)
	if err != nil {
		log.Fatalf("parent check: cannot read parent executable: %v", err)
	}
	parentPath = resolveFinalPath(parentPath)

	selfPath, err := os.Executable()
	if err != nil {
		log.Fatalf("parent check: cannot read own executable: %v", err)
	}
	selfPath = resolveFinalPath(selfPath)

	selfDir := filepath.Dir(selfPath)
	parentDir := filepath.Dir(parentPath)
	parentBase := filepath.Base(parentPath)

	if runtime.GOOS == "windows" {
		if !strings.EqualFold(parentDir, selfDir) || !strings.EqualFold(parentBase, expectedParentName+".exe") {
			log.Fatalf("parent check failed: unexpected parent %q, selfPath is %q", parentPath, selfPath)
		}
		return
	}

	if parentDir != selfDir || parentBase != expectedParentName {
		if imageParent(parentPath) {
			return
		}
		log.Fatalf("parent check failed: unexpected parent %q, selfPath is %q", parentPath, selfPath)
	}
}
