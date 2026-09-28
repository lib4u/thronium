//go:build windows

package process

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Windows has no execute bit. Only a program image is accepted: a .bat or
// .cmd would run through cmd.exe, which parses the arguments by its own rules.
func runnable(path string, _ os.FileInfo) error {
	if !strings.EqualFold(filepath.Ext(path), ".exe") {
		return errors.New("external_core_executable_unavailable")
	}
	return nil
}
