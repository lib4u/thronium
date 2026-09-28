//go:build !windows

package process

import (
	"errors"
	"os"
)

func runnable(_ string, file os.FileInfo) error {
	if file.Mode().Perm()&0111 == 0 {
		return errors.New("external_core_executable_unavailable")
	}
	if file.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return errors.New("external_core_executable_privileged")
	}
	return nil
}
