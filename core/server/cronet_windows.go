//go:build windows && with_purego

package main

import (
	"os"
	"path/filepath"

	"github.com/sagernet/cronet-go"
)

// Cronet looks beside the executable first and then along PATH. A DLL is
// taken only from beside ThroniumCore.exe: when it is not there, loading is
// settled now on that exact path, so a later Naive outbound fails cleanly
// instead of finding a planted libcronet.dll elsewhere.
func init() {
	executable, err := os.Executable()
	if err != nil {
		return
	}
	beside := filepath.Join(filepath.Dir(executable), "libcronet.dll")
	if _, err := os.Stat(beside); err != nil {
		_ = cronet.LoadLibrary(beside)
	}
}
