//go:build !windows

package main

import "os"

func privileged() bool { return os.Geteuid() == 0 }
