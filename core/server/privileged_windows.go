//go:build windows

package main

import "golang.org/x/sys/windows"

// An elevated token is Windows' root: an administrator who approved UAC, or
// SYSTEM. A filtered administrator token is not privileged.
func privileged() bool { return windows.GetCurrentProcessToken().IsElevated() }
