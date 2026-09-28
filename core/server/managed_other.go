//go:build !linux && !windows

package main

import "net"

func managedMain() bool            { return false }
func verifyManagedParent(net.Conn) {}
