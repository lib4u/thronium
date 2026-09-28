//go:build linux

package main

import (
	"ThroneCore/internal/tunsession"
	"ThroneCore/parentcheck"
	"fmt"
	"net"
	"os"
)

func managedMain() bool {
	if len(os.Args) == 1 {
		return false
	}
	if !parentcheck.ManagedAllowed() {
		panic("managed TUN is not enabled in this build")
	}
	switch {
	case len(os.Args) == 4 && os.Args[1] == "--thronium-tun-supervisor":
		parentcheck.CheckParentProcess()
		if err := tunsession.Run(os.Args[2], os.Args[3]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return true
	case len(os.Args) == 2 && os.Args[1] == "--thronium-tun-worker":
		parentcheck.ManagedWorker = true
		return false
	default:
		panic("invalid managed core arguments")
	}
}
func verifyManagedParent(conn net.Conn) {
	if parentcheck.ManagedWorker {
		if err := tunsession.VerifyWorkerParent(conn); err != nil {
			panic(err)
		}
	}
}
