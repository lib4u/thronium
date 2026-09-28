//go:build windows

package main

import (
	"ThroneCore/internal/boxdns"
	"ThroneCore/internal/winservice"
	"ThroneCore/parentcheck"
	"fmt"
	"net"
	"os"
)

// managedMain runs ThroniumService, which owns TUN and system DNS for the
// application, and marks the SYSTEM worker core it starts.
func managedMain() bool {
	if len(os.Args) == 1 {
		return false
	}
	if !parentcheck.ManagedAllowed() {
		panic("managed TUN is not enabled in this build")
	}
	switch {
	case len(os.Args) == 2 && os.Args[1] == "--thronium-service":
		if err := winservice.Run(boxdns.RestoreAllMarked); err != nil {
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

// ConnectIPC has already matched the pipe's server to the parent PID.
func verifyManagedParent(net.Conn) {
	if parentcheck.ManagedWorker {
		if err := winservice.VerifyWorkerParent(parentcheck.ParentPID); err != nil {
			panic(err)
		}
	}
}
