package main

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func withCoreConn(t *testing.T, conn net.Conn) {
	coreConnMu.Lock()
	coreConn = conn
	coreConnMu.Unlock()
	t.Cleanup(func() {
		coreConnMu.Lock()
		coreConn = nil
		coreConnMu.Unlock()
	})
}

func TestParentExitRunsTheChannelTeardownInsteadOfExiting(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() { runDispatch(server); close(done) }()
	withCoreConn(t, server)
	exited := make(chan struct{})
	go parentExited("test", time.Minute, func() { close(exited) })
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("dispatch did not run its teardown")
	}
	select {
	case <-exited:
		t.Fatal("exited instead of letting the teardown finish")
	default:
	}
}

func TestParentExitGivesUpOnATeardownThatHangs(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	const method = "test-parent-exit-hang"
	handlers[method] = func(context.Context, []byte) ([]byte, error) {
		close(started)
		<-release
		return nil, nil
	}
	defer delete(handlers, method)
	server, client := net.Pipe()
	defer client.Close()
	go runDispatch(server)
	frame := make([]byte, 10+len(method))
	binary.LittleEndian.PutUint32(frame, 1)
	binary.LittleEndian.PutUint16(frame[4:], uint16(len(method)))
	copy(frame[6:], method)
	if _, err := client.Write(frame); err != nil {
		t.Fatal(err)
	}
	<-started
	withCoreConn(t, server)
	exited := make(chan struct{})
	go parentExited("test", 50*time.Millisecond, func() { close(exited) })
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("a hanging teardown kept the core alive")
	}
}

func TestParentExitBeforeTheChannelExitsAtOnce(t *testing.T) {
	withCoreConn(t, nil)
	exited := make(chan struct{})
	go parentExited("test", time.Minute, func() { close(exited) })
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("no channel, yet the core waited")
	}
}
