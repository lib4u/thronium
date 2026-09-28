package main

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestDispatchDrainsPendingRequestAfterIPCCloses(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	const method = "test-pending-start"
	handlers[method] = func(context.Context, []byte) ([]byte, error) {
		close(started)
		<-release
		return nil, nil
	}
	defer delete(handlers, method)
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() { runDispatch(server); close(done) }()
	frame := make([]byte, 10+len(method))
	binary.LittleEndian.PutUint32(frame, 1)
	binary.LittleEndian.PutUint16(frame[4:], uint16(len(method)))
	copy(frame[6:], method)
	if _, err := client.Write(frame); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("request did not start")
	}
	client.Close()
	select {
	case <-done:
		t.Fatal("dispatcher exited before the pending request finished")
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("dispatcher did not cleanly exit after draining its request")
	}
}
