package process

import (
	"log"
	"strings"
	"sync"
)

// Drain even when disabled/exhausted. Never allow arbitrary child output to
// produce an unbounded single log entry or flood the worker's IPC goroutines.
type boundedOutput struct {
	mu    sync.Mutex
	noOut bool
	bytes int
}

func (p *boundedOutput) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := len(b)
	if p.noOut || p.bytes >= 1024*1024 {
		return n, nil
	}
	if len(b) > 16*1024 {
		b = b[:16*1024]
	}
	if len(b) > 1024*1024-p.bytes {
		b = b[:1024*1024-p.bytes]
	}
	p.bytes += len(b)
	log.Print("Extra Core: " + strings.ToValidUTF8(string(b), "�"))
	return n, nil
}
