package openvpn

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestSingleUseCredentialsRejectReplayAcrossConcurrentKeyMethods(t *testing.T) {
	client := &Client{}
	client.options.Authentication.SingleUse = true
	var sent atomic.Int32
	var workers sync.WaitGroup
	for range 100 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := client.reserveSingleUseAuth(); err == nil {
				sent.Add(1)
			} else if classifyClientSessionError(err) != clientSessionErrorTerminal {
				t.Errorf("replay refusal must stop the supervisor: %v", err)
			}
		}()
	}
	workers.Wait()
	if sent.Load() != 1 {
		t.Fatalf("credential sends = %d", sent.Load())
	}
	client.purgeStagedCredentials()
	if client.reserveSingleUseAuth() == nil {
		t.Fatal("purging cached credentials re-enabled a spent code")
	}
}

func TestSingleUseCredentialsLeaveOrdinaryClientsAndFreshClientsIndependent(t *testing.T) {
	ordinary := &Client{}
	for range 5 {
		if err := ordinary.reserveSingleUseAuth(); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		fresh := &Client{}
		fresh.options.Authentication.SingleUse = true
		if err := fresh.reserveSingleUseAuth(); err != nil {
			t.Fatal(err)
		}
	}
}
