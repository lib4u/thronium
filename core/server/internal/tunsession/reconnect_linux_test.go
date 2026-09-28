//go:build linux

package tunsession

import (
	"testing"
	"time"
)

func TestReconnectBackoffAndCrashBudget(t *testing.T) {
	now := time.Now()
	s := session{enabled: true, desired: []byte("private request"), phase: "connected", connectedAt: now}
	for attempt, delay := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second} {
		s.attempts = uint32(attempt)
		s.workerLost(now)
		if s.phase != "reconnecting" || s.retryAt.Sub(now) != delay {
			t.Fatalf("attempt %d: %s %s", attempt, s.phase, s.retryAt.Sub(now))
		}
	}
	s.attempts = 3
	s.workerLost(now)
	if s.phase != "failed" || s.failure != "tun_reconnect_failed" || s.desired != nil || !s.retryAt.IsZero() {
		t.Fatal("crash loop did not stop and discard credentials")
	}
}

func TestStableConnectionResetsBudgetAndStopCancelsIntent(t *testing.T) {
	now := time.Now()
	s := session{enabled: true, desired: []byte("private request"), attempts: 3, phase: "connected", connectedAt: now.Add(-stableConnection)}
	s.workerLost(now)
	if s.attempts != 0 || s.phase != "reconnecting" {
		t.Fatal("stable uptime did not reset budget")
	}
	if err := s.stop(); err != nil {
		t.Fatal(err)
	}
	s.workerLost(now)
	if s.phase != "idle" || s.desired != nil || !s.retryAt.IsZero() {
		t.Fatal("late worker exit restarted a cancelled connection")
	}
}

func TestDisabledRecoveryAndIdleCoreNeverReconnect(t *testing.T) {
	for _, s := range []*session{
		{enabled: false, desired: []byte("private request"), phase: "connected"},
		{enabled: true, phase: "idle"},
	} {
		s.workerLost(time.Now())
		if !s.retryAt.IsZero() || s.desired != nil || s.phase == "reconnecting" {
			t.Fatal("unexpected automatic connection")
		}
	}
}
