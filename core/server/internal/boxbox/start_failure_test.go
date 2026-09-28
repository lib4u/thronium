package boxbox

import (
	"errors"
	"testing"
)

func TestStartFailureSurvivesCleanup(t *testing.T) {
	startErr := errors.New("start failed")
	closeErr := errors.New("close failed")
	for _, test := range []struct {
		name      string
		close     func() error
		wantClose bool
	}{
		{"successful cleanup", func() error { return nil }, false},
		{"failed cleanup", func() error { return closeErr }, true},
		{"panicking cleanup", func() error { panic("partially initialized") }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			called := false
			err := closeAfterStartFailure(startErr, func() error { called = true; return test.close() })
			if !called || !errors.Is(err, startErr) {
				t.Fatalf("cleanup=%v; initial failure lost: %v", called, err)
			}
			if test.wantClose && !errors.Is(err, closeErr) {
				t.Fatalf("cleanup error lost: %v", err)
			}
		})
	}
}
