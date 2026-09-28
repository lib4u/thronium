package openconnect

import (
	"context"
	"fmt"
	"io"
	"testing"

	E "github.com/sagernet/sing/common/exceptions"
)

func TestCanceledChallengeIsTerminal(t *testing.T) {
	for name, err := range map[string]error{
		"direct":  ErrAuthChallengeCanceled,
		"wrapped": fmt.Errorf("owned fixture: %w", ErrAuthChallengeCanceled),
		"joined":  E.Errors(io.EOF, ErrAuthChallengeCanceled),
	} {
		t.Run(name, func(t *testing.T) {
			if classifyClientSessionError(err) != clientSessionErrorTerminal {
				t.Fatal("user cancellation must not initiate another authentication attempt")
			}
		})
	}
}

func TestOtherSessionFailurePolicyIsRetained(t *testing.T) {
	for name, value := range map[string]struct {
		err  error
		want clientSessionErrorClass
	}{
		"nil":                   {nil, clientSessionErrorRetryable},
		"transport":             {io.EOF, clientSessionErrorRetryable},
		"context":               {context.Canceled, clientSessionErrorRetryable},
		"credentials":           {ErrAuthenticationFailed, clientSessionErrorTerminal},
		"retryable-credentials": {newRetryableAuthenticationError(ErrAuthenticationFailed, authCachePassword), clientSessionErrorRetryable},
		"invalid-material":      {ErrInvalidTLSMaterial, clientSessionErrorTerminal},
	} {
		t.Run(name, func(t *testing.T) {
			if got := classifyClientSessionError(value.err); got != value.want {
				t.Fatalf("classification = %v, want %v", got, value.want)
			}
		})
	}
}
