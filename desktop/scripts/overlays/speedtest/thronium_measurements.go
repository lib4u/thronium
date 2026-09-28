package speedtest

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sync"
)

// The direction's Start joins all handlers before the caller reads err.
// Deadline/cancellation stops a timed sample; protocol and body errors fail it.
type transferErrors struct {
	once sync.Once
	err  error
}

func (f *transferErrors) record(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	f.once.Do(func() { f.err = err })
	return true
}

func checkHTTPStatus(response *http.Response) error {
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("speedtest HTTP status %d", response.StatusCode)
	}
	return nil
}

func validateTransfer(direction string, bytes int64, rate float64) error {
	if bytes <= 0 || rate <= 0 || math.IsNaN(rate) || math.IsInf(rate, 0) {
		return fmt.Errorf("speedtest %s returned no valid measurement", direction)
	}
	return nil
}
