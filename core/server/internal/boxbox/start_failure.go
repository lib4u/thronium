package boxbox

import (
	"errors"
	"fmt"
)

// closeAfterStartFailure preserves the original failure even if a partly
// initialized service panics while closing. A cleanup panic must never turn a
// failed Start into a successful nil result.
func closeAfterStartFailure(startErr error, close func() error) (result error) {
	result = startErr
	defer func() {
		if recover() != nil {
			result = errors.Join(result, errors.New("startup cleanup panicked"))
		}
	}()
	if err := close(); err != nil {
		result = errors.Join(result, fmt.Errorf("startup cleanup: %w", err))
	}
	return result
}
