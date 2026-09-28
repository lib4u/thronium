//go:build !linux && !darwin && !windows

package endpointprobe

import (
	"context"
	"net/netip"
	"time"
)

func echo(context.Context, netip.Addr, socketControl) (time.Duration, error) { return 0, errICMP }
