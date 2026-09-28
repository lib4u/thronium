package main

import (
	"ThroneCore/gen"
	"ThroneCore/test_utils"
	"context"
	"time"
)

// The status source belongs to the same test environment as the measurement.
// Only explicitly requested, measured endpoints participate in this protocol.
type diagnosticVPN struct {
	tags     []string
	measured map[string]bool
	live     bool
	timeout  time.Duration
	collect  testVPNStatusCollector
}

func prepareDiagnosticVPN(ctx context.Context, requested, measured, available []string, live bool, timeoutMS int32, collect testVPNStatusCollector) diagnosticVPN {
	v := diagnosticVPN{tags: measuredVPNEndpointTags(requested, measured, available), measured: make(map[string]bool, len(measured)), live: live, timeout: defaultVPNStatusTimeout, collect: collect}
	for _, tag := range measured {
		v.measured[tag] = true
	}
	if timeoutMS > 0 {
		v.timeout = time.Duration(timeoutMS) * time.Millisecond
	}
	if len(v.tags) > 0 && !live && ctx.Err() == nil {
		waitCtx, cancel := context.WithTimeout(ctx, v.timeout)
		collect(waitCtx, v.tags, v.timeout)
		cancel()
	}
	return v
}

func (v diagnosticVPN) failed(ctx context.Context, failed []string) []*gen.VPNEndpointStatus {
	if len(failed) == 0 {
		return nil
	}
	named := make(map[string]bool, len(failed))
	for _, tag := range failed {
		named[tag] = true
	}
	// A failed measured outbound names itself; an awaited dependency endpoint
	// cannot, so a failure of the measurement snapshots it as well.
	var tags []string
	for _, tag := range v.tags {
		if named[tag] || !v.measured[tag] {
			tags = append(tags, tag)
		}
	}
	if len(tags) == 0 {
		return nil
	}
	// A fresh snapshot after a failed disposable measurement cannot spend a
	// second readiness budget. Existing live-instance tests may still wait.
	timeout := time.Duration(0)
	if v.live {
		timeout = v.timeout
	}
	return v.collect(ctx, tags, timeout)
}

func runIPMeasurement(ctx context.Context, in *gen.IPTestRequest, tags, available []string, run func(context.Context) []*gen.IPTestRes, collect testVPNStatusCollector) *gen.IPTestResp {
	vpn := prepareDiagnosticVPN(ctx, in.VpnEndpointTags, tags, available, false, in.GetVpnStatusTimeoutMs(), collect)
	var results []*gen.IPTestRes
	if ctx.Err() != nil {
		for _, tag := range tags {
			results = append(results, &gen.IPTestRes{OutboundTag: To(tag), Error: To(test_utils.ErrTestAborted.Error())})
		}
	} else {
		results = run(ctx)
	}
	var failed []string
	for _, result := range results {
		if result.GetError() != "" {
			failed = append(failed, result.GetOutboundTag())
		}
	}
	return &gen.IPTestResp{Results: results, VpnStatus: vpn.failed(ctx, failed)}
}

func runSpeedMeasurement(ctx context.Context, in *gen.SpeedTestRequest, tags, available []string, run func(context.Context) []*gen.SpeedTestResult, collect testVPNStatusCollector) *gen.SpeedTestResponse {
	vpn := prepareDiagnosticVPN(ctx, in.VpnEndpointTags, tags, available, in.GetTestCurrent(), in.GetVpnStatusTimeoutMs(), collect)
	var results []*gen.SpeedTestResult
	if ctx.Err() != nil {
		for _, tag := range tags {
			results = append(results, &gen.SpeedTestResult{OutboundTag: To(tag), Error: To(test_utils.ErrTestAborted.Error()), Cancelled: To(true)})
		}
	} else {
		results = run(ctx)
	}
	var failed []string
	for _, result := range results {
		if result.GetError() != "" || result.GetCancelled() {
			failed = append(failed, result.GetOutboundTag())
		}
	}
	return &gen.SpeedTestResponse{Results: results, VpnStatus: vpn.failed(ctx, failed)}
}
