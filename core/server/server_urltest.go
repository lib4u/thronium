package main

import (
	"ThroneCore/gen"
	"ThroneCore/test_utils"
	"context"
	"time"
)

type testVPNStatusCollector func(context.Context, []string, time.Duration) []*gen.VPNEndpointStatus

// Only explicitly requested endpoints the box actually runs may delay a fresh
// disposable test: measured outbounds, or endpoints a measured outbound dials
// through (a chain hop, a complete configuration's own endpoint). Deduplication
// also avoids redundant readiness subscriptions.
func measuredVPNEndpointTags(requested, measured, available []string) []string {
	selected := make(map[string]bool, len(measured)+len(available))
	for _, tag := range measured {
		selected[tag] = true
	}
	for _, tag := range available {
		selected[tag] = true
	}
	var tags []string
	for _, tag := range requested {
		if selected[tag] {
			tags = append(tags, tag)
			delete(selected, tag)
		}
	}
	return tags
}

func testVPNStatusTimeout(in *gen.TestReq) time.Duration {
	if ms := in.GetVpnStatusTimeoutMs(); ms > 0 {
		return time.Duration(ms) * time.Millisecond
	}
	return defaultVPNStatusTimeout
}

// A new VPN endpoint starts asynchronously. Wait in the same environment before
// dialing HTTP; collecting its status after an early dial failure is too late.
// The callbacks keep this orchestration independent of box construction and let
// tests exercise actual status transitions without creating a system tunnel.
func runURLTest(ctx context.Context, in *gen.TestReq, tags, available []string,
	run func(context.Context) []*test_utils.URLTestResult, collect testVPNStatusCollector,
) *gen.TestResp {
	var readiness []string
	if !in.GetTestCurrent() {
		readiness = measuredVPNEndpointTags(in.VpnEndpointTags, tags, available)
	}
	if len(readiness) > 0 {
		timeout := testVPNStatusTimeout(in)
		// All endpoints share this single budget, including resolution and waits.
		waitCtx, cancel := context.WithTimeout(ctx, timeout)
		collect(waitCtx, readiness, timeout)
		cancel()
	}

	var results []*test_utils.URLTestResult
	if len(readiness) > 0 && ctx.Err() != nil {
		// StopTest canceled the captured test context while awaiting readiness.
		// Do not start HTTP work after that cancellation.
		for _, tag := range tags {
			results = append(results, &test_utils.URLTestResult{Tag: tag, Error: test_utils.ErrTestAborted})
		}
	} else {
		results = run(ctx)
	}
	res := make([]*gen.URLTestResp, 0, len(results))
	failed := make(map[string]bool, len(results))
	for idx, data := range results {
		errStr := ""
		if data.Error != nil {
			errStr = data.Error.Error()
		}
		failed[tags[idx]] = errStr != ""
		res = append(res, &gen.URLTestResp{
			OutboundTag: To(tags[idx]),
			LatencyMs:   To(int32(data.Duration.Milliseconds())),
			Error:       To(errStr),
		})
	}
	out := &gen.TestResp{Results: res}
	anyFailed := false
	for _, f := range failed {
		anyFailed = anyFailed || f
	}
	measured := make(map[string]bool, len(tags))
	for _, tag := range tags {
		measured[tag] = true
	}
	dependency := make(map[string]bool, len(readiness))
	for _, tag := range readiness {
		dependency[tag] = !measured[tag]
	}
	var pending []string
	for _, tag := range in.VpnEndpointTags {
		// A failed measured outbound names itself; an awaited dependency endpoint
		// cannot, so any failure of the disposable measurement snapshots it as well.
		if failed[tag] || (anyFailed && dependency[tag]) {
			pending = append(pending, tag)
		}
	}
	if len(pending) > 0 {
		// A disposable test has spent its readiness budget already. Take a fresh
		// snapshot after failed HTTP without waiting again. Live-instance tests
		// retain their existing post-HTTP wait and never pre-wait.
		timeout := time.Duration(0)
		if in.GetTestCurrent() {
			timeout = testVPNStatusTimeout(in)
		}
		out.VpnStatus = collect(ctx, pending, timeout)
	}
	return out
}
