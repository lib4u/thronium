package main

import (
	"ThroneCore/gen"
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestVPNDiagnosticsWaitBeforeActualHTTP(t *testing.T) {
	for _, kind := range []string{"ip", "speed"} {
		t.Run(kind, func(t *testing.T) {
			state := newTestVPNState(&gen.VPNEndpointStatus{Tag: To("proxy"), State: To("connecting")})
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !state.endpoint().snapshot().GetConnected() {
					t.Error("measurement reached HTTP before VPN readiness")
				}
				requests.Add(1)
				w.WriteHeader(200)
			}))
			defer server.Close()
			waiting := make(chan struct{})
			done := make(chan struct{})
			var measured atomic.Bool
			collect := func(ctx context.Context, tags []string, limit time.Duration) []*gen.VPNEndpointStatus {
				close(waiting)
				return []*gen.VPNEndpointStatus{awaitVPNStatus(ctx, state.endpoint(), limit)}
			}
			request := func(ctx context.Context) {
				measured.Store(true)
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
				res, err := server.Client().Do(req)
				if err != nil {
					t.Error(err)
					return
				}
				res.Body.Close()
			}
			go func() {
				defer close(done)
				if kind == "ip" {
					out := runIPMeasurement(context.Background(), &gen.IPTestRequest{VpnEndpointTags: []string{"proxy"}}, []string{"proxy"}, nil, func(ctx context.Context) []*gen.IPTestRes {
						request(ctx)
						return []*gen.IPTestRes{{OutboundTag: To("proxy"), Ip: To("203.0.113.9")}}
					}, collect)
					if len(out.Results) != 1 || out.Results[0].GetIp() != "203.0.113.9" || len(out.VpnStatus) != 0 {
						t.Error("IP result lost")
					}
				} else {
					out := runSpeedMeasurement(context.Background(), &gen.SpeedTestRequest{VpnEndpointTags: []string{"proxy"}}, []string{"proxy"}, nil, func(ctx context.Context) []*gen.SpeedTestResult {
						request(ctx)
						return []*gen.SpeedTestResult{{OutboundTag: To("proxy"), DlBytes: To(int64(123))}}
					}, collect)
					if len(out.Results) != 1 || out.Results[0].GetDlBytes() != 123 || len(out.VpnStatus) != 0 {
						t.Error("speed result lost")
					}
				}
			}()
			<-waiting
			if measured.Load() || requests.Load() != 0 {
				t.Fatal("measurement did not wait")
			}
			state.set(&gen.VPNEndpointStatus{Tag: To("proxy"), State: To("connected"), Connected: To(true)})
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("VPN readiness did not release measurement")
			}
			if requests.Load() != 1 {
				t.Fatal("missing actual HTTP measurement")
			}
		})
	}
}

func TestVPNDiagnosticsCancellationNeverStartsMeasurement(t *testing.T) {
	for _, kind := range []string{"ip", "speed"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var calls []time.Duration
			collect := func(ctx context.Context, tags []string, limit time.Duration) []*gen.VPNEndpointStatus {
				calls = append(calls, limit)
				cancel()
				return nil
			}
			if kind == "ip" {
				out := runIPMeasurement(ctx, &gen.IPTestRequest{VpnEndpointTags: []string{"proxy"}}, []string{"proxy"}, nil, func(context.Context) []*gen.IPTestRes { t.Fatal("cancelled IP callback ran"); return nil }, collect)
				if len(out.Results) != 1 || out.Results[0].GetError() != "test aborted" {
					t.Fatal("missing IP cancellation")
				}
			} else {
				out := runSpeedMeasurement(ctx, &gen.SpeedTestRequest{VpnEndpointTags: []string{"proxy"}}, []string{"proxy"}, nil, func(context.Context) []*gen.SpeedTestResult { t.Fatal("cancelled speed callback ran"); return nil }, collect)
				if len(out.Results) != 1 || !out.Results[0].GetCancelled() {
					t.Fatal("missing speed cancellation")
				}
			}
			if !reflect.DeepEqual(calls, []time.Duration{10 * time.Second, 0}) {
				t.Fatalf("unexpected readiness budget: %v", calls)
			}
		})
	}
}

func TestVPNDiagnosticsShareBudgetAndCollectFreshMeasuredFailures(t *testing.T) {
	ctx := context.Background()
	var calls []time.Duration
	var seen [][]string
	collect := func(ctx context.Context, tags []string, limit time.Duration) []*gen.VPNEndpointStatus {
		calls = append(calls, limit)
		seen = append(seen, append([]string(nil), tags...))
		if limit > 0 {
			<-ctx.Done()
		}
		return []*gen.VPNEndpointStatus{{Tag: To("proxy"), State: To("auth-pending")}}
	}
	started := time.Now()
	out := runSpeedMeasurement(ctx, &gen.SpeedTestRequest{VpnEndpointTags: []string{"unrelated", "proxy", "proxy"}, VpnStatusTimeoutMs: To(int32(30))}, []string{"proxy", "ordinary"}, nil, func(context.Context) []*gen.SpeedTestResult {
		return []*gen.SpeedTestResult{{OutboundTag: To("proxy"), Error: To("failed")}, {OutboundTag: To("ordinary"), Error: To("failed")}}
	}, collect)
	if time.Since(started) > time.Second || !reflect.DeepEqual(calls, []time.Duration{30 * time.Millisecond, 0}) || !reflect.DeepEqual(seen, [][]string{{"proxy"}, {"proxy"}}) || len(out.VpnStatus) != 1 || out.VpnStatus[0].GetState() != "auth-pending" {
		t.Fatalf("bad readiness/status contract: %v %v %v", calls, seen, out)
	}
}

func TestVPNDiagnosticsLeaveOrdinaryAndLiveMeasurementsAlone(t *testing.T) {
	for _, live := range []bool{false, true} {
		calls := 0
		measured := false
		request := &gen.SpeedTestRequest{TestCurrent: To(live)}
		if live {
			request.VpnEndpointTags = []string{"proxy"}
		}
		out := runSpeedMeasurement(context.Background(), request, []string{"proxy"}, nil, func(context.Context) []*gen.SpeedTestResult {
			measured = true
			return []*gen.SpeedTestResult{{OutboundTag: To("proxy"), DlBytes: To(int64(55))}}
		}, func(context.Context, []string, time.Duration) []*gen.VPNEndpointStatus { calls++; return nil })
		if !measured || calls != 0 || len(out.Results) != 1 || out.Results[0].GetDlBytes() != 55 {
			t.Fatal("ordinary/live success changed")
		}
	}
}

func TestSpeedMeasurementEmptyRequestIsRejectedWithoutStartingBox(t *testing.T) {
	_, err := (&server{}).SpeedTest(context.Background(), &gen.SpeedTestRequest{})
	if err == nil || err.Error() != "cannot run empty test" {
		t.Fatalf("unexpected empty request outcome: %v", err)
	}
}

func TestVPNDiagnosticsAwaitDependencyEndpointsAndReportThemOnFailure(t *testing.T) {
	hop := newTestVPNState(&gen.VPNEndpointStatus{Tag: To("hop"), State: To("connected"), Connected: To(true)})
	var awaited [][]string
	collect := func(ctx context.Context, tags []string, limit time.Duration) []*gen.VPNEndpointStatus {
		awaited = append(awaited, tags)
		var out []*gen.VPNEndpointStatus
		for range tags {
			out = append(out, awaitVPNStatus(ctx, hop.endpoint(), limit))
		}
		return out
	}
	out := runIPMeasurement(context.Background(), &gen.IPTestRequest{VpnEndpointTags: []string{"hop", "ghost"}}, []string{"proxy"}, []string{"hop"}, func(context.Context) []*gen.IPTestRes {
		return []*gen.IPTestRes{{OutboundTag: To("proxy"), Error: To("owned failure")}}
	}, collect)
	if !reflect.DeepEqual(awaited, [][]string{{"hop"}, {"hop"}}) || len(out.VpnStatus) != 1 || out.VpnStatus[0].GetTag() != "hop" {
		t.Fatalf("dependency endpoint handling: awaited=%v status=%v", awaited, out.VpnStatus)
	}
	awaited = nil
	ok := runIPMeasurement(context.Background(), &gen.IPTestRequest{VpnEndpointTags: []string{"hop"}}, []string{"proxy"}, []string{"hop"}, func(context.Context) []*gen.IPTestRes {
		return []*gen.IPTestRes{{OutboundTag: To("proxy"), Ip: To("203.0.113.9")}}
	}, collect)
	if !reflect.DeepEqual(awaited, [][]string{{"hop"}}) || len(ok.VpnStatus) != 0 {
		t.Fatalf("successful measurement must not snapshot again: awaited=%v status=%v", awaited, ok.VpnStatus)
	}
}
