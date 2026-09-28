package main

import (
	"ThroneCore/gen"
	"ThroneCore/test_utils"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testVPNState struct {
	mu      sync.Mutex
	status  *gen.VPNEndpointStatus
	changed chan struct{}
}

func newTestVPNState(status *gen.VPNEndpointStatus) *testVPNState {
	return &testVPNState{status: status, changed: make(chan struct{})}
}

func (s *testVPNState) endpoint() *vpnEndpoint {
	return &vpnEndpoint{
		updated: func() <-chan struct{} {
			s.mu.Lock()
			defer s.mu.Unlock()
			return s.changed
		},
		snapshot: func() *gen.VPNEndpointStatus {
			s.mu.Lock()
			defer s.mu.Unlock()
			return s.status
		},
	}
}

func (s *testVPNState) set(status *gen.VPNEndpointStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = status
	close(s.changed)
	s.changed = make(chan struct{})
}

func vpnURLRequest() *gen.TestReq {
	return &gen.TestReq{VpnEndpointTags: []string{"proxy"}, VpnStatusTimeoutMs: To(int32(2000))}
}

func vpnURLFailure() []*test_utils.URLTestResult {
	return []*test_utils.URLTestResult{{Tag: "proxy", Error: errors.New("owned HTTP failure")}}
}

func TestVPNURLReadinessPrecedesActualHTTPRequest(t *testing.T) {
	state := newTestVPNState(&gen.VPNEndpointStatus{Tag: To("proxy"), State: To("connecting")})
	var requests atomic.Int32
	listener := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !state.endpoint().snapshot().GetConnected() {
			t.Error("HTTP reached the listener before VPN readiness")
		}
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer listener.Close()
	waiting := make(chan struct{})
	finished := make(chan *gen.TestResp, 1)
	go func() {
		finished <- runURLTest(context.Background(), vpnURLRequest(), []string{"proxy"}, nil, func(ctx context.Context) []*test_utils.URLTestResult {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, listener.URL, nil)
			if err == nil {
				var res *http.Response
				res, err = listener.Client().Do(req)
				if res != nil {
					res.Body.Close()
				}
			}
			return []*test_utils.URLTestResult{{Tag: "proxy", Duration: time.Millisecond, Error: err}}
		}, func(ctx context.Context, tags []string, timeout time.Duration) []*gen.VPNEndpointStatus {
			close(waiting)
			return []*gen.VPNEndpointStatus{awaitVPNStatus(ctx, state.endpoint(), timeout)}
		})
	}()
	<-waiting
	select {
	case <-finished:
		t.Fatal("HTTP operation finished while the endpoint was still connecting")
	default:
	}
	if requests.Load() != 0 {
		t.Fatal("HTTP started before readiness")
	}
	state.set(&gen.VPNEndpointStatus{Tag: To("proxy"), State: To("connected"), Connected: To(true)})
	select {
	case out := <-finished:
		if len(out.Results) != 1 || out.Results[0].GetError() != "" || out.Results[0].GetLatencyMs() != 1 || len(out.VpnStatus) != 0 || requests.Load() != 1 {
			t.Fatalf("unexpected HTTP outcome: %v, requests=%d", out, requests.Load())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("readiness transition did not release HTTP")
	}
}

func TestVPNURLCancellationDuringReadinessNeverStartsHTTP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	state := newTestVPNState(&gen.VPNEndpointStatus{Tag: To("proxy"), State: To("connecting")})
	var requests atomic.Int32
	listener := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer listener.Close()
	called := false
	var waits []time.Duration
	out := runURLTest(ctx, vpnURLRequest(), []string{"proxy"}, nil, func(ctx context.Context) []*test_utils.URLTestResult {
		called = true
		// Deliberately not cancellation-aware: the orchestration must not call it.
		res, err := listener.Client().Get(listener.URL)
		if res != nil {
			res.Body.Close()
		}
		return []*test_utils.URLTestResult{{Tag: "proxy", Error: err}}
	}, func(ctx context.Context, tags []string, timeout time.Duration) []*gen.VPNEndpointStatus {
		waits = append(waits, timeout)
		if timeout > 0 {
			cancel()
		}
		return []*gen.VPNEndpointStatus{awaitVPNStatus(ctx, state.endpoint(), timeout)}
	})
	if called || requests.Load() != 0 || len(out.Results) != 1 || out.Results[0].GetError() != test_utils.ErrTestAborted.Error() || !reflect.DeepEqual(waits, []time.Duration{2 * time.Second, 0}) {
		t.Fatalf("canceled prewait started HTTP or repeated wait: called=%v requests=%d waits=%v response=%v", called, requests.Load(), waits, out)
	}
}

func TestVPNURLReadinessUsesOneDeadlineAndFreshNonblockingStatus(t *testing.T) {
	in := vpnURLRequest()
	in.VpnEndpointTags = []string{"proxy", "second", "proxy", "unmeasured"}
	in.VpnStatusTimeoutMs = To(int32(25))
	var waits []time.Duration
	var deadline time.Time
	started := time.Now()
	httpStarted := false
	out := runURLTest(context.Background(), in, []string{"proxy", "second"}, nil, func(ctx context.Context) []*test_utils.URLTestResult {
		httpStarted = true
		if time.Now().Before(deadline) {
			t.Error("connecting endpoints did not wait for their shared deadline")
		}
		return []*test_utils.URLTestResult{vpnURLFailure()[0], {Tag: "second", Duration: time.Millisecond}}
	}, func(ctx context.Context, tags []string, timeout time.Duration) []*gen.VPNEndpointStatus {
		waits = append(waits, timeout)
		if timeout == 0 {
			if !httpStarted || !reflect.DeepEqual(tags, []string{"proxy", "proxy"}) {
				t.Errorf("fresh status must follow HTTP and include only failed requested tags: %v", tags)
			}
			return []*gen.VPNEndpointStatus{{Tag: To("proxy"), State: To("error"), AuthFailed: To(true)}}
		}
		if !reflect.DeepEqual(tags, []string{"proxy", "second"}) {
			t.Errorf("prewait must deduplicate the measured intersection: %v", tags)
		}
		var ok bool
		deadline, ok = ctx.Deadline()
		if !ok || deadline.Sub(started) > 100*time.Millisecond {
			t.Error("missing shared request deadline")
		}
		var wg sync.WaitGroup
		for range tags {
			wg.Add(1)
			go func() {
				defer wg.Done()
				state := newTestVPNState(&gen.VPNEndpointStatus{State: To("connecting")})
				awaitVPNStatus(ctx, state.endpoint(), time.Hour)
			}()
		}
		wg.Wait()
		return nil
	})
	if !httpStarted || !reflect.DeepEqual(waits, []time.Duration{25 * time.Millisecond, 0}) || len(out.VpnStatus) != 1 || !out.VpnStatus[0].GetAuthFailed() {
		t.Fatalf("not one readiness budget plus fresh snapshot: %v %v", waits, out)
	}
}

func TestVPNURLSettledStatesDoNotWaitForAnotherStatus(t *testing.T) {
	for _, status := range []*gen.VPNEndpointStatus{
		{State: To("connected"), Connected: To(true)},
		{State: To("error"), AuthFailed: To(true)},
		{State: To("auth-pending"), Challenge: &gen.VPNChallenge{Id: To("owned"), EndpointTag: To("proxy")}},
	} {
		t.Run(status.GetState(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			state := newTestVPNState(status)
			if got := awaitVPNStatus(ctx, state.endpoint(), time.Hour); got != status || ctx.Err() != nil {
				t.Fatal("terminal diagnostic state waited for an update")
			}
		})
	}
}

func TestVPNURLNoTagsAndCurrentKeepLegacyOrderingAndTimeout(t *testing.T) {
	for _, test := range []struct {
		name      string
		current   bool
		tags      []string
		failure   bool
		wantCalls []time.Duration
	}{
		{name: "ordinary-no-tags", failure: true},
		{name: "unmeasured-tag", tags: []string{"unmeasured"}, failure: true},
		{name: "current-failure", current: true, tags: []string{"proxy"}, failure: true, wantCalls: []time.Duration{17 * time.Second}},
		{name: "current-success", current: true, tags: []string{"proxy"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			in := &gen.TestReq{TestCurrent: To(test.current), VpnEndpointTags: test.tags, VpnStatusTimeoutMs: To(int32(17000))}
			var waits []time.Duration
			ran := false
			runURLTest(context.Background(), in, []string{"proxy"}, nil, func(context.Context) []*test_utils.URLTestResult {
				ran = true
				if test.failure {
					return vpnURLFailure()
				}
				return []*test_utils.URLTestResult{{Tag: "proxy", Duration: time.Millisecond}}
			}, func(ctx context.Context, tags []string, timeout time.Duration) []*gen.VPNEndpointStatus {
				if !ran {
					t.Error("legacy caller acquired a new pre-HTTP wait")
				}
				waits = append(waits, timeout)
				return nil
			})
			if !ran || !reflect.DeepEqual(waits, test.wantCalls) {
				t.Fatalf("legacy ordering/timeout changed: %v", waits)
			}
		})
	}
	if testVPNStatusTimeout(&gen.TestReq{}) != 10*time.Second || testVPNStatusTimeout(&gen.TestReq{VpnStatusTimeoutMs: To(int32(-1))}) != 10*time.Second || testVPNStatusTimeout(&gen.TestReq{VpnStatusTimeoutMs: To(int32(17000))}) != 17*time.Second {
		t.Fatal("default or explicit positive timeout changed")
	}
}

func TestVPNURLMissingAndEmptyEndpointTagsDoNotWait(t *testing.T) {
	for _, tag := range []string{"missing", ""} {
		t.Run("tag="+tag, func(t *testing.T) {
			in := &gen.TestReq{VpnEndpointTags: []string{tag}}
			var waits []time.Duration
			called := false
			out := runURLTest(context.Background(), in, []string{tag}, nil, func(context.Context) []*test_utils.URLTestResult {
				called = true
				return []*test_utils.URLTestResult{{Tag: tag, Error: errors.New("no outbound found")}}
			}, func(ctx context.Context, tags []string, timeout time.Duration) []*gen.VPNEndpointStatus {
				waits = append(waits, timeout)
				return collectVPNStatus(ctx, nil, tags, timeout)
			})
			if !called || len(out.VpnStatus) != 1 || out.VpnStatus[0].GetTag() != tag || out.VpnStatus[0].GetError() != errInstanceNotRunning.Error() || !reflect.DeepEqual(waits, []time.Duration{10 * time.Second, 0}) {
				t.Fatalf("missing endpoint behavior changed: %v waits=%v", out, waits)
			}
		})
	}
}

// A chain hop or a complete configuration's own endpoint is not a measured
// outbound, yet the measured outbound dials through it: the test waits for it
// like for the measured endpoint itself, and a failed measurement reports it.
func TestVPNURLDependencyEndpointsAwaitReadinessAndReportFailures(t *testing.T) {
	hop := newTestVPNState(&gen.VPNEndpointStatus{Tag: To("hop"), State: To("connecting")})
	in := &gen.TestReq{VpnEndpointTags: []string{"hop", "ghost"}, VpnStatusTimeoutMs: To(int32(2000))}
	var awaited [][]string
	var runs atomic.Int32
	finished := make(chan *gen.TestResp, 1)
	go func() {
		finished <- runURLTest(context.Background(), in, []string{"proxy"}, []string{"hop"}, func(ctx context.Context) []*test_utils.URLTestResult {
			runs.Add(1)
			if !hop.endpoint().snapshot().GetConnected() {
				t.Error("HTTP ran before the dependency endpoint was ready")
			}
			return []*test_utils.URLTestResult{{Tag: "proxy", Error: errors.New("owned HTTP failure")}}
		}, func(ctx context.Context, tags []string, timeout time.Duration) []*gen.VPNEndpointStatus {
			awaited = append(awaited, tags)
			var out []*gen.VPNEndpointStatus
			for range tags {
				out = append(out, awaitVPNStatus(ctx, hop.endpoint(), timeout))
			}
			return out
		})
	}()
	time.Sleep(50 * time.Millisecond)
	if runs.Load() != 0 {
		t.Fatal("HTTP did not wait for the dependency endpoint")
	}
	hop.set(&gen.VPNEndpointStatus{Tag: To("hop"), State: To("connected"), Connected: To(true)})
	select {
	case out := <-finished:
		// The unknown tag is never awaited; the awaited hop is snapshotted after the failure.
		if !reflect.DeepEqual(awaited, [][]string{{"hop"}, {"hop"}}) || len(out.VpnStatus) != 1 || out.VpnStatus[0].GetTag() != "hop" {
			t.Fatalf("dependency readiness: awaited=%v status=%v", awaited, out.VpnStatus)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("dependency readiness did not release HTTP")
	}
}
