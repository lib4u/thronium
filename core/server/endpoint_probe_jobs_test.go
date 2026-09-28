package main

import (
	"ThroneCore/gen"
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestEndpointJobsAreBoundedConsumableAndCancelable(t *testing.T) {
	endpointJobs.Lock()
	for _, j := range endpointJobs.jobs {
		j.cancel()
	}
	endpointJobs.jobs = map[string]*endpointJob{}
	endpointJobs.Unlock()
	t.Cleanup(func() {
		endpointJobs.Lock()
		defer endpointJobs.Unlock()
		for _, j := range endpointJobs.jobs {
			j.cancel()
		}
		endpointJobs.jobs = map[string]*endpointJob{}
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	p, _ := strconv.Atoi(port)
	ctx := context.Background()
	req := &gen.EndpointProbeReq{Method: To("tcp"), Host: To("localhost"), Port: To(uint32(p)), TimeoutMs: To(uint32(500))}
	s := &server{}
	var ids []string
	for i := 0; i < 10; i++ {
		j, err := s.StartEndpointProbe(ctx, req)
		if err != nil || j.GetId() == "" {
			t.Fatalf("start %v %v", j, err)
		}
		ids = append(ids, j.GetId())
	}
	rejected, _ := s.StartEndpointProbe(ctx, req)
	if rejected.GetError() != "probe_busy" {
		t.Fatal(rejected)
	}
	for _, id := range ids {
		deadline := time.Now().Add(2 * time.Second)
		for {
			j, err := s.QueryEndpointProbe(ctx, &gen.EndpointProbeJobReq{Id: &id})
			if err != nil {
				t.Fatal(err)
			}
			if j.GetDone() {
				if j.GetError() != "" || j.GetLatencyMs() < 0 {
					t.Fatal(j)
				}
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("job stuck")
			}
			time.Sleep(time.Millisecond)
		}
		consumed, _ := s.QueryEndpointProbe(ctx, &gen.EndpointProbeJobReq{Id: &id})
		if consumed.GetError() != "probe_direct_unavailable" {
			t.Fatal("reused completed job")
		}
	}
	j, _ := s.StartEndpointProbe(ctx, req)
	id := &gen.EndpointProbeJobReq{Id: j.Id}
	s.CancelEndpointProbe(ctx, id)
	cancelled, _ := s.QueryEndpointProbe(ctx, id)
	if cancelled.GetError() != "probe_direct_unavailable" {
		t.Fatal("cancelled job published")
	}
}
