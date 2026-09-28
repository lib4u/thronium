package main

// The managed core already has the capability needed for its TUN output mark.
// Only short start/query/cancel RPCs use its IPC; network operations never block
// the supervisor, UI polling or disconnect. Jobs never load/alter a VPN config.
import (
	"ThroneCore/gen"
	"ThroneCore/internal/endpointprobe"
	"context"
	"crypto/rand"
	"google.golang.org/protobuf/proto"
	"sync"
	"time"
)

type endpointJob struct {
	result  *gen.EndpointProbeJob
	cancel  context.CancelFunc
	expires time.Time
}

var endpointJobs = struct {
	sync.Mutex
	jobs map[string]*endpointJob
}{jobs: map[string]*endpointJob{}}

func (s *server) StartEndpointProbe(_ context.Context, in *gen.EndpointProbeReq) (*gen.EndpointProbeJob, error) {
	endpointJobs.Lock()
	defer endpointJobs.Unlock()
	now := time.Now()
	for id, job := range endpointJobs.jobs {
		if now.After(job.expires) {
			job.cancel()
			delete(endpointJobs.jobs, id)
		}
	}
	if len(endpointJobs.jobs) >= 10 {
		return &gen.EndpointProbeJob{Done: To(true), Error: To("probe_busy")}, nil
	}
	id := rand.Text()
	ctx, cancel := context.WithCancel(context.Background())
	job := &endpointJob{result: &gen.EndpointProbeJob{Id: &id, Done: To(false)}, cancel: cancel, expires: now.Add(30 * time.Second)}
	endpointJobs.jobs[id] = job
	request := proto.Clone(in).(*gen.EndpointProbeReq)
	mark := autoRedirectMark.Load()
	go func() {
		ms, code := endpointprobe.RunWithMark(ctx, request.GetMethod(), request.GetHost(), request.GetPort(), request.GetTimeoutMs(), mark)
		cancel()
		endpointJobs.Lock()
		job.result = &gen.EndpointProbeJob{Id: &id, Done: To(true), LatencyMs: &ms, Error: &code}
		endpointJobs.Unlock()
	}()
	return proto.Clone(job.result).(*gen.EndpointProbeJob), nil
}

func (s *server) QueryEndpointProbe(_ context.Context, in *gen.EndpointProbeJobReq) (*gen.EndpointProbeJob, error) {
	endpointJobs.Lock()
	defer endpointJobs.Unlock()
	job := endpointJobs.jobs[in.GetId()]
	if job == nil {
		return &gen.EndpointProbeJob{Done: To(true), Error: To("probe_direct_unavailable")}, nil
	}
	result := proto.Clone(job.result).(*gen.EndpointProbeJob)
	if result.GetDone() {
		delete(endpointJobs.jobs, in.GetId())
	}
	return result, nil
}

func (s *server) CancelEndpointProbe(_ context.Context, in *gen.EndpointProbeJobReq) (*gen.EmptyResp, error) {
	endpointJobs.Lock()
	defer endpointJobs.Unlock()
	if job := endpointJobs.jobs[in.GetId()]; job != nil {
		job.cancel()
		delete(endpointJobs.jobs, in.GetId())
	}
	return &gen.EmptyResp{}, nil
}
