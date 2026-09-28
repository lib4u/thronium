package main

import (
	"ThroneCore/gen"
	"ThroneCore/internal/endpointprobe"
	"context"
)

func (s *server) EndpointProbe(ctx context.Context, in *gen.EndpointProbeReq) (*gen.EndpointProbeResp, error) {
	ms, code := endpointprobe.Run(ctx, in.GetMethod(), in.GetHost(), in.GetPort(), in.GetTimeoutMs())
	return &gen.EndpointProbeResp{LatencyMs: &ms, Error: &code}, nil
}
