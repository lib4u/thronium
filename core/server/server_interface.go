package main

import (
	"ThroneCore/gen"
	"ThroneCore/internal/boxdns"
	"context"
	"errors"
)

func (s *server) GetDefaultInterface(ctx context.Context, in *gen.EmptyReq) (*gen.GetDefaultInterfaceResponse, error) {
	ifc := boxdns.DefaultInterface()
	if ifc == nil {
		return nil, errors.New("no default interface")
	}
	return &gen.GetDefaultInterfaceResponse{
		Name:  To(ifc.Name),
		Index: To(int32(ifc.Index)),
	}, nil
}
