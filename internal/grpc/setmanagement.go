package grpc

/*
Copyright The CryptOS Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import (
	"context"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SetManagement handles cryptos.node.v1.NodeService/SetManagement. It merges the
// supplied managed-state into the node's own persisted config (a
// read-modify-write: read the current config, replace only Management,
// persist) rather than replacing the whole config, so a Fleet Manager LINK
// enrollment can mark the node managed without clobbering role, network,
// bootstrap, or PKI settings it never touched. A nil Management unlinks the
// node from its Fleet Manager.
//
// Only available on a running node (ConfigStore != nil); the maintenance
// servers leave ConfigStore nil, so SetManagement returns Unimplemented
// there, matching the other running-node-only RPCs. A node with no persisted
// config yet has nothing to merge into and returns FailedPrecondition.
func (s *Server) SetManagement(ctx context.Context, req *nodev1.SetManagementRequest) (_ *nodev1.SetManagementResponse, retErr error) {
	// The Fleet Manager reports a masked error to the operator, so the node's
	// own audit entry carries the reason a refused call was refused.
	defer func() {
		if retErr != nil {
			auditFailure(ctx, retErr)
		}
	}()
	if s.cfg.ConfigStore == nil {
		return nil, status.Error(codes.Unimplemented, "SetManagement not available in maintenance mode")
	}
	if err := AuthorizeAdmin(ctx, s.cfg.Trust); err != nil {
		return nil, err
	}
	cur, err := s.cfg.ConfigStore.Current(ctx)
	if err != nil {
		if status.Code(err) == codes.FailedPrecondition {
			return nil, status.Errorf(codes.FailedPrecondition, "SetManagement: %s", status.Convert(err).Message())
		}
		return nil, status.Errorf(codes.Internal, "SetManagement: read config: %v", err)
	}
	cur.Management = req.GetManagement() // merge: set or clear, all else preserved
	resp, err := s.cfg.ConfigStore.Apply(ctx, cur)
	if err != nil {
		// Keep InvalidArgument: the merged config failed validation, which
		// is not a node fault.
		if status.Code(err) == codes.InvalidArgument {
			return nil, status.Errorf(codes.InvalidArgument, "SetManagement: apply: %v", status.Convert(err).Message())
		}
		return nil, status.Errorf(codes.Internal, "SetManagement: apply: %v", err)
	}
	return &nodev1.SetManagementResponse{Generation: resp.GetGeneration(), RequiresReboot: resp.GetRequiresReboot()}, nil
}
