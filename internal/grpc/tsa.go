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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

// TsaCertificateLister backs ListTsaCertificates: every TSA certificate the
// node has signed tokens with, newest first, read from the state partition
// whether or not the TSA runs this boot.
type TsaCertificateLister interface {
	ListTsaCertificates(ctx context.Context) ([]*nodev1.TsaCertificate, error)
}

// ListTsaCertificates handles cryptos.node.v1.NodeService/ListTsaCertificates.
// It is a read authorized like ListIssued. The maintenance servers leave the
// lister nil, so it answers FailedPrecondition there.
func (s *Server) ListTsaCertificates(ctx context.Context, _ *nodev1.ListTsaCertificatesRequest) (*nodev1.ListTsaCertificatesResponse, error) {
	if s.cfg.TsaCertificates == nil {
		return nil, status.Error(codes.FailedPrecondition, "the TSA certificates are not readable in maintenance mode")
	}
	if err := AuthorizeAdmin(ctx, s.cfg.Trust); err != nil {
		return nil, err
	}
	certs, err := s.cfg.TsaCertificates.ListTsaCertificates(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "ListTsaCertificates: %v", err)
	}
	return &nodev1.ListTsaCertificatesResponse{Certificates: certs}, nil
}
