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
	"crypto/x509"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

type mockTsaCertificates struct {
	calls int
	certs []*nodev1.TsaCertificate
	err   error
}

func (m *mockTsaCertificates) ListTsaCertificates(context.Context) ([]*nodev1.TsaCertificate, error) {
	m.calls++
	return m.certs, m.err
}

func serverWithTsa(t *testing.T, lister TsaCertificateLister, adminCert *x509.Certificate) *Server {
	t.Helper()
	cfg := ServerConfig{Auditor: &mockAuditor{}, TLSConfig: mtlsTLSConfig(t), Trust: trustForCert(t, adminCert)}
	if lister != nil {
		cfg.TsaCertificates = lister
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

// The maintenance servers have no state partition open, so the RPC is
// FailedPrecondition there, as the contract says.
func TestListTsaCertificates_FailedPreconditionInMaintenance(t *testing.T) {
	admin := authzTestCert(t)
	srv := serverWithTsa(t, nil, admin)
	_, err := srv.ListTsaCertificates(authzMTLSContext(admin), &nodev1.ListTsaCertificatesRequest{})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition", status.Code(err))
	}
}

func TestListTsaCertificates_NonAdminIsDenied(t *testing.T) {
	admin := authzTestCert(t)
	m := &mockTsaCertificates{}
	srv := serverWithTsa(t, m, admin)
	_, err := srv.ListTsaCertificates(authzMTLSContext(authzTestCert(t)), &nodev1.ListTsaCertificatesRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}
	if m.calls != 0 {
		t.Fatal("the lister was reached for a non-admin caller")
	}
}

func TestListTsaCertificates_ReturnsTheList(t *testing.T) {
	admin := authzTestCert(t)
	m := &mockTsaCertificates{certs: []*nodev1.TsaCertificate{{SerialHex: "b2", Current: true}, {SerialHex: "a1"}}}
	srv := serverWithTsa(t, m, admin)
	resp, err := srv.ListTsaCertificates(authzMTLSContext(admin), &nodev1.ListTsaCertificatesRequest{})
	if err != nil {
		t.Fatalf("ListTsaCertificates: %v", err)
	}
	if len(resp.GetCertificates()) != 2 || resp.GetCertificates()[0].GetSerialHex() != "b2" {
		t.Fatalf("certificates = %v", resp.GetCertificates())
	}
	if _, err := srv.ListTsaCertificates(context.Background(), &nodev1.ListTsaCertificatesRequest{}); err != nil {
		t.Fatalf("over the local socket: %v", err)
	}
}

func TestListTsaCertificates_ReadFailureIsInternal(t *testing.T) {
	admin := authzTestCert(t)
	srv := serverWithTsa(t, &mockTsaCertificates{err: context.DeadlineExceeded}, admin)
	_, err := srv.ListTsaCertificates(authzMTLSContext(admin), &nodev1.ListTsaCertificatesRequest{})
	if status.Code(err) != codes.Internal {
		t.Fatalf("code = %v, want Internal", status.Code(err))
	}
}
