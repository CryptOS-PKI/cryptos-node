// Package apiconformance_test checks the node API contract end to end: the
// generated NodeService client, dialled over mTLS, reaches a handler for every
// RPC the generated server descriptor declares.
package apiconformance_test

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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	stdgrpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"github.com/CryptOS-PKI/cryptos-node/internal/audit"
	"github.com/CryptOS-PKI/cryptos-node/internal/bootstrap"
	"github.com/CryptOS-PKI/cryptos-node/internal/ca"
	nodegrpc "github.com/CryptOS-PKI/cryptos-node/internal/grpc"
)

// unservedByDesign lists the RPCs this build deliberately answers with
// Unimplemented from its own handler. They still have to reach that handler:
// the framework's "unknown service" or "unknown method" answer fails the test.
var unservedByDesign = map[string]bool{
	"SignCSR": true, // debug-only (build tag debug_signcsr)
}

func TestNodeServiceRoundTrip(t *testing.T) {
	pki := newTestPKI(t)
	client := startNode(t, pki)

	calls := rpcCalls(client)

	declared := map[string]bool{}
	for _, m := range nodev1.NodeService_ServiceDesc.Methods {
		declared[m.MethodName] = true
	}
	for _, s := range nodev1.NodeService_ServiceDesc.Streams {
		declared[s.StreamName] = true
	}
	for name := range declared {
		if _, ok := calls[name]; !ok {
			t.Errorf("NodeService declares %s but the round-trip test does not call it", name)
		}
	}
	for name := range calls {
		if !declared[name] {
			t.Errorf("the round-trip test calls %s, which NodeService does not declare", name)
		}
	}

	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			st := status.Convert(call(ctx))
			if st.Code() != codes.Unimplemented {
				return
			}
			msg := st.Message()
			if strings.HasPrefix(msg, "unknown service") || strings.HasPrefix(msg, "unknown method") {
				t.Fatalf("%s did not reach a handler: %v", name, msg)
			}
			if !unservedByDesign[name] {
				t.Fatalf("%s answered Unimplemented with every dependency wired: %v", name, msg)
			}
		})
	}
}

func rpcCalls(c nodev1.NodeServiceClient) map[string]func(context.Context) error {
	unary := func(f func(context.Context) error) func(context.Context) error { return f }
	return map[string]func(context.Context) error{
		"ApplyConfig": unary(func(ctx context.Context) error {
			_, err := c.ApplyConfig(ctx, &nodev1.ApplyConfigRequest{})
			return err
		}),
		"GetStatus": unary(func(ctx context.Context) error {
			_, err := c.GetStatus(ctx, &nodev1.GetStatusRequest{})
			return err
		}),
		"ListInstallDisks": unary(func(ctx context.Context) error {
			_, err := c.ListInstallDisks(ctx, &nodev1.ListInstallDisksRequest{})
			return err
		}),
		"GetIdentity": unary(func(ctx context.Context) error {
			_, err := c.GetIdentity(ctx, &nodev1.GetIdentityRequest{})
			return err
		}),
		"StartCeremony": func(ctx context.Context) error {
			stream, err := c.StartCeremony(ctx, &nodev1.StartCeremonyRequest{})
			if err != nil {
				return err
			}
			for {
				if _, err := stream.Recv(); err != nil {
					if errors.Is(err, io.EOF) {
						return nil
					}
					return err
				}
			}
		},
		"SignCSR": unary(func(ctx context.Context) error {
			_, err := c.SignCSR(ctx, &nodev1.SignCSRRequest{})
			return err
		}),
		"SignSubordinateCSR": unary(func(ctx context.Context) error {
			_, err := c.SignSubordinateCSR(ctx, &nodev1.SignSubordinateCSRRequest{})
			return err
		}),
		"IssueLeaf": unary(func(ctx context.Context) error {
			_, err := c.IssueLeaf(ctx, &nodev1.IssueLeafRequest{})
			return err
		}),
		"GetSubordinateCSR": unary(func(ctx context.Context) error {
			_, err := c.GetSubordinateCSR(ctx, &nodev1.GetSubordinateCSRRequest{})
			return err
		}),
		"SubmitSubordinateCertificate": unary(func(ctx context.Context) error {
			_, err := c.SubmitSubordinateCertificate(ctx, &nodev1.SubmitSubordinateCertificateRequest{})
			return err
		}),
		"RevokeCertificate": unary(func(ctx context.Context) error {
			_, err := c.RevokeCertificate(ctx, &nodev1.RevokeCertificateRequest{})
			return err
		}),
		"ListIssued": unary(func(ctx context.Context) error {
			_, err := c.ListIssued(ctx, &nodev1.ListIssuedRequest{})
			return err
		}),
		"ListRevocations": unary(func(ctx context.Context) error {
			_, err := c.ListRevocations(ctx, &nodev1.ListRevocationsRequest{})
			return err
		}),
		"GetIssuedCertificate": unary(func(ctx context.Context) error {
			_, err := c.GetIssuedCertificate(ctx, &nodev1.GetIssuedCertificateRequest{})
			return err
		}),
		"ExportCAKey": unary(func(ctx context.Context) error {
			_, err := c.ExportCAKey(ctx, &nodev1.ExportCAKeyRequest{})
			return err
		}),
		"ImportCAKey": unary(func(ctx context.Context) error {
			_, err := c.ImportCAKey(ctx, &nodev1.ImportCAKeyRequest{})
			return err
		}),
		"BeginKeyRotation": unary(func(ctx context.Context) error {
			_, err := c.BeginKeyRotation(ctx, &nodev1.BeginKeyRotationRequest{})
			return err
		}),
		"CompleteKeyRotation": unary(func(ctx context.Context) error {
			_, err := c.CompleteKeyRotation(ctx, &nodev1.CompleteKeyRotationRequest{})
			return err
		}),
		"GetRenewalCSR": unary(func(ctx context.Context) error {
			_, err := c.GetRenewalCSR(ctx, &nodev1.GetRenewalCSRRequest{})
			return err
		}),
		"SubmitRenewedCertificate": unary(func(ctx context.Context) error {
			_, err := c.SubmitRenewedCertificate(ctx, &nodev1.SubmitRenewedCertificateRequest{})
			return err
		}),
		"Reset": unary(func(ctx context.Context) error {
			_, err := c.Reset(ctx, &nodev1.ResetRequest{})
			return err
		}),
		"RemoteReset": unary(func(ctx context.Context) error {
			_, err := c.RemoteReset(ctx, &nodev1.RemoteResetRequest{})
			return err
		}),
		"Attest": unary(func(ctx context.Context) error {
			_, err := c.Attest(ctx, &nodev1.AttestRequest{})
			return err
		}),
		"SetManagement": unary(func(ctx context.Context) error {
			_, err := c.SetManagement(ctx, &nodev1.SetManagementRequest{})
			return err
		}),
		"GetConfig": unary(func(ctx context.Context) error {
			_, err := c.GetConfig(ctx, &nodev1.GetConfigRequest{})
			return err
		}),
		"StageImage": func(ctx context.Context) error {
			stream, err := c.StageImage(ctx)
			if err != nil {
				return err
			}
			if err := stream.Send(&nodev1.StageImageRequest{}); err != nil && !errors.Is(err, io.EOF) {
				return err
			}
			_, err = stream.CloseAndRecv()
			return err
		},
		"RollbackImage": unary(func(ctx context.Context) error {
			_, err := c.RollbackImage(ctx, &nodev1.RollbackImageRequest{})
			return err
		}),
		"ActivateImage": unary(func(ctx context.Context) error {
			_, err := c.ActivateImage(ctx, &nodev1.ActivateImageRequest{})
			return err
		}),
		"GetImageStatus": unary(func(ctx context.Context) error {
			_, err := c.GetImageStatus(ctx, &nodev1.GetImageStatusRequest{})
			return err
		}),
		"Reboot": unary(func(ctx context.Context) error {
			_, err := c.Reboot(ctx, &nodev1.RebootRequest{})
			return err
		}),
		"MintScepChallenge": unary(func(ctx context.Context) error {
			_, err := c.MintScepChallenge(ctx, &nodev1.MintScepChallengeRequest{})
			return err
		}),
		"ListScepChallenges": unary(func(ctx context.Context) error {
			_, err := c.ListScepChallenges(ctx, &nodev1.ListScepChallengesRequest{})
			return err
		}),
		"RevokeScepChallenge": unary(func(ctx context.Context) error {
			_, err := c.RevokeScepChallenge(ctx, &nodev1.RevokeScepChallengeRequest{})
			return err
		}),
		"ListScepEnrollments": unary(func(ctx context.Context) error {
			_, err := c.ListScepEnrollments(ctx, &nodev1.ListScepEnrollmentsRequest{})
			return err
		}),
		"ApproveScepEnrollment": unary(func(ctx context.Context) error {
			_, err := c.ApproveScepEnrollment(ctx, &nodev1.ApproveScepEnrollmentRequest{})
			return err
		}),
		"RejectScepEnrollment": unary(func(ctx context.Context) error {
			_, err := c.RejectScepEnrollment(ctx, &nodev1.RejectScepEnrollmentRequest{})
			return err
		}),
		"ListTsaCertificates": unary(func(ctx context.Context) error {
			_, err := c.ListTsaCertificates(ctx, &nodev1.ListTsaCertificatesRequest{})
			return err
		}),
		"ListAuditEvents": unary(func(ctx context.Context) error {
			_, err := c.ListAuditEvents(ctx, &nodev1.ListAuditEventsRequest{})
			return err
		}),
		"VerifyAuditChain": unary(func(ctx context.Context) error {
			_, err := c.VerifyAuditChain(ctx, &nodev1.VerifyAuditChainRequest{})
			return err
		}),
	}
}

// startNode serves NodeService over mTLS on a loopback port with every
// dependency wired to a fake, and returns a generated client dialled to it
// with the pinned admin certificate.
func startNode(t *testing.T, pki testPKI) nodev1.NodeServiceClient {
	t.Helper()
	fp := sha256.Sum256(pki.adminLeaf.Raw)
	trust, err := bootstrap.LoadTrust("", hex.EncodeToString(fp[:]))
	if err != nil {
		t.Fatalf("LoadTrust: %v", err)
	}
	f := fakes{}
	srv, err := nodegrpc.New(nodegrpc.ServerConfig{
		TLSConfig:           pki.server,
		Auditor:             f,
		Identity:            f,
		Status:              f,
		Ceremony:            f,
		ConfigStore:         f,
		Installer:           f,
		DiskLister:          f,
		Resetter:            f,
		RemoteResetter:      f,
		Signer:              f,
		SubordinateSigner:   f,
		LeafSigner:          f,
		SubordinateEnroller: f,
		Rekeyer:             f,
		Renewer:             f,
		Revoker:             f,
		Exporter:            f,
		Importer:            f,
		Attester:            f,
		ImageUpgrader:       imageFakes{},
		Rebooter:            f,
		ScepAdmin:           f,
		AuditLog:            f,
		Trust:               trust,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := stdgrpc.NewClient(lis.Addr().String(), stdgrpc.WithTransportCredentials(credentials.NewTLS(pki.client)))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return nodev1.NewNodeServiceClient(conn)
}

// errFake is what every fake dependency answers, so each handler runs to the
// point where it calls its dependency and fails cleanly.
var errFake = errors.New("apiconformance: fake dependency")

type fakes struct{}

func (fakes) Append(*nodev1.AuditEvent) error { return nil }
func (fakes) Get(context.Context) (*nodev1.Identity, error) {
	return nil, errFake
}
func (fakes) Status(context.Context) (*nodev1.NodeStatus, error) { return nil, errFake }
func (fakes) Start(context.Context, *nodev1.StartCeremonyRequest, func(*nodev1.StartCeremonyResponse) error) error {
	return errFake
}
func (fakes) Apply(context.Context, *nodev1.MachineConfig) (*nodev1.ApplyConfigResponse, error) {
	return nil, errFake
}
func (fakes) Current(context.Context) (*nodev1.MachineConfig, error) { return nil, errFake }
func (fakes) Install(context.Context, *nodev1.MachineConfig) (*nodev1.ApplyConfigResponse, error) {
	return nil, errFake
}
func (fakes) ListInstallDisks(context.Context) ([]*nodev1.InstallDisk, error) { return nil, errFake }
func (fakes) Reset(context.Context, string) error                             { return errFake }
func (fakes) SignCSR(context.Context, []byte, string) ([]byte, error)         { return nil, errFake }
func (fakes) SignSubordinate(context.Context, []byte, string) ([][]byte, string, *ca.ValidityCap, error) {
	return nil, "", nil, errFake
}
func (fakes) IssueLeafWithRequestSANs(context.Context, []byte, string, []string) ([]byte, *ca.ValidityCap, error) {
	return nil, nil, errFake
}
func (fakes) CSR(context.Context) ([]byte, error) { return nil, errFake }
func (fakes) AcceptCertificate(context.Context, [][]byte) (*nodev1.Identity, error) {
	return nil, errFake
}
func (fakes) BeginRotation(context.Context) ([]byte, error) { return nil, errFake }
func (fakes) CompleteRotation(context.Context, [][]byte) (*nodev1.Identity, error) {
	return nil, errFake
}
func (fakes) RenewalCSR(context.Context) ([]byte, error) { return nil, errFake }
func (fakes) AcceptRenewal(context.Context, [][]byte) (*nodev1.Identity, error) {
	return nil, errFake
}
func (fakes) Revoke(context.Context, string, int) (*nodev1.Revocation, error) { return nil, errFake }
func (fakes) ListIssued(context.Context) ([]*nodev1.IssuedCert, error)        { return nil, errFake }
func (fakes) ListRevocations(context.Context) ([]*nodev1.Revocation, error)   { return nil, errFake }
func (fakes) GetIssuedCertificate(context.Context, string) (*nodev1.GetIssuedCertificateResponse, error) {
	return nil, errFake
}
func (fakes) ExportCAKey(context.Context, []byte) ([]byte, error) { return nil, errFake }
func (fakes) ImportCAKey(context.Context, []byte, []byte) (*nodev1.Identity, error) {
	return nil, errFake
}
func (fakes) SignNonce(context.Context, []byte) ([]byte, []byte, error) { return nil, nil, errFake }
func (fakes) Reboot(context.Context, string, bool) error                { return errFake }
func (fakes) MintScepChallenge(context.Context, *nodev1.MintScepChallengeRequest, string) (*nodev1.MintScepChallengeResponse, error) {
	return nil, errFake
}
func (fakes) ListScepChallenges(context.Context, *nodev1.ListScepChallengesRequest) (*nodev1.ListScepChallengesResponse, error) {
	return nil, errFake
}
func (fakes) RevokeScepChallenge(context.Context, *nodev1.RevokeScepChallengeRequest) (*nodev1.RevokeScepChallengeResponse, error) {
	return nil, errFake
}
func (fakes) ListScepEnrollments(context.Context, *nodev1.ListScepEnrollmentsRequest) (*nodev1.ListScepEnrollmentsResponse, error) {
	return nil, errFake
}
func (fakes) ApproveScepEnrollment(context.Context, *nodev1.ApproveScepEnrollmentRequest) (*nodev1.ApproveScepEnrollmentResponse, error) {
	return nil, errFake
}
func (fakes) RejectScepEnrollment(context.Context, *nodev1.RejectScepEnrollmentRequest) (*nodev1.RejectScepEnrollmentResponse, error) {
	return nil, errFake
}
func (fakes) List(audit.Query) (audit.Page, error) { return audit.Page{}, errFake }
func (fakes) Verify() (audit.VerifyResult, error)  { return audit.VerifyResult{}, errFake }

// imageFakes backs ImageUpgrader, whose Status method would clash with
// StatusProvider's on a single type.
type imageFakes struct{}

func (imageFakes) Stage(context.Context, []byte, []byte) (*nodev1.ImageStatus, error) {
	return nil, errFake
}
func (imageFakes) Rollback(context.Context) (*nodev1.ImageStatus, error) { return nil, errFake }
func (imageFakes) Activate(context.Context, string) error                { return errFake }
func (imageFakes) Status(context.Context) (*nodev1.ImageStatus, error)   { return nil, errFake }

type testPKI struct {
	server    *tls.Config
	client    *tls.Config
	adminLeaf *x509.Certificate
}

// newTestPKI mints a throwaway CA, a loopback server certificate and an
// admin client certificate, all in memory.
func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "apiconformance-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	leaf := func(serial int64, cn string, server bool) (tls.Certificate, *x509.Certificate) {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatalf("leaf key: %v", err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		if server {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatalf("leaf cert: %v", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("parse leaf: %v", err)
		}
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}, cert
	}
	serverCert, _ := leaf(2, "node.test", true)
	adminCert, adminLeaf := leaf(3, "admin.test", false)

	return testPKI{
		server: &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientCAs:    pool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			MinVersion:   tls.VersionTLS13,
		},
		client: &tls.Config{
			Certificates: []tls.Certificate{adminCert},
			RootCAs:      pool,
			ServerName:   "127.0.0.1",
			MinVersion:   tls.VersionTLS13,
		},
		adminLeaf: adminLeaf,
	}
}
