package main

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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"github.com/CryptOS-PKI/cryptos-node/internal/bootstrap"
	cgrpc "github.com/CryptOS-PKI/cryptos-node/internal/grpc"
)

// fakeScepAdmin records what the scep verbs sent.
type fakeScepAdmin struct {
	mint    *nodev1.MintScepChallengeRequest
	revoke  string
	list    string
	approve string
	reject  *nodev1.RejectScepEnrollmentRequest
}

var testExpiry = timestamppb.New(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))

func (f *fakeScepAdmin) MintScepChallenge(_ context.Context, req *nodev1.MintScepChallengeRequest, actor string) (*nodev1.MintScepChallengeResponse, error) {
	f.mint = req
	return &nodev1.MintScepChallengeResponse{
		ChallengePassword: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
		Challenge:         &nodev1.ScepChallenge{Id: "c1", Profile: "cisco-device", BoundNames: req.GetBoundNames(), ExpiresAt: testExpiry, CreatedByCn: actor},
	}, nil
}

func (f *fakeScepAdmin) ListScepChallenges(context.Context, *nodev1.ListScepChallengesRequest) (*nodev1.ListScepChallengesResponse, error) {
	return &nodev1.ListScepChallengesResponse{Challenges: []*nodev1.ScepChallenge{{Id: "c1", Profile: "cisco-device", ExpiresAt: testExpiry, CreatedByCn: "roundtrip-admin"}}}, nil
}

func (f *fakeScepAdmin) RevokeScepChallenge(_ context.Context, req *nodev1.RevokeScepChallengeRequest) (*nodev1.RevokeScepChallengeResponse, error) {
	f.revoke = req.GetId()
	return &nodev1.RevokeScepChallengeResponse{Challenge: &nodev1.ScepChallenge{Id: req.GetId(), Profile: "cisco-device"}}, nil
}

func (f *fakeScepAdmin) ListScepEnrollments(_ context.Context, req *nodev1.ListScepEnrollmentsRequest) (*nodev1.ListScepEnrollmentsResponse, error) {
	f.list = req.GetProfile()
	return &nodev1.ListScepEnrollmentsResponse{Enrollments: []*nodev1.ScepEnrollment{{
		Id: "e1", Profile: "cisco-device", SubjectDn: "CN=sw1.example.com", DnsNames: []string{"sw1.example.com"}, KeyAlg: "RSA-2048", ReceivedAt: testExpiry,
	}}}, nil
}

func (f *fakeScepAdmin) ApproveScepEnrollment(_ context.Context, req *nodev1.ApproveScepEnrollmentRequest) (*nodev1.ApproveScepEnrollmentResponse, error) {
	f.approve = req.GetId()
	return &nodev1.ApproveScepEnrollmentResponse{Enrollment: &nodev1.ScepEnrollment{Id: req.GetId()}, SerialHex: "1a2b"}, nil
}

func (f *fakeScepAdmin) RejectScepEnrollment(_ context.Context, req *nodev1.RejectScepEnrollmentRequest) (*nodev1.RejectScepEnrollmentResponse, error) {
	f.reject = req
	return &nodev1.RejectScepEnrollmentResponse{Enrollment: &nodev1.ScepEnrollment{Id: req.GetId()}}, nil
}

func startScepServer(t *testing.T, admin cgrpc.ScepAdmin) *testServer {
	t.Helper()
	return startTestServerWith(t, func(cfg *cgrpc.ServerConfig, clientCert *x509.Certificate) {
		if admin != nil {
			cfg.ScepAdmin = admin
		}
		fp := sha256.Sum256(clientCert.Raw)
		trust, err := bootstrap.LoadTrust("", hex.EncodeToString(fp[:]))
		if err != nil {
			t.Fatalf("LoadTrust: %v", err)
		}
		cfg.Trust = trust
	})
}

func TestSCEPChallengeMint(t *testing.T) {
	f := &fakeScepAdmin{}
	ts := startScepServer(t, f)
	out, err := ts.run(t, "scep", "challenge", "mint", "--profile", "cisco-device", "--ttl", "30m", "--name", "sw1.example.com", "--name", "sw1-mgmt.example.com")
	if err != nil {
		t.Fatalf("mint: %v (out=%s)", err, out)
	}
	if f.mint.GetProfile() != "cisco-device" || f.mint.GetTtlSeconds() != 1800 || len(f.mint.GetBoundNames()) != 2 {
		t.Fatalf("request = %v", f.mint)
	}
	for _, want := range []string{"Challenge:   ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", "ID:          c1", "Expires:     2026-10-01T12:00:00Z", "sw1-mgmt.example.com", "shown once"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if _, err := ts.run(t, "scep", "challenge", "mint", "--ttl", "1500ms"); err == nil {
		t.Fatal("a TTL that is not whole seconds must be refused")
	}
	if _, err := ts.run(t, "scep", "challenge", "mint", "--ttl", "2000000h"); err == nil {
		t.Fatal("a TTL that does not fit in 32 bits of seconds must be refused")
	}
}

func TestSCEPChallengeListAndRevoke(t *testing.T) {
	f := &fakeScepAdmin{}
	ts := startScepServer(t, f)
	out, err := ts.run(t, "scep", "challenge", "list")
	if err != nil || !strings.Contains(out, "c1") || !strings.Contains(out, "cisco-device") || strings.Contains(out, "ABCDEF") {
		t.Fatalf("list: %v\n%s", err, out)
	}
	if _, err := ts.run(t, "scep", "challenge", "revoke"); err == nil {
		t.Fatal("revoke without --id must fail")
	}
	out, err = ts.run(t, "scep", "challenge", "revoke", "--id", "c1")
	if err != nil || f.revoke != "c1" || !strings.Contains(out, "Revoked challenge c1") {
		t.Fatalf("revoke: %v %q\n%s", err, f.revoke, out)
	}
}

func TestSCEPEnrollmentVerbs(t *testing.T) {
	f := &fakeScepAdmin{}
	ts := startScepServer(t, f)
	out, err := ts.run(t, "scep", "enrollments", "list", "--profile", "cisco-device")
	if err != nil || f.list != "cisco-device" || !strings.Contains(out, "e1") || !strings.Contains(out, "RSA-2048") {
		t.Fatalf("list: %v\n%s", err, out)
	}
	out, err = ts.run(t, "scep", "enrollments", "approve", "--id", "e1")
	if err != nil || f.approve != "e1" || !strings.Contains(out, "serial 1a2b") {
		t.Fatalf("approve: %v\n%s", err, out)
	}
	out, err = ts.run(t, "scep", "enrollments", "reject", "--id", "e1", "--reason", "unknown device")
	if err != nil || f.reject.GetReason() != "unknown device" || !strings.Contains(out, "Rejected enrolment e1") {
		t.Fatalf("reject: %v\n%s", err, out)
	}
}

func TestSCEPVerbsWhenSCEPIsOff(t *testing.T) {
	ts := startScepServer(t, nil)
	out, err := ts.run(t, "scep", "challenge", "mint")
	if err == nil || !strings.Contains(err.Error(), "SCEP is not running") {
		t.Fatalf("mint with SCEP off = %v (out=%s), want the not-running refusal", err, out)
	}
}

func TestRevokeRefusesAReasonCodeOutsideRFC5280(t *testing.T) {
	ts := startTestServer(t)
	// 1<<32 wraps to 0 (unspecified) if it is narrowed to 32 bits unchecked.
	for _, reason := range []string{"4294967296", "-1", "11"} {
		_, err := ts.run(t, "ca", "revoke", "--serial", "01", "--reason", reason)
		if err == nil || !strings.Contains(err.Error(), "--reason") {
			t.Errorf("--reason %s: want a --reason error, got %v", reason, err)
		}
	}
}
