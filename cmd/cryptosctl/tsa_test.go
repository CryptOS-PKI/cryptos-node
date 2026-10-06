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

type fakeTsaCertificates struct{ certs []*nodev1.TsaCertificate }

func (f fakeTsaCertificates) ListTsaCertificates(context.Context) ([]*nodev1.TsaCertificate, error) {
	return f.certs, nil
}

func startTsaServer(t *testing.T, lister cgrpc.TsaCertificateLister) *testServer {
	t.Helper()
	return startTestServerWith(t, func(cfg *cgrpc.ServerConfig, clientCert *x509.Certificate) {
		cfg.TsaCertificates = lister
		fp := sha256.Sum256(clientCert.Raw)
		trust, err := bootstrap.LoadTrust("", hex.EncodeToString(fp[:]))
		if err != nil {
			t.Fatalf("LoadTrust: %v", err)
		}
		cfg.Trust = trust
	})
}

func TestTSACertificatesListsNewestFirstAndMarksTheCurrentOne(t *testing.T) {
	nb := timestamppb.New(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	na := timestamppb.New(time.Date(2027, 10, 1, 0, 0, 0, 0, time.UTC))
	ts := startTsaServer(t, fakeTsaCertificates{certs: []*nodev1.TsaCertificate{
		{SerialHex: "b2", Sha256Hex: strings.Repeat("ab", 32), NotBefore: nb, NotAfter: na, Current: true, CertPem: "-----BEGIN CERTIFICATE-----\nQg==\n-----END CERTIFICATE-----\n"},
		{SerialHex: "a1", Sha256Hex: strings.Repeat("cd", 32), NotBefore: nb, NotAfter: na, CertPem: "-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----\n"},
	}})
	out, err := ts.run(t, "tsa", "certificates")
	if err != nil {
		t.Fatalf("tsa certificates: %v\n%s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 || !strings.Contains(lines[0], "SERIAL") || !strings.HasPrefix(lines[1], "b2") || !strings.Contains(lines[1], "yes") ||
		!strings.HasPrefix(lines[2], "a1") || strings.Contains(lines[2], "yes") || !strings.Contains(lines[1], "2027-10-01T00:00:00Z") {
		t.Fatalf("output:\n%s", out)
	}

	out, err = ts.run(t, "tsa", "certificates", "--pem")
	if err != nil || strings.Count(out, "BEGIN CERTIFICATE") != 2 {
		t.Fatalf("--pem: %v\n%s", err, out)
	}
}

func TestTSACertificatesWhenNoneExist(t *testing.T) {
	ts := startTsaServer(t, fakeTsaCertificates{})
	out, err := ts.run(t, "tsa", "certificates")
	if err != nil || !strings.Contains(out, "no TSA certificates") {
		t.Fatalf("tsa certificates: %v\n%s", err, out)
	}
}
