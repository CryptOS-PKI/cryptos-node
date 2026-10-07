package init

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
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"github.com/CryptOS-PKI/cryptos-node/internal/cms"
	"github.com/CryptOS-PKI/cryptos-node/internal/config"
	"github.com/CryptOS-PKI/cryptos-node/internal/revocation"
	"github.com/CryptOS-PKI/cryptos-node/internal/storage/etcd"
	"github.com/CryptOS-PKI/cryptos-node/internal/tsa"
)

type tsaFixture struct {
	ctx      context.Context
	ca       *estTestCA
	deps     tsaDeps
	revStore *revocation.Store
	synced   bool
}

func newTSAFixture(t *testing.T) *tsaFixture {
	t.Helper()
	srv, err := etcd.Open(t.TempDir())
	if err != nil {
		t.Fatalf("etcd.Open: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	cli, err := srv.Client()
	if err != nil {
		t.Fatalf("etcd.Client: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	f := &tsaFixture{ctx: ctx, ca: newESTTestCA(t), revStore: revocation.NewStore(cli), synced: true}
	f.deps = tsaDeps{
		cli: cli, backend: NewSoftRootBackend(), load: f.ca.loader(), issuer: f.ca.issuerFunc(), revStore: f.revStore,
		timeStatus: func() *nodev1.TimeSyncStatus {
			if !f.synced {
				return &nodev1.TimeSyncStatus{State: nodev1.TimeSyncState_TIME_SYNC_STATE_PENDING}
			}
			return &nodev1.TimeSyncStatus{
				State:      nodev1.TimeSyncState_TIME_SYNC_STATE_SYNCED,
				LastOffset: durationpb.New(3 * time.Millisecond),
				LastSync:   timestamppb.Now(),
			}
		},
	}
	return f
}

func tsaBootConfig() *config.Config {
	return &config.Config{PKI: config.PKI{
		RootKeyAlg: config.RootKeyECDSAP384,
		TSA:        &config.TSA{PolicyOID: "1.3.6.1.4.1.32473.1.1", AllowedNetworks: []string{"192.0.2.0/24"}},
	}}
}

func tsaQuery(t *testing.T, h http.Handler, remote string) *httptest.ResponseRecorder {
	t.Helper()
	sum := sha256.Sum256([]byte("artifact"))
	type imprint struct {
		Alg  struct{ Algorithm asn1.ObjectIdentifier }
		Hash []byte
	}
	var mi imprint
	mi.Alg.Algorithm = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	mi.Hash = sum[:]
	der, err := asn1.Marshal(struct {
		Version int
		MI      imprint
		CertReq bool
	}{1, mi, true})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(der))
	req.RemoteAddr = remote
	req.Header.Set("Content-Type", tsa.ContentTypeQuery)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// tokenSigner returns the certificate a granted reply's token is signed by.
func tokenSigner(t *testing.T, body []byte) *x509.Certificate {
	t.Helper()
	var resp struct {
		Status struct{ Status int }
		Token  asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(body, &resp); err != nil {
		t.Fatalf("not a TimeStampResp: %v", err)
	}
	if resp.Status.Status != 0 {
		t.Fatalf("status = %d, want granted", resp.Status.Status)
	}
	sd, err := cms.ParseSignedData(resp.Token.FullBytes)
	if err != nil {
		t.Fatal(err)
	}
	signers, err := sd.Verify(cms.VerifyOptions{})
	if err != nil {
		t.Fatalf("the token does not verify: %v", err)
	}
	return signers[0]
}

func TestTSAServiceIsOffWithoutTheBlock(t *testing.T) {
	f := newTSAFixture(t)
	if svc := newTSAService(f.ctx, &config.Config{}, f.deps); svc != nil {
		t.Fatal("a TSA was built with pki.tsa off")
	}
}

func TestTSAServiceSignsWithACertificateFromTheCA(t *testing.T) {
	f := newTSAFixture(t)
	svc := newTSAService(f.ctx, tsaBootConfig(), f.deps)
	if svc == nil {
		t.Fatal("no TSA built from a valid block")
	}
	if svc.addr != ":318" {
		t.Errorf("default listener = %q, want :318", svc.addr)
	}
	if f.ca.closed == 0 {
		t.Error("the CA key was not released after signing the TSA certificate")
	}
	rec := tsaQuery(t, svc.handler, "192.0.2.5:4000")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	signer := tokenSigner(t, rec.Body.Bytes())
	if err := signer.CheckSignatureFrom(f.ca.cert); err != nil {
		t.Fatalf("the TSA certificate does not chain to the CA: %v", err)
	}
	if signer.Equal(f.ca.cert) {
		t.Fatal("the token is signed by the CA certificate")
	}
	rec2, ok, err := f.revStore.GetIssued(f.ctx, signer.SerialNumber.Text(16))
	if err != nil || !ok || rec2.ProfileName != tsaIssuedProfile {
		t.Fatalf("the TSA certificate is not in the issued set: ok=%t err=%v rec=%+v", ok, err, rec2)
	}

	if rec := tsaQuery(t, svc.handler, "203.0.113.5:4000"); rec.Code != http.StatusForbidden {
		t.Errorf("a client outside allowed_networks got %d, want 403", rec.Code)
	}
}

func TestTSAServiceRefusesWhileTheClockIsUnsynced(t *testing.T) {
	f := newTSAFixture(t)
	f.synced = false
	svc := newTSAService(f.ctx, tsaBootConfig(), f.deps)
	rec := tsaQuery(t, svc.handler, "192.0.2.5:4000")
	var resp struct {
		Status struct {
			Status       int
			StatusString []string       `asn1:"optional,utf8"`
			FailInfo     asn1.BitString `asn1:"optional"`
		}
	}
	if _, err := asn1.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Status.Status != 2 || resp.Status.FailInfo.At(int(tsa.FailTimeNotAvailable)) != 1 {
		t.Fatalf("status %d failInfo %v, want rejection with timeNotAvailable", resp.Status.Status, resp.Status.FailInfo)
	}
}

func TestTSACatalogListsCertificatesAndMarksTheCurrentOne(t *testing.T) {
	f := newTSAFixture(t)
	svc := newTSAService(f.ctx, tsaBootConfig(), f.deps)
	running := true
	cat := tsaCatalog{store: tsa.NewStore(f.deps.cli), current: func() (*x509.Certificate, bool) {
		if !running {
			return nil, false
		}
		return svc.certs.Current()
	}}
	got, err := cat.ListTsaCertificates(f.ctx)
	if err != nil || len(got) != 1 {
		t.Fatalf("ListTsaCertificates = %d entries, %v", len(got), err)
	}
	cur, _ := svc.certs.Current()
	e := got[0]
	block, _ := pem.Decode([]byte(e.GetCertPem()))
	sum := sha256.Sum256(cur.Raw)
	if block == nil || !bytes.Equal(block.Bytes, cur.Raw) || e.GetSerialHex() != cur.SerialNumber.Text(16) ||
		e.GetSha256Hex() != hex.EncodeToString(sum[:]) || !e.GetCurrent() ||
		!e.GetNotBefore().AsTime().Equal(cur.NotBefore) || !e.GetNotAfter().AsTime().Equal(cur.NotAfter) {
		t.Fatalf("entry = %+v", e)
	}

	running = false
	got, err = cat.ListTsaCertificates(f.ctx)
	if err != nil || len(got) != 1 || got[0].GetCurrent() {
		t.Fatalf("with the TSA not running: %d entries, current=%t, err=%v; want the certificate listed, not current", len(got), len(got) == 1 && got[0].GetCurrent(), err)
	}
}
