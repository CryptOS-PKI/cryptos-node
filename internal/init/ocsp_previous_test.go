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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/CryptOS-PKI/cryptos-node/internal/bootstrap"
	"github.com/CryptOS-PKI/cryptos-node/internal/config"
	"github.com/CryptOS-PKI/cryptos-node/internal/node"
	"github.com/CryptOS-PKI/cryptos-node/internal/revocation"
	"github.com/CryptOS-PKI/cryptos-node/internal/storage/etcd"
)

// rotationRig wires an established Intermediate the way run.go does, with a
// real rekeyer and enroller, so a test can issue leaves, re-key and query /ocsp.
type rotationRig struct {
	store     *node.Store
	revStore  *revocation.Store
	parent    *rekeyParent
	rekeyer   *nodeRekeyer
	signer    *node.CASigner
	responder *ocspResponder
	ocspFn    func(context.Context, []byte) ([]byte, error)
}

func newRotationRig(t *testing.T) (*rotationRig, context.Context) {
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
	store, err := node.New(cli)
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	revStore := revocation.NewStore(cli)
	parent := newRekeyParent(t)

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	blob, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "Child Issuing CA"}}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	if err := store.StageSubordinate(ctx, csr, blob, pub); err != nil {
		t.Fatalf("StageSubordinate: %v", err)
	}
	if err := store.CommitSubordinateCert(ctx, [][]byte{parent.signIntermediate(t, &key.PublicKey, ""), parent.der}); err != nil {
		t.Fatalf("CommitSubordinateCert: %v", err)
	}

	backend := NewSoftRootBackend()
	load := func(ctx context.Context) (crypto.Signer, func(), error) {
		priv, pub, _, err := store.RootKeyBlobs(ctx)
		if err != nil {
			return nil, nil, err
		}
		s, err := backend.LoadKey(priv, pub)
		if err != nil {
			return nil, nil, err
		}
		return s, func() { _ = s.Close() }, nil
	}
	issuer := func(ctx context.Context) (*x509.Certificate, error) {
		id, err := store.Identity(ctx)
		if err != nil {
			return nil, err
		}
		return x509.ParseCertificate(id.ChainDer[0])
	}

	trust, err := bootstrap.LoadTrust(certPEM(parent.der), "")
	if err != nil {
		t.Fatalf("LoadTrust: %v", err)
	}
	enr, err := node.NewSubordinateEnroller(store, trust)
	if err != nil {
		t.Fatalf("NewSubordinateEnroller: %v", err)
	}
	rekeyer, err := newRekeyer(store, backend, rekeyConfig(), enr)
	if err != nil {
		t.Fatalf("newRekeyer: %v", err)
	}

	cfg := &config.Config{PKI: config.PKI{Profiles: []config.CertificateProfile{
		{Name: "leaf", ValidityDays: 30, KeyUsage: []string{"digital_signature"}, ExtKeyUsage: []string{"server_auth"}},
	}}}
	signer := node.NewCASigner(load, issuer, func(context.Context) (*config.Config, error) { return cfg, nil }).
		WithRecorder(IssuedRecorder(revStore))
	revoker := &nodeRevoker{store: revStore, crlBuilder: revocation.NewCRLBuilder(revStore, time.Hour), load: load, issuer: issuer}
	responder := newOCSPResponder(store, load, issuer, 0)
	return &rotationRig{
		store:     store,
		revStore:  revStore,
		parent:    parent,
		rekeyer:   rekeyer,
		signer:    signer,
		responder: responder,
		ocspFn:    revoker.ocspFn(revocation.NewOCSPResponder(revStore), responder),
	}, ctx
}

// issueLeaf returns a new leaf and the CA certificate that issued it.
func (r *rotationRig) issueLeaf(t *testing.T, ctx context.Context) (leaf, ca *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "svc.example"}}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	chain, _, err := r.signer.IssueLeafForNames(ctx, csr, "leaf", nil)
	if err != nil {
		t.Fatalf("IssueLeafForNames: %v", err)
	}
	if leaf, err = x509.ParseCertificate(chain[0]); err != nil {
		t.Fatalf("ParseCertificate leaf: %v", err)
	}
	if ca, err = x509.ParseCertificate(chain[1]); err != nil {
		t.Fatalf("ParseCertificate CA: %v", err)
	}
	return leaf, ca
}

func (r *rotationRig) ensureResponder(t *testing.T, ctx context.Context) *x509.Certificate {
	t.Helper()
	cert, _, err := r.responder.ensure(ctx)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	return cert
}

// reKey runs a full rotation: begin, parent signature, complete.
func (r *rotationRig) reKey(t *testing.T, ctx context.Context) {
	t.Helper()
	csr, err := r.rekeyer.BeginRotation(ctx)
	if err != nil {
		t.Fatalf("BeginRotation: %v", err)
	}
	der := r.parent.signCSR(t, csr, "Child Issuing CA")
	if _, err := r.rekeyer.CompleteRotation(ctx, [][]byte{der, r.parent.der}); err != nil {
		t.Fatalf("CompleteRotation: %v", err)
	}
}

// query asks /ocsp about leaf, naming issuer in the CertID, and validates the
// response against that same issuer, as a relying party does.
func (r *rotationRig) query(t *testing.T, ctx context.Context, leaf, issuer *x509.Certificate, opts *ocsp.RequestOptions) (*ocsp.Response, error) {
	t.Helper()
	reqDER, err := ocsp.CreateRequest(leaf, issuer, opts)
	if err != nil {
		t.Fatalf("ocsp.CreateRequest: %v", err)
	}
	body, err := r.ocspFn(ctx, reqDER)
	if err != nil {
		t.Fatalf("ocspFn: %v", err)
	}
	return ocsp.ParseResponseForCert(body, leaf, issuer)
}

func TestOCSPAnswersAnOldKeyLeafWithThePreviousResponder(t *testing.T) {
	r, ctx := newRotationRig(t)
	leaf, oldCA := r.issueLeaf(t, ctx)
	oldResponder := r.ensureResponder(t, ctx)

	r.reKey(t, ctx)

	got, err := r.query(t, ctx, leaf, oldCA, nil)
	if err != nil {
		t.Fatalf("response does not validate against the old Intermediate: %v", err)
	}
	if got.Status != ocsp.Good {
		t.Errorf("status = %d, want Good", got.Status)
	}
	if got.Certificate == nil || got.Certificate.SerialNumber.Cmp(oldResponder.SerialNumber) != 0 {
		t.Errorf("response embeds responder %v, want the retired responder %s", got.Certificate, oldResponder.SerialNumber.Text(16))
	}
}

func TestOCSPReportsARevokedOldKeyLeaf(t *testing.T) {
	r, ctx := newRotationRig(t)
	leaf, oldCA := r.issueLeaf(t, ctx)
	r.ensureResponder(t, ctx)
	r.reKey(t, ctx)

	if _, err := r.revStore.Revoke(ctx, leaf.SerialNumber.Text(16), ocsp.KeyCompromise, time.Now().UTC()); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	got, err := r.query(t, ctx, leaf, oldCA, nil)
	if err != nil {
		t.Fatalf("response does not validate against the old Intermediate: %v", err)
	}
	if got.Status != ocsp.Revoked || got.RevocationReason != ocsp.KeyCompromise {
		t.Errorf("status = %d reason = %d, want Revoked keyCompromise", got.Status, got.RevocationReason)
	}
}

func TestOCSPCurrentKeyRequestsKeepTheCurrentResponder(t *testing.T) {
	r, ctx := newRotationRig(t)
	r.issueLeaf(t, ctx)
	oldResponder := r.ensureResponder(t, ctx)
	r.reKey(t, ctx)

	leaf, newCA := r.issueLeaf(t, ctx)
	got, err := r.query(t, ctx, leaf, newCA, nil)
	if err != nil {
		t.Fatalf("response does not validate against the new Intermediate: %v", err)
	}
	if got.Certificate == nil || got.Certificate.SerialNumber.Cmp(oldResponder.SerialNumber) == 0 {
		t.Error("a request naming the current key was answered by the retired responder")
	}
}

// RFC 6960 section 4.2.1: the response names the same CertID as the request,
// including its hash algorithm.
func TestOCSPEchoesTheHashAlgorithmOfTheRequest(t *testing.T) {
	r, ctx := newRotationRig(t)
	oldLeaf, oldCA := r.issueLeaf(t, ctx)
	r.ensureResponder(t, ctx)
	r.reKey(t, ctx)
	newLeaf, newCA := r.issueLeaf(t, ctx)

	for _, tc := range []struct {
		name         string
		leaf, issuer *x509.Certificate
	}{
		{"previous key", oldLeaf, oldCA},
		{"current key", newLeaf, newCA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := r.query(t, ctx, tc.leaf, tc.issuer, &ocsp.RequestOptions{Hash: crypto.SHA256})
			if err != nil {
				t.Fatalf("response does not validate: %v", err)
			}
			if got.IssuerHash != crypto.SHA256 {
				t.Errorf("response CertID hash = %v, want SHA-256", got.IssuerHash)
			}
		})
	}
}

func TestSecondReKeyReplacesThePreviousResponder(t *testing.T) {
	r, ctx := newRotationRig(t)
	r.ensureResponder(t, ctx)
	r.reKey(t, ctx)

	secondLeaf, secondCA := r.issueLeaf(t, ctx)
	secondResponder := r.ensureResponder(t, ctx)
	r.reKey(t, ctx)

	got, err := r.query(t, ctx, secondLeaf, secondCA, nil)
	if err != nil {
		t.Fatalf("response does not validate against the second key: %v", err)
	}
	if got.Certificate == nil || got.Certificate.SerialNumber.Cmp(secondResponder.SerialNumber) != 0 {
		t.Error("the slot does not hold the responder retired by the second re-key")
	}
}

// With no OCSP traffic or ticker between two re-keys, the stored responder is
// still the one under the first key. It must not be paired with the second CA
// certificate; the slot keeps the first key's pair, which still matches.
func TestReKeyKeepsTheSlotWhenTheStoredResponderIsStale(t *testing.T) {
	r, ctx := newRotationRig(t)
	firstLeaf, firstCA := r.issueLeaf(t, ctx)
	r.ensureResponder(t, ctx)
	r.reKey(t, ctx)
	r.reKey(t, ctx)

	got, err := r.query(t, ctx, firstLeaf, firstCA, nil)
	if err != nil {
		t.Fatalf("response does not validate against the first key: %v", err)
	}
	if got.Status != ocsp.Good {
		t.Errorf("status = %d, want Good", got.Status)
	}
}

func TestExpiredPreviousResponderIsDropped(t *testing.T) {
	r, ctx := newRotationRig(t)
	retired := r.ensureResponder(t, ctx)
	r.reKey(t, ctx)

	if err := r.responder.dropExpiredPrevious(ctx, retired.NotAfter.Add(-time.Minute)); err != nil {
		t.Fatalf("dropExpiredPrevious before expiry: %v", err)
	}
	if _, _, _, ok, err := r.store.PreviousOCSPResponder(ctx); err != nil || !ok {
		t.Fatalf("slot before expiry ok=%v err=%v, want it kept", ok, err)
	}

	if err := r.responder.dropExpiredPrevious(ctx, retired.NotAfter.Add(time.Minute)); err != nil {
		t.Fatalf("dropExpiredPrevious after expiry: %v", err)
	}
	if _, _, _, ok, err := r.store.PreviousOCSPResponder(ctx); err != nil || ok {
		t.Fatalf("slot after expiry ok=%v err=%v, want it empty", ok, err)
	}
}

// An expired slot must not answer even if the ticker has not dropped it yet.
func TestExpiredPreviousResponderDoesNotAnswer(t *testing.T) {
	r, ctx := newRotationRig(t)
	leaf, oldCA := r.issueLeaf(t, ctx)
	retired := r.ensureResponder(t, ctx)
	r.reKey(t, ctx)

	reqDER, err := ocsp.CreateRequest(leaf, oldCA, nil)
	if err != nil {
		t.Fatalf("ocsp.CreateRequest: %v", err)
	}
	if _, ok := r.responder.previousFor(ctx, reqDER, retired.NotAfter.Add(time.Minute)); ok {
		t.Error("an expired previous responder was selected")
	}
}
