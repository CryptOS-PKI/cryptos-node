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
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/CryptOS-PKI/cryptos-node/internal/ca"
	"github.com/CryptOS-PKI/cryptos-node/internal/node"
	"github.com/CryptOS-PKI/cryptos-node/internal/storage/etcd"
)

// ocspResponderFixture builds a soft self-signed CA (issuer + key) and a
// node.Store backed by an embedded etcd, then returns a responder manager wired
// to load that CA key per use, mirroring the CRL/OCSP loader pattern.
type ocspResponderFixture struct {
	store    *node.Store
	issuer   *x509.Certificate
	caKey    crypto.Signer
	validity time.Duration
}

func newOCSPResponderFixture(t *testing.T, validity time.Duration) (*ocspResponderFixture, *ocspResponder, context.Context) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return newOCSPResponderFixtureWithCAKey(t, validity, caKey)
}

// newOCSPResponderFixtureWithCAKey is newOCSPResponderFixture over a CA key the
// caller chooses, so the RSA-CA cases can drive the same wiring.
func newOCSPResponderFixtureWithCAKey(t *testing.T, validity time.Duration, caKey crypto.Signer) (*ocspResponderFixture, *ocspResponder, context.Context) {
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

	p := ca.Profile{
		Subject:   pkix.Name{CommonName: "CryptOS Test CA"},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:      true,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, _, err := ca.Sign(p, caKey.Public(), nil, caKey)
	if err != nil {
		t.Fatalf("ca.Sign issuer: %v", err)
	}
	issuer, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate issuer: %v", err)
	}

	f := &ocspResponderFixture{store: store, issuer: issuer, caKey: caKey, validity: validity}
	load := func(context.Context) (crypto.Signer, func(), error) { return f.caKey, func() {}, nil }
	issuerFn := func(context.Context) (*x509.Certificate, error) { return f.issuer, nil }
	mgr := newOCSPResponder(store, load, issuerFn, validity)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return f, mgr, ctx
}

func hasOCSPNoCheck(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidOCSPNoCheck) {
			return true
		}
	}
	return false
}

func TestOCSPResponderEnsureMints(t *testing.T) {
	f, mgr, ctx := newOCSPResponderFixture(t, 7*24*time.Hour)

	cert, key, err := mgr.ensure(ctx)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if key == nil {
		t.Fatal("ensure returned a nil key")
	}

	// OCSPSigning EKU present.
	foundEKU := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageOCSPSigning {
			foundEKU = true
		}
	}
	if !foundEKU {
		t.Error("responder cert missing ExtKeyUsageOCSPSigning")
	}
	// digitalSignature KU.
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("responder cert missing KeyUsageDigitalSignature")
	}
	// id-pkix-ocsp-nocheck present.
	if !hasOCSPNoCheck(cert) {
		t.Error("responder cert missing id-pkix-ocsp-nocheck extension")
	}
	// Not a CA.
	if cert.IsCA {
		t.Error("responder cert is a CA, want end-entity")
	}
	// Chains to the issuer.
	roots := x509.NewCertPool()
	roots.AddCert(f.issuer)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}}); err != nil {
		t.Errorf("responder cert does not chain to issuer: %v", err)
	}
	// Public key of the returned signer matches the cert.
	certPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("responder cert public key type %T, want *ecdsa.PublicKey", cert.PublicKey)
	}
	keyPub, ok := key.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("returned key public type %T, want *ecdsa.PublicKey", key.Public())
	}
	if !certPub.Equal(keyPub) {
		t.Error("returned key does not match responder cert public key")
	}
}

func TestOCSPResponderEnsureReusesFresh(t *testing.T) {
	_, mgr, ctx := newOCSPResponderFixture(t, 7*24*time.Hour)

	first, _, err := mgr.ensure(ctx)
	if err != nil {
		t.Fatalf("first ensure: %v", err)
	}
	second, _, err := mgr.ensure(ctx)
	if err != nil {
		t.Fatalf("second ensure: %v", err)
	}
	if first.SerialNumber.Cmp(second.SerialNumber) != 0 {
		t.Errorf("ensure re-minted a still-fresh responder: serials %s != %s", first.SerialNumber, second.SerialNumber)
	}
}

// After a CA re-key the stored responder is still fresh, but it was signed by
// the discarded key. Responses for the new key's leaves have to chain to the
// new CA certificate, so the responder must be re-minted under the new key
// (#383).
func TestOCSPResponderRemintsAfterCAReKey(t *testing.T) {
	f, mgr, ctx := newOCSPResponderFixture(t, 7*24*time.Hour)

	before, _, err := mgr.ensure(ctx)
	if err != nil {
		t.Fatalf("ensure before re-key: %v", err)
	}

	newKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey new CA key: %v", err)
	}
	p := ca.Profile{
		Subject:   f.issuer.Subject,
		NotBefore: time.Now().Add(-time.Minute),
		NotAfter:  time.Now().Add(5 * 365 * 24 * time.Hour),
		IsCA:      true,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, _, err := ca.Sign(p, newKey.Public(), nil, newKey)
	if err != nil {
		t.Fatalf("ca.Sign re-keyed issuer: %v", err)
	}
	newIssuer, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate re-keyed issuer: %v", err)
	}
	f.issuer, f.caKey = newIssuer, newKey

	after, afterKey, err := mgr.ensure(ctx)
	if err != nil {
		t.Fatalf("ensure after re-key: %v", err)
	}
	if after.SerialNumber.Cmp(before.SerialNumber) == 0 {
		t.Fatal("ensure kept the responder signed by the old CA key")
	}
	if err := after.CheckSignatureFrom(newIssuer); err != nil {
		t.Fatalf("responder does not chain to the re-keyed CA: %v", err)
	}

	respDER, err := ocsp.CreateResponse(newIssuer, after, ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: big.NewInt(42),
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().Add(time.Hour),
		Certificate:  after,
	}, afterKey)
	if err != nil {
		t.Fatalf("CreateResponse: %v", err)
	}
	if _, err := ocsp.ParseResponse(respDER, newIssuer); err != nil {
		t.Fatalf("a client checking against the re-keyed CA rejects the response: %v", err)
	}

	again, _, err := mgr.ensure(ctx)
	if err != nil {
		t.Fatalf("ensure after re-mint: %v", err)
	}
	if again.SerialNumber.Cmp(after.SerialNumber) != 0 {
		t.Error("ensure re-minted the responder again after it was renewed under the new key")
	}
}

func TestOCSPResponderEnsureRenewsWithinWindow(t *testing.T) {
	f, mgr, ctx := newOCSPResponderFixture(t, 7*24*time.Hour)

	first, _, err := mgr.ensure(ctx)
	if err != nil {
		t.Fatalf("first ensure: %v", err)
	}

	// Persist a stored responder whose remaining life is inside the renewal
	// window (less than half the validity), which forces a re-mint. Mint it
	// with a NotAfter close to now so remaining life < validity/2.
	staleKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey stale: %v", err)
	}
	now := time.Now()
	p := responderProfile(f.issuer, now, now.Add(time.Hour)) // ~1h left, well inside 3.5d window
	der, _, err := ca.Sign(p, staleKey.Public(), f.issuer, f.caKey)
	if err != nil {
		t.Fatalf("ca.Sign stale: %v", err)
	}
	blob, err := x509.MarshalECPrivateKey(staleKey)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	pub, err := x509.MarshalPKIXPublicKey(staleKey.Public())
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	if err := f.store.PutOCSPResponder(ctx, der, blob, pub); err != nil {
		t.Fatalf("PutOCSPResponder stale: %v", err)
	}

	renewed, _, err := mgr.ensure(ctx)
	if err != nil {
		t.Fatalf("renew ensure: %v", err)
	}
	staleCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate stale: %v", err)
	}
	if renewed.SerialNumber.Cmp(staleCert.SerialNumber) == 0 {
		t.Error("ensure returned the stale responder instead of re-minting")
	}
	if renewed.SerialNumber.Cmp(first.SerialNumber) == 0 {
		t.Error("ensure re-used the first responder instead of re-minting")
	}
}

// A responder capped to an issuer that expires inside the renewal window can
// never be minted any longer, so re-minting it would only reload the CA key on
// every call for the same notAfter. It is kept until a re-mint would gain time.
func TestOCSPResponderKeepsAResponderCappedAtItsIssuer(t *testing.T) {
	f, mgr, ctx := newOCSPResponderFixture(t, 7*24*time.Hour)
	now := time.Now()
	der, _, err := ca.Sign(ca.Profile{
		Subject:   pkix.Name{CommonName: "Example Issuing CA G1"},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(12 * time.Hour),
		IsCA:      true,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, f.caKey.Public(), nil, f.caKey)
	if err != nil {
		t.Fatalf("ca.Sign short-lived issuer: %v", err)
	}
	if f.issuer, err = x509.ParseCertificate(der); err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	first, _, err := mgr.ensure(ctx)
	if err != nil {
		t.Fatalf("first ensure: %v", err)
	}
	if !first.NotAfter.Equal(f.issuer.NotAfter) {
		t.Fatalf("responder NotAfter = %s, want capped to issuer %s", first.NotAfter, f.issuer.NotAfter)
	}
	second, _, err := mgr.ensure(ctx)
	if err != nil {
		t.Fatalf("second ensure: %v", err)
	}
	if first.SerialNumber.Cmp(second.SerialNumber) != 0 {
		t.Errorf("ensure re-minted a responder already capped at its issuer: serials %s != %s", first.SerialNumber, second.SerialNumber)
	}
}

// TestOCSPResponderMintsAnRSAKeyForAnRSACA is criterion one of #200: an RSA CA
// must not end up with an ECDSA responder key, because a client that rejects
// the ECDSA family would verify the chain and then fail on the OCSP response.
func TestOCSPResponderMintsAnRSAKeyForAnRSACA(t *testing.T) {
	f, mgr, ctx := newOCSPResponderFixtureWithCAKey(t, 7*24*time.Hour, testRSACAKey(t))

	cert, key, err := mgr.ensure(ctx)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}

	keyPub, ok := key.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatalf("responder key type = %T, want an RSA key", key.Public())
	}
	if bits := keyPub.N.BitLen(); bits != nodeKeyRSABits {
		t.Errorf("responder key size = %d bits, want %d", bits, nodeKeyRSABits)
	}
	if !rsaSHA2SigAlgsInit[cert.SignatureAlgorithm] {
		t.Errorf("responder cert SignatureAlgorithm = %v, want a SHA-2 RSA algorithm", cert.SignatureAlgorithm)
	}
	certPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("responder cert public key type = %T, want *rsa.PublicKey", cert.PublicKey)
	}
	if !certPub.Equal(keyPub) {
		t.Error("returned key does not match the responder cert public key")
	}
	roots := x509.NewCertPool()
	roots.AddCert(f.issuer)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}}); err != nil {
		t.Errorf("responder cert does not chain to the RSA issuer: %v", err)
	}
}

// TestOCSPResponderReloadsAnRSAKeyAcrossRestart is criterion two: the stored
// RSA key is PKCS#8, and a fresh manager over the same store has to load it
// rather than silently re-minting (or failing) on every boot.
func TestOCSPResponderReloadsAnRSAKeyAcrossRestart(t *testing.T) {
	validity := 7 * 24 * time.Hour
	f, mgr, ctx := newOCSPResponderFixtureWithCAKey(t, validity, testRSACAKey(t))

	first, _, err := mgr.ensure(ctx)
	if err != nil {
		t.Fatalf("first ensure: %v", err)
	}

	// A second manager over the same store stands in for a restart.
	restarted := newOCSPResponder(
		f.store,
		func(context.Context) (crypto.Signer, func(), error) { return f.caKey, func() {}, nil },
		func(context.Context) (*x509.Certificate, error) { return f.issuer, nil },
		validity,
	)
	second, key, err := restarted.ensure(ctx)
	if err != nil {
		t.Fatalf("ensure after restart: %v", err)
	}
	if first.SerialNumber.Cmp(second.SerialNumber) != 0 {
		t.Errorf("restart re-minted the responder: serials %s != %s", first.SerialNumber, second.SerialNumber)
	}
	if _, ok := key.Public().(*rsa.PublicKey); !ok {
		t.Fatalf("reloaded key type = %T, want an RSA key", key.Public())
	}
	if !second.PublicKey.(*rsa.PublicKey).Equal(key.Public()) {
		t.Error("reloaded key does not match the stored responder cert")
	}
}

// TestOCSPResponderKeepsECDSAForAnECDSACA pins the no-change half of #200.
func TestOCSPResponderKeepsECDSAForAnECDSACA(t *testing.T) {
	_, mgr, ctx := newOCSPResponderFixture(t, 7*24*time.Hour)

	cert, key, err := mgr.ensure(ctx)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	pub, ok := key.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("responder key type = %T, want an ECDSA key", key.Public())
	}
	if pub.Curve != elliptic.P384() {
		t.Errorf("responder key curve = %v, want P-384", pub.Curve.Params().Name)
	}
	if cert.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		t.Errorf("responder cert SignatureAlgorithm = %v, want ECDSAWithSHA384", cert.SignatureAlgorithm)
	}
}

// rsaSHA2SigAlgsInit is the set an RSA-only relying party will verify.
var rsaSHA2SigAlgsInit = map[x509.SignatureAlgorithm]bool{
	x509.SHA256WithRSA: true,
	x509.SHA384WithRSA: true,
	x509.SHA512WithRSA: true,
}

// testRSACAKeyOnce caches one RSA CA key for the whole package: an RSA keygen
// at this size costs a visible fraction of a second, and a throwaway CA key
// does not need to be distinct per test.
//
// The size is nodeKeyRSABits rather than ca.MinRSAIssuerKeyBits, because a CA
// certificate is also a subject: ca.Sign applies ca.MinRSASubjectKeyBits to the
// key being certified, so an RSA-2048 CA cannot even self-sign its own root.
var testRSACAKeyOnce = sync.OnceValues(func() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, nodeKeyRSABits)
})

func testRSACAKey(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := testRSACAKeyOnce()
	if err != nil {
		t.Fatalf("GenerateKey RSA CA: %v", err)
	}
	return key
}
