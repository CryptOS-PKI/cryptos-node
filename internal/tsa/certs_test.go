package tsa

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
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	testValidity = 365 * 24 * time.Hour
	testOverlap  = 30 * 24 * time.Hour
)

func newCertFixture(t *testing.T) *certFixture {
	t.Helper()
	return newCertFixtureWith(t, "")
}

func TestEnsureMintsATimestampingCertificate(t *testing.T) {
	f := newCertFixture(t)
	f.ensure()

	cert, ok := f.mgr.Current()
	if !ok {
		t.Fatal("no current TSA certificate after Ensure")
	}
	if err := cert.CheckSignatureFrom(f.ca.cert); err != nil {
		t.Fatalf("the TSA certificate does not chain to the CA: %v", err)
	}
	if cert.IsCA {
		t.Error("the TSA certificate is a CA certificate")
	}
	if cert.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("key usage = %v, want digitalSignature only", cert.KeyUsage)
	}
	var eku []asn1.ObjectIdentifier
	found := false
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 37}) {
			continue
		}
		if found {
			t.Fatal("more than one extendedKeyUsage extension")
		}
		found = true
		if !ext.Critical {
			t.Error("extendedKeyUsage is not critical (RFC 3161 section 2.3)")
		}
		if rest, err := asn1.Unmarshal(ext.Value, &eku); err != nil || len(rest) != 0 {
			t.Fatalf("extendedKeyUsage does not parse: %v", err)
		}
	}
	if len(eku) != 1 || !eku[0].Equal(oidKPTimeStamping) {
		t.Errorf("extendedKeyUsage = %v, want exactly id-kp-timeStamping", eku)
	}
	if want := f.clock.now.Add(testValidity); cert.NotAfter.Sub(want).Abs() > time.Second {
		t.Errorf("notAfter = %s, want %s", cert.NotAfter, want)
	}
	if !strings.HasSuffix(cert.Subject.CommonName, " TSA") {
		t.Errorf("subject CN = %q", cert.Subject.CommonName)
	}
	if len(cert.CRLDistributionPoints) != 0 || len(cert.OCSPServer) != 0 {
		t.Error("revocation pointers stamped with no revocation base URL")
	}
	if f.recorded != 1 {
		t.Errorf("recorded %d certificates in the issued store, want 1", f.recorded)
	}
	pub := f.published()
	if len(pub) != 1 || !pub[0].Equal(cert) {
		t.Fatalf("published = %d certificates, want the current one", len(pub))
	}
	if !f.keyStored(cert) {
		t.Error("the current certificate has no stored key")
	}
}

func TestCertificateProfileStampsRevocationPointersWhenConfigured(t *testing.T) {
	f := newCertFixtureWith(t, "http://ca.example.org")
	f.ensure()
	cert, _ := f.mgr.Current()
	if len(cert.CRLDistributionPoints) != 1 || cert.CRLDistributionPoints[0] != "http://ca.example.org/crl" {
		t.Errorf("CDP = %v", cert.CRLDistributionPoints)
	}
	if len(cert.OCSPServer) != 1 || cert.OCSPServer[0] != "http://ca.example.org/ocsp" {
		t.Errorf("OCSP = %v", cert.OCSPServer)
	}
	if len(cert.IssuingCertificateURL) != 1 || cert.IssuingCertificateURL[0] != "http://ca.example.org/ca.cer" {
		t.Errorf("caIssuers = %v", cert.IssuingCertificateURL)
	}
}

func TestEnsureKeepsTheCurrentCertificateOutsideTheOverlap(t *testing.T) {
	f := newCertFixture(t)
	f.ensure()
	first, _ := f.mgr.Current()
	f.clock.advance(testValidity - testOverlap - time.Hour)
	f.ensure()
	cur, _ := f.mgr.Current()
	if !cur.Equal(first) {
		t.Fatal("Ensure replaced a certificate outside its overlap")
	}
	if n := len(f.published()); n != 1 {
		t.Fatalf("published %d certificates, want 1", n)
	}
	if f.creates != 1 {
		t.Errorf("created %d keys, want 1", f.creates)
	}
}

func TestEnsureRotatesInsideTheOverlapAndKeepsThePastCertificatePublished(t *testing.T) {
	f := newCertFixture(t)
	f.ensure()
	first, _ := f.mgr.Current()
	f.clock.advance(testValidity - testOverlap + time.Hour)
	f.ensure()

	cur, _ := f.mgr.Current()
	if cur.Equal(first) {
		t.Fatal("Ensure kept a certificate inside its overlap")
	}
	if cur.PublicKey.(*ecdsa.PublicKey).Equal(first.PublicKey) {
		t.Error("the successor reuses the old key")
	}
	pub := f.published()
	if len(pub) != 2 || !pub[0].Equal(cur) || !pub[1].Equal(first) {
		t.Fatalf("published = %d certificates, want the successor then the past one", len(pub))
	}
	if f.keyStored(first) {
		t.Error("the retired certificate's key is still stored")
	}
	if !f.keyStored(cur) {
		t.Error("the successor has no stored key")
	}
}

func TestEnsureKeepsExpiredCertificatesPublished(t *testing.T) {
	f := newCertFixture(t)
	f.ensure()
	first, _ := f.mgr.Current()
	f.clock.advance(2 * testValidity)
	f.ensure()
	pub := f.published()
	if len(pub) != 2 || !pub[1].Equal(first) {
		t.Fatalf("published = %d certificates, want the new one and the expired one", len(pub))
	}
	cur, _ := f.mgr.Current()
	if !f.clock.now.Before(cur.NotAfter) {
		t.Error("the current certificate has expired")
	}
}

func TestEnsureReplacesARevokedCertificate(t *testing.T) {
	f := newCertFixture(t)
	f.ensure()
	first, _ := f.mgr.Current()
	f.revoked[first.SerialNumber.Text(16)] = true
	f.ensure()
	cur, _ := f.mgr.Current()
	if cur.Equal(first) {
		t.Fatal("Ensure kept signing with a revoked certificate")
	}
	if f.keyStored(first) {
		t.Error("the revoked certificate's key is still stored")
	}
}

func TestEnsureReplacesACertificateThatNoLongerChains(t *testing.T) {
	f := newCertFixture(t)
	f.ensure()
	first, _ := f.mgr.Current()
	f.ca = newTestCA(t, "Example Issuing CA G2")
	f.ensure()
	cur, _ := f.mgr.Current()
	if cur.Equal(first) {
		t.Fatal("Ensure kept a certificate signed by the previous CA key")
	}
	if err := cur.CheckSignatureFrom(f.ca.cert); err != nil {
		t.Fatalf("the successor does not chain to the new CA certificate: %v", err)
	}
	if n := len(f.published()); n != 2 {
		t.Errorf("published %d certificates, want 2", n)
	}
}

func TestEnsureFailsWithoutACertificateWhenMintingFails(t *testing.T) {
	f := newCertFixture(t)
	f.mintErr = errors.New("CA key unavailable")
	if err := f.mgr.Ensure(f.ctx); err == nil {
		t.Fatal("Ensure succeeded with no certificate to sign with")
	}
	if _, ok := f.mgr.Current(); ok {
		t.Fatal("a current certificate exists after a failed mint")
	}
}

func TestEnsureKeepsTheCurrentCertificateWhenTheSuccessorFails(t *testing.T) {
	f := newCertFixture(t)
	f.ensure()
	first, _ := f.mgr.Current()
	f.clock.advance(testValidity - testOverlap + time.Hour)
	f.mintErr = errors.New("CA key unavailable")
	f.ensure()
	cur, ok := f.mgr.Current()
	if !ok || !cur.Equal(first) {
		t.Fatal("a failed successor dropped the current certificate")
	}
	if !f.keyStored(first) {
		t.Error("a failed successor deleted the current key")
	}
}

func TestEnsureSurvivesARestart(t *testing.T) {
	f := newCertFixture(t)
	f.ensure()
	first, _ := f.mgr.Current()
	again := f.newManager()
	if err := again.Ensure(f.ctx); err != nil {
		t.Fatalf("Ensure after restart: %v", err)
	}
	cur, _ := again.Current()
	if !cur.Equal(first) {
		t.Fatal("a restart replaced a valid certificate")
	}
}

func TestWithSignerSignsWithTheCurrentKeyAndReleasesIt(t *testing.T) {
	f := newCertFixture(t)
	f.ensure()
	digest := sha512.Sum384([]byte("tbs"))
	var sig []byte
	var signedBy *x509.Certificate
	err := f.mgr.WithSigner(f.ctx, func(cert *x509.Certificate, key crypto.Signer) error {
		signedBy = cert
		var err error
		sig, err = key.Sign(rand.Reader, digest[:], crypto.SHA384)
		return err
	})
	if err != nil {
		t.Fatalf("WithSigner: %v", err)
	}
	cur, _ := f.mgr.Current()
	if !signedBy.Equal(cur) {
		t.Fatal("WithSigner handed over a certificate other than the current one")
	}
	if !ecdsa.VerifyASN1(cur.PublicKey.(*ecdsa.PublicKey), digest[:], sig) {
		t.Fatal("the signature does not verify under the current certificate")
	}
	if f.loads == 0 || f.loads != f.closes {
		t.Errorf("loaded the key %d times and released it %d times", f.loads, f.closes)
	}
}

func TestWithSignerFailsWithoutACertificate(t *testing.T) {
	f := newCertFixture(t)
	err := f.mgr.WithSigner(f.ctx, func(*x509.Certificate, crypto.Signer) error { return nil })
	if !errors.Is(err, ErrNoCertificate) {
		t.Fatalf("WithSigner = %v, want ErrNoCertificate", err)
	}
}

func TestNewCertManagerRejectsAnOverlapNotShorterThanTheValidity(t *testing.T) {
	f := newCertFixture(t)
	deps := f.deps()
	if _, err := NewCertManager(deps, CertOptions{Validity: testOverlap, Overlap: testOverlap}); err == nil {
		t.Fatal("NewCertManager accepted an overlap equal to the validity")
	}
	if _, err := NewCertManager(deps, CertOptions{Validity: testValidity}); err == nil {
		t.Fatal("NewCertManager accepted a zero overlap")
	}
}
