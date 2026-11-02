package revocation

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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/CryptOS-PKI/cryptos-node/internal/ca"
)

// issueLeaf mints a leaf certificate signed by issuer and returns its serial in
// the base-16 form the store keys on (big.Int.Text(16)) alongside the parsed
// certificate.
func issueLeaf(t *testing.T, issuer *x509.Certificate, issuerKey crypto.Signer) (string, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	p := ca.Profile{
		Subject:     pkix.Name{CommonName: "leaf.acme.example"},
		NotBefore:   time.Unix(0, 0).UTC(),
		NotAfter:    time.Unix(1<<31, 0).UTC(),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, _, err := ca.Sign(p, key.Public(), issuer, issuerKey)
	if err != nil {
		t.Fatalf("ca.Sign: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert.SerialNumber.Text(16), cert
}

// oidOCSPNoCheck is id-pkix-ocsp-nocheck (RFC 6960), stamped on a delegated
// responder certificate.
var oidOCSPNoCheck = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}

// delegatedResponder mints an OCSP responder certificate signed by issuer and
// returns the parsed cert and its key. The cert carries the OCSPSigning EKU and
// id-pkix-ocsp-nocheck so ocsp.ParseResponse accepts it as a delegated signer
// that chains to the issuer.
func delegatedResponder(t *testing.T, issuer *x509.Certificate, issuerKey crypto.Signer) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	p := ca.Profile{
		Subject:     pkix.Name{CommonName: issuer.Subject.CommonName + " OCSP Responder"},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(7 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		ExtraExtensions: []pkix.Extension{{
			Id:       oidOCSPNoCheck,
			Critical: false,
			Value:    []byte{0x05, 0x00},
		}},
	}
	der, _, err := ca.Sign(p, key.Public(), issuer, issuerKey)
	if err != nil {
		t.Fatalf("ca.Sign responder: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate responder: %v", err)
	}
	return cert, key
}

func TestOCSPGoodRevokedUnknown(t *testing.T) {
	s, ctx := newRevStore(t)
	issuer, key := selfSignedCA(t)
	responderCert, responderKey := delegatedResponder(t, issuer, key)
	goodSerial, goodCert := issueLeaf(t, issuer, key)
	revSerial, revCert := issueLeaf(t, issuer, key)
	_ = s.RecordIssued(ctx, IssuedRecord{SerialHex: goodSerial, NotAfter: goodCert.NotAfter})
	_ = s.RecordIssued(ctx, IssuedRecord{SerialHex: revSerial, NotAfter: revCert.NotAfter})
	_, _ = s.Revoke(ctx, revSerial, ocsp.KeyCompromise, time.Now())

	resp := NewOCSPResponder(s)
	for _, tc := range []struct {
		cert *x509.Certificate
		want int
	}{
		{goodCert, ocsp.Good}, {revCert, ocsp.Revoked},
	} {
		reqDER, _ := ocsp.CreateRequest(tc.cert, issuer, nil)
		respDER, err := resp.Respond(ctx, reqDER, issuer, responderCert, responderKey, time.Now())
		if err != nil {
			t.Fatalf("Respond: %v", err)
		}
		parsed, err := ocsp.ParseResponse(respDER, issuer)
		if err != nil {
			t.Fatalf("ParseResponse: %v", err)
		}
		if parsed.Status != tc.want {
			t.Fatalf("status=%d want %d", parsed.Status, tc.want)
		}
	}
	// unknown serial: a leaf not recorded in the store
	_, unknownCert := issueLeaf(t, issuer, key)
	reqDER, _ := ocsp.CreateRequest(unknownCert, issuer, nil)
	respDER, err := resp.Respond(ctx, reqDER, issuer, responderCert, responderKey, time.Now())
	if err != nil {
		t.Fatalf("Respond unknown: %v", err)
	}
	parsed, err := ocsp.ParseResponse(respDER, issuer)
	if err != nil {
		t.Fatalf("ParseResponse unknown: %v", err)
	}
	if parsed.Status != ocsp.Unknown {
		t.Fatalf("unknown serial status=%d want %d", parsed.Status, ocsp.Unknown)
	}
}

func TestRequestNamesIssuer(t *testing.T) {
	newCA := func(cn string, key crypto.Signer) *x509.Certificate {
		t.Helper()
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: cn},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
		if err != nil {
			t.Fatalf("CreateCertificate: %v", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("ParseCertificate: %v", err)
		}
		return cert
	}
	newKey := func() crypto.Signer {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		return key
	}
	key := newKey()
	named := newCA("Issuing CA", key)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(7)}

	for _, hash := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		reqDER, err := ocsp.CreateRequest(leaf, named, &ocsp.RequestOptions{Hash: hash})
		if err != nil {
			t.Fatalf("ocsp.CreateRequest %v: %v", hash, err)
		}
		for _, tc := range []struct {
			name   string
			issuer *x509.Certificate
			want   bool
		}{
			{"same name and key", named, true},
			{"same name, other key", newCA("Issuing CA", newKey()), false},
			{"other name, same key", newCA("Other CA", key), false},
		} {
			got, err := RequestNamesIssuer(reqDER, tc.issuer)
			if err != nil {
				t.Fatalf("%v %s: %v", hash, tc.name, err)
			}
			if got != tc.want {
				t.Errorf("%v %s = %v, want %v", hash, tc.name, got, tc.want)
			}
		}
	}

	if _, err := RequestNamesIssuer([]byte("not a request"), named); err == nil {
		t.Error("a malformed request did not fail")
	}
}
