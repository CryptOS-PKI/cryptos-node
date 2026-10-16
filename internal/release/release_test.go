package release

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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"
)

// selfSigned returns a base64 DER certificate for key, in the form the build
// stamps in, so the tests can exercise parse without a real release key.
func selfSigned(t *testing.T, key any, pub any) string {
	t.Helper()

	tmpl := &x509.Certificate{
		NotAfter:     time.Now().Add(time.Hour),
		NotBefore:    time.Now().Add(-time.Hour),
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "CryptOS Release Signing"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	return base64.StdEncoding.EncodeToString(der)
}

func rsaCert(t *testing.T) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	return selfSigned(t, key, &key.PublicKey)
}

// A build that was given a release certificate can name the key an image must
// be signed by.
func TestParse_ReturnsTheEmbeddedCertificate(t *testing.T) {
	cert, err := parse(rsaCert(t))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cert.Subject.CommonName != "CryptOS Release Signing" {
		t.Errorf("CommonName = %q", cert.Subject.CommonName)
	}
}

// A development build has no release certificate. That must be a distinct,
// recognisable condition rather than a parse error, because the node turns the
// upgrade RPCs off for it instead of failing every call with something
// alarming.
func TestParse_NoCertificateIsItsOwnCondition(t *testing.T) {
	for name, in := range map[string]string{
		"empty":      "",
		"whitespace": "  \n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parse(in); !errors.Is(err, ErrNoCertificate) {
				t.Errorf("err = %v, want ErrNoCertificate", err)
			}
		})
	}
}

// Detached release signatures are RSA PKCS#1 v1.5, which is what a UEFI
// Secure Boot key is. An ECDSA certificate here would be a build mistake that
// otherwise surfaces only at the first upgrade attempt, on the node.
func TestParse_RefusesANonRSACertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	_, err = parse(selfSigned(t, key, &key.PublicKey))
	if err == nil || errors.Is(err, ErrNoCertificate) {
		t.Fatalf("err = %v, want a non-RSA complaint", err)
	}
}

// Garbage must not read as "no certificate": one means upgrades are
// deliberately off, the other means the build is broken.
func TestParse_GarbageIsNotTheSameAsAbsent(t *testing.T) {
	_, err := parse("bm90IGEgY2VydA==")
	if err == nil || errors.Is(err, ErrNoCertificate) {
		t.Fatalf("err = %v, want a parse failure distinct from ErrNoCertificate", err)
	}
}

// Certificate reads whatever this image carries: the sign-time anchor from
// the environment when there is one, else the build stamp. A development
// build gets ErrNoCertificate; a signed one gets a certificate. Both are
// legitimate, so this asserts the accessor agrees with resolve rather than
// pinning one outcome.
func TestCertificate_MatchesTheResolvedAnchor(t *testing.T) {
	cert, err := Certificate()
	want, wantErr := resolve(os.Getenv(EnvAnchor), CertificateDER)

	switch {
	case wantErr != nil && (err == nil || err.Error() != wantErr.Error()):
		t.Fatalf("Certificate err = %v, want %v", err, wantErr)
	case wantErr == nil && err != nil:
		t.Fatalf("Certificate: %v", err)
	case wantErr == nil && !cert.Equal(want):
		t.Error("Certificate returned something other than the resolved anchor")
	}
}

// A sign-time anchor wins over the build stamp: the signing step is the last
// word on whose image this is.
func TestResolve_SignTimeAnchorWins(t *testing.T) {
	signTime, buildTime := rsaCert(t), rsaCert(t)

	got, err := resolve(signTime, buildTime)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	want, _ := parse(signTime)
	if !got.Equal(want) {
		t.Error("resolve returned the build-time anchor, want the sign-time one")
	}
}

// With no sign-time anchor the build stamp is used, as before.
func TestResolve_FallsBackToTheBuildStamp(t *testing.T) {
	buildTime := rsaCert(t)
	for name, signTime := range map[string]string{
		"unset":      "",
		"whitespace": " \n",
	} {
		t.Run(name, func(t *testing.T) {
			got, err := resolve(signTime, buildTime)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			want, _ := parse(buildTime)
			if !got.Equal(want) {
				t.Error("resolve did not return the build-time anchor")
			}
		})
	}
}

// An image with neither anchor keeps the distinct "no certificate" condition,
// so the node still turns the upgrade RPCs off cleanly.
func TestResolve_NeitherAnchorIsNoCertificate(t *testing.T) {
	if _, err := resolve("", ""); !errors.Is(err, ErrNoCertificate) {
		t.Errorf("err = %v, want ErrNoCertificate", err)
	}
}

// A sign-time anchor that does not parse must fail, not fall back to the build
// stamp: quietly trusting a different key would hide a broken signing step.
func TestResolve_BrokenSignTimeAnchorDoesNotFallBack(t *testing.T) {
	_, err := resolve("bm90IGEgY2VydA==", rsaCert(t))
	if err == nil || errors.Is(err, ErrNoCertificate) {
		t.Fatalf("err = %v, want a sign-time anchor failure", err)
	}
}

// The sign-time anchor gets the same RSA check as the build stamp, because the
// detached release signature it verifies is PKCS#1 v1.5.
func TestResolve_SignTimeAnchorMustBeRSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := resolve(selfSigned(t, key, &key.PublicKey), rsaCert(t)); err == nil {
		t.Fatal("resolve accepted an ECDSA sign-time anchor")
	}
}
