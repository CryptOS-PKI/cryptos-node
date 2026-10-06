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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // only to build a SHA-1 imprint the TSA must refuse
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"regexp"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos-node/internal/ca"
	"github.com/CryptOS-PKI/cryptos-node/internal/cms"
)

var (
	testPolicy  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 32473, 1, 1}
	oidSHA1     = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidMD5      = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
	oidSHA224   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
	oidSHA256   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidSHA256NP = pkix.AlgorithmIdentifier{Algorithm: oidSHA256}
)

// staticSigner is a TokenSigner over one certificate and key.
type staticSigner struct {
	cert *x509.Certificate
	key  crypto.Signer
	err  error
}

func (s *staticSigner) WithSigner(_ context.Context, fn func(*x509.Certificate, crypto.Signer) error) error {
	if s.err != nil {
		return s.err
	}
	return fn(s.cert, s.key)
}

// newTSA issues a TSA certificate from a fresh CA with the real profile.
func newTSA(t *testing.T) (*testCA, *staticSigner) {
	t.Helper()
	authority := newTestCA(t, "Example Issuing CA G1")
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return authority, &staticSigner{cert: issueTSACert(t, authority, key), key: key}
}

func issueTSACert(t *testing.T, authority *testCA, key crypto.Signer) *x509.Certificate {
	t.Helper()
	now := time.Now().UTC()
	der, _, err := ca.Sign(CertificateProfile(authority.cert, now, now.Add(testValidity), ""), key.Public(), authority.cert, authority.key)
	if err != nil {
		t.Fatalf("issue the TSA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func newTestResponder(t *testing.T, s TokenSigner, now func() time.Time) *Responder {
	t.Helper()
	r, err := NewResponder(s, ResponderOptions{Policy: testPolicy, Accuracy: 1500 * time.Millisecond, Now: now})
	if err != nil {
		t.Fatalf("NewResponder: %v", err)
	}
	return r
}

// Wire shapes for reading responses, written from RFC 3161 independently of
// the encoder.
type (
	reqImprint struct {
		HashAlgorithm pkix.AlgorithmIdentifier
		HashedMessage []byte
	}
	reqForTest struct {
		Version        int
		MessageImprint reqImprint
		ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
		Nonce          *big.Int              `asn1:"optional"`
		CertReq        bool                  `asn1:"optional,default:false"`
	}
	respStatus struct {
		Status       int
		StatusString []string       `asn1:"optional,utf8"`
		FailInfo     asn1.BitString `asn1:"optional"`
	}
	respForTest struct {
		Status respStatus
		Token  asn1.RawValue `asn1:"optional"`
	}
	accuracyForTest struct {
		Seconds int `asn1:"optional"`
		Millis  int `asn1:"optional,tag:0"`
		Micros  int `asn1:"optional,tag:1"`
	}
	tstInfoForTest struct {
		Version        int
		Policy         asn1.ObjectIdentifier
		MessageImprint asn1.RawValue
		SerialNumber   *big.Int
		GenTime        asn1.RawValue
		Accuracy       accuracyForTest `asn1:"optional"`
		Ordering       bool            `asn1:"optional,default:false"`
		Nonce          *big.Int        `asn1:"optional"`
	}
	issuerSerialForTest struct {
		Issuer []asn1.RawValue
		Serial *big.Int
	}
	essCertIDv2ForTest struct {
		Raw          asn1.RawContent
		CertHash     []byte
		IssuerSerial issuerSerialForTest
	}
	signingCertV2ForTest struct {
		Certs []essCertIDv2ForTest
	}
)

func encodeRequest(t *testing.T, r reqForTest) []byte {
	t.Helper()
	der, err := asn1.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func sha256Request(nonce *big.Int, certReq bool) reqForTest {
	sum := sha256.Sum256([]byte("artifact"))
	return reqForTest{Version: 1, MessageImprint: reqImprint{oidSHA256NP, sum[:]}, Nonce: nonce, CertReq: certReq}
}

func parseResponse(t *testing.T, der []byte) respForTest {
	t.Helper()
	var r respForTest
	rest, err := asn1.Unmarshal(der, &r)
	if err != nil || len(rest) != 0 {
		t.Fatalf("the response is not a TimeStampResp: %v (%d trailing bytes)", err, len(rest))
	}
	return r
}

// verifiedToken checks a granted response end to end: the SignedData
// verifies under the TSA certificate, the content is a TSTInfo, and the
// signing-certificate-v2 attribute names the TSA certificate. It returns the
// parsed TSTInfo and SignedData.
func verifiedToken(t *testing.T, der []byte, tsaCert *x509.Certificate) (tstInfoForTest, *cms.SignedData) {
	t.Helper()
	r := parseResponse(t, der)
	if r.Status.Status != 0 {
		t.Fatalf("status = %d (%v), want granted", r.Status.Status, r.Status.StatusString)
	}
	if r.Status.FailInfo.BitLength != 0 {
		t.Fatal("a granted response carries failInfo")
	}
	sd, err := cms.ParseSignedData(r.Token.FullBytes)
	if err != nil {
		t.Fatalf("the token is not a SignedData: %v", err)
	}
	if !sd.ContentType.Equal(cms.OIDTSTInfo) {
		t.Fatalf("eContentType = %s, want id-ct-TSTInfo", sd.ContentType)
	}
	if sd.Version != 3 {
		t.Errorf("SignedData version = %d, want 3", sd.Version)
	}
	signers, err := sd.Verify(cms.VerifyOptions{Certificates: []*x509.Certificate{tsaCert}})
	if err != nil {
		t.Fatalf("the token does not verify: %v", err)
	}
	if len(signers) != 1 || !signers[0].Equal(tsaCert) {
		t.Fatal("the token is not signed by the TSA certificate")
	}
	si := sd.SignerInfos[0]
	if si.IssuerAndSerial == nil {
		t.Fatal("the signer is not identified by issuer and serial number")
	}

	var scv2 signingCertV2ForTest
	if err := si.SignedAttribute(oidSigningCertificateV2, &scv2); err != nil {
		t.Fatalf("signing-certificate-v2: %v", err)
	}
	if len(scv2.Certs) != 1 {
		t.Fatalf("signing-certificate-v2 names %d certificates, want 1", len(scv2.Certs))
	}
	id := scv2.Certs[0]
	want := sha256.Sum256(tsaCert.Raw)
	if !bytes.Equal(id.CertHash, want[:]) {
		t.Error("ESSCertIDv2 certHash is not the SHA-256 of the TSA certificate")
	}
	var first asn1.RawValue
	if _, err := asn1.Unmarshal(id.Raw, &first); err != nil {
		t.Fatal(err)
	}
	if inner, _ := splitForTest(first.Bytes); len(inner) == 0 || inner[0].Tag != asn1.TagOctetString {
		t.Error("ESSCertIDv2 spells out its hash algorithm; SHA-256 is the DEFAULT and DER leaves it out")
	}
	if id.IssuerSerial.Serial.Cmp(tsaCert.SerialNumber) != 0 {
		t.Error("ESSCertIDv2 issuerSerial has the wrong serial")
	}
	if len(id.IssuerSerial.Issuer) != 1 || id.IssuerSerial.Issuer[0].Tag != 4 || !bytes.Equal(id.IssuerSerial.Issuer[0].Bytes, tsaCert.RawIssuer) {
		t.Error("ESSCertIDv2 issuerSerial does not name the TSA certificate's issuer as a directoryName")
	}

	var info tstInfoForTest
	rest, err := asn1.Unmarshal(sd.Content, &info)
	if err != nil || len(rest) != 0 {
		t.Fatalf("the content is not a TSTInfo: %v", err)
	}
	return info, sd
}

func splitForTest(b []byte) ([]asn1.RawValue, error) {
	var out []asn1.RawValue
	for len(b) > 0 {
		var v asn1.RawValue
		rest, err := asn1.Unmarshal(b, &v)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		b = rest
	}
	return out, nil
}

func TestRespondGrantsAVerifiableToken(t *testing.T) {
	_, s := newTSA(t)
	gen := time.Date(2026, 10, 6, 20, 15, 30, 250_400_000, time.UTC)
	r := newTestResponder(t, s, func() time.Time { return gen })
	nonce, _ := new(big.Int).SetString("123456789abcdef0123456789abcdef", 16)
	reqDER := encodeRequest(t, sha256Request(nonce, false))

	resp, out, err := r.Respond(context.Background(), reqDER)
	if err != nil || !out.Granted {
		t.Fatalf("Respond: granted=%t err=%v reason=%s", out.Granted, err, out.Reason)
	}
	info, sd := verifiedToken(t, resp, s.cert)

	if info.Version != 1 {
		t.Errorf("TSTInfo version = %d", info.Version)
	}
	if !info.Policy.Equal(testPolicy) {
		t.Errorf("policy = %s, want %s", info.Policy, testPolicy)
	}
	var req reqForTest
	if _, err := asn1.Unmarshal(reqDER, &req); err != nil {
		t.Fatal(err)
	}
	wantImprint, _ := asn1.Marshal(req.MessageImprint)
	if !bytes.Equal(info.MessageImprint.FullBytes, wantImprint) {
		t.Error("the token does not echo the message imprint")
	}
	if info.Nonce == nil || info.Nonce.Cmp(nonce) != 0 {
		t.Errorf("nonce = %v, want %v", info.Nonce, nonce)
	}
	if info.SerialNumber.Cmp(out.Serial) != 0 || info.SerialNumber.Sign() <= 0 || info.SerialNumber.BitLen() > 160 {
		t.Errorf("serial = %v", info.SerialNumber)
	}
	if info.GenTime.Tag != asn1.TagGeneralizedTime || string(info.GenTime.Bytes) != "20261006201530.25Z" {
		t.Errorf("genTime = tag %d %q, want GeneralizedTime 20261006201530.25Z", info.GenTime.Tag, info.GenTime.Bytes)
	}
	if info.Accuracy.Seconds != 1 || info.Accuracy.Millis != 500 || info.Accuracy.Micros != 0 {
		t.Errorf("accuracy = %+v, want 1s 500ms", info.Accuracy)
	}
	if info.Ordering {
		t.Error("ordering is claimed")
	}
	if len(sd.Certificates) != 0 {
		t.Error("the token carries certificates though certReq was false")
	}
	if got := sd.SignerInfos[0].DigestAlgorithm.Algorithm; !got.Equal(oidSHA384) {
		t.Errorf("token digest = %s, want SHA-384 for a P-384 key", got)
	}
}

func TestRespondCarriesTheTSACertificateWhenAsked(t *testing.T) {
	_, s := newTSA(t)
	r := newTestResponder(t, s, nil)
	resp, out, _ := r.Respond(context.Background(), encodeRequest(t, sha256Request(nil, true)))
	if !out.Granted {
		t.Fatalf("rejected: %s", out.Reason)
	}
	info, sd := verifiedToken(t, resp, s.cert)
	if len(sd.Certificates) != 1 || !bytes.Equal(sd.Certificates[0], s.cert.Raw) {
		t.Fatalf("certificates = %d, want exactly the TSA certificate", len(sd.Certificates))
	}
	if info.Nonce != nil {
		t.Error("a nonce appears though the request sent none")
	}
}

func TestRespondAcceptsSHA384AndSHA512Imprints(t *testing.T) {
	_, s := newTSA(t)
	r := newTestResponder(t, s, nil)
	s384 := sha512.Sum384([]byte("x"))
	s512 := sha512.Sum512([]byte("x"))
	for name, mi := range map[string]reqImprint{
		"SHA-384":           {pkix.AlgorithmIdentifier{Algorithm: oidSHA384}, s384[:]},
		"SHA-512":           {pkix.AlgorithmIdentifier{Algorithm: oidSHA512}, s512[:]},
		"SHA-256 with NULL": {pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue}, s512[:32]},
	} {
		t.Run(name, func(t *testing.T) {
			resp, out, _ := r.Respond(context.Background(), encodeRequest(t, reqForTest{Version: 1, MessageImprint: mi}))
			if !out.Granted {
				t.Fatalf("rejected: %s", out.Reason)
			}
			verifiedToken(t, resp, s.cert)
		})
	}
}

func assertRejected(t *testing.T, resp []byte, out Outcome, want FailureInfo) {
	t.Helper()
	if out.Granted {
		t.Fatal("granted, want a rejection")
	}
	if out.Fail != want {
		t.Errorf("outcome failInfo = %s, want %s", out.Fail, want)
	}
	r := parseResponse(t, resp)
	if r.Status.Status != 2 {
		t.Errorf("status = %d, want rejection (2)", r.Status.Status)
	}
	if len(r.Token.FullBytes) != 0 {
		t.Error("a rejection carries a token")
	}
	fi := r.Status.FailInfo
	if fi.BitLength != int(want)+1 || fi.At(int(want)) != 1 {
		t.Errorf("failInfo = %d bits, want bit %d (%s) set and last", fi.BitLength, want, want)
	}
	for i := 0; i < fi.BitLength; i++ {
		if i != int(want) && fi.At(i) != 0 {
			t.Errorf("failInfo bit %d is set too", i)
		}
	}
	if len(r.Status.StatusString) != 1 || r.Status.StatusString[0] == "" {
		t.Error("a rejection has no statusString")
	}
}

func TestRespondRefusesWeakAndUnknownImprintAlgorithmsWithBadAlg(t *testing.T) {
	_, s := newTSA(t)
	r := newTestResponder(t, s, nil)
	s1 := sha1.Sum([]byte("x"))
	for name, mi := range map[string]reqImprint{
		"SHA-1":           {pkix.AlgorithmIdentifier{Algorithm: oidSHA1}, s1[:]},
		"MD5":             {pkix.AlgorithmIdentifier{Algorithm: oidMD5}, make([]byte, 16)},
		"SHA-224":         {pkix.AlgorithmIdentifier{Algorithm: oidSHA224}, make([]byte, 28)},
		"SHA-256 w/ args": {pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.RawValue{FullBytes: []byte{0x02, 0x01, 0x01}}}, make([]byte, 32)},
	} {
		t.Run(name, func(t *testing.T) {
			resp, out, err := r.Respond(context.Background(), encodeRequest(t, reqForTest{Version: 1, MessageImprint: mi}))
			if err != nil {
				t.Fatal(err)
			}
			assertRejected(t, resp, out, FailBadAlg)
		})
	}
}

func TestRespondRefusesMalformedRequestsWithBadDataFormat(t *testing.T) {
	_, s := newTSA(t)
	r := newTestResponder(t, s, nil)
	good := encodeRequest(t, sha256Request(nil, false))
	v2 := sha256Request(nil, false)
	v2.Version = 2
	short := sha256Request(nil, false)
	short.MessageImprint.HashedMessage = short.MessageImprint.HashedMessage[:31]
	for name, der := range map[string][]byte{
		"garbage":        []byte("not a request"),
		"empty":          nil,
		"trailing bytes": append(append([]byte{}, good...), 0x00),
		"version 2":      encodeRequest(t, v2),
		"short imprint":  encodeRequest(t, short),
	} {
		t.Run(name, func(t *testing.T) {
			resp, out, err := r.Respond(context.Background(), der)
			if err != nil {
				t.Fatal(err)
			}
			assertRejected(t, resp, out, FailBadDataFormat)
		})
	}
}

func TestRespondHonoursTheRequestedPolicy(t *testing.T) {
	_, s := newTSA(t)
	r := newTestResponder(t, s, nil)
	same := sha256Request(nil, false)
	same.ReqPolicy = testPolicy
	resp, out, _ := r.Respond(context.Background(), encodeRequest(t, same))
	if !out.Granted {
		t.Fatalf("a request for the served policy was rejected: %s", out.Reason)
	}
	if info, _ := verifiedToken(t, resp, s.cert); !info.Policy.Equal(testPolicy) {
		t.Error("wrong policy in the token")
	}

	other := sha256Request(nil, false)
	other.ReqPolicy = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 32473, 9}
	resp, out, _ = r.Respond(context.Background(), encodeRequest(t, other))
	assertRejected(t, resp, out, FailUnacceptedPolicy)
}

func TestRespondRefusesRequestExtensionsWithUnacceptedExtension(t *testing.T) {
	_, s := newTSA(t)
	r := newTestResponder(t, s, nil)
	base := encodeRequest(t, sha256Request(nil, false))
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(base, &outer); err != nil {
		t.Fatal(err)
	}
	ext, _ := asn1.Marshal(pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 32473, 2}, Value: []byte{0x05, 0x00}})
	exts := tlv(0xa0, ext)
	der := tlv(0x30, outer.Bytes, exts)
	resp, out, err := r.Respond(context.Background(), der)
	if err != nil {
		t.Fatal(err)
	}
	assertRejected(t, resp, out, FailUnacceptedExtension)
}

func TestRespondAnswersSystemFailureWhenSigningFails(t *testing.T) {
	_, s := newTSA(t)
	s.err = errors.New("TPM unavailable")
	r := newTestResponder(t, s, nil)
	resp, out, err := r.Respond(context.Background(), encodeRequest(t, sha256Request(nil, false)))
	if err != nil {
		t.Fatal(err)
	}
	assertRejected(t, resp, out, FailSystemFailure)
}

func TestRespondGivesEveryTokenItsOwnSerial(t *testing.T) {
	_, s := newTSA(t)
	r := newTestResponder(t, s, nil)
	seen := map[string]bool{}
	for range 64 {
		_, out, _ := r.Respond(context.Background(), encodeRequest(t, sha256Request(nil, false)))
		if !out.Granted {
			t.Fatalf("rejected: %s", out.Reason)
		}
		k := out.Serial.Text(16)
		if seen[k] {
			t.Fatalf("serial %s issued twice", k)
		}
		seen[k] = true
	}
}

func TestRespondSignsWithAnRSATSAKey(t *testing.T) {
	authority := newTestCA(t, "Example Issuing CA G1")
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	s := &staticSigner{cert: issueTSACert(t, authority, key), key: key}
	r := newTestResponder(t, s, nil)
	resp, out, _ := r.Respond(context.Background(), encodeRequest(t, sha256Request(big.NewInt(7), true)))
	if !out.Granted {
		t.Fatalf("rejected: %s", out.Reason)
	}
	_, sd := verifiedToken(t, resp, s.cert)
	if got := sd.SignerInfos[0].DigestAlgorithm.Algorithm; !got.Equal(oidSHA384) {
		t.Errorf("token digest = %s, want SHA-384 for RSA 3072", got)
	}
}

func TestGeneralizedTimeDropsTrailingZeros(t *testing.T) {
	re := regexp.MustCompile(`^\d{14}(\.\d*[1-9])?Z$`)
	for in, want := range map[time.Time]string{
		time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC):           "20260102030405Z",
		time.Date(2026, 1, 2, 3, 4, 5, 100_000_000, time.UTC): "20260102030405.1Z",
		time.Date(2026, 1, 2, 3, 4, 5, 123_999_999, time.UTC): "20260102030405.123Z",
		time.Date(2026, 1, 2, 3, 4, 5, 999_000, time.UTC):     "20260102030405Z",
	} {
		enc := generalizedTime(in)
		var v asn1.RawValue
		if _, err := asn1.Unmarshal(enc, &v); err != nil {
			t.Fatal(err)
		}
		if got := string(v.Bytes); got != want || !re.MatchString(got) {
			t.Errorf("generalizedTime(%s) = %q, want %q", in, got, want)
		}
	}
}

func TestNewResponderRequiresAPolicyAndAnAccuracy(t *testing.T) {
	_, s := newTSA(t)
	if _, err := NewResponder(s, ResponderOptions{Accuracy: time.Second}); err == nil {
		t.Error("NewResponder accepted no policy")
	}
	if _, err := NewResponder(s, ResponderOptions{Policy: testPolicy}); err == nil {
		t.Error("NewResponder accepted no accuracy")
	}
}
