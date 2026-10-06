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
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/CryptOS-PKI/cryptos-node/internal/ca"
	"github.com/CryptOS-PKI/cryptos-node/internal/cms"
)

// oidSigningCertificateV2 is id-aa-signingCertificateV2 (RFC 5035 section
// 3), the attribute RFC 5816 lets a token identify its signer with by a
// SHA-2 hash.
var oidSigningCertificateV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}

// PKIStatus values (RFC 3161 section 2.4.2).
const (
	statusGranted   = 0
	statusRejection = 2
)

// tokenParams are the per-token values the responder decides.
type tokenParams struct {
	policy   asn1.ObjectIdentifier
	accuracy time.Duration
	serial   *big.Int
	genTime  time.Time
}

// newSerial returns a token serial number: 159 random bits, positive and
// non-zero, within the 160 bits RFC 3161 section 2.4.2 says a requester must
// be able to handle. Two tokens sharing one is as likely as a collision of
// random 159-bit values.
func newSerial() (*big.Int, error) {
	b := make([]byte, 20)
	for {
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("tsa: generate a serial number: %w", err)
		}
		b[0] &= 0x7f
		if s := new(big.Int).SetBytes(b); s.Sign() > 0 {
			return s, nil
		}
	}
}

// tlv encodes one DER element with a short- or long-form length.
func tlv(tag byte, parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := []byte{tag}
	switch {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	case n < 0x10000:
		out = append(out, 0x82, byte(n>>8), byte(n))
	default:
		out = append(out, 0x83, byte(n>>16), byte(n>>8), byte(n))
	}
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// generalizedTime encodes t in UTC as a DER GeneralizedTime with the
// millisecond fraction RFC 3161 section 2.4.2 allows: trailing zeros
// dropped, and no decimal point for a whole second. encoding/asn1 writes
// whole seconds only.
func generalizedTime(t time.Time) []byte {
	t = t.UTC().Truncate(time.Millisecond)
	s := t.Format("20060102150405")
	if ms := t.Nanosecond() / int(time.Millisecond); ms != 0 {
		s += "." + strings.TrimRight(fmt.Sprintf("%03d", ms), "0")
	}
	return tlv(0x18, []byte(s+"Z"))
}

// accuracy encodes d as an Accuracy (RFC 3161 section 2.4.2): seconds, and
// millis in 1..999 when there is a remainder. A field that would be zero is
// left out.
func accuracy(d time.Duration) ([]byte, error) {
	ms := d.Milliseconds()
	if ms <= 0 {
		return nil, errors.New("tsa: the accuracy must be at least one millisecond")
	}
	var parts [][]byte
	if s := ms / 1000; s > 0 {
		enc, err := asn1.Marshal(s)
		if err != nil {
			return nil, err
		}
		parts = append(parts, enc)
	}
	if rem := ms % 1000; rem > 0 {
		enc, err := asn1.Marshal(rem)
		if err != nil {
			return nil, err
		}
		// millis [0] IMPLICIT INTEGER: the INTEGER's contents under tag
		// [0].
		enc[0] = 0x80
		parts = append(parts, enc)
	}
	return tlv(0x30, parts...), nil
}

// tstInfo encodes the TSTInfo (RFC 3161 section 2.4.2) for req. ordering is
// left at its default, FALSE: the TSA claims no ordering between tokens
// beyond what genTime and the accuracy say. The tsa name and extensions are
// left out.
func tstInfo(req *Request, p tokenParams) ([]byte, error) {
	version, err := asn1.Marshal(1)
	if err != nil {
		return nil, err
	}
	policy, err := asn1.Marshal(p.policy)
	if err != nil {
		return nil, fmt.Errorf("tsa: encode the policy: %w", err)
	}
	serial, err := asn1.Marshal(p.serial)
	if err != nil {
		return nil, err
	}
	acc, err := accuracy(p.accuracy)
	if err != nil {
		return nil, err
	}
	parts := [][]byte{version, policy, req.rawImprint, serial, generalizedTime(p.genTime), acc}
	if req.Nonce != nil {
		nonce, err := asn1.Marshal(req.Nonce)
		if err != nil {
			return nil, err
		}
		parts = append(parts, nonce)
	}
	return tlv(0x30, parts...), nil
}

// signingCertificateV2 is the signing-certificate-v2 attribute naming cert
// (RFC 5035 section 5.4.1.1, RFC 5816 section 2.2.1): one ESSCertIDv2 with
// the certificate's SHA-256 hash, the default algorithm and so left out, and
// its issuer and serial number.
func signingCertificateV2(cert *x509.Certificate) (cms.Attribute, error) {
	hash := sha256.Sum256(cert.Raw)
	certHash, err := asn1.Marshal(hash[:])
	if err != nil {
		return cms.Attribute{}, err
	}
	serial, err := asn1.Marshal(cert.SerialNumber)
	if err != nil {
		return cms.Attribute{}, err
	}
	// GeneralNames holding one directoryName [4]; Name is a CHOICE, so the
	// tag is explicit.
	issuerSerial := tlv(0x30, tlv(0x30, tlv(0xa4, cert.RawIssuer)), serial)
	essCertID := tlv(0x30, certHash, issuerSerial)
	value := tlv(0x30, tlv(0x30, essCertID))
	return cms.Attribute{Type: oidSigningCertificateV2, Values: []asn1.RawValue{{FullBytes: value}}}, nil
}

// signatureHash is the digest a TSA key signs with: the one the node pairs
// with that key when it signs certificates (SHA-384 for P-384 and RSA 3072 or
// larger).
func signatureHash(pub crypto.PublicKey) (crypto.Hash, error) {
	alg, err := ca.SignatureAlgorithmFor(pub)
	if err != nil {
		return 0, fmt.Errorf("tsa: TSA key: %w", err)
	}
	switch alg {
	case x509.ECDSAWithSHA384, x509.SHA384WithRSA:
		return crypto.SHA384, nil
	case x509.SHA256WithRSA:
		return crypto.SHA256, nil
	default:
		return 0, fmt.Errorf("tsa: TSA key: no digest for signature algorithm %s", alg)
	}
}

// signToken wraps an encoded TSTInfo in a SignedData signed by key under
// cert: the TimeStampToken (RFC 3161 section 2.4.2). The TSA certificate is
// carried when the requester asked for it.
func signToken(info []byte, cert *x509.Certificate, key crypto.Signer, includeCert bool) ([]byte, error) {
	h, err := signatureHash(key.Public())
	if err != nil {
		return nil, err
	}
	attr, err := signingCertificateV2(cert)
	if err != nil {
		return nil, err
	}
	var opts cms.SignOptions
	if includeCert {
		opts.Certificates = [][]byte{cert.Raw}
	}
	return cms.Sign(cms.OIDTSTInfo, info, []cms.Signer{{
		Certificate: cert,
		Key:         key,
		Hash:        h,
		Attributes:  []cms.Attribute{attr},
	}}, opts)
}

// statusInfo encodes a PKIStatusInfo. failInfo is ignored for granted.
func statusInfo(status int, fail FailureInfo, text string) ([]byte, error) {
	st, err := asn1.Marshal(status)
	if err != nil {
		return nil, err
	}
	parts := [][]byte{st}
	if text != "" {
		s, err := asn1.MarshalWithParams(text, "utf8")
		if err != nil {
			return nil, err
		}
		parts = append(parts, tlv(0x30, s))
	}
	if status != statusGranted {
		// A named BIT STRING in DER ends at its last set bit.
		bits := int(fail) + 1
		buf := make([]byte, (bits+7)/8)
		buf[int(fail)/8] = 0x80 >> (uint(fail) % 8)
		fi, err := asn1.Marshal(asn1.BitString{Bytes: buf, BitLength: bits})
		if err != nil {
			return nil, err
		}
		parts = append(parts, fi)
	}
	return tlv(0x30, parts...), nil
}

// grantedResponse is a TimeStampResp carrying token.
func grantedResponse(token []byte) ([]byte, error) {
	st, err := statusInfo(statusGranted, 0, "")
	if err != nil {
		return nil, err
	}
	return tlv(0x30, st, token), nil
}

// rejectionResponse is a TimeStampResp refusing the request with fail and
// text, and no token.
func rejectionResponse(fail FailureInfo, text string) ([]byte, error) {
	st, err := statusInfo(statusRejection, fail, text)
	if err != nil {
		return nil, err
	}
	return tlv(0x30, st), nil
}
