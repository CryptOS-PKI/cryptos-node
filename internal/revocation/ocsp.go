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
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"time"

	"golang.org/x/crypto/ocsp"
)

// ocspNextUpdate is how far ahead an OCSP response advertises its validity. It
// mirrors the CRL refresh cadence closely enough that clients re-query within a
// day of a revocation taking effect.
const ocspNextUpdate = 24 * time.Hour

// OCSPResponder answers RFC 6960 OCSP requests from the revocation Store. Like
// the CRL builder it holds no key material: the issuer certificate, the
// delegated responder certificate, and the responder signing key are supplied
// per Respond call, the same loader pattern the node uses for issuance.
type OCSPResponder struct {
	store *Store
}

// NewOCSPResponder returns an OCSPResponder backed by store.
func NewOCSPResponder(store *Store) *OCSPResponder {
	return &OCSPResponder{store: store}
}

// Respond parses the DER-encoded OCSP request in reqDER, looks the requested
// serial up in the store, and returns a signed DER OCSP response. The status is
// Revoked when the serial has a revoked record, Good when it is issued but not
// revoked, and Unknown when the store has no issued record for it. The response
// is signed by the delegated responder key and embeds responderCert (a
// CA-minted cert carrying id-kp-OCSPSigning that chains to issuer), so a
// relying party validates the signer without loading the CA key per request. A
// malformed request returns an error so the HTTP layer can emit the RFC 6960
// malformedRequest bytes.
func (r *OCSPResponder) Respond(ctx context.Context, reqDER []byte, issuer, responderCert *x509.Certificate, responderKey crypto.Signer, now time.Time) ([]byte, error) {
	req, err := ocsp.ParseRequest(reqDER)
	if err != nil {
		return nil, fmt.Errorf("revocation: Respond: parse request: %w", err)
	}

	serialHex := req.SerialNumber.Text(16)

	tmpl := ocsp.Response{
		SerialNumber: req.SerialNumber,
		// RFC 6960 section 4.2.1: the response names the requested CertID, so it
		// is hashed with the algorithm the client chose.
		IssuerHash: req.HashAlgorithm,
		ThisUpdate: now,
		NextUpdate: now.Add(ocspNextUpdate),
		// Embed the delegated responder certificate so a relying party can
		// validate that the response signer (responderKey) chains to issuer via
		// a cert carrying id-kp-OCSPSigning, rather than expecting the CA key to
		// have signed the response directly.
		Certificate: responderCert,
	}

	if revoked, ok, err := r.store.GetRevoked(ctx, serialHex); err != nil {
		return nil, fmt.Errorf("revocation: Respond: get revoked %q: %w", serialHex, err)
	} else if ok {
		tmpl.Status = ocsp.Revoked
		tmpl.RevokedAt = revoked.RevokedAt
		tmpl.RevocationReason = revoked.ReasonCode
	} else if _, issued, err := r.store.GetIssued(ctx, serialHex); err != nil {
		return nil, fmt.Errorf("revocation: Respond: get issued %q: %w", serialHex, err)
	} else if issued {
		tmpl.Status = ocsp.Good
	} else {
		tmpl.Status = ocsp.Unknown
	}

	respDER, err := ocsp.CreateResponse(issuer, responderCert, tmpl, responderKey)
	if err != nil {
		return nil, fmt.Errorf("revocation: Respond: create response: %w", err)
	}
	return respDER, nil
}

// RequestNamesIssuer reports whether the CertID in reqDER names issuer, which
// RFC 6960 section 4.1.1 defines as both the hash of the issuer's DN and the
// hash of its public key (the BIT STRING value, without tag and length). It
// fails on a malformed request.
func RequestNamesIssuer(reqDER []byte, issuer *x509.Certificate) (bool, error) {
	req, err := ocsp.ParseRequest(reqDER)
	if err != nil {
		return false, fmt.Errorf("revocation: RequestNamesIssuer: parse request: %w", err)
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &spki); err != nil {
		return false, fmt.Errorf("revocation: RequestNamesIssuer: parse issuer public key: %w", err)
	}
	nameHash := req.HashAlgorithm.New()
	nameHash.Write(issuer.RawSubject)
	keyHash := req.HashAlgorithm.New()
	keyHash.Write(spki.PublicKey.RightAlign())
	return bytes.Equal(nameHash.Sum(nil), req.IssuerNameHash) &&
		bytes.Equal(keyHash.Sum(nil), req.IssuerKeyHash), nil
}
