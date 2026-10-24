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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"log"
	"time"

	"github.com/CryptOS-PKI/cryptos-node/internal/ca"
	"github.com/CryptOS-PKI/cryptos-node/internal/node"
)

// defaultOCSPResponderValidity is the lifetime of a minted delegated OCSP
// responder certificate (one week). The responder is re-minted at the halfway
// point (remaining life < validity/2), so a fresh responder is always at least
// half its life away from expiry.
const defaultOCSPResponderValidity = 168 * time.Hour

// oidOCSPNoCheck is id-pkix-ocsp-nocheck (RFC 6960 §4.2.2.2.1). A responder
// certificate carrying it tells relying parties not to check the responder's
// own revocation status, which is the standard treatment for a short-lived
// delegated responder cert.
var oidOCSPNoCheck = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}

// asn1NULL is the DER encoding of ASN.1 NULL, the value of the ocsp-nocheck
// extension.
var asn1NULL = []byte{0x05, 0x00}

// responderProfile builds the ca.Profile for a delegated OCSP responder
// certificate: an end-entity cert with digitalSignature key usage, the
// OCSPSigning extended key usage, a subject derived from the issuer CN, and the
// non-critical id-pkix-ocsp-nocheck extension.
func responderProfile(issuer *x509.Certificate, notBefore, notAfter time.Time) ca.Profile {
	return ca.Profile{
		Subject:     pkix.Name{CommonName: issuer.Subject.CommonName + " OCSP Responder"},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		IsCA:        false,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		ExtraExtensions: []pkix.Extension{{
			Id:       oidOCSPNoCheck,
			Critical: false,
			Value:    asn1NULL,
		}},
	}
}

// ocspResponder mints and renews this node's delegated OCSP responder
// certificate, backed by a dedicated software-backend key persisted in the
// node store. It holds the same CA key loader and issuer getter the CRL/OCSP
// closures use (reload-per-use, released via the loader's close fn), so the CA
// key is loaded only to mint/renew the responder cert, never per OCSP request.
type ocspResponder struct {
	store    *node.Store
	load     node.KeyLoader
	issuer   node.IssuerFunc
	validity time.Duration
}

// newOCSPResponder returns an ocspResponder using the given store, CA key
// loader, issuer getter, and responder-cert validity window. A zero validity
// falls back to defaultOCSPResponderValidity.
func newOCSPResponder(store *node.Store, load node.KeyLoader, issuer node.IssuerFunc, validity time.Duration) *ocspResponder {
	if validity <= 0 {
		validity = defaultOCSPResponderValidity
	}
	return &ocspResponder{store: store, load: load, issuer: issuer, validity: validity}
}

// ensure returns the current delegated OCSP responder certificate and its
// signing key, minting a fresh one when none is stored, the stored one fails to
// parse, or the stored one is inside the renewal window (remaining life less
// than half the validity). A freshly minted responder is persisted before it is
// returned, so a later ensure (or a restart) reuses it until renewal.
func (r *ocspResponder) ensure(ctx context.Context) (*x509.Certificate, crypto.Signer, error) {
	if cert, key, ok := r.loadStored(ctx); ok {
		return cert, key, nil
	}
	return r.mint(ctx)
}

// loadStored returns the persisted responder cert+key when one exists, parses,
// was signed by the current CA certificate, and is still outside the renewal
// window. Any failure (absent, unparsable, signed by another key, expiring)
// reports ok=false so the caller re-mints.
//
// The signature check is what renews the responder after a CA re-key: the
// rotation swaps the CA key and certificate but leaves the stored responder,
// still fresh, signed by the discarded key, and a client checking against the
// new CA certificate rejects responses it signs (#383).
//
// The window is half the lifetime a re-mint could actually get: ca.Sign caps
// the responder at the issuer's notAfter, so once the issuer has less than the
// full validity left, measuring against r.validity would re-mint on every call
// for the same capped notAfter.
func (r *ocspResponder) loadStored(ctx context.Context) (*x509.Certificate, crypto.Signer, bool) {
	certDER, keyBlob, _, ok, err := r.store.OCSPResponder(ctx)
	if err != nil || !ok {
		return nil, nil, false
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, false
	}
	achievable := r.validity
	if issuer, err := r.issuer(ctx); err == nil && issuer != nil {
		if err := cert.CheckSignatureFrom(issuer); err != nil {
			log.Printf("OCSP responder: stored certificate (serial %s) is not signed by the current CA certificate, re-minting: %v",
				cert.SerialNumber.Text(16), err)
			return nil, nil, false
		}
		achievable = min(achievable, time.Until(issuer.NotAfter))
	}
	remaining := time.Until(cert.NotAfter)
	if remaining < achievable/2 {
		return nil, nil, false
	}
	key, err := parseNodeKey(keyBlob)
	if err != nil {
		return nil, nil, false
	}
	return cert, key, true
}

// mint signs a responder certificate with the CA key + issuer (loaded per use
// and released immediately) over a fresh responder key of the CA key's own
// algorithm, persists both, and returns them.
//
// The CA key is loaded before the responder key is generated because it is
// what decides the responder key's algorithm: an ECDSA CA signs responses an
// RSA-only client rejects, so on an RSA CA the responder key must be RSA
// too (#200).
func (r *ocspResponder) mint(ctx context.Context) (*x509.Certificate, crypto.Signer, error) {
	signer, closeFn, err := r.load(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("init: load CA key for OCSP responder: %w", err)
	}
	if closeFn != nil {
		defer closeFn()
	}
	issuerCert, err := r.issuer(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("init: load issuer for OCSP responder: %w", err)
	}
	key, err := newNodeKey(signer.Public())
	if err != nil {
		return nil, nil, fmt.Errorf("init: generate OCSP responder key: %w", err)
	}

	now := time.Now().UTC()
	prof := responderProfile(issuerCert, now, now.Add(r.validity))
	der, _, err := ca.Sign(prof, key.Public(), issuerCert, signer)
	if err != nil {
		return nil, nil, fmt.Errorf("init: sign OCSP responder cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("init: parse OCSP responder cert: %w", err)
	}

	keyBlob, err := marshalNodeKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("init: marshal OCSP responder key: %w", err)
	}
	keyPublic, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, nil, fmt.Errorf("init: marshal OCSP responder public key: %w", err)
	}
	if err := r.store.PutOCSPResponder(ctx, der, keyBlob, keyPublic); err != nil {
		return nil, nil, fmt.Errorf("init: persist OCSP responder: %w", err)
	}
	return cert, key, nil
}
