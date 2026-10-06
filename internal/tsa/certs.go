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
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/CryptOS-PKI/cryptos-node/internal/ca"
)

var (
	oidExtKeyUsage    = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidKPTimeStamping = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
)

// ErrNoCertificate means the TSA has no certificate to sign with.
var ErrNoCertificate = errors.New("tsa: no TSA certificate to sign with")

// KeyBlobs are a TSA key as the key backend persists it: TPM-wrapped blobs
// on a TPM node, the encoded software key otherwise.
type KeyBlobs struct {
	Private []byte
	Public  []byte
}

// MintFunc signs a TSA certificate over pub with the node's CA key, valid
// from notBefore to notAfter, and returns its DER. Production builds it from
// CertificateProfile and ca.Sign.
type MintFunc func(ctx context.Context, pub crypto.PublicKey, notBefore, notAfter time.Time) ([]byte, error)

// CertDeps are what a CertManager works with.
type CertDeps struct {
	Store *Store
	// CreateKey creates a new TSA key in the key backend.
	CreateKey func(ctx context.Context) (KeyBlobs, error)
	// LoadKey loads a TSA key for signing and returns a release func the
	// caller runs once the signature is made.
	LoadKey func(ctx context.Context, k KeyBlobs) (crypto.Signer, func(), error)
	Mint    MintFunc
	// Issuer returns the node's current CA certificate.
	Issuer func(ctx context.Context) (*x509.Certificate, error)
	// Revoked reports whether a certificate, by hex serial, is revoked.
	// Optional.
	Revoked func(ctx context.Context, serialHex string) (bool, error)
	// Record enters a newly issued TSA certificate in the node's issued
	// set, so it is listed and can be revoked. Optional. A certificate that
	// cannot be recorded is not used.
	Record func(ctx context.Context, der []byte) error
}

// CertOptions tunes a CertManager.
type CertOptions struct {
	Validity time.Duration
	Overlap  time.Duration
	// Now and Logf default to time.Now and discarding.
	Now  func() time.Time
	Logf func(string, ...any)
}

// CertificateProfile is the ca.Profile of a TSA certificate: an end-entity
// certificate with key usage digitalSignature and one extended key usage,
// id-kp-timeStamping, critical (RFC 3161 section 2.3). crypto/x509 always
// writes the extended key usage non-critical, so the extension is built here.
// With a revocation base URL the certificate carries the node's CRL, OCSP
// and caIssuers pointers, like every other certificate the node issues.
func CertificateProfile(issuer *x509.Certificate, notBefore, notAfter time.Time, revocationBaseURL string) ca.Profile {
	// Marshalling a fixed OID list cannot fail.
	eku, _ := asn1.Marshal([]asn1.ObjectIdentifier{oidKPTimeStamping})
	p := ca.Profile{
		Subject:   pkix.Name{CommonName: issuer.Subject.CommonName + " TSA"},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{
			Id:       oidExtKeyUsage,
			Critical: true,
			Value:    eku,
		}},
	}
	if base := strings.TrimRight(revocationBaseURL, "/"); base != "" {
		p.CRLDistributionPoints = []string{base + "/crl"}
		p.OCSPServer = []string{base + "/ocsp"}
		p.IssuingCertificateURL = []string{base + "/ca.cer"}
	}
	return p
}

// current is the certificate tokens are signed with and its key blobs.
type current struct {
	cert  *x509.Certificate
	blobs KeyBlobs
}

// CertManager keeps the node's TSA certificates (see the package doc).
type CertManager struct {
	deps     CertDeps
	validity time.Duration
	overlap  time.Duration
	now      func() time.Time
	logf     func(string, ...any)

	// ensure serialises Ensure passes; signMu serialises signatures, since
	// a loaded TPM key is not safe for concurrent use.
	ensure sync.Mutex
	signMu sync.Mutex

	mu  sync.RWMutex
	cur *current
}

// NewCertManager returns a CertManager. Call Ensure before signing.
func NewCertManager(deps CertDeps, opts CertOptions) (*CertManager, error) {
	if deps.Store == nil || deps.CreateKey == nil || deps.LoadKey == nil || deps.Mint == nil || deps.Issuer == nil {
		return nil, errors.New("tsa: NewCertManager: store, CreateKey, LoadKey, Mint and Issuer are required")
	}
	if opts.Validity <= 0 || opts.Overlap <= 0 || opts.Overlap >= opts.Validity {
		return nil, fmt.Errorf("tsa: NewCertManager: the overlap (%s) must be positive and shorter than the validity (%s)", opts.Overlap, opts.Validity)
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	return &CertManager{deps: deps, validity: opts.Validity, overlap: opts.Overlap, now: opts.Now, logf: opts.Logf}, nil
}

// Ensure loads the stored certificates, picks the one to sign with, issues a
// successor when there is none or the current one is inside its overlap,
// revoked, or no longer chains to the CA certificate, and deletes the keys of
// every certificate that no longer signs. It runs at boot and then
// periodically. It fails only when it leaves no certificate to sign with.
func (m *CertManager) Ensure(ctx context.Context) error {
	m.ensure.Lock()
	defer m.ensure.Unlock()

	now := m.now()
	recs, bad, err := m.deps.Store.list(ctx)
	if err != nil {
		return err
	}
	if bad > 0 {
		m.logf("tsa: %d stored TSA certificate record(s) do not load; ignoring them", bad)
	}
	issuer, err := m.deps.Issuer(ctx)
	if err != nil {
		return fmt.Errorf("tsa: load the CA certificate: %w", err)
	}
	if issuer == nil {
		return errors.New("tsa: this node has no CA certificate yet")
	}

	var cur *loadedCert
	reason := "no TSA certificate yet"
	for i := range recs {
		r := &recs[i]
		if !r.stored.hasKey() {
			continue
		}
		serial := r.cert.SerialNumber.Text(16)
		if !now.Before(r.cert.NotAfter) {
			reason = fmt.Sprintf("TSA certificate %s expired %s", serial, r.cert.NotAfter.UTC().Format(time.RFC3339))
			break
		}
		if err := r.cert.CheckSignatureFrom(issuer); err != nil {
			reason = fmt.Sprintf("TSA certificate %s does not chain to the current CA certificate", serial)
			break
		}
		if m.deps.Revoked != nil {
			revoked, rerr := m.deps.Revoked(ctx, serial)
			if rerr != nil {
				m.logf("tsa: could not check whether TSA certificate %s is revoked: %v (treating it as usable)", serial, rerr)
			} else if revoked {
				reason = fmt.Sprintf("TSA certificate %s is revoked", serial)
				break
			}
		}
		cur = r
		if left := r.cert.NotAfter.Sub(now); left <= m.overlap {
			reason = fmt.Sprintf("TSA certificate %s expires %s, inside the %s overlap", serial, r.cert.NotAfter.UTC().Format(time.RFC3339), m.overlap)
		} else {
			reason = ""
		}
		break
	}

	if reason != "" {
		m.logf("tsa: issuing a new TSA certificate (%s)", reason)
		next, merr := m.issue(ctx, now)
		switch {
		case merr != nil && cur == nil:
			m.set(nil)
			return merr
		case merr != nil:
			m.logf("tsa: issuing the successor failed, keeping TSA certificate %s: %v", cur.cert.SerialNumber.Text(16), merr)
		case cur != nil && !next.cert.NotAfter.After(cur.cert.NotAfter):
			// The CA certificate caps the TSA certificate's notAfter, so
			// near the CA's own expiry a successor cannot outlive the
			// current one; using it would only issue again on every pass.
			m.logf("tsa: the successor would not outlive TSA certificate %s (the CA expires %s); keeping the current one",
				cur.cert.SerialNumber.Text(16), issuer.NotAfter.UTC().Format(time.RFC3339))
		default:
			cur = next
		}
	}

	if cur == nil {
		m.set(nil)
		return ErrNoCertificate
	}
	for i := range recs {
		r := recs[i]
		if !r.stored.hasKey() || r.cert.Equal(cur.cert) {
			continue
		}
		serial := r.cert.SerialNumber.Text(16)
		if err := m.deps.Store.retireKey(ctx, serial, r.stored); err != nil {
			m.logf("tsa: could not delete the key of retired TSA certificate %s: %v", serial, err)
			continue
		}
		m.logf("tsa: TSA certificate %s retired; its key is deleted and the certificate stays published", serial)
	}
	m.set(&current{cert: cur.cert, blobs: cur.stored.blobs()})
	m.logf("tsa: signing with TSA certificate %s, valid until %s",
		cur.cert.SerialNumber.Text(16), cur.cert.NotAfter.UTC().Format(time.RFC3339))
	return nil
}

// issue creates a key, has the CA certify it, records and stores the
// certificate, and returns it.
func (m *CertManager) issue(ctx context.Context, now time.Time) (*loadedCert, error) {
	blobs, err := m.deps.CreateKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("tsa: create the TSA key: %w", err)
	}
	signer, release, err := m.deps.LoadKey(ctx, blobs)
	if err != nil {
		return nil, fmt.Errorf("tsa: load the new TSA key: %w", err)
	}
	pub := signer.Public()
	if release != nil {
		release()
	}
	der, err := m.deps.Mint(ctx, pub, now, now.Add(m.validity))
	if err != nil {
		return nil, fmt.Errorf("tsa: sign the TSA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("tsa: parse the TSA certificate: %w", err)
	}
	if eq, ok := cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool }); !ok || !eq.Equal(pub) {
		return nil, errors.New("tsa: the TSA certificate does not certify the new key")
	}
	if m.deps.Record != nil {
		if err := m.deps.Record(ctx, der); err != nil {
			return nil, fmt.Errorf("tsa: record the TSA certificate: %w", err)
		}
	}
	stored := storedCert{CertDER: der, KeyPrivate: blobs.Private, KeyPublic: blobs.Public}
	serial := cert.SerialNumber.Text(16)
	if err := m.deps.Store.put(ctx, serial, stored); err != nil {
		return nil, err
	}
	m.logf("tsa: TSA certificate %s issued, valid until %s", serial, cert.NotAfter.UTC().Format(time.RFC3339))
	return &loadedCert{cert: cert, stored: stored}, nil
}

func (m *CertManager) set(c *current) {
	m.mu.Lock()
	m.cur = c
	m.mu.Unlock()
}

// Current returns the certificate tokens are signed with.
func (m *CertManager) Current() (*x509.Certificate, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cur == nil {
		return nil, false
	}
	return m.cur.cert, true
}

// WithSigner loads the current TSA key, hands it to fn with its certificate,
// and releases it when fn returns. Signatures are serialised.
func (m *CertManager) WithSigner(ctx context.Context, fn func(cert *x509.Certificate, key crypto.Signer) error) error {
	m.mu.RLock()
	c := m.cur
	m.mu.RUnlock()
	if c == nil {
		return ErrNoCertificate
	}
	m.signMu.Lock()
	defer m.signMu.Unlock()
	key, release, err := m.deps.LoadKey(ctx, c.blobs)
	if err != nil {
		return fmt.Errorf("tsa: load the TSA key: %w", err)
	}
	if release != nil {
		defer release()
	}
	return fn(c.cert, key)
}
