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
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"time"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"github.com/CryptOS-PKI/cryptos-node/internal/node"
	"github.com/CryptOS-PKI/cryptos-node/internal/revocation"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// defaultCRLNextUpdateHours is the CRL validity window used when the config
// leaves crl_next_update_hours at zero (one week).
const defaultCRLNextUpdateHours = 168

// defaultRevocationHTTPPort is the anonymous CRL/OCSP listener port used when
// the config leaves revocation_http_port at zero.
const defaultRevocationHTTPPort = 80

// nonzero returns v when it is non-zero, otherwise the fallback. It lets the
// wiring apply documented defaults for optional config fields.
func nonzero(v, fallback uint32) uint32 {
	if v == 0 {
		return fallback
	}
	return v
}

// IssuedRecorder returns a CASigner recorder that parses a freshly minted
// certificate and persists it into the revocation issued set. The recorder is
// called after a successful Sign but before the certificate is returned to the
// caller, so the issued set never drifts from what a caller received.
func IssuedRecorder(store *revocation.Store) func(ctx context.Context, der []byte, profileName string) error {
	return func(ctx context.Context, der []byte, profileName string) error {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("init: parse issued certificate: %w", err)
		}
		return store.RecordIssued(ctx, issuedRecordFromCert(cert, profileName))
	}
}

// issuedRecordFromCert maps a parsed certificate to a revocation.IssuedRecord.
// The serial hex is the single join key shared with the CRL and OCSP paths.
func issuedRecordFromCert(cert *x509.Certificate, profileName string) revocation.IssuedRecord {
	return revocation.IssuedRecord{
		SerialHex:   cert.SerialNumber.Text(16),
		SubjectDN:   cert.Subject.String(),
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		SKIHex:      hex.EncodeToString(cert.SubjectKeyId),
		ProfileName: profileName,
		IssuedAt:    time.Now().UTC(),
		DER:         cert.Raw,
	}
}

// nodeRevoker adapts a revocation.Store plus a CRL rebuild to the
// grpc.Revoker interface. Revoke records the revocation and then rebuilds the
// published CRL so the anonymous /crl endpoint reflects the new state on its
// next fetch. It is wired only on the management listeners.
type nodeRevoker struct {
	store      *revocation.Store
	crlBuilder *revocation.CRLBuilder
	load       node.KeyLoader
	issuer     node.IssuerFunc
	// chain returns this node's certificate chain, its own CA certificate
	// first and the root last: the chain of everything it issues.
	chain func(ctx context.Context) ([][]byte, error)
}

// Revoke marks serialHex revoked with the given reason, then rebuilds the CRL
// cache. The store reports revocation.ErrNotIssued for a serial this node never
// issued; the handler maps that to NotFound. A CRL rebuild failure is surfaced
// so the caller learns the published CRL did not refresh, even though the store
// write already committed.
func (r *nodeRevoker) Revoke(ctx context.Context, serialHex string, reason int) (*nodev1.Revocation, error) {
	rec, err := r.store.Revoke(ctx, serialHex, reason, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if _, err := r.buildCRL(ctx); err != nil {
		return nil, fmt.Errorf("init: rebuild CRL after revoke: %w", err)
	}
	return revocationToProto(rec), nil
}

// ListIssued returns this node's issued-certificate inventory.
func (r *nodeRevoker) ListIssued(ctx context.Context) ([]*nodev1.IssuedCert, error) {
	recs, err := r.store.ListIssued(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*nodev1.IssuedCert, 0, len(recs))
	for _, rec := range recs {
		out = append(out, issuedToProto(rec))
	}
	return out, nil
}

// Issued-certificate status values on the wire.
const (
	issuedStatusValid   = "valid"
	issuedStatusRevoked = "revoked"
	issuedStatusExpired = "expired"
)

// GetIssuedCertificate returns the certificate this node issued under
// serialHex (canonical lower-case hex), with the issuer-to-root chain and its
// status. Revocation takes precedence over expiry, so a revoked certificate
// reports when it was revoked even once it has also expired. It returns
// revocation.ErrNotIssued for a serial this node never issued and
// revocation.ErrCertificateNotStored for a record that predates keeping the
// DER.
func (r *nodeRevoker) GetIssuedCertificate(ctx context.Context, serialHex string) (*nodev1.GetIssuedCertificateResponse, error) {
	rec, ok, err := r.store.GetIssued(ctx, serialHex)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, revocation.ErrNotIssued
	}
	if len(rec.DER) == 0 {
		return nil, fmt.Errorf("init: serial %s: %w", serialHex, revocation.ErrCertificateNotStored)
	}
	chain, err := r.chain(ctx)
	if err != nil {
		return nil, fmt.Errorf("init: load the certificate chain: %w", err)
	}
	resp := &nodev1.GetIssuedCertificateResponse{CertificateDer: rec.DER, ChainDer: chain, Status: issuedStatusValid}
	rev, revoked, err := r.store.GetRevoked(ctx, serialHex)
	if err != nil {
		return nil, err
	}
	switch {
	case revoked:
		resp.Status = issuedStatusRevoked
		resp.RevokedAt = rev.RevokedAt.UTC().Format(time.RFC3339)
	case time.Now().After(rec.NotAfter):
		resp.Status = issuedStatusExpired
	}
	return resp, nil
}

// ListRevocations returns this node's revoked-certificate inventory.
func (r *nodeRevoker) ListRevocations(ctx context.Context) ([]*nodev1.Revocation, error) {
	recs, err := r.store.ListRevoked(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*nodev1.Revocation, 0, len(recs))
	for _, rec := range recs {
		out = append(out, revocationToProto(rec))
	}
	return out, nil
}

// buildCRL loads the CA key and issuer via the same loader/issuer used for
// signing (reload-per-use, released via the loader's close fn) and builds the
// signed DER CRL. It is used both by the anonymous /crl endpoint and to refresh
// the CRL after a revoke.
func (r *nodeRevoker) buildCRL(ctx context.Context) ([]byte, error) {
	signer, closeFn, err := r.load(ctx)
	if err != nil {
		return nil, fmt.Errorf("init: load CA key for CRL: %w", err)
	}
	if closeFn != nil {
		defer closeFn()
	}
	issuer, err := r.issuer(ctx)
	if err != nil {
		return nil, fmt.Errorf("init: load issuer for CRL: %w", err)
	}
	return r.crlBuilder.Build(ctx, issuer, signer, time.Now().UTC())
}

// crlFn returns the /crl provider closure for the anonymous HTTP listener: it
// loads the CA key + issuer per use and builds a fresh signed CRL.
func (r *nodeRevoker) crlFn() func(ctx context.Context) ([]byte, error) {
	return r.buildCRL
}

// caCertFn returns the caIssuers provider closure for the anonymous HTTP
// listener: this node's own CA certificate as DER. It needs no key, only the
// issuer certificate, and fails while the node has none (a subordinate still
// awaiting its chain), which the listener reports as 500.
func (r *nodeRevoker) caCertFn() func(ctx context.Context) ([]byte, error) {
	return func(ctx context.Context) ([]byte, error) {
		issuer, err := r.issuer(ctx)
		if err != nil {
			return nil, fmt.Errorf("init: load issuer for caIssuers: %w", err)
		}
		if issuer == nil {
			return nil, errors.New("init: no issuer certificate for caIssuers")
		}
		return issuer.Raw, nil
	}
}

// ocspFn returns the /ocsp responder closure for the anonymous HTTP listener.
// It ensures the delegated OCSP responder certificate + key exist (minting or
// renewing via the node's CA when needed, cheap when current), loads the issuer
// for the response, and answers a parsed OCSP request from the store via resp,
// signing with the delegated responder key rather than the CA key. If the
// responder cannot be ensured (CA key unavailable) the request fails; the HTTP
// layer maps that to internalError.
//
// A request naming the CA key a re-key retired is answered by the responder kept
// for that key, checked first because it needs neither the CA key nor a current
// responder. Its leaves chain only to the old CA certificate, so an answer from
// the current responder would not verify (#387).
func (r *nodeRevoker) ocspFn(resp *revocation.OCSPResponder, responder *ocspResponder) func(ctx context.Context, reqDER []byte) ([]byte, error) {
	return func(ctx context.Context, reqDER []byte) ([]byte, error) {
		now := time.Now().UTC()
		if prev, ok := responder.previousFor(ctx, reqDER, now); ok {
			log.Printf("OCSP: answering for the previous CA key with responder serial %s", prev.cert.SerialNumber.Text(16))
			return resp.Respond(ctx, reqDER, prev.issuer, prev.cert, prev.key, now)
		}
		responderCert, responderKey, err := responder.ensure(ctx)
		if err != nil {
			return nil, fmt.Errorf("init: ensure OCSP responder: %w", err)
		}
		issuer, err := r.issuer(ctx)
		if err != nil {
			return nil, fmt.Errorf("init: load issuer for OCSP: %w", err)
		}
		return resp.Respond(ctx, reqDER, issuer, responderCert, responderKey, now)
	}
}

// issuedToProto maps a stored IssuedRecord to its wire form.
func issuedToProto(r revocation.IssuedRecord) *nodev1.IssuedCert {
	return &nodev1.IssuedCert{
		SerialHex:   r.SerialHex,
		SubjectDn:   r.SubjectDN,
		NotBefore:   timestamppb.New(r.NotBefore),
		NotAfter:    timestamppb.New(r.NotAfter),
		SkiHex:      r.SKIHex,
		ProfileName: r.ProfileName,
		IssuedAt:    timestamppb.New(r.IssuedAt),
	}
}

// revocationToProto maps a stored RevokedRecord to its wire form.
func revocationToProto(r revocation.RevokedRecord) *nodev1.Revocation {
	return &nodev1.Revocation{
		SerialHex:  r.SerialHex,
		RevokedAt:  timestamppb.New(r.RevokedAt),
		ReasonCode: int32(r.ReasonCode),
	}
}
