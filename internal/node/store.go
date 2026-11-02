package node

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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"strconv"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"github.com/CryptOS-PKI/cryptos-node/internal/bootstrap"
	"github.com/CryptOS-PKI/cryptos-node/internal/storage/etcd"
)

// Phase is the node lifecycle phase persisted at etcd KeyStatePhase. It is
// the single source of truth for where in the boot/ceremony flow the node
// is.
type Phase string

const (
	// PhaseFormatting: the state partition is being formatted (first boot).
	PhaseFormatting Phase = "formatting"
	// PhaseUnsealed: the state partition is open but no identity exists yet.
	PhaseUnsealed Phase = "unsealed"
	// PhaseNoIdentity: ready to run the first-boot ceremony.
	PhaseNoIdentity Phase = "no-identity"
	// PhaseCeremonyInProgress: a ceremony started but has not committed.
	PhaseCeremonyInProgress Phase = "ceremony-in-progress"
	// PhaseAwaitingCert: a subordinate has generated its key + CSR and is
	// waiting for a parent-signed certificate chain before it can commit
	// its identity.
	PhaseAwaitingCert Phase = "awaiting-cert"
	// PhaseIdentityEstablished: steady state, the node identity exists.
	PhaseIdentityEstablished Phase = "identity-established"
)

// IdentityState maps a Phase to the proto IdentityState reported by
// GetStatus.
func (p Phase) IdentityState() nodev1.IdentityState {
	switch p {
	case PhaseIdentityEstablished:
		return nodev1.IdentityState_IDENTITY_STATE_ESTABLISHED
	case PhaseCeremonyInProgress:
		return nodev1.IdentityState_IDENTITY_STATE_CEREMONY_IN_PROGRESS
	case PhaseAwaitingCert:
		return nodev1.IdentityState_IDENTITY_STATE_AWAITING_CERT
	default:
		return nodev1.IdentityState_IDENTITY_STATE_NONE
	}
}

// ErrNoIdentity is returned by Identity when the Root identity has not
// been established yet.
var ErrNoIdentity = errors.New("node: no identity established")

// ErrIdentityExists is returned by CommitFirstCeremony when an identity
// already exists, so the guarded transaction did not apply.
var ErrIdentityExists = errors.New("node: identity already exists")

// ErrNotAwaitingCert is returned when a subordinate operation requires
// the node to be in PhaseAwaitingCert but it is not.
var ErrNotAwaitingCert = errors.New("node: node is not awaiting a certificate")

// ErrNoSubordinateCSR is returned by SubordinateCSR when no pending CSR
// has been staged.
var ErrNoSubordinateCSR = errors.New("node: no subordinate CSR staged")

// ErrNoRotation is returned by CommitRotation when no re-key has been
// staged, so the guarded transaction did not apply.
var ErrNoRotation = errors.New("node: no key rotation staged")

// ErrIdentityChanged is returned by CommitRenewal when the node's CA
// certificate is no longer the one the renewal was verified against (a
// concurrent renewal or key rotation committed first), so the guarded
// transaction did not apply.
var ErrIdentityChanged = errors.New("node: CA certificate changed during renewal")

// Store is the typed accessor over the embedded etcd datastore. It is
// the only place outside internal/storage/etcd that reads or writes
// CryptOS state keys; callers go through these methods rather than
// hardcoding paths.
//
// Store does not own the client's lifecycle — the caller (PID 1)
// supplies a connected *clientv3.Client and closes it on shutdown.
type Store struct {
	cli *clientv3.Client
}

// New returns a Store backed by cli. cli must be non-nil and connected.
func New(cli *clientv3.Client) (*Store, error) {
	if cli == nil {
		return nil, errors.New("node: New: nil etcd client")
	}
	return &Store{cli: cli}, nil
}

// Phase reads the current lifecycle phase. A missing key returns
// PhaseNoIdentity (a freshly-initialized store with no phase written
// yet is, semantically, awaiting a ceremony).
func (s *Store) Phase(ctx context.Context) (Phase, error) {
	v, ok, err := s.getString(ctx, etcd.KeyStatePhase)
	if err != nil {
		return "", err
	}
	if !ok {
		return PhaseNoIdentity, nil
	}
	return Phase(v), nil
}

// SetPhase writes the lifecycle phase.
func (s *Store) SetPhase(ctx context.Context, p Phase) error {
	if _, err := s.cli.Put(ctx, etcd.KeyStatePhase, string(p)); err != nil {
		return fmt.Errorf("node: SetPhase: %w", err)
	}
	return nil
}

// BootCount reads the boot counter, defaulting to 0 when unset.
func (s *Store) BootCount(ctx context.Context) (uint64, error) {
	v, ok, err := s.getString(ctx, etcd.KeyBootCount)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, nil
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("node: BootCount: parse %q: %w", v, err)
	}
	return n, nil
}

// IncrementBootCount atomically increments and returns the boot counter.
// It retries on a concurrent update; on a single-writer node the loop
// runs at most twice.
func (s *Store) IncrementBootCount(ctx context.Context) (uint64, error) {
	for {
		cur, ok, err := s.getKV(ctx, etcd.KeyBootCount)
		if err != nil {
			return 0, err
		}
		var n uint64
		var rev int64
		if ok {
			n, err = strconv.ParseUint(string(cur.Value), 10, 64)
			if err != nil {
				return 0, fmt.Errorf("node: IncrementBootCount: parse %q: %w", cur.Value, err)
			}
			rev = cur.ModRevision
		}
		next := n + 1
		cmp := clientv3.Compare(clientv3.ModRevision(etcd.KeyBootCount), "=", rev)
		resp, err := s.cli.Txn(ctx).
			If(cmp).
			Then(clientv3.OpPut(etcd.KeyBootCount, strconv.FormatUint(next, 10))).
			Commit()
		if err != nil {
			return 0, fmt.Errorf("node: IncrementBootCount: %w", err)
		}
		if resp.Succeeded {
			return next, nil
		}
		// Lost the race; retry with the fresh revision.
	}
}

// HasIdentity reports whether the Root certificate has been committed.
func (s *Store) HasIdentity(ctx context.Context) (bool, error) {
	_, ok, err := s.getKV(ctx, etcd.KeyRootCert)
	return ok, err
}

// Identity returns the node's Identity. For a subordinate node that has
// committed a parent-signed chain (KeyIdentityChain present) the chain is
// the full leaf-first path. For a Phase 1 Root the chain has length 1
// (from KeyRootCert). Returns ErrNoIdentity when no identity has been
// committed yet.
func (s *Store) Identity(ctx context.Context) (*nodev1.Identity, error) {
	chainKV, hasChain, err := s.getKV(ctx, etcd.KeyIdentityChain)
	if err != nil {
		return nil, err
	}
	if hasChain {
		var chain [][]byte
		if err := json.Unmarshal(chainKV.Value, &chain); err != nil {
			return nil, fmt.Errorf("node: Identity: decode chain: %w", err)
		}
		if len(chain) == 0 {
			return nil, fmt.Errorf("node: Identity: chain is empty")
		}
		return identityFromChain(chain), nil
	}

	kv, ok, err := s.getKV(ctx, etcd.KeyRootCert)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNoIdentity
	}
	der := append([]byte(nil), kv.Value...)
	return identityFromChain([][]byte{der}), nil
}

// identityFromChain builds the proto Identity from a leaf-first DER
// chain: the concatenated PEM and the SHA-256 of the leaf (chain[0]).
func identityFromChain(chain [][]byte) *nodev1.Identity {
	chainDer := make([][]byte, len(chain))
	var pemBytes []byte
	for i, der := range chain {
		chainDer[i] = append([]byte(nil), der...)
		pemBytes = append(pemBytes, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	leaf := sha256.Sum256(chain[0])
	return &nodev1.Identity{
		ChainDer:   chainDer,
		ChainPem:   string(pemBytes),
		LeafSha256: leaf[:],
	}
}

// AdminRecord is the persisted representation of a trusted administrator
// certificate stored under etcd PrefixAdmins.
type AdminRecord struct {
	SubjectDN string    `json:"subject_dn"`
	SHA256Hex string    `json:"sha256"`
	NotAfter  time.Time `json:"not_after"`
	CertPEM   string    `json:"cert_pem"`
}

func adminRecordFrom(a bootstrap.Admin) AdminRecord {
	return AdminRecord{
		SubjectDN: a.Subject,
		SHA256Hex: hex.EncodeToString(a.SHA256[:]),
		NotAfter:  a.NotAfter,
		CertPEM:   a.CertPEM,
	}
}

// FirstCeremonyCommit bundles every artifact written atomically at the
// end of the first-boot Root ceremony.
type FirstCeremonyCommit struct {
	// RootCertDER is the DER of the self-signed Root certificate.
	RootCertDER []byte
	// RootKeyBlob is the TPM-wrapped Root private key blob.
	RootKeyBlob []byte
	// RootKeyPublic is the TPM public blob for the Root key.
	RootKeyPublic []byte
	// ManifestID identifies the ceremony manifest (the etcd key suffix).
	ManifestID string
	// ManifestBytes is the serialized, signed Ceremony Manifest.
	ManifestBytes []byte
	// Admin is the administrator promoted to steady-state on completion.
	Admin bootstrap.Admin
}

func (c FirstCeremonyCommit) validate() error {
	switch {
	case len(c.RootCertDER) == 0:
		return errors.New("RootCertDER is empty")
	case len(c.RootKeyBlob) == 0:
		return errors.New("RootKeyBlob is empty")
	case len(c.RootKeyPublic) == 0:
		return errors.New("RootKeyPublic is empty")
	case c.ManifestID == "":
		return errors.New("ManifestID is empty")
	case len(c.ManifestBytes) == 0:
		return errors.New("ManifestBytes is empty")
	case c.Admin.SHA256 == [32]byte{}:
		return errors.New("admin record is empty")
	}
	return nil
}

// CommitFirstCeremony writes all identity-creating artifacts in a single
// etcd transaction guarded by "no current identity exists". On success
// the node transitions to PhaseIdentityEstablished. If an identity
// already exists the transaction does not apply and ErrIdentityExists is
// returned, which makes ceremony re-entry after a crash idempotent.
func (s *Store) CommitFirstCeremony(ctx context.Context, c FirstCeremonyCommit) error {
	if err := c.validate(); err != nil {
		return fmt.Errorf("node: CommitFirstCeremony: %w", err)
	}
	adminJSON, err := json.Marshal(adminRecordFrom(c.Admin))
	if err != nil {
		return fmt.Errorf("node: CommitFirstCeremony: marshal admin: %w", err)
	}
	adminKey := etcd.PrefixAdmins + hex.EncodeToString(c.Admin.SHA256[:])

	resp, err := s.cli.Txn(ctx).
		If(clientv3.Compare(clientv3.CreateRevision(etcd.KeyRootCert), "=", 0)).
		Then(
			clientv3.OpPut(etcd.KeyRootCert, string(c.RootCertDER)),
			clientv3.OpPut(etcd.KeyRootKeyBlob, string(c.RootKeyBlob)),
			clientv3.OpPut(etcd.KeyRootKeyPublic, string(c.RootKeyPublic)),
			clientv3.OpPut(etcd.PrefixCeremonyManifests+c.ManifestID, string(c.ManifestBytes)),
			clientv3.OpPut(adminKey, string(adminJSON)),
			clientv3.OpPut(etcd.KeyStatePhase, string(PhaseIdentityEstablished)),
		).
		Commit()
	if err != nil {
		return fmt.Errorf("node: CommitFirstCeremony: txn: %w", err)
	}
	if !resp.Succeeded {
		return ErrIdentityExists
	}
	return nil
}

// RootKeyBlobs returns the stored TPM private + public blobs for the
// Root key, for loading the signer on a subsequent boot. ok is false
// when no identity has been committed.
func (s *Store) RootKeyBlobs(ctx context.Context) (private, public []byte, ok bool, err error) {
	privKV, okPriv, err := s.getKV(ctx, etcd.KeyRootKeyBlob)
	if err != nil {
		return nil, nil, false, err
	}
	pubKV, okPub, err := s.getKV(ctx, etcd.KeyRootKeyPublic)
	if err != nil {
		return nil, nil, false, err
	}
	if !okPriv || !okPub {
		return nil, nil, false, nil
	}
	return append([]byte(nil), privKV.Value...), append([]byte(nil), pubKV.Value...), true, nil
}

// StageSubordinate persists a subordinate node's pending CSR and CA key
// and transitions the node to PhaseAwaitingCert. It is guarded so it only
// applies from a no-identity state: the transaction requires that no Root
// certificate and no committed chain already exist, which makes a re-run
// after a crash safe (a second call while already established does not
// apply and returns ErrIdentityExists). The phase before staging must be
// no-identity; StageSubordinate is idempotent when called again while
// already AwaitingCert (it re-writes the same pending artifacts).
func (s *Store) StageSubordinate(ctx context.Context, csrDER, keyBlob, keyPublic []byte) error {
	switch {
	case len(csrDER) == 0:
		return errors.New("node: StageSubordinate: csrDER is empty")
	case len(keyBlob) == 0:
		return errors.New("node: StageSubordinate: keyBlob is empty")
	case len(keyPublic) == 0:
		return errors.New("node: StageSubordinate: keyPublic is empty")
	}

	resp, err := s.cli.Txn(ctx).
		If(
			clientv3.Compare(clientv3.CreateRevision(etcd.KeyRootCert), "=", 0),
			clientv3.Compare(clientv3.CreateRevision(etcd.KeyIdentityChain), "=", 0),
		).
		Then(
			clientv3.OpPut(etcd.KeySubordinateCSR, string(csrDER)),
			clientv3.OpPut(etcd.KeySubordinateKeyBlob, string(keyBlob)),
			clientv3.OpPut(etcd.KeySubordinateKeyPublic, string(keyPublic)),
			clientv3.OpPut(etcd.KeyStatePhase, string(PhaseAwaitingCert)),
		).
		Commit()
	if err != nil {
		return fmt.Errorf("node: StageSubordinate: txn: %w", err)
	}
	if !resp.Succeeded {
		return ErrIdentityExists
	}
	return nil
}

// SubordinateCSR returns the staged subordinate CSR DER. ok is false when
// no CSR has been staged.
func (s *Store) SubordinateCSR(ctx context.Context) (csrDER []byte, ok bool, err error) {
	kv, ok, err := s.getKV(ctx, etcd.KeySubordinateCSR)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return nil, false, nil
	}
	return append([]byte(nil), kv.Value...), true, nil
}

// SubordinateKeyBlobs returns the staged subordinate CA private + public
// key blobs, for loading the signer once the chain is committed. ok is
// false when no key has been staged.
func (s *Store) SubordinateKeyBlobs(ctx context.Context) (private, public []byte, ok bool, err error) {
	privKV, okPriv, err := s.getKV(ctx, etcd.KeySubordinateKeyBlob)
	if err != nil {
		return nil, nil, false, err
	}
	pubKV, okPub, err := s.getKV(ctx, etcd.KeySubordinateKeyPublic)
	if err != nil {
		return nil, nil, false, err
	}
	if !okPriv || !okPub {
		return nil, nil, false, nil
	}
	return append([]byte(nil), privKV.Value...), append([]byte(nil), pubKV.Value...), true, nil
}

// CommitSubordinateCert atomically records a parent-signed identity for a
// subordinate node. The chain is leaf-first (chainDER[0] is this node's
// certificate). It is written under KeyIdentityChain, the leaf is
// mirrored to KeyRootCert so existing readers keep working, and the phase
// moves to PhaseIdentityEstablished. The transaction is guarded so it
// only applies from PhaseAwaitingCert; any other phase does not apply and
// returns ErrNotAwaitingCert, which makes commit re-entry after a crash
// idempotent. Chain verification is the caller's responsibility (the
// enroller verifies to the pinned parent anchor before calling this).
func (s *Store) CommitSubordinateCert(ctx context.Context, chainDER [][]byte) error {
	if len(chainDER) == 0 {
		return errors.New("node: CommitSubordinateCert: chain is empty")
	}
	for i, der := range chainDER {
		if len(der) == 0 {
			return fmt.Errorf("node: CommitSubordinateCert: chain[%d] is empty", i)
		}
	}
	chainJSON, err := json.Marshal(chainDER)
	if err != nil {
		return fmt.Errorf("node: CommitSubordinateCert: marshal chain: %w", err)
	}
	leafDER := chainDER[0]

	// Guard the phase before touching the staged key so the no-staging and
	// wrong-phase cases keep returning ErrNotAwaitingCert (the guarded
	// transaction below still enforces this atomically; this pre-check only
	// keeps the error contract and lets the promotion rely on the staged key
	// being present). A node in PhaseAwaitingCert always has a staged key:
	// StageSubordinate writes the key atomically with the phase.
	phase, err := s.Phase(ctx)
	if err != nil {
		return fmt.Errorf("node: CommitSubordinateCert: read phase: %w", err)
	}
	if phase != PhaseAwaitingCert {
		return ErrNotAwaitingCert
	}

	// Promote the staged subordinate CA key into the canonical CA-key location
	// the signer reads (KeyRootKeyBlob/KeyRootKeyPublic). Staging persisted the
	// key under the subordinate keys, but the CA signer's loader reads the Root
	// key location; without this promotion an established subordinate has an
	// empty RootKeyBlobs and cannot issue. This mirrors the leaf cert being
	// mirrored to KeyRootCert below so existing readers keep working.
	keyPriv, keyPub, ok, err := s.SubordinateKeyBlobs(ctx)
	if err != nil {
		return fmt.Errorf("node: CommitSubordinateCert: read staged key: %w", err)
	}
	if !ok {
		return errors.New("node: CommitSubordinateCert: no staged subordinate key to promote")
	}

	resp, err := s.cli.Txn(ctx).
		If(clientv3.Compare(clientv3.Value(etcd.KeyStatePhase), "=", string(PhaseAwaitingCert))).
		Then(
			clientv3.OpPut(etcd.KeyIdentityChain, string(chainJSON)),
			clientv3.OpPut(etcd.KeyRootCert, string(leafDER)),
			clientv3.OpPut(etcd.KeyRootKeyBlob, string(keyPriv)),
			clientv3.OpPut(etcd.KeyRootKeyPublic, string(keyPub)),
			clientv3.OpPut(etcd.KeyStatePhase, string(PhaseIdentityEstablished)),
		).
		Commit()
	if err != nil {
		return fmt.Errorf("node: CommitSubordinateCert: txn: %w", err)
	}
	if !resp.Succeeded {
		return ErrNotAwaitingCert
	}
	return nil
}

// StageRotation persists a re-key node's pending new CSR and CA key in the
// rotation slot (separate from the active identity) for an established
// subordinate. It is the established-node sibling of StageSubordinate, guarded
// to the OPPOSITE state: it applies only when an identity already exists (a
// committed chain), so a Root or a not-yet-established subordinate cannot begin
// a re-key. Overwrite of an existing rotation slot is allowed so re-begin
// regenerates the new key. The node keeps serving with its current key while
// the rotation slot holds the new one; CommitRotation performs the atomic swap.
// Returns ErrNoIdentity when no identity has been committed.
func (s *Store) StageRotation(ctx context.Context, csrDER, keyBlob, keyPublic []byte) error {
	switch {
	case len(csrDER) == 0:
		return errors.New("node: StageRotation: csrDER is empty")
	case len(keyBlob) == 0:
		return errors.New("node: StageRotation: keyBlob is empty")
	case len(keyPublic) == 0:
		return errors.New("node: StageRotation: keyPublic is empty")
	}

	resp, err := s.cli.Txn(ctx).
		If(clientv3.Compare(clientv3.CreateRevision(etcd.KeyIdentityChain), "!=", 0)).
		Then(
			clientv3.OpPut(etcd.KeyRotationCSR, string(csrDER)),
			clientv3.OpPut(etcd.KeyRotationKeyBlob, string(keyBlob)),
			clientv3.OpPut(etcd.KeyRotationKeyPublic, string(keyPublic)),
		).
		Commit()
	if err != nil {
		return fmt.Errorf("node: StageRotation: txn: %w", err)
	}
	if !resp.Succeeded {
		return ErrNoIdentity
	}
	return nil
}

// RotationCSR returns the staged re-key CSR DER. ok is false when no rotation
// has been staged.
func (s *Store) RotationCSR(ctx context.Context) (csrDER []byte, ok bool, err error) {
	kv, ok, err := s.getKV(ctx, etcd.KeyRotationCSR)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return nil, false, nil
	}
	return append([]byte(nil), kv.Value...), true, nil
}

// RotationKeyBlobs returns the staged re-key CA private + public key blobs, for
// loading the new signer once the new chain is committed. ok is false when no
// rotation has been staged.
func (s *Store) RotationKeyBlobs(ctx context.Context) (private, public []byte, ok bool, err error) {
	privKV, okPriv, err := s.getKV(ctx, etcd.KeyRotationKeyBlob)
	if err != nil {
		return nil, nil, false, err
	}
	pubKV, okPub, err := s.getKV(ctx, etcd.KeyRotationKeyPublic)
	if err != nil {
		return nil, nil, false, err
	}
	if !okPriv || !okPub {
		return nil, nil, false, nil
	}
	return append([]byte(nil), privKV.Value...), append([]byte(nil), pubKV.Value...), true, nil
}

// CommitRotation atomically swaps an established subordinate to its re-keyed
// identity. The chain is leaf-first (chainDER[0] is this node's new
// certificate). In a single guarded transaction it promotes the staged rotation
// key into the canonical CA-key location (KeyRootKeyBlob/KeyRootKeyPublic), sets
// KeyIdentityChain to the new chain, mirrors the new leaf to KeyRootCert so
// existing readers keep working, and deletes the three rotation-slot keys. The
// transaction is guarded on the rotation key-blob existing so a commit with no
// staged rotation does not apply and returns ErrNoRotation, which makes commit
// re-entry after a crash idempotent. The old key is discarded; certificates it
// already signed keep validating until they expire. The delegated OCSP
// responder under the old key moves to the previous-responder slot in the same
// transaction, so OCSP keeps working for those certificates. Chain verification (that
// the chain roots to the pinned parent anchor and that the leaf carries the
// staged rotation key) is the caller's responsibility (the enroller verifies
// before calling this).
func (s *Store) CommitRotation(ctx context.Context, chainDER [][]byte) error {
	if len(chainDER) == 0 {
		return errors.New("node: CommitRotation: chain is empty")
	}
	for i, der := range chainDER {
		if len(der) == 0 {
			return fmt.Errorf("node: CommitRotation: chain[%d] is empty", i)
		}
	}
	chainJSON, err := json.Marshal(chainDER)
	if err != nil {
		return fmt.Errorf("node: CommitRotation: marshal chain: %w", err)
	}
	leafDER := chainDER[0]

	// Read the staged rotation key to promote. The guarded transaction below
	// re-checks the rotation key-blob exists atomically; this pre-read only lets
	// the promotion carry the key value (a node with a staged rotation always has
	// all three slot keys: StageRotation writes them together).
	keyPriv, keyPub, ok, err := s.RotationKeyBlobs(ctx)
	if err != nil {
		return fmt.Errorf("node: CommitRotation: read staged rotation key: %w", err)
	}
	if !ok {
		return ErrNoRotation
	}

	retire, err := s.retireResponderOps(ctx)
	if err != nil {
		return fmt.Errorf("node: CommitRotation: %w", err)
	}

	ops := []clientv3.Op{
		clientv3.OpPut(etcd.KeyRootKeyBlob, string(keyPriv)),
		clientv3.OpPut(etcd.KeyRootKeyPublic, string(keyPub)),
		clientv3.OpPut(etcd.KeyIdentityChain, string(chainJSON)),
		clientv3.OpPut(etcd.KeyRootCert, string(leafDER)),
		clientv3.OpDelete(etcd.KeyRotationCSR),
		clientv3.OpDelete(etcd.KeyRotationKeyBlob),
		clientv3.OpDelete(etcd.KeyRotationKeyPublic),
	}
	ops = append(ops, retire...)
	resp, err := s.cli.Txn(ctx).
		If(clientv3.Compare(clientv3.CreateRevision(etcd.KeyRotationKeyBlob), "!=", 0)).
		Then(ops...).
		Commit()
	if err != nil {
		return fmt.Errorf("node: CommitRotation: txn: %w", err)
	}
	if !resp.Succeeded {
		return ErrNoRotation
	}
	return nil
}

// retireResponderOps returns the operations that move the stored OCSP responder
// and the CA certificate it chains to into the previous-responder slot. It
// returns none when there is nothing valid to keep: no responder has been
// minted, or the stored one is not signed by the CA being retired, which
// happens when two re-keys land before the responder is re-minted. Pairing that
// responder with this CA certificate would produce responses no client accepts,
// so the slot keeps what it has, a pair that still matches.
func (s *Store) retireResponderOps(ctx context.Context) ([]clientv3.Op, error) {
	certDER, keyBlob, _, ok, err := s.OCSPResponder(ctx)
	if err != nil {
		return nil, fmt.Errorf("read OCSP responder: %w", err)
	}
	if !ok {
		log.Printf("node: re-key: no OCSP responder stored, nothing to keep for the retiring CA key")
		return nil, nil
	}
	caKV, ok, err := s.getKV(ctx, etcd.KeyRootCert)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}
	if !ok {
		return nil, nil
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		log.Printf("node: re-key: stored OCSP responder does not parse, not keeping it: %v", err)
		return nil, nil
	}
	caCert, err := x509.ParseCertificate(caKV.Value)
	if err != nil {
		log.Printf("node: re-key: CA certificate does not parse, not keeping the OCSP responder: %v", err)
		return nil, nil
	}
	if err := cert.CheckSignatureFrom(caCert); err != nil {
		log.Printf("node: re-key: OCSP responder (serial %s) is not signed by the retiring CA certificate, not keeping it: %v",
			cert.SerialNumber.Text(16), err)
		return nil, nil
	}
	log.Printf("node: re-key: keeping OCSP responder (serial %s) for the retiring CA key until %s",
		cert.SerialNumber.Text(16), cert.NotAfter.UTC().Format(time.RFC3339))
	return []clientv3.Op{
		clientv3.OpPut(etcd.KeyOCSPPreviousResponderCert, string(certDER)),
		clientv3.OpPut(etcd.KeyOCSPPreviousResponderKeyBlob, string(keyBlob)),
		clientv3.OpPut(etcd.KeyOCSPPreviousResponderCACert, string(caKV.Value)),
	}, nil
}

// CommitRenewal atomically replaces an established subordinate's CA
// certificate with a re-certification of the SAME key. The chain is leaf-first
// (chainDER[0] is the renewed certificate). In a single guarded transaction it
// sets KeyIdentityChain to the new chain, mirrors the new leaf to KeyRootCert,
// and records the replaced certificate under PrefixIdentityHistory for audit.
// The CA key blobs are not touched. The transaction applies only while
// KeyRootCert still equals currentLeafDER (the certificate the caller verified
// the renewal against) and a committed chain exists, so a racing renewal or key
// rotation makes it return ErrIdentityChanged instead of overwriting. Chain
// verification (parent anchor, same key, same subject) is the caller's
// responsibility (the enroller verifies before calling this).
func (s *Store) CommitRenewal(ctx context.Context, currentLeafDER []byte, chainDER [][]byte) error {
	if len(currentLeafDER) == 0 {
		return errors.New("node: CommitRenewal: current certificate is empty")
	}
	if len(chainDER) == 0 {
		return errors.New("node: CommitRenewal: chain is empty")
	}
	for i, der := range chainDER {
		if len(der) == 0 {
			return fmt.Errorf("node: CommitRenewal: chain[%d] is empty", i)
		}
	}
	chainJSON, err := json.Marshal(chainDER)
	if err != nil {
		return fmt.Errorf("node: CommitRenewal: marshal chain: %w", err)
	}
	sum := sha256.Sum256(currentLeafDER)

	resp, err := s.cli.Txn(ctx).
		If(
			clientv3.Compare(clientv3.Value(etcd.KeyRootCert), "=", string(currentLeafDER)),
			clientv3.Compare(clientv3.CreateRevision(etcd.KeyIdentityChain), "!=", 0),
		).
		Then(
			clientv3.OpPut(etcd.PrefixIdentityHistory+hex.EncodeToString(sum[:]), string(currentLeafDER)),
			clientv3.OpPut(etcd.KeyIdentityChain, string(chainJSON)),
			clientv3.OpPut(etcd.KeyRootCert, string(chainDER[0])),
		).
		Commit()
	if err != nil {
		return fmt.Errorf("node: CommitRenewal: txn: %w", err)
	}
	if !resp.Succeeded {
		return ErrIdentityChanged
	}
	return nil
}

// CertificateHistory returns the CA certificates (DER) this node replaced by
// re-certification, oldest first.
func (s *Store) CertificateHistory(ctx context.Context) ([][]byte, error) {
	resp, err := s.cli.Get(ctx, etcd.PrefixIdentityHistory,
		clientv3.WithPrefix(),
		clientv3.WithSort(clientv3.SortByCreateRevision, clientv3.SortAscend))
	if err != nil {
		return nil, fmt.Errorf("node: CertificateHistory: %w", err)
	}
	out := make([][]byte, 0, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		out = append(out, append([]byte(nil), kv.Value...))
	}
	return out, nil
}

// CommitRestoredIdentity atomically restores a CA identity from an operator
// backup onto a node that has none. It is the storage counterpart of a CA key
// import (the recovery sibling of the first-boot ceremony): it writes the
// restored CA key blobs to KeyRootKeyBlob/KeyRootKeyPublic, the restored
// identity chain (leaf-first) to KeyIdentityChain, mirrors the leaf to
// KeyRootCert so existing readers keep working, and moves the node to
// PhaseIdentityEstablished. The transaction is guarded like StageSubordinate so
// it only applies from a no-identity state: it requires that no Root
// certificate and no committed chain already exist. If an identity already
// exists the transaction does not apply and ErrIdentityExists is returned.
// Chain/key validation (that the chain's leaf carries the restored key) is the
// caller's responsibility.
func (s *Store) CommitRestoredIdentity(ctx context.Context, keyBlob, keyPublic []byte, chainDER [][]byte) error {
	switch {
	case len(keyBlob) == 0:
		return errors.New("node: CommitRestoredIdentity: keyBlob is empty")
	case len(keyPublic) == 0:
		return errors.New("node: CommitRestoredIdentity: keyPublic is empty")
	case len(chainDER) == 0:
		return errors.New("node: CommitRestoredIdentity: chain is empty")
	}
	for i, der := range chainDER {
		if len(der) == 0 {
			return fmt.Errorf("node: CommitRestoredIdentity: chain[%d] is empty", i)
		}
	}
	chainJSON, err := json.Marshal(chainDER)
	if err != nil {
		return fmt.Errorf("node: CommitRestoredIdentity: marshal chain: %w", err)
	}
	leafDER := chainDER[0]

	resp, err := s.cli.Txn(ctx).
		If(
			clientv3.Compare(clientv3.CreateRevision(etcd.KeyRootCert), "=", 0),
			clientv3.Compare(clientv3.CreateRevision(etcd.KeyIdentityChain), "=", 0),
		).
		Then(
			clientv3.OpPut(etcd.KeyRootKeyBlob, string(keyBlob)),
			clientv3.OpPut(etcd.KeyRootKeyPublic, string(keyPublic)),
			clientv3.OpPut(etcd.KeyIdentityChain, string(chainJSON)),
			clientv3.OpPut(etcd.KeyRootCert, string(leafDER)),
			clientv3.OpPut(etcd.KeyStatePhase, string(PhaseIdentityEstablished)),
		).
		Commit()
	if err != nil {
		return fmt.Errorf("node: CommitRestoredIdentity: txn: %w", err)
	}
	if !resp.Succeeded {
		return ErrIdentityExists
	}
	return nil
}

// PutOCSPResponder persists the delegated OCSP responder certificate (DER) and
// its private key (software-backend blob + PKIX public blob, the same encoding
// as the CA key). The responder is node-internal state minted and renewed by
// the node's own CA; it is written under the /cryptos/pki/ocsp-responder/ keys.
func (s *Store) PutOCSPResponder(ctx context.Context, certDER, keyBlob, keyPublic []byte) error {
	switch {
	case len(certDER) == 0:
		return errors.New("node: PutOCSPResponder: certDER is empty")
	case len(keyBlob) == 0:
		return errors.New("node: PutOCSPResponder: keyBlob is empty")
	case len(keyPublic) == 0:
		return errors.New("node: PutOCSPResponder: keyPublic is empty")
	}
	_, err := s.cli.Txn(ctx).
		Then(
			clientv3.OpPut(etcd.KeyOCSPResponderCert, string(certDER)),
			clientv3.OpPut(etcd.KeyOCSPResponderKeyBlob, string(keyBlob)),
			clientv3.OpPut(etcd.KeyOCSPResponderKeyPublic, string(keyPublic)),
		).
		Commit()
	if err != nil {
		return fmt.Errorf("node: PutOCSPResponder: txn: %w", err)
	}
	return nil
}

// OCSPResponder returns the stored delegated OCSP responder certificate (DER)
// and its private + public key blobs. ok is false when no responder has been
// persisted yet (a node that has not minted one).
func (s *Store) OCSPResponder(ctx context.Context) (certDER, keyBlob, keyPublic []byte, ok bool, err error) {
	certKV, okCert, err := s.getKV(ctx, etcd.KeyOCSPResponderCert)
	if err != nil {
		return nil, nil, nil, false, err
	}
	blobKV, okBlob, err := s.getKV(ctx, etcd.KeyOCSPResponderKeyBlob)
	if err != nil {
		return nil, nil, nil, false, err
	}
	pubKV, okPub, err := s.getKV(ctx, etcd.KeyOCSPResponderKeyPublic)
	if err != nil {
		return nil, nil, nil, false, err
	}
	if !okCert || !okBlob || !okPub {
		return nil, nil, nil, false, nil
	}
	return append([]byte(nil), certKV.Value...),
		append([]byte(nil), blobKV.Value...),
		append([]byte(nil), pubKV.Value...),
		true, nil
}

// PreviousOCSPResponder returns the responder retired by the last CA re-key:
// its certificate (DER), its private key blob, and the CA certificate (DER) it
// chains to. ok is false when the slot is empty.
func (s *Store) PreviousOCSPResponder(ctx context.Context) (certDER, keyBlob, caCertDER []byte, ok bool, err error) {
	certKV, okCert, err := s.getKV(ctx, etcd.KeyOCSPPreviousResponderCert)
	if err != nil {
		return nil, nil, nil, false, err
	}
	blobKV, okBlob, err := s.getKV(ctx, etcd.KeyOCSPPreviousResponderKeyBlob)
	if err != nil {
		return nil, nil, nil, false, err
	}
	caKV, okCA, err := s.getKV(ctx, etcd.KeyOCSPPreviousResponderCACert)
	if err != nil {
		return nil, nil, nil, false, err
	}
	if !okCert || !okBlob || !okCA {
		return nil, nil, nil, false, nil
	}
	return append([]byte(nil), certKV.Value...),
		append([]byte(nil), blobKV.Value...),
		append([]byte(nil), caKV.Value...),
		true, nil
}

// DropPreviousOCSPResponder empties the previous-responder slot if it still
// holds certDER, so a re-key that filled the slot in the meantime is not undone.
func (s *Store) DropPreviousOCSPResponder(ctx context.Context, certDER []byte) error {
	_, err := s.cli.Txn(ctx).
		If(clientv3.Compare(clientv3.Value(etcd.KeyOCSPPreviousResponderCert), "=", string(certDER))).
		Then(
			clientv3.OpDelete(etcd.KeyOCSPPreviousResponderCert),
			clientv3.OpDelete(etcd.KeyOCSPPreviousResponderKeyBlob),
			clientv3.OpDelete(etcd.KeyOCSPPreviousResponderCACert),
		).
		Commit()
	if err != nil {
		return fmt.Errorf("node: DropPreviousOCSPResponder: txn: %w", err)
	}
	return nil
}

// getString returns the value at key as a string and whether it exists.
func (s *Store) getString(ctx context.Context, key string) (string, bool, error) {
	kv, ok, err := s.getKV(ctx, key)
	if err != nil || !ok {
		return "", ok, err
	}
	return string(kv.Value), true, nil
}

// getKV returns the single KV at key (exact match) and whether it exists.
func (s *Store) getKV(ctx context.Context, key string) (kv *kvPair, ok bool, err error) {
	resp, err := s.cli.Get(ctx, key)
	if err != nil {
		return nil, false, fmt.Errorf("node: get %q: %w", key, err)
	}
	if len(resp.Kvs) == 0 {
		return nil, false, nil
	}
	return &kvPair{Value: resp.Kvs[0].Value, ModRevision: resp.Kvs[0].ModRevision}, true, nil
}

// kvPair is the minimal slice of an etcd KV that Store needs.
type kvPair struct {
	Value       []byte
	ModRevision int64
}
