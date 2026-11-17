package e2e_test

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

// This file composes the real CryptOS hierarchy across a root and a
// subordinate node in one process, using the software (nodeID) root-key
// backend so no TPM or CGO is required. It is the reproducible P6 proof that
// the mechanism works end-to-end: the root establishes its identity, signs the
// subordinate's CSR into a CA certificate, the subordinate verifies the
// returned chain against its pinned parent anchor and commits, serves the full
// chain, and then issues a leaf that chains back to the root. A physical
// two-VM run on the lab is a separate operator step.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"github.com/CryptOS-PKI/cryptos-node/internal/bootstrap"
	"github.com/CryptOS-PKI/cryptos-node/internal/ca"
	"github.com/CryptOS-PKI/cryptos-node/internal/ceremony"
	"github.com/CryptOS-PKI/cryptos-node/internal/config"
	cinit "github.com/CryptOS-PKI/cryptos-node/internal/init"
	"github.com/CryptOS-PKI/cryptos-node/internal/node"
	"github.com/CryptOS-PKI/cryptos-node/internal/storage/etcd"
	"github.com/CryptOS-PKI/cryptos-node/internal/testadmin"
)

// TestHierarchyE2E drives the full root plus subordinate CA lifecycle with the
// real code paths, wired together with the software key backend.
func TestHierarchyE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	// -----------------------------------------------------------------
	// Step 1: establish the ROOT via the real first-boot ceremony.
	// -----------------------------------------------------------------
	rootStore := newStore(t)
	adminFP := establishRoot(t, ctx, rootStore)

	rootID, err := rootStore.Identity(ctx)
	if err != nil {
		t.Fatalf("root Identity after ceremony: %v", err)
	}
	if len(rootID.ChainDer) != 1 {
		t.Fatalf("root chain len = %d, want 1 (self-signed root)", len(rootID.ChainDer))
	}
	rootCertDER := rootID.ChainDer[0]
	rootCert, err := x509.ParseCertificate(rootCertDER)
	if err != nil {
		t.Fatalf("parse root cert: %v", err)
	}
	if !rootCert.IsCA {
		t.Fatal("root cert IsCA = false")
	}
	// The root must self-verify (it is its own anchor).
	rootOnlyPool := x509.NewCertPool()
	rootOnlyPool.AddCert(rootCert)
	if _, err := rootCert.Verify(x509.VerifyOptions{Roots: rootOnlyPool}); err != nil {
		t.Fatalf("root cert does not self-verify: %v", err)
	}
	rootPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCertDER}))

	// The root's on-node config carries the certificate profiles it signs
	// with. The ceremony only needs root subject/validity; profiles live in
	// the node's loaded config, which is what the CASigner consults.
	rootSigningCfg := rootProfilesConfig()

	// -----------------------------------------------------------------
	// Step 2: stage the SUBORDINATE on a second store + software key.
	// -----------------------------------------------------------------
	subStore := newStore(t)
	subKey := newP384Key(t)
	subCSRDER := buildCSR(t, subKey, pkix.Name{CommonName: "ACME Issuing G1"})
	subKeyBlob := marshalECKey(t, subKey)
	subKeyPub := marshalECPub(t, subKey)
	if err := subStore.StageSubordinate(ctx, subCSRDER, subKeyBlob, subKeyPub); err != nil {
		t.Fatalf("StageSubordinate: %v", err)
	}
	if phase, _ := subStore.Phase(ctx); phase != node.PhaseAwaitingCert {
		t.Fatalf("subordinate phase after stage = %q, want %q", phase, node.PhaseAwaitingCert)
	}
	gotCSR, ok, err := subStore.SubordinateCSR(ctx)
	if err != nil || !ok {
		t.Fatalf("SubordinateCSR ok=%v err=%v", ok, err)
	}
	if string(gotCSR) != string(subCSRDER) {
		t.Fatal("SubordinateCSR did not round-trip the staged CSR")
	}

	// -----------------------------------------------------------------
	// Step 3: the ROOT signs the subordinate CSR into a CA certificate.
	// -----------------------------------------------------------------
	rootSigner := newRootCASigner(t, ctx, rootStore, rootCert, rootSigningCfg)
	chainDER, chainPEM, _, err := rootSigner.SignSubordinate(ctx, subCSRDER, "sub-ca")
	if err != nil {
		t.Fatalf("root SignSubordinate: %v", err)
	}
	if chainPEM == "" {
		t.Fatal("SignSubordinate returned an empty chain PEM")
	}
	if len(chainDER) != 2 {
		t.Fatalf("signed chain len = %d, want 2 [sub, root]", len(chainDER))
	}
	subCert, err := x509.ParseCertificate(chainDER[0])
	if err != nil {
		t.Fatalf("parse subordinate cert: %v", err)
	}
	if !subCert.IsCA {
		t.Fatal("subordinate cert IsCA = false")
	}
	// The profile requested pathLen 1; the root is unconstrained (a root omits
	// pathLenConstraint), so the profile value stands: MaxPathLen 1, not zero.
	if subCert.MaxPathLen != 1 || subCert.MaxPathLenZero {
		t.Fatalf("subordinate pathLen: got MaxPathLen=%d MaxPathLenZero=%v, want 1/false",
			subCert.MaxPathLen, subCert.MaxPathLenZero)
	}
	if string(chainDER[1]) != string(rootCertDER) {
		t.Fatal("second chain element is not the root certificate")
	}
	// The subordinate cert verifies to the root.
	if _, err := subCert.Verify(x509.VerifyOptions{
		Roots:     rootOnlyPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Fatalf("subordinate cert does not verify to the root: %v", err)
	}

	// -----------------------------------------------------------------
	// Step 4: the SUBORDINATE accepts + commits, then serves the chain.
	// -----------------------------------------------------------------
	subCfg := subordinateConfig(t, rootPEM)
	parentTrust, err := subCfg.ParentTrust()
	if err != nil {
		t.Fatalf("subordinate ParentTrust: %v", err)
	}
	if parentTrust == nil {
		t.Fatal("subordinate ParentTrust returned nil for a configured parent")
	}
	enroller, err := node.NewSubordinateEnroller(subStore, parentTrust)
	if err != nil {
		t.Fatalf("NewSubordinateEnroller: %v", err)
	}

	committedID, err := enroller.AcceptCertificate(ctx, chainDER)
	if err != nil {
		t.Fatalf("subordinate AcceptCertificate: %v", err)
	}
	if len(committedID.ChainDer) != 2 {
		t.Fatalf("committed identity chain len = %d, want 2 [intermediate, root]", len(committedID.ChainDer))
	}
	if phase, _ := subStore.Phase(ctx); phase != node.PhaseIdentityEstablished {
		t.Fatalf("subordinate phase after accept = %q, want %q", phase, node.PhaseIdentityEstablished)
	}

	// Identity() serves the full [intermediate, root] chain, and it verifies to
	// the pinned root anchor.
	served, err := subStore.Identity(ctx)
	if err != nil {
		t.Fatalf("subordinate Identity after commit: %v", err)
	}
	if len(served.ChainDer) != 2 {
		t.Fatalf("served chain len = %d, want 2", len(served.ChainDer))
	}
	servedLeaf, err := x509.ParseCertificate(served.ChainDer[0])
	if err != nil {
		t.Fatalf("parse served leaf: %v", err)
	}
	if _, err := servedLeaf.Verify(x509.VerifyOptions{
		Roots:     rootOnlyPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Fatalf("served intermediate does not verify to the root anchor: %v", err)
	}

	// Negative: a chain minted by a WRONG anchor (rooting to a different CA)
	// is rejected on a fresh subordinate and never commits.
	assertWrongAnchorRejected(t, ctx, subKey)
	// Negative: a chain for a DIFFERENT leaf key, though rooted at the pinned
	// anchor, is rejected on a fresh subordinate and never commits.
	assertWrongLeafKeyRejected(t, ctx, rootPEM, rootCert, rootStore, rootSigningCfg)

	// -----------------------------------------------------------------
	// Step 5: the SUBORDINATE issues a leaf that chains to the root.
	// -----------------------------------------------------------------
	subCASigner := newSubordinateCASigner(t, ctx, subStore, subCert, subCfg)
	leafKey := newP384Key(t)
	leafCSR := buildCSR(t, leafKey, pkix.Name{CommonName: "node.acme.example"})
	leafDER, err := subCASigner.IssueLeaf(ctx, leafCSR, "leaf")
	if err != nil {
		t.Fatalf("subordinate IssueLeaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if leaf.IsCA {
		t.Fatal("issued leaf IsCA = true, want a non-CA end-entity")
	}
	// The leaf verifies through [intermediate, root] to the root anchor.
	intermediates := x509.NewCertPool()
	intermediates.AddCert(subCert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         rootOnlyPool,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("leaf does not verify through [intermediate, root]: %v", err)
	}
	_ = adminFP
}

// assertWrongAnchorRejected stages a fresh subordinate pinned to one root but
// offered a chain rooted at an unrelated CA. AcceptCertificate must reject it
// and leave the node awaiting its certificate.
func assertWrongAnchorRejected(t *testing.T, ctx context.Context, subKey *ecdsa.PrivateKey) {
	t.Helper()

	// The pinned anchor is a self-signed root the subordinate trusts.
	pinnedKey := newP384Key(t)
	pinnedDER := selfSignedRoot(t, pinnedKey, "Pinned Root")
	pinnedPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pinnedDER}))

	// A rogue root actually signs the leaf; the offered chain roots to it.
	rogueKey := newP384Key(t)
	rogueDER := selfSignedRoot(t, rogueKey, "Rogue Root")
	rogueCert, err := x509.ParseCertificate(rogueDER)
	if err != nil {
		t.Fatalf("parse rogue root: %v", err)
	}

	store := newStore(t)
	csrDER := buildCSR(t, subKey, pkix.Name{CommonName: "ACME Issuing G1"})
	if err := store.StageSubordinate(ctx, csrDER, []byte("blob"), []byte("pub")); err != nil {
		t.Fatalf("StageSubordinate (wrong-anchor case): %v", err)
	}

	// The rogue signs a subordinate-CA cert carrying the node's real staged
	// key, so only the anchor mismatch (not a key mismatch) causes rejection.
	rogueLeafDER := signSubCA(t, rogueCert, rogueKey, &subKey.PublicKey)
	chain := [][]byte{rogueLeafDER, rogueDER}

	trust, err := bootstrap.LoadTrust(pinnedPEM, "")
	if err != nil {
		t.Fatalf("LoadTrust (pinned): %v", err)
	}
	enroller, err := node.NewSubordinateEnroller(store, trust)
	if err != nil {
		t.Fatalf("NewSubordinateEnroller (wrong-anchor case): %v", err)
	}
	if _, err := enroller.AcceptCertificate(ctx, chain); err == nil {
		t.Fatal("AcceptCertificate accepted a chain rooted at the wrong anchor")
	}
	if phase, _ := store.Phase(ctx); phase != node.PhaseAwaitingCert {
		t.Fatalf("phase after wrong-anchor reject = %q, want %q (no commit)", phase, node.PhaseAwaitingCert)
	}
}

// assertWrongLeafKeyRejected stages a fresh subordinate pinned to the real
// root, but the root signs a chain for a DIFFERENT key than the node staged.
// The chain roots to the pinned anchor yet the leaf key is wrong, so
// AcceptCertificate must reject it without committing.
func assertWrongLeafKeyRejected(t *testing.T, ctx context.Context, rootPEM string, rootCert *x509.Certificate, rootStore *node.Store, rootSigningCfg *config.Config) {
	t.Helper()

	store := newStore(t)
	stagedKey := newP384Key(t)
	csrDER := buildCSR(t, stagedKey, pkix.Name{CommonName: "ACME Issuing G1"})
	if err := store.StageSubordinate(ctx, csrDER, []byte("blob"), []byte("pub")); err != nil {
		t.Fatalf("StageSubordinate (wrong-key case): %v", err)
	}

	// The root signs a subordinate CSR for a completely different key.
	otherKey := newP384Key(t)
	otherCSR := buildCSR(t, otherKey, pkix.Name{CommonName: "ACME Issuing G1"})
	rootSigner := newRootCASigner(t, ctx, rootStore, rootCert, rootSigningCfg)
	chain, _, _, err := rootSigner.SignSubordinate(ctx, otherCSR, "sub-ca")
	if err != nil {
		t.Fatalf("root SignSubordinate (other key): %v", err)
	}

	trust, err := bootstrap.LoadTrust(rootPEM, "")
	if err != nil {
		t.Fatalf("LoadTrust (root): %v", err)
	}
	enroller, err := node.NewSubordinateEnroller(store, trust)
	if err != nil {
		t.Fatalf("NewSubordinateEnroller (wrong-key case): %v", err)
	}
	if _, err := enroller.AcceptCertificate(ctx, chain); err == nil {
		t.Fatal("AcceptCertificate accepted a chain minted for the wrong leaf key")
	}
	if phase, _ := store.Phase(ctx); phase != node.PhaseAwaitingCert {
		t.Fatalf("phase after wrong-key reject = %q, want %q (no commit)", phase, node.PhaseAwaitingCert)
	}
}

// newStore spins up an embedded etcd in a temp dir and returns a *node.Store,
// mirroring the store-test harness.
func newStore(t *testing.T) *node.Store {
	t.Helper()
	srv, err := etcd.Open(t.TempDir())
	if err != nil {
		t.Fatalf("etcd.Open: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	cli, err := srv.Client()
	if err != nil {
		t.Fatalf("etcd.Client: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	s, err := node.New(cli)
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	return s
}

// establishRoot runs the real first-boot ceremony against store with the
// software key backend and a no-peer (local-socket) context, and returns the
// bootstrap admin fingerprint the ceremony was configured with.
func establishRoot(t *testing.T, ctx context.Context, store *node.Store) [32]byte {
	t.Helper()

	adminFP := adminFingerprint(t)
	trust, err := bootstrap.LoadTrust("", hex.EncodeToString(adminFP[:]))
	if err != nil {
		t.Fatalf("LoadTrust (admin): %v", err)
	}
	seed := make([]byte, ceremony.SeedLength)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("seed: %v", err)
	}
	eng, err := ceremony.New(ceremony.Config{
		RootKey:     cinit.NewSoftRootBackend(),
		Store:       store,
		ConfigStore: config.NewFileStore(t.TempDir()),
		Trust:       trust,
		Seed:        seed,
	})
	if err != nil {
		t.Fatalf("ceremony.New: %v", err)
	}

	req := &nodev1.StartCeremonyRequest{
		Kind:              nodev1.CeremonyKind_CEREMONY_KIND_FIRST_BOOT_ROOT,
		MachineConfigYaml: rootCeremonyYAML(),
	}
	// A no-peer context is the local root-only UNIX socket: authorizeCaller
	// trusts it, so this drives the production ceremony without mTLS setup.
	if err := eng.Start(ctx, req, func(*nodev1.StartCeremonyResponse) error { return nil }); err != nil {
		t.Fatalf("ceremony Start: %v", err)
	}
	return adminFP
}

// newRootCASigner builds the root's node.CASigner: the KeyLoader reloads the
// root CA key from the store's persisted blobs through the software backend
// (as production does), the IssuerFunc serves the root cert, and the
// ConfigFunc serves the root's profile-carrying config.
func newRootCASigner(t *testing.T, ctx context.Context, store *node.Store, rootCert *x509.Certificate, cfg *config.Config) *node.CASigner {
	t.Helper()

	priv, pub, ok, err := store.RootKeyBlobs(ctx)
	if err != nil || !ok {
		t.Fatalf("RootKeyBlobs ok=%v err=%v", ok, err)
	}
	backend := cinit.NewSoftRootBackend()
	load := func(context.Context) (crypto.Signer, func(), error) {
		signer, err := backend.LoadKey(priv, pub)
		if err != nil {
			return nil, nil, err
		}
		return signer, func() { _ = signer.Close() }, nil
	}
	issuer := func(context.Context) (*x509.Certificate, error) { return rootCert, nil }
	get := func(context.Context) (*config.Config, error) { return cfg, nil }
	return node.NewCASigner(load, issuer, get)
}

// newSubordinateCASigner builds the subordinate's node.CASigner exactly as
// production wires it in internal/init/run.go: the KeyLoader reloads the CA key
// from the store's canonical KeyRootKeyBlob location through the software
// backend. Loading from the store (not an in-memory key) is deliberate — it is
// the only way this test proves that committing the parent-signed chain also
// promoted the staged subordinate key into the location the signer reads.
func newSubordinateCASigner(t *testing.T, ctx context.Context, store *node.Store, subCert *x509.Certificate, cfg *config.Config) *node.CASigner {
	t.Helper()

	priv, pub, ok, err := store.RootKeyBlobs(ctx)
	if err != nil || !ok {
		t.Fatalf("subordinate RootKeyBlobs after commit: ok=%v err=%v", ok, err)
	}
	backend := cinit.NewSoftRootBackend()
	load := func(context.Context) (crypto.Signer, func(), error) {
		signer, err := backend.LoadKey(priv, pub)
		if err != nil {
			return nil, nil, err
		}
		return signer, func() { _ = signer.Close() }, nil
	}
	issuer := func(context.Context) (*x509.Certificate, error) { return subCert, nil }
	get := func(context.Context) (*config.Config, error) { return cfg, nil }
	return node.NewCASigner(load, issuer, get)
}

// rootProfilesConfig is the root node's loaded config: role root, with a CA
// profile (sub-ca, pathLen 1) it signs subordinates under and a leaf profile.
func rootProfilesConfig() *config.Config {
	pathLen := uint32(1)
	return &config.Config{
		Role: config.Role{Kind: config.RoleRoot},
		PKI: config.PKI{
			Profiles: []config.CertificateProfile{
				{
					Name:             "sub-ca",
					KeyAlg:           config.RootKeyECDSAP384,
					Subject:          config.Subject{CommonName: "ACME Issuing G1"},
					ValidityDays:     3650,
					BasicConstraints: config.BasicConstraints{IsCA: true, PathLen: &pathLen},
					KeyUsage:         []string{"cert_sign", "crl_sign"},
				},
				{
					Name:             "leaf",
					KeyAlg:           config.RootKeyECDSAP384,
					Subject:          config.Subject{CommonName: "leaf"},
					ValidityDays:     90,
					BasicConstraints: config.BasicConstraints{IsCA: false},
					KeyUsage:         []string{"digital_signature"},
					ExtKeyUsage:      []string{"server_auth"},
				},
			},
		},
	}
}

// subordinateConfig is the subordinate node's loaded config: role intermediate,
// pinned to the root anchor via pki.parent.ca_cert_pem, with a leaf profile it
// issues end-entity certificates under. It is validated through config.Parse so
// the ParentTrust path is exercised exactly as production loads it.
func subordinateConfig(t *testing.T, rootPEM string) *config.Config {
	t.Helper()
	indented := indentPEM(rootPEM, "      ")
	yaml := []byte(fmt.Sprintf(`apiVersion: cryptos.dev/v1alpha1
kind: MachineConfig
metadata:
  name: issuing-g1
role:
  kind: intermediate
network:
  interface: eth0
  address: 10.0.0.11/24
  gateway: 10.0.0.1
bootstrap:
  admin_cert_pem: "`+testadmin.YAMLPEM+`"
pki:
  root_key_alg: ECDSA-P384
  root_subject:
    common_name: "ACME Issuing G1"
    organization: "ACME"
    country: "US"
  root_validity_years: 10
  path_len_constraint: 0
  parent:
    ca_cert_pem: |
%s
  profiles:
    - name: leaf
      key_alg: ECDSA-P384
      subject:
        common_name: leaf
      validity_days: 90
      basic_constraints:
        is_ca: false
      key_usage: [digital_signature]
      ext_key_usage: [server_auth]
`, indented))
	cfg, err := config.Parse(yaml)
	if err != nil {
		t.Fatalf("config.Parse (subordinate): %v", err)
	}
	return cfg
}

// rootCeremonyYAML is the operator's MachineConfig for the first-boot root
// ceremony. The ceremony consumes only the root subject and validity here; the
// signing profiles live in the node's loaded config (rootProfilesConfig).
func rootCeremonyYAML() []byte {
	return []byte(fmt.Sprintf(`apiVersion: cryptos.dev/v1alpha1
kind: MachineConfig
metadata:
  name: root-ca
role:
  kind: root
network:
  interface: eth0
  address: 10.0.0.10/24
  gateway: 10.0.0.1
bootstrap:
  admin_cert_pem: "` + testadmin.YAMLPEM + `"
pki:
  root_key_alg: ECDSA-P384
  root_subject:
    common_name: "ACME Root CA"
    organization: "ACME"
    country: "US"
  root_validity_years: 20
  path_len_constraint: 1
`))
}

// adminFingerprint mints a throwaway admin certificate and returns its SHA-256
// fingerprint, the form the ceremony config pins.
func adminFingerprint(t *testing.T) [32]byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("admin GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "bootstrap-admin"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("admin CreateCertificate: %v", err)
	}
	return sha256.Sum256(der)
}

// newP384Key generates a fresh ECDSA P-384 key (the Phase-2 profile).
func newP384Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}

// buildCSR builds a DER PKCS#10 CSR for key with subject, matching what
// production's buildSubordinateCSR emits (ECDSAWithSHA384).
func buildCSR(t *testing.T, key *ecdsa.PrivateKey, subject pkix.Name) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: x509.ECDSAWithSHA384,
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return der
}

// selfSignedRoot mints a self-signed P-384 root CA cert DER for key with the
// given common name, via the real ca.SelfSignRoot.
func selfSignedRoot(t *testing.T, key *ecdsa.PrivateKey, cn string) []byte {
	t.Helper()
	now := time.Now()
	der, _, err := ca.SelfSignRoot(ca.RootParams{
		Signer:    key,
		Subject:   pkix.Name{CommonName: cn},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("SelfSignRoot: %v", err)
	}
	return der
}

// signSubCA signs a subordinate-CA certificate for subjectPub with the issuer
// cert and key via the real ca.Sign, returning its DER.
func signSubCA(t *testing.T, issuer *x509.Certificate, issuerKey crypto.Signer, subjectPub crypto.PublicKey) []byte {
	t.Helper()
	now := time.Now()
	pathLen := 0
	der, _, err := ca.Sign(ca.Profile{
		Subject:   pkix.Name{CommonName: "ACME Issuing G1"},
		NotBefore: now.Add(-time.Minute),
		NotAfter:  now.Add(12 * time.Hour),
		IsCA:      true,
		PathLen:   &pathLen,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, subjectPub, issuer, issuerKey)
	if err != nil {
		t.Fatalf("ca.Sign: %v", err)
	}
	return der
}

func marshalECKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	return der
}

func marshalECPub(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return der
}

// indentPEM prefixes every line of a PEM block with prefix so it nests under a
// YAML literal block scalar.
func indentPEM(pemStr, prefix string) string {
	out := ""
	for _, line := range splitLines(pemStr) {
		if line == "" {
			continue
		}
		out += prefix + line + "\n"
	}
	return out
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
