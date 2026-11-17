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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"github.com/CryptOS-PKI/cryptos-node/internal/bootstrap"
	"github.com/CryptOS-PKI/cryptos-node/internal/config"
	cgrpc "github.com/CryptOS-PKI/cryptos-node/internal/grpc"
	"github.com/CryptOS-PKI/cryptos-node/internal/storage/etcd"
	"github.com/CryptOS-PKI/cryptos-node/internal/testadmin"
)

// Providers satisfy the gRPC dependency interfaces.
var (
	_ cgrpc.Identity       = (*IdentityProvider)(nil)
	_ cgrpc.StatusProvider = (*StatusProvider)(nil)
	_ cgrpc.ConfigStore    = (*ConfigStore)(nil)
)

// newTestStore spins up an embedded etcd in a temp dir and returns a
// Store plus a context.
func newTestStore(t *testing.T) (*Store, context.Context) {
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
	s, err := New(cli)
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return s, ctx
}

func testAdmin(t *testing.T) (bootstrap.Admin, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "admin"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	a, err := bootstrap.AdminFromCertDER(der)
	if err != nil {
		t.Fatalf("AdminFromCertDER: %v", err)
	}
	return a, der
}

func sampleCommit(t *testing.T) FirstCeremonyCommit {
	t.Helper()
	admin, _ := testAdmin(t)
	return FirstCeremonyCommit{
		RootCertDER:   []byte("root-cert-der"),
		RootKeyBlob:   []byte("priv-blob"),
		RootKeyPublic: []byte("pub-blob"),
		ManifestID:    "ceremony-0001",
		ManifestBytes: []byte("signed-manifest"),
		Admin:         admin,
	}
}

func TestPhaseRoundTrip(t *testing.T) {
	s, ctx := newTestStore(t)

	got, err := s.Phase(ctx)
	if err != nil {
		t.Fatalf("Phase: %v", err)
	}
	if got != PhaseNoIdentity {
		t.Errorf("default Phase = %q, want %q", got, PhaseNoIdentity)
	}

	for _, p := range []Phase{PhaseFormatting, PhaseUnsealed, PhaseCeremonyInProgress, PhaseIdentityEstablished} {
		if err := s.SetPhase(ctx, p); err != nil {
			t.Fatalf("SetPhase(%q): %v", p, err)
		}
		got, err := s.Phase(ctx)
		if err != nil {
			t.Fatalf("Phase: %v", err)
		}
		if got != p {
			t.Errorf("Phase = %q, want %q", got, p)
		}
	}
}

func TestPhaseIdentityStateMapping(t *testing.T) {
	tests := map[Phase]nodev1.IdentityState{
		PhaseIdentityEstablished: nodev1.IdentityState_IDENTITY_STATE_ESTABLISHED,
		PhaseCeremonyInProgress:  nodev1.IdentityState_IDENTITY_STATE_CEREMONY_IN_PROGRESS,
		PhaseNoIdentity:          nodev1.IdentityState_IDENTITY_STATE_NONE,
		PhaseUnsealed:            nodev1.IdentityState_IDENTITY_STATE_NONE,
		PhaseFormatting:          nodev1.IdentityState_IDENTITY_STATE_NONE,
		Phase("garbage"):         nodev1.IdentityState_IDENTITY_STATE_NONE,
	}
	for p, want := range tests {
		if got := p.IdentityState(); got != want {
			t.Errorf("Phase(%q).IdentityState() = %v, want %v", p, got, want)
		}
	}
}

func TestBootCount(t *testing.T) {
	s, ctx := newTestStore(t)
	got, err := s.BootCount(ctx)
	if err != nil {
		t.Fatalf("BootCount: %v", err)
	}
	if got != 0 {
		t.Errorf("initial BootCount = %d, want 0", got)
	}
	for want := uint64(1); want <= 3; want++ {
		n, err := s.IncrementBootCount(ctx)
		if err != nil {
			t.Fatalf("IncrementBootCount: %v", err)
		}
		if n != want {
			t.Errorf("IncrementBootCount = %d, want %d", n, want)
		}
	}
	if got, _ := s.BootCount(ctx); got != 3 {
		t.Errorf("BootCount = %d, want 3", got)
	}
}

func TestIdentityLifecycle(t *testing.T) {
	s, ctx := newTestStore(t)

	if _, err := s.Identity(ctx); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("Identity before commit = %v, want ErrNoIdentity", err)
	}
	if ok, _ := s.HasIdentity(ctx); ok {
		t.Error("HasIdentity = true before commit")
	}

	c := sampleCommit(t)
	if err := s.CommitFirstCeremony(ctx, c); err != nil {
		t.Fatalf("CommitFirstCeremony: %v", err)
	}

	if ok, _ := s.HasIdentity(ctx); !ok {
		t.Error("HasIdentity = false after commit")
	}
	id, err := s.Identity(ctx)
	if err != nil {
		t.Fatalf("Identity after commit: %v", err)
	}
	if len(id.ChainDer) != 1 || string(id.ChainDer[0]) != "root-cert-der" {
		t.Errorf("Identity.ChainDer = %v, want single root-cert-der", id.ChainDer)
	}
	wantLeaf := sha256.Sum256([]byte("root-cert-der"))
	if string(id.LeafSha256) != string(wantLeaf[:]) {
		t.Error("Identity.LeafSha256 mismatch")
	}

	phase, _ := s.Phase(ctx)
	if phase != PhaseIdentityEstablished {
		t.Errorf("phase after commit = %q, want %q", phase, PhaseIdentityEstablished)
	}

	priv, pub, ok, err := s.RootKeyBlobs(ctx)
	if err != nil || !ok {
		t.Fatalf("RootKeyBlobs ok=%v err=%v", ok, err)
	}
	if string(priv) != "priv-blob" || string(pub) != "pub-blob" {
		t.Errorf("RootKeyBlobs = (%q,%q), want (priv-blob,pub-blob)", priv, pub)
	}
}

func TestCommitFirstCeremonyIsIdempotent(t *testing.T) {
	s, ctx := newTestStore(t)
	c := sampleCommit(t)
	if err := s.CommitFirstCeremony(ctx, c); err != nil {
		t.Fatalf("first commit: %v", err)
	}
	// A second commit (e.g. a re-run after a crash) must not overwrite.
	c2 := sampleCommit(t)
	c2.RootCertDER = []byte("DIFFERENT-root")
	if err := s.CommitFirstCeremony(ctx, c2); !errors.Is(err, ErrIdentityExists) {
		t.Fatalf("second commit = %v, want ErrIdentityExists", err)
	}
	id, _ := s.Identity(ctx)
	if string(id.ChainDer[0]) != "root-cert-der" {
		t.Error("second commit overwrote the Root cert")
	}
}

func TestCommitFirstCeremonyValidation(t *testing.T) {
	s, ctx := newTestStore(t)
	bad := sampleCommit(t)
	bad.RootKeyBlob = nil
	if err := s.CommitFirstCeremony(ctx, bad); err == nil {
		t.Fatal("CommitFirstCeremony with empty RootKeyBlob = nil, want error")
	}
}

func TestProviders(t *testing.T) {
	s, ctx := newTestStore(t)

	// IdentityProvider before + after commit.
	ip := NewIdentityProvider(s)
	if _, err := ip.Get(ctx); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("IdentityProvider.Get before commit = %v, want ErrNoIdentity", err)
	}
	if err := s.CommitFirstCeremony(ctx, sampleCommit(t)); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if _, err := ip.Get(ctx); err != nil {
		t.Errorf("IdentityProvider.Get after commit = %v, want nil", err)
	}

	// StatusProvider reflects role, phase, version, and health probes.
	tpmCalled := false
	sp, err := NewStatusProvider(StatusConfig{
		Store:           s,
		Role:            nodev1.NodeRole_NODE_ROLE_ROOT,
		SoftwareVersion: "test-1.2.3",
		TPMState: func() nodev1.TpmState {
			tpmCalled = true
			return nodev1.TpmState_TPM_STATE_OK
		},
	})
	if err != nil {
		t.Fatalf("NewStatusProvider: %v", err)
	}
	st, err := sp.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Role != nodev1.NodeRole_NODE_ROLE_ROOT {
		t.Errorf("Status.Role = %v", st.Role)
	}
	if st.IdentityState != nodev1.IdentityState_IDENTITY_STATE_ESTABLISHED {
		t.Errorf("Status.IdentityState = %v, want ESTABLISHED", st.IdentityState)
	}
	if st.SoftwareVersion != "test-1.2.3" {
		t.Errorf("Status.SoftwareVersion = %q", st.SoftwareVersion)
	}
	if st.EtcdState != nodev1.EtcdState_ETCD_STATE_OK {
		t.Errorf("Status.EtcdState = %v, want OK default", st.EtcdState)
	}
	if !tpmCalled {
		t.Error("TPMState probe was not called")
	}

	// ConfigStore.Apply rejects a nil config.
	cs := NewConfigStore(config.NewFileStore(t.TempDir()))
	if _, err := cs.Apply(ctx, nil); err == nil {
		t.Error("Apply(nil) = nil error, want error")
	}

	// Apply happy path: first Apply sets generation=1, RequiresReboot=true,
	// and returns a SHA-256 digest. A second Apply bumps generation to 2.
	validYAML := []byte(`apiVersion: cryptos.dev/v1alpha1
kind: MachineConfig
metadata: {name: apply-test}
role: {kind: root}
network: {interface: eth0, address: 10.0.0.10/24, gateway: 10.0.0.1}
bootstrap: {admin_cert_pem: "` + testadmin.YAMLPEM + `"}
pki:
  root_key_alg: ECDSA-P384
  root_subject: {common_name: "Apply Test Root", organization: "Test", country: "US"}
  root_validity_years: 10
  path_len_constraint: 0
`)
	parsed, err := config.Parse(validYAML)
	if err != nil {
		t.Fatalf("config.Parse: %v", err)
	}
	cs2 := NewConfigStore(config.NewFileStore(t.TempDir()))
	resp, err := cs2.Apply(ctx, parsed.ToProto())
	if err != nil {
		t.Fatalf("Apply (first): %v", err)
	}
	if resp.Generation != 1 {
		t.Errorf("first Apply generation = %d, want 1", resp.Generation)
	}
	if !resp.RequiresReboot {
		t.Error("Apply should set RequiresReboot=true")
	}
	if len(resp.ConfigDigest) != sha256.Size {
		t.Errorf("ConfigDigest len = %d, want %d", len(resp.ConfigDigest), sha256.Size)
	}
	resp2, err := cs2.Apply(ctx, parsed.ToProto())
	if err != nil {
		t.Fatalf("Apply (second): %v", err)
	}
	if resp2.Generation != 2 {
		t.Errorf("second Apply generation = %d, want 2", resp2.Generation)
	}

	// Current round-trips what Apply just persisted, so SetManagement's
	// read-modify-write has a real config to merge into.
	got, err := cs2.Current(ctx)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if !proto.Equal(got, parsed.ToProto()) {
		t.Errorf("Current = %v, want %v", got, parsed.ToProto())
	}

	// Current before any Apply/Write has nothing to read yet.
	cs3 := NewConfigStore(config.NewFileStore(t.TempDir()))
	if _, err := cs3.Current(ctx); err == nil {
		t.Error("Current with no persisted config = nil error, want error")
	}
}

func TestNewNilClient(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("New(nil) = nil error, want error")
	}
}

// TestConfigStoreApply_PreservesProtocols is the regression guard for #205.
//
// Apply used to write a config built solely from the proto, which then had no
// acme or est field, so it silently disabled both protocols -- and the Fleet
// Manager applies config this way whenever it changes a profile. The blocks
// now travel in the proto, with their secrets redacted on the way out, and a
// read-apply round trip must still leave both protocols as they were.
func TestConfigStoreApply_PreservesProtocols(t *testing.T) {
	ctx := context.Background()
	withProtocols := []byte(`apiVersion: cryptos.dev/v1alpha1
kind: MachineConfig
metadata: {name: protocols-test}
role: {kind: issuing}
network: {interface: eth0, address: 10.0.0.10/24, gateway: 10.0.0.1}
bootstrap: {admin_cert_pem: "` + testadmin.YAMLPEM + `"}
pki:
  root_key_alg: ECDSA-P384
  root_subject: {common_name: "Protocols Test Issuing CA", organization: "Test", country: "US"}
  path_len_constraint: 0
  parent: {ca_cert_sha256: "abababababababababababababababababababababababababababababababab"}
  profiles:
    - name: leaf-server
      key_alg: ECDSA-P384
      validity_days: 90
      key_usage: [digital_signature]
      ext_key_usage: [server_auth]
  acme:
    base_url: https://ca.example.org/acme
    profile: leaf-server
    allow_anonymous_accounts: true
  est:
    hostnames: [est.example.org]
    profile: leaf-server
    allow_any_identifier: true
`)
	parsed, err := config.Parse(withProtocols)
	if err != nil {
		t.Fatalf("config.Parse: %v", err)
	}
	if parsed.PKI.ACME == nil || parsed.PKI.EST == nil {
		t.Fatal("fixture does not configure both protocols")
	}

	// Seed the file directly, the way a ceremony or an operator does.
	fs := config.NewFileStore(t.TempDir())
	if _, err := fs.Write(withProtocols); err != nil {
		t.Fatalf("FileStore.Write (seed): %v", err)
	}
	cs := NewConfigStore(fs)

	// What the Fleet Manager does: read the config over the wire and apply it
	// back.
	current, err := cs.Current(ctx)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if len(current.GetPki().GetProfiles()) == 0 {
		t.Fatal("the round-tripped proto lost the profiles too")
	}
	if _, err := cs.Apply(ctx, current); err != nil {
		t.Fatalf("Apply (round trip): %v", err)
	}

	// Assert against what was actually persisted.
	raw, _, ok, err := fs.Read()
	if err != nil || !ok {
		t.Fatalf("FileStore.Read after apply: ok=%v err=%v", ok, err)
	}
	after, err := config.Parse(raw)
	if err != nil {
		t.Fatalf("parse persisted config: %v", err)
	}

	if after.PKI.ACME == nil {
		t.Error("ACME was deleted by an apply that never mentioned it")
	} else if after.PKI.ACME.BaseURL != "https://ca.example.org/acme" {
		t.Errorf("ACME.BaseURL = %q, want it preserved", after.PKI.ACME.BaseURL)
	}
	if after.PKI.EST == nil {
		t.Error("EST was deleted by an apply that never mentioned it")
	} else if len(after.PKI.EST.Hostnames) != 1 || after.PKI.EST.Hostnames[0] != "est.example.org" {
		t.Errorf("EST.Hostnames = %v, want it preserved", after.PKI.EST.Hostnames)
	}
}

// The revocation preflight and resolver facts are read per GetStatus, so a
// preflight that starts passing after boot shows up without a reboot. With no
// probe wired (maintenance, or a test) the fields stay unset.
func TestStatusProviderReportsPreflightAndResolver(t *testing.T) {
	s, ctx := newTestStore(t)
	pf := &nodev1.RevocationPreflight{State: nodev1.RevocationPreflightState_REVOCATION_PREFLIGHT_STATE_FAILING, LastError: "no such host"}
	rs := &nodev1.ResolverStatus{Source: nodev1.ResolverSource_RESOLVER_SOURCE_DHCP_LEASE, Nameservers: []string{"192.0.2.53"}}
	sp, err := NewStatusProvider(StatusConfig{
		Store:               s,
		Role:                nodev1.NodeRole_NODE_ROLE_INTERMEDIATE,
		RevocationPreflight: func() *nodev1.RevocationPreflight { return pf },
		Resolver:            func() *nodev1.ResolverStatus { return rs },
	})
	if err != nil {
		t.Fatalf("NewStatusProvider: %v", err)
	}
	st, err := sp.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.GetRevocationPreflight() != pf {
		t.Errorf("revocation_preflight = %v, want %v", st.GetRevocationPreflight(), pf)
	}
	if st.GetResolver() != rs {
		t.Errorf("resolver = %v, want %v", st.GetResolver(), rs)
	}

	pf = &nodev1.RevocationPreflight{State: nodev1.RevocationPreflightState_REVOCATION_PREFLIGHT_STATE_OK}
	if st, _ := sp.Status(ctx); st.GetRevocationPreflight().GetState() != nodev1.RevocationPreflightState_REVOCATION_PREFLIGHT_STATE_OK {
		t.Errorf("a later check was not reflected: %v", st.GetRevocationPreflight())
	}

	bare, err := NewStatusProvider(StatusConfig{Store: s, Role: nodev1.NodeRole_NODE_ROLE_ROOT})
	if err != nil {
		t.Fatalf("NewStatusProvider: %v", err)
	}
	if st, _ := bare.Status(ctx); st.GetRevocationPreflight() != nil || st.GetResolver() != nil {
		t.Errorf("unwired probes must leave the fields unset: %v", st)
	}
}

func TestConfigStoreCurrentWithNoConfigIsErrNoConfig(t *testing.T) {
	cs := NewConfigStore(config.NewFileStore(t.TempDir()))
	if _, err := cs.Current(context.Background()); !errors.Is(err, ErrNoConfig) {
		t.Fatalf("Current with no persisted config = %v, want ErrNoConfig", err)
	}
}

// The time-sync state is read per GetStatus, so the first good sync after boot
// shows up without a reboot. Unwired, the field stays unset.
func TestStatusProviderReportsTimeSync(t *testing.T) {
	s, ctx := newTestStore(t)
	ts := &nodev1.TimeSyncStatus{State: nodev1.TimeSyncState_TIME_SYNC_STATE_PENDING}
	sp, err := NewStatusProvider(StatusConfig{
		Store:    s,
		Role:     nodev1.NodeRole_NODE_ROLE_ISSUING,
		TimeSync: func() *nodev1.TimeSyncStatus { return ts },
	})
	if err != nil {
		t.Fatalf("NewStatusProvider: %v", err)
	}
	if st, _ := sp.Status(ctx); st.GetTimeSync() != ts {
		t.Fatalf("time_sync = %v, want %v", st.GetTimeSync(), ts)
	}
	ts = &nodev1.TimeSyncStatus{State: nodev1.TimeSyncState_TIME_SYNC_STATE_SYNCED}
	if st, _ := sp.Status(ctx); st.GetTimeSync().GetState() != nodev1.TimeSyncState_TIME_SYNC_STATE_SYNCED {
		t.Fatalf("a later sync was not reflected: %v", st.GetTimeSync())
	}
	bare, err := NewStatusProvider(StatusConfig{Store: s, Role: nodev1.NodeRole_NODE_ROLE_ROOT})
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := bare.Status(ctx); st.GetTimeSync() != nil {
		t.Fatalf("unwired time sync must leave the field unset: %v", st.GetTimeSync())
	}
}
