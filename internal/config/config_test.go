package config

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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"github.com/CryptOS-PKI/cryptos-node/internal/tpm"
)

// validYAML returns a minimal valid Phase 1 MachineConfig as YAML.
// admin_cert_pem is filled in with a freshly-generated self-signed cert
// so the parser's PEM validation has something real to chew on.
func validYAML(t *testing.T) []byte {
	t.Helper()
	pemCert := selfSignedCertPEM(t)
	var b bytes.Buffer
	b.WriteString(`apiVersion: cryptos.dev/v1alpha1
kind: MachineConfig
metadata:
  name: ca-east-1
role:
  kind: root
network:
  interface: eth0
  address: 10.0.0.10/24
  gateway: 10.0.0.1
bootstrap:
  admin_cert_pem: |
`)
	for _, line := range strings.Split(strings.TrimRight(pemCert, "\n"), "\n") {
		b.WriteString("    " + line + "\n")
	}
	b.WriteString(`pki:
  root_key_alg: ECDSA-P384
  root_subject:
    common_name: "CryptOS Root CA — Acme Corp"
    organization: "Acme Corp"
    country: "US"
  root_validity_years: 20
  path_len_constraint: 2
`)
	return b.Bytes()
}

// selfSignedCertPEM produces a throwaway PEM-encoded X.509 cert for
// tests that exercise the admin_cert_pem validation path.
func selfSignedCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-admin"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestParse_HappyPath(t *testing.T) {
	cfg, err := Parse(validYAML(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Role.Kind != RoleRoot {
		t.Fatalf("Role.Kind = %q, want %q", cfg.Role.Kind, RoleRoot)
	}
	if cfg.PKI.RootValidityYears != 20 {
		t.Fatalf("RootValidityYears = %d, want 20", cfg.PKI.RootValidityYears)
	}
}

func TestNodeRoleMapping(t *testing.T) {
	cases := map[RoleKind]nodev1.NodeRole{
		RoleRoot:         nodev1.NodeRole_NODE_ROLE_ROOT,
		RoleIntermediate: nodev1.NodeRole_NODE_ROLE_INTERMEDIATE,
		RoleIssuing:      nodev1.NodeRole_NODE_ROLE_ISSUING,
	}
	for kind, want := range cases {
		c := &Config{Role: Role{Kind: kind}}
		if got := c.NodeRole(); got != want {
			t.Fatalf("NodeRole(%q) = %v, want %v", kind, got, want)
		}
	}
}

func TestValidateAcceptsPhase2Roles(t *testing.T) {
	// A minimal otherwise-valid config (built the way validYAML does) with
	// each role must pass role validation; only role.kind changes here.
	for _, kind := range []RoleKind{RoleRoot, RoleIntermediate, RoleIssuing} {
		cfg, err := Parse(validYAML(t))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		cfg.Role.Kind = kind
		if kind == RoleIntermediate || kind == RoleIssuing {
			// A subordinate must pin a parent trust anchor to validate.
			cfg.PKI.Parent = &Parent{CACertSHA256: strings.Repeat("a", 64)}
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("role %q should validate, got %v", kind, err)
		}
	}
	cfg, err := Parse(validYAML(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg.Role.Kind = "bogus"
	if err := cfg.Validate(); err == nil {
		t.Fatal("role 'bogus' must be rejected")
	}
}

func TestRevocationConfigSurvivesProtoRoundTrip(t *testing.T) {
	// The maintenance installer stages an installed node's config by going
	// through the proto (FromProto then re-marshal), so revocation config must
	// survive ToProto -> FromProto or it never reaches an installed node.
	cfg, err := Parse(validYAML(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg.PKI.RevocationBaseURL = "http://pki.acme.example"
	cfg.PKI.AllowUnverifiedRevocationURL = true
	cfg.PKI.CRLNextUpdateHours = 72
	cfg.PKI.RevocationHTTPPort = 8080
	cfg.PKI.RootLeafIssuance = RootLeafIssuanceAcknowledged

	got, err := FromProto(cfg.ToProto())
	if err != nil {
		t.Fatalf("FromProto: %v", err)
	}
	if got.PKI.RootLeafIssuance != RootLeafIssuanceAcknowledged {
		t.Errorf("RootLeafIssuance = %q, want it preserved (the ROOT leaf-issuance ack must reach installed nodes)", got.PKI.RootLeafIssuance)
	}
	if got.PKI.RevocationBaseURL != "http://pki.acme.example" {
		t.Errorf("RevocationBaseURL = %q, want it preserved", got.PKI.RevocationBaseURL)
	}
	if !got.PKI.AllowUnverifiedRevocationURL {
		t.Error("AllowUnverifiedRevocationURL dropped in proto round-trip")
	}
	if got.PKI.CRLNextUpdateHours != 72 {
		t.Errorf("CRLNextUpdateHours = %d, want 72", got.PKI.CRLNextUpdateHours)
	}
	if got.PKI.RevocationHTTPPort != 8080 {
		t.Errorf("RevocationHTTPPort = %d, want 8080", got.PKI.RevocationHTTPPort)
	}
}

func TestValidateStateKey(t *testing.T) {
	base := func(t *testing.T) *Config {
		t.Helper()
		cfg, err := Parse(validYAML(t))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		return cfg
	}

	// An unknown mode is rejected.
	cfg := base(t)
	cfg.StateKey.Mode = "bogus"
	if err := cfg.Validate(); err == nil {
		t.Error("state_key.mode 'bogus' must be rejected")
	}

	// mode kms without a kms section is rejected.
	cfg = base(t)
	cfg.StateKey.Mode = StateKeyModeKMS
	if err := cfg.Validate(); err == nil {
		t.Error("state_key.mode kms without a kms section must be rejected")
	}

	// mode kms with a kms section but no endpoint is rejected.
	cfg = base(t)
	cfg.StateKey.Mode = StateKeyModeKMS
	cfg.StateKey.KMS = &KmsStateKey{}
	if err := cfg.Validate(); err == nil {
		t.Error("state_key.kms with an empty endpoint must be rejected")
	}

	// mode kms with a malformed endpoint is rejected.
	cfg = base(t)
	cfg.StateKey.Mode = StateKeyModeKMS
	cfg.StateKey.KMS = &KmsStateKey{Endpoint: "not-a-url"}
	if err := cfg.Validate(); err == nil {
		t.Error("state_key.kms.endpoint that is not an http(s) URL must be rejected")
	}

	// A well-formed kms config passes.
	cfg = base(t)
	cfg.StateKey.Mode = StateKeyModeKMS
	cfg.StateKey.KMS = &KmsStateKey{Endpoint: "https://kms.acme.example:8443"}
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid kms state_key config should validate, got %v", err)
	}

	// The empty mode (build-time default) passes.
	cfg = base(t)
	cfg.StateKey.Mode = ""
	if err := cfg.Validate(); err != nil {
		t.Errorf("empty state_key.mode should validate, got %v", err)
	}

	// The tpm and nodeid modes pass without a kms section.
	for _, mode := range []string{StateKeyModeTPM, StateKeyModeNodeID} {
		cfg = base(t)
		cfg.StateKey.Mode = mode
		if err := cfg.Validate(); err != nil {
			t.Errorf("state_key.mode %q should validate, got %v", mode, err)
		}
	}
}

func TestStateKeyConfigSurvivesProtoRoundTrip(t *testing.T) {
	// The maintenance installer stages an installed node's config through the
	// proto (FromProto then re-marshal), so the state-key choice must survive
	// ToProto -> FromProto or it never reaches an installed node.
	cfg, err := Parse(validYAML(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg.StateKey.Mode = StateKeyModeKMS
	cfg.StateKey.KMS = &KmsStateKey{
		Endpoint: "https://kms.acme.example:8443",
		TrustPEM: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
	}

	got, err := FromProto(cfg.ToProto())
	if err != nil {
		t.Fatalf("FromProto: %v", err)
	}
	if got.StateKey.Mode != StateKeyModeKMS {
		t.Errorf("StateKey.Mode = %q, want %q", got.StateKey.Mode, StateKeyModeKMS)
	}
	if got.StateKey.KMS == nil {
		t.Fatal("StateKey.KMS dropped in proto round-trip")
	}
	if got.StateKey.KMS.Endpoint != cfg.StateKey.KMS.Endpoint {
		t.Errorf("StateKey.KMS.Endpoint = %q, want %q", got.StateKey.KMS.Endpoint, cfg.StateKey.KMS.Endpoint)
	}
	if got.StateKey.KMS.TrustPEM != cfg.StateKey.KMS.TrustPEM {
		t.Errorf("StateKey.KMS.TrustPEM = %q, want %q", got.StateKey.KMS.TrustPEM, cfg.StateKey.KMS.TrustPEM)
	}
}

func TestManagement_ProtoRoundTrip(t *testing.T) {
	// A LINK enrollment sets Management via ApplyConfig, which stages the
	// node's config through the proto (FromProto then re-marshal), so the
	// managed state must survive ToProto -> FromProto or it never reaches an
	// installed node.
	cfg, err := Parse(validYAML(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg.Management = &Management{
		ManagerCN:               "operator@acme.example",
		TrustPEM:                "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n",
		OperatorSurfaceReadonly: true,
	}

	got, err := FromProto(cfg.ToProto())
	if err != nil {
		t.Fatalf("FromProto: %v", err)
	}
	if got.Management == nil {
		t.Fatal("Management dropped in proto round-trip")
	}
	if got.Management.ManagerCN != cfg.Management.ManagerCN {
		t.Errorf("Management.ManagerCN = %q, want %q", got.Management.ManagerCN, cfg.Management.ManagerCN)
	}
	if got.Management.TrustPEM != cfg.Management.TrustPEM {
		t.Errorf("Management.TrustPEM = %q, want %q", got.Management.TrustPEM, cfg.Management.TrustPEM)
	}
	if !got.Management.OperatorSurfaceReadonly {
		t.Errorf("Management.OperatorSurfaceReadonly = %v, want true", got.Management.OperatorSurfaceReadonly)
	}
}

func TestManagement_NilRoundTripsClean(t *testing.T) {
	cfg, err := Parse(validYAML(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got, err := FromProto(cfg.ToProto())
	if err != nil {
		t.Fatalf("FromProto: %v", err)
	}
	if got.Management != nil {
		t.Fatalf("nil Management became %+v", got.Management)
	}
}

func TestValidate_Management(t *testing.T) {
	cfg, err := Parse(validYAML(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg.Management = &Management{}
	if err := cfg.Validate(); err == nil {
		t.Fatal("management with an empty manager_cn must be rejected")
	}

	// The Fleet Manager names itself and sends no trust_pem, so manager_cn alone
	// is a valid link (#418). trust_pem is not used to authenticate anything.
	cfg.Management = &Management{ManagerCN: "operator@acme.example", OperatorSurfaceReadonly: true}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("management with only a manager_cn must be accepted: %v", err)
	}

	// A node that already carries a trust_pem still loads.
	cfg.Management = &Management{
		ManagerCN: "operator@acme.example",
		TrustPEM:  "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("management with a trust_pem must be accepted: %v", err)
	}
}

func TestValidate_RootValidityYearsRoleScoped(t *testing.T) {
	// A subordinate does not self-sign a root, so root_validity_years is
	// unused and omitting it (0) must still validate.
	for _, kind := range []RoleKind{RoleIntermediate, RoleIssuing} {
		cfg, err := Parse(validYAML(t))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		cfg.Role.Kind = kind
		cfg.PKI.RootValidityYears = 0
		cfg.PKI.Parent = &Parent{CACertSHA256: strings.Repeat("a", 64)}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("subordinate role %q with root_validity_years=0 should validate, got %v", kind, err)
		}
	}

	// A root still requires it in [1, 30].
	cfg, err := Parse(validYAML(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg.Role.Kind = RoleRoot
	cfg.PKI.RootValidityYears = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("root with root_validity_years=0 must be rejected")
	}
}

func TestParse_ToProto_RoundTrip(t *testing.T) {
	cfg, err := Parse(validYAML(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	proto := cfg.ToProto()
	if proto.GetApiVersion() != APIVersion {
		t.Fatalf("proto.ApiVersion = %q, want %q", proto.GetApiVersion(), APIVersion)
	}
	if proto.GetPki().GetRootValidityYears() != 20 {
		t.Fatalf("proto.Pki.RootValidityYears = %d, want 20", proto.GetPki().GetRootValidityYears())
	}
	if proto.GetBootstrap().GetAdminCertPem() == "" {
		t.Fatalf("proto.Bootstrap.AdminCertPem should be populated")
	}
}

func TestParse_Digest_StableAcrossWhitespace(t *testing.T) {
	cfg1, err := Parse(validYAML(t))
	if err != nil {
		t.Fatalf("Parse 1: %v", err)
	}
	d1, err := cfg1.Digest()
	if err != nil {
		t.Fatalf("Digest 1: %v", err)
	}

	// Build a second config from the same Go values but stress digest
	// stability by recomputing it directly.
	d2, err := cfg1.Digest()
	if err != nil {
		t.Fatalf("Digest 2: %v", err)
	}
	if hex.EncodeToString(d1) != hex.EncodeToString(d2) {
		t.Fatalf("digest not stable: %x vs %x", d1, d2)
	}
}

// rejectionTest exercises one validation rule by mutating valid YAML.
type rejectionTest struct {
	name    string
	mutate  func(string) string
	wantSub string
}

func TestParse_Rejections(t *testing.T) {
	base := string(validYAML(t))
	cases := []rejectionTest{
		{
			name:    "wrong apiVersion",
			mutate:  func(s string) string { return strings.Replace(s, APIVersion, "cryptos.dev/v0", 1) },
			wantSub: "apiVersion",
		},
		{
			name:    "wrong kind",
			mutate:  func(s string) string { return strings.Replace(s, "kind: MachineConfig", "kind: NotMachineConfig", 1) },
			wantSub: "kind",
		},
		{
			name:    "unknown role",
			mutate:  func(s string) string { return strings.Replace(s, "kind: root", "kind: bogus", 1) },
			wantSub: "role.kind",
		},
		{
			name:    "missing interface",
			mutate:  func(s string) string { return strings.Replace(s, "interface: eth0", `interface: ""`, 1) },
			wantSub: "network.interface",
		},
		{
			name:    "address not CIDR",
			mutate:  func(s string) string { return strings.Replace(s, "10.0.0.10/24", "10.0.0.10", 1) },
			wantSub: "network.address",
		},
		{
			name:    "gateway not IP",
			mutate:  func(s string) string { return strings.Replace(s, "gateway: 10.0.0.1", "gateway: not-an-ip", 1) },
			wantSub: "network.gateway",
		},
		{
			name: "wrong root_key_alg",
			mutate: func(s string) string {
				return strings.Replace(s, "root_key_alg: ECDSA-P384", "root_key_alg: ECDSA-P256", 1)
			},
			wantSub: "root_key_alg",
		},
		{
			name: "root validity 0",
			mutate: func(s string) string {
				return strings.Replace(s, "root_validity_years: 20", "root_validity_years: 0", 1)
			},
			wantSub: "root_validity_years",
		},
		{
			name: "root validity too high",
			mutate: func(s string) string {
				return strings.Replace(s, "root_validity_years: 20", "root_validity_years: 100", 1)
			},
			wantSub: "root_validity_years",
		},
		{
			name: "path length too high",
			mutate: func(s string) string {
				return strings.Replace(s, "path_len_constraint: 2", "path_len_constraint: 99", 1)
			},
			wantSub: "path_len_constraint",
		},
		{
			name: "empty CN",
			mutate: func(s string) string {
				return strings.Replace(s, `common_name: "CryptOS Root CA — Acme Corp"`, `common_name: ""`, 1)
			},
			wantSub: "common_name",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.mutate(base)))
			if err == nil {
				t.Fatalf("Parse should have failed")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not mention %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestParse_BootstrapExactlyOne(t *testing.T) {
	base := string(validYAML(t))

	// Both set → error.
	withBoth := strings.Replace(
		base,
		"bootstrap:\n  admin_cert_pem: |\n",
		"bootstrap:\n  admin_cert_sha256: \""+strings.Repeat("a", 64)+"\"\n  admin_cert_pem: |\n",
		1,
	)
	if _, err := Parse([]byte(withBoth)); err == nil {
		t.Fatalf("Parse should fail when both bootstrap fields are set")
	}

	// Neither set → error.
	idxStart := strings.Index(base, "bootstrap:")
	idxEnd := strings.Index(base, "pki:")
	withNeither := base[:idxStart] + "bootstrap:\n" + base[idxEnd:]
	if _, err := Parse([]byte(withNeither)); err == nil {
		t.Fatalf("Parse should fail when neither bootstrap field is set")
	}
}

func TestParse_AdminCertSHA256(t *testing.T) {
	base := string(validYAML(t))
	// Replace the entire bootstrap section with the sha256 path.
	idxStart := strings.Index(base, "bootstrap:")
	idxEnd := strings.Index(base, "pki:")
	withSHA := base[:idxStart] +
		"bootstrap:\n  admin_cert_sha256: \"" + strings.Repeat("a", 64) + "\"\n" +
		base[idxEnd:]
	if _, err := Parse([]byte(withSHA)); err != nil {
		t.Fatalf("Parse with sha256 bootstrap: %v", err)
	}
}

func TestParse_AdminCertSHA256_BadLength(t *testing.T) {
	base := string(validYAML(t))
	idxStart := strings.Index(base, "bootstrap:")
	idxEnd := strings.Index(base, "pki:")
	withBad := base[:idxStart] +
		"bootstrap:\n  admin_cert_sha256: \"deadbeef\"\n" +
		base[idxEnd:]
	if _, err := Parse([]byte(withBad)); err == nil {
		t.Fatalf("Parse should reject 8-char sha256")
	}
}

func TestParse_EmptyInput(t *testing.T) {
	if _, err := Parse(nil); err == nil {
		t.Fatalf("Parse(nil) should fail")
	}
	if _, err := Parse([]byte{}); err == nil {
		t.Fatalf("Parse([]) should fail")
	}
}

func TestFromProtoRoundTrip(t *testing.T) {
	orig, err := Parse(validYAML(t))
	if err != nil {
		t.Fatal(err)
	}
	pb := orig.ToProto()
	back, err := FromProto(pb)
	if err != nil {
		t.Fatalf("FromProto: %v", err)
	}
	y, err := back.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	reparsed, err := Parse(y)
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	if reparsed.Metadata.Name != orig.Metadata.Name ||
		reparsed.Network.Address != orig.Network.Address ||
		reparsed.PKI.RootKeyAlg != orig.PKI.RootKeyAlg {
		t.Error("round-trip changed a field")
	}
}

func ptrU32(v uint32) *uint32 { return &v }

// sampleProfiles returns a CA profile and a leaf profile exercising every
// mapped field (basic constraints, SANs, extra extensions).
func sampleProfiles() []CertificateProfile {
	return []CertificateProfile{
		{
			Name:             "sub-ca",
			KeyAlg:           RootKeyECDSAP384,
			Subject:          Subject{CommonName: "CryptOS Issuing CA", Organization: "Acme Corp", Country: "US"},
			ValidityDays:     3650,
			BasicConstraints: BasicConstraints{IsCA: true, PathLen: ptrU32(0)},
			KeyUsage:         []string{"cert_sign", "crl_sign"},
		},
		{
			Name:             "leaf-server",
			KeyAlg:           RootKeyECDSAP384,
			Subject:          Subject{CommonName: "node.example"},
			ValidityDays:     90,
			BasicConstraints: BasicConstraints{IsCA: false},
			ExtKeyUsage:      []string{"server_auth"},
			SANs:             SubjectAltNames{DNS: []string{"node.example"}},
			ExtraExtensions:  []X509Extension{{OID: "1.3.6.1.5.5.7.1.1", Critical: false, Value: []byte{0x30, 0x00}}},
		},
	}
}

func TestProfileRoundTrip(t *testing.T) {
	cfg, err := Parse(validYAML(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg.PKI.Profiles = sampleProfiles()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate sample profiles: %v", err)
	}
	back, err := FromProto(cfg.ToProto())
	if err != nil {
		t.Fatalf("FromProto: %v", err)
	}
	if !reflect.DeepEqual(back.PKI.Profiles, cfg.PKI.Profiles) {
		t.Fatalf("profiles round-trip mismatch:\n got  %#v\n want %#v", back.PKI.Profiles, cfg.PKI.Profiles)
	}
}

func TestProfileByName(t *testing.T) {
	cfg := &Config{PKI: PKI{Profiles: sampleProfiles()}}

	got := cfg.ProfileByName("leaf-server")
	if got == nil {
		t.Fatal("ProfileByName(leaf-server): got nil, want the leaf-server profile")
	}
	if got.Name != "leaf-server" {
		t.Fatalf("ProfileByName(leaf-server): got %q", got.Name)
	}
	if got.BasicConstraints.IsCA {
		t.Fatal("ProfileByName(leaf-server): expected a non-CA profile")
	}

	subCA := cfg.ProfileByName("sub-ca")
	if subCA == nil || !subCA.BasicConstraints.IsCA {
		t.Fatalf("ProfileByName(sub-ca): got %#v, want the CA profile", subCA)
	}

	if got := cfg.ProfileByName("does-not-exist"); got != nil {
		t.Fatalf("ProfileByName(absent): got %#v, want nil", got)
	}

	if got := (*Config)(nil).ProfileByName("anything"); got != nil {
		t.Fatalf("ProfileByName on nil Config: got %#v, want nil", got)
	}
}

func TestValidateProfileRejections(t *testing.T) {
	cases := []struct {
		name     string
		profiles []CertificateProfile
		wantSub  string
	}{
		{
			name: "duplicate names",
			profiles: []CertificateProfile{
				{Name: "dup", KeyAlg: RootKeyECDSAP384, ValidityDays: 1},
				{Name: "dup", KeyAlg: RootKeyECDSAP384, ValidityDays: 1},
			},
			wantSub: "duplicate",
		},
		{
			name:     "empty name",
			profiles: []CertificateProfile{{Name: "", KeyAlg: RootKeyECDSAP384, ValidityDays: 1}},
			wantSub:  "name",
		},
		{
			name:     "validity zero",
			profiles: []CertificateProfile{{Name: "p", KeyAlg: RootKeyECDSAP384, ValidityDays: 0}},
			wantSub:  "validity_days",
		},
		{
			name:     "bogus key usage",
			profiles: []CertificateProfile{{Name: "p", KeyAlg: RootKeyECDSAP384, ValidityDays: 1, KeyUsage: []string{"bogus"}}},
			wantSub:  "key_usage",
		},
		{
			name:     "bad extension oid",
			profiles: []CertificateProfile{{Name: "p", KeyAlg: RootKeyECDSAP384, ValidityDays: 1, ExtraExtensions: []X509Extension{{OID: "nope"}}}},
			wantSub:  "oid",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse(validYAML(t))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			cfg.PKI.Profiles = tc.profiles
			err = cfg.Validate()
			if err == nil {
				t.Fatalf("expected validation failure")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not mention %q", err.Error(), tc.wantSub)
			}
		})
	}
}

// parentPEMYAML returns a valid subordinate (intermediate) config carrying a
// pki.parent with a PEM anchor. The parent PEM is a throwaway self-signed cert.
func parentPEMYAML(t *testing.T) []byte {
	t.Helper()
	base := string(validYAML(t))
	// Make it a subordinate role.
	base = strings.Replace(base, "kind: root", "kind: intermediate", 1)
	// Append a pki.parent block with a PEM anchor, indented under pki.
	parentPEM := selfSignedCertPEM(t)
	var b bytes.Buffer
	b.WriteString(base)
	b.WriteString("  parent:\n    ca_cert_pem: |\n")
	for _, line := range strings.Split(strings.TrimRight(parentPEM, "\n"), "\n") {
		b.WriteString("      " + line + "\n")
	}
	return b.Bytes()
}

func TestParse_ParentPEM_RoundTrip(t *testing.T) {
	cfg, err := Parse(parentPEMYAML(t))
	if err != nil {
		t.Fatalf("Parse subordinate with pki.parent: %v", err)
	}
	if cfg.PKI.Parent == nil {
		t.Fatal("PKI.Parent should be non-nil")
	}
	if cfg.PKI.Parent.CACertPEM == "" {
		t.Fatal("PKI.Parent.CACertPEM should be populated")
	}
	// proto round-trip preserves the parent.
	back, err := FromProto(cfg.ToProto())
	if err != nil {
		t.Fatalf("FromProto: %v", err)
	}
	if back.PKI.Parent == nil || back.PKI.Parent.CACertPEM != cfg.PKI.Parent.CACertPEM {
		t.Fatalf("parent round-trip mismatch: got %#v", back.PKI.Parent)
	}
	// ParentTrust builds a trust anchor from the PEM.
	trust, err := cfg.ParentTrust()
	if err != nil {
		t.Fatalf("ParentTrust: %v", err)
	}
	if trust == nil {
		t.Fatal("ParentTrust should be non-nil for a subordinate with a parent")
	}
	if !trust.HasCertificate() {
		t.Fatal("ParentTrust from PEM should carry the certificate")
	}
}

func TestParentTrust_RootIsNil(t *testing.T) {
	cfg, err := Parse(validYAML(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	trust, err := cfg.ParentTrust()
	if err != nil {
		t.Fatalf("ParentTrust on root: %v", err)
	}
	if trust != nil {
		t.Fatal("ParentTrust on a root (no parent) should be nil")
	}
}

func TestParentTrust_SHA256(t *testing.T) {
	base := string(validYAML(t))
	base = strings.Replace(base, "kind: root", "kind: issuing", 1)
	withParent := base + "  parent:\n    ca_cert_sha256: \"" + strings.Repeat("a", 64) + "\"\n"
	cfg, err := Parse([]byte(withParent))
	if err != nil {
		t.Fatalf("Parse subordinate with sha256 parent: %v", err)
	}
	trust, err := cfg.ParentTrust()
	if err != nil {
		t.Fatalf("ParentTrust: %v", err)
	}
	if trust == nil {
		t.Fatal("ParentTrust should be non-nil")
	}
	if trust.HasCertificate() {
		t.Fatal("ParentTrust from a fingerprint should not carry a certificate")
	}
}

func TestValidate_ParentRules(t *testing.T) {
	// Subordinate without a parent → error.
	sub := strings.Replace(string(validYAML(t)), "kind: root", "kind: intermediate", 1)
	if _, err := Parse([]byte(sub)); err == nil {
		t.Fatal("subordinate without pki.parent must be rejected")
	} else if !strings.Contains(err.Error(), "parent") {
		t.Fatalf("error %q should mention parent", err.Error())
	}

	// Root WITH a parent → error.
	rootWithParent := string(validYAML(t)) +
		"  parent:\n    ca_cert_sha256: \"" + strings.Repeat("a", 64) + "\"\n"
	if _, err := Parse([]byte(rootWithParent)); err == nil {
		t.Fatal("root with pki.parent must be rejected")
	} else if !strings.Contains(err.Error(), "parent") {
		t.Fatalf("error %q should mention parent", err.Error())
	}

	// Subordinate with BOTH PEM and SHA256 → error.
	subBoth := strings.Replace(string(validYAML(t)), "kind: root", "kind: issuing", 1)
	subBoth = subBoth + "  parent:\n    ca_cert_sha256: \"" + strings.Repeat("a", 64) + "\"\n    ca_cert_pem: |\n"
	for _, line := range strings.Split(strings.TrimRight(selfSignedCertPEM(t), "\n"), "\n") {
		subBoth += "      " + line + "\n"
	}
	if _, err := Parse([]byte(subBoth)); err == nil {
		t.Fatal("subordinate with both parent PEM and SHA256 must be rejected")
	} else if !strings.Contains(err.Error(), "parent") {
		t.Fatalf("error %q should mention parent", err.Error())
	}
}

func TestParse_InstallDisk(t *testing.T) {
	base := string(validYAML(t))
	withInstall := base + "install:\n  disk: /dev/vda\n"
	cfg, err := Parse([]byte(withInstall))
	if err != nil {
		t.Fatalf("Parse with install.disk: %v", err)
	}
	if cfg.Install.Disk != "/dev/vda" {
		t.Fatalf("Install.Disk = %q, want %q", cfg.Install.Disk, "/dev/vda")
	}
}

func TestInstallDisk_ProtoRoundTrip(t *testing.T) {
	base := string(validYAML(t))
	withInstall := base + "install:\n  disk: /dev/vda\n"
	orig, err := Parse([]byte(withInstall))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	pb := orig.ToProto()
	if pb.GetInstall().GetDisk() != "/dev/vda" {
		t.Fatalf("proto.Install.Disk = %q, want %q", pb.GetInstall().GetDisk(), "/dev/vda")
	}
	back, err := FromProto(pb)
	if err != nil {
		t.Fatalf("FromProto: %v", err)
	}
	if back.Install.Disk != "/dev/vda" {
		t.Fatalf("FromProto Install.Disk = %q, want %q", back.Install.Disk, "/dev/vda")
	}
}

func TestValidate_RevocationBaseURL(t *testing.T) {
	cfg, _ := Parse(validYAML(t))
	cfg.PKI.RevocationBaseURL = "://bad"
	if err := cfg.Validate(); err == nil {
		t.Fatal("malformed revocation_base_url must be rejected")
	}
	cfg2, _ := Parse(validYAML(t))
	cfg2.PKI.RevocationBaseURL = "http://pki.acme.example"
	if err := cfg2.Validate(); err != nil {
		t.Fatalf("valid revocation_base_url should pass: %v", err)
	}
}

// TestValidateAcceptsRSARootKeyAlgs covers the RSA CA key algorithms. A
// platform CA that accepts only RSA signatures can be subordinated only under
// an RSA-rooted chain, so RSA must be selectable for the node's own CA key.
func TestValidateAcceptsRSARootKeyAlgs(t *testing.T) {
	accepted := []RootKeyAlg{RootKeyECDSAP384, RootKeyRSA3072, RootKeyRSA4096}
	for _, alg := range accepted {
		t.Run("accepts "+string(alg), func(t *testing.T) {
			y := strings.Replace(string(validYAML(t)), "root_key_alg: ECDSA-P384", "root_key_alg: "+string(alg), 1)
			if _, err := Parse([]byte(y)); err != nil {
				t.Fatalf("Parse(%s): unexpected error: %v", alg, err)
			}
		})
	}
	// RSA-2048 is rejected with the rest: a CA key and a profile key are both
	// keys this CA certifies, and ca.ValidateSubjectKey will not certify an RSA
	// key below 3072 bits, so accepting 2048 here only defers the failure to
	// the ceremony or to subordination (#203).
	rejected := []string{"RSA-1024", "RSA-1536", "RSA-2048", "RSA", "rsa-3072", "ECDSA-P256", ""}
	for _, alg := range rejected {
		t.Run("rejects "+alg, func(t *testing.T) {
			y := strings.Replace(string(validYAML(t)), "root_key_alg: ECDSA-P384", "root_key_alg: "+alg, 1)
			if _, err := Parse([]byte(y)); err == nil {
				t.Fatalf("Parse(%q): want error, got nil", alg)
			}
		})
	}
}

// TestValidateProfilesAcceptsRSAKeyAlg covers the same vocabulary on a
// certificate profile's key_alg.
func TestValidateProfilesAcceptsRSAKeyAlg(t *testing.T) {
	for _, alg := range []RootKeyAlg{RootKeyECDSAP384, RootKeyRSA3072, RootKeyRSA4096} {
		t.Run("accepts "+string(alg), func(t *testing.T) {
			err := validateProfiles([]CertificateProfile{{Name: "p", KeyAlg: alg, ValidityDays: 1}})
			if err != nil {
				t.Fatalf("validateProfiles(%s): unexpected error: %v", alg, err)
			}
		})
	}
	for _, alg := range []RootKeyAlg{"RSA-1024", "RSA-2048"} {
		t.Run("rejects "+string(alg), func(t *testing.T) {
			if err := validateProfiles([]CertificateProfile{{Name: "p", KeyAlg: alg, ValidityDays: 1}}); err == nil {
				t.Fatalf("validateProfiles(%s): want error, got nil", alg)
			}
		})
	}
}

// TestRootKeyAlgKeyAlgorithm pins the mapping from the config vocabulary to
// the key-creation algorithm. The mapping is what carries an operator's
// pki.root_key_alg through to the key the node actually generates.
func TestRootKeyAlgKeyAlgorithm(t *testing.T) {
	tests := []struct {
		alg     RootKeyAlg
		want    tpm.KeyAlgorithm
		wantErr bool
	}{
		{alg: RootKeyECDSAP384, want: tpm.AlgorithmECDSAP384},
		{alg: RootKeyRSA3072, want: tpm.AlgorithmRSA3072},
		{alg: RootKeyRSA4096, want: tpm.AlgorithmRSA4096},
		{alg: "RSA-1024", wantErr: true},
		{alg: "RSA-2048", wantErr: true},
		{alg: "", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(string(tc.alg), func(t *testing.T) {
			got, err := tc.alg.KeyAlgorithm()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("KeyAlgorithm(%q): want error, got %v", tc.alg, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("KeyAlgorithm(%q): unexpected error: %v", tc.alg, err)
			}
			if got != tc.want {
				t.Errorf("KeyAlgorithm(%q) = %v, want %v", tc.alg, got, tc.want)
			}
		})
	}
}

// A node linked to a Fleet Manager carries a management block. The manager
// names itself (manager_cn); trust_pem is not used to authenticate anything
// and the manager does not send one, so only manager_cn is required.
func TestParse_Management(t *testing.T) {
	base := string(validYAML(t))
	for _, tc := range []struct {
		name    string
		block   string
		wantErr string
	}{
		{"manager_cn only", "management:\n  manager_cn: operator@example.org\n  operator_surface_readonly: true\n", ""},
		{"manager_cn with a trust_pem is still accepted", "management:\n  manager_cn: operator@example.org\n  trust_pem: \"anything\"\n", ""},
		{"no manager_cn", "management:\n  operator_surface_readonly: true\n", "config: management.manager_cn: required when management is set"},
		{"no management block", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse([]byte(base + tc.block))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Parse: %v", err)
				}
				if tc.block != "" && (cfg.Management == nil || cfg.Management.ManagerCN != "operator@example.org") {
					t.Fatalf("Management = %+v, want manager_cn operator@example.org", cfg.Management)
				}
				return
			}
			if err == nil || err.Error() != tc.wantErr {
				t.Fatalf("error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}
