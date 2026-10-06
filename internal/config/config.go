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
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"github.com/CryptOS-PKI/cryptos-node/internal/bootstrap"
	"github.com/CryptOS-PKI/cryptos-node/internal/ca"
	"github.com/CryptOS-PKI/cryptos-node/internal/tpm"
)

// APIVersion is the only api/kind pair accepted in Phase 1. Validator
// rejects any other value with no silent migration.
const (
	APIVersion = "cryptos.dev/v1alpha1"
	Kind       = "MachineConfig"
)

// RoleKind enumerates the supported node roles (root, and the Phase-2
// subordinate roles intermediate and issuing).
type RoleKind string

const (
	RoleRoot         RoleKind = "root"
	RoleIntermediate RoleKind = "intermediate" // Phase 2
	RoleIssuing      RoleKind = "issuing"      // Phase 2
)

// RootKeyAlg enumerates the supported CA key algorithms. The value selects
// both the key generated for this node's own CA and, because a certificate's
// signature comes from the issuer's key, the signature algorithm every
// certificate it issues will carry. If a target TPM cannot satisfy the
// requested algorithm, PID 1 fails to boot rather than silently downgrading.
//
// RSA is offered because platform CAs exist that accept only SHA-2 RSA
// signatures and reject the whole ECDSA family. Such a CA can be subordinated
// only under a chain that is RSA-signed at every level it must verify, which
// means this node's own CA key has to be RSA.
type RootKeyAlg string

const (
	RootKeyECDSAP384 RootKeyAlg = "ECDSA-P384"
	RootKeyRSA3072   RootKeyAlg = "RSA-3072"
	RootKeyRSA4096   RootKeyAlg = "RSA-4096"
)

// rootKeyAlgs is the closed set of accepted values. Membership is the whole
// validation rule: sizes below RSA-3072 are absent rather than range-checked,
// so an unlisted value is rejected by name.
//
// RSA-2048 is deliberately absent even though ca.MinRSAIssuerKeyBits allows a
// 2048-bit key to sign. This vocabulary names keys CryptOS generates and then
// certifies -- its own CA key, and the subject keys of the certificates it
// issues -- and ca.ValidateSubjectKey will not certify an RSA key below 3072
// bits. Offering 2048 would validate at config time and fail at the ceremony
// or at subordination instead (#203).
var rootKeyAlgs = map[RootKeyAlg]struct{}{
	RootKeyECDSAP384: {},
	RootKeyRSA3072:   {},
	RootKeyRSA4096:   {},
}

// Valid reports whether a is a supported CA key algorithm.
func (a RootKeyAlg) Valid() bool {
	_, ok := rootKeyAlgs[a]
	return ok
}

// KeyAlgorithm maps the config vocabulary to the algorithm the key backend
// generates. Without this the configured value would be validated and then
// ignored, which is what happened while ECDSA P-384 was the only option.
func (a RootKeyAlg) KeyAlgorithm() (tpm.KeyAlgorithm, error) {
	switch a {
	case RootKeyECDSAP384:
		return tpm.AlgorithmECDSAP384, nil
	case RootKeyRSA3072:
		return tpm.AlgorithmRSA3072, nil
	case RootKeyRSA4096:
		return tpm.AlgorithmRSA4096, nil
	default:
		return 0, fmt.Errorf("config: unsupported key algorithm %q, must be one of %s", a, supportedRootKeyAlgs())
	}
}

// supportedRootKeyAlgs lists the accepted values in a stable order, for error
// messages.
func supportedRootKeyAlgs() string {
	return strings.Join([]string{
		string(RootKeyECDSAP384),
		string(RootKeyRSA3072),
		string(RootKeyRSA4096),
	}, ", ")
}

// Config is the validated, in-memory representation of a machine config.
type Config struct {
	APIVersion string    `yaml:"apiVersion"`
	Kind       string    `yaml:"kind"`
	Metadata   Metadata  `yaml:"metadata"`
	Role       Role      `yaml:"role"`
	Network    Network   `yaml:"network"`
	Bootstrap  Bootstrap `yaml:"bootstrap"`
	PKI        PKI       `yaml:"pki"`
	Install    Install   `yaml:"install"`
	StateKey   StateKey  `yaml:"state_key"`
	// Management is nil on an unmanaged node and set by a LINK enrollment via
	// ApplyConfig. It is carried in the proto MachineConfig so the managed
	// state survives ApplyConfig and reaches an installed node (the
	// maintenance installer reconstructs the staged YAML from the proto).
	Management *Management `yaml:"management,omitempty"`
}

// StateKey selects the protector for the encrypted state-partition key. Mode is
// "" (build-time default) | "nodeid" | "tpm" | "kms". It is carried in the proto
// MachineConfig so the choice survives ApplyConfig and reaches an installed node
// (the maintenance installer reconstructs the staged YAML from the proto). The
// mode takes effect when the state volume is first sealed; every later boot
// reads it from the volume.
type StateKey struct {
	Mode string       `yaml:"mode"`
	KMS  *KmsStateKey `yaml:"kms"`
}

// CheckSealed refuses a mode other than sealed, the mode the node's state
// volume was sealed with at install. An empty mode asks for nothing and passes.
func (sk StateKey) CheckSealed(sealed string) error {
	if sk.Mode == "" || sk.Mode == sealed {
		return nil
	}
	return fmt.Errorf("config: state_key.mode %q: this node's state volume is sealed in %q mode, which is fixed at install; reinstall the node to change it",
		sk.Mode, sealed)
}

// KmsStateKey configures the envelope-encryption KMS that seals/unseals the
// state key. Only first-boot provisioning reads this from the machine config;
// later boots recover the endpoint and sealed blob from the LUKS2 header token.
type KmsStateKey struct {
	// Endpoint is the base URL of the seal/unseal KMS.
	Endpoint string `yaml:"endpoint"`
	// TrustPEM optionally pins the PEM CA bundle verifying the KMS TLS server.
	TrustPEM string `yaml:"trust_pem"`
}

// State-key mode values. The empty string means the node's build-time default.
const (
	StateKeyModeNodeID = "nodeid"
	StateKeyModeTPM    = "tpm"
	StateKeyModeKMS    = "kms"
)

// Management marks a node as Fleet-Manager-managed (set via ApplyConfig on a
// LINK enrollment; takes effect on reboot). Nil on unmanaged nodes.
type Management struct {
	ManagerCN               string `yaml:"manager_cn"`
	TrustPEM                string `yaml:"trust_pem"`
	OperatorSurfaceReadonly bool   `yaml:"operator_surface_readonly"`
}

// Install declares how the node provisions itself to persistent storage during
// the maintenance-mode install. Absent on an already-installed node.
type Install struct {
	Disk string `yaml:"disk"`
}

// Metadata carries operator-facing identifiers (not used for trust).
type Metadata struct {
	Name string `yaml:"name"`
}

// Role declares the CA role this node boots into.
type Role struct {
	Kind RoleKind `yaml:"kind"`
}

// Network declares the static network configuration. DHCP is Phase 2.
type Network struct {
	Interface string `yaml:"interface"`
	Address   string `yaml:"address"` // CIDR, e.g. "10.0.0.10/24"
	Gateway   string `yaml:"gateway"`
	// Nameservers are the DNS servers the node resolves names through, as
	// IPv4 literals in order. When empty the node falls back to the DNS
	// servers its kernel DHCP lease supplied, if any. Without either the node
	// cannot resolve a hostname, which blocks issuance when
	// pki.revocation_base_url names a host (#233).
	Nameservers []string `yaml:"nameservers"`
	// Search is the ordered DNS search-domain list. When empty the domain
	// from the DHCP lease, if any, is used.
	Search []string `yaml:"search"`
	// NTPServers are the SNTP servers the node keeps its clock in sync with,
	// at most MaxNTPServers, each an IPv4 literal or a hostname. A hostname is
	// resolved through the node resolver at each sync, so a DNS change is
	// picked up without a reboot. When empty the node uses the NTP servers
	// from its kernel DHCP lease (option 42), if any; with neither it runs on
	// its hardware clock.
	NTPServers []string `yaml:"ntp_servers"`
}

// Bootstrap carries the administrator credential trusted on first boot.
// Exactly one of AdminCertPEM or AdminCertSHA256 must be set.
type Bootstrap struct {
	AdminCertPEM    string `yaml:"admin_cert_pem"`
	AdminCertSHA256 string `yaml:"admin_cert_sha256"`
}

// PKI declares the CA's cryptographic parameters and naming.
type PKI struct {
	RootKeyAlg        RootKeyAlg `yaml:"root_key_alg"`
	RootSubject       Subject    `yaml:"root_subject"`
	RootValidityYears uint32     `yaml:"root_validity_years"`
	// PathLenConstraint is RESERVED for intermediate/issuing CAs (Phase 2).
	// It is NOT applied to the Phase 1 Root: per RFC 5280 §4.2.1.9 a Root is
	// left unconstrained (any depth); path depth is bounded at sub-CAs.
	PathLenConstraint uint32 `yaml:"path_len_constraint"`
	// Profiles are the operator-defined certificate profiles (Phase 2) this
	// node may generate a CSR from or stamp when signing. Referenced by name
	// from the issuance flows. Empty on Phase 1 configs.
	Profiles []CertificateProfile `yaml:"profiles"`
	// RootLeafIssuance is the explicit, irreversible operator acknowledgement
	// required before a ROOT-role node will issue end-entity (leaf)
	// certificates directly. A best-practice PKI issues leaves from an
	// issuing CA, never the offline Root; a Root that has signed a leaf can
	// no longer credibly claim to have signed only CAs. The signing service
	// refuses IssueLeaf on a ROOT node unless this equals
	// RootLeafIssuanceAcknowledged. It is carried in the proto MachineConfig so
	// the acknowledgement survives ApplyConfig and reaches an installed node
	// (the maintenance installer reconstructs the staged YAML from the proto).
	RootLeafIssuance string `yaml:"root_leaf_issuance"`
	// RevocationBaseURL is the operator-visible base URL under which this node
	// publishes its CRL, OCSP responder and CA certificate. When set, issuance
	// stamps a CDP pointer at <base>/crl, an AIA-OCSP pointer at <base>/ocsp and
	// an AIA caIssuers pointer at <base>/ca.cer, and the node starts an anonymous
	// HTTP listener serving those paths on a management boot.
	// Carried in the proto MachineConfig so it survives ApplyConfig and reaches
	// an installed node (the revocation fields and root_leaf_issuance all do).
	RevocationBaseURL string `yaml:"revocation_base_url"`
	// AllowUnverifiedRevocationURL overrides the fail-closed revocation preflight:
	// when true the node still issues even if the configured base URL does not
	// resolve or its /crl, /ocsp and /ca.cer endpoints are unreachable. Intended for an
	// isolated lab where DNS is not yet wired; production leaves it false so a
	// misconfigured URL blocks issuance rather than stamping a dead pointer.
	AllowUnverifiedRevocationURL bool `yaml:"allow_unverified_revocation_url"`
	// AllowUnsyncedClock overrides the fail-closed clock gate: while a time
	// source is configured or leased but the node has not synced its clock
	// this boot, certificate signing is refused unless this is true. The dates
	// a CA stamps are only as good as its clock, so production leaves it
	// false. A node with no time source is never gated, and CRL and OCSP
	// generation are never gated.
	AllowUnsyncedClock bool `yaml:"allow_unsynced_clock"`
	// CRLNextUpdateHours is the CRL validity window: nextUpdate is thisUpdate
	// plus this many hours. Zero means the caller's default (168h / one week).
	CRLNextUpdateHours uint32 `yaml:"crl_next_update_hours"`
	// RevocationHTTPPort is the TCP port the anonymous CRL/OCSP HTTP listener
	// binds on a management boot. Zero means the caller's default.
	RevocationHTTPPort uint32 `yaml:"revocation_http_port"`
	// Parent is the trust anchor a subordinate CA pins for its issuer: the
	// parent CA it verifies a handed-back signed chain against during the
	// first-boot ceremony. Required on an intermediate/issuing node, absent
	// (nil) on a Root.
	Parent *Parent `yaml:"parent"`
	// ACME configures the RFC 8555 enrolment endpoint. Nil (the field
	// omitted) disables ACME entirely and is the default: an enrolment
	// protocol is opened deliberately, never by forgetting to close it.
	//
	// It is carried in the proto MachineConfig as Pki.acme, under the
	// protocol-block rules in protocols.go: a Root refuses it, its secrets
	// are write-only over the API, and any change takes effect at the next
	// boot.
	ACME *ACME `yaml:"acme"`
	// EST configures the RFC 7030 enrolment endpoint. Nil (the field
	// omitted) disables EST entirely and is the default, for the same reason
	// ACME is off by default: an enrolment protocol is opened deliberately.
	//
	// Like ACME, it is carried as Pki.est under the same rules.
	EST *EST `yaml:"est"`
	// SCEP configures the RFC 8894 enrolment endpoint (see SCEP). Nil is
	// off, the default. Unlike ACME and EST it is carried in the proto.
	SCEP *SCEP `yaml:"scep"`
	// TSA configures the RFC 3161 time-stamp authority (see TSA). Nil is
	// off, the default. Like ACME and EST it is carried as Pki.tsa, keeps an
	// off block's settings in DisabledTSA, and a Root refuses it.
	TSA *TSA `yaml:"tsa"`
	// DisabledACME and DisabledEST keep the settings of a protocol block
	// that is switched off (enabled: false), so the same block can be
	// switched back on without re-entering them. Nothing reads them at boot:
	// a protocol runs only from ACME or EST. At most one of ACME and
	// DisabledACME is set, and likewise for EST. In YAML a disabled block is
	// the acme or est block with enabled: false.
	DisabledACME *ACME `yaml:"-" json:",omitempty"`
	DisabledEST  *EST  `yaml:"-" json:",omitempty"`
	DisabledTSA  *TSA  `yaml:"-" json:",omitempty"`
}

// EST configures the node's RFC 7030 server.
type EST struct {
	// Hostnames are the names and IP literals clients reach this endpoint
	// on. The node mints its own TLS server certificate for them from its
	// CA, so a name missing here is a name clients cannot verify. Required.
	Hostnames []string `yaml:"hostnames"`
	// HTTPPort is the TCP port the EST listener binds. Zero means the
	// caller's default. Unlike ACME this listener terminates TLS itself,
	// because simplereenroll authenticates with a TLS client certificate
	// that has to reach the handler.
	HTTPPort uint32 `yaml:"http_port"`
	// Profile names the leaf certificate profile EST issues under. It must
	// name a non-CA profile in Profiles. Required.
	Profile string `yaml:"profile"`
	// Label is the optional path segment between /.well-known/est and the
	// operation (RFC 7030 section 3.2.2), which is how one host offers
	// several CAs. Empty serves the unlabelled paths.
	Label string `yaml:"label"`
	// Realm is the HTTP Basic realm offered when simpleenroll challenges.
	Realm string `yaml:"realm"`
	// AllowedIdentifierSuffixes restricts the names simpleenroll will issue
	// for. It does not restrict simplereenroll, whose names are pinned to
	// the certificate the client already holds.
	AllowedIdentifierSuffixes []string `yaml:"allowed_identifier_suffixes"`
	// AllowAnyIdentifier drops that restriction. It must be set by name:
	// simpleenroll proves nothing about control of a name, so without an
	// allowlist a single leaked credential mints a certificate for anything.
	AllowAnyIdentifier bool `yaml:"allow_any_identifier"`
	// EnrollCredentials are the HTTP Basic credentials that authorize
	// simpleenroll. Leaving it empty is a valid deployment: simpleenroll
	// stays closed and the node offers certificate-authenticated renewal
	// only, for fleets that enrol through ACME and renew through EST.
	EnrollCredentials []ESTEnrollCredential `yaml:"enroll_credentials"`
}

// ESTEnrollCredential is one provisioned simpleenroll credential.
type ESTEnrollCredential struct {
	// Username is the HTTP Basic user name.
	Username string `yaml:"username"`
	// PasswordSHA256 is the lowercase hex SHA-256 of the password, so the
	// running configuration never holds a live credential. That is only safe
	// because the password must be a generated high-entropy value: a plain
	// digest of a chosen word would fall to a dictionary in seconds.
	PasswordSHA256 string `yaml:"password_sha256"`
}

// ACME configures the node's RFC 8555 server.
type ACME struct {
	// BaseURL is the externally reachable base under which the ACME
	// endpoints live, for example https://ca.example.org/acme. Every URL
	// handed to a client is built from it and every request's protected url
	// header is checked against it, so it must be what clients dial rather
	// than what the node binds. Required.
	BaseURL string `yaml:"base_url"`
	// HTTPPort is the TCP port the ACME listener binds. Zero means the
	// caller's default. It is separate from RevocationHTTPPort because the
	// CRL/OCSP listener is plain HTTP by design while ACME is normally
	// fronted by TLS.
	HTTPPort uint32 `yaml:"http_port"`
	// Profile names the leaf certificate profile ACME issues under. It must
	// name a non-CA profile in Profiles. Required: there is no default,
	// because "whichever profile happens to be first" is not a policy.
	Profile string `yaml:"profile"`
	// TermsOfService, when set, is advertised in the directory and a new
	// account must agree to it.
	TermsOfService string `yaml:"terms_of_service"`
	// Website is advertised in the directory meta.
	Website string `yaml:"website"`
	// AllowAnonymousAccounts drops the External Account Binding requirement
	// (RFC 8555 section 7.3.4), letting anyone who can answer an http-01
	// challenge register and order. The knob is inverted deliberately, the
	// same way AllowUnverifiedRevocationURL is: an internal CA reachable by
	// any host on the network is a broad grant, so the safe posture is what
	// an operator gets by leaving the field alone.
	AllowAnonymousAccounts bool `yaml:"allow_anonymous_accounts"`
	// ExternalAccountKeys are the HMAC keys an operator provisions for
	// External Account Binding. At least one is required unless
	// AllowAnonymousAccounts is set.
	ExternalAccountKeys []ExternalAccountKey `yaml:"external_account_keys"`
	// AllowedIdentifierSuffixes, when non-empty, restricts the DNS names
	// this node will order for: an identifier must equal, or be a subdomain
	// of, one of these. Empty places no name restriction, leaving proof of
	// control and the account binding as the only gates.
	AllowedIdentifierSuffixes []string `yaml:"allowed_identifier_suffixes"`
	// OrderTTLHours is how long an order and its authorizations stay valid.
	// Zero means the caller's default.
	OrderTTLHours uint32 `yaml:"order_ttl_hours"`
}

// ExternalAccountKey is one provisioned External Account Binding credential.
type ExternalAccountKey struct {
	// KeyID is the identifier the client sends as the binding's kid.
	KeyID string `yaml:"key_id"`
	// HMACKeyBase64 is the shared secret, base64url-encoded without padding,
	// which is the form every ACME client expects to be handed.
	HMACKeyBase64 string `yaml:"hmac_key_base64"`
}

// MinEABKeyBytes is the smallest External Account Binding secret accepted. The
// binding is an HMAC and nothing rate-limits an offline guess against a
// captured one, so a short shared secret would be the weakest link in the
// whole enrolment path.
const MinEABKeyBytes = 32

// Parent is the pinned issuer trust anchor for a subordinate CA. Exactly one
// of CACertPEM or CACertSHA256 must be set, mirroring the bootstrap admin
// credential shape.
type Parent struct {
	CACertPEM    string `yaml:"ca_cert_pem"`
	CACertSHA256 string `yaml:"ca_cert_sha256"`
}

// RootLeafIssuanceAcknowledged is the exact RootLeafIssuance value that
// unlocks direct leaf issuance from a ROOT-role node.
const RootLeafIssuanceAcknowledged = "acknowledged-irreversible"

// CertificateProfile is an operator-defined template for CSR generation and
// certificate signing: key parameters, subject, validity, and a covering
// subset of X.509 extensions plus a raw-OID escape hatch (ExtraExtensions).
type CertificateProfile struct {
	Name             string           `yaml:"name"`
	KeyAlg           RootKeyAlg       `yaml:"key_alg"`
	Subject          Subject          `yaml:"subject"`
	ValidityDays     uint32           `yaml:"validity_days"`
	BasicConstraints BasicConstraints `yaml:"basic_constraints"`
	KeyUsage         []string         `yaml:"key_usage"`
	ExtKeyUsage      []string         `yaml:"ext_key_usage"`
	SANs             SubjectAltNames  `yaml:"sans"`
	ExtraExtensions  []X509Extension  `yaml:"extra_extensions"`
	// AllowRequestSANs lets an admin IssueLeaf call replace the profile's SANs
	// with the DNS names it supplies (cryptosctl ca issue-leaf --dns). Off by default, so a
	// profile's static SANs are the only names it stamps unless it opts in.
	// Leaf profiles only.
	AllowRequestSANs bool `yaml:"allow_request_sans"`
	// ValidityPolicy decides what issuance does when ValidityDays would run
	// past the issuing CA's own notAfter: cap (the default when empty) ends
	// the certificate with its issuer, reject refuses to issue.
	ValidityPolicy ValidityPolicy `yaml:"validity_policy"`
}

// BasicConstraints models the RFC 5280 basicConstraints extension. PathLen
// applies only when IsCA: a non-nil zero means no CAs may be issued below
// (leaf-only issuing CA); nil means unconstrained depth.
type BasicConstraints struct {
	IsCA    bool    `yaml:"is_ca"`
	PathLen *uint32 `yaml:"path_len"`
}

// SubjectAltNames carries the typed subjectAltName entries for a profile.
type SubjectAltNames struct {
	DNS   []string `yaml:"dns"`
	IP    []string `yaml:"ip"`
	Email []string `yaml:"email"`
	URI   []string `yaml:"uri"`
	// KRB5Principal lists Kerberos principals (name[/instance]@REALM), stamped
	// as KRB5PrincipalName otherName entries (id-pkinit-san). A KDC
	// certificate carries krbtgt/<REALM>@<REALM>.
	KRB5Principal []string `yaml:"krb5_principal"`
	// UPN lists Microsoft user principal names (prefix@suffix), stamped as
	// otherName entries of type 1.3.6.1.4.1.311.20.2.3.
	UPN []string `yaml:"upn"`
}

// X509Extension is the raw escape hatch: a dotted OID, criticality flag, and
// the DER-encoded extension value, for extensions not yet typed.
type X509Extension struct {
	OID      string `yaml:"oid"`
	Critical bool   `yaml:"critical"`
	Value    []byte `yaml:"value"`
}

// Subject is the X.500 Distinguished Name for the Root certificate.
type Subject struct {
	CommonName   string `yaml:"common_name"`
	Organization string `yaml:"organization"`
	Country      string `yaml:"country"`
	// Province is the X.509 ST relative distinguished name (state or province).
	Province string `yaml:"province"`
	// Locality is the X.509 L relative distinguished name (city or locality).
	Locality string `yaml:"locality"`
}

// Parse parses a machine-config YAML document and runs every Phase 1
// validation rule. The returned Config is safe to apply.
func Parse(raw []byte) (*Config, error) {
	c, err := decode(raw)
	if err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// ParseForApply parses a config a client is about to apply. It is Parse with
// one allowance: an empty protocol secret (an ACME hmac_key_base64 or an EST
// password_sha256) passes, because it asks the node to keep the secret it
// stores under the same identifier, which is what `config get` prints. The
// node resolves those and validates strictly before storing anything.
func ParseForApply(raw []byte) (*Config, error) {
	c, err := decode(raw)
	if err != nil {
		return nil, err
	}
	if err := c.validate(true); err != nil {
		return nil, err
	}
	return c, nil
}

func decode(raw []byte) (*Config, error) {
	if len(raw) == 0 {
		return nil, errors.New("config: empty input")
	}
	raw, flags, err := popProtocolFlags(raw)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: parse YAML: %w", err)
	}
	c.applyProtocolFlags(flags)
	return &c, nil
}

// Validate runs every Phase 1 schema rule against c. The error wraps
// the field path so callers can surface it via INVALID_ARGUMENT details
// on the gRPC layer.
func (c *Config) Validate() error {
	return c.validate(false)
}

// validate is Validate, optionally letting protocol secrets be empty (see
// ParseForApply).
func (c *Config) validate(keptSecrets bool) error {
	if c == nil {
		return errors.New("config: nil config")
	}
	if c.APIVersion != APIVersion {
		return fmt.Errorf("config: apiVersion: expected %q, got %q", APIVersion, c.APIVersion)
	}
	if c.Kind != Kind {
		return fmt.Errorf("config: kind: expected %q, got %q", Kind, c.Kind)
	}
	switch c.Role.Kind {
	case RoleRoot, RoleIntermediate, RoleIssuing:
	default:
		return fmt.Errorf("config: role.kind: must be one of %q/%q/%q, got %q",
			RoleRoot, RoleIntermediate, RoleIssuing, c.Role.Kind)
	}
	if c.Network.Interface == "" {
		return errors.New("config: network.interface: required")
	}
	if _, err := netip.ParsePrefix(c.Network.Address); err != nil {
		return fmt.Errorf("config: network.address: must be CIDR: %w", err)
	}
	if _, err := netip.ParseAddr(c.Network.Gateway); err != nil {
		return fmt.Errorf("config: network.gateway: must be IP: %w", err)
	}
	if err := validateNameservers(c.Network.Nameservers); err != nil {
		return err
	}
	if err := validateSearch(c.Network.Search); err != nil {
		return err
	}
	if err := validateNTPServers(c.Network.NTPServers); err != nil {
		return err
	}
	if err := validateBootstrap(c.Bootstrap); err != nil {
		return err
	}
	if !c.PKI.RootKeyAlg.Valid() {
		return fmt.Errorf("config: pki.root_key_alg: must be one of %s, got %q", supportedRootKeyAlgs(), c.PKI.RootKeyAlg)
	}
	// root_validity_years governs the lifetime of a root's self-signed
	// certificate, so it is required only for a root. A subordinate never
	// self-signs: its validity comes from the parent's sub-ca profile at
	// signing time, so the field is unused and not required for
	// intermediate/issuing roles.
	if c.Role.Kind == RoleRoot && (c.PKI.RootValidityYears < 1 || c.PKI.RootValidityYears > 30) {
		return fmt.Errorf("config: pki.root_validity_years: must be in [1, 30], got %d", c.PKI.RootValidityYears)
	}
	if c.PKI.PathLenConstraint > 5 {
		return fmt.Errorf("config: pki.path_len_constraint: must be in [0, 5], got %d", c.PKI.PathLenConstraint)
	}
	if c.PKI.RootSubject.CommonName == "" {
		return errors.New("config: pki.root_subject.common_name: required")
	}
	if err := validateProfiles(c.PKI.Profiles); err != nil {
		return err
	}
	if err := validateRevocationBaseURL(c.PKI.RevocationBaseURL); err != nil {
		return err
	}
	if err := validateProtocolRole(c.Role.Kind, c.PKI); err != nil {
		return err
	}
	if err := validateACME(c.PKI.ACME, c.PKI.Profiles, keptSecrets); err != nil {
		return err
	}
	if err := validateEST(c.PKI.EST, c.PKI.Profiles, keptSecrets); err != nil {
		return err
	}
	if err := validateSCEP(c.Role.Kind, c.PKI.SCEP, c.PKI.Profiles); err != nil {
		return err
	}
	if err := validateTSA(c.PKI.TSA); err != nil {
		return err
	}
	if err := validateParent(c.Role.Kind, c.PKI.Parent); err != nil {
		return err
	}
	if err := validateStateKey(c.StateKey); err != nil {
		return err
	}
	if err := validateManagement(c.Management); err != nil {
		return err
	}
	return nil
}

// validateManagement enforces that a managed node names its manager and
// carries the trust anchor; an unmanaged node (nil) has no constraint.
func validateManagement(m *Management) error {
	if m == nil {
		return nil
	}
	if m.ManagerCN == "" {
		return errors.New("config: management.manager_cn: required when management is set")
	}
	if m.TrustPEM == "" {
		return errors.New("config: management.trust_pem: required when management is set")
	}
	return nil
}

// validateStateKey enforces the state-key protector rules: mode must be empty
// (build-time default) or one of nodeid/tpm/kms; when mode is kms, the kms
// section is required and its endpoint must be a well-formed http(s) URL. DNS
// resolution is deliberately NOT done here (the box may validate its config
// before the network is up); reachability is a runtime concern.
func validateStateKey(sk StateKey) error {
	switch sk.Mode {
	case "", StateKeyModeNodeID, StateKeyModeTPM, StateKeyModeKMS:
	default:
		return fmt.Errorf("config: state_key.mode: must be one of %q/%q/%q (empty = build default), got %q",
			StateKeyModeNodeID, StateKeyModeTPM, StateKeyModeKMS, sk.Mode)
	}
	if sk.Mode != StateKeyModeKMS {
		return nil
	}
	if sk.KMS == nil {
		return errors.New("config: state_key.kms: required when state_key.mode is \"kms\"")
	}
	u, err := url.Parse(sk.KMS.Endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("config: state_key.kms.endpoint: must be an http(s) URL")
	}
	return nil
}

// validateRevocationBaseURL enforces that a configured revocation base URL is a
// well-formed http(s) URL with a host. DNS resolution is deliberately NOT done
// here: the box may validate its config before the network is up. Reachability
// is a runtime preflight (see internal/revocation). An empty value is allowed.
func validateRevocationBaseURL(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("config: pki.revocation_base_url: must be an http(s) URL")
	}
	return nil
}

// validateACME enforces the ACME rules. A nil block means ACME is off and
// nothing is checked. When it is on, the checks are all fail-closed: the base
// URL must be well-formed (it is compared against every request's signed url
// header, so a wrong one breaks every request rather than degrading), the
// named profile must exist and must be a leaf profile, and account binding
// keys must be present and long enough unless anonymous accounts were
// explicitly allowed.
//
// As elsewhere in this file, no DNS resolution happens here: the box may
// validate its config before the network is up.
//
// keptSecrets lets an empty key through (see ParseForApply).
func validateACME(a *ACME, profiles []CertificateProfile, keptSecrets bool) error {
	if a == nil {
		return nil
	}
	u, err := url.Parse(a.BaseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("config: pki.acme.base_url: must be an http(s) URL")
	}
	if a.Profile == "" {
		return errors.New("config: pki.acme.profile: required when pki.acme is set")
	}
	var prof *CertificateProfile
	for i := range profiles {
		if profiles[i].Name == a.Profile {
			prof = &profiles[i]
			break
		}
	}
	if prof == nil {
		return fmt.Errorf("config: pki.acme.profile: no profile named %q in pki.profiles", a.Profile)
	}
	if prof.BasicConstraints.IsCA {
		return fmt.Errorf("config: pki.acme.profile: %q is a CA profile; ACME issues end-entity certificates only", a.Profile)
	}

	if !a.AllowAnonymousAccounts && len(a.ExternalAccountKeys) == 0 {
		return errors.New("config: pki.acme.external_account_keys: at least one key is required " +
			"unless pki.acme.allow_anonymous_accounts is true")
	}
	seen := make(map[string]bool, len(a.ExternalAccountKeys))
	for i, k := range a.ExternalAccountKeys {
		if k.KeyID == "" {
			return fmt.Errorf("config: pki.acme.external_account_keys[%d].key_id: required", i)
		}
		if seen[k.KeyID] {
			return fmt.Errorf("config: pki.acme.external_account_keys[%d].key_id: %q is duplicated", i, k.KeyID)
		}
		seen[k.KeyID] = true
		if keptSecrets && k.HMACKeyBase64 == "" {
			continue
		}
		raw, derr := base64.RawURLEncoding.DecodeString(k.HMACKeyBase64)
		if derr != nil {
			return fmt.Errorf("config: pki.acme.external_account_keys[%d].hmac_key_base64: "+
				"must be base64url without padding", i)
		}
		if len(raw) < MinEABKeyBytes {
			return fmt.Errorf("config: pki.acme.external_account_keys[%d].hmac_key_base64: "+
				"must decode to at least %d bytes, got %d", i, MinEABKeyBytes, len(raw))
		}
	}
	return nil
}

// validateEST enforces the EST rules. A nil block means EST is off and
// nothing is checked.
//
// The rule worth reading twice is the last one. simpleenroll authenticates a
// caller but proves nothing about the name it asks for, so an allowlist is
// required whenever credentials are configured. An operator who genuinely
// wants an unrestricted endpoint has to say allow_any_identifier, which is a
// line a reviewer can find.
//
// keptSecrets lets an empty password digest through (see ParseForApply).
func validateEST(e *EST, profiles []CertificateProfile, keptSecrets bool) error {
	if e == nil {
		return nil
	}
	if len(e.Hostnames) == 0 {
		return errors.New("config: pki.est.hostnames: at least one hostname is required; " +
			"the node mints its TLS server certificate for them")
	}
	for i, h := range e.Hostnames {
		if strings.TrimSpace(h) == "" {
			return fmt.Errorf("config: pki.est.hostnames[%d]: must not be empty", i)
		}
	}
	if strings.Contains(e.Label, "/") {
		return fmt.Errorf("config: pki.est.label: must be a single path segment, got %q", e.Label)
	}
	if e.Profile == "" {
		return errors.New("config: pki.est.profile: required when pki.est is set")
	}
	var prof *CertificateProfile
	for i := range profiles {
		if profiles[i].Name == e.Profile {
			prof = &profiles[i]
			break
		}
	}
	if prof == nil {
		return fmt.Errorf("config: pki.est.profile: no profile named %q in pki.profiles", e.Profile)
	}
	if prof.BasicConstraints.IsCA {
		return fmt.Errorf("config: pki.est.profile: %q is a CA profile; EST issues end-entity certificates only", e.Profile)
	}

	seen := make(map[string]bool, len(e.EnrollCredentials))
	for i, cred := range e.EnrollCredentials {
		if cred.Username == "" {
			return fmt.Errorf("config: pki.est.enroll_credentials[%d].username: required", i)
		}
		if seen[cred.Username] {
			return fmt.Errorf("config: pki.est.enroll_credentials[%d].username: %q is duplicated", i, cred.Username)
		}
		seen[cred.Username] = true
		if keptSecrets && cred.PasswordSHA256 == "" {
			continue
		}
		raw, err := hex.DecodeString(cred.PasswordSHA256)
		if err != nil || len(raw) != sha256.Size {
			return fmt.Errorf("config: pki.est.enroll_credentials[%d].password_sha256: "+
				"must be %d lowercase hex characters (a SHA-256 digest)", i, sha256.Size*2)
		}
	}
	if len(e.EnrollCredentials) > 0 && len(e.AllowedIdentifierSuffixes) == 0 && !e.AllowAnyIdentifier {
		return errors.New("config: pki.est.allowed_identifier_suffixes: required when " +
			"pki.est.enroll_credentials is set, unless pki.est.allow_any_identifier is true; " +
			"simpleenroll has no proof of control")
	}
	return nil
}

// validateParent enforces the subordinate parent-anchor rules: a Root must not
// carry a parent; an intermediate/issuing node must carry exactly one of the
// parent PEM or SHA-256.
func validateParent(role RoleKind, p *Parent) error {
	isSubordinate := role == RoleIntermediate || role == RoleIssuing
	if !isSubordinate {
		if p != nil {
			return errors.New("config: pki.parent: must not be set on a root node")
		}
		return nil
	}
	if p == nil {
		return errors.New("config: pki.parent: required on an intermediate/issuing node")
	}
	hasPEM := p.CACertPEM != ""
	hasSHA := p.CACertSHA256 != ""
	if hasPEM == hasSHA {
		return errors.New("config: pki.parent: exactly one of ca_cert_pem or ca_cert_sha256 is required")
	}
	if hasSHA {
		if len(p.CACertSHA256) != 64 {
			return fmt.Errorf("config: pki.parent.ca_cert_sha256: must be 64 hex characters, got %d", len(p.CACertSHA256))
		}
		if _, err := hex.DecodeString(p.CACertSHA256); err != nil {
			return fmt.Errorf("config: pki.parent.ca_cert_sha256: not hex: %w", err)
		}
		return nil
	}
	block, rest := pem.Decode([]byte(p.CACertPEM))
	if block == nil {
		return errors.New("config: pki.parent.ca_cert_pem: no PEM block found")
	}
	if block.Type != "CERTIFICATE" {
		return fmt.Errorf("config: pki.parent.ca_cert_pem: PEM type %q, want CERTIFICATE", block.Type)
	}
	if len(strings.TrimSpace(string(rest))) != 0 {
		return errors.New("config: pki.parent.ca_cert_pem: must contain exactly one PEM block")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return fmt.Errorf("config: pki.parent.ca_cert_pem: parse: %w", err)
	}
	return nil
}

// ParentTrust builds a bootstrap.Trust from the pinned parent anchor. It
// returns nil (no error) when no parent is configured (a Root). Validate must
// have accepted the config first; a mis-shaped parent surfaces as an error.
func (c *Config) ParentTrust() (*bootstrap.Trust, error) {
	if c == nil || c.PKI.Parent == nil {
		return nil, nil
	}
	return bootstrap.LoadTrust(c.PKI.Parent.CACertPEM, c.PKI.Parent.CACertSHA256)
}

// validateProfiles enforces the Phase 2 certificate-profile rules. An empty
// slice is allowed (Phase 1 configs carry no profiles).
func validateProfiles(profiles []CertificateProfile) error {
	seen := make(map[string]struct{}, len(profiles))
	for i, p := range profiles {
		if p.Name == "" {
			return fmt.Errorf("config: pki.profiles[%d].name: required", i)
		}
		if _, dup := seen[p.Name]; dup {
			return fmt.Errorf("config: pki.profiles[%d].name: duplicate name %q", i, p.Name)
		}
		seen[p.Name] = struct{}{}
		if !p.KeyAlg.Valid() {
			return fmt.Errorf("config: pki.profiles[%d].key_alg: must be one of %s, got %q", i, supportedRootKeyAlgs(), p.KeyAlg)
		}
		if p.ValidityDays == 0 {
			return fmt.Errorf("config: pki.profiles[%d].validity_days: must be greater than 0", i)
		}
		if _, err := ca.ParseKeyUsage(p.KeyUsage); err != nil {
			return fmt.Errorf("config: pki.profiles[%d].key_usage: %w", i, err)
		}
		if _, _, err := ca.ParseExtKeyUsage(p.ExtKeyUsage); err != nil {
			return fmt.Errorf("config: pki.profiles[%d].ext_key_usage: %w", i, err)
		}
		for j, ext := range p.ExtraExtensions {
			if err := validateOID(ext.OID); err != nil {
				return fmt.Errorf("config: pki.profiles[%d].extra_extensions[%d].oid: %w", i, j, err)
			}
		}
		if !p.ValidityPolicy.Valid() {
			return fmt.Errorf("config: pki.profiles[%d].validity_policy: must be %q or %q, got %q", i, ValidityPolicyCap, ValidityPolicyReject, p.ValidityPolicy)
		}
		if p.AllowRequestSANs && p.BasicConstraints.IsCA {
			return fmt.Errorf("config: pki.profiles[%d].allow_request_sans: applies to leaf profiles only, not a CA profile", i)
		}
		if _, err := p.SANs.OtherNames(); err != nil {
			return fmt.Errorf("config: pki.profiles[%d].%w", i, err)
		}
		if len(p.SANs.KRB5Principal)+len(p.SANs.UPN) > 0 {
			for j, ext := range p.ExtraExtensions {
				if ext.OID == "2.5.29.17" {
					return fmt.Errorf("config: pki.profiles[%d].extra_extensions[%d]: a raw subjectAltName extension cannot be combined with sans.krb5_principal or sans.upn", i, j)
				}
			}
		}
	}
	return nil
}

// OtherNames returns the profile's otherName SANs (Kerberos principals, then
// UPNs) in the form ca.Sign stamps. A malformed entry is an error naming its
// field and index.
func (s SubjectAltNames) OtherNames() ([]ca.OtherName, error) {
	var out []ca.OtherName
	for j, v := range s.KRB5Principal {
		on, err := ca.KRB5PrincipalName(v)
		if err != nil {
			return nil, fmt.Errorf("sans.krb5_principal[%d]: %w", j, err)
		}
		out = append(out, on)
	}
	for j, v := range s.UPN {
		on, err := ca.UPN(v)
		if err != nil {
			return nil, fmt.Errorf("sans.upn[%d]: %w", j, err)
		}
		out = append(out, on)
	}
	return out, nil
}

// validateOID accepts a dotted OID of at least two numeric arcs.
func validateOID(oid string) error {
	arcs := strings.Split(oid, ".")
	if len(arcs) < 2 {
		return fmt.Errorf("invalid OID %q: need at least two arcs", oid)
	}
	for _, arc := range arcs {
		if arc == "" {
			return fmt.Errorf("invalid OID %q: empty arc", oid)
		}
		for _, r := range arc {
			if r < '0' || r > '9' {
				return fmt.Errorf("invalid OID %q: non-numeric arc %q", oid, arc)
			}
		}
	}
	return nil
}

// NodeRole maps the configured RoleKind to the API NodeRole.
func (c *Config) NodeRole() nodev1.NodeRole {
	switch c.Role.Kind {
	case RoleIntermediate:
		return nodev1.NodeRole_NODE_ROLE_INTERMEDIATE
	case RoleIssuing:
		return nodev1.NodeRole_NODE_ROLE_ISSUING
	default:
		return nodev1.NodeRole_NODE_ROLE_ROOT
	}
}

// ProfileByName returns the certificate profile with the given name, or nil
// when no profile carries that name. It is a linear scan over PKI.Profiles.
func (c *Config) ProfileByName(name string) *CertificateProfile {
	if c == nil {
		return nil
	}
	for i := range c.PKI.Profiles {
		if c.PKI.Profiles[i].Name == name {
			return &c.PKI.Profiles[i]
		}
	}
	return nil
}

func validateBootstrap(b Bootstrap) error {
	hasPEM := b.AdminCertPEM != ""
	hasSHA := b.AdminCertSHA256 != ""
	if hasPEM == hasSHA {
		return errors.New("config: bootstrap: exactly one of admin_cert_pem or admin_cert_sha256 is required")
	}
	if hasSHA {
		if len(b.AdminCertSHA256) != 64 {
			return fmt.Errorf("config: bootstrap.admin_cert_sha256: must be 64 hex characters, got %d", len(b.AdminCertSHA256))
		}
		if _, err := hex.DecodeString(b.AdminCertSHA256); err != nil {
			return fmt.Errorf("config: bootstrap.admin_cert_sha256: not hex: %w", err)
		}
		return nil
	}
	block, rest := pem.Decode([]byte(b.AdminCertPEM))
	if block == nil {
		return errors.New("config: bootstrap.admin_cert_pem: no PEM block found")
	}
	if block.Type != "CERTIFICATE" {
		return fmt.Errorf("config: bootstrap.admin_cert_pem: PEM type %q, want CERTIFICATE", block.Type)
	}
	if len(strings.TrimSpace(string(rest))) != 0 {
		return errors.New("config: bootstrap.admin_cert_pem: must contain exactly one PEM block")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return fmt.Errorf("config: bootstrap.admin_cert_pem: parse: %w", err)
	}
	return nil
}

// Digest returns the SHA-256 digest of the canonical (JSON, sorted
// keys) encoding of the config. Stable across whitespace and comment
// changes in the source YAML.
func (c *Config) Digest() ([]byte, error) {
	canon, err := canonicalJSON(c)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(canon)
	return sum[:], nil
}

func canonicalJSON(c *Config) ([]byte, error) {
	// json.Marshal sorts map keys but not struct fields. Round-trip
	// through a map[string]interface{} to enforce sorted-keys output.
	intermediate, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("config: canonicalize: %w", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(intermediate, &m); err != nil {
		return nil, fmt.Errorf("config: canonicalize roundtrip: %w", err)
	}
	return marshalSorted(m)
}

func marshalSorted(v interface{}) ([]byte, error) {
	switch t := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var sb strings.Builder
		sb.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return nil, err
			}
			sb.Write(kb)
			sb.WriteByte(':')
			vb, err := marshalSorted(t[k])
			if err != nil {
				return nil, err
			}
			sb.Write(vb)
		}
		sb.WriteByte('}')
		return []byte(sb.String()), nil
	case []interface{}:
		var sb strings.Builder
		sb.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				sb.WriteByte(',')
			}
			eb, err := marshalSorted(e)
			if err != nil {
				return nil, err
			}
			sb.Write(eb)
		}
		sb.WriteByte(']')
		return []byte(sb.String()), nil
	default:
		return json.Marshal(t)
	}
}

// Marshal renders c as the canonical machine.yaml document. A disabled
// protocol block is written as its block with enabled: false.
func (c *Config) Marshal() ([]byte, error) {
	if c.PKI.DisabledACME == nil && c.PKI.DisabledEST == nil && c.PKI.DisabledTSA == nil {
		return yaml.Marshal(c)
	}
	return marshalWithDisabledBlocks(c)
}

// FromProto converts a proto MachineConfig back to a Config. It is the
// inverse of ToProto. Guard against sparse protos; each nested message
// is checked for nil before dereference.
func FromProto(pb *nodev1.MachineConfig) (*Config, error) {
	if pb == nil {
		return nil, errors.New("config: FromProto: nil proto")
	}
	c := &Config{
		APIVersion: pb.ApiVersion,
		Kind:       pb.Kind,
	}
	if pb.Metadata != nil {
		c.Metadata.Name = pb.Metadata.Name
	}
	if pb.Role != nil {
		c.Role.Kind = RoleKind(pb.Role.Kind)
	}
	if pb.Network != nil {
		c.Network.Interface = pb.Network.Interface
		c.Network.Address = pb.Network.Address
		c.Network.Gateway = pb.Network.Gateway
		c.Network.Nameservers = pb.Network.Nameservers
		c.Network.Search = pb.Network.Search
		c.Network.NTPServers = pb.Network.NtpServers
	}
	if pb.Bootstrap != nil {
		c.Bootstrap.AdminCertPEM = pb.Bootstrap.AdminCertPem
		c.Bootstrap.AdminCertSHA256 = pb.Bootstrap.AdminCertSha256
	}
	if pb.Pki != nil {
		c.PKI.RootKeyAlg = RootKeyAlg(pb.Pki.RootKeyAlg)
		c.PKI.RootValidityYears = pb.Pki.RootValidityYears
		c.PKI.PathLenConstraint = pb.Pki.PathLenConstraint
		if pb.Pki.RootSubject != nil {
			c.PKI.RootSubject.CommonName = pb.Pki.RootSubject.CommonName
			c.PKI.RootSubject.Organization = pb.Pki.RootSubject.Organization
			c.PKI.RootSubject.Country = pb.Pki.RootSubject.Country
			c.PKI.RootSubject.Province = pb.Pki.RootSubject.Province
			c.PKI.RootSubject.Locality = pb.Pki.RootSubject.Locality
		}
		c.PKI.Profiles = profilesFromProto(pb.Pki.Profiles)
		c.PKI.RevocationBaseURL = pb.Pki.RevocationBaseUrl
		c.PKI.AllowUnverifiedRevocationURL = pb.Pki.AllowUnverifiedRevocationUrl
		c.PKI.AllowUnsyncedClock = pb.Pki.AllowUnsyncedClock
		c.PKI.CRLNextUpdateHours = pb.Pki.CrlNextUpdateHours
		c.PKI.RevocationHTTPPort = pb.Pki.RevocationHttpPort
		c.PKI.RootLeafIssuance = pb.Pki.RootLeafIssuance
		if pb.Pki.Parent != nil {
			c.PKI.Parent = &Parent{
				CACertPEM:    pb.Pki.Parent.CaCertPem,
				CACertSHA256: pb.Pki.Parent.CaCertSha256,
			}
		}
		c.PKI.ACME, c.PKI.DisabledACME = acmeFromProto(pb.Pki.Acme)
		c.PKI.EST, c.PKI.DisabledEST = estFromProto(pb.Pki.Est)
		c.PKI.SCEP = scepFromProto(pb.Pki.Scep)
		c.PKI.TSA, c.PKI.DisabledTSA = tsaFromProto(pb.Pki.Tsa)
	}
	if pb.Install != nil {
		c.Install.Disk = pb.Install.Disk
	}
	if pb.StateKey != nil {
		c.StateKey.Mode = pb.StateKey.Mode
		if pb.StateKey.Kms != nil {
			c.StateKey.KMS = &KmsStateKey{
				Endpoint: pb.StateKey.Kms.Endpoint,
				TrustPEM: pb.StateKey.Kms.TrustPem,
			}
		}
	}
	if pb.Management != nil {
		c.Management = &Management{
			ManagerCN:               pb.Management.ManagerCn,
			TrustPEM:                pb.Management.TrustPem,
			OperatorSurfaceReadonly: pb.Management.OperatorSurfaceReadonly,
		}
	}
	return c, nil
}

// ToProto adapts the validated Config to the api/ proto MachineConfig
// for the gRPC layer. Only the Phase 1 subset is populated. The protocol
// secrets are included; use ToProtoRedacted for a reader.
func (c *Config) ToProto() *nodev1.MachineConfig {
	pki := &nodev1.Pki{
		RootKeyAlg: string(c.PKI.RootKeyAlg),
		RootSubject: &nodev1.Subject{
			CommonName:   c.PKI.RootSubject.CommonName,
			Organization: c.PKI.RootSubject.Organization,
			Country:      c.PKI.RootSubject.Country,
			Province:     c.PKI.RootSubject.Province,
			Locality:     c.PKI.RootSubject.Locality,
		},
		RootValidityYears:            c.PKI.RootValidityYears,
		PathLenConstraint:            c.PKI.PathLenConstraint,
		Profiles:                     profilesToProto(c.PKI.Profiles),
		RevocationBaseUrl:            c.PKI.RevocationBaseURL,
		AllowUnverifiedRevocationUrl: c.PKI.AllowUnverifiedRevocationURL,
		CrlNextUpdateHours:           c.PKI.CRLNextUpdateHours,
		RevocationHttpPort:           c.PKI.RevocationHTTPPort,
		RootLeafIssuance:             c.PKI.RootLeafIssuance,
		Acme:                         acmeToProto(c.PKI.ACME, c.PKI.DisabledACME),
		Est:                          estToProto(c.PKI.EST, c.PKI.DisabledEST),
		AllowUnsyncedClock:           c.PKI.AllowUnsyncedClock,
		Scep:                         scepToProto(c.PKI.SCEP),
		Tsa:                          tsaToProto(c.PKI.TSA, c.PKI.DisabledTSA),
	}
	if c.PKI.Parent != nil {
		pki.Parent = &nodev1.Parent{
			CaCertPem:    c.PKI.Parent.CACertPEM,
			CaCertSha256: c.PKI.Parent.CACertSHA256,
		}
	}
	stateKey := &nodev1.StateKey{Mode: c.StateKey.Mode}
	if c.StateKey.KMS != nil {
		stateKey.Kms = &nodev1.KmsStateKey{
			Endpoint: c.StateKey.KMS.Endpoint,
			TrustPem: c.StateKey.KMS.TrustPEM,
		}
	}
	var management *nodev1.Management
	if c.Management != nil {
		management = &nodev1.Management{
			ManagerCn:               c.Management.ManagerCN,
			TrustPem:                c.Management.TrustPEM,
			OperatorSurfaceReadonly: c.Management.OperatorSurfaceReadonly,
		}
	}
	return &nodev1.MachineConfig{
		ApiVersion: c.APIVersion,
		Kind:       c.Kind,
		Metadata: &nodev1.Metadata{
			Name: c.Metadata.Name,
		},
		Role: &nodev1.Role{
			Kind: string(c.Role.Kind),
		},
		Network: &nodev1.Network{
			Interface:   c.Network.Interface,
			Address:     c.Network.Address,
			Gateway:     c.Network.Gateway,
			Nameservers: c.Network.Nameservers,
			Search:      c.Network.Search,
			NtpServers:  c.Network.NTPServers,
		},
		Bootstrap: &nodev1.Bootstrap{
			AdminCertPem:    c.Bootstrap.AdminCertPEM,
			AdminCertSha256: c.Bootstrap.AdminCertSHA256,
		},
		Pki: pki,
		Install: &nodev1.Install{
			Disk: c.Install.Disk,
		},
		StateKey:   stateKey,
		Management: management,
	}
}

// profilesToProto maps the Go certificate profiles to their proto form. A nil
// or empty input yields a nil slice so the round-trip is stable.
func profilesToProto(in []CertificateProfile) []*nodev1.CertificateProfile {
	if len(in) == 0 {
		return nil
	}
	out := make([]*nodev1.CertificateProfile, len(in))
	for i, p := range in {
		out[i] = &nodev1.CertificateProfile{
			Name:   p.Name,
			KeyAlg: string(p.KeyAlg),
			Subject: &nodev1.Subject{
				CommonName:   p.Subject.CommonName,
				Organization: p.Subject.Organization,
				Country:      p.Subject.Country,
			},
			ValidityDays: p.ValidityDays,
			BasicConstraints: &nodev1.BasicConstraints{
				IsCa:    p.BasicConstraints.IsCA,
				PathLen: p.BasicConstraints.PathLen,
			},
			KeyUsage:    p.KeyUsage,
			ExtKeyUsage: p.ExtKeyUsage,
			Sans: &nodev1.SubjectAltNames{
				Dns:           p.SANs.DNS,
				Ip:            p.SANs.IP,
				Email:         p.SANs.Email,
				Uri:           p.SANs.URI,
				Krb5Principal: p.SANs.KRB5Principal,
				Upn:           p.SANs.UPN,
			},
			ExtraExtensions:  extraExtensionsToProto(p.ExtraExtensions),
			AllowRequestSans: p.AllowRequestSANs,
			ValidityPolicy:   string(p.ValidityPolicy),
		}
	}
	return out
}

func extraExtensionsToProto(in []X509Extension) []*nodev1.X509Extension {
	if len(in) == 0 {
		return nil
	}
	out := make([]*nodev1.X509Extension, len(in))
	for i, e := range in {
		out[i] = &nodev1.X509Extension{
			Oid:      e.OID,
			Critical: e.Critical,
			Value:    e.Value,
		}
	}
	return out
}

// profilesFromProto is the inverse of profilesToProto. Nil nested messages are
// guarded so a sparse proto does not panic.
func profilesFromProto(in []*nodev1.CertificateProfile) []CertificateProfile {
	if len(in) == 0 {
		return nil
	}
	out := make([]CertificateProfile, len(in))
	for i, p := range in {
		if p == nil {
			continue
		}
		prof := CertificateProfile{
			Name:             p.Name,
			KeyAlg:           RootKeyAlg(p.KeyAlg),
			ValidityDays:     p.ValidityDays,
			KeyUsage:         p.KeyUsage,
			ExtKeyUsage:      p.ExtKeyUsage,
			AllowRequestSANs: p.AllowRequestSans,
			ValidityPolicy:   ValidityPolicy(p.ValidityPolicy),
		}
		if p.Subject != nil {
			prof.Subject.CommonName = p.Subject.CommonName
			prof.Subject.Organization = p.Subject.Organization
			prof.Subject.Country = p.Subject.Country
		}
		if p.BasicConstraints != nil {
			prof.BasicConstraints.IsCA = p.BasicConstraints.IsCa
			prof.BasicConstraints.PathLen = p.BasicConstraints.PathLen
		}
		if p.Sans != nil {
			prof.SANs.DNS = p.Sans.Dns
			prof.SANs.IP = p.Sans.Ip
			prof.SANs.Email = p.Sans.Email
			prof.SANs.URI = p.Sans.Uri
			prof.SANs.KRB5Principal = p.Sans.Krb5Principal
			prof.SANs.UPN = p.Sans.Upn
		}
		prof.ExtraExtensions = extraExtensionsFromProto(p.ExtraExtensions)
		out[i] = prof
	}
	return out
}

func extraExtensionsFromProto(in []*nodev1.X509Extension) []X509Extension {
	if len(in) == 0 {
		return nil
	}
	out := make([]X509Extension, len(in))
	for i, e := range in {
		if e == nil {
			continue
		}
		out[i] = X509Extension{
			OID:      e.Oid,
			Critical: e.Critical,
			Value:    e.Value,
		}
	}
	return out
}
