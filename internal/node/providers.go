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
	"errors"
	"fmt"
	"log"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"github.com/CryptOS-PKI/cryptos-node/internal/config"
)

// IdentityProvider adapts a Store to the grpc.Identity interface.
type IdentityProvider struct {
	store *Store
}

// NewIdentityProvider returns an IdentityProvider over store.
func NewIdentityProvider(store *Store) *IdentityProvider {
	return &IdentityProvider{store: store}
}

// Get returns the node's Identity, or ErrNoIdentity before the ceremony
// has committed. The gRPC layer maps the error to FAILED_PRECONDITION.
func (p *IdentityProvider) Get(ctx context.Context) (*nodev1.Identity, error) {
	return p.store.Identity(ctx)
}

// StatusConfig configures a StatusProvider. Store and Role are required;
// the health functions are optional and default to OK when nil.
type StatusConfig struct {
	// Store reads phase + boot count.
	Store *Store
	// Role is the node's configured role.
	Role nodev1.NodeRole
	// SoftwareVersion is the running build's version string.
	SoftwareVersion string
	// TPMState reports live TPM health; nil defaults to TPM_STATE_OK.
	TPMState func() nodev1.TpmState
	// EtcdState reports live datastore health; nil defaults to ETCD_STATE_OK.
	EtcdState func() nodev1.EtcdState
	// RevocationPreflight reports the latest revocation preflight; nil leaves
	// NodeStatus.revocation_preflight unset.
	RevocationPreflight func() *nodev1.RevocationPreflight
	// Resolver reports the DNS resolver written at boot; nil leaves
	// NodeStatus.resolver unset.
	Resolver func() *nodev1.ResolverStatus
	// BootConfig is the machine config this boot started from. Nil (a
	// maintenance boot, or a test) leaves NodeStatus.protocols unset and
	// config_reboot_pending false.
	BootConfig *config.Config
	// ConfigFile is the stored machine config, read per GetStatus and
	// compared with BootConfig: an ApplyConfig lands there and takes effect
	// only at the next boot.
	ConfigFile *config.FileStore
	// ProtocolRunning reports whether a protocol's listener started this
	// boot; nil reports every protocol as not running.
	ProtocolRunning func(nodev1.ServiceProtocol) bool
	// TimeSync reports the SNTP clock synchronisation state; nil leaves
	// NodeStatus.time_sync unset.
	TimeSync func() *nodev1.TimeSyncStatus
}

// StatusProvider adapts a Store + live health probes to grpc.StatusProvider.
type StatusProvider struct {
	cfg StatusConfig
}

// NewStatusProvider returns a StatusProvider. Returns an error if Store
// is nil.
func NewStatusProvider(cfg StatusConfig) (*StatusProvider, error) {
	if cfg.Store == nil {
		return nil, errors.New("node: NewStatusProvider: Store is required")
	}
	return &StatusProvider{cfg: cfg}, nil
}

// Status builds the live NodeStatus.
func (p *StatusProvider) Status(ctx context.Context) (*nodev1.NodeStatus, error) {
	phase, err := p.cfg.Store.Phase(ctx)
	if err != nil {
		return nil, err
	}
	bootCount, err := p.cfg.Store.BootCount(ctx)
	if err != nil {
		return nil, err
	}
	tpmState := nodev1.TpmState_TPM_STATE_OK
	if p.cfg.TPMState != nil {
		tpmState = p.cfg.TPMState()
	}
	etcdState := nodev1.EtcdState_ETCD_STATE_OK
	if p.cfg.EtcdState != nil {
		etcdState = p.cfg.EtcdState()
	}
	var preflight *nodev1.RevocationPreflight
	if p.cfg.RevocationPreflight != nil {
		preflight = p.cfg.RevocationPreflight()
	}
	var resolver *nodev1.ResolverStatus
	if p.cfg.Resolver != nil {
		resolver = p.cfg.Resolver()
	}
	protocols, rebootPending := p.protocols()
	var timeSync *nodev1.TimeSyncStatus
	if p.cfg.TimeSync != nil {
		timeSync = p.cfg.TimeSync()
	}
	return &nodev1.NodeStatus{
		Role:            p.cfg.Role,
		IdentityState:   phase.IdentityState(),
		TpmState:        tpmState,
		EtcdState:       etcdState,
		BootCount:       bootCount,
		SoftwareVersion: p.cfg.SoftwareVersion,
		// Thin M4: no Fleet Manager endpoint concept yet, so a node is not
		// enrolled. The real connected/disconnected signal arrives with the
		// future Fleet Manager enrollment spec.
		FleetManager:        nodev1.FleetManagerState_FLEET_MANAGER_STATE_NOT_ENROLLED,
		RevocationPreflight: preflight,
		Resolver:            resolver,
		Protocols:           protocols,
		ConfigRebootPending: rebootPending,
		TimeSync:            timeSync,
	}, nil
}

// protocols reports each enrolment protocol's configured and running state,
// and whether the stored config holds a reboot-required change this boot has
// not taken up. Configured comes from the stored config, because that is what
// the next boot starts; running comes from this boot.
//
// A stored config that cannot be read or parsed is reported against the boot
// config with the pending flag set: the next boot would not start from what
// is running now either way, since an unparseable config drops the node to
// maintenance.
func (p *StatusProvider) protocols() ([]*nodev1.ProtocolStatus, bool) {
	boot := p.cfg.BootConfig
	if boot == nil {
		return nil, false
	}
	stored, err := p.storedConfig()
	pending := false
	if err != nil {
		log.Printf("status: read the stored config: %v (reporting a pending reboot)", err)
		stored, pending = boot, true
	} else {
		pending = config.NeedsReboot(boot, stored)
	}
	running := func(proto nodev1.ServiceProtocol) bool {
		return p.cfg.ProtocolRunning != nil && p.cfg.ProtocolRunning(proto)
	}
	out := []*nodev1.ProtocolStatus{
		{
			Protocol:      nodev1.ServiceProtocol_SERVICE_PROTOCOL_ACME,
			Configured:    stored.PKI.ACME != nil,
			Running:       running(nodev1.ServiceProtocol_SERVICE_PROTOCOL_ACME),
			RebootPending: !config.Equivalent(boot.PKI.ACME, stored.PKI.ACME),
		},
		{
			Protocol:      nodev1.ServiceProtocol_SERVICE_PROTOCOL_EST,
			Configured:    stored.PKI.EST != nil,
			Running:       running(nodev1.ServiceProtocol_SERVICE_PROTOCOL_EST),
			RebootPending: !config.Equivalent(boot.PKI.EST, stored.PKI.EST),
		},
		{
			Protocol:      nodev1.ServiceProtocol_SERVICE_PROTOCOL_SCEP,
			Configured:    stored.PKI.SCEP != nil,
			Running:       running(nodev1.ServiceProtocol_SERVICE_PROTOCOL_SCEP),
			RebootPending: !config.Equivalent(boot.PKI.SCEP, stored.PKI.SCEP),
		},
		{
			Protocol:      nodev1.ServiceProtocol_SERVICE_PROTOCOL_TSA,
			Configured:    stored.PKI.TSA != nil,
			Running:       running(nodev1.ServiceProtocol_SERVICE_PROTOCOL_TSA),
			RebootPending: !config.Equivalent(boot.PKI.TSA, stored.PKI.TSA),
		},
	}
	return out, pending
}

func (p *StatusProvider) storedConfig() (*config.Config, error) {
	if p.cfg.ConfigFile == nil {
		return nil, errors.New("no config store wired")
	}
	raw, _, ok, err := p.cfg.ConfigFile.Read()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("no config stored")
	}
	return config.Parse(raw)
}

// ConfigStore adapts a config.FileStore to the grpc.ConfigStore interface.
type ConfigStore struct {
	fs *config.FileStore

	// issuer returns this node's CA certificate, so Apply can warn about
	// profiles that outlive it. Nil until WithIssuer; Apply then skips the
	// check.
	issuer IssuerFunc

	// sealedStateKeyMode is the mode the node's state volume was sealed with.
	// Empty until WithSealedStateKeyMode; Apply then skips the check.
	sealedStateKeyMode string
}

// NewConfigStore returns a ConfigStore backed by fs.
func NewConfigStore(fs *config.FileStore) *ConfigStore {
	return &ConfigStore{fs: fs}
}

// WithIssuer wires this node's CA certificate getter and returns the same
// ConfigStore for chaining. Apply then warns about every profile whose
// validity_days already runs past that certificate's notAfter.
func (c *ConfigStore) WithIssuer(issuer IssuerFunc) *ConfigStore {
	c.issuer = issuer
	return c
}

// WithSealedStateKeyMode records the mode the node's state volume was sealed
// with and returns the same ConfigStore for chaining. Apply then refuses a
// config naming another state_key.mode with codes.FailedPrecondition, because
// init reads the mode from the volume and would ignore it.
func (c *ConfigStore) WithSealedStateKeyMode(mode string) *ConfigStore {
	c.sealedStateKeyMode = mode
	return c
}

// ErrNoConfig is returned by ConfigStore.Current before any config has been
// persisted. It carries codes.FailedPrecondition, because the node is not
// ready rather than broken, so gRPC handlers can tell it apart from a genuine
// read failure by code without importing this package.
var ErrNoConfig = status.Error(codes.FailedPrecondition, "node: no config persisted yet")

// Current returns the node's currently persisted machine config, parsed and
// converted to its proto representation with the protocol secrets blanked
// (they are write-only; Apply keeps them by identifier). It returns
// ErrNoConfig if no config has been written yet: GetConfig and SetManagement
// have nothing to read or merge into before the first ApplyConfig/install has
// persisted one.
func (c *ConfigStore) Current(ctx context.Context) (*nodev1.MachineConfig, error) {
	raw, _, ok, err := c.fs.Read()
	if err != nil {
		return nil, fmt.Errorf("node: Current: %w", err)
	}
	if !ok {
		return nil, ErrNoConfig
	}
	parsed, err := config.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("node: Current: parse: %w", err)
	}
	return parsed.ToProtoRedacted(), nil
}

// Apply converts cfg to YAML, validates it, persists it via the FileStore,
// and returns the new generation, digest, and whether a reboot is required.
//
// The enrolment protocol blocks are resolved against the stored config (see
// config.FromProtoOver): a block the caller left out is kept, and an empty
// secret keeps the stored one for the same identifier. Every protocol change
// is reboot-required, because the listeners start only at boot.
//
// A config that fails the schema rules is rejected with codes.InvalidArgument
// and nothing is written: the store's generation and contents are unchanged.
// This is a live CA, so fail closed -- profiles are read live for signing, and
// everything else is only checked again by config.Parse on the next boot.
func (c *ConfigStore) Apply(ctx context.Context, cfg *nodev1.MachineConfig) (*nodev1.ApplyConfigResponse, error) {
	if cfg == nil {
		return nil, status.Error(codes.InvalidArgument, "node: Apply: nil config")
	}

	// Read the current config before anything is written. It serves two
	// purposes: resolving the protocol blocks and secrets the caller left to
	// the node, and classifying whether the change needs a reboot.
	//
	// Classify BEFORE overwriting: a change limited to the hot-reconfigurable
	// fields (cert profiles, root-leaf-issuance acknowledgement, revocation
	// preflight override, clock-gate override) takes effect live for signing,
	// so the caller need not reboot. Any other change — or a
	// first apply with no prior config — requires a reboot. Fail safe to reboot
	// if the current config cannot be read or parsed.
	var oldCfg *config.Config
	if oldRaw, _, ok, rerr := c.fs.Read(); rerr == nil && ok {
		if prev, perr := config.Parse(oldRaw); perr == nil {
			oldCfg = prev
		} else {
			log.Printf("node: Apply: stored config does not parse, nothing to keep from it: %v", perr)
		}
	}
	parsed, err := config.FromProtoOver(cfg, oldCfg)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "node: Apply: %v", err)
	}
	if c.sealedStateKeyMode != "" {
		if err := parsed.StateKey.CheckSealed(c.sealedStateKeyMode); err != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "node: Apply: %v", err)
		}
	}
	requiresReboot := config.NeedsReboot(oldCfg, parsed)
	log.Printf("node: Apply: acme=%t est=%t scep=%t requires_reboot=%t", parsed.PKI.ACME != nil, parsed.PKI.EST != nil, parsed.PKI.SCEP != nil, requiresReboot)

	// Validate exactly what will be written: after the protocol blocks are
	// resolved, so a kept ACME or EST block is checked against the incoming
	// profiles, and before anything touches the store.
	if err := parsed.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "node: Apply: validate: %v", err)
	}

	raw, err := parsed.Marshal()
	if err != nil {
		return nil, fmt.Errorf("node: Apply: marshal: %w", err)
	}

	gen, err := c.fs.Write(raw)
	if err != nil {
		return nil, fmt.Errorf("node: Apply: persist: %w", err)
	}
	digest := sha256.Sum256(raw)
	return &nodev1.ApplyConfigResponse{
		Generation:     gen,
		RequiresReboot: requiresReboot,
		ConfigDigest:   digest[:],
		Warnings:       c.validityWarnings(ctx, parsed),
	}, nil
}

// validityWarnings returns the profiles in cfg that outlive this node's CA
// certificate. A node without one yet (before its ceremony, or a subordinate
// still awaiting its parent's signature) has nothing to compare against, so
// an issuer error yields no warnings rather than failing an apply that has
// already been persisted.
func (c *ConfigStore) validityWarnings(ctx context.Context, cfg *config.Config) []string {
	if c.issuer == nil {
		return nil
	}
	issuer, err := c.issuer(ctx)
	if err != nil {
		return nil
	}
	return cfg.ProfileValidityWarnings(issuer, time.Now())
}
