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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/go-tpm/tpm2"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"github.com/CryptOS-PKI/cryptos-node/internal/acme"
	"github.com/CryptOS-PKI/cryptos-node/internal/audit"
	"github.com/CryptOS-PKI/cryptos-node/internal/bootstrap"
	"github.com/CryptOS-PKI/cryptos-node/internal/buildinfo"
	"github.com/CryptOS-PKI/cryptos-node/internal/ceremony"
	"github.com/CryptOS-PKI/cryptos-node/internal/config"
	"github.com/CryptOS-PKI/cryptos-node/internal/console"
	"github.com/CryptOS-PKI/cryptos-node/internal/est"
	cgrpc "github.com/CryptOS-PKI/cryptos-node/internal/grpc"
	"github.com/CryptOS-PKI/cryptos-node/internal/imageupgrade"
	"github.com/CryptOS-PKI/cryptos-node/internal/init/mounts"
	"github.com/CryptOS-PKI/cryptos-node/internal/init/netlink"
	"github.com/CryptOS-PKI/cryptos-node/internal/node"
	"github.com/CryptOS-PKI/cryptos-node/internal/release"
	"github.com/CryptOS-PKI/cryptos-node/internal/reset"
	"github.com/CryptOS-PKI/cryptos-node/internal/revocation"
	"github.com/CryptOS-PKI/cryptos-node/internal/scep"
	"github.com/CryptOS-PKI/cryptos-node/internal/storage/etcd"
	"github.com/CryptOS-PKI/cryptos-node/internal/storage/luks"
	"github.com/CryptOS-PKI/cryptos-node/internal/tpm"
	"github.com/CryptOS-PKI/cryptos-node/internal/tsa"
)

// resetRebootDelay is the grace period between accepting a Reset and
// restarting the node, so the gRPC ResetResponse flushes to the console
// before the connection drops on reboot.
const resetRebootDelay = 2 * time.Second

// nodeResetter adapts internal/reset to the grpc.Resetter interface. It is
// wired on the local console socket (Reset) and the mTLS server
// (RemoteReset). Reset delegates to reset.Wipe, which checks the confirmation
// CN against the CA CN, erases the state-key material (fail-safe: no reboot on
// an erase error), clears the staged ESP config best-effort, and reboots. On a
// confirm-CN mismatch it returns reset.ErrConfirmMismatch, which the grpc
// handler maps to PermissionDenied; with no CA CN yet it returns
// reset.ErrNoCAIdentity, mapped to FailedPrecondition.
type nodeResetter struct {
	// caCN returns the node's current CA CN, or "" before one exists. It is
	// called per Reset, not captured at boot: a CA certificate installed after
	// the current boot must be confirmable without a reboot first.
	caCN       func() string
	device     reset.Eraser
	clearStage func() error
	reboot     func()
}

// Reset implements grpc.Resetter.
func (r nodeResetter) Reset(ctx context.Context, confirmCommonName string) error {
	return reset.Wipe(ctx, confirmCommonName, reset.Options{
		RootCN:     r.caCN(),
		Device:     r.device,
		ClearStage: r.clearStage,
		Reboot:     r.reboot,
	})
}

// Version is the running build's software version, surfaced via GetStatus.
// It is stamped at build time into internal/buildinfo (scripts/buildinfo.sh);
// an unstamped build reports "dev".
var Version = buildinfo.Version

// StateKeyMode selects the state-key/root-key providers. Default "tpm"; a
// nodeID image sets "nodeid" via -ldflags -X at build time. See
// plan/2026-07-03-nodeid-state-key-design.md.
var StateKeyMode = "tpm"

// cryptsetupBinary is the static cryptsetup shipped in the rootfs.
const cryptsetupBinary = "/sbin/cryptsetup"

// newStateKeyBackends builds the state-key protector and Root-key backend for
// the effective mode. "nodeid" never opens the TPM; "kms" envelope-encrypts the
// state key with an external KMS (software Root key, no TPM); "tpm" opens the
// TPM and fails closed (with a hint) if absent. The sk argument carries the
// mode-specific settings (the kms endpoint/trust bundle) used only on first
// boot; later boots recover from the persisted token. The returned func
// releases the TPM (no-op in the nodeid/kms modes).
func newStateKeyBackends(mode string, sk config.StateKey) (StateKeyProtector, ceremony.RootKeyBackend, func(), nodev1.TpmState, error) {
	switch mode {
	case config.StateKeyModeNodeID:
		return newNodeIDProtector(readProductUUID, StateLabel), softRootBackend{},
			func() {}, nodev1.TpmState_TPM_STATE_UNAVAILABLE, nil
	case config.StateKeyModeKMS:
		prot, err := newKMSProtector(sk.KMS)
		if err != nil {
			return nil, nil, func() {}, nodev1.TpmState_TPM_STATE_UNAVAILABLE, fmt.Errorf("init: kms state key: %w", err)
		}
		return prot, softRootBackend{}, func() {}, nodev1.TpmState_TPM_STATE_UNAVAILABLE, nil
	}
	tp, err := tpm.Open("")
	if err != nil {
		return nil, nil, func() {}, nodev1.TpmState_TPM_STATE_UNAVAILABLE,
			fmt.Errorf("init: open TPM: %w (if this host cannot provide a vTPM, use the nodeID image variant)", err)
	}
	caps, err := tp.Probe()
	if err != nil {
		_ = tp.Close()
		return nil, nil, func() {}, nodev1.TpmState_TPM_STATE_UNAVAILABLE, fmt.Errorf("init: probe TPM: %w", err)
	}
	log.Printf("init: TPM capabilities: ECC curves %v, RSA key sizes %v", caps.LoadedCurves, caps.RSAKeyBits)
	if !caps.SupportsCurve(tpm2.TPMECCNistP384) {
		_ = tp.Close()
		return nil, nil, func() {}, nodev1.TpmState_TPM_STATE_INSUFFICIENT_CAPABILITY,
			errors.New("init: TPM does not advertise ECDSA P-384")
	}
	return newTPMProtector(tp, tpm.DefaultSealPCRs), tpmRootBackend{tp},
		func() { _ = tp.Close() }, nodev1.TpmState_TPM_STATE_OK, nil
}

// Boot runs the full PID 1 bring-up sequence and blocks serving the
// management API until a shutdown is requested (the Reboot RPC, SIGTERM,
// Ctrl-Alt-Del, or the ACPI power button). It returns once the orderly
// teardown has run, with the action PID 1 should then ask the kernel for.
// Every step is fail-closed: any error returns and PID 1 reboots (there is
// no recovery shell).
//
// NOTE: this is device-level I/O and only runs on a Linux node with a
// TPM; on a dev host the platform helpers fail fast. Runtime validation
// is the QEMU + swtpm integration boot.
func Boot(ctx context.Context) (ShutdownAction, error) {
	shutdown := newShutdownRequests()
	err := boot(ctx, shutdown)

	return shutdown.Action(), err
}

func boot(ctx context.Context, shutdown *shutdownRequests) (err error) {
	// 1. Early kernel mounts (must precede /dev-dependent steps).
	if err := mounts.EarlyMounts(); err != nil {
		return err
	}

	// Route verbose stdlib logging to the kernel ring buffer now that devtmpfs
	// has created /dev/kmsg. This must happen after EarlyMounts and before the
	// first log.Printf below, otherwise the lines fall through to init's stderr
	// and clutter the branded console= device on prod.
	routeVerboseLogs()
	bi := buildinfo.Get()
	log.Printf("cryptos %s (commit %s, built %s)", bi.Version, bi.Commit, bi.BuildDate)

	// Branded boot: open the console and render the shield once. Each bring-up
	// step below marks its status. Best-effort: if the console cannot be opened,
	// step is a no-op and boot proceeds unchanged.
	var scr *console.Renderer
	if cons, err := openConsole(); err == nil {
		scr = console.NewRenderer(cons)
		_ = scr.Banner()
	}
	// Branded per-stage progress. begin marks a stage as in progress; done marks
	// it complete with [ok]. If Boot returns an error before done() (a fail-closed
	// reboot; there is no shell to inspect), the deferred renderer surfaces [!!]
	// on the stage that was running, so the console shows WHERE boot died.
	var currentStep string
	begin := func(name string) { currentStep = name }
	done := func() {
		if scr != nil && currentStep != "" {
			_ = scr.Step(currentStep, console.StepOK)
		}
		currentStep = ""
	}
	defer func() {
		if err != nil && scr != nil && currentStep != "" {
			_ = scr.Step(currentStep, console.StepFail)
		}
	}()

	// 2. Derive paths; probe for the state partition before touching the TPM.
	// Maintenance mode: no cryptos-state partition means nothing is installed
	// (booted from the ISO). Serve the limited maintenance API instead of the
	// normal TPM/LUKS/ceremony bring-up. Probe before the TPM step so a VM with
	// no vTPM still enters maintenance cleanly.
	paths := DerivePaths()
	if stateDeviceMissing(StateLabel) {
		return runMaintenance(ctx)
	}
	begin("state volume")

	// 3. Resolve the state partition by its GPT name via sysfs (the image has no
	// udev, so the by-partlabel symlinks never exist); devtmpfs has created the
	// /dev node. First-boot is decided from the partition itself (!IsLUKS), not
	// from config, because config does not exist yet.
	stateDevice, err := resolveStateDevice(StateLabel)
	if err != nil {
		return err
	}
	paths.Device = stateDevice
	dev := &luks.Device{Path: paths.Device, Runner: &luks.ExecRunner{Binary: cryptsetupBinary}}

	// 4. State-key + Root-key backends (TPM-sealed by default; nodeID/software
	// or KMS-wrapped for the TPM-less variants), then open (or first-boot-format)
	// the encrypted state volume with them.
	st, err := stateUnlocker{
		device: dev, stage: realESPStageAccessors(),
		buildDefault: StateKeyMode, newBackends: newStateKeyBackends,
	}.unlock(ctx)
	if err != nil {
		return err
	}
	defer st.close()
	log.Printf("state key mode: %s", st.protector.Name())
	mode, rootBackend, tpmState, vol, firstBoot := st.mode, st.root, st.tpmState, st.vol, st.firstBoot
	if firstBoot {
		if err := mkfsExt4(vol.Path); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(paths.Mount, 0o700); err != nil {
		return fmt.Errorf("init: mkdir %s: %w", paths.Mount, err)
	}
	if err := mountFS(vol.Path, paths.Mount, "ext4"); err != nil {
		return err
	}
	// Registered first so it runs last: every store on the state filesystem
	// (etcd, the audit log) is closed by the time it is unmounted and locked.
	defer func() {
		if cerr := closeStateVolume(context.Background(), paths.Mount, unmountFS, vol); cerr != nil {
			log.Printf("shutdown: %v", cerr)
		}
	}()
	done()
	begin("configuration")
	// paths.ConfigDir is intentionally not created here — config.FileStore.Write
	// creates it (MkdirAll) when it first persists, and the read path tolerates
	// its absence (missing dir reads as "no config yet").
	for _, d := range []string{paths.EtcdDir, paths.AuditDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("init: mkdir %s: %w", d, err)
		}
	}

	// 5. Load machine config from the state fs. Precedence: persisted config →
	// ESP-staged config (seeded by the installer at EFI/cryptos/machine.yaml).
	// Missing or unparseable config on an already-installed node drops to
	// maintenance mode.
	cfgStore := config.NewFileStore(paths.ConfigDir)
	cfg, err := loadOrSeedConfig(cfgStore, realESPStageAccessors())
	if err != nil {
		if errors.Is(err, errEnterMaintenance) {
			// The state partition exists (the early stateDeviceMissing ISO path
			// was not taken) but holds no config: this is the re-provision
			// landing after a console Reset. Serve re-provision maintenance,
			// which persists the applied config to the mounted state and reboots
			// into the ceremony, rather than the bare-disk installer.
			log.Printf("REPROVISION: %v", err)
			return runReprovisionMaintenance(ctx, cfgStore, mode)
		}
		return err
	}
	if err := cfg.StateKey.CheckSealed(mode); err != nil {
		log.Printf("state key: %v; using the sealed mode", err)
	}
	done()
	begin("network")

	// 6. Apply config-dependent bring-up. Early connectivity (if needed before
	// this point) is provided by kernel ip=dhcp; the static apply is idempotent.
	if err := netlink.BringUpLoopback(); err != nil {
		return err
	}
	if err := setHostname(cfg.Metadata.Name); err != nil {
		return err
	}
	nlCfg, err := networkConfig(cfg)
	if err != nil {
		return err
	}
	if err := netlink.ConfigureInterface(nlCfg); err != nil {
		return err
	}
	// The resolver comes from network.nameservers, else from the kernel DHCP
	// lease. Without one no hostname resolves, and a hostname
	// pki.revocation_base_url then blocks all issuance (#233). A failure here
	// is logged, not fatal: the node stays manageable, and the revocation
	// preflight still refuses issuance while the name does not resolve.
	resolver, err := configureResolver(cfg.Network)
	if err != nil {
		log.Printf("init: resolver: %v", err)
	}
	done()
	begin("clock")

	// 6b. Time sync. It needs the network and the resolver (a hostname server)
	// and runs before etcd, the listeners and signing, so etcd leases, TLS
	// validity and issued dates all start on corrected time. The boot sync is
	// bounded and never fails the boot; while a configured source has not
	// synced, the CA signer refuses to sign (see wireClockGate). The floor is
	// recorded on the way down, before the state volume is closed.
	timeSync := startTimeSync(ctx, cfg.Network, paths.Mount)
	go timeSync.Run(ctx)
	defer timeSync.Shutdown()
	done()
	begin("embedded etcd")

	// 7. Master seed (audit + ceremony signing keys derive from it).
	seed, err := LoadOrCreateSeed(paths.Seed)
	if err != nil {
		return err
	}

	// 8. Embedded etcd + state store.
	es, err := etcd.Open(paths.EtcdDir)
	if err != nil {
		return fmt.Errorf("init: start etcd: %w", err)
	}
	done()
	begin("management API")
	defer func() {
		if cerr := es.Close(); cerr != nil {
			log.Printf("shutdown: close etcd: %v", cerr)
		} else {
			log.Printf("shutdown: etcd closed")
		}
	}()
	cli, err := es.Client()
	if err != nil {
		return fmt.Errorf("init: etcd client: %w", err)
	}
	defer func() { _ = cli.Close() }()
	store, err := node.New(cli)
	if err != nil {
		return err
	}
	if _, err := store.IncrementBootCount(ctx); err != nil {
		return fmt.Errorf("init: boot count: %w", err)
	}

	// 8b. Subordinate first-boot key + CSR. On an intermediate/issuing node with
	// no identity yet, generate the CA key and stage the CSR, entering
	// awaiting-cert; the node then serves the CSR and waits for a parent-signed
	// chain. A Root, or a subordinate already awaiting-cert or established, is a
	// no-op here and loads normally. The Root self-signing ceremony is never run
	// for a subordinate.
	if err := stageSubordinateIfNeeded(ctx, cfg, store, rootBackend); err != nil {
		return err
	}

	// 9. Bootstrap admin trust + audit log.
	trust, err := bootstrap.LoadTrust(cfg.Bootstrap.AdminCertPEM, cfg.Bootstrap.AdminCertSHA256)
	if err != nil {
		return err
	}
	logger, err := audit.Open(paths.AuditDir, seed)
	if err != nil {
		return fmt.Errorf("init: open audit: %w", err)
	}
	defer func() {
		if cerr := logger.Close(); cerr != nil {
			log.Printf("shutdown: close the audit log: %v", cerr)
		} else {
			log.Printf("shutdown: audit log closed")
		}
	}()

	// 10. Providers + ceremony engine, shared by both listeners.
	//
	// The revocation preflight is built here so GetStatus can report it; it is
	// driven after the revocation listener is up (below) and consumed by the
	// CA signer. GetStatus also reports the resolver written above.
	preflight := revocation.NewPreflight(cfg.PKI.RevocationBaseURL, revocation.DefaultResolver, revocation.DefaultProbe)
	// The enrolment listeners start once, below, from this boot's config. A
	// protocol switched by ApplyConfig waits for the next boot, and GetStatus
	// shows it configured but not running until then.
	var acmeRunning, estRunning, scepRunning, tsaRunning atomic.Bool
	statusProv, err := node.NewStatusProvider(node.StatusConfig{
		Store:           store,
		Role:            cfg.NodeRole(),
		SoftwareVersion: Version,
		TPMState:        func() nodev1.TpmState { return tpmState },
		RevocationPreflight: func() *nodev1.RevocationPreflight {
			return revocationPreflightStatus(cfg.PKI.RevocationBaseURL, preflight)
		},
		Resolver:   func() *nodev1.ResolverStatus { return resolver },
		BootConfig: cfg,
		ConfigFile: cfgStore,
		ProtocolRunning: func(p nodev1.ServiceProtocol) bool {
			switch p {
			case nodev1.ServiceProtocol_SERVICE_PROTOCOL_ACME:
				return acmeRunning.Load()
			case nodev1.ServiceProtocol_SERVICE_PROTOCOL_EST:
				return estRunning.Load()
			case nodev1.ServiceProtocol_SERVICE_PROTOCOL_SCEP:
				return scepRunning.Load()
			case nodev1.ServiceProtocol_SERVICE_PROTOCOL_TSA:
				return tsaRunning.Load()
			default:
				return false
			}
		},
		TimeSync: timeSync.Status,
	})
	if err != nil {
		return err
	}
	eng, err := ceremony.New(ceremony.Config{RootKey: rootBackend, Store: store, ConfigStore: cfgStore, Trust: trust, Seed: seed})
	if err != nil {
		return err
	}
	issuerFunc := func(ctx context.Context) (*x509.Certificate, error) {
		id, err := store.Identity(ctx)
		if err != nil {
			return nil, err
		}
		if len(id.ChainDer) == 0 {
			return nil, errors.New("init: identity has no certificate chain")
		}
		return x509.ParseCertificate(id.ChainDer[0])
	}
	baseCfg := func() cgrpc.ServerConfig {
		return cgrpc.ServerConfig{
			Auditor:     logger,
			AuditLog:    logger,
			Identity:    node.NewIdentityProvider(store),
			Status:      statusProv,
			Ceremony:    eng,
			ConfigStore: node.NewConfigStore(cfgStore).WithIssuer(issuerFunc).WithSealedStateKeyMode(mode),
		}
	}

	// CA signing service backing the P3a signing RPCs. The CA key is never held
	// after boot: the loader re-reads the persisted key blobs and reloads them
	// through the same RootKeyBackend the ceremony provisioned with (the TPM in
	// tpm mode, the software backend in nodeID mode), returning a Close for the
	// handler to release once signing completes. The issuer getter parses this
	// node's own committed CA certificate; the config getter returns the loaded
	// machine config so profile lookups and the ROOT leaf-issuance ack are read
	// from the live config. The signers are wired only into the management
	// listeners below; the maintenance/reprovision servers never see them, so the
	// signing RPCs refuse there.
	keyLoader := func(ctx context.Context) (crypto.Signer, func(), error) {
		priv, pub, ok, err := store.RootKeyBlobs(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("init: read CA key blobs: %w", err)
		}
		if !ok {
			return nil, nil, errors.New("init: no CA key material (ceremony not committed)")
		}
		signer, err := rootBackend.LoadKey(priv, pub)
		if err != nil {
			return nil, nil, fmt.Errorf("init: load CA key: %w", err)
		}
		return signer, func() { _ = signer.Close() }, nil
	}
	// The signer reads the LIVE on-disk config, not the boot snapshot, so an
	// ApplyConfig change on a running node (a new/updated cert profile, the
	// root-leaf-issuance acknowledgement, the revocation preflight override,
	// the clock-gate override) takes effect for signing immediately
	// without a reboot. Fall back to the boot config if the store is briefly
	// unreadable; install-level fields (network/disk/role/state key) are still
	// only consumed at boot, so reading them live here is harmless.
	configFunc := func(context.Context) (*config.Config, error) {
		raw, _, ok, err := cfgStore.Read()
		if err != nil || !ok {
			return cfg, nil
		}
		return config.Parse(raw)
	}
	caSigner := node.NewCASigner(keyLoader, issuerFunc, configFunc)

	// FM enrollment challenge-response (Attest RPC): signs a manager-supplied
	// nonce with this node's CA identity key, reloading it through the same
	// keyLoader used for signing. Wired only into the management listeners
	// below; the maintenance/reprovision servers never see it, so Attest
	// returns Unimplemented there.
	attester, err := newAttester(keyLoader)
	if err != nil {
		return fmt.Errorf("init: build attester: %w", err)
	}

	// Revocation engine (CRL + OCSP + issued/revoked store), wired only into the
	// management listeners below. The recorder tracks every issued certificate;
	// the preflight gates CDP/AIA stamping fail-closed; the Revoker revokes and
	// rebuilds the published CRL. The maintenance/reprovision servers never see
	// any of it, so the revocation RPCs and the HTTP listener are management-only.
	revStore := revocation.NewStore(cli)
	crlDur := time.Duration(nonzero(cfg.PKI.CRLNextUpdateHours, defaultCRLNextUpdateHours)) * time.Hour
	crlBuilder := revocation.NewCRLBuilder(revStore, crlDur)
	ocspResp := revocation.NewOCSPResponder(revStore)
	caSigner.WithPreflight(preflight.Ensure).WithRecorder(IssuedRecorder(revStore))
	wireClockGate(caSigner, timeSync)
	revoker := &nodeRevoker{store: revStore, crlBuilder: crlBuilder, load: keyLoader, issuer: issuerFunc,
		chain: func(ctx context.Context) ([][]byte, error) {
			id, err := store.Identity(ctx)
			if err != nil {
				return nil, err
			}
			return id.GetChainDer(), nil
		}}
	// SCEP (RFC 8894) responder, built here so the admin RPCs can be wired
	// into both management listeners; its HTTP listener starts at 12e. It
	// exists only when pki.scep is set in the config this boot started from
	// (Validate refuses it on a Root). A failure to set it up leaves SCEP off
	// for this boot, and the SCEP RPCs answer FailedPrecondition, rather than
	// failing a boot that still has to serve everything else.
	scepSrv, scepRAs := newSCEPServer(ctx, cfg, cli, keyLoader, issuerFunc, caSigner, revStore, revoker, logger)

	// RFC 3161 time-stamp authority, built here so its certificate exists
	// before the listener starts at 12f. It exists only when pki.tsa is on in
	// the config this boot started from (Validate refuses it on a Root). Its
	// key comes from the same backend as the CA key, and its clock gate reads
	// the time-sync engine. A failure to set it up leaves the TSA off for this
	// boot rather than failing the boot. The certificate catalog is served
	// whether or not the TSA runs, so old tokens stay verifiable.
	tsaSvc := newTSAService(ctx, cfg, tsaDeps{
		cli: cli, backend: rootBackend, load: keyLoader, issuer: issuerFunc, revStore: revStore, timeStatus: timeSync.Status,
	})
	tsaCerts := tsaCatalog{store: tsa.NewStore(cli), current: func() (*x509.Certificate, bool) {
		if tsaSvc == nil || !tsaRunning.Load() {
			return nil, false
		}
		return tsaSvc.certs.Current()
	}}

	// Delegated OCSP responder manager: it mints/renews a short-lived responder
	// certificate with this node's CA (loading the CA key only to mint/renew,
	// never per OCSP request) so responses are signed by the responder key, not
	// the CA key. It shares the same key loader + issuer getter used for signing.
	ocspResponderMgr := newOCSPResponder(store, keyLoader, issuerFunc, 0)

	// Subordinate enroller backing the P3b subordinate-ceremony RPCs. It is built
	// only on an intermediate/issuing node: cfg.ParentTrust returns the pinned
	// parent anchor (a Root returns nil, nil). The enroller reads the staged CSR
	// from the store and, on AcceptCertificate, verifies the offered chain roots
	// to that anchor and matches this node's staged key before committing. Like
	// the CA signers it is wired only into the management listeners below; the
	// maintenance/reprovision servers never see it, so the ceremony RPCs refuse
	// there with Unimplemented.
	//
	// The same enroller also backs CA key rotation on an established subordinate
	// (BeginKeyRotation/CompleteKeyRotation): the rekeyer generates a new CA key
	// through the RootKeyBackend, stages it in the store's rotation slot, and on
	// completion delegates the trust decision + atomic swap to the enroller's
	// AcceptRotation. Like the enroller it is built only on a subordinate; a Root
	// leaves it nil so the rotation RPCs return Unimplemented there.
	//
	// The enroller also backs same-key re-certification (GetRenewalCSR /
	// SubmitRenewedCertificate): the renewer signs a CSR with the CURRENT CA key
	// through the same keyLoader the signer uses and, on submit, delegates to the
	// enroller's AcceptRenewal. The signer, CRL, OCSP responder and EST paths all
	// read the issuer certificate through issuerFunc on each use, so a committed
	// renewal takes effect without a reboot. A Root leaves it nil.
	var subEnroller cgrpc.SubordinateEnroller
	var rekeyer cgrpc.Rekeyer
	var renewer cgrpc.Renewer
	parentTrust, err := cfg.ParentTrust()
	if err != nil {
		return fmt.Errorf("init: load parent trust anchor: %w", err)
	}
	if parentTrust != nil {
		enr, err := node.NewSubordinateEnroller(store, parentTrust)
		if err != nil {
			return fmt.Errorf("init: build subordinate enroller: %w", err)
		}
		subEnroller = enr
		rk, err := newRekeyer(store, rootBackend, cfg, enr)
		if err != nil {
			return fmt.Errorf("init: build rekeyer: %w", err)
		}
		rekeyer = rk
		rn, err := NewRenewer(store, keyLoader, enr)
		if err != nil {
			return fmt.Errorf("init: build renewer: %w", err)
		}
		renewer = rn
	}

	// 11. Local UNIX-socket listener (root-only, no TLS). Only this server
	// carries the Resetter, so the unauthenticated local Reset RPC is refused
	// (Unimplemented) on the mTLS listener. The same resetter is also wired to
	// the mTLS server as RemoteResetter below, backing the admin-authorized
	// RemoteReset; that is a separate field so the network-facing server never
	// exposes the local Reset semantics.
	//
	// caCN returns the node's CA leaf CN, read best-effort from the identity
	// provider. It is looked up on every call, never captured here: on the boot
	// that runs the ceremony, or installs a subordinate's certificate, the
	// identity only exists after boot, and the reset, image activate and reboot
	// confirmations must still be checkable then. It is empty before the
	// identity commits; every confirmation then fails closed with
	// reset.ErrNoCAIdentity, which is correct: an unprovisioned node has no key
	// material to wipe and nothing a CN echo could vouch for.
	caCN := func() string {
		id, idErr := node.NewIdentityProvider(store).Get(context.Background())
		if idErr != nil {
			return ""
		}
		return console.RootCN(id)
	}
	rst := nodeResetter{
		caCN:       caCN,
		device:     dev,
		clearStage: realESPStageAccessors().stageDeleter,
		reboot: func() {
			// Reboot off the RPC goroutine after a short grace period so
			// the ResetResponse flushes before the connection drops.
			go func() {
				time.Sleep(resetRebootDelay)
				rebootNode()
			}()
		},
	}
	// Orderly reboot/power-off (Reboot RPC), confirmed by the same CA CN echo.
	rebooter := newNodeRebooter(caCN, shutdown)
	// CA key escrow (export/restore). It is exportable only when the CA key is
	// software-backed (nodeID/KMS state-key modes); a TPM-sealed key is
	// non-exportable, so export is refused in tpm mode. It is wired only into the
	// management listeners below (local + mTLS), never the maintenance servers.
	escrow := newCAEscrow(store, caKeyExportable(mode))

	// In-place image upgrade (#208), so replacing the OS stops meaning a
	// re-provision that destroys the CA key. It needs two things this is the
	// only place to get them:
	//
	// The release certificate this build was signed against. A build without
	// one leaves imageUpgrader nil, so the upgrade RPCs are Unimplemented
	// rather than accepting an image the node cannot attribute. That is the
	// normal state of a development build, so it only logs.
	//
	// The digest of the image the node booted, read here at startup because
	// this is the last moment it is knowable: the file on the boot path is the
	// one the firmware just booted, and it stays that way only until something
	// stages over it. Without it the node could not answer whether a reboot is
	// still outstanding.
	//
	// On a TPM node the state key is sealed to PCR 11, which measures the
	// image, so staging also reseals the key for the incoming image before the
	// ESP is written, and a rollback drops the copy for the image it rolls back
	// from. The other modes do not bind the key to the image.
	var reseal, retarget func(context.Context, []byte, ...[]byte) error
	if mode == config.StateKeyModeTPM {
		resealer := newStateKeyResealer(dev, func() (resealTPM, error) { return tpm.Open("") })
		reseal, retarget = resealer.Reseal, resealer.Retarget
	}
	var imageUpgrader cgrpc.ImageUpgrader
	if releaseCert, relErr := release.Certificate(); relErr != nil {
		log.Printf("image upgrade: disabled (%v)", relErr)
	} else if runningDigest, digErr := digestFile(realESPMounter, imageupgrade.ActiveRelPath); digErr != nil {
		// Fail soft: a node that cannot read its own ESP must still serve PKI.
		// Refusing upgrades is the safe outcome, because the alternative is
		// staging against a partition the node cannot read.
		log.Printf("image upgrade: disabled (read the running image: %v)", digErr)
	} else if iu, iuErr := newImageUpgrader(imageUpgradeOptions{
		CACN:     caCN,
		Mount:    realESPMounter,
		Release:  releaseCert,
		Running:  runningDigest,
		Version:  Version,
		Reseal:   reseal,
		Retarget: retarget,
		Reboot: func() {
			// Reboot off the RPC goroutine after a grace period so the
			// ActivateImageResponse flushes before the connection drops, then
			// take the same orderly shutdown path as the Reboot RPC.
			time.AfterFunc(imageActivateRebootDelay, func() { shutdown.Request(ShutdownReboot) })
		},
	}); iuErr != nil {
		log.Printf("image upgrade: disabled (%v)", iuErr)
	} else {
		imageUpgrader = iu
		log.Printf("image upgrade: ready (running image %s)", runningDigest)
	}

	localCfg := baseCfg()
	localCfg.Resetter = rst
	localCfg.SubordinateSigner = caSigner
	localCfg.LeafSigner = caSigner
	localCfg.SubordinateEnroller = subEnroller
	localCfg.Rekeyer = rekeyer
	localCfg.Renewer = renewer
	localCfg.Revoker = revoker
	localCfg.Exporter = escrow
	localCfg.Importer = escrow
	localCfg.Attester = attester
	localCfg.ImageUpgrader = imageUpgrader
	localCfg.Rebooter = rebooter
	localCfg.Trust = trust
	if scepSrv != nil {
		localCfg.ScepAdmin = scepSrv
	}
	localCfg.TsaCertificates = tsaCerts
	_ = os.Remove(LocalSocketPath)
	localSrv, err := cgrpc.NewLocal(localCfg)
	if err != nil {
		return err
	}
	localLis, err := net.Listen("unix", LocalSocketPath)
	if err != nil {
		return fmt.Errorf("init: listen %s: %w", LocalSocketPath, err)
	}
	go func() { _ = localSrv.Serve(localLis) }()
	defer func() {
		localSrv.Stop()
		log.Printf("shutdown: local API stopped")
	}()

	// 12. mTLS listener on the configured address. It presents the
	// self-signed boot certificate until the node has a CA, then one signed by
	// that CA.
	sans, err := ServerSANs(cfg)
	if err != nil {
		return err
	}
	serverCert, err := GenerateServerCert(sans, cfg.PKI.RootKeyAlg)
	if err != nil {
		return err
	}
	mgmtSANs, err := ManagementSANs(cfg)
	if err != nil {
		return err
	}
	mgmtCert := newManagementCert(managementCertOptions{
		SelfSigned: serverCert,
		Load:       keyLoader,
		Issuer:     issuerFunc,
		Chain: func(ctx context.Context) ([][]byte, error) {
			id, err := store.Identity(ctx)
			if err != nil {
				return nil, err
			}
			return id.GetChainDer(), nil
		},
		Hosts: mgmtSANs,
		Alg:   cfg.PKI.RootKeyAlg,
		HasCA: func(ctx context.Context) bool {
			_, err := store.Identity(ctx)
			return !errors.Is(err, node.ErrNoIdentity)
		},
		// The console shows the fingerprint of the certificate in use so a
		// client's pin can be checked against the node itself. Without the
		// file the console just omits the line, so a failed write never
		// stops the listener.
		Publish: func(c tls.Certificate) error {
			if err := PublishManagementCert(console.ManagementCertPath, c); err != nil {
				return err
			}
			log.Printf("management cert: published %s (sha256 %s, issuer %q)",
				console.ManagementCertPath, console.Fingerprint(c.Leaf.Raw), c.Leaf.Issuer)
			return nil
		},
	})
	defer func() { _ = os.Remove(console.ManagementCertPath) }()
	if err := mgmtCert.refresh(ctx); err != nil {
		log.Printf("management cert: %v", err)
	}
	go mgmtCert.run(ctx, managementCertRefresh)
	tlsCfg, err := managementTLSConfig(mgmtCert, trust)
	if err != nil {
		return err
	}
	mtlsCfg := baseCfg()
	mtlsCfg.TLSConfig = tlsCfg
	mtlsCfg.SubordinateSigner = caSigner
	mtlsCfg.LeafSigner = caSigner
	mtlsCfg.SubordinateEnroller = subEnroller
	mtlsCfg.Rekeyer = rekeyer
	mtlsCfg.Renewer = renewer
	mtlsCfg.Revoker = revoker
	mtlsCfg.Exporter = escrow
	mtlsCfg.Importer = escrow
	mtlsCfg.Attester = attester
	mtlsCfg.ImageUpgrader = imageUpgrader
	mtlsCfg.Rebooter = rebooter
	mtlsCfg.Trust = trust
	if scepSrv != nil {
		mtlsCfg.ScepAdmin = scepSrv
	}
	mtlsCfg.TsaCertificates = tsaCerts
	// RemoteReset (manager-mediated decommission) is admin-authorized over
	// mTLS: it drives the same destructive wipe as the local Reset, so it
	// carries the same resetter here. The mTLS server leaves Resetter nil, so
	// the unauthenticated local Reset stays refused on the network; only the
	// admin-gated + CN-echoed RemoteReset can reach the wipe over mTLS.
	mtlsCfg.RemoteResetter = rst
	mtlsSrv, err := cgrpc.New(mtlsCfg)
	if err != nil {
		return err
	}
	addr, err := ManagementAddr(cfg)
	if err != nil {
		return err
	}
	mtlsLis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("init: listen %s: %w", addr, err)
	}
	go func() { _ = mtlsSrv.Serve(mtlsLis) }()
	defer func() {
		mtlsSrv.Stop()
		log.Printf("shutdown: mTLS API stopped")
	}()

	// 12b. Anonymous HTTP listener for /crl, /ocsp and the AIA caIssuers
	// certificate (/ca.cer). It is started only on a management boot (where the
	// signers are wired) and only when a revocation base URL is configured; the
	// maintenance/reprovision servers never reach here. The crl/ocsp closures
	// load the CA key + issuer via the same loader/issuer used for signing
	// (reload-per-use, released on completion); the caIssuers closure reads only
	// the issuer certificate.
	if cfg.PKI.RevocationBaseURL != "" {
		httpAddr := fmt.Sprintf(":%d", nonzero(cfg.PKI.RevocationHTTPPort, defaultRevocationHTTPPort))
		handler := revocation.NewHandler(revoker.crlFn(), revoker.ocspFn(ocspResp, ocspResponderMgr), revoker.caCertFn())
		routes := handler.Routes()
		if scepSrv != nil && scepSharesRevocationListener(cfg) {
			mux := http.NewServeMux()
			mux.Handle("/", routes)
			scepSrv.Mount(mux)
			routes = mux
		}
		stopHTTP, herr := revocation.ServeHandler(ctx, httpAddr, routes)
		if herr != nil {
			return fmt.Errorf("init: start revocation HTTP listener on %s: %w", httpAddr, herr)
		}
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = stopHTTP(shutdownCtx)
		}()
		log.Printf("revocation HTTP listener up: %s (base=%s)", httpAddr, cfg.PKI.RevocationBaseURL)
		if scepSrv != nil && scepSharesRevocationListener(cfg) {
			scepRunning.Store(true)
			log.Printf("SCEP listener up: %s%s and %s%s, sharing the CRL/OCSP listener (profiles=%d)",
				httpAddr, scep.PathPKIClient, httpAddr, scep.PathSCEP, len(cfg.PKI.SCEP.Profiles))
		}

		// Ensure the delegated OCSP responder exists before serving (best-effort:
		// a failure only logs; the responder is re-ensured lazily per request and
		// on the renewal ticker, and the boot never fails on it).
		if _, _, err := ocspResponderMgr.ensure(ctx); err != nil {
			log.Printf("OCSP responder: initial ensure failed: %v (will retry on request and on the renewal ticker)", err)
		} else {
			log.Printf("OCSP responder: ready")
		}

		// Drive the revocation preflight AFTER the endpoint is listening (it probes
		// this node's own /crl, /ocsp and /ca.cer), then re-check periodically so OK()
		// reflects live DNS + endpoint reachability and recovers if the base URL
		// becomes reachable after boot. A failing preflight only blocks CDP/AIA
		// stamping (fail-closed in the signer, overridable with
		// allow_unverified_revocation_url); it never blocks the boot. The same
		// ticker re-ensures the delegated OCSP responder so it is re-minted past
		// its halfway renewal point.
		go func() {
			check := func() {
				if err := preflight.Check(ctx); err != nil {
					log.Printf("revocation preflight: %v (CDP/AIA issuance blocked unless allow_unverified_revocation_url is set)", err)
				} else {
					log.Printf("revocation preflight: ok (%s)", cfg.PKI.RevocationBaseURL)
				}
				if _, _, err := ocspResponderMgr.ensure(ctx); err != nil {
					log.Printf("OCSP responder: renewal ensure failed: %v", err)
				}
			}
			check()
			t := time.NewTicker(30 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					check()
				}
			}
		}()
	}

	// 12c. ACME (RFC 8555) enrolment listener. Like the revocation listener it
	// is anonymous, management-boot only, and off unless configured. Issuance
	// goes through the same CA signer as every other path, so the profile still
	// decides the extensions and the certificate is recorded before it is
	// handed back; the ACME layer only decides which names were proved.
	if cfg.PKI.ACME != nil {
		acmeHandler, herr := NewACMEHandler(cli, caSigner, acmeRevoker(revoker), cfg.PKI.ACME)
		if herr != nil {
			return herr
		}
		acmeAddr := fmt.Sprintf(":%d", nonzero(cfg.PKI.ACME.HTTPPort, defaultACMEHTTPPort))
		stopACME, serr := acme.Serve(ctx, acmeAddr, acmeHandler)
		if serr != nil {
			return fmt.Errorf("init: start the ACME listener on %s: %w", acmeAddr, serr)
		}
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = stopACME(shutdownCtx)
		}()
		acmeRunning.Store(true)
		log.Printf("ACME listener up: %s (base=%s profile=%s external_account_binding=%t)",
			acmeAddr, cfg.PKI.ACME.BaseURL, cfg.PKI.ACME.Profile, !cfg.PKI.ACME.AllowAnonymousAccounts)
	} else {
		log.Printf("ACME: off in the boot config; not listening")
	}

	// 12d. EST (RFC 7030) enrolment listener. Unlike ACME it terminates TLS
	// itself, because simplereenroll authenticates with a TLS client
	// certificate that has to reach the handler. The server certificate is
	// minted from this node's own CA and renewed in place, so a client that
	// trusts the CA also trusts the listener.
	if cfg.PKI.EST != nil {
		estOpts, eerr := estOptions(cfg.PKI.EST)
		if eerr != nil {
			return eerr
		}
		estHandler, herr := est.NewHandler(
			estCAChain(issuerFunc),
			estIssuer(caSigner, cfg.PKI.EST.Profile),
			estRevoked(revStore),
			estOpts,
		)
		if herr != nil {
			return fmt.Errorf("init: build the EST handler: %w", herr)
		}
		estCert := newESTServerCert(keyLoader, issuerFunc, cfg.PKI.EST.Hostnames, cfg.PKI.RootKeyAlg)
		estAddr := fmt.Sprintf(":%d", nonzero(cfg.PKI.EST.HTTPPort, defaultESTHTTPPort))
		stopEST, serr := est.Serve(ctx, estAddr, estTLSConfig(estCert), estHandler)
		if serr != nil {
			return fmt.Errorf("init: start the EST listener on %s: %w", estAddr, serr)
		}
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = stopEST(shutdownCtx)
		}()
		estRunning.Store(true)
		log.Printf("EST listener up: %s (hosts=%v profile=%s simpleenroll=%t)",
			estAddr, cfg.PKI.EST.Hostnames, cfg.PKI.EST.Profile, estOpts.EnrollAuth != nil)
	} else {
		log.Printf("EST: off in the boot config; not listening")
	}

	// 12e. SCEP (RFC 8894) enrolment listener, when it does not share the
	// CRL/OCSP listener above. Plain HTTP, as the RFC intends: the CMS
	// envelope carries confidentiality and integrity. Like every enrolment
	// protocol it starts only here, at boot, from the stored config.
	if scepSrv != nil {
		if !scepSharesRevocationListener(cfg) {
			scepAddr := fmt.Sprintf(":%d", scepListenPort(cfg))
			stopSCEP, serr := scep.Serve(ctx, scepAddr, scepSrv.Routes())
			if serr != nil {
				return fmt.Errorf("init: start the SCEP listener on %s: %w", scepAddr, serr)
			}
			defer func() {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = stopSCEP(shutdownCtx)
			}()
			scepRunning.Store(true)
			log.Printf("SCEP listener up: %s%s and %s%s (profiles=%d)",
				scepAddr, scep.PathPKIClient, scepAddr, scep.PathSCEP, len(cfg.PKI.SCEP.Profiles))
		}
		go superviseSCEPRA(ctx, scepRAs)
	} else {
		log.Printf("SCEP: off this boot")
	}

	// 12f. RFC 3161 time-stamp authority listener. Plain HTTP, as the RFC
	// describes: the token carries its own integrity. Like every enrolment
	// protocol it starts only here, at boot, from the stored config.
	if tsaSvc != nil {
		stopTSA, serr := tsa.Serve(ctx, tsaSvc.addr, tsaSvc.handler)
		if serr != nil {
			return fmt.Errorf("init: start the TSA listener on %s: %w", tsaSvc.addr, serr)
		}
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = stopTSA(shutdownCtx)
		}()
		tsaRunning.Store(true)
		log.Printf("TSA listener up: %s (POST %s)", tsaSvc.addr, tsa.ContentTypeQuery)
		go superviseTSACerts(ctx, tsaSvc.certs)
	} else {
		log.Printf("TSA: off this boot")
	}

	done()
	log.Printf("listeners up: mTLS=%s local=%s first_boot=%t", addr, LocalSocketPath, firstBoot)

	// 13. Supervise the console dashboard now that the listeners are up. It
	// polls the local socket and redraws the node status frame. A console crash
	// is non-critical: superviseConsole restarts it and never returns an error
	// that would reboot a serving CA.
	go superviseConsole(ctx)

	// 14. Park until a shutdown is requested, then return so the deferred
	// teardown runs before PID 1 reboots or powers off. SIGINT must be handled
	// before Ctrl-Alt-Del is switched to delivering it, and it stays handled
	// through the teardown (no signal.Stop): a second Ctrl-Alt-Del with no
	// handler would make the Go runtime exit, and PID 1 exiting panics the
	// kernel.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	if cerr := disableCtrlAltDel(); cerr != nil {
		log.Printf("shutdown: Ctrl-Alt-Del stays an immediate restart: %v", cerr)
	}
	watchShutdownSources(ctx, shutdown.Request, append(powerButtonSources(), signalSource{signals: sigs})...)
	log.Printf("shutdown: %s requested; stopping", shutdown.Wait(ctx))
	return nil
}

// networkConfig builds the netlink config from the machine config.
func networkConfig(cfg *config.Config) (netlink.Config, error) {
	p, err := netip.ParsePrefix(cfg.Network.Address)
	if err != nil {
		return netlink.Config{}, fmt.Errorf("init: network.address: %w", err)
	}
	var gw netip.Addr
	if cfg.Network.Gateway != "" {
		if gw, err = netip.ParseAddr(cfg.Network.Gateway); err != nil {
			return netlink.Config{}, fmt.Errorf("init: network.gateway: %w", err)
		}
	}
	return netlink.Config{Name: cfg.Network.Interface, Address: p, Gateway: gw}, nil
}
