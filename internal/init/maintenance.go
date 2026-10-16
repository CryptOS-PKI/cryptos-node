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
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"github.com/CryptOS-PKI/cryptos-node/internal/config"
	"github.com/CryptOS-PKI/cryptos-node/internal/console"
	cgrpc "github.com/CryptOS-PKI/cryptos-node/internal/grpc"
	"github.com/CryptOS-PKI/cryptos-node/internal/init/netlink"
	"github.com/CryptOS-PKI/cryptos-node/internal/node"
)

// nopAuditor drops audit events. Maintenance mode has no durable state store to
// persist an audit chain to, and it serves only the unauthenticated GetStatus,
// so there is nothing meaningful to record. The grpc audit interceptors require
// a non-nil Auditor, so maintenance supplies this no-op.
type nopAuditor struct{}

func (nopAuditor) Append(*nodev1.AuditEvent) error { return nil }

// startConsoleSocket brings up the on-box UNIX socket in maintenance mode and
// supervises the cryptos-console dashboard, so the console renders the
// "awaiting configuration" maintenance screen instead of a blank display. It
// serves only GetStatus (the maintenance status); GetIdentity/ApplyConfig/Reset
// are absent here, which the dashboard tolerates (it renders the maintenance
// state). Best-effort and non-critical: any failure is logged and the node
// continues serving the management API. Returns a stop func for the caller to
// defer.
func startConsoleSocket(ctx context.Context) func() {
	_ = os.Remove(LocalSocketPath)
	srv, err := cgrpc.NewLocal(cgrpc.ServerConfig{
		Auditor: nopAuditor{},
		Status:  newMaintenanceStatus(Version),
	})
	if err != nil {
		log.Printf("maintenance: console socket server: %v", err)
		return func() {}
	}
	lis, err := net.Listen("unix", LocalSocketPath)
	if err != nil {
		log.Printf("maintenance: console socket listen: %v", err)
		return func() {}
	}
	go func() { _ = srv.Serve(lis) }()
	go superviseConsole(ctx)
	return srv.Stop
}

// runMaintenance brings up the limited maintenance service. Loopback is up and
// the kernel has configured the primary interface via ip=dhcp; when no DHCP
// server answered, startLinkLocalFallback gives an interface a self-assigned
// 169.254.0.0/16 address instead. We only serve the management API, on every
// address (0.0.0.0), with a self-signed maintenance cert and NO client
// verification (Talos --insecure). No TPM, LUKS, etcd, or ceremony. Parks until
// a shutdown signal or a successful install (which triggers reboot), then
// returns so PID 1 reboots.
func runMaintenance(ctx context.Context) error {
	if err := netlink.BringUpLoopback(); err != nil {
		return err
	}
	defer startLinkLocalFallback(ctx)()
	serverCert, removeCert, err := newMaintenanceCert(console.ManagementCertPath)
	if err != nil {
		return err
	}
	defer removeCert()

	// rebootCh is closed/sent by maintenanceInstaller after a successful
	// install. When it fires, GracefulStop flushes the in-flight ApplyConfig
	// response to the client before tearing down the connection, then this
	// function returns and PID 1 reboots.
	rebootCh := make(chan struct{}, 1)
	inst := &maintenanceInstaller{rebootCh: rebootCh}

	srv, err := cgrpc.NewMaintenance(cgrpc.ServerConfig{
		TLSConfig:  MaintenanceServerTLSConfig(serverCert),
		Auditor:    nopAuditor{},
		Status:     newMaintenanceStatus(Version),
		Installer:  inst,
		DiskLister: node.NewInstallDiskLister(),
	})
	if err != nil {
		return err
	}
	addr := net.JoinHostPort("0.0.0.0", strconv.Itoa(ManagementPort))
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("init: maintenance listen %s: %w", addr, err)
	}
	go func() {
		if err := srv.Serve(lis); err != nil {
			log.Printf("maintenance: gRPC serve error: %v", err)
		}
	}()
	defer srv.Stop()
	defer startConsoleSocket(ctx)()
	log.Printf("MAINTENANCE mode: management API on %s (client auth OFF); no state disk present", addr)

	sigCtx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	select {
	case <-sigCtx.Done():
		log.Printf("shutdown signal received")
	case <-rebootCh:
		log.Printf("install complete; rebooting")
	}
	return nil
}

// runReprovisionMaintenance brings up maintenance after a console Reset. The
// cryptos-state partition already exists and is mounted at cfgStore's dir, but
// holds no config (the reset erased the state-key material and cleared the
// staged ESP config, then rebooted). Boot's loadOrSeedConfig therefore returns
// errEnterMaintenance without having taken the early ISO-install path, and lands
// here. Unlike runMaintenance (which wires the bare-disk Installer that
// re-partitions a disk), this wires a reprovisioner whose ApplyConfig persists
// the config to the mounted state and reboots into the ceremony.
//
// The listener setup mirrors runMaintenance: self-signed cert, client auth OFF
// (Talos --insecure), no-op auditor. It parks until a shutdown signal or a
// successful re-provision (which triggers reboot), then returns so PID 1 reboots.
func runReprovisionMaintenance(ctx context.Context, cfgStore *config.FileStore, sealedMode string) error {
	if err := netlink.BringUpLoopback(); err != nil {
		return err
	}
	defer startLinkLocalFallback(ctx)()
	serverCert, removeCert, err := newMaintenanceCert(console.ManagementCertPath)
	if err != nil {
		return err
	}
	defer removeCert()

	// rebootCh is signalled by reprovisioner after it persists the config. When
	// it fires, GracefulStop flushes the in-flight ApplyConfig response to the
	// client before tearing down the connection, then this function returns and
	// PID 1 reboots into the ceremony.
	rebootCh := make(chan struct{}, 1)
	rp := &reprovisioner{store: cfgStore, rebootCh: rebootCh, sealedMode: sealedMode}

	srv, err := cgrpc.NewMaintenance(cgrpc.ServerConfig{
		TLSConfig:  MaintenanceServerTLSConfig(serverCert),
		Auditor:    nopAuditor{},
		Status:     newMaintenanceStatus(Version),
		Installer:  rp,
		DiskLister: node.NewInstallDiskLister(),
	})
	if err != nil {
		return err
	}
	addr := net.JoinHostPort("0.0.0.0", strconv.Itoa(ManagementPort))
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("init: reprovision listen %s: %w", addr, err)
	}
	go func() {
		if err := srv.Serve(lis); err != nil {
			log.Printf("reprovision: gRPC serve error: %v", err)
		}
	}()
	defer srv.Stop()
	defer startConsoleSocket(ctx)()
	log.Printf("REPROVISION mode: management API on %s (client auth OFF); state present, awaiting config", addr)

	sigCtx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	select {
	case <-sigCtx.Done():
		log.Printf("shutdown signal received")
	case <-rebootCh:
		log.Printf("re-provision complete; rebooting")
	}
	return nil
}

// newMaintenanceCert mints the throwaway self-signed certificate the
// maintenance listener presents and publishes its public half at path, so the
// console shows the fingerprint an operator compares before adopting the
// node. A failed publish only costs the console line, so it is logged and the
// listener still starts. The returned cleanup removes the published file.
func newMaintenanceCert(path string) (tls.Certificate, func(), error) {
	cert, err := GenerateServerCert([]string{"localhost"}, "")
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	if err := PublishManagementCert(path, cert); err != nil {
		log.Printf("maintenance: %v", err)
	} else {
		log.Printf("management cert: published %s (sha256 %s, maintenance)", path, console.Fingerprint(cert.Leaf.Raw))
	}
	return cert, func() { _ = os.Remove(path) }, nil
}
