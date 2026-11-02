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
	"os"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"github.com/CryptOS-PKI/cryptos-node/internal/config"
	"github.com/CryptOS-PKI/cryptos-node/internal/install"
)

// installFn is the signature of install.Install, extracted so tests can inject
// a fake without needing a real disk or UKI.
type installFn func(ctx context.Context, o install.Options, r install.Runner, mountDir string, copyFn func(dst, src string) error, d install.Deps) error

// locateBootUKIFn is the signature of LocateBootUKI, injectable for tests.
type locateBootUKIFn func(targetDisk string) (string, error)

// maintenanceInstaller implements grpc.Installer for the maintenance-mode
// ApplyConfig path. It validates the config, locates the boot UKI on the ESP,
// writes the UKI and staged config YAML to the target disk, and then signals
// the runMaintenance loop to return so PID 1 reboots.
//
// Reboot handoff: the installer sends on rebootCh after install.Install returns
// (inside the gRPC handler, before the handler returns to the interceptor).
// runMaintenance selects on rebootCh; when it fires, it returns so PID 1's
// Boot() function receives a nil error and reboots. The send itself does not
// order anything against the response write (the channel is buffered, so the
// handler carries on immediately). What keeps the response safe is the
// deferred srv.Stop() in runMaintenance: it calls GracefulStop, which waits
// for in-flight RPCs, this ApplyConfig included, to finish and write their
// responses before closing the connections. So the client receives
// RequiresReboot: true before the node goes down. A direct syscall.Reboot
// inside the handler would skip that wait and race with the response write.
type maintenanceInstaller struct {
	rebootCh chan struct{}

	// injectable for testing; nil means use the real implementations.
	doInstall   installFn
	doLocateUKI locateBootUKIFn
}

// Install validates cfg, locates the booted UKI, installs to disk, and triggers
// a reboot by signalling runMaintenance to return.
func (m *maintenanceInstaller) Install(ctx context.Context, cfg *nodev1.MachineConfig) (*nodev1.ApplyConfigResponse, error) {
	parsed, err := config.FromProtoOver(cfg, nil)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "apply-config: parse: %v", err)
	}
	if err := parsed.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "apply-config: validate: %v", err)
	}
	if parsed.Install.Disk == "" {
		return nil, status.Error(codes.InvalidArgument, "apply-config: install.disk is required for a maintenance-mode install")
	}

	locateUKI := m.doLocateUKI
	if locateUKI == nil {
		locateUKI = LocateBootUKI
	}
	uki, err := locateUKI(parsed.Install.Disk)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "apply-config: locate boot UKI: %v", err)
	}

	yamlBytes, err := parsed.Marshal()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "apply-config: marshal config: %v", err)
	}

	// Mount scratch directory for the installer.
	mountDir, err := os.MkdirTemp("", "cryptos-install-esp-*")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "apply-config: mktemp mount dir: %v", err)
	}
	defer func() { _ = os.Remove(mountDir) }()

	doInst := m.doInstall
	if doInst == nil {
		doInst = install.Install
	}
	if err := doInst(ctx, install.Options{
		Disk:       parsed.Install.Disk,
		UKI:        uki,
		ConfigYAML: yamlBytes,
	}, install.ExecRunner{}, mountDir, install.CopyFile, install.RealDeps()); err != nil {
		return nil, status.Errorf(codes.Internal, "apply-config: install: %v", err)
	}

	// Signal runMaintenance to return so PID 1 reboots. Non-blocking send:
	// if nothing is listening (e.g. in unit tests) we simply continue.
	select {
	case m.rebootCh <- struct{}{}:
	default:
	}

	return &nodev1.ApplyConfigResponse{RequiresReboot: true}, nil
}
