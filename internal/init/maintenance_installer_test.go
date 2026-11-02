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
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"github.com/CryptOS-PKI/cryptos-node/internal/install"
)

// validMachineConfig returns a minimal but fully-valid MachineConfig proto for
// tests that need to reach past the parse/validate step.
func validMachineConfig() *nodev1.MachineConfig {
	return &nodev1.MachineConfig{
		ApiVersion: "cryptos.dev/v1alpha1",
		Kind:       "MachineConfig",
		Metadata:   &nodev1.Metadata{Name: "test-node"},
		Role:       &nodev1.Role{Kind: "root"},
		Network: &nodev1.Network{
			Interface: "eth0",
			Address:   "10.0.0.1/24",
			Gateway:   "10.0.0.254",
		},
		Bootstrap: &nodev1.Bootstrap{
			AdminCertSha256: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
		},
		Pki: &nodev1.Pki{
			RootKeyAlg:        "ECDSA-P384",
			RootValidityYears: 10,
			RootSubject:       &nodev1.Subject{CommonName: "Test Root CA"},
		},
		Install: &nodev1.Install{Disk: "/dev/sda"},
	}
}

// TestMaintenanceInstaller_MissingDisk verifies that Install returns
// INVALID_ARGUMENT when install.disk is absent in the config.
func TestMaintenanceInstaller_MissingDisk(t *testing.T) {
	cfg := validMachineConfig()
	cfg.Install = &nodev1.Install{Disk: ""} // no disk

	inst := &maintenanceInstaller{rebootCh: make(chan struct{}, 1)}
	_, err := inst.Install(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for missing install.disk")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
	}
}

// TestMaintenanceInstaller_NilConfig verifies that a nil proto returns
// INVALID_ARGUMENT rather than panicking.
func TestMaintenanceInstaller_NilConfig(t *testing.T) {
	inst := &maintenanceInstaller{rebootCh: make(chan struct{}, 1)}
	_, err := inst.Install(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil config")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
	}
}

// TestMaintenanceInstaller_InstallSuccess verifies that a successful install
// returns RequiresReboot: true and sends on rebootCh.
func TestMaintenanceInstaller_InstallSuccess(t *testing.T) {
	rebootCh := make(chan struct{}, 1)
	var installCalled bool
	inst := &maintenanceInstaller{
		rebootCh: rebootCh,
		doLocateUKI: func(string) (string, error) {
			return "/fake/uki.efi", nil
		},
		doInstall: func(_ context.Context, o install.Options, _ install.Runner, _ string, _ func(string, string) error, _ install.Deps) error {
			installCalled = true
			if o.Disk != "/dev/sda" {
				t.Errorf("Disk = %q, want /dev/sda", o.Disk)
			}
			if o.UKI != "/fake/uki.efi" {
				t.Errorf("UKI = %q, want /fake/uki.efi", o.UKI)
			}
			if len(o.ConfigYAML) == 0 {
				t.Error("ConfigYAML is empty; expected marshalled config")
			}
			return nil
		},
	}

	resp, err := inst.Install(context.Background(), validMachineConfig())
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !resp.GetRequiresReboot() {
		t.Fatal("RequiresReboot = false, want true")
	}
	if !installCalled {
		t.Fatal("install func was not called")
	}
	select {
	case <-rebootCh:
		// expected
	default:
		t.Fatal("rebootCh did not receive a signal after successful install")
	}
}

// TestMaintenanceInstaller_InstallError verifies that an install failure is
// surfaced as INTERNAL and does not signal rebootCh.
func TestMaintenanceInstaller_InstallError(t *testing.T) {
	rebootCh := make(chan struct{}, 1)
	inst := &maintenanceInstaller{
		rebootCh: rebootCh,
		doLocateUKI: func(string) (string, error) {
			return "/fake/uki.efi", nil
		},
		doInstall: func(_ context.Context, _ install.Options, _ install.Runner, _ string, _ func(string, string) error, _ install.Deps) error {
			return errors.New("sgdisk: permission denied")
		},
	}

	_, err := inst.Install(context.Background(), validMachineConfig())
	if err == nil {
		t.Fatal("expected error from failed install")
	}
	if status.Code(err) != codes.Internal {
		t.Fatalf("code = %v, want Internal", status.Code(err))
	}
	select {
	case <-rebootCh:
		t.Fatal("rebootCh received signal on error; should not reboot")
	default:
		// expected: no reboot signal
	}
}

// TestMaintenanceInstaller_LocateUKIError verifies that a locateBootUKI failure
// is surfaced as INTERNAL.
func TestMaintenanceInstaller_LocateUKIError(t *testing.T) {
	inst := &maintenanceInstaller{
		rebootCh: make(chan struct{}, 1),
		doLocateUKI: func(string) (string, error) {
			return "", errors.New("no EFI partition found")
		},
	}
	_, err := inst.Install(context.Background(), validMachineConfig())
	if err == nil {
		t.Fatal("expected error for locate UKI failure")
	}
	if status.Code(err) != codes.Internal {
		t.Fatalf("code = %v, want Internal", status.Code(err))
	}
}

// TestMaintenanceInstaller_LocateUKISkipsTarget verifies that the boot-UKI
// lookup is told the install target, so it never reads the UKI from the disk
// it is about to repartition.
func TestMaintenanceInstaller_LocateUKISkipsTarget(t *testing.T) {
	var gotTarget string
	inst := &maintenanceInstaller{
		rebootCh: make(chan struct{}, 1),
		doLocateUKI: func(target string) (string, error) {
			gotTarget = target
			return "/fake/uki.efi", nil
		},
		doInstall: func(_ context.Context, _ install.Options, _ install.Runner, _ string, _ func(string, string) error, _ install.Deps) error {
			return nil
		},
	}
	if _, err := inst.Install(context.Background(), validMachineConfig()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if gotTarget != "/dev/sda" {
		t.Fatalf("locate boot UKI got target %q, want /dev/sda", gotTarget)
	}
}
