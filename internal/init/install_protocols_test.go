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
	"encoding/base64"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"github.com/CryptOS-PKI/cryptos-node/internal/config"
	"github.com/CryptOS-PKI/cryptos-node/internal/install"
)

var installEABKey = base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

// issuingMachineConfigWithProtocols is validMachineConfig as an issuing node
// with ACME and EST switched on.
func issuingMachineConfigWithProtocols() *nodev1.MachineConfig {
	pb := validMachineConfig()
	pb.Role.Kind = "issuing"
	pb.Pki.RootValidityYears = 0
	pb.Pki.Parent = &nodev1.Parent{CaCertSha256: "abababababababababababababababababababababababababababababababab"}
	pb.Pki.Profiles = []*nodev1.CertificateProfile{{
		Name: "leaf-server", KeyAlg: "ECDSA-P384", ValidityDays: 90,
		KeyUsage: []string{"digital_signature"}, ExtKeyUsage: []string{"server_auth"},
	}}
	pb.Pki.Acme = &nodev1.Acme{
		Enabled: true,
		BaseUrl: "https://ca.example.org/acme",
		Profile: "leaf-server",
		ExternalAccountKeys: []*nodev1.AcmeExternalAccountKey{
			{KeyId: "ops", HmacKeyBase64: installEABKey},
		},
	}
	pb.Pki.Est = &nodev1.Est{
		Enabled:            true,
		Hostnames:          []string{"est.example.org"},
		Profile:            "leaf-server",
		AllowAnyIdentifier: true,
	}
	return pb
}

// The maintenance install writes the staged YAML the installed node boots
// from, so the protocol blocks it was given must be in it.
func TestMaintenanceInstaller_CarriesProtocolBlocks(t *testing.T) {
	var staged []byte
	inst := &maintenanceInstaller{
		rebootCh:    make(chan struct{}, 1),
		doLocateUKI: func(string) (string, error) { return "/fake/uki.efi", nil },
		doInstall: func(_ context.Context, o install.Options, _ install.Runner, _ string, _ func(string, string) error, _ install.Deps) error {
			staged = o.ConfigYAML
			return nil
		},
	}
	if _, err := inst.Install(context.Background(), issuingMachineConfigWithProtocols()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	cfg, err := config.Parse(staged)
	if err != nil {
		t.Fatalf("parse the staged config: %v", err)
	}
	if cfg.PKI.ACME == nil || cfg.PKI.ACME.ExternalAccountKeys[0].HMACKeyBase64 != installEABKey {
		t.Errorf("staged ACME = %+v, want the applied block with its secret", cfg.PKI.ACME)
	}
	if cfg.PKI.EST == nil || cfg.PKI.EST.Hostnames[0] != "est.example.org" {
		t.Errorf("staged EST = %+v, want the applied block", cfg.PKI.EST)
	}
}

// A fresh install has no stored secret to keep, so an empty one is refused
// with a message that says so, before anything touches the disk.
func TestMaintenanceInstaller_RejectsEmptySecret(t *testing.T) {
	pb := issuingMachineConfigWithProtocols()
	pb.Pki.Acme.ExternalAccountKeys[0].HmacKeyBase64 = ""
	called := false
	inst := &maintenanceInstaller{
		rebootCh:    make(chan struct{}, 1),
		doLocateUKI: func(string) (string, error) { return "/fake/uki.efi", nil },
		doInstall: func(context.Context, install.Options, install.Runner, string, func(string, string) error, install.Deps) error {
			called = true
			return nil
		},
	}
	_, err := inst.Install(context.Background(), pb)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v (err %v), want InvalidArgument", status.Code(err), err)
	}
	if !strings.Contains(err.Error(), `no stored key for key_id "ops"`) {
		t.Errorf("error %q does not say the node has no key to keep", err)
	}
	if called {
		t.Error("the disk was written for a config with an empty secret")
	}
}

func TestMaintenanceInstaller_RejectsProtocolOnRoot(t *testing.T) {
	pb := validMachineConfig()
	pb.Pki.Profiles = issuingMachineConfigWithProtocols().Pki.Profiles
	pb.Pki.Est = &nodev1.Est{Enabled: true, Hostnames: []string{"est.example.org"}, Profile: "leaf-server", AllowAnyIdentifier: true}
	inst := &maintenanceInstaller{rebootCh: make(chan struct{}, 1)}
	if _, err := inst.Install(context.Background(), pb); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("install of a root serving EST: code = %v (err %v), want InvalidArgument", status.Code(err), err)
	}
}

func TestReprovisioner_CarriesProtocolBlocks(t *testing.T) {
	store := config.NewFileStore(t.TempDir())
	rp := &reprovisioner{store: store, rebootCh: make(chan struct{}, 1)}
	if _, err := rp.Install(context.Background(), issuingMachineConfigWithProtocols()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	raw, _, ok, err := store.Read()
	if err != nil || !ok {
		t.Fatalf("config not persisted: ok=%v err=%v", ok, err)
	}
	cfg, err := config.Parse(raw)
	if err != nil {
		t.Fatalf("parse the persisted config: %v", err)
	}
	if cfg.PKI.ACME == nil || cfg.PKI.EST == nil {
		t.Errorf("persisted protocols: acme=%+v est=%+v, want both", cfg.PKI.ACME, cfg.PKI.EST)
	}
}
