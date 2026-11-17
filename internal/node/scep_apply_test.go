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
	"testing"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"github.com/CryptOS-PKI/cryptos-node/internal/config"
	"github.com/CryptOS-PKI/cryptos-node/internal/testadmin"
)

var scepIssuingYAML = []byte(`apiVersion: cryptos.dev/v1alpha1
kind: MachineConfig
metadata: {name: scep-test}
role: {kind: issuing}
network: {interface: eth0, address: 10.0.0.10/24, gateway: 10.0.0.1}
bootstrap: {admin_cert_pem: "` + testadmin.YAMLPEM + `"}
pki:
  root_key_alg: ECDSA-P384
  root_subject: {common_name: "SCEP Test Issuing", organization: "Test", country: "US"}
  root_validity_years: 10
  path_len_constraint: 0
  parent: {ca_cert_sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
  profiles:
    - name: cisco-device
      key_alg: ECDSA-P384
      validity_days: 365
      key_usage: [digital_signature, key_encipherment]
      ext_key_usage: [client_auth]
  scep:
    profiles:
      - {profile: cisco-device, min_rsa_key_bits: 2048}
    allowed_identifier_suffixes: [example.com]
`)

func storedSCEP(t *testing.T, fs *config.FileStore) *config.SCEP {
	t.Helper()
	raw, _, ok, err := fs.Read()
	if err != nil || !ok {
		t.Fatalf("FileStore.Read: ok=%v err=%v", ok, err)
	}
	cfg, err := config.Parse(raw)
	if err != nil {
		t.Fatalf("parse stored config: %v", err)
	}
	return cfg.PKI.SCEP
}

// SCEP travels through the proto, so a config read over the wire and applied
// back keeps it; a client that leaves the block out keeps it too; and only an
// explicit enabled=false switches it off, at the next boot.
func TestConfigStoreApply_SCEPBlockRules(t *testing.T) {
	ctx := context.Background()
	fs := config.NewFileStore(t.TempDir())
	if _, err := fs.Write(scepIssuingYAML); err != nil {
		t.Fatalf("seed: %v", err)
	}
	cs := NewConfigStore(fs)

	current, err := cs.Current(ctx)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if !current.GetPki().GetScep().GetEnabled() {
		t.Fatal("GetConfig does not report SCEP as enabled")
	}
	if _, err := cs.Apply(ctx, current); err != nil {
		t.Fatalf("Apply (round trip): %v", err)
	}
	if s := storedSCEP(t, fs); s == nil || s.Profiles[0].MinRSAKeyBits != 2048 {
		t.Fatalf("a round trip changed the SCEP block: %+v", s)
	}

	current.Pki.Scep = nil
	if _, err := cs.Apply(ctx, current); err != nil {
		t.Fatalf("Apply (no scep block): %v", err)
	}
	if storedSCEP(t, fs) == nil {
		t.Fatal("an apply that left pki.scep out switched SCEP off")
	}

	current.Pki.Scep = &nodev1.Scep{Enabled: false}
	resp, err := cs.Apply(ctx, current)
	if err != nil {
		t.Fatalf("Apply (scep off): %v", err)
	}
	if storedSCEP(t, fs) != nil {
		t.Fatal("enabled=false did not switch SCEP off")
	}
	if !resp.GetRequiresReboot() {
		t.Fatal("switching SCEP off must require a reboot: the listener starts only at boot")
	}
}

// SCEP is reported in NodeStatus.protocols like ACME and EST: configured from
// the stored config, running from this boot, and a reboot pending once an
// apply has switched it off while the listener still runs.
func TestStatusProviderReportsSCEP(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	fs := config.NewFileStore(t.TempDir())
	if _, err := fs.Write(scepIssuingYAML); err != nil {
		t.Fatalf("seed: %v", err)
	}
	cs := NewConfigStore(fs)
	sp, err := NewStatusProvider(StatusConfig{
		Store:      s,
		Role:       nodev1.NodeRole_NODE_ROLE_ISSUING,
		BootConfig: storedConfig(t, fs),
		ConfigFile: fs,
		ProtocolRunning: func(p nodev1.ServiceProtocol) bool {
			return p == nodev1.ServiceProtocol_SERVICE_PROTOCOL_SCEP
		},
	})
	if err != nil {
		t.Fatalf("NewStatusProvider: %v", err)
	}

	st, err := sp.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if ps := protocolState(t, st, nodev1.ServiceProtocol_SERVICE_PROTOCOL_SCEP); !ps.GetConfigured() || !ps.GetRunning() || ps.GetRebootPending() {
		t.Fatalf("SCEP as booted = %v, want configured and running with nothing pending", ps)
	}

	current, err := cs.Current(ctx)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	current.Pki.Scep = &nodev1.Scep{Enabled: false}
	if _, err := cs.Apply(ctx, current); err != nil {
		t.Fatalf("Apply (scep off): %v", err)
	}
	st, err = sp.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if ps := protocolState(t, st, nodev1.ServiceProtocol_SERVICE_PROTOCOL_SCEP); ps.GetConfigured() || !ps.GetRunning() || !ps.GetRebootPending() {
		t.Fatalf("SCEP switched off in the store while running = %v, want not configured, running, reboot pending", ps)
	}
	if !st.GetConfigRebootPending() {
		t.Error("config_reboot_pending is not set after SCEP was switched off")
	}
}
