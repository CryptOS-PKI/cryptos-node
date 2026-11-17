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
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"github.com/CryptOS-PKI/cryptos-node/internal/config"
	"github.com/CryptOS-PKI/cryptos-node/internal/testadmin"
)

// protocolsOffSeed is an issuing node with a leaf profile and no enrolment
// protocol switched on.
const protocolsOffSeed = `apiVersion: cryptos.dev/v1alpha1
kind: MachineConfig
metadata: {name: protocols-switch-test}
role: {kind: issuing}
network: {interface: eth0, address: 10.0.0.10/24, gateway: 10.0.0.1}
bootstrap: {admin_cert_pem: "` + testadmin.YAMLPEM + `"}
pki:
  root_key_alg: ECDSA-P384
  root_subject: {common_name: "Protocols Switch Issuing CA", organization: "Test", country: "US"}
  path_len_constraint: 0
  parent: {ca_cert_sha256: "abababababababababababababababababababababababababababababababab"}
  profiles:
    - name: leaf-server
      key_alg: ECDSA-P384
      validity_days: 90
      key_usage: [digital_signature]
      ext_key_usage: [server_auth]
`

var testEABKey = base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

func seededStore(t *testing.T, seed string) (*config.FileStore, *ConfigStore) {
	t.Helper()
	fs := config.NewFileStore(t.TempDir())
	if _, err := fs.Write([]byte(seed)); err != nil {
		t.Fatalf("FileStore.Write (seed): %v", err)
	}
	return fs, NewConfigStore(fs)
}

func storedConfig(t *testing.T, fs *config.FileStore) *config.Config {
	t.Helper()
	raw, _, ok, err := fs.Read()
	if err != nil || !ok {
		t.Fatalf("FileStore.Read: ok=%v err=%v", ok, err)
	}
	c, err := config.Parse(raw)
	if err != nil {
		t.Fatalf("parse the stored config: %v", err)
	}
	return c
}

func acmeOn() *nodev1.Acme {
	return &nodev1.Acme{
		Enabled: true,
		BaseUrl: "https://ca.example.org/acme",
		Profile: "leaf-server",
		ExternalAccountKeys: []*nodev1.AcmeExternalAccountKey{
			{KeyId: "ops", HmacKeyBase64: testEABKey},
		},
	}
}

// The round trip an operator or the Fleet Manager makes: switch ACME on, read
// the config back, apply it unchanged, then switch ACME off. Every switch is
// stored and answered requires_reboot, the secret never comes back over the
// wire, and an unchanged re-apply neither loses the secret nor asks for a
// reboot.
func TestConfigStoreApply_ACMEOnThenOff(t *testing.T) {
	ctx := context.Background()
	fs, cs := seededStore(t, protocolsOffSeed)

	current, err := cs.Current(ctx)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if a := current.GetPki().GetAcme(); a == nil || a.GetEnabled() {
		t.Fatalf("GetConfig of a node without ACME = %v, want an explicit enabled=false block", a)
	}

	// On.
	current.Pki.Acme = acmeOn()
	resp, err := cs.Apply(ctx, current)
	if err != nil {
		t.Fatalf("Apply (ACME on): %v", err)
	}
	if !resp.GetRequiresReboot() {
		t.Error("switching ACME on did not answer requires_reboot")
	}
	stored := storedConfig(t, fs)
	if stored.PKI.ACME == nil || stored.PKI.ACME.ExternalAccountKeys[0].HMACKeyBase64 != testEABKey {
		t.Fatalf("stored ACME after switching on = %+v, want the applied block with its secret", stored.PKI.ACME)
	}

	// Read back: on, with the secret blank.
	current, err = cs.Current(ctx)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	a := current.GetPki().GetAcme()
	if !a.GetEnabled() || a.GetBaseUrl() != "https://ca.example.org/acme" {
		t.Fatalf("GetConfig after switching on = %v, want the ACME block", a)
	}
	if len(a.GetExternalAccountKeys()) != 1 || a.GetExternalAccountKeys()[0].GetHmacKeyBase64() != "" {
		t.Errorf("GetConfig returned the EAB secret: %v", a.GetExternalAccountKeys())
	}

	// Apply what was read, unchanged.
	resp, err = cs.Apply(ctx, current)
	if err != nil {
		t.Fatalf("Apply (unchanged read-back): %v", err)
	}
	if resp.GetRequiresReboot() {
		t.Error("an unchanged re-apply asked for a reboot")
	}
	if got := storedConfig(t, fs).PKI.ACME.ExternalAccountKeys[0].HMACKeyBase64; got != testEABKey {
		t.Errorf("stored EAB secret after the read-back apply = %q, want it kept", got)
	}

	// Off.
	current.Pki.Acme = &nodev1.Acme{Enabled: false}
	resp, err = cs.Apply(ctx, current)
	if err != nil {
		t.Fatalf("Apply (ACME off): %v", err)
	}
	if !resp.GetRequiresReboot() {
		t.Error("switching ACME off did not answer requires_reboot")
	}
	if stored := storedConfig(t, fs); stored.PKI.ACME != nil {
		t.Errorf("stored ACME after switching off = %+v, want none", stored.PKI.ACME)
	}
	current, err = cs.Current(ctx)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if current.GetPki().GetAcme().GetEnabled() {
		t.Error("GetConfig still reports ACME on after switching it off")
	}
}

// A client that predates the protocol blocks sends none. That must leave the
// node's protocols as they are, not switch them off.
func TestConfigStoreApply_AbsentBlockKeepsProtocol(t *testing.T) {
	ctx := context.Background()
	fs, cs := seededStore(t, protocolsOffSeed)
	pb := storedConfig(t, fs).ToProto()
	pb.Pki.Acme = acmeOn()
	if _, err := cs.Apply(ctx, pb); err != nil {
		t.Fatalf("Apply (ACME on): %v", err)
	}

	pb, err := cs.Current(ctx)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	pb.Pki.Acme = nil
	pb.Pki.Est = nil
	pb.Pki.Profiles[0].ValidityDays = 30
	if _, err := cs.Apply(ctx, pb); err != nil {
		t.Fatalf("Apply (no protocol blocks): %v", err)
	}
	stored := storedConfig(t, fs)
	if stored.PKI.ACME == nil || stored.PKI.ACME.ExternalAccountKeys[0].HMACKeyBase64 != testEABKey {
		t.Errorf("an apply without the ACME block changed it: %+v", stored.PKI.ACME)
	}
	if stored.PKI.Profiles[0].ValidityDays != 30 {
		t.Error("the rest of the apply was not stored")
	}
}

func TestConfigStoreApply_RejectsSecretlessNewCredential(t *testing.T) {
	ctx := context.Background()
	fs, cs := seededStore(t, protocolsOffSeed)
	beforeRaw, beforeGen, _, _ := fs.Read()

	pb := storedConfig(t, fs).ToProto()
	pb.Pki.Acme = acmeOn()
	pb.Pki.Acme.ExternalAccountKeys[0].HmacKeyBase64 = ""
	_, err := cs.Apply(ctx, pb)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("Apply with an empty secret for a new key_id: code = %v (err %v), want InvalidArgument", status.Code(err), err)
	}
	if !strings.Contains(err.Error(), `"ops"`) {
		t.Errorf("error %q does not name the key_id", err)
	}
	afterRaw, afterGen, _, _ := fs.Read()
	if afterGen != beforeGen || !bytes.Equal(afterRaw, beforeRaw) {
		t.Error("a rejected apply changed the stored config")
	}
}

func TestConfigStoreApply_RejectsProtocolOnRoot(t *testing.T) {
	ctx := context.Background()
	fs, cs := seededStore(t, protocolsOffSeed)
	beforeRaw, beforeGen, _, _ := fs.Read()

	for _, tc := range []struct {
		name   string
		mutate func(*nodev1.MachineConfig)
	}{
		{"acme", func(pb *nodev1.MachineConfig) { pb.Pki.Acme = acmeOn() }},
		{"est", func(pb *nodev1.MachineConfig) {
			pb.Pki.Est = &nodev1.Est{Enabled: true, Hostnames: []string{"est.example.org"}, Profile: "leaf-server"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pb := storedConfig(t, fs).ToProto()
			pb.Role.Kind = string(config.RoleRoot)
			pb.Pki.Parent = nil
			pb.Pki.RootValidityYears = 10
			tc.mutate(pb)
			_, err := cs.Apply(ctx, pb)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("Apply of a root serving %s: code = %v (err %v), want InvalidArgument", tc.name, status.Code(err), err)
			}
			if !strings.Contains(err.Error(), "root") {
				t.Errorf("error %q does not say the root role is the reason", err)
			}
			afterRaw, afterGen, _, _ := fs.Read()
			if afterGen != beforeGen || !bytes.Equal(afterRaw, beforeRaw) {
				t.Error("a rejected apply changed the stored config")
			}
		})
	}
}

func protocolState(t *testing.T, st *nodev1.NodeStatus, p nodev1.ServiceProtocol) *nodev1.ProtocolStatus {
	t.Helper()
	for _, ps := range st.GetProtocols() {
		if ps.GetProtocol() == p {
			return ps
		}
	}
	t.Fatalf("NodeStatus.protocols has no entry for %v: %v", p, st.GetProtocols())
	return nil
}

// Status compares the stored config with the one this boot started from, so a
// protocol switched on by ApplyConfig shows configured but not running, with a
// reboot pending, until the node reboots.
func TestStatusProviderReportsProtocols(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	fs, cs := seededStore(t, protocolsOffSeed)
	boot := storedConfig(t, fs)

	running := map[nodev1.ServiceProtocol]bool{}
	sp, err := NewStatusProvider(StatusConfig{
		Store:           s,
		Role:            nodev1.NodeRole_NODE_ROLE_ISSUING,
		BootConfig:      boot,
		ConfigFile:      fs,
		ProtocolRunning: func(p nodev1.ServiceProtocol) bool { return running[p] },
	})
	if err != nil {
		t.Fatalf("NewStatusProvider: %v", err)
	}

	st, err := sp.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	for _, p := range []nodev1.ServiceProtocol{nodev1.ServiceProtocol_SERVICE_PROTOCOL_ACME, nodev1.ServiceProtocol_SERVICE_PROTOCOL_EST} {
		ps := protocolState(t, st, p)
		if ps.GetConfigured() || ps.GetRunning() || ps.GetRebootPending() {
			t.Errorf("%v on a node with nothing switched on = %v, want all false", p, ps)
		}
	}
	if st.GetConfigRebootPending() {
		t.Error("config_reboot_pending is set with the stored config unchanged since boot")
	}

	pb := boot.ToProto()
	pb.Pki.Acme = acmeOn()
	if _, err := cs.Apply(ctx, pb); err != nil {
		t.Fatalf("Apply (ACME on): %v", err)
	}
	st, err = sp.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	acme := protocolState(t, st, nodev1.ServiceProtocol_SERVICE_PROTOCOL_ACME)
	if !acme.GetConfigured() || acme.GetRunning() || !acme.GetRebootPending() {
		t.Errorf("ACME after an apply switched it on = %v, want configured, not running, reboot pending", acme)
	}
	if est := protocolState(t, st, nodev1.ServiceProtocol_SERVICE_PROTOCOL_EST); est.GetRebootPending() {
		t.Errorf("EST was untouched but reports a pending reboot: %v", est)
	}
	if !st.GetConfigRebootPending() {
		t.Error("config_reboot_pending is not set after a reboot-required apply")
	}

	// The next boot: it starts from the stored config and the listener runs.
	booted := storedConfig(t, fs)
	running[nodev1.ServiceProtocol_SERVICE_PROTOCOL_ACME] = true
	sp, err = NewStatusProvider(StatusConfig{
		Store:           s,
		Role:            nodev1.NodeRole_NODE_ROLE_ISSUING,
		BootConfig:      booted,
		ConfigFile:      fs,
		ProtocolRunning: func(p nodev1.ServiceProtocol) bool { return running[p] },
	})
	if err != nil {
		t.Fatalf("NewStatusProvider: %v", err)
	}
	st, err = sp.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	acme = protocolState(t, st, nodev1.ServiceProtocol_SERVICE_PROTOCOL_ACME)
	if !acme.GetConfigured() || !acme.GetRunning() || acme.GetRebootPending() {
		t.Errorf("ACME after the reboot = %v, want configured and running with nothing pending", acme)
	}
	if st.GetConfigRebootPending() {
		t.Error("config_reboot_pending survived the reboot")
	}
}

// Without a boot config (maintenance mode) the protocol list stays unset.
func TestStatusProviderWithoutBootConfigLeavesProtocolsUnset(t *testing.T) {
	s, ctx := newTestStore(t)
	sp, err := NewStatusProvider(StatusConfig{Store: s, Role: nodev1.NodeRole_NODE_ROLE_ISSUING})
	if err != nil {
		t.Fatalf("NewStatusProvider: %v", err)
	}
	st, err := sp.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(st.GetProtocols()) != 0 || st.GetConfigRebootPending() {
		t.Errorf("status without a boot config = protocols %v, pending %v; want unset", st.GetProtocols(), st.GetConfigRebootPending())
	}
}
