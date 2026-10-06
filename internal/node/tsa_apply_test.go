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
	"testing"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"github.com/CryptOS-PKI/cryptos-node/internal/config"
)

var tsaIssuingYAML = bytes.Replace(scepIssuingYAML, []byte("  scep:\n"), []byte(
	"  tsa:\n    policy_oid: \"1.3.6.1.4.1.32473.1.1\"\n  scep:\n"), 1)

// The TSA is reported in NodeStatus.protocols like the other protocols:
// configured from the stored config, running from this boot, and a reboot
// pending once an apply switches it while the listener runs. Switching it is
// reboot-required.
func TestStatusProviderReportsTheTSA(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	fs := config.NewFileStore(t.TempDir())
	if _, err := fs.Write(tsaIssuingYAML); err != nil {
		t.Fatalf("seed: %v", err)
	}
	cs := NewConfigStore(fs)
	sp, err := NewStatusProvider(StatusConfig{
		Store:      s,
		Role:       nodev1.NodeRole_NODE_ROLE_ISSUING,
		BootConfig: storedConfig(t, fs),
		ConfigFile: fs,
		ProtocolRunning: func(p nodev1.ServiceProtocol) bool {
			return p == nodev1.ServiceProtocol_SERVICE_PROTOCOL_TSA
		},
	})
	if err != nil {
		t.Fatalf("NewStatusProvider: %v", err)
	}
	st, err := sp.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if ps := protocolState(t, st, nodev1.ServiceProtocol_SERVICE_PROTOCOL_TSA); !ps.GetConfigured() || !ps.GetRunning() || ps.GetRebootPending() {
		t.Fatalf("TSA as booted = %v, want configured and running with nothing pending", ps)
	}

	current, err := cs.Current(ctx)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if !current.GetPki().GetTsa().GetEnabled() || current.GetPki().GetTsa().GetPolicyOid() == "" {
		t.Fatalf("GetConfig reports the TSA as %v", current.GetPki().GetTsa())
	}
	current.Pki.Tsa.Enabled = false
	resp, err := cs.Apply(ctx, current)
	if err != nil {
		t.Fatalf("Apply (tsa off): %v", err)
	}
	if !resp.GetRequiresReboot() {
		t.Fatal("switching the TSA off must require a reboot: the listener starts only at boot")
	}
	st, err = sp.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if ps := protocolState(t, st, nodev1.ServiceProtocol_SERVICE_PROTOCOL_TSA); ps.GetConfigured() || !ps.GetRunning() || !ps.GetRebootPending() {
		t.Fatalf("TSA switched off while running = %v, want not configured, running, reboot pending", ps)
	}
}
