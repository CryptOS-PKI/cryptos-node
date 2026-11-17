package main

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
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"

	"github.com/CryptOS-PKI/cryptos-node/internal/testadmin"
)

func TestHumanStatusShowsProtocols(t *testing.T) {
	s := &nodev1.NodeStatus{
		Role: nodev1.NodeRole_NODE_ROLE_ISSUING,
		Protocols: []*nodev1.ProtocolStatus{
			{Protocol: nodev1.ServiceProtocol_SERVICE_PROTOCOL_ACME, Configured: true, Running: true},
			{Protocol: nodev1.ServiceProtocol_SERVICE_PROTOCOL_EST, Configured: true, Running: false, RebootPending: true},
		},
		ConfigRebootPending: true,
	}
	out := humanStatus(s)
	for _, want := range []string{
		"Protocols:", "ACME on", "EST on (not running, reboot pending)",
		"Reboot:", "pending",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("humanStatus missing %q in:\n%s", want, out)
		}
	}

	off := humanStatus(&nodev1.NodeStatus{
		Protocols: []*nodev1.ProtocolStatus{
			{Protocol: nodev1.ServiceProtocol_SERVICE_PROTOCOL_ACME},
			{Protocol: nodev1.ServiceProtocol_SERVICE_PROTOCOL_EST, Running: true, RebootPending: true},
		},
	})
	for _, want := range []string{"ACME off", "EST off (still running, reboot pending)"} {
		if !strings.Contains(off, want) {
			t.Errorf("humanStatus missing %q in:\n%s", want, off)
		}
	}
	if strings.Contains(off, "Reboot:") {
		t.Errorf("humanStatus flagged a reboot the node did not report:\n%s", off)
	}

	// A node that does not report protocols (maintenance mode, an older node)
	// prints no Protocols line rather than an empty one.
	if bare := humanStatus(&nodev1.NodeStatus{}); strings.Contains(bare, "Protocols:") {
		t.Errorf("humanStatus printed unreported protocols:\n%s", bare)
	}
}

const protocolsConfig = `apiVersion: cryptos.dev/v1alpha1
kind: MachineConfig
metadata:
  name: pki-issuing-test
role:
  kind: issuing
network:
  interface: eth0
  address: 192.0.2.30/24
  gateway: 192.0.2.1
pki:
  root_key_alg: ECDSA-P384
  root_subject:
    common_name: Protocols Issuing CA
  parent:
    ca_cert_sha256: abababababababababababababababababababababababababababababababab
  profiles:
    - name: leaf-server
      key_alg: ECDSA-P384
      validity_days: 90
      key_usage: [digital_signature]
      ext_key_usage: [server_auth]
  acme:
    base_url: https://ca.example.org/acme
    profile: leaf-server
    external_account_keys:
      - key_id: ops
        hmac_key_base64: EAB_KEY
bootstrap:
  admin_cert_pem: "` + testadmin.YAMLPEM + `"
`

// config get prints the EAB secret blank, and feeding that output back to
// config apply keeps the secret the node holds.
func TestConfigGetApply_KeepsWriteOnlySecret(t *testing.T) {
	ts := startTestServer(t)
	dir := t.TempDir()
	secret := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	path := filepath.Join(dir, "machine.yaml")
	if err := os.WriteFile(path, []byte(strings.Replace(protocolsConfig, "EAB_KEY", secret, 1)), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	out, err := ts.run(t, "config", "apply", "-f", path)
	if err != nil {
		t.Fatalf("config apply: %v (out=%s)", err, out)
	}
	if !strings.Contains(out, "requires_reboot=true") {
		t.Errorf("switching ACME on did not report requires_reboot:\n%s", out)
	}

	got, err := ts.run(t, "config", "get")
	if err != nil {
		t.Fatalf("config get: %v (out=%s)", err, got)
	}
	if strings.Contains(got, secret) {
		t.Fatalf("config get printed the EAB secret:\n%s", got)
	}
	if !strings.Contains(got, "key_id: ops") {
		t.Errorf("config get dropped the key_id:\n%s", got)
	}

	back := filepath.Join(dir, "back.yaml")
	if err := os.WriteFile(back, []byte(got), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	out, err = ts.run(t, "config", "apply", "-f", back)
	if err != nil {
		t.Fatalf("config apply of the config get output: %v (out=%s)", err, out)
	}
	if !strings.Contains(out, "requires_reboot=false") {
		t.Errorf("an unchanged re-apply reported a reboot:\n%s", out)
	}
}
