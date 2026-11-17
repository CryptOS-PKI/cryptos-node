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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CryptOS-PKI/cryptos-node/internal/config"

	"github.com/CryptOS-PKI/cryptos-node/internal/testadmin"
)

// minimalConfig is a machine config that validates, so the round trip is
// exercised against the real parser rather than a fixture that only looks
// like one.
const minimalConfig = `apiVersion: cryptos.dev/v1alpha1
kind: MachineConfig
metadata:
  name: pki-root-test
role:
  kind: root
network:
  interface: eth0
  address: 192.0.2.20/24
  gateway: 192.0.2.1
pki:
  root_key_alg: ECDSA-P384
  root_validity_years: 20
  root_subject:
    common_name: Round Trip Root CA
    organization: Example Organization
bootstrap:
  admin_cert_pem: "` + testadmin.YAMLPEM + `"
`

// The point of the verb: read what the node is actually configured with,
// which before this was unanswerable from the CLI.
func TestConfigGet_ReturnsWhatWasApplied(t *testing.T) {
	ts := startTestServer(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "machine.yaml")
	if err := os.WriteFile(path, []byte(minimalConfig), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if out, err := ts.run(t, "config", "apply", "-f", path); err != nil {
		t.Fatalf("config apply: %v (out=%s)", err, out)
	}

	out, err := ts.run(t, "config", "get")
	if err != nil {
		t.Fatalf("config get: %v (out=%s)", err, out)
	}
	if !strings.Contains(out, "Round Trip Root CA") {
		t.Errorf("output does not carry the applied subject:\n%s", out)
	}
	if !strings.Contains(out, "192.0.2.20/24") {
		t.Errorf("output does not carry the applied address:\n%s", out)
	}
}

// The output has to be usable as input, or the read-edit-apply cycle the RPC
// was built for does not close.
func TestConfigGet_OutputParsesAsAConfig(t *testing.T) {
	ts := startTestServer(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "machine.yaml")
	if err := os.WriteFile(path, []byte(minimalConfig), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := ts.run(t, "config", "apply", "-f", path); err != nil {
		t.Fatalf("config apply: %v", err)
	}

	out, err := ts.run(t, "config", "get")
	if err != nil {
		t.Fatalf("config get: %v", err)
	}

	parsed, err := config.Parse([]byte(out))
	if err != nil {
		t.Fatalf("config get output does not parse as a machine config: %v\n%s", err, out)
	}
	if parsed.PKI.RootSubject.CommonName != "Round Trip Root CA" {
		t.Errorf("round-tripped common name = %q", parsed.PKI.RootSubject.CommonName)
	}
}

func TestConfigGet_JSONOutput(t *testing.T) {
	ts := startTestServer(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "machine.yaml")
	if err := os.WriteFile(path, []byte(minimalConfig), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := ts.run(t, "config", "apply", "-f", path); err != nil {
		t.Fatalf("config apply: %v", err)
	}

	out, err := ts.run(t, "config", "get", "-o", "json")
	if err != nil {
		t.Fatalf("config get -o json: %v (out=%s)", err, out)
	}
	if !strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Errorf("output is not JSON:\n%s", out)
	}
}
