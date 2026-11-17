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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"github.com/CryptOS-PKI/cryptos-node/internal/config"
)

// applyConfigRequest mirrors exactly what newConfigApplyCmd sends over the
// wire: config.Parse the raw YAML, then call ToProto.  This test confirms
// that install.disk survives the client-side YAML→proto conversion so the
// maintenance node receives a non-empty Install.Disk in the ApplyConfig RPC.
func TestApplyConfig_InstallDiskSentOnWire(t *testing.T) {
	raw := buildMachineYAMLWithInstall(t, "/dev/vdb")

	cfg, err := config.Parse(raw)
	if err != nil {
		t.Fatalf("config.Parse: %v", err)
	}

	// Reproduce the exact request the command builds.
	req := &nodev1.ApplyConfigRequest{Config: cfg.ToProto()}

	if req.Config.GetInstall().GetDisk() != "/dev/vdb" {
		t.Fatalf("ApplyConfigRequest.Config.Install.Disk = %q, want %q",
			req.Config.GetInstall().GetDisk(), "/dev/vdb")
	}
}

// selfSignedAdminCertPEM mints a throwaway PEM-encoded X.509 cert suitable
// for the bootstrap.admin_cert_pem field in a MachineConfig YAML under test.
func selfSignedAdminCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-admin"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// buildMachineYAMLWithInstall produces a minimal valid Phase 1 MachineConfig
// YAML that includes an install section specifying disk.  The bootstrap field
// uses a freshly-generated self-signed certificate so validation passes.
func buildMachineYAMLWithInstall(t *testing.T, disk string) []byte {
	t.Helper()
	pemCert := selfSignedAdminCertPEM(t)
	var b bytes.Buffer
	fmt.Fprintf(&b, `apiVersion: cryptos.dev/v1alpha1
kind: MachineConfig
metadata:
  name: maint-node-1
role:
  kind: root
network:
  interface: eth0
  address: 10.0.0.10/24
  gateway: 10.0.0.1
bootstrap:
  admin_cert_pem: |
`)
	for _, line := range strings.Split(strings.TrimRight(pemCert, "\n"), "\n") {
		fmt.Fprintf(&b, "    %s\n", line)
	}
	fmt.Fprintf(&b, `pki:
  root_key_alg: ECDSA-P384
  root_subject:
    common_name: "CryptOS Root CA"
    organization: "Test Org"
    country: "US"
  root_validity_years: 20
install:
  disk: %s
`, disk)
	return b.Bytes()
}

// newConfirmCmd returns a cobra.Command wired with the given stdin and a
// captured stdout, for exercising confirmUnverifiedRevocation.
func newConfirmCmd(stdin string) (*cobra.Command, *bytes.Buffer) {
	cmd := &cobra.Command{}
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetIn(strings.NewReader(stdin))
	return cmd, out
}

func TestConfirmUnverifiedRevocation_Root(t *testing.T) {
	cfg := &config.Config{
		Role: config.Role{Kind: config.RoleRoot},
		PKI:  config.PKI{RootSubject: config.Subject{CommonName: "ACME Root CA G1"}},
	}
	// Correct CN proceeds.
	cmd, _ := newConfirmCmd("ACME Root CA G1\n")
	if err := confirmUnverifiedRevocation(cmd, cfg, false); err != nil {
		t.Fatalf("root with correct CN should proceed, got %v", err)
	}
	// Wrong CN aborts; "yes" is NOT accepted on a root.
	for _, in := range []string{"wrong\n", "yes\n"} {
		cmd, _ := newConfirmCmd(in)
		if err := confirmUnverifiedRevocation(cmd, cfg, false); err == nil {
			t.Fatalf("root with input %q should abort", in)
		}
	}
	// --yes skips the prompt.
	cmd, _ = newConfirmCmd("")
	if err := confirmUnverifiedRevocation(cmd, cfg, true); err != nil {
		t.Fatalf("--yes should skip confirmation, got %v", err)
	}
}

func TestConfirmUnverifiedRevocation_Subordinate(t *testing.T) {
	cfg := &config.Config{
		Role: config.Role{Kind: config.RoleIntermediate},
		PKI:  config.PKI{RootSubject: config.Subject{CommonName: "ACME Intermediate CA G1"}},
	}
	cmd, _ := newConfirmCmd("yes\n")
	if err := confirmUnverifiedRevocation(cmd, cfg, false); err != nil {
		t.Fatalf("subordinate with yes should proceed, got %v", err)
	}
	cmd, _ = newConfirmCmd("no\n")
	if err := confirmUnverifiedRevocation(cmd, cfg, false); err == nil {
		t.Fatal("subordinate with 'no' should abort")
	}
}

// A hostname revocation_base_url with no network.nameservers depends on the
// DHCP lease for DNS. apply warns on stderr before contacting the node, and
// stays quiet once a static resolver is declared (#233).
func TestConfigApply_WarnsWhenRevocationHostHasNoResolver(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra string
		warn  bool
	}{
		{"no nameservers", "", true},
		{"static nameservers", "  nameservers: [10.0.0.53]\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := strings.Replace(string(buildMachineYAMLWithInstall(t, "/dev/vdb")),
				"  gateway: 10.0.0.1\n", "  gateway: 10.0.0.1\n"+tc.extra, 1)
			raw = strings.Replace(raw, "  root_validity_years: 20\n",
				"  root_validity_years: 20\n  revocation_base_url: http://pki.example.org\n", 1)
			file := filepath.Join(t.TempDir(), "machine.yaml")
			if err := os.WriteFile(file, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			// An identity that does not exist makes dial fail, so the command
			// stops after the client-side checks without a node.
			missing := filepath.Join(t.TempDir(), "missing.pem")
			cmd := newConfigApplyCmd(&globalOpts{endpoint: "127.0.0.1:1", identityCert: missing, identityKey: missing, trustCert: missing})
			stderr := &bytes.Buffer{}
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(stderr)
			cmd.SetArgs([]string{"-f", file})
			if err := cmd.Execute(); err == nil {
				t.Fatal("expected the dial to fail")
			}
			got := strings.Contains(stderr.String(), "network.nameservers")
			if got != tc.warn {
				t.Fatalf("warning printed = %t, want %t; stderr:\n%s", got, tc.warn, stderr.String())
			}
		})
	}
}

// A config that names the admin only by fingerprint is refused on the
// workstation, before the client reads its identity or dials anything: a node
// installed from it would erase its disk and then boot-loop. The error says
// what to do instead.
func TestConfigApply_RefusesFingerprintOnlyAdminBeforeDialing(t *testing.T) {
	raw := string(buildMachineYAMLWithInstall(t, "/dev/vdb"))
	start := strings.Index(raw, "bootstrap:")
	end := strings.Index(raw, "pki:")
	if start < 0 || end < start {
		t.Fatalf("test config has no bootstrap section:\n%s", raw)
	}
	raw = raw[:start] + "bootstrap:\n  admin_cert_sha256: \"" + strings.Repeat("a", 64) + "\"\n" + raw[end:]
	file := filepath.Join(t.TempDir(), "machine.yaml")
	if err := os.WriteFile(file, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	// Nothing here can be dialled or read: if the refusal didn't come first, the
	// error would be about the missing identity or the connection.
	missing := filepath.Join(t.TempDir(), "missing.pem")
	cmd := newConfigApplyCmd(&globalOpts{endpoint: "127.0.0.1:1", identityCert: missing, identityKey: missing, trustCert: missing})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"-f", file})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected the fingerprint-only config to be refused")
	}
	for _, want := range []string{"bootstrap.admin_cert_sha256", "needs the full admin certificate", "set bootstrap.admin_cert_pem"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not contain %q", err.Error(), want)
		}
	}
}

// apply warns when the node has no declared time source, and when a hostname
// time server has no static resolver to find it.
func TestConfigApply_WarnsAboutTimeSource(t *testing.T) {
	for _, tc := range []struct {
		name      string
		extra     string
		wantWarns []string
		noWarns   []string
	}{
		{"no ntp servers", "", []string{"network.ntp_servers is empty"}, nil},
		{"literal ntp server", "  ntp_servers: [10.0.0.123]\n", nil, []string{"ntp_servers"}},
		{"hostname ntp server without nameservers", "  ntp_servers: [time.example.org]\n", []string{"time.example.org", "network.nameservers"}, []string{"is empty. The node syncs"}},
		{"hostname ntp server with nameservers", "  ntp_servers: [time.example.org]\n  nameservers: [10.0.0.53]\n", nil, []string{"ntp_servers"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := strings.Replace(string(buildMachineYAMLWithInstall(t, "/dev/vdb")),
				"  gateway: 10.0.0.1\n", "  gateway: 10.0.0.1\n"+tc.extra, 1)
			file := filepath.Join(t.TempDir(), "machine.yaml")
			if err := os.WriteFile(file, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			missing := filepath.Join(t.TempDir(), "missing.pem")
			cmd := newConfigApplyCmd(&globalOpts{endpoint: "127.0.0.1:1", identityCert: missing, identityKey: missing, trustCert: missing})
			stderr := &bytes.Buffer{}
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(stderr)
			cmd.SetArgs([]string{"-f", file})
			if err := cmd.Execute(); err == nil {
				t.Fatal("expected the dial to fail")
			}
			for _, w := range tc.wantWarns {
				if !strings.Contains(stderr.String(), w) {
					t.Errorf("stderr missing %q:\n%s", w, stderr.String())
				}
			}
			for _, w := range tc.noWarns {
				if strings.Contains(stderr.String(), w) {
					t.Errorf("stderr unexpectedly contains %q:\n%s", w, stderr.String())
				}
			}
		})
	}
}
