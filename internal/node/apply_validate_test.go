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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"github.com/CryptOS-PKI/cryptos-node/internal/config"
	"github.com/CryptOS-PKI/cryptos-node/internal/testadmin"
)

// applyValidateSeed is a valid running-node config with a leaf profile that
// ACME references.
const applyValidateSeed = `apiVersion: cryptos.dev/v1alpha1
kind: MachineConfig
metadata: {name: apply-validate-test}
role: {kind: issuing}
network: {interface: eth0, address: 10.0.0.10/24, gateway: 10.0.0.1}
bootstrap: {admin_cert_pem: "` + testadmin.YAMLPEM + `"}
pki:
  root_key_alg: ECDSA-P384
  root_subject: {common_name: "Apply Validate Issuing CA", organization: "Test", country: "US"}
  path_len_constraint: 0
  parent: {ca_cert_sha256: "abababababababababababababababababababababababababababababababab"}
  revocation_base_url: https://ca.example.org
  profiles:
    - name: leaf-server
      key_alg: ECDSA-P384
      validity_days: 90
      key_usage: [digital_signature]
      ext_key_usage: [server_auth]
  acme:
    base_url: https://ca.example.org/acme
    profile: leaf-server
    allow_anonymous_accounts: true
`

// TestConfigStoreApply_RejectsInvalidConfig is the regression guard for #229.
//
// Apply on a running node used to persist whatever FromProto produced without
// running the schema rules, so an invalid config could reach a live CA: hot
// fields were used for signing at once, and the rest failed config.Parse on the
// next boot. Apply must fail closed: InvalidArgument, and nothing persisted.
func TestConfigStoreApply_RejectsInvalidConfig(t *testing.T) {
	seed, err := config.Parse([]byte(applyValidateSeed))
	if err != nil {
		t.Fatalf("config.Parse(seed): %v", err)
	}

	tests := []struct {
		name   string
		mutate func(pb *nodev1.MachineConfig)
	}{
		{
			name: "malformed revocation_base_url",
			mutate: func(pb *nodev1.MachineConfig) {
				pb.Pki.RevocationBaseUrl = "not a url"
			},
		},
		{
			name: "invalid profile",
			mutate: func(pb *nodev1.MachineConfig) {
				pb.Pki.Profiles[0].ValidityDays = 0
			},
		},
		{
			name: "missing root subject common name",
			mutate: func(pb *nodev1.MachineConfig) {
				pb.Pki.RootSubject.CommonName = ""
			},
		},
		{
			// Valid on its own, invalid once the ACME block names a profile
			// the incoming config dropped. Validation has to run on the
			// config that would actually be written.
			name: "carried-forward ACME references a removed profile",
			mutate: func(pb *nodev1.MachineConfig) {
				pb.Pki.Profiles[0].Name = "leaf-renamed"
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			fs := config.NewFileStore(t.TempDir())
			if _, err := fs.Write([]byte(applyValidateSeed)); err != nil {
				t.Fatalf("FileStore.Write (seed): %v", err)
			}
			beforeRaw, beforeGen, ok, err := fs.Read()
			if err != nil || !ok {
				t.Fatalf("FileStore.Read (before): ok=%v err=%v", ok, err)
			}

			pb := seed.ToProto()
			tc.mutate(pb)

			cs := NewConfigStore(fs)
			resp, err := cs.Apply(ctx, pb)
			if err == nil {
				t.Fatalf("Apply(invalid) = %v, nil error; want an error", resp)
			}
			if got := status.Code(err); got != codes.InvalidArgument {
				t.Errorf("Apply(invalid) code = %v, want InvalidArgument (err: %v)", got, err)
			}

			afterRaw, afterGen, ok, err := fs.Read()
			if err != nil || !ok {
				t.Fatalf("FileStore.Read (after): ok=%v err=%v", ok, err)
			}
			if afterGen != beforeGen {
				t.Errorf("generation after rejected Apply = %d, want unchanged %d", afterGen, beforeGen)
			}
			if !bytes.Equal(afterRaw, beforeRaw) {
				t.Error("persisted config changed after a rejected Apply")
			}
		})
	}
}
