package ceremony

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
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

// TestStart_RSAOnTPMWithoutSize_FailsPrecondition runs the root ceremony with
// root_key_alg RSA-3072 against the in-process simulator, which, like many
// real TPM parts, implements RSA-2048 only. The ceremony must stop with
// FailedPrecondition naming the algorithm, emit nothing, commit no identity,
// and leave the node able to run the ceremony again with an algorithm the TPM
// has. It must never fall back to a software key or a smaller size.
func TestStart_RSAOnTPMWithoutSize_FailsPrecondition(t *testing.T) {
	h, ctx := newHarness(t)
	c := &collector{}
	rsaYAML := bytes.Replace(machineYAML(h.adminPEM), []byte("root_key_alg: ECDSA-P384"), []byte("root_key_alg: RSA-3072"), 1)

	err := h.engine.Start(ctx, &nodev1.StartCeremonyRequest{
		Kind:              nodev1.CeremonyKind_CEREMONY_KIND_FIRST_BOOT_ROOT,
		MachineConfigYaml: rsaYAML,
	}, c.send)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("Start(RSA-3072 on a TPM without it): code = %v, want FailedPrecondition (err=%v)", status.Code(err), err)
	}
	if !strings.Contains(err.Error(), "RSA-3072") {
		t.Errorf("error %q does not name RSA-3072", err)
	}
	if len(c.kinds) != 0 {
		t.Errorf("events emitted on a refused ceremony: %v", c.kinds)
	}
	if ok, _ := h.store.HasIdentity(ctx); ok {
		t.Fatal("identity established despite the TPM lacking RSA-3072")
	}

	retry := &collector{}
	if err := h.engine.Start(ctx, &nodev1.StartCeremonyRequest{
		Kind:              nodev1.CeremonyKind_CEREMONY_KIND_FIRST_BOOT_ROOT,
		MachineConfigYaml: machineYAML(h.adminPEM),
	}, retry.send); err != nil {
		t.Fatalf("retry with ECDSA-P384: %v", err)
	}
	assertOrder(t, retry.kinds, wantOrder())
}
