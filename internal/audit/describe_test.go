package audit

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
	"testing"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

func TestDescribe(t *testing.T) {
	for _, tc := range []struct {
		name        string
		ev          *nodev1.AuditEvent
		wantTarget  string
		wantSummary string
	}{
		{
			name: "revocation names the serial",
			ev: &nodev1.AuditEvent{RpcMethod: "/cryptos.node.v1.NodeService/RevokeCertificate", Outcome: nodev1.Outcome_OUTCOME_OK,
				Details: map[string]string{DetailSerial: "1a2b"}},
			wantTarget:  "1a2b",
			wantSummary: "revoked a certificate: 1a2b",
		},
		{
			name: "issuance names the asserted names",
			ev: &nodev1.AuditEvent{RpcMethod: "/cryptos.node.v1.NodeService/IssueLeaf", Outcome: nodev1.Outcome_OUTCOME_OK,
				Details: map[string]string{"request_dns_names": "www.example.org"}},
			wantTarget:  "www.example.org",
			wantSummary: "issued a leaf certificate: www.example.org",
		},
		{
			name: "config apply names the generation",
			ev: &nodev1.AuditEvent{RpcMethod: "/cryptos.node.v1.NodeService/ApplyConfig", Outcome: nodev1.Outcome_OUTCOME_OK,
				Details: map[string]string{DetailConfigGeneration: "7", DetailConfigDigest: "abcd", DetailRequiresReboot: "false"}},
			wantSummary: "applied a machine config: generation 7",
		},
		{
			name: "config apply that needs a reboot says so",
			ev: &nodev1.AuditEvent{RpcMethod: "/cryptos.node.v1.NodeService/ApplyConfig", Outcome: nodev1.Outcome_OUTCOME_OK,
				Details: map[string]string{DetailConfigGeneration: "8", DetailConfigDigest: "abcd", DetailRequiresReboot: "true"}},
			wantSummary: "applied a machine config: generation 8 (takes effect at the next reboot)",
		},
		{
			name: "reboot",
			ev: &nodev1.AuditEvent{RpcMethod: "/cryptos.node.v1.NodeService/Reboot", Outcome: nodev1.Outcome_OUTCOME_OK,
				Details: map[string]string{DetailRebootKind: RebootKindReboot}},
			wantSummary: "rebooted the node",
		},
		{
			name: "power-off",
			ev: &nodev1.AuditEvent{RpcMethod: "/cryptos.node.v1.NodeService/Reboot", Outcome: nodev1.Outcome_OUTCOME_OK,
				Details: map[string]string{DetailRebootKind: RebootKindPowerOff}},
			wantSummary: "powered off the node",
		},
		{
			name:        "reboot recorded before the kind was",
			ev:          &nodev1.AuditEvent{RpcMethod: "/cryptos.node.v1.NodeService/Reboot", Outcome: nodev1.Outcome_OUTCOME_OK},
			wantSummary: "rebooted or powered off the node",
		},
		{
			name:        "denied",
			ev:          &nodev1.AuditEvent{RpcMethod: "/cryptos.node.v1.NodeService/ApplyConfig", Outcome: nodev1.Outcome_OUTCOME_DENIED},
			wantSummary: "applied a machine config (denied)",
		},
		{
			name:        "failed",
			ev:          &nodev1.AuditEvent{RpcMethod: "/cryptos.node.v1.NodeService/StartCeremony", Outcome: nodev1.Outcome_OUTCOME_ERROR},
			wantSummary: "ran the first-boot ceremony (failed)",
		},
		{
			name:        "escrow",
			ev:          &nodev1.AuditEvent{RpcMethod: "/cryptos.node.v1.NodeService/ExportCAKey", Outcome: nodev1.Outcome_OUTCOME_OK},
			wantSummary: "exported an encrypted CA key backup",
		},
		{
			name:        "reboot",
			ev:          &nodev1.AuditEvent{RpcMethod: "/cryptos.node.v1.NodeService/Reboot", Outcome: nodev1.Outcome_OUTCOME_OK},
			wantSummary: "rebooted or powered off the node",
		},
		{
			name:        "an RPC with no description",
			ev:          &nodev1.AuditEvent{RpcMethod: "/cryptos.node.v1.NodeService/GetStatus", Outcome: nodev1.Outcome_OUTCOME_OK},
			wantSummary: "called GetStatus",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target, summary := Describe(tc.ev)
			if target != tc.wantTarget || summary != tc.wantSummary {
				t.Errorf("Describe = (%q, %q), want (%q, %q)", target, summary, tc.wantTarget, tc.wantSummary)
			}
		})
	}
}

// MethodName is the name an operator filters by and sees.
func TestMethodName(t *testing.T) {
	for in, want := range map[string]string{
		"/cryptos.node.v1.NodeService/IssueLeaf": "IssueLeaf",
		"cryptos.node.v1.NodeService/IssueLeaf":  "IssueLeaf",
		"IssueLeaf":                              "IssueLeaf",
		"":                                       "",
	} {
		if got := MethodName(in); got != want {
			t.Errorf("MethodName(%q) = %q, want %q", in, got, want)
		}
	}
}

// A failed call says why when the handler recorded a reason: the operator
// reading the log sees what the node refused, not only that it did.
func TestDescribe_FailureReason(t *testing.T) {
	const method = "/cryptos.node.v1.NodeService/SetManagement"
	for _, tc := range []struct {
		name        string
		ev          *nodev1.AuditEvent
		wantSummary string
	}{
		{
			name: "a failure with a reason shows it",
			ev: &nodev1.AuditEvent{RpcMethod: method, Outcome: nodev1.Outcome_OUTCOME_ERROR,
				Details: map[string]string{DetailError: "config: management.manager_cn: required when management is set"}},
			wantSummary: "changed the Fleet Manager link (failed): config: management.manager_cn: required when management is set",
		},
		{
			name:        "a failure with no reason is as before",
			ev:          &nodev1.AuditEvent{RpcMethod: method, Outcome: nodev1.Outcome_OUTCOME_ERROR},
			wantSummary: "changed the Fleet Manager link (failed)",
		},
		{
			name: "a success ignores a stray reason",
			ev: &nodev1.AuditEvent{RpcMethod: method, Outcome: nodev1.Outcome_OUTCOME_OK,
				Details: map[string]string{DetailError: "left over"}},
			wantSummary: "changed the Fleet Manager link",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, got := Describe(tc.ev); got != tc.wantSummary {
				t.Fatalf("summary = %q, want %q", got, tc.wantSummary)
			}
		})
	}
}
