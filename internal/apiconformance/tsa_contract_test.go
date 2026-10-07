package apiconformance_test

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
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestPkiCarriesTsaBlock(t *testing.T) {
	pki := nodev1.File_cryptos_node_v1_config_proto.Messages().ByName("Pki")
	if pki == nil {
		t.Fatal("message Pki is not declared")
	}
	assertProtocolField(t, pki, "tsa", protocolField{16, protoreflect.MessageKind, false, "cryptos.node.v1.Tsa"})
}

func TestTsaMirrorsNodeConfig(t *testing.T) {
	fd := nodev1.File_cryptos_node_v1_config_proto
	assertProtocolShape(t, fd, "Tsa", map[protoreflect.Name]protocolField{
		"enabled":              {1, protoreflect.BoolKind, false, ""},
		"http_port":            {2, protoreflect.Uint32Kind, false, ""},
		"policy_oid":           {3, protoreflect.StringKind, false, ""},
		"accuracy_ms":          {4, protoreflect.Uint32Kind, false, ""},
		"rate_limit":           {5, protoreflect.MessageKind, false, "cryptos.node.v1.TsaRateLimit"},
		"allowed_networks":     {6, protoreflect.StringKind, true, ""},
		"certificate":          {7, protoreflect.MessageKind, false, "cryptos.node.v1.TsaCertificateSettings"},
		"max_sync_age_seconds": {8, protoreflect.Uint32Kind, false, ""},
		"max_drift_ppm":        {9, protoreflect.Uint32Kind, false, ""},
		"max_clock_error_ms":   {10, protoreflect.Uint32Kind, false, ""},
	})
	assertProtocolShape(t, fd, "TsaRateLimit", map[protoreflect.Name]protocolField{
		"requests_per_minute": {1, protoreflect.Uint32Kind, false, ""},
		"burst":               {2, protoreflect.Uint32Kind, false, ""},
	})
	assertProtocolShape(t, fd, "TsaCertificateSettings", map[protoreflect.Name]protocolField{
		"validity_days":         {1, protoreflect.Uint32Kind, false, ""},
		"rotation_overlap_days": {2, protoreflect.Uint32Kind, false, ""},
	})
}

// No deployment may inherit another's policy OID, so the field must stay a
// plain string with no default for a generated client to fill in.
func TestTsaPolicyOIDHasNoDefault(t *testing.T) {
	md := nodev1.File_cryptos_node_v1_config_proto.Messages().ByName("Tsa")
	if md == nil {
		t.Fatal("message Tsa is not declared")
	}
	f := md.Fields().ByName("policy_oid")
	if f == nil {
		t.Fatal("Tsa.policy_oid is not declared")
	}
	if f.HasDefault() || f.HasPresence() {
		t.Error("Tsa.policy_oid must be a plain proto3 string with no default")
	}
	if got := (&nodev1.Tsa{}).GetPolicyOid(); got != "" {
		t.Errorf("a zero Tsa has policy_oid %q, want empty", got)
	}
}

func TestServiceProtocolIncludesTsa(t *testing.T) {
	ed := nodev1.File_cryptos_node_v1_status_proto.Enums().ByName("ServiceProtocol")
	if ed == nil {
		t.Fatal("enum ServiceProtocol is not declared")
	}
	v := ed.Values().ByName("SERVICE_PROTOCOL_TSA")
	if v == nil {
		t.Fatal("ServiceProtocol.SERVICE_PROTOCOL_TSA is not declared")
	}
	if v.Number() != 4 {
		t.Errorf("ServiceProtocol.SERVICE_PROTOCOL_TSA = %d, want 4", v.Number())
	}
}

func TestNodeServiceDeclaresListTsaCertificates(t *testing.T) {
	svc := nodev1.File_cryptos_node_v1_node_proto.Services().ByName("NodeService")
	if svc == nil {
		t.Fatal("service NodeService is not declared")
	}
	m := svc.Methods().ByName("ListTsaCertificates")
	if m == nil {
		t.Fatal("NodeService.ListTsaCertificates is not declared")
	}
	if m.IsStreamingClient() || m.IsStreamingServer() {
		t.Error("NodeService.ListTsaCertificates must be unary")
	}
	if got := m.Input().FullName(); got != "cryptos.node.v1.ListTsaCertificatesRequest" {
		t.Errorf("NodeService.ListTsaCertificates takes %s", got)
	}
	if got := m.Output().FullName(); got != "cryptos.node.v1.ListTsaCertificatesResponse" {
		t.Errorf("NodeService.ListTsaCertificates returns %s", got)
	}
}

func TestTsaCertificateMessages(t *testing.T) {
	fd := nodev1.File_cryptos_node_v1_tsa_proto
	assertProtocolShape(t, fd, "TsaCertificate", map[protoreflect.Name]protocolField{
		"cert_pem":   {1, protoreflect.StringKind, false, ""},
		"serial_hex": {2, protoreflect.StringKind, false, ""},
		"sha256_hex": {3, protoreflect.StringKind, false, ""},
		"not_before": {4, protoreflect.MessageKind, false, "google.protobuf.Timestamp"},
		"not_after":  {5, protoreflect.MessageKind, false, "google.protobuf.Timestamp"},
		"current":    {6, protoreflect.BoolKind, false, ""},
	})
	assertProtocolShape(t, fd, "ListTsaCertificatesRequest", map[protoreflect.Name]protocolField{})
	assertProtocolShape(t, fd, "ListTsaCertificatesResponse", map[protoreflect.Name]protocolField{
		"certificates": {1, protoreflect.MessageKind, true, "cryptos.node.v1.TsaCertificate"},
	})
}
