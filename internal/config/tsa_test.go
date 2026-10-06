package config

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
	"encoding/asn1"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

// validTSA is a block that must pass, so each rejection below differs from a
// passing config in exactly one way.
func validTSA() *TSA {
	return &TSA{
		HTTPPort:        3318,
		PolicyOID:       "1.3.6.1.4.1.32473.1.1",
		AccuracyMS:      500,
		RateLimit:       TSARateLimit{RequestsPerMinute: 120, Burst: 20},
		AllowedNetworks: []string{"192.0.2.0/24", "2001:db8::/32", "198.51.100.7"},
		Certificate:     TSACertificate{ValidityDays: 200, RotationOverlapDays: 20},
	}
}

func TestValidateTSAAccepts(t *testing.T) {
	cfg := issuingConfig(t)
	cfg.PKI.TSA = validTSA()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a valid TSA block was rejected: %v", err)
	}
	cfg.PKI.TSA = &TSA{PolicyOID: "2.999"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a TSA block with only a policy was rejected: %v", err)
	}
}

func TestValidateTSAAbsentIsOff(t *testing.T) {
	cfg := issuingConfig(t)
	if cfg.PKI.TSA != nil {
		t.Fatal("the TSA must default to off")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateTSARejects(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*TSA)
		want   string
	}{
		"no policy":               {func(s *TSA) { s.PolicyOID = "" }, "pki.tsa.policy_oid: required"},
		"one arc":                 {func(s *TSA) { s.PolicyOID = "1" }, "pki.tsa.policy_oid"},
		"first arc 3":             {func(s *TSA) { s.PolicyOID = "3.1" }, "pki.tsa.policy_oid"},
		"second arc 40 under 1":   {func(s *TSA) { s.PolicyOID = "1.40" }, "pki.tsa.policy_oid"},
		"leading zero":            {func(s *TSA) { s.PolicyOID = "1.3.06.1" }, "pki.tsa.policy_oid"},
		"empty arc":               {func(s *TSA) { s.PolicyOID = "1.3..1" }, "pki.tsa.policy_oid"},
		"not decimal":             {func(s *TSA) { s.PolicyOID = "1.3.6.x" }, "pki.tsa.policy_oid"},
		"signed arc":              {func(s *TSA) { s.PolicyOID = "1.3.+6" }, "pki.tsa.policy_oid"},
		"arc too large":           {func(s *TSA) { s.PolicyOID = "1.3.99999999999999999999" }, "pki.tsa.policy_oid"},
		"port":                    {func(s *TSA) { s.HTTPPort = 70000 }, "pki.tsa.http_port"},
		"accuracy over a minute":  {func(s *TSA) { s.AccuracyMS = 60001 }, "pki.tsa.accuracy_ms"},
		"bad network":             {func(s *TSA) { s.AllowedNetworks = []string{"10.0.0.0/33"} }, "pki.tsa.allowed_networks[0]"},
		"hostname network":        {func(s *TSA) { s.AllowedNetworks = []string{"ca.example.org"} }, "pki.tsa.allowed_networks[0]"},
		"validity over a year":    {func(s *TSA) { s.Certificate.ValidityDays = 366 }, "pki.tsa.certificate.validity_days"},
		"overlap not shorter":     {func(s *TSA) { s.Certificate.RotationOverlapDays = 200 }, "pki.tsa.certificate.rotation_overlap_days"},
		"default overlap too big": {func(s *TSA) { s.Certificate = TSACertificate{ValidityDays: 30} }, "pki.tsa.certificate.rotation_overlap_days"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := issuingConfig(t)
			cfg.PKI.TSA = validTSA()
			tc.mutate(cfg.PKI.TSA)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate = %v, want an error naming %q", err, tc.want)
			}
		})
	}
}

func TestValidateTSARejectsARoot(t *testing.T) {
	cfg, err := Parse(validYAML(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg.PKI.TSA = validTSA()
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "pki.tsa") {
		t.Fatalf("a Root accepted the TSA: %v", err)
	}
	cfg.PKI.TSA, cfg.PKI.DisabledTSA = nil, validTSA()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a Root refused an off TSA block: %v", err)
	}
}

func TestTSADefaults(t *testing.T) {
	var s TSA
	if s.Accuracy() != time.Second {
		t.Errorf("Accuracy = %s, want 1s", s.Accuracy())
	}
	if s.RequestsPerMinute() != 60 || s.Burst() != 60 {
		t.Errorf("rate = %d/min burst %d, want 60 and 60", s.RequestsPerMinute(), s.Burst())
	}
	s.RateLimit.RequestsPerMinute = 30
	if s.Burst() != 30 {
		t.Errorf("burst = %d, want the rate (30)", s.Burst())
	}
	if s.Certificate.Validity() != 365*24*time.Hour || s.Certificate.Overlap() != 30*24*time.Hour {
		t.Errorf("certificate = %s overlap %s, want 365d and 30d", s.Certificate.Validity(), s.Certificate.Overlap())
	}
	v := validTSA()
	if v.Accuracy() != 500*time.Millisecond {
		t.Errorf("Accuracy = %s", v.Accuracy())
	}
	oid, err := v.Policy()
	if err != nil || !oid.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 32473, 1, 1}) {
		t.Errorf("Policy = %v, %v", oid, err)
	}
	nets, err := v.Networks()
	want := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("198.51.100.7/32")}
	if err != nil || !reflect.DeepEqual(nets, want) {
		t.Errorf("Networks = %v, %v", nets, err)
	}
}

func TestTSARoundTripsThroughProto(t *testing.T) {
	cfg := issuingConfig(t)
	cfg.PKI.TSA = validTSA()
	pb := cfg.ToProto()
	got := pb.GetPki().GetTsa()
	if !got.GetEnabled() || got.GetPolicyOid() != "1.3.6.1.4.1.32473.1.1" || got.GetHttpPort() != 3318 ||
		got.GetAccuracyMs() != 500 || got.GetRateLimit().GetRequestsPerMinute() != 120 || got.GetRateLimit().GetBurst() != 20 ||
		got.GetCertificate().GetValidityDays() != 200 || got.GetCertificate().GetRotationOverlapDays() != 20 ||
		!reflect.DeepEqual(got.GetAllowedNetworks(), cfg.PKI.TSA.AllowedNetworks) {
		t.Fatalf("ToProto lost TSA settings: %v", got)
	}
	back, err := FromProto(pb)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back.PKI.TSA, cfg.PKI.TSA) {
		t.Fatalf("FromProto = %+v, want %+v", back.PKI.TSA, cfg.PKI.TSA)
	}
}

func TestTSABlockRules(t *testing.T) {
	prev := issuingConfig(t)
	prev.PKI.TSA = validTSA()

	absent := prev.ToProto()
	absent.Pki.Tsa = nil
	got, err := FromProtoOver(absent, prev)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.PKI.TSA, prev.PKI.TSA) {
		t.Fatal("an apply without the TSA block did not keep the stored one")
	}

	off := prev.ToProto()
	off.Pki.Tsa.Enabled = false
	got, err = FromProtoOver(off, prev)
	if err != nil {
		t.Fatal(err)
	}
	if got.PKI.TSA != nil || !reflect.DeepEqual(got.PKI.DisabledTSA, prev.PKI.TSA) {
		t.Fatalf("enabled=false: on=%+v off=%+v, want off keeping the settings", got.PKI.TSA, got.PKI.DisabledTSA)
	}
	if rb := got.ToProto().GetPki().GetTsa(); rb.GetEnabled() || rb.GetPolicyOid() != prev.PKI.TSA.PolicyOID {
		t.Fatalf("the off block read back as %v", rb)
	}

	offIncomplete := &nodev1.MachineConfig{}
	*offIncomplete = *prev.ToProto()
	offIncomplete.Pki.Tsa = &nodev1.Tsa{Enabled: false, HttpPort: 999999}
	got, err = FromProtoOver(offIncomplete, prev)
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("an off block was checked for completeness: %v", err)
	}

	on := prev.ToProto()
	on.Pki.Tsa.PolicyOid = ""
	got, err = FromProtoOver(on, prev)
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Validate(); err == nil {
		t.Fatal("enabled=true without a policy OID validated")
	}
}

func TestTSAYAMLEnabledFlag(t *testing.T) {
	base := issuingConfig(t)
	base.PKI.TSA = validTSA()
	raw, err := base.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !reflect.DeepEqual(got.PKI.TSA, base.PKI.TSA) {
		t.Fatal("the TSA block did not round-trip through YAML")
	}

	base.PKI.TSA, base.PKI.DisabledTSA = nil, validTSA()
	raw, err = base.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "enabled: false") {
		t.Fatalf("an off TSA block is not written with enabled: false:\n%s", raw)
	}
	got, err = Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.PKI.TSA != nil || !reflect.DeepEqual(got.PKI.DisabledTSA, base.PKI.DisabledTSA) {
		t.Fatal("the off TSA block did not round-trip through YAML")
	}
}

func TestTSAChangeNeedsAReboot(t *testing.T) {
	old := issuingConfig(t)
	next := issuingConfig(t)
	next.PKI.TSA = validTSA()
	if !NeedsReboot(old, next) {
		t.Error("switching the TSA on is live, want reboot-required")
	}
	old.PKI.TSA = validTSA()
	next.PKI.TSA.AccuracyMS = 900
	if !NeedsReboot(old, next) {
		t.Error("changing the TSA accuracy is live, want reboot-required")
	}
}
