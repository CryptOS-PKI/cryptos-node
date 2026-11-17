package testadmin

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
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestPEMIsAnAdminCertificate(t *testing.T) {
	c := Certificate()
	if c.Subject.CommonName != "test-admin" {
		t.Fatalf("common name = %q", c.Subject.CommonName)
	}
	if c.IsCA {
		t.Fatalf("the admin certificate is a CA")
	}
}

// YAMLPEM must come out of a YAML double-quoted scalar as exactly PEMText, so a
// one-line flow mapping can carry the whole certificate.
func TestYAMLPEMRoundTripsThroughYAML(t *testing.T) {
	var doc struct {
		Bootstrap struct {
			PEM string `yaml:"admin_cert_pem"`
		} `yaml:"bootstrap"`
	}
	if err := yaml.Unmarshal([]byte(`bootstrap: {admin_cert_pem: "`+YAMLPEM+`"}`), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Bootstrap.PEM != PEMText {
		t.Fatalf("YAMLPEM decoded to %q, want PEMText", doc.Bootstrap.PEM)
	}
}

func TestBootstrapIsABlockScalarOfThePEM(t *testing.T) {
	var doc struct {
		Bootstrap struct {
			PEM string `yaml:"admin_cert_pem"`
		} `yaml:"bootstrap"`
	}
	if err := yaml.Unmarshal([]byte(Bootstrap()), &doc); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(doc.Bootstrap.PEM) != strings.TrimSpace(PEMText) {
		t.Fatalf("Bootstrap() decoded to %q", doc.Bootstrap.PEM)
	}
}

func TestFingerprintIsTheDigestOfTheCertificate(t *testing.T) {
	first := Fingerprint()
	second := Fingerprint()
	if first != second {
		t.Fatalf("the fingerprint changed between calls")
	}
	if first == ([32]byte{}) {
		t.Fatalf("the fingerprint is all zeros")
	}
}
