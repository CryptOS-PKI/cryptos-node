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
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"strings"
)

// Package testadmin gives tests one real bootstrap admin certificate.
//
// A config that names the admin only by fingerprint is refused (a node
// installed from one boot-loops), so tests that need a valid config use the
// whole certificate. The certificate is fixed and public: a self-signed ECDSA
// P-256 certificate with the common name test-admin, valid for a hundred years
// so no test expires, and its key was discarded. A test that needs to sign as
// the admin makes its own key and certificate instead.

// PEMText is the admin certificate as one PEM CERTIFICATE block, the value of
// bootstrap.admin_cert_pem.
const PEMText = `-----BEGIN CERTIFICATE-----
MIIBSTCB8KADAgECAgkA9IcLX/4D0A8wCgYIKoZIzj0EAwIwFTETMBEGA1UEAwwK
dGVzdC1hZG1pbjAgFw0yNjExMTcyMDMyMzZaGA8yMTI2MTAyNDIwMzIzNlowFTET
MBEGA1UEAwwKdGVzdC1hZG1pbjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABON4
5yGY7uP+dL2C1eayPaWSUce+ccOO49Gp0lXgKPgurLrACILG1hB4QmwSy2nEL6Ss
Hs93+sPgV2nsR6qCrGmjJzAlMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggr
BgEFBQcDAjAKBggqhkjOPQQDAgNIADBFAiBSqiDnvadPHgRtZR6o0yRTke+1QC8Q
6n2F3wmveXEseQIhALBsfBNrksxHVdUx6KNGfnKChhcMPyTVfxCSZ0VzvOrT
-----END CERTIFICATE-----
`

// YAMLPEM is PEMText on one line, with the line breaks written as \n, for a
// double-quoted YAML scalar. It lets a one-line flow mapping carry the whole
// certificate: bootstrap: {admin_cert_pem: "<YAMLPEM>"}.
const YAMLPEM = "-----BEGIN CERTIFICATE-----\\nMIIBSTCB8KADAgECAgkA9IcLX/4D0A8wCgYIKoZIzj0EAwIwFTETMBEGA1UEAwwK\\ndGVzdC1hZG1pbjAgFw0yNjExMTcyMDMyMzZaGA8yMTI2MTAyNDIwMzIzNlowFTET\\nMBEGA1UEAwwKdGVzdC1hZG1pbjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABON4\\n5yGY7uP+dL2C1eayPaWSUce+ccOO49Gp0lXgKPgurLrACILG1hB4QmwSy2nEL6Ss\\nHs93+sPgV2nsR6qCrGmjJzAlMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggr\\nBgEFBQcDAjAKBggqhkjOPQQDAgNIADBFAiBSqiDnvadPHgRtZR6o0yRTke+1QC8Q\\n6n2F3wmveXEseQIhALBsfBNrksxHVdUx6KNGfnKChhcMPyTVfxCSZ0VzvOrT\\n-----END CERTIFICATE-----\\n"

// PEM returns PEMText.
func PEM() string { return PEMText }

// Certificate is the parsed admin certificate.
func Certificate() *x509.Certificate {
	block, _ := pem.Decode([]byte(PEMText))
	if block == nil {
		panic("testadmin: PEMText holds no PEM block")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("testadmin: parse certificate: " + err.Error())
	}
	return c
}

// Fingerprint is the SHA-256 of the admin certificate's DER bytes.
func Fingerprint() [32]byte { return sha256.Sum256(Certificate().Raw) }

// Bootstrap is a complete top-level bootstrap section for a YAML machine
// config, ending in a newline: "bootstrap:" with admin_cert_pem as a block
// scalar. Splice it where a fixture had a bootstrap line.
func Bootstrap() string {
	return "bootstrap:\n  admin_cert_pem: |\n" + Indent(PEMText, "    ")
}

// Indent prefixes every non-empty line of s with prefix and ends the result
// with a newline.
func Indent(s, prefix string) string {
	var b strings.Builder
	for _, l := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		if l != "" {
			b.WriteString(prefix)
		}
		b.WriteString(l)
		b.WriteString("\n")
	}
	return b.String()
}
