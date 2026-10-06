package tsa

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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The OpenSSL tests check the tokens against an independent RFC 3161
// implementation: `openssl ts` builds the requests and verifies the replies.
// They need OpenSSL 3 (CRYPTOS_TEST_OPENSSL overrides the binary). Without
// it they skip locally, but fail under CI, so the check never silently stops
// running.

type tsOpenSSL struct {
	t   *testing.T
	bin string
	dir string
}

func newTSOpenSSL(t *testing.T) *tsOpenSSL {
	t.Helper()
	bin := os.Getenv("CRYPTOS_TEST_OPENSSL")
	if bin == "" {
		bin = "openssl"
	}
	unavailable := func(why string) {
		if os.Getenv("CI") != "" {
			t.Fatalf("OpenSSL interoperability tests cannot run under CI: %s", why)
		}
		t.Skipf("skipping OpenSSL interoperability: %s (set CRYPTOS_TEST_OPENSSL)", why)
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		unavailable(bin + " is not on PATH")
	}
	out, err := exec.Command(path, "version").CombinedOutput()
	if err != nil || !strings.HasPrefix(string(out), "OpenSSL 3") {
		unavailable("need OpenSSL 3, have " + strings.TrimSpace(string(out)))
	}
	return &tsOpenSSL{t: t, bin: path, dir: t.TempDir()}
}

func (o *tsOpenSSL) run(args ...string) string {
	o.t.Helper()
	cmd := exec.Command(o.bin, args...)
	cmd.Dir = o.dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		o.t.Fatalf("openssl %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func (o *tsOpenSSL) write(name string, data []byte) string {
	o.t.Helper()
	p := filepath.Join(o.dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		o.t.Fatal(err)
	}
	return p
}

func (o *tsOpenSSL) read(name string) []byte {
	o.t.Helper()
	b, err := os.ReadFile(filepath.Join(o.dir, name))
	if err != nil {
		o.t.Fatal(err)
	}
	return b
}

func certPEM(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

// tsaKeys are the TSA key algorithms a node can have: the CA key's.
func tsaKeys(t *testing.T) map[string]crypto.Signer {
	t.Helper()
	ec, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]crypto.Signer{"ECDSA P-384": ec, "RSA 3072": r}
}

func TestOpenSSLVerifiesOurTokens(t *testing.T) {
	o := newTSOpenSSL(t)
	for name, key := range tsaKeys(t) {
		t.Run(name, func(t *testing.T) {
			o := &tsOpenSSL{t: t, bin: o.bin, dir: t.TempDir()}
			authority := newTestCA(t, "Example Issuing CA G1")
			s := &staticSigner{cert: issueTSACert(t, authority, key), key: key}
			r := newTestResponder(t, s, nil)
			o.write("ca.pem", certPEM(authority.cert))
			o.write("tsa.pem", certPEM(s.cert))
			o.write("artifact.bin", []byte("an artifact to timestamp"))

			cases := []struct {
				name  string
				query []string
				// verify is how the reply is checked: against the query
				// file, or against the data with the TSA certificate
				// supplied when the token does not carry it.
				verify []string
			}{
				{"sha256 with nonce and certReq", []string{"-sha256", "-cert"}, []string{"-queryfile", "req.tsq"}},
				{"sha384 without certReq", []string{"-sha384"}, []string{"-data", "artifact.bin", "-untrusted", "tsa.pem"}},
				{"sha512 no nonce with the served policy", []string{"-sha512", "-no_nonce", "-cert", "-tspolicy", testPolicy.String()}, []string{"-queryfile", "req.tsq"}},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					o := &tsOpenSSL{t: t, bin: o.bin, dir: o.dir}
					o.run(append([]string{"ts", "-query", "-data", "artifact.bin", "-out", "req.tsq"}, tc.query...)...)
					resp, out, err := r.Respond(context.Background(), o.read("req.tsq"))
					if err != nil || !out.Granted {
						t.Fatalf("Respond: granted=%t err=%v reason=%s", out.Granted, err, out.Reason)
					}
					o.write("resp.tsr", resp)
					got := o.run(append([]string{"ts", "-verify", "-in", "resp.tsr", "-CAfile", "ca.pem"}, tc.verify...)...)
					if !strings.Contains(got, "Verification: OK") {
						t.Fatalf("openssl ts -verify did not report OK:\n%s", got)
					}
					text := o.run("ts", "-reply", "-in", "resp.tsr", "-text")
					for _, want := range []string{"Status: Granted.", "Policy OID: " + testPolicy.String(), "Accuracy: 0x01 seconds, 0x01F4 millis, unspecified micros", "Ordering: no"} {
						if !strings.Contains(text, want) {
							t.Errorf("openssl ts -reply -text lacks %q:\n%s", want, text)
						}
					}
				})
			}
		})
	}
}

func TestOpenSSLReadsOurRejection(t *testing.T) {
	o := newTSOpenSSL(t)
	_, s := newTSA(t)
	r := newTestResponder(t, s, nil)
	o.write("artifact.bin", []byte("an artifact to timestamp"))
	o.run("ts", "-query", "-data", "artifact.bin", "-sha1", "-out", "req.tsq")
	resp, out, err := r.Respond(context.Background(), o.read("req.tsq"))
	if err != nil || out.Granted || out.Fail != FailBadAlg {
		t.Fatalf("Respond to a SHA-1 query: granted=%t fail=%s err=%v", out.Granted, out.Fail, err)
	}
	o.write("resp.tsr", resp)
	text := o.run("ts", "-reply", "-in", "resp.tsr", "-text")
	for _, want := range []string{"Status: Rejected.", "unrecognized or unsupported algorithm identifier"} {
		if !strings.Contains(text, want) {
			t.Errorf("openssl ts -reply -text lacks %q:\n%s", want, text)
		}
	}
}
