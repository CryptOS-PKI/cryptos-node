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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos-node/internal/ukisign"
)

func runSign(t *testing.T, args ...string) error {
	t.Helper()

	root := newRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs(append([]string{"image", "sign"}, args...))

	return root.Execute()
}

// writeSigningPair writes a throwaway RSA key and self-signed certificate as
// PEM files and returns their paths.
func writeSigningPair(t *testing.T, dir string) (string, string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		NotAfter:     time.Now().Add(time.Hour),
		NotBefore:    time.Now().Add(-time.Hour),
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Example Release Signing"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyPath, certPath := filepath.Join(dir, "release.key"), filepath.Join(dir, "release.crt")
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}

	return keyPath, certPath
}

func TestImageSign_RequiresImageKeyAndCert(t *testing.T) {
	dir := t.TempDir()
	keyPath, certPath := writeSigningPair(t, dir)
	image := filepath.Join(dir, "cryptos-amd64.uki.unsigned")

	for name, args := range map[string][]string{
		"no image": {"--key", keyPath, "--cert", certPath},
		"no key":   {"--image", image, "--cert", certPath},
		"no cert":  {"--image", image, "--key", keyPath},
		"out=in":   {"--image", image, "--key", keyPath, "--cert", certPath, "--out", image},
	} {
		t.Run(name, func(t *testing.T) {
			if err := runSign(t, args...); err == nil {
				t.Error("image sign ran without what it needs")
			}
		})
	}
}

// Something that is not a UKI is refused, and nothing is written for it.
func TestImageSign_RefusesANonUKIAndWritesNothing(t *testing.T) {
	dir := t.TempDir()
	keyPath, certPath := writeSigningPair(t, dir)
	image := filepath.Join(dir, "cryptos-amd64.uki.unsigned")
	if err := os.WriteFile(image, []byte("not a PE image"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := runSign(t, "--image", image, "--key", keyPath, "--cert", certPath)
	if !errors.Is(err, ukisign.ErrNotUKI) {
		t.Fatalf("err = %v, want ErrNotUKI", err)
	}
	for _, p := range []string{filepath.Join(dir, "cryptos-amd64.uki"), filepath.Join(dir, "cryptos-amd64.uki.sig")} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s was written for a refused image", p)
		}
	}
}
