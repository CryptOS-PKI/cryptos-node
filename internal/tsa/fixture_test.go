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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos-node/internal/ca"
	"github.com/CryptOS-PKI/cryptos-node/internal/storage/etcd"
)

// testCA is a self-signed ECDSA P-384 CA standing in for the node's CA key.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	now := time.Now().UTC()
	pathLen := 0
	der, _, err := ca.Sign(ca.Profile{
		Subject:   pkix.Name{CommonName: cn, Organization: []string{"Example"}},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(20 * 365 * 24 * time.Hour),
		IsCA:      true,
		PathLen:   &pathLen,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, key.Public(), nil, key)
	if err != nil {
		t.Fatalf("self-sign the test CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse the test CA: %v", err)
	}
	return &testCA{cert: cert, key: key}
}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// certFixture is a CertManager over an embedded etcd, a test CA and a
// software key backend that counts what it is asked to do.
type certFixture struct {
	t       *testing.T
	ctx     context.Context
	ca      *testCA
	store   *Store
	clock   *testClock
	revBase string
	mgr     *CertManager
	logs    *bytes.Buffer
	logsMu  sync.Mutex

	mintErr  error
	revoked  map[string]bool
	recorded int
	creates  int
	loads    int
	closes   int
}

func newCertFixtureWith(t *testing.T, revocationBase string) *certFixture {
	t.Helper()
	srv, err := etcd.Open(t.TempDir())
	if err != nil {
		t.Fatalf("etcd.Open: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	cli, err := srv.Client()
	if err != nil {
		t.Fatalf("etcd.Client: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)

	f := &certFixture{
		t: t, ctx: ctx, ca: newTestCA(t, "Example Issuing CA G1"), store: NewStore(cli),
		clock: &testClock{now: time.Now().UTC()}, revBase: revocationBase, logs: &bytes.Buffer{},
		revoked: map[string]bool{},
	}
	f.mgr = f.newManager()
	return f
}

func (f *certFixture) logf(format string, args ...any) {
	f.logsMu.Lock()
	defer f.logsMu.Unlock()
	fmt.Fprintf(f.logs, format+"\n", args...)
}

func (f *certFixture) deps() CertDeps {
	return CertDeps{
		Store: f.store,
		CreateKey: func(context.Context) (KeyBlobs, error) {
			f.creates++
			key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			if err != nil {
				return KeyBlobs{}, err
			}
			priv, err := x509.MarshalECPrivateKey(key)
			if err != nil {
				return KeyBlobs{}, err
			}
			pub, err := x509.MarshalPKIXPublicKey(key.Public())
			if err != nil {
				return KeyBlobs{}, err
			}
			return KeyBlobs{Private: priv, Public: pub}, nil
		},
		LoadKey: func(_ context.Context, k KeyBlobs) (crypto.Signer, func(), error) {
			key, err := x509.ParseECPrivateKey(k.Private)
			if err != nil {
				return nil, nil, err
			}
			f.loads++
			return key, func() { f.closes++ }, nil
		},
		Mint: func(_ context.Context, pub crypto.PublicKey, notBefore, notAfter time.Time) ([]byte, error) {
			if f.mintErr != nil {
				return nil, f.mintErr
			}
			der, _, err := ca.Sign(CertificateProfile(f.ca.cert, notBefore, notAfter, f.revBase), pub, f.ca.cert, f.ca.key)
			return der, err
		},
		Issuer: func(context.Context) (*x509.Certificate, error) { return f.ca.cert, nil },
		Revoked: func(_ context.Context, serialHex string) (bool, error) {
			return f.revoked[serialHex], nil
		},
		Record: func(context.Context, []byte) error {
			f.recorded++
			return nil
		},
	}
}

func (f *certFixture) newManager() *CertManager {
	f.t.Helper()
	m, err := NewCertManager(f.deps(), CertOptions{Validity: testValidity, Overlap: testOverlap, Now: f.clock.Now, Logf: f.logf})
	if err != nil {
		f.t.Fatalf("NewCertManager: %v", err)
	}
	return m
}

func (f *certFixture) ensure() {
	f.t.Helper()
	if err := f.mgr.Ensure(f.ctx); err != nil {
		f.t.Fatalf("Ensure: %v\n%s", err, f.logs.String())
	}
}

func (f *certFixture) published() []*x509.Certificate {
	f.t.Helper()
	certs, err := f.store.Published(f.ctx)
	if err != nil {
		f.t.Fatalf("Published: %v", err)
	}
	return certs
}

func (f *certFixture) keyStored(cert *x509.Certificate) bool {
	f.t.Helper()
	rec, ok, err := f.store.get(f.ctx, cert.SerialNumber.Text(16))
	if err != nil || !ok {
		f.t.Fatalf("read the stored record for %s: ok=%v err=%v", cert.SerialNumber.Text(16), ok, err)
	}
	return len(rec.KeyPrivate) > 0 || len(rec.KeyPublic) > 0
}
