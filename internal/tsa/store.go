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
	"crypto/x509"
	"encoding/json"
	"fmt"
	"sort"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/CryptOS-PKI/cryptos-node/internal/storage/etcd"
)

// storedCert is one TSA certificate. The key blobs are present only while
// the certificate is the one tokens are signed with.
type storedCert struct {
	CertDER    []byte `json:"cert_der"`
	KeyPrivate []byte `json:"key_private,omitempty"`
	KeyPublic  []byte `json:"key_public,omitempty"`
}

func (s storedCert) blobs() KeyBlobs {
	return KeyBlobs{Private: s.KeyPrivate, Public: s.KeyPublic}
}

func (s storedCert) hasKey() bool {
	return len(s.KeyPrivate) > 0
}

// Store persists the TSA certificates in the node's embedded etcd, which
// lives on the encrypted state partition.
type Store struct {
	cli *clientv3.Client
}

// NewStore returns a Store backed by cli.
func NewStore(cli *clientv3.Client) *Store {
	return &Store{cli: cli}
}

func (s *Store) put(ctx context.Context, serialHex string, c storedCert) error {
	buf, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("tsa: marshal certificate %s: %w", serialHex, err)
	}
	if _, err := s.cli.Put(ctx, etcd.PrefixTSACerts+serialHex, string(buf)); err != nil {
		return fmt.Errorf("tsa: store certificate %s: %w", serialHex, err)
	}
	return nil
}

func (s *Store) get(ctx context.Context, serialHex string) (storedCert, bool, error) {
	resp, err := s.cli.Get(ctx, etcd.PrefixTSACerts+serialHex)
	if err != nil {
		return storedCert{}, false, fmt.Errorf("tsa: read certificate %s: %w", serialHex, err)
	}
	if len(resp.Kvs) == 0 {
		return storedCert{}, false, nil
	}
	var c storedCert
	if err := json.Unmarshal(resp.Kvs[0].Value, &c); err != nil {
		return storedCert{}, false, fmt.Errorf("tsa: decode certificate %s: %w", serialHex, err)
	}
	return c, true, nil
}

// retireKey deletes the key blobs of a certificate that no longer signs,
// keeping the certificate itself published.
func (s *Store) retireKey(ctx context.Context, serialHex string, c storedCert) error {
	return s.put(ctx, serialHex, storedCert{CertDER: c.CertDER})
}

// loadedCert is a stored record with its certificate parsed.
type loadedCert struct {
	cert   *x509.Certificate
	stored storedCert
}

// list returns every stored record whose certificate parses, newest first,
// and the number of records that did not.
func (s *Store) list(ctx context.Context) ([]loadedCert, int, error) {
	resp, err := s.cli.Get(ctx, etcd.PrefixTSACerts, clientv3.WithPrefix())
	if err != nil {
		return nil, 0, fmt.Errorf("tsa: list certificates: %w", err)
	}
	out := make([]loadedCert, 0, len(resp.Kvs))
	bad := 0
	for _, kv := range resp.Kvs {
		var c storedCert
		if err := json.Unmarshal(kv.Value, &c); err != nil {
			bad++
			continue
		}
		cert, err := x509.ParseCertificate(c.CertDER)
		if err != nil {
			bad++
			continue
		}
		out = append(out, loadedCert{cert: cert, stored: c})
	}
	sort.SliceStable(out, func(i, j int) bool { return newer(out[i].cert, out[j].cert) })
	return out, bad, nil
}

// newer orders certificates newest first: by notBefore, then by notAfter,
// then by serial so the order is total.
func newer(a, b *x509.Certificate) bool {
	if !a.NotBefore.Equal(b.NotBefore) {
		return a.NotBefore.After(b.NotBefore)
	}
	if !a.NotAfter.Equal(b.NotAfter) {
		return a.NotAfter.After(b.NotAfter)
	}
	return a.SerialNumber.Cmp(b.SerialNumber) > 0
}

// Published returns every TSA certificate the node has signed tokens with,
// current and past, expired or not, newest first. It reads the store
// directly, so it answers whether or not the TSA runs this boot.
func (s *Store) Published(ctx context.Context) ([]*x509.Certificate, error) {
	recs, _, err := s.list(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*x509.Certificate, len(recs))
	for i, r := range recs {
		out[i] = r.cert
	}
	return out, nil
}
