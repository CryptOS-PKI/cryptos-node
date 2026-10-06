package init

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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"google.golang.org/protobuf/types/known/timestamppb"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"github.com/CryptOS-PKI/cryptos-node/internal/ca"
	"github.com/CryptOS-PKI/cryptos-node/internal/ceremony"
	"github.com/CryptOS-PKI/cryptos-node/internal/config"
	"github.com/CryptOS-PKI/cryptos-node/internal/node"
	"github.com/CryptOS-PKI/cryptos-node/internal/revocation"
	"github.com/CryptOS-PKI/cryptos-node/internal/tsa"
)

// defaultTSAHTTPPort is the TSA listener's port when pki.tsa.http_port is
// zero: 318, the port IANA assigns to the Time Stamp Protocol.
const defaultTSAHTTPPort = 318

// tsaCertEnsureInterval is how often a running node re-checks its TSA
// certificate, so the successor takes over when the overlap starts without a
// reboot.
const tsaCertEnsureInterval = time.Hour

// tsaIssuedProfile is the profile name TSA certificates are recorded under in
// the issued set.
const tsaIssuedProfile = "tsa"

// tsaService is the TSA for this boot: its certificates and its HTTP
// handler.
type tsaService struct {
	certs   *tsa.CertManager
	handler http.Handler
	addr    string
}

// tsaKeyFuncs creates and loads TSA keys through the CA key backend, so the
// TSA key lives where the CA key does: in the TPM on a TPM node, in software
// otherwise. The key has the CA key's configured algorithm.
func tsaKeyFuncs(backend ceremony.RootKeyBackend, alg config.RootKeyAlg) (
	func(context.Context) (tsa.KeyBlobs, error),
	func(context.Context, tsa.KeyBlobs) (crypto.Signer, func(), error),
) {
	create := func(context.Context) (tsa.KeyBlobs, error) {
		keyAlg, err := alg.KeyAlgorithm()
		if err != nil {
			return tsa.KeyBlobs{}, fmt.Errorf("init: TSA key algorithm: %w", err)
		}
		created, err := backend.CreateKey(keyAlg)
		if err != nil {
			return tsa.KeyBlobs{}, err
		}
		return tsa.KeyBlobs{Private: created.Private, Public: created.Public}, nil
	}
	load := func(_ context.Context, k tsa.KeyBlobs) (crypto.Signer, func(), error) {
		signer, err := backend.LoadKey(k.Private, k.Public)
		if err != nil {
			return nil, nil, err
		}
		return signer, func() { _ = signer.Close() }, nil
	}
	return create, load
}

// tsaMint returns the TSA-certificate signing closure. The CA key is loaded
// for the signature and released straight after, as for the SCEP RA.
func tsaMint(load node.KeyLoader, issuer node.IssuerFunc, revocationBaseURL string) tsa.MintFunc {
	return func(ctx context.Context, pub crypto.PublicKey, notBefore, notAfter time.Time) ([]byte, error) {
		signer, closeFn, err := load(ctx)
		if err != nil {
			return nil, fmt.Errorf("init: load the CA key for the TSA certificate: %w", err)
		}
		if closeFn != nil {
			defer closeFn()
		}
		issuerCert, err := issuer(ctx)
		if err != nil {
			return nil, fmt.Errorf("init: load the issuer for the TSA certificate: %w", err)
		}
		if issuerCert == nil {
			return nil, errors.New("init: no issuer certificate for the TSA certificate")
		}
		der, _, err := ca.Sign(tsa.CertificateProfile(issuerCert, notBefore, notAfter, revocationBaseURL), pub, issuerCert, signer)
		return der, err
	}
}

// tsaDeps are what newTSAService builds the TSA from.
type tsaDeps struct {
	cli        *clientv3.Client
	backend    ceremony.RootKeyBackend
	load       node.KeyLoader
	issuer     node.IssuerFunc
	revStore   *revocation.Store
	timeStatus func() *nodev1.TimeSyncStatus
}

// newTSAService builds the TSA for this boot, or returns nil when pki.tsa is
// off or the TSA cannot be set up; the reason is logged and the rest of the
// node serves on. The TSA certificate is ensured here, before the listener
// starts, so the first request has a certificate to be signed with.
func newTSAService(ctx context.Context, cfg *config.Config, d tsaDeps) *tsaService {
	t := cfg.PKI.TSA
	if t == nil {
		return nil
	}
	policy, err := t.Policy()
	if err != nil {
		log.Printf("TSA: off this boot: pki.tsa.policy_oid: %v", err)
		return nil
	}
	networks, err := t.Networks()
	if err != nil {
		log.Printf("TSA: off this boot: %v", err)
		return nil
	}
	create, loadKey := tsaKeyFuncs(d.backend, cfg.PKI.RootKeyAlg)
	record := IssuedRecorder(d.revStore)
	certs, err := tsa.NewCertManager(tsa.CertDeps{
		Store:     tsa.NewStore(d.cli),
		CreateKey: create,
		LoadKey:   loadKey,
		Mint:      tsaMint(d.load, d.issuer, cfg.PKI.RevocationBaseURL),
		Issuer:    d.issuer,
		Revoked: func(ctx context.Context, serialHex string) (bool, error) {
			_, revoked, err := d.revStore.GetRevoked(ctx, serialHex)
			return revoked, err
		},
		Record: func(ctx context.Context, der []byte) error { return record(ctx, der, tsaIssuedProfile) },
	}, tsa.CertOptions{Validity: t.Certificate.Validity(), Overlap: t.Certificate.Overlap(), Logf: log.Printf})
	if err != nil {
		log.Printf("TSA: off this boot: %v", err)
		return nil
	}
	if err := certs.Ensure(ctx); err != nil {
		log.Printf("TSA: off this boot: the TSA certificate could not be set up: %v", err)
		return nil
	}
	responder, err := tsa.NewResponder(certs, tsa.ResponderOptions{
		Policy:        policy,
		Accuracy:      t.Accuracy(),
		TimeAvailable: tsa.ClockGate(d.timeStatus, t.Accuracy()),
		Logf:          log.Printf,
	})
	if err != nil {
		log.Printf("TSA: off this boot: %v", err)
		return nil
	}
	handler, err := tsa.NewHandler(responder, tsa.HandlerOptions{
		AllowedNetworks:   networks,
		RequestsPerMinute: t.RequestsPerMinute(),
		Burst:             t.Burst(),
		Logf:              log.Printf,
	})
	if err != nil {
		log.Printf("TSA: off this boot: %v", err)
		return nil
	}
	log.Printf("TSA: ready: policy=%s accuracy=%s rate=%d/min burst=%d allowed_networks=%v certificate validity=%s overlap=%s",
		policy, t.Accuracy(), t.RequestsPerMinute(), t.Burst(), t.AllowedNetworks, t.Certificate.Validity(), t.Certificate.Overlap())
	return &tsaService{certs: certs, handler: handler, addr: fmt.Sprintf(":%d", nonzero(t.HTTPPort, defaultTSAHTTPPort))}
}

// superviseTSACerts re-checks the TSA certificate on a timer, so the
// successor takes over when the rotation overlap begins, without a reboot.
func superviseTSACerts(ctx context.Context, certs *tsa.CertManager) {
	t := time.NewTicker(tsaCertEnsureInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := certs.Ensure(ctx); err != nil {
				log.Printf("TSA: certificate check failed: %v", err)
			}
		}
	}
}

// tsaCatalog backs ListTsaCertificates. It reads the store, so it answers
// whether or not the TSA runs this boot; current reports the certificate
// tokens are signed with, and nothing while the TSA is not running.
type tsaCatalog struct {
	store   *tsa.Store
	current func() (*x509.Certificate, bool)
}

func (c tsaCatalog) ListTsaCertificates(ctx context.Context) ([]*nodev1.TsaCertificate, error) {
	certs, err := c.store.Published(ctx)
	if err != nil {
		return nil, err
	}
	var cur *x509.Certificate
	if c.current != nil {
		cur, _ = c.current()
	}
	out := make([]*nodev1.TsaCertificate, 0, len(certs))
	for _, cert := range certs {
		sum := sha256.Sum256(cert.Raw)
		out = append(out, &nodev1.TsaCertificate{
			CertPem:   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
			SerialHex: cert.SerialNumber.Text(16),
			Sha256Hex: hex.EncodeToString(sum[:]),
			NotBefore: timestamppb.New(cert.NotBefore),
			NotAfter:  timestamppb.New(cert.NotAfter),
			Current:   cur != nil && cur.Equal(cert),
		})
	}
	return out, nil
}
