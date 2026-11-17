package e2e

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

// This file proves an RSA CA key held in a TPM end to end: the real first-boot
// ceremony creates an RSA-3072 root key inside the TPM, the node "reboots"
// (the TPM process restarts on its persisted state), and the key reloaded
// through the production backend signs a leaf, a subordinate CA, a CSR, a CRL
// and a delegated OCSP responder.
//
// The in-process simulator the unit tests use implements RSA-2048 only, so
// this runs against swtpm (libtpms), which implements RSA-3072. It skips when
// swtpm is not installed, except in CI, where a missing swtpm is a failure so
// the RSA TPM path can never silently stop being tested.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"golang.org/x/crypto/ocsp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"github.com/CryptOS-PKI/cryptos-node/internal/bootstrap"
	"github.com/CryptOS-PKI/cryptos-node/internal/ca"
	"github.com/CryptOS-PKI/cryptos-node/internal/ceremony"
	"github.com/CryptOS-PKI/cryptos-node/internal/config"
	cinit "github.com/CryptOS-PKI/cryptos-node/internal/init"
	"github.com/CryptOS-PKI/cryptos-node/internal/node"
	"github.com/CryptOS-PKI/cryptos-node/internal/revocation"
	"github.com/CryptOS-PKI/cryptos-node/internal/storage/etcd"
	"github.com/CryptOS-PKI/cryptos-node/internal/testadmin"
	"github.com/CryptOS-PKI/cryptos-node/internal/tpm"
)

// swtpmSocket is a transport.TPMCloser over swtpm's raw command socket: one
// command out, one length-prefixed response back.
//
// On a node, /dev/tpmrm0 goes through the Linux TPM driver, which resends a
// command the TPM answered with TPM_RC_RETRY or TPM_RC_TESTING. A raw socket has
// no driver, so Send does the same. Some libtpms versions answer an RSA
// signature with TPM_RC_RETRY.
type swtpmSocket struct{ conn net.Conn }

// Response codes the Linux TPM driver retries (TPM 2.0 Part 2, 6.6.3).
const (
	rcRetry   = 0x922
	rcTesting = 0x90A
)

func (s *swtpmSocket) Send(cmd []byte) ([]byte, error) {
	deadline := time.Now().Add(10 * time.Second)
	for {
		rsp, err := s.roundTrip(cmd)
		if err != nil {
			return nil, err
		}
		switch binary.BigEndian.Uint32(rsp[6:10]) {
		case rcRetry, rcTesting:
			if time.Now().Before(deadline) {
				time.Sleep(20 * time.Millisecond)
				continue
			}
		}
		return rsp, nil
	}
}

func (s *swtpmSocket) roundTrip(cmd []byte) ([]byte, error) {
	if _, err := s.conn.Write(cmd); err != nil {
		return nil, err
	}
	header := make([]byte, 10)
	if _, err := io.ReadFull(s.conn, header); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[2:6])
	if size < 10 {
		return nil, fmt.Errorf("swtpm: response size %d is shorter than its header", size)
	}
	rsp := make([]byte, size)
	copy(rsp, header)
	if _, err := io.ReadFull(s.conn, rsp[10:]); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (s *swtpmSocket) Close() error { return s.conn.Close() }

// swtpmNode is one run of an swtpm process over a state directory that
// survives restarts, standing in for a node's TPM across reboots.
type swtpmNode struct {
	t        *testing.T
	stateDir string
	cmd      *exec.Cmd
	tpm      *tpm.TPM
}

// newSWTPMNode returns a node with swtpm started, or skips when swtpm is not
// installed outside CI.
func newSWTPMNode(t *testing.T) *swtpmNode {
	t.Helper()
	if _, err := exec.LookPath("swtpm"); err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("swtpm is not installed; CI must install it so the TPM-held RSA CA path is tested")
		}
		t.Skip("swtpm not installed; the TPM-held RSA-3072 CA path needs a TPM that implements RSA-3072")
	}
	// A short path: a unix socket path is capped near 104 bytes on macOS, and
	// t.TempDir embeds the test name.
	dir, err := os.MkdirTemp("", "swtpm-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	n := &swtpmNode{t: t, stateDir: dir}
	n.start()
	t.Cleanup(n.stop)
	return n
}

func (n *swtpmNode) start() {
	n.t.Helper()
	sock := filepath.Join(n.stateDir, "cmd.sock")
	_ = os.Remove(sock)
	cmd := exec.Command("swtpm", "socket", "--tpm2",
		"--tpmstate", "dir="+n.stateDir,
		"--server", "type=unixio,path="+sock,
		"--ctrl", "type=unixio,path="+filepath.Join(n.stateDir, "ctrl.sock"),
		"--flags", "not-need-init,startup-clear")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		n.t.Fatalf("start swtpm: %v", err)
	}
	n.cmd = cmd

	var conn net.Conn
	deadline := time.Now().Add(10 * time.Second)
	for {
		var err error
		if conn, err = net.Dial("unix", sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			n.stop()
			n.t.Fatalf("swtpm socket never came up: %v (stderr: %s)", err, stderr.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	n.tpm = tpm.OpenTransport(&swtpmSocket{conn: conn})
}

func (n *swtpmNode) stop() {
	if n.tpm != nil {
		_ = n.tpm.Close()
		n.tpm = nil
	}
	if n.cmd != nil {
		// swtpm writes its NV state (the persisted SRK) as it changes, so a
		// kill after a grace period loses nothing a reboot needs. Some builds
		// do not exit on SIGTERM once their client has gone.
		_ = n.cmd.Process.Signal(syscall.SIGTERM)
		exited := make(chan struct{})
		go func() { _ = n.cmd.Wait(); close(exited) }()
		select {
		case <-exited:
		case <-time.After(3 * time.Second):
			_ = n.cmd.Process.Kill()
			<-exited
		}
		n.cmd = nil
	}
}

// reboot restarts swtpm on the same state, as a node reboot restarts its TPM.
func (n *swtpmNode) reboot() {
	n.t.Helper()
	n.stop()
	n.start()
}

func newRSATPMStore(t *testing.T) *node.Store {
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
	s, err := node.New(cli)
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	return s
}

// rsaTPMRootYAML is the operator's root MachineConfig with an RSA-3072 CA key.
// The node's state-key mode is not part of it: which backend holds the key is
// the ceremony's RootKey, here the tpm-mode backend.
func rsaTPMRootYAML() []byte {
	return []byte(fmt.Sprintf(`apiVersion: cryptos.dev/v1alpha1
kind: MachineConfig
metadata:
  name: rsa-tpm-root
role:
  kind: root
network:
  interface: eth0
  address: 10.0.0.10/24
  gateway: 10.0.0.1
bootstrap:
  admin_cert_pem: "` + testadmin.YAMLPEM + `"
pki:
  root_key_alg: RSA-3072
  root_subject:
    common_name: "ACME RSA Root CA"
    organization: "ACME"
    country: "US"
  root_validity_years: 20
  path_len_constraint: 1
`))
}

// loadCAKey reloads the CA key the way production's keyLoader does: the
// persisted blobs, through the tpm-mode RootKeyBackend.
func loadCAKey(t *testing.T, ctx context.Context, store *node.Store, tp *tpm.TPM) crypto.Signer {
	t.Helper()
	priv, pub, ok, err := store.RootKeyBlobs(ctx)
	if err != nil || !ok {
		t.Fatalf("RootKeyBlobs ok=%v err=%v", ok, err)
	}
	signer, err := cinit.NewTPMRootBackend(tp).LoadKey(priv, pub)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	t.Cleanup(func() { _ = signer.Close() })
	return signer
}

func TestTPMHeldRSACAEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)
	now := time.Now().UTC().Truncate(time.Second)

	tpmNode := newSWTPMNode(t)
	caps, err := tpmNode.tpm.Probe()
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !caps.SupportsRSAKeyBits(3072) {
		t.Fatalf("this swtpm does not implement RSA-3072 (RSA sizes %v); libtpms 0.8 or later is needed", caps.RSAKeyBits)
	}

	// Step 1: the real first-boot ceremony, tpm mode, RSA-3072.
	store := newRSATPMStore(t)
	adminFP := sha256.Sum256([]byte("TPM-held RSA CA bootstrap admin"))
	trust, err := bootstrap.LoadTrust("", hex.EncodeToString(adminFP[:]))
	if err != nil {
		t.Fatalf("LoadTrust: %v", err)
	}
	seed := make([]byte, ceremony.SeedLength)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("seed: %v", err)
	}
	eng, err := ceremony.New(ceremony.Config{
		RootKey:     cinit.NewTPMRootBackend(tpmNode.tpm),
		Store:       store,
		ConfigStore: config.NewFileStore(t.TempDir()),
		Trust:       trust,
		Seed:        seed,
	})
	if err != nil {
		t.Fatalf("ceremony.New: %v", err)
	}
	rsaYAML := rsaTPMRootYAML()
	if err := eng.Start(ctx, &nodev1.StartCeremonyRequest{
		Kind:              nodev1.CeremonyKind_CEREMONY_KIND_FIRST_BOOT_ROOT,
		MachineConfigYaml: rsaYAML,
	}, func(*nodev1.StartCeremonyResponse) error { return nil }); err != nil {
		t.Fatalf("ceremony Start (RSA-3072, tpm mode): %v", err)
	}

	id, err := store.Identity(ctx)
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	rootCert, err := x509.ParseCertificate(id.ChainDer[0])
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}
	rootPub, ok := rootCert.PublicKey.(*rsa.PublicKey)
	if !ok || rootPub.N.BitLen() != 3072 {
		t.Fatalf("root public key = %T (%v), want a 3072-bit RSA key", rootCert.PublicKey, rootCert.PublicKeyAlgorithm)
	}
	if rootCert.SignatureAlgorithm != x509.SHA384WithRSA {
		t.Errorf("root SignatureAlgorithm = %v, want SHA384-RSA", rootCert.SignatureAlgorithm)
	}
	if err := rootCert.CheckSignatureFrom(rootCert); err != nil {
		t.Fatalf("root does not self-verify: %v", err)
	}

	// The persisted key is a TPM object with the ECDSA key's properties, not a
	// software key: generated in, and never movable off, this TPM.
	_, pubBlob, _, err := store.RootKeyBlobs(ctx)
	if err != nil {
		t.Fatalf("RootKeyBlobs: %v", err)
	}
	tpmPub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](pubBlob)
	if err != nil {
		t.Fatalf("stored public blob is not a TPM2B_PUBLIC: %v", err)
	}
	area, err := tpmPub.Contents()
	if err != nil {
		t.Fatalf("public contents: %v", err)
	}
	if area.Type != tpm2.TPMAlgRSA || !area.ObjectAttributes.FixedTPM || !area.ObjectAttributes.FixedParent || !area.ObjectAttributes.SensitiveDataOrigin {
		t.Fatalf("stored key type 0x%x attributes %+v: want an RSA key with fixedTPM, fixedParent and sensitiveDataOrigin", area.Type, area.ObjectAttributes)
	}

	// Step 2: reboot, then reload through the production backend.
	tpmNode.reboot()
	caKey := loadCAKey(t, ctx, store, tpmNode.tpm)
	if !rootPub.Equal(caKey.Public()) {
		t.Fatal("the reloaded TPM key is not the key the root certificate names")
	}

	t.Run("leaf", func(t *testing.T) {
		leafDER, _, err := ca.Sign(ca.Profile{
			Subject:     pkix.Name{CommonName: "host.acme.example"},
			NotBefore:   now,
			NotAfter:    now.AddDate(0, 0, 90),
			KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:    []string{"host.acme.example"},
		}, rsaSubjectKey(t).Public(), rootCert, caKey)
		if err != nil {
			t.Fatalf("Sign leaf: %v", err)
		}
		leaf, err := x509.ParseCertificate(leafDER)
		if err != nil {
			t.Fatalf("parse leaf: %v", err)
		}
		if !rsaSHA2SigAlgs[leaf.SignatureAlgorithm] {
			t.Errorf("leaf SignatureAlgorithm = %v, want SHA-2 RSA", leaf.SignatureAlgorithm)
		}
		pool := x509.NewCertPool()
		pool.AddCert(rootCert)
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now.Add(time.Hour), DNSName: "host.acme.example"}); err != nil {
			t.Fatalf("leaf does not chain to the TPM-held root: %v", err)
		}
	})

	t.Run("subordinate", func(t *testing.T) {
		pathLen := 0
		subDER, _, err := ca.Sign(ca.Profile{
			Subject:   pkix.Name{CommonName: "ACME RSA Issuing CA", Organization: []string{"ACME"}},
			NotBefore: now,
			NotAfter:  now.AddDate(5, 0, 0),
			IsCA:      true,
			PathLen:   &pathLen,
			KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}, rsaSubjectKey(t).Public(), rootCert, caKey)
		if err != nil {
			t.Fatalf("Sign subordinate: %v", err)
		}
		sub, err := x509.ParseCertificate(subDER)
		if err != nil {
			t.Fatalf("parse subordinate: %v", err)
		}
		if !sub.IsCA || !rsaSHA2SigAlgs[sub.SignatureAlgorithm] {
			t.Errorf("subordinate IsCA=%v SignatureAlgorithm=%v, want a CA with a SHA-2 RSA signature", sub.IsCA, sub.SignatureAlgorithm)
		}
		if err := sub.CheckSignatureFrom(rootCert); err != nil {
			t.Fatalf("subordinate CheckSignatureFrom root: %v", err)
		}
	})

	t.Run("csr", func(t *testing.T) {
		// A subordinate node's TPM key signs its own PKCS#10 request.
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "ACME RSA Intermediate CA"},
		}, caKey)
		if err != nil {
			t.Fatalf("CreateCertificateRequest: %v", err)
		}
		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			t.Fatalf("ParseCertificateRequest: %v", err)
		}
		if err := csr.CheckSignature(); err != nil {
			t.Fatalf("CSR signature: %v", err)
		}
	})

	revStore, _ := newRevocationStore(t)
	leafDER, _, err := ca.Sign(ca.Profile{
		Subject:     pkix.Name{CommonName: "revoked.acme.example"},
		NotBefore:   now,
		NotAfter:    now.AddDate(0, 0, 90),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, rsaSubjectKey(t).Public(), rootCert, caKey)
	if err != nil {
		t.Fatalf("Sign leaf to revoke: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf to revoke: %v", err)
	}
	serialHex := leafCert.SerialNumber.Text(16)
	if err := revStore.RecordIssued(ctx, revocation.IssuedRecord{SerialHex: serialHex, NotAfter: leafCert.NotAfter}); err != nil {
		t.Fatalf("RecordIssued: %v", err)
	}
	if _, err := revStore.Revoke(ctx, serialHex, ocsp.KeyCompromise, now); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	t.Run("crl", func(t *testing.T) {
		crlDER, err := revocation.NewCRLBuilder(revStore, 168*time.Hour).Build(ctx, rootCert, caKey, now.Add(time.Minute))
		if err != nil {
			t.Fatalf("Build CRL: %v", err)
		}
		crl, err := x509.ParseRevocationList(crlDER)
		if err != nil {
			t.Fatalf("ParseRevocationList: %v", err)
		}
		if !rsaSHA2SigAlgs[crl.SignatureAlgorithm] {
			t.Errorf("CRL SignatureAlgorithm = %v, want SHA-2 RSA", crl.SignatureAlgorithm)
		}
		if err := crl.CheckSignatureFrom(rootCert); err != nil {
			t.Fatalf("CRL CheckSignatureFrom: %v", err)
		}
		if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Text(16) != serialHex {
			t.Fatalf("CRL entries = %v, want the one revoked serial %s", crl.RevokedCertificateEntries, serialHex)
		}
	})

	t.Run("ocsp", func(t *testing.T) {
		responderKey := rsaSubjectKey(t)
		responderDER, _, err := ca.Sign(ca.Profile{
			Subject:     pkix.Name{CommonName: "ACME RSA Root CA OCSP Responder"},
			NotBefore:   now,
			NotAfter:    now.AddDate(0, 0, 7),
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
			ExtraExtensions: []pkix.Extension{{
				Id:    oidOCSPNoCheckE2E,
				Value: []byte{0x05, 0x00},
			}},
		}, responderKey.Public(), rootCert, caKey)
		if err != nil {
			t.Fatalf("Sign responder: %v", err)
		}
		responderCert, err := x509.ParseCertificate(responderDER)
		if err != nil {
			t.Fatalf("parse responder: %v", err)
		}
		reqDER, err := ocsp.CreateRequest(leafCert, rootCert, nil)
		if err != nil {
			t.Fatalf("CreateRequest: %v", err)
		}
		respDER, err := revocation.NewOCSPResponder(revStore).Respond(ctx, reqDER, rootCert, responderCert, responderKey, now.Add(time.Minute))
		if err != nil {
			t.Fatalf("Respond: %v", err)
		}
		// ParseResponse checks the responder certificate was issued by the
		// TPM-held root, as well as the response signature.
		resp, err := ocsp.ParseResponse(respDER, rootCert)
		if err != nil {
			t.Fatalf("ParseResponse: %v", err)
		}
		if resp.Status != ocsp.Revoked {
			t.Errorf("Status = %d, want Revoked (%d)", resp.Status, ocsp.Revoked)
		}
	})

	// A second ceremony on the same node is refused: the TPM key is the node's
	// identity from here on.
	err = eng.Start(ctx, &nodev1.StartCeremonyRequest{
		Kind:              nodev1.CeremonyKind_CEREMONY_KIND_FIRST_BOOT_ROOT,
		MachineConfigYaml: rsaYAML,
	}, func(*nodev1.StartCeremonyResponse) error { return nil })
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("second ceremony = %v, want FailedPrecondition IDENTITY_EXISTS", err)
	}
}
