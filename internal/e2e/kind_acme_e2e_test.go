package e2e_test

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

// This file proves that a real Kubernetes client gets a real certificate from
// CryptOS over ACME. The node side is the same in-process hierarchy as
// hierarchy_e2e_test.go (software key backend, embedded etcd, no TPM): a Root
// signs an Intermediate, and the Intermediate serves ACME from a pki.acme
// block parsed by config.Parse and built by cinit.NewACMEHandler, which is
// what the boot serves. The client side is cert-manager in a kind cluster,
// enrolling through an http-01 solver behind the cluster's ingress.
//
// The cluster is stood up by test/kind/run.sh (task e2e:kind), which sets the
// CRYPTOS_E2E_KIND_* variables below. Without them the test skips.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/CryptOS-PKI/cryptos-node/internal/acme"
	"github.com/CryptOS-PKI/cryptos-node/internal/config"
	cinit "github.com/CryptOS-PKI/cryptos-node/internal/init"
	"github.com/CryptOS-PKI/cryptos-node/internal/node"
	"github.com/CryptOS-PKI/cryptos-node/internal/revocation"
	"github.com/CryptOS-PKI/cryptos-node/internal/storage/etcd"
	"github.com/CryptOS-PKI/cryptos-node/internal/testadmin"
)

const (
	kindNamespace   = "cryptos-e2e"
	kindIssuer      = "cryptos-acme"
	kindCertificate = "whoami"
	kindSecret      = "whoami-tls"
	kindEABSecret   = "cryptos-acme-eab"
	kindEABKeyID    = "kind-e2e"
	kindLeafProfile = "acme-leaf"

	// acmeOriginAddr is the plain-HTTP origin the ACME handler is served on,
	// loopback only; acmeFrontPort is the TLS front the cluster dials.
	acmeOriginAddr = "127.0.0.1:8555"
	acmeFrontPort  = "8443"

	certReadyTimeout = 5 * time.Minute
)

// kindEnv is what test/kind/run.sh hands the test about the cluster it built.
type kindEnv struct {
	// hostIP is the host's address on the kind docker network: where pods
	// reach the ACME front, and the IP SAN on the front's certificate.
	hostIP string
	// hostname is the name the Certificate requests. It resolves to the
	// cluster's ingress both on the host (so the node's http-01 fetch lands
	// there) and inside the cluster (so cert-manager's self-check does).
	hostname   string
	kubeconfig string
	kubectl    string
}

func kindEnvOrSkip(t *testing.T) kindEnv {
	t.Helper()
	if os.Getenv("CRYPTOS_E2E_KIND") != "1" {
		t.Skip("kind ACME e2e: not requested; run `task e2e:kind` on a Linux host with docker")
	}
	env := kindEnv{
		hostIP:     os.Getenv("CRYPTOS_E2E_KIND_HOST_IP"),
		hostname:   os.Getenv("CRYPTOS_E2E_KIND_HOSTNAME"),
		kubeconfig: os.Getenv("CRYPTOS_E2E_KIND_KUBECONFIG"),
		kubectl:    os.Getenv("CRYPTOS_E2E_KIND_KUBECTL"),
	}
	if env.kubectl == "" {
		env.kubectl = "kubectl"
	}
	if net.ParseIP(env.hostIP) == nil || env.hostname == "" || env.kubeconfig == "" {
		t.Fatalf("kind ACME e2e: CRYPTOS_E2E_KIND_HOST_IP, _HOSTNAME and _KUBECONFIG must be set (got %q, %q, %q)",
			env.hostIP, env.hostname, env.kubeconfig)
	}
	return env
}

// TestKindCertManagerACME drives cert-manager against an ACME-serving
// Intermediate: the Certificate goes Ready with a chain to the CryptOS root,
// the node records the issuance, the ingress serves it, and a forced renewal
// yields a new serial that is recorded too.
func TestKindCertManagerACME(t *testing.T) {
	env := kindEnvOrSkip(t)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	t.Cleanup(cancel)

	n := startACMENode(t, ctx, env)
	rootCert, rootPEM, revStore := n.root, n.rootPEM, n.revStore

	kc := kubectlRunner{t: t, env: env}
	applyIssuerAndCertificate(t, ctx, kc, rootPEM, n.baseURL, n.eabKeyB64, env.hostname)

	first := waitForIssuedCertificate(t, ctx, kc, "", certReadyTimeout)
	assertCertificate(t, ctx, first, rootCert, env.hostname, revStore)
	assertServedByIngress(t, ctx, env.hostname, rootCert, first.leaf.SerialNumber.Text(16))

	// Force a renewal the way `cmctl renew` does: set Issuing=True on the
	// Certificate's status, which cert-manager's trigger controller acts on.
	firstSerial := first.leaf.SerialNumber.Text(16)
	t.Logf("forcing renewal of %s/%s (current serial %s)", kindNamespace, kindCertificate, firstSerial)
	patch := fmt.Sprintf(`[{"op":"add","path":"/status/conditions/-","value":{"type":"Issuing","status":"True","reason":"ManuallyTriggered","message":"Certificate re-issuance manually triggered by the CryptOS kind e2e test","lastTransitionTime":%q}}]`,
		time.Now().UTC().Format(time.RFC3339))
	if _, err := kc.run(ctx, "", "-n", kindNamespace, "patch", "certificate", kindCertificate,
		"--subresource=status", "--type=json", "-p", patch); err != nil {
		t.Fatalf("trigger renewal: %v", err)
	}

	second := waitForIssuedCertificate(t, ctx, kc, firstSerial, certReadyTimeout)
	secondSerial := second.leaf.SerialNumber.Text(16)
	if secondSerial == firstSerial {
		t.Fatalf("renewal kept serial %s, want a new one", firstSerial)
	}
	t.Logf("renewed: serial %s -> %s", firstSerial, secondSerial)
	assertCertificate(t, ctx, second, rootCert, env.hostname, revStore)
	assertServedByIngress(t, ctx, env.hostname, rootCert, secondSerial)
}

// acmeNode is the ACME-serving Intermediate the cluster enrols against.
type acmeNode struct {
	root      *x509.Certificate
	rootPEM   []byte
	revStore  *revocation.Store
	baseURL   string
	eabKeyB64 string
}

// startACMENode builds a Root, an Intermediate it signs, and serves ACME from
// the Intermediate behind a TLS front on env.hostIP.
func startACMENode(t *testing.T, ctx context.Context, env kindEnv) acmeNode {
	t.Helper()
	// Root, then an Intermediate it signs, exactly as TestHierarchyE2E does.
	rootStore := newStore(t)
	establishRoot(t, ctx, rootStore)
	rootID, err := rootStore.Identity(ctx)
	if err != nil {
		t.Fatalf("root Identity: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootID.ChainDer[0])
	if err != nil {
		t.Fatalf("parse root cert: %v", err)
	}
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})
	t.Logf("root established: subject=%q serial=%s", rootCert.Subject, rootCert.SerialNumber.Text(16))

	subStore, cli := newStoreWithClient(t)
	subKey := newP384Key(t)
	subCSR := buildCSR(t, subKey, pkix.Name{CommonName: "ACME Issuing G1"})
	if err := subStore.StageSubordinate(ctx, subCSR, marshalECKey(t, subKey), marshalECPub(t, subKey)); err != nil {
		t.Fatalf("StageSubordinate: %v", err)
	}
	chainDER, _, _, err := newRootCASigner(t, ctx, rootStore, rootCert, rootProfilesConfig()).SignSubordinate(ctx, subCSR, "sub-ca")
	if err != nil {
		t.Fatalf("root SignSubordinate: %v", err)
	}

	eabKey := make([]byte, config.MinEABKeyBytes)
	if _, err := rand.Read(eabKey); err != nil {
		t.Fatalf("EAB key: %v", err)
	}
	eabKeyB64 := base64.RawURLEncoding.EncodeToString(eabKey)
	baseURL := "https://" + net.JoinHostPort(env.hostIP, acmeFrontPort) + "/acme"
	subCfg := intermediateACMEConfig(t, string(rootPEM), env, baseURL, eabKeyB64)

	parentTrust, err := subCfg.ParentTrust()
	if err != nil {
		t.Fatalf("ParentTrust: %v", err)
	}
	enroller, err := node.NewSubordinateEnroller(subStore, parentTrust)
	if err != nil {
		t.Fatalf("NewSubordinateEnroller: %v", err)
	}
	if _, err := enroller.AcceptCertificate(ctx, chainDER); err != nil {
		t.Fatalf("AcceptCertificate: %v", err)
	}
	subCert, err := x509.ParseCertificate(chainDER[0])
	if err != nil {
		t.Fatalf("parse intermediate: %v", err)
	}
	t.Logf("intermediate committed: subject=%q serial=%s", subCert.Subject, subCert.SerialNumber.Text(16))

	// The boot wires the issued-set recorder onto the signer before any
	// listener starts; do the same so ACME issuance lands in ListIssued.
	revStore := revocation.NewStore(cli)
	signer := newSubordinateCASigner(t, ctx, subStore, subCert, subCfg).WithRecorder(cinit.IssuedRecorder(revStore))

	startACME(t, ctx, cli, signer, subCfg, env)
	return acmeNode{root: rootCert, rootPEM: rootPEM, revStore: revStore, baseURL: baseURL, eabKeyB64: eabKeyB64}

}

// newStoreWithClient is newStore that also hands back the etcd client, which
// the ACME and revocation stores are built on in production.
func newStoreWithClient(t *testing.T) (*node.Store, *clientv3.Client) {
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
	return s, cli
}

// intermediateACMEConfig is the Intermediate's machine config with ACME on:
// a leaf profile ACME issues under, a server profile for the TLS front that
// carries the host IP as its SAN, and the pki.acme block with one External
// Account Binding key. It goes through config.Parse so validateACME runs.
func intermediateACMEConfig(t *testing.T, rootPEM string, env kindEnv, baseURL, eabKeyB64 string) *config.Config {
	t.Helper()
	suffix := env.hostname[strings.Index(env.hostname, ".")+1:]
	yaml := fmt.Sprintf(`apiVersion: cryptos.dev/v1alpha1
kind: MachineConfig
metadata:
  name: issuing-kind
role:
  kind: intermediate
network:
  interface: eth0
  address: 10.0.0.11/24
  gateway: 10.0.0.1
bootstrap:
  admin_cert_pem: "`+testadmin.YAMLPEM+`"
pki:
  root_key_alg: ECDSA-P384
  root_subject:
    common_name: "ACME Issuing G1"
    organization: "ACME"
    country: "US"
  root_validity_years: 10
  path_len_constraint: 0
  parent:
    ca_cert_pem: |
%s
  profiles:
    - name: %s
      key_alg: ECDSA-P384
      subject:
        common_name: acme
      validity_days: 90
      basic_constraints:
        is_ca: false
      key_usage: [digital_signature]
      ext_key_usage: [server_auth]
    - name: acme-front
      key_alg: ECDSA-P384
      subject:
        common_name: cryptos-acme-front
      validity_days: 7
      basic_constraints:
        is_ca: false
      key_usage: [digital_signature]
      ext_key_usage: [server_auth]
      sans:
        ip: ["%s"]
  acme:
    base_url: %s
    profile: %s
    allowed_identifier_suffixes: [%s]
    external_account_keys:
      - key_id: %s
        hmac_key_base64: %s
`, indentPEM(rootPEM, "      "), kindLeafProfile,
		env.hostIP, baseURL, kindLeafProfile, suffix, kindEABKeyID, eabKeyB64)
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("config.Parse (intermediate with pki.acme): %v", err)
	}
	return cfg
}

// startACME serves the node's ACME handler on a loopback origin and puts a
// TLS front in front of it on the kind network, the deployment docs/acme.md
// describes. The front's certificate is issued by the Intermediate, so the
// cluster trusts it through the same root it is handed as caBundle.
func startACME(t *testing.T, ctx context.Context, cli *clientv3.Client, signer *node.CASigner, cfg *config.Config, env kindEnv) {
	t.Helper()

	h, err := cinit.NewACMEHandler(cli, signer, nil, cfg.PKI.ACME)
	if err != nil {
		t.Fatalf("NewACMEHandler: %v", err)
	}
	stop, err := acme.Serve(ctx, acmeOriginAddr, h)
	if err != nil {
		t.Fatalf("acme.Serve: %v", err)
	}
	t.Cleanup(func() {
		sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer scancel()
		_ = stop(sctx)
	})
	t.Logf("ACME origin up on http://%s (base_url %s)", acmeOriginAddr, cfg.PKI.ACME.BaseURL)

	frontKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("front key: %v", err)
	}
	frontChain, _, err := signer.IssueLeafForNames(ctx, buildCSR(t, frontKey, pkix.Name{CommonName: "cryptos-acme-front"}), "acme-front", nil)
	if err != nil {
		t.Fatalf("issue the TLS front certificate: %v", err)
	}
	front := tls.Certificate{Certificate: frontChain, PrivateKey: frontKey}

	origin := &url.URL{Scheme: "http", Host: acmeOriginAddr}
	proxy := httputil.NewSingleHostReverseProxy(origin)
	lis, err := net.Listen("tcp", net.JoinHostPort(env.hostIP, acmeFrontPort))
	if err != nil {
		t.Fatalf("listen for the ACME TLS front: %v", err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Logf("ACME front: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
			proxy.ServeHTTP(w, r)
		}),
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{front}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.ServeTLS(lis, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	t.Logf("ACME TLS front up on https://%s", lis.Addr())
}

// applyIssuerAndCertificate creates the EAB secret, the ClusterIssuer that
// points cert-manager at the node, and the Certificate for hostname.
func applyIssuerAndCertificate(t *testing.T, ctx context.Context, kc kubectlRunner, rootPEM []byte, baseURL, eabKeyB64, hostname string) {
	t.Helper()
	manifest := fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: %[1]s
  namespace: cert-manager
type: Opaque
stringData:
  hmac: %[2]s
---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: %[3]s
spec:
  acme:
    server: %[4]s/directory
    caBundle: %[5]s
    privateKeySecretRef:
      name: %[3]s-account
    externalAccountBinding:
      keyID: %[6]s
      keySecretRef:
        name: %[1]s
        key: hmac
    solvers:
      - http01:
          ingress:
            ingressClassName: contour
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: %[7]s
  namespace: %[8]s
spec:
  secretName: %[9]s
  dnsNames: [%[10]s]
  privateKey:
    algorithm: ECDSA
    size: 384
  issuerRef:
    kind: ClusterIssuer
    name: %[3]s
`, kindEABSecret, eabKeyB64, kindIssuer, baseURL, base64.StdEncoding.EncodeToString(rootPEM),
		kindEABKeyID, kindCertificate, kindNamespace, kindSecret, hostname)
	// The cert-manager webhook can report Available a few seconds before it
	// admits requests, so a refused apply right after install is retried.
	deadline := time.Now().Add(90 * time.Second)
	for {
		_, err := kc.run(ctx, manifest, "apply", "-f", "-")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("apply ClusterIssuer and Certificate: %v", err)
		}
		t.Logf("apply refused, retrying: %v", err)
		time.Sleep(5 * time.Second)
	}
	t.Logf("applied ClusterIssuer %s (server %s/directory) and Certificate %s/%s for %s",
		kindIssuer, baseURL, kindNamespace, kindCertificate, hostname)
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer ccancel()
		_, _ = kc.run(cctx, manifest, "delete", "--ignore-not-found", "--wait=false", "-f", "-")
	})
}

// issuedCertificate is what cert-manager wrote into the Certificate's secret.
type issuedCertificate struct {
	leaf          *x509.Certificate
	intermediates []*x509.Certificate
	key           any
}

// waitForIssuedCertificate polls until the Certificate is Ready and its secret
// holds a leaf whose serial is not notSerial, dumping cert-manager's view of
// the enrolment if that does not happen in time.
func waitForIssuedCertificate(t *testing.T, ctx context.Context, kc kubectlRunner, notSerial string, timeout time.Duration) issuedCertificate {
	t.Helper()
	deadline := time.Now().Add(timeout)
	lastState := ""
	for {
		ready, _ := kc.run(ctx, "", "-n", kindNamespace, "get", "certificate", kindCertificate,
			"-o", `jsonpath={.status.conditions[?(@.type=="Ready")].status}/{.status.conditions[?(@.type=="Ready")].reason}`)
		if ready != lastState {
			t.Logf("Certificate %s/%s Ready=%s", kindNamespace, kindCertificate, ready)
			lastState = ready
		}
		if strings.HasPrefix(ready, "True/") {
			got, err := readIssuedCertificate(ctx, kc)
			if err != nil {
				t.Logf("Certificate Ready but secret not readable yet: %v", err)
			} else if got.leaf.SerialNumber.Text(16) != notSerial {
				return got
			}
		}
		if time.Now().After(deadline) {
			kc.dumpDiagnostics(ctx)
			t.Fatalf("Certificate %s/%s did not get a new certificate within %s (last Ready=%q)",
				kindNamespace, kindCertificate, timeout, ready)
		}
		select {
		case <-ctx.Done():
			kc.dumpDiagnostics(context.Background())
			t.Fatalf("context done waiting for the Certificate: %v", ctx.Err())
		case <-time.After(3 * time.Second):
		}
	}
}

func readIssuedCertificate(ctx context.Context, kc kubectlRunner) (issuedCertificate, error) {
	var out issuedCertificate
	crtB64, err := kc.run(ctx, "", "-n", kindNamespace, "get", "secret", kindSecret, "-o", `jsonpath={.data.tls\.crt}`)
	if err != nil {
		return out, err
	}
	keyB64, err := kc.run(ctx, "", "-n", kindNamespace, "get", "secret", kindSecret, "-o", `jsonpath={.data.tls\.key}`)
	if err != nil {
		return out, err
	}
	crtPEM, err := base64.StdEncoding.DecodeString(strings.TrimSpace(crtB64))
	if err != nil {
		return out, fmt.Errorf("decode tls.crt: %w", err)
	}
	keyPEM, err := base64.StdEncoding.DecodeString(strings.TrimSpace(keyB64))
	if err != nil {
		return out, fmt.Errorf("decode tls.key: %w", err)
	}
	var certs []*x509.Certificate
	for rest := crtPEM; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return out, fmt.Errorf("parse tls.crt: %w", err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return out, errors.New("tls.crt holds no certificate")
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return out, errors.New("tls.key holds no PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		if ec, ecErr := x509.ParseECPrivateKey(block.Bytes); ecErr == nil {
			key, err = ec, nil
		}
	}
	if err != nil {
		return out, fmt.Errorf("parse tls.key: %w", err)
	}
	out.leaf, out.intermediates, out.key = certs[0], certs[1:], key
	return out, nil
}

// assertCertificate checks what a relying party and an auditor would: the
// chain verifies to the CryptOS root for hostname, the SANs are exactly the
// requested name, the key is the P-384 key cert-manager generated, and the
// node's issued set holds the serial under the ACME profile.
func assertCertificate(t *testing.T, ctx context.Context, got issuedCertificate, root *x509.Certificate, hostname string, revStore *revocation.Store) {
	t.Helper()
	serial := got.leaf.SerialNumber.Text(16)

	roots := x509.NewCertPool()
	roots.AddCert(root)
	inter := x509.NewCertPool()
	for _, c := range got.intermediates {
		inter.AddCert(c)
	}
	chains, err := got.leaf.Verify(x509.VerifyOptions{
		DNSName:       hostname,
		Roots:         roots,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Fatalf("secret %s chain does not verify to the CryptOS root: %v", kindSecret, err)
	}
	t.Logf("serial %s verifies: %d-certificate path to %q", serial, len(chains[0]), root.Subject)

	if len(got.leaf.DNSNames) != 1 || got.leaf.DNSNames[0] != hostname {
		t.Fatalf("leaf DNS SANs = %v, want [%s]", got.leaf.DNSNames, hostname)
	}
	if len(got.leaf.IPAddresses) != 0 || len(got.leaf.EmailAddresses) != 0 || len(got.leaf.URIs) != 0 {
		t.Fatalf("leaf carries non-DNS SANs: ip=%v email=%v uri=%v", got.leaf.IPAddresses, got.leaf.EmailAddresses, got.leaf.URIs)
	}
	pub, ok := got.leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P384() {
		t.Fatalf("leaf key is %T, want ECDSA P-384", got.leaf.PublicKey)
	}
	priv, ok := got.key.(*ecdsa.PrivateKey)
	if !ok || !priv.PublicKey.Equal(pub) {
		t.Fatal("tls.key does not match the leaf's public key")
	}

	rec, found, err := revStore.GetIssued(ctx, serial)
	if err != nil {
		t.Fatalf("GetIssued(%s): %v", serial, err)
	}
	if !found {
		all, _ := revStore.ListIssued(ctx)
		t.Fatalf("serial %s is not in the node's issued set (%d records)", serial, len(all))
	}
	if rec.ProfileName != kindLeafProfile || !bytes.Equal(rec.DER, got.leaf.Raw) {
		t.Fatalf("issued record for %s: profile=%q der-match=%v, want profile %q and the served DER",
			serial, rec.ProfileName, bytes.Equal(rec.DER, got.leaf.Raw), kindLeafProfile)
	}
	t.Logf("node recorded serial %s under profile %q", serial, rec.ProfileName)
}

// assertServedByIngress fetches https://hostname through the cluster ingress
// with only the CryptOS root trusted, and waits until the ingress presents the
// certificate with wantSerial.
func assertServedByIngress(t *testing.T, ctx context.Context, hostname string, root *x509.Certificate, wantSerial string) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(root)
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: hostname, MinVersion: tls.VersionTLS12},
		},
	}
	deadline := time.Now().Add(2 * time.Minute)
	var last string
	for {
		resp, err := client.Get("https://" + hostname + "/")
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
			_ = resp.Body.Close()
			served := resp.TLS.PeerCertificates[0].SerialNumber.Text(16)
			if resp.StatusCode == http.StatusOK && served == wantSerial {
				t.Logf("ingress serves serial %s for %s (HTTP %d, %d body bytes)", served, hostname, resp.StatusCode, len(body))
				return
			}
			last = fmt.Sprintf("HTTP %d with serial %s", resp.StatusCode, served)
		} else {
			last = err.Error()
		}
		if time.Now().After(deadline) {
			t.Fatalf("ingress never served serial %s for %s; last: %s", wantSerial, hostname, last)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context done waiting for the ingress: %v", ctx.Err())
		case <-time.After(3 * time.Second):
		}
	}
}

// kubectlRunner runs kubectl against the kind cluster's kubeconfig.
type kubectlRunner struct {
	t   *testing.T
	env kindEnv
}

func (k kubectlRunner) run(ctx context.Context, stdin string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	full := append([]string{"--kubeconfig", k.env.kubeconfig}, args...)
	cmd := exec.CommandContext(cctx, k.env.kubectl, full...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("kubectl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// dumpDiagnostics logs cert-manager's view of the enrolment so a red run says
// which step stalled without a rerun.
func (k kubectlRunner) dumpDiagnostics(ctx context.Context) {
	k.t.Helper()
	for _, args := range [][]string{
		{"-n", kindNamespace, "describe", "certificate,certificaterequest,order,challenge"},
		{"describe", "clusterissuer", kindIssuer},
		{"-n", kindNamespace, "get", "ingress,pods,svc", "-o", "wide"},
		{"-n", "cert-manager", "logs", "deploy/cert-manager", "--tail=200"},
	} {
		out, err := k.run(ctx, "", args...)
		k.t.Logf("--- kubectl %s ---\n%s", strings.Join(args, " "), out)
		if err != nil {
			k.t.Logf("(%v)", err)
		}
	}
}
