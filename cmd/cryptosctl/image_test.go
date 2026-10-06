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
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"github.com/CryptOS-PKI/cryptos-node/internal/bootstrap"
	cgrpc "github.com/CryptOS-PKI/cryptos-node/internal/grpc"
	"github.com/CryptOS-PKI/cryptos-node/internal/reset"
)

// recordingUpgrader stands in for the node's real upgrader, so these tests
// exercise the actual gRPC streaming path and the real chunking in the CLI
// without needing an ESP.
type recordingUpgrader struct {
	activateErr error
	rollbackErr error

	received    []byte
	signature   []byte
	activatedCN string
	rolledBack  bool
}

func (r *recordingUpgrader) Stage(_ context.Context, image, signature []byte) (*nodev1.ImageStatus, error) {
	r.received = image
	r.signature = signature
	sum := sha256.Sum256(image)

	return &nodev1.ImageStatus{
		ActiveSha256:  hex.EncodeToString(sum[:]),
		RebootPending: true,
		RunningSha256: "0000",
	}, nil
}

func (r *recordingUpgrader) Rollback(context.Context) (*nodev1.ImageStatus, error) {
	r.rolledBack = true
	if r.rollbackErr != nil {
		return nil, r.rollbackErr
	}

	return &nodev1.ImageStatus{ActiveSha256: "0000", RunningSha256: "0000"}, nil
}

func (r *recordingUpgrader) Activate(_ context.Context, confirmCommonName string) error {
	r.activatedCN = confirmCommonName

	return r.activateErr
}

func (r *recordingUpgrader) Status(context.Context) (*nodev1.ImageStatus, error) {
	return &nodev1.ImageStatus{
		ActiveSha256:   "abcd",
		RebootPending:  false,
		RunningSha256:  "abcd",
		RunningVersion: "v1.2.3",
	}, nil
}

// startImageServer wires the upgrader plus the admin trust the image RPCs
// authorize against, which the base harness deliberately leaves unset.
func startImageServer(t *testing.T, up cgrpc.ImageUpgrader) *testServer {
	t.Helper()

	return startTestServerWith(t, func(cfg *cgrpc.ServerConfig, clientCert *x509.Certificate) {
		cfg.ImageUpgrader = up

		fp := sha256.Sum256(clientCert.Raw)
		trust, err := bootstrap.LoadTrust("", hex.EncodeToString(fp[:]))
		if err != nil {
			t.Fatalf("LoadTrust: %v", err)
		}
		cfg.Trust = trust
	})
}

// writeImage writes size random bytes plus a signature file beside it, the
// layout cryptos-appliance's build/uki/sign.sh produces.
func writeImage(t *testing.T, dir string, size int) (imagePath string, contents []byte) {
	t.Helper()

	contents = make([]byte, size)
	if _, err := rand.Read(contents); err != nil {
		t.Fatalf("rand: %v", err)
	}
	imagePath = filepath.Join(dir, "cryptos-amd64.uki")
	if err := os.WriteFile(imagePath, contents, 0o600); err != nil {
		t.Fatalf("write image: %v", err)
	}
	if err := os.WriteFile(imagePath+".sig", []byte("detached-release-signature"), 0o600); err != nil {
		t.Fatalf("write signature: %v", err)
	}

	return imagePath, contents
}

// The upload has to survive chunking: an image larger than one chunk must
// arrive at the node byte-identical and in order, or the node would reject a
// perfectly good build as unverifiable.
func TestImageStage_UploadsAMultiChunkImageIntact(t *testing.T) {
	up := &recordingUpgrader{}
	ts := startImageServer(t, up)
	imagePath, contents := writeImage(t, t.TempDir(), imageChunkBytes*2+1234)

	out, err := ts.run(t, "image", "stage", "--image", imagePath)
	if err != nil {
		t.Fatalf("image stage: %v (out=%s)", err, out)
	}

	if len(up.received) != len(contents) {
		t.Fatalf("node received %d bytes, sent %d", len(up.received), len(contents))
	}
	if sha256.Sum256(up.received) != sha256.Sum256(contents) {
		t.Error("the image the node received is not the one that was sent")
	}
	if string(up.signature) != "detached-release-signature" {
		t.Errorf("signature = %q, want the one beside the image", up.signature)
	}
}

// cryptos-appliance's build/uki/sign.sh writes the signature as <image>.sig,
// so not having to name it is the common case and worth not getting wrong.
func TestImageStage_DefaultsTheSignaturePathBesideTheImage(t *testing.T) {
	up := &recordingUpgrader{}
	ts := startImageServer(t, up)
	dir := t.TempDir()
	imagePath, _ := writeImage(t, dir, 64)

	if _, err := ts.run(t, "image", "stage", "--image", imagePath); err != nil {
		t.Fatalf("image stage: %v", err)
	}
	if string(up.signature) != "detached-release-signature" {
		t.Errorf("signature = %q, want the sibling .sig picked up", up.signature)
	}
}

// A missing signature must fail before the upload, not after it.
func TestImageStage_RefusesAMissingSignature(t *testing.T) {
	up := &recordingUpgrader{}
	ts := startImageServer(t, up)
	dir := t.TempDir()
	imagePath, _ := writeImage(t, dir, 64)
	if err := os.Remove(imagePath + ".sig"); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	if _, err := ts.run(t, "image", "stage", "--image", imagePath); err == nil {
		t.Fatal("image stage succeeded with no signature file")
	}
	if up.received != nil {
		t.Error("the image was uploaded despite a missing signature")
	}
}

func TestImageStatus_ReportsTheRunningImage(t *testing.T) {
	ts := startImageServer(t, &recordingUpgrader{})

	out, err := ts.run(t, "image", "status")
	if err != nil {
		t.Fatalf("image status: %v (out=%s)", err, out)
	}
	if !strings.Contains(out, "v1.2.3") {
		t.Errorf("output does not name the running version: %s", out)
	}
}

func TestImageRollback_CallsTheNode(t *testing.T) {
	up := &recordingUpgrader{}
	ts := startImageServer(t, up)

	if _, err := ts.run(t, "image", "rollback"); err != nil {
		t.Fatalf("image rollback: %v", err)
	}
	if !up.rolledBack {
		t.Error("the node was not asked to roll back")
	}
}

// Rebooting an issuing CA is an outage, so the CLI must not let it happen
// without the operator naming the CA.
func TestImageActivate_RequiresTheConfirmation(t *testing.T) {
	up := &recordingUpgrader{}
	ts := startImageServer(t, up)

	if _, err := ts.run(t, "image", "activate"); err == nil {
		t.Fatal("image activate rebooted the node with no confirmation")
	}
	if up.activatedCN != "" {
		t.Error("the node was contacted despite a missing confirmation")
	}
}

func TestImageActivate_PassesTheConfirmationThrough(t *testing.T) {
	up := &recordingUpgrader{}
	ts := startImageServer(t, up)

	if _, err := ts.run(t, "image", "activate", "--confirm", "Example Root CA G1"); err != nil {
		t.Fatalf("image activate: %v", err)
	}
	if up.activatedCN != "Example Root CA G1" {
		t.Errorf("confirm CN = %q", up.activatedCN)
	}
}

// A wrong confirmation must surface as a refusal, not as a success the
// operator then waits on a reboot for.
func TestImageActivate_ReportsAMismatchedConfirmation(t *testing.T) {
	up := &recordingUpgrader{activateErr: reset.ErrConfirmMismatch}
	ts := startImageServer(t, up)

	if _, err := ts.run(t, "image", "activate", "--confirm", "Wrong CA"); err == nil {
		t.Fatal("image activate reported success on a mismatched confirmation")
	}
}
