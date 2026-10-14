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
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos-node/internal/grpc"
	"github.com/CryptOS-PKI/cryptos-node/internal/imageupgrade"
	"github.com/CryptOS-PKI/cryptos-node/internal/reset"
	"github.com/CryptOS-PKI/cryptos-node/internal/storage/luks"
	"github.com/CryptOS-PKI/cryptos-node/internal/ukipcr"
)

const testCACN = "Example Root CA G1"

// releaseKey is a stand-in for the operator's Secure Boot release key.
type releaseKey struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

func newReleaseKey(t *testing.T) releaseKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		NotAfter:     time.Now().Add(time.Hour),
		NotBefore:    time.Now().Add(-time.Hour),
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "CryptOS Release Signing"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	return releaseKey{cert: cert, key: key}
}

func (r releaseKey) sign(t *testing.T, image []byte) []byte {
	t.Helper()

	sum := sha256.Sum256(image)
	sig, err := rsa.SignPKCS1v15(rand.Reader, r.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("SignPKCS1v15: %v", err)
	}

	return sig
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)

	return hex.EncodeToString(sum[:])
}

// espDir is a directory standing in for a mounted ESP. It records how each
// mount asked for, so a test can assert the node never mounted the real
// ESP read-write for an image it was going to refuse.
type espDir struct {
	root      string
	mounts    []bool // one entry per mount; true means read-write
	mountErr  error
	unmounted int
}

func newESPDir(t *testing.T, activeImage []byte) *espDir {
	t.Helper()

	root := t.TempDir()
	if activeImage != nil {
		if err := os.MkdirAll(filepath.Join(root, "EFI", "BOOT"), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(filepath.Join(root, imageupgrade.ActiveRelPath), activeImage, 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	return &espDir{root: root}
}

func (e *espDir) mount(readWrite bool, fn func(root string) error) error {
	e.mounts = append(e.mounts, readWrite)
	if e.mountErr != nil {
		return e.mountErr
	}
	defer func() { e.unmounted++ }()

	return fn(e.root)
}

func (e *espDir) mountedReadWrite() bool {
	for _, rw := range e.mounts {
		if rw {
			return true
		}
	}

	return false
}

// newTestUpgrader builds an upgrader over a directory ESP, as run.go builds
// one over the real partition.
func newTestUpgrader(t *testing.T, esp *espDir, rel releaseKey, running []byte, reboot func()) *nodeImageUpgrader {
	t.Helper()

	return newTestUpgraderCN(t, esp, rel, running, reboot, func() string { return testCACN })
}

// newTestUpgraderCN is newTestUpgrader with the CA CN lookup supplied, so a
// test can change the node's CA CN after the upgrader is built.
func newTestUpgraderCN(t *testing.T, esp *espDir, rel releaseKey, running []byte, reboot func(), caCN func() string) *nodeImageUpgrader {
	t.Helper()

	u, err := newImageUpgrader(imageUpgradeOptions{
		CACN:    caCN,
		Mount:   esp.mount,
		Reboot:  reboot,
		Release: rel.cert,
		Running: digestOf(running),
		Version: "v1.2.3",
	})
	if err != nil {
		t.Fatalf("newImageUpgrader: %v", err)
	}

	return u
}

// The upgrade #208 is for: a signed image becomes the one the node will boot,
// the state partition is never touched, and the caller is told a reboot is
// still outstanding.
func TestUpgrader_StageInstallsAndReportsARebootPending(t *testing.T) {
	rel := newReleaseKey(t)
	old := []byte("the running image")
	esp := newESPDir(t, old)
	u := newTestUpgrader(t, esp, rel, old, func() { t.Fatal("Stage must not reboot") })

	image := []byte("the new image")
	st, err := u.Stage(context.Background(), image, rel.sign(t, image))
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}

	if st.GetActiveSha256() != digestOf(image) {
		t.Errorf("active_sha256 = %q, want the new image", st.GetActiveSha256())
	}
	if st.GetRunningSha256() != digestOf(old) {
		t.Errorf("running_sha256 = %q, want the image the node booted", st.GetRunningSha256())
	}
	if st.GetPreviousSha256() != digestOf(old) {
		t.Errorf("previous_sha256 = %q, want the old image retained", st.GetPreviousSha256())
	}
	if !st.GetRebootPending() {
		t.Error("reboot_pending must be true while running and active differ")
	}
	if st.GetRunningVersion() != "v1.2.3" {
		t.Errorf("running_version = %q", st.GetRunningVersion())
	}
}

// The ESP must not even be mounted writable for an image the node is going to
// refuse. Verifying first keeps a bad upload from touching the boot partition
// of a production CA at all.
func TestUpgrader_StageVerifiesBeforeMountingWritable(t *testing.T) {
	rel := newReleaseKey(t)
	other := newReleaseKey(t)
	old := []byte("the running image")
	esp := newESPDir(t, old)
	u := newTestUpgrader(t, esp, rel, old, func() { t.Fatal("must not reboot") })

	image := []byte("the new image")
	_, err := u.Stage(context.Background(), image, other.sign(t, image))
	if !errors.Is(err, grpc.ErrImageNotVerified) {
		t.Fatalf("err = %v, want ErrImageNotVerified", err)
	}
	if esp.mountedReadWrite() {
		t.Error("the ESP was mounted read-write for an image that failed verification")
	}
	got, readErr := os.ReadFile(filepath.Join(esp.root, imageupgrade.ActiveRelPath))
	if readErr != nil || string(got) != string(old) {
		t.Errorf("active image = %q (%v), want it untouched", got, readErr)
	}
}

// Rollback restores the retained image and, like staging, leaves the reboot
// to the operator.
func TestUpgrader_RollbackRestoresTheRetainedImage(t *testing.T) {
	rel := newReleaseKey(t)
	old := []byte("the running image")
	esp := newESPDir(t, old)
	u := newTestUpgrader(t, esp, rel, old, func() { t.Fatal("Rollback must not reboot") })

	image := []byte("the bad new image")
	if _, err := u.Stage(context.Background(), image, rel.sign(t, image)); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	st, err := u.Rollback(context.Background())
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if st.GetActiveSha256() != digestOf(old) {
		t.Errorf("active_sha256 = %q, want the retained image restored", st.GetActiveSha256())
	}
}

// A node that has never been upgraded has nothing to roll back to, and that
// reads as a precondition rather than an internal failure.
func TestUpgrader_RollbackWithNothingRetained(t *testing.T) {
	rel := newReleaseKey(t)
	old := []byte("the running image")
	esp := newESPDir(t, old)
	u := newTestUpgrader(t, esp, rel, old, func() { t.Fatal("must not reboot") })

	if _, err := u.Rollback(context.Background()); !errors.Is(err, grpc.ErrNoPreviousImage) {
		t.Fatalf("err = %v, want ErrNoPreviousImage", err)
	}
}

// Rebooting an issuing CA is an outage, so an empty confirmation can never
// authorize one -- the same fail-closed rule the resetter applies.
func TestUpgrader_ActivateFailsClosedOnAnEmptyConfirmation(t *testing.T) {
	rel := newReleaseKey(t)
	old := []byte("the running image")
	esp := newESPDir(t, old)
	rebooted := false
	u := newTestUpgrader(t, esp, rel, old, func() { rebooted = true })

	if err := u.Activate(context.Background(), ""); !errors.Is(err, reset.ErrConfirmMismatch) {
		t.Fatalf("err = %v, want ErrConfirmMismatch", err)
	}
	if rebooted {
		t.Error("the node rebooted on an empty confirmation")
	}
}

func TestUpgrader_ActivateRefusesTheWrongCommonName(t *testing.T) {
	rel := newReleaseKey(t)
	old := []byte("the running image")
	esp := newESPDir(t, old)
	rebooted := false
	u := newTestUpgrader(t, esp, rel, old, func() { rebooted = true })

	image := []byte("the new image")
	if _, err := u.Stage(context.Background(), image, rel.sign(t, image)); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if err := u.Activate(context.Background(), "Some Other CA"); !errors.Is(err, reset.ErrConfirmMismatch) {
		t.Fatalf("err = %v, want ErrConfirmMismatch", err)
	}
	if rebooted {
		t.Error("the node rebooted on a mismatched confirmation")
	}
}

// Rebooting when nothing is staged is an outage with nothing to show for it,
// so it is refused rather than obeyed.
func TestUpgrader_ActivateRefusesWhenNothingIsStaged(t *testing.T) {
	rel := newReleaseKey(t)
	old := []byte("the running image")
	esp := newESPDir(t, old)
	rebooted := false
	u := newTestUpgrader(t, esp, rel, old, func() { rebooted = true })

	err := u.Activate(context.Background(), testCACN)
	if err == nil || errors.Is(err, reset.ErrConfirmMismatch) {
		t.Fatalf("err = %v, want a complaint that nothing is staged", err)
	}
	if rebooted {
		t.Error("the node rebooted with no staged image")
	}
}

func TestUpgrader_ActivateRebootsOnTheRightCommonName(t *testing.T) {
	rel := newReleaseKey(t)
	old := []byte("the running image")
	esp := newESPDir(t, old)
	rebooted := false
	u := newTestUpgrader(t, esp, rel, old, func() { rebooted = true })

	image := []byte("the new image")
	if _, err := u.Stage(context.Background(), image, rel.sign(t, image)); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if err := u.Activate(context.Background(), testCACN); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if !rebooted {
		t.Error("the node did not reboot on a correct confirmation")
	}
}

// Stage, Rollback and Activate share one lock (#373): two upgrade calls at
// the same time could otherwise both write BOOTX64.NEW.EFI, and a caller made
// while another is already running gets FailedPrecondition rather than
// queuing behind it or racing it.
//
// This drives the overlap with real goroutines rather than only holding the
// lock by hand, so it proves the lock is actually wired into Stage, not just
// that TryLock itself works.
func TestUpgrader_StageSerializesAgainstAConcurrentStage(t *testing.T) {
	rel := newReleaseKey(t)
	old := []byte("the running image")
	esp := newESPDir(t, old)
	started := make(chan struct{})
	release := make(chan struct{})
	blockingMount := func(readWrite bool, fn func(root string) error) error {
		return esp.mount(readWrite, func(root string) error {
			close(started)
			<-release

			return fn(root)
		})
	}
	u, err := newImageUpgrader(imageUpgradeOptions{
		CACN:    func() string { return testCACN },
		Mount:   blockingMount,
		Reboot:  func() { t.Fatal("must not reboot") },
		Release: rel.cert,
		Running: digestOf(old),
		Version: "v1.2.3",
	})
	if err != nil {
		t.Fatalf("newImageUpgrader: %v", err)
	}

	image := []byte("the new image")
	sig := rel.sign(t, image)
	firstDone := make(chan error, 1)
	go func() {
		_, stageErr := u.Stage(context.Background(), image, sig)
		firstDone <- stageErr
	}()

	<-started
	if _, err := u.Stage(context.Background(), image, sig); !errors.Is(err, grpc.ErrUpgradeInProgress) {
		t.Fatalf("concurrent Stage err = %v, want ErrUpgradeInProgress", err)
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("the first Stage: %v", err)
	}
}

// A caller must not be able to Stage while a Rollback the test holds the lock
// for is in flight (or vice versa); checked here against the lock directly,
// which exercises the same guard the goroutine test above exercises through
// real concurrency.
func TestUpgrader_StageRefusesWhileAnUpgradeIsInProgress(t *testing.T) {
	rel := newReleaseKey(t)
	old := []byte("the running image")
	esp := newESPDir(t, old)
	u := newTestUpgrader(t, esp, rel, old, func() { t.Fatal("must not reboot") })
	u.mu.Lock()
	defer u.mu.Unlock()

	image := []byte("the new image")
	if _, err := u.Stage(context.Background(), image, rel.sign(t, image)); !errors.Is(err, grpc.ErrUpgradeInProgress) {
		t.Fatalf("err = %v, want ErrUpgradeInProgress", err)
	}
	if esp.mountedReadWrite() {
		t.Error("a refused concurrent Stage still mounted the ESP")
	}
}

func TestUpgrader_RollbackRefusesWhileAnUpgradeIsInProgress(t *testing.T) {
	rel := newReleaseKey(t)
	old := []byte("the running image")
	esp := newESPDir(t, old)
	u := newTestUpgrader(t, esp, rel, old, func() { t.Fatal("must not reboot") })
	u.mu.Lock()
	defer u.mu.Unlock()

	if _, err := u.Rollback(context.Background()); !errors.Is(err, grpc.ErrUpgradeInProgress) {
		t.Fatalf("err = %v, want ErrUpgradeInProgress", err)
	}
	if esp.mountedReadWrite() {
		t.Error("a refused concurrent Rollback still mounted the ESP")
	}
}

func TestUpgrader_ActivateRefusesWhileAnUpgradeIsInProgress(t *testing.T) {
	rel := newReleaseKey(t)
	old := []byte("the running image")
	esp := newESPDir(t, old)
	u := newTestUpgrader(t, esp, rel, old, func() { t.Fatal("must not reboot") })

	image := []byte("the new image")
	if _, err := u.Stage(context.Background(), image, rel.sign(t, image)); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	u.mu.Lock()
	defer u.mu.Unlock()

	if err := u.Activate(context.Background(), testCACN); !errors.Is(err, grpc.ErrUpgradeInProgress) {
		t.Fatalf("err = %v, want ErrUpgradeInProgress", err)
	}
}

// On a node that has not been upgraded, running and active are the same image
// and nothing is outstanding.
func TestUpgrader_StatusOnAnUnupgradedNode(t *testing.T) {
	rel := newReleaseKey(t)
	old := []byte("the running image")
	esp := newESPDir(t, old)
	u := newTestUpgrader(t, esp, rel, old, func() { t.Fatal("must not reboot") })

	st, err := u.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.GetRebootPending() {
		t.Error("reboot_pending must be false when running and active are the same image")
	}
	if st.GetPreviousSha256() != "" {
		t.Errorf("previous_sha256 = %q, want empty", st.GetPreviousSha256())
	}
	if esp.mountedReadWrite() {
		t.Error("reading status mounted the ESP read-write")
	}
}

// A build with no release certificate must refuse to construct an upgrader, so
// the RPCs are Unimplemented rather than silently accepting any image.
func TestNewImageUpgrader_RequiresARelease(t *testing.T) {
	esp := newESPDir(t, []byte("image"))
	_, err := newImageUpgrader(imageUpgradeOptions{
		CACN:    func() string { return testCACN },
		Mount:   esp.mount,
		Reboot:  func() {},
		Running: "aa",
	})
	if err == nil {
		t.Error("newImageUpgrader accepted a build with no release certificate")
	}
}

// Every mount is released, including on the failure paths, or the ESP stays
// busy and the next upgrade cannot mount it.
func TestUpgrader_UnmountsEvenWhenStagingFails(t *testing.T) {
	rel := newReleaseKey(t)
	old := []byte("the running image")
	esp := newESPDir(t, old)
	u := newTestUpgrader(t, esp, rel, old, func() { t.Fatal("must not reboot") })

	// A directory where the incoming image must go makes the write fail.
	if err := os.MkdirAll(filepath.Join(esp.root, "EFI", "BOOT", "BOOTX64.NEW.EFI"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	image := []byte("the new image")
	if _, err := u.Stage(context.Background(), image, rel.sign(t, image)); err == nil {
		t.Fatal("Stage reported success despite an unwritable slot")
	}
	if esp.unmounted != len(esp.mounts) {
		t.Errorf("unmounted %d of %d mounts", esp.unmounted, len(esp.mounts))
	}
	got, _ := os.ReadFile(filepath.Join(esp.root, imageupgrade.ActiveRelPath))
	if string(got) != string(old) {
		t.Errorf("active image = %q, want the node still bootable", got)
	}
}

// The CA CN is read per call. A node whose CA certificate is installed after
// its current boot (a subordinate's submit-subordinate-cert, or the ceremony
// boot) had an empty CN at startup, and must still accept the correct CN
// without first needing the reboot it is asking for.
func TestUpgrader_ActivateHonoursACACNInstalledAfterBoot(t *testing.T) {
	rel := newReleaseKey(t)
	old := []byte("the running image")
	esp := newESPDir(t, old)
	cn := ""
	rebooted := false
	u := newTestUpgraderCN(t, esp, rel, old, func() { rebooted = true }, func() string { return cn })

	image := []byte("the new image")
	if _, err := u.Stage(context.Background(), image, rel.sign(t, image)); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if err := u.Activate(context.Background(), testCACN); !errors.Is(err, reset.ErrNoCAIdentity) {
		t.Fatalf("before the CA certificate is installed: err = %v, want ErrNoCAIdentity", err)
	}
	if rebooted {
		t.Fatal("the node rebooted with no CA identity")
	}

	cn = testCACN
	if err := u.Activate(context.Background(), testCACN); err != nil {
		t.Fatalf("after the CA certificate is installed: %v", err)
	}
	if !rebooted {
		t.Error("the node did not reboot on a correct confirmation")
	}
}

// Rollback is confirmed by the activate that follows it, so the same late CN
// must be honoured there too.
func TestUpgrader_ActivateAfterRollbackHonoursACACNInstalledAfterBoot(t *testing.T) {
	rel := newReleaseKey(t)
	running := []byte("the running image")
	esp := newESPDir(t, running)
	cn := ""
	rebooted := false
	u := newTestUpgraderCN(t, esp, rel, running, func() { rebooted = true }, func() string { return cn })

	// Two stages leave a retained image that differs from the running one, so
	// rolling back leaves a reboot pending.
	for _, img := range [][]byte{[]byte("image one"), []byte("image two")} {
		if _, err := u.Stage(context.Background(), img, rel.sign(t, img)); err != nil {
			t.Fatalf("Stage: %v", err)
		}
	}
	st, err := u.Rollback(context.Background())
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !st.GetRebootPending() {
		t.Fatal("rollback to a different image must leave a reboot pending")
	}

	cn = testCACN
	if err := u.Activate(context.Background(), testCACN); err != nil {
		t.Fatalf("Activate after rollback: %v", err)
	}
	if !rebooted {
		t.Error("the node did not reboot on a correct confirmation")
	}
}

func TestUpgrader_ActivateWithNoCAIdentity(t *testing.T) {
	rel := newReleaseKey(t)
	old := []byte("the running image")
	esp := newESPDir(t, old)
	u := newTestUpgraderCN(t, esp, rel, old, func() { t.Fatal("must not reboot") }, func() string { return "" })

	for _, confirm := range []string{"", testCACN} {
		if err := u.Activate(context.Background(), confirm); !errors.Is(err, reset.ErrNoCAIdentity) {
			t.Fatalf("confirm %q: err = %v, want ErrNoCAIdentity", confirm, err)
		}
	}
}

// resealCall records one Reseal the upgrader asked for.
type resealCall struct {
	running  []byte
	bootable [][]byte
}

func newResealingUpgrader(t *testing.T, esp *espDir, rel releaseKey, running []byte, reseal func(context.Context, []byte, ...[]byte) error) *nodeImageUpgrader {
	t.Helper()

	u, err := newImageUpgrader(imageUpgradeOptions{
		CACN:    func() string { return testCACN },
		Mount:   esp.mount,
		Reboot:  func() { t.Fatal("Stage must not reboot") },
		Release: rel.cert,
		Running: digestOf(running),
		Version: "v1.2.3",
		Reseal:  reseal,
	})
	if err != nil {
		t.Fatalf("newImageUpgrader: %v", err)
	}

	return u
}

// On a TPM node the key has to be resealed for every image that will be
// bootable after the stage, and before the stage writes anything.
func TestUpgrader_StageResealsForEveryBootableImageFirst(t *testing.T) {
	rel := newReleaseKey(t)
	old := []byte("the running image")
	esp := newESPDir(t, old)
	var calls []resealCall
	u := newResealingUpgrader(t, esp, rel, old, func(_ context.Context, running []byte, bootable ...[]byte) error {
		active, _ := os.ReadFile(filepath.Join(esp.root, imageupgrade.ActiveRelPath))
		if string(active) != string(old) {
			t.Error("the ESP was written before the reseal ran")
		}
		calls = append(calls, resealCall{running: running, bootable: bootable})
		return nil
	})

	image := []byte("the new image")
	if _, err := u.Stage(context.Background(), image, rel.sign(t, image)); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("Reseal called %d times, want 1", len(calls))
	}
	if string(calls[0].running) != string(old) {
		t.Errorf("running = %q, want the image read back from the ESP", calls[0].running)
	}
	if len(calls[0].bootable) != 2 || string(calls[0].bootable[0]) != string(image) || string(calls[0].bootable[1]) != string(old) {
		t.Errorf("bootable = %q, want the new image and the one retained for rollback", calls[0].bootable)
	}
}

// Staging again before a reboot: the image staged first becomes the
// retained one, so it has to stay unsealable too.
func TestUpgrader_RestageCoversTheImageItDisplaces(t *testing.T) {
	rel := newReleaseKey(t)
	old := []byte("the running image")
	esp := newESPDir(t, old)
	var last resealCall
	u := newResealingUpgrader(t, esp, rel, old, func(_ context.Context, running []byte, bootable ...[]byte) error {
		last = resealCall{running: running, bootable: bootable}
		return nil
	})

	first, second := []byte("first staged"), []byte("second staged")
	if _, err := u.Stage(context.Background(), first, rel.sign(t, first)); err != nil {
		t.Fatalf("first Stage: %v", err)
	}
	if _, err := u.Stage(context.Background(), second, rel.sign(t, second)); err != nil {
		t.Fatalf("second Stage: %v", err)
	}
	if string(last.running) != string(old) {
		t.Errorf("running = %q, want the booted image, found in the previous slot", last.running)
	}
	if len(last.bootable) != 2 || string(last.bootable[0]) != string(second) || string(last.bootable[1]) != string(first) {
		t.Errorf("bootable = %q, want the second image and the first it displaces", last.bootable)
	}
}

func TestUpgrader_StageRefusedByTheResealWritesNothing(t *testing.T) {
	rel := newReleaseKey(t)
	old := []byte("the running image")
	esp := newESPDir(t, old)
	u := newResealingUpgrader(t, esp, rel, old, func(context.Context, []byte, ...[]byte) error {
		return fmt.Errorf("%w: prediction mismatch", errResealRefused)
	})

	image := []byte("the new image")
	_, err := u.Stage(context.Background(), image, rel.sign(t, image))
	if !errors.Is(err, grpc.ErrImageNotResealable) {
		t.Fatalf("err = %v, want ErrImageNotResealable", err)
	}
	entries, _ := os.ReadDir(filepath.Join(esp.root, "EFI", "BOOT"))
	if len(entries) != 1 {
		t.Errorf("ESP holds %d files after a refused stage, want only the original", len(entries))
	}
	got, _ := os.ReadFile(filepath.Join(esp.root, imageupgrade.ActiveRelPath))
	if string(got) != string(old) {
		t.Errorf("active image = %q, want it untouched", got)
	}
}

// A reseal that fails for any other reason still stops the stage, but it is
// not a refusal: the node, not the image, has the problem.
func TestUpgrader_StageStopsOnAResealFailure(t *testing.T) {
	rel := newReleaseKey(t)
	old := []byte("the running image")
	esp := newESPDir(t, old)
	u := newResealingUpgrader(t, esp, rel, old, func(context.Context, []byte, ...[]byte) error {
		return errors.New("cryptsetup: device busy")
	})

	image := []byte("the new image")
	_, err := u.Stage(context.Background(), image, rel.sign(t, image))
	if err == nil || errors.Is(err, grpc.ErrImageNotResealable) {
		t.Fatalf("err = %v, want a plain failure", err)
	}
	got, _ := os.ReadFile(filepath.Join(esp.root, imageupgrade.ActiveRelPath))
	if string(got) != string(old) {
		t.Errorf("active image = %q, want it untouched", got)
	}
}

func TestUpgrader_StageRefusesWhenTheRunningImageIsGone(t *testing.T) {
	rel := newReleaseKey(t)
	running := []byte("the running image")
	esp := newESPDir(t, []byte("something else entirely"))
	u := newResealingUpgrader(t, esp, rel, running, func(context.Context, []byte, ...[]byte) error {
		t.Fatal("Reseal must not run without the running image to check against")
		return nil
	})

	image := []byte("the new image")
	if _, err := u.Stage(context.Background(), image, rel.sign(t, image)); !errors.Is(err, grpc.ErrImageNotResealable) {
		t.Fatalf("err = %v, want ErrImageNotResealable", err)
	}
}

// newTPMUpgrader is an upgrader wired the way run.go wires a TPM node: the
// real resealer over a fake TPM and header.
func newTPMUpgrader(t *testing.T, esp *espDir, rel releaseKey, running []byte, r *stateKeyResealer) *nodeImageUpgrader {
	t.Helper()

	u, err := newImageUpgrader(imageUpgradeOptions{
		CACN:     func() string { return testCACN },
		Mount:    esp.mount,
		Reboot:   func() {},
		Release:  rel.cert,
		Running:  digestOf(running),
		Version:  "v1.2.3",
		Reseal:   r.Reseal,
		Retarget: r.Retarget,
	})
	if err != nil {
		t.Fatalf("newImageUpgrader: %v", err)
	}

	return u
}

// Stage B on A, boot B, roll back: the ESP can only boot A now, so the header
// must hold a token for A and none for B.
func TestUpgrader_RollbackPrunesTheRolledBackFromToken(t *testing.T) {
	rel := newReleaseKey(t)
	imgA, imgB := []byte("image A"), []byte("image B")
	tp, hdr, _ := installNode(t, imgA)
	esp := newESPDir(t, imgA)

	if _, err := newTPMUpgrader(t, esp, rel, imgA, newTestResealer(tp, hdr)).Stage(context.Background(), imgB, rel.sign(t, imgB)); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if got, want := hdr.imagesCovered(t), sortedDigests(imgA, imgB); !slices.Equal(got, want) {
		t.Fatalf("after stage tokens cover %v, want %v", got, want)
	}
	if !bootsOn(t, tp, hdr, imgB) {
		t.Fatal("the staged image cannot open the state volume")
	}

	hdr.ops = nil
	st, err := newTPMUpgrader(t, esp, rel, imgB, newTestResealer(tp, hdr)).Rollback(context.Background())
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if st.GetActiveSha256() != digestOf(imgA) {
		t.Fatalf("active = %s, want image A", st.GetActiveSha256())
	}
	if got, want := hdr.imagesCovered(t), sortedDigests(imgA); !slices.Equal(got, want) {
		t.Fatalf("after rollback tokens cover %v, want %v", got, want)
	}
	if len(hdr.ops) == 0 || !strings.HasPrefix(hdr.ops[0], "import ") {
		t.Errorf("header ops = %v, want the new token added before any removal", hdr.ops)
	}
	if !bootsOn(t, tp, hdr, imgA) {
		t.Fatal("the rollback target cannot open the state volume")
	}
	if bootsOn(t, tp, hdr, imgB) {
		t.Fatal("the rolled-back-from image still opens the state volume")
	}
}

// Rolling back a stage that was never booted drops the staged image's token
// and keeps the running one's.
func TestUpgrader_RollbackBeforeRebootPrunesTheStagedToken(t *testing.T) {
	rel := newReleaseKey(t)
	imgA, imgB := []byte("image A"), []byte("image B")
	tp, hdr, _ := installNode(t, imgA)
	esp := newESPDir(t, imgA)
	u := newTPMUpgrader(t, esp, rel, imgA, newTestResealer(tp, hdr))

	if _, err := u.Stage(context.Background(), imgB, rel.sign(t, imgB)); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if _, err := u.Rollback(context.Background()); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if got, want := hdr.imagesCovered(t), sortedDigests(imgA); !slices.Equal(got, want) {
		t.Fatalf("tokens cover %v, want %v", got, want)
	}
	if !bootsOn(t, tp, hdr, imgA) {
		t.Fatal("the running image cannot open the state volume")
	}
}

// Two stages without a reboot, then a rollback: the running image is off the
// ESP, so nothing can prove this boot for a fresh seal. The target's existing
// token is kept and every other one goes.
func TestUpgrader_RollbackWithTheRunningImageGoneKeepsTheTargetToken(t *testing.T) {
	rel := newReleaseKey(t)
	imgA, imgB, imgC := []byte("image A"), []byte("image B"), []byte("image C")
	tp, hdr, _ := installNode(t, imgA)
	esp := newESPDir(t, imgA)
	u := newTPMUpgrader(t, esp, rel, imgA, newTestResealer(tp, hdr))
	for _, img := range [][]byte{imgB, imgC} {
		if _, err := u.Stage(context.Background(), img, rel.sign(t, img)); err != nil {
			t.Fatalf("Stage: %v", err)
		}
	}

	st, err := u.Rollback(context.Background())
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if st.GetActiveSha256() != digestOf(imgB) {
		t.Fatalf("active = %s, want image B", st.GetActiveSha256())
	}
	if got, want := hdr.imagesCovered(t), sortedDigests(imgB); !slices.Equal(got, want) {
		t.Fatalf("tokens cover %v, want %v", got, want)
	}
	if !bootsOn(t, tp, hdr, imgB) {
		t.Fatal("the rollback target cannot open the state volume")
	}
}

// Without a proven boot and without a token of its own, the target could be
// left with nothing, so the header is not touched.
func TestRetarget_WithoutARunningImageNeedsTheTargetsToken(t *testing.T) {
	imgA := []byte("image A")
	tp, hdr, _ := installNode(t, imgA)

	if err := newTestResealer(tp, hdr).Retarget(context.Background(), nil, []byte("image B")); err == nil {
		t.Fatal("Retarget dropped tokens though the target has none")
	}
	if len(hdr.ops) != 0 {
		t.Errorf("the header was changed: %v", hdr.ops)
	}
}

// The ESP has already been rolled back when the prune runs, so a prune that
// cannot proceed leaves the header as it was and the rollback stands.
func TestUpgrader_RollbackSurvivesAFailedPrune(t *testing.T) {
	rel := newReleaseKey(t)
	imgA, imgB := []byte("image A"), []byte("image B")
	tp, hdr, _ := installNode(t, imgA)
	esp := newESPDir(t, imgA)
	if _, err := newTPMUpgrader(t, esp, rel, imgA, newTestResealer(tp, hdr)).Stage(context.Background(), imgB, rel.sign(t, imgB)); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	tp.boot(imgB)
	hdr.ops = nil
	hdr.failNext["token import"] = hdr.counts["token import"] + 1

	st, err := newTPMUpgrader(t, esp, rel, imgB, newTestResealer(tp, hdr)).Rollback(context.Background())
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if st.GetActiveSha256() != digestOf(imgA) {
		t.Fatalf("active = %s, want image A", st.GetActiveSha256())
	}
	if got, want := hdr.imagesCovered(t), sortedDigests(imgA, imgB); !slices.Equal(got, want) {
		t.Fatalf("tokens cover %v, want the header unchanged (%v)", got, want)
	}
	if !bootsOn(t, tp, hdr, imgA) {
		t.Fatal("the rollback target cannot open the state volume")
	}
}

// A refused stage names the refusal once and keeps the specific cause.
func TestUpgrader_StageRefusalSaysSoOnce(t *testing.T) {
	rel := newReleaseKey(t)
	imgA := []byte("image A")
	tp, hdr, _ := installNode(t, imgA)
	esp := newESPDir(t, imgA)

	image := []byte("unpredictable image")
	_, err := newTPMUpgrader(t, esp, rel, imgA, newTestResealer(tp, hdr)).Stage(context.Background(), image, rel.sign(t, image))
	if !errors.Is(err, grpc.ErrImageNotResealable) || !errors.Is(err, ukipcr.ErrUnpredictable) {
		t.Fatalf("err = %v, want ErrImageNotResealable wrapping ErrUnpredictable", err)
	}
	if n := strings.Count(err.Error(), "cannot be resealed"); n != 1 {
		t.Errorf("error %q states the refusal %d times, want once", err, n)
	}
	if !strings.Contains(err.Error(), "predict PCR 11 for image") || !strings.Contains(err.Error(), "test image") {
		t.Errorf("error %q lost the specific cause", err)
	}
}

// The same stage, boot and rollback against a real LUKS2 header, so the
// token set is read back by cryptsetup itself. Skipped where cryptsetup is
// unavailable.
func TestUpgrader_RollbackPrunesTheToken_RealCryptsetup(t *testing.T) {
	bin, err := exec.LookPath("cryptsetup")
	if err != nil {
		t.Skip("cryptsetup not on PATH")
	}
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.img")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create device file: %v", err)
	}
	if err := os.Truncate(path, 32<<20); err != nil {
		t.Fatalf("size device file: %v", err)
	}
	run := &luks.ExecRunner{Binary: bin}
	key := bytes.Repeat([]byte{0x5a}, stateKeyBytes)
	if _, stderr, err := run.Run(ctx, bytes.NewReader(key),
		"luksFormat", "--type", "luks2", "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000",
		"--batch-mode", "--key-file", "-", path); err != nil {
		t.Skipf("luksFormat unavailable here: %v (%s)", err, stderr)
	}
	dev := &luks.Device{Path: path, Runner: run}

	rel := newReleaseKey(t)
	imgA, imgB := []byte("image A"), []byte("image B")
	tp := newPolicyTPM()
	tp.boot(imgA)
	priv, pub, err := tp.SealToPCR(key, []int{7, 11})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	tok, _ := luks.BuildTPM2Token(priv, pub, stateKeyslot, []int{7, 11}, nil)
	tokJSON, _ := json.Marshal(tok)
	if err := dev.ImportToken(ctx, StateTokenID, tokJSON); err != nil {
		t.Fatalf("import install token: %v", err)
	}
	resealer := func() *stateKeyResealer {
		r := newStateKeyResealer(dev, func() (resealTPM, error) { return tp, nil })
		r.predict = fakePredictor
		return r
	}
	covered := func() []string {
		all, err := dev.Tokens(ctx)
		if err != nil {
			t.Fatalf("Tokens: %v", err)
		}
		var out []string
		for _, tt := range tpmTokensOf(all) {
			out = append(out, tt.tok.ImageSHA256)
		}
		slices.Sort(out)
		return out
	}

	esp := newESPDir(t, imgA)
	if _, err := newTPMUpgrader(t, esp, rel, imgA, resealer()).Stage(ctx, imgB, rel.sign(t, imgB)); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if got, want := covered(), sortedDigests(imgA, imgB); !slices.Equal(got, want) {
		t.Fatalf("after stage tokens cover %v, want %v", got, want)
	}

	tp.boot(imgB)
	if _, err := newTPMUpgrader(t, esp, rel, imgB, resealer()).Rollback(ctx); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if got, want := covered(), sortedDigests(imgA); !slices.Equal(got, want) {
		t.Fatalf("after rollback tokens cover %v, want %v", got, want)
	}
	all, _ := dev.Tokens(ctx)
	tp.boot(imgA)
	got, _, err := unsealAny(tp, tpmTokensOf(all), imageDigest(imgA))
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("the rollback target cannot unseal the state key: %v", err)
	}
}
