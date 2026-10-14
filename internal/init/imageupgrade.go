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

// The node side of in-place image upgrades (#208): the grpc.ImageUpgrader a
// running node serves, over internal/imageupgrade and the real ESP.
//
// The state partition is never opened here. That is the whole point of the
// feature: an OS change stops being a re-provision that destroys the CA key.
// On a TPM node staging does write to the partition's LUKS header, adding a
// sealed copy of the state key for the incoming image (see
// statekeyreseal.go), but the volume itself stays locked.

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	cgrpc "github.com/CryptOS-PKI/cryptos-node/internal/grpc"
	"github.com/CryptOS-PKI/cryptos-node/internal/imageupgrade"
	"github.com/CryptOS-PKI/cryptos-node/internal/reset"
)

// imageActivateRebootDelay lets the ActivateImageResponse flush before the
// connection drops, the same handoff the resetter and the installer use: a
// direct reboot inside the handler races the reply and the caller cannot tell
// success from a dropped connection.
const imageActivateRebootDelay = 2 * time.Second

// espMounter mounts the node's EFI System Partition, runs fn against the mount
// point, and unmounts -- including when fn fails, or the partition stays busy
// and the next upgrade cannot mount it.
//
// readWrite is a parameter rather than always true so reading status cannot
// modify the boot partition of a production CA even by accident.
type espMounter func(readWrite bool, fn func(root string) error) error

// imageUpgradeOptions carries the dependencies for a nodeImageUpgrader.
type imageUpgradeOptions struct {
	// CACN returns this node's current CA common name, echoed by the caller
	// to authorize a reboot. It is called per Activate so a CA certificate
	// installed after boot is honoured. Empty (an unprovisioned node) makes
	// every confirmation fail with reset.ErrNoCAIdentity.
	CACN func() string
	// Mount mounts the ESP for one operation.
	Mount espMounter
	// Reboot restarts the node. It runs only after a confirmed Activate.
	Reboot func()
	// Release is the certificate an incoming image must be signed by, from
	// internal/release. Nil is refused: a build with no release certificate
	// serves no upgrade RPCs at all rather than accepting anything.
	Release *x509.Certificate
	// Running is the SHA-256 (hex) of the image this node booted, captured at
	// startup before anything could stage over it. It is what makes
	// reboot_pending answerable: once an upgrade is staged, the file on the
	// boot path is no longer the file that is running.
	Running string
	// Version is the build version string of the running image, which is what
	// an operator actually recognises.
	Version string
	// Reseal, when set, makes the state key unsealable by the running image
	// and every image in bootable, and by nothing else. Stage calls it before
	// the ESP is written, so a node whose key is sealed to the image (a TPM
	// node, where PCR 11 measures the UKI) cannot stage itself into a boot
	// that fails to open its state. Nil where the key is not bound to the
	// image (nodeID and KMS modes).
	Reseal func(ctx context.Context, running []byte, bootable ...[]byte) error
	// Retarget, when set, makes the state key unsealable by exactly the images
	// in bootable; running only proves the current boot. Rollback calls it
	// after the ESP is rolled back, so the image rolled back from, which the
	// ESP can no longer boot, stops being able to open the state. Nil wherever
	// Reseal is nil.
	Retarget func(ctx context.Context, running []byte, bootable ...[]byte) error
}

// nodeImageUpgrader implements grpc.ImageUpgrader.
type nodeImageUpgrader struct {
	opts imageUpgradeOptions

	// mu serializes Stage, Rollback and Activate (#373): all three choreograph
	// the same ESP slots (BOOTX64.NEW.EFI is shared write scratch), so two of
	// them in flight at once could corrupt a slot rather than merely race for
	// it. TryLock rather than Lock: a caller made while another is already
	// running is refused outright (FailedPrecondition), not queued behind it.
	mu sync.Mutex
}

func newImageUpgrader(opts imageUpgradeOptions) (*nodeImageUpgrader, error) {
	if opts.CACN == nil {
		return nil, errors.New("init: image upgrade: a CA CN lookup is required")
	}
	if opts.Mount == nil {
		return nil, errors.New("init: image upgrade: a mounter is required")
	}
	if opts.Reboot == nil {
		return nil, errors.New("init: image upgrade: a reboot function is required")
	}
	if opts.Release == nil {
		return nil, errors.New("init: image upgrade: a release certificate is required")
	}

	return &nodeImageUpgrader{opts: opts}, nil
}

// Stage verifies the image and installs it as the one the firmware will boot,
// retaining the current image. It does not reboot.
func (u *nodeImageUpgrader) Stage(ctx context.Context, image, signature []byte) (*nodev1.ImageStatus, error) {
	if !u.mu.TryLock() {
		return nil, cgrpc.ErrUpgradeInProgress
	}
	defer u.mu.Unlock()

	// Verified before the ESP is mounted at all, let alone writable. An image
	// the node cannot attribute never gets near the boot partition of a
	// production CA, and the stager verifies again on its own behalf -- cheap
	// next to the upload, and it keeps that guarantee a property of the stager
	// rather than of this caller remembering to check.
	if err := imageupgrade.Verify(image, signature, u.opts.Release); err != nil {
		return nil, fmt.Errorf("%w: %w", cgrpc.ErrImageNotVerified, err)
	}

	var st imageupgrade.Status
	err := u.opts.Mount(true, func(root string) error {
		stager, newErr := imageupgrade.New(dirFS{root: root}, u.opts.Release)
		if newErr != nil {
			return newErr
		}
		if u.opts.Reseal != nil {
			// Before the stager touches a slot: if the key cannot follow the
			// image, the ESP is left exactly as it was.
			if resealErr := u.reseal(ctx, dirFS{root: root}, image); resealErr != nil {
				return resealErr
			}
		}
		var stageErr error
		st, stageErr = stager.Stage(image, signature)

		return stageErr
	})
	if err != nil {
		return nil, fmt.Errorf("init: stage image: %w", err)
	}

	return u.imageStatus(st), nil
}

// reseal covers the images that will be bootable once image is staged: image
// itself and the current active image, which the stager retains as the
// previous one. The running image is covered too, since it is what boots if
// the node restarts before anything else changes.
//
// The running image is read back from the ESP by digest rather than trusted
// from memory: it is the one whose prediction is checked against the TPM, so
// it has to be the exact bytes the firmware loaded.
func (u *nodeImageUpgrader) reseal(ctx context.Context, esp dirFS, image []byte) error {
	var running, active []byte
	for _, rel := range []string{imageupgrade.ActiveRelPath, imageupgrade.PreviousRelPath} {
		data, err := esp.ReadFile(rel)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read %s: %w", rel, err)
		}
		if rel == imageupgrade.ActiveRelPath {
			active = data
		}
		if running == nil && imageDigest(data) == u.opts.Running {
			running = data
		}
	}
	if running == nil {
		// Only reachable after staging twice without a reboot, which rotates
		// the running image off the ESP.
		return fmt.Errorf("%w: the running image is no longer on the ESP; reboot into the staged image or roll back first", errResealRefused)
	}

	bootable := [][]byte{image}
	if active != nil {
		bootable = append(bootable, active)
	}
	if err := u.opts.Reseal(ctx, running, bootable...); err != nil {
		return fmt.Errorf("reseal the state key: %w", err)
	}

	return nil
}

// Rollback puts the retained image back on the boot path. It does not reboot.
//
// On a TPM node it then drops the state key copy for every image the ESP can
// no longer boot, the one rolled back from included. That runs after the ESP write, so a
// rollback that could not be completed never costs the node a token it still
// boots with, and a prune that fails does not undo the rollback: the header
// keeps its old tokens, the rollback target among them, until the next stage.
func (u *nodeImageUpgrader) Rollback(ctx context.Context) (*nodev1.ImageStatus, error) {
	if !u.mu.TryLock() {
		return nil, cgrpc.ErrUpgradeInProgress
	}
	defer u.mu.Unlock()

	var st imageupgrade.Status
	err := u.opts.Mount(true, func(root string) error {
		esp := dirFS{root: root}
		stager, newErr := imageupgrade.New(esp, u.opts.Release)
		if newErr != nil {
			return newErr
		}
		// Read before the rollback overwrites the active slot, which is where
		// the running image is once the node has booted a staged one.
		var running []byte
		if u.opts.Retarget != nil {
			var readErr error
			if running, readErr = u.runningFromESP(esp); readErr != nil {
				return readErr
			}
		}
		if rbErr := stager.Rollback(); rbErr != nil {
			return rbErr
		}
		if u.opts.Retarget != nil {
			u.pruneAfterRollback(ctx, esp, running)
		}
		var statusErr error
		st, statusErr = stager.Status()

		return statusErr
	})
	if err != nil {
		if errors.Is(err, imageupgrade.ErrNoPrevious) {
			// Translated to this package's sentinel so the handler can answer
			// FailedPrecondition without importing the implementation.
			return nil, cgrpc.ErrNoPreviousImage
		}

		return nil, fmt.Errorf("init: roll back image: %w", err)
	}

	return u.imageStatus(st), nil
}

// runningFromESP returns the running image's bytes from the active or the
// previous slot, or nil when neither holds it.
func (u *nodeImageUpgrader) runningFromESP(esp dirFS) ([]byte, error) {
	for _, rel := range []string{imageupgrade.ActiveRelPath, imageupgrade.PreviousRelPath} {
		data, err := esp.ReadFile(rel)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", rel, err)
		}
		if imageDigest(data) == u.opts.Running {
			return data, nil
		}
	}

	return nil, nil
}

// pruneAfterRollback leaves the state key unsealable only by the image the
// ESP now boots. Failures are logged, not returned: the rollback has already
// happened, and every token the header had, the target's included, is still
// there.
func (u *nodeImageUpgrader) pruneAfterRollback(ctx context.Context, esp dirFS, running []byte) {
	if running == nil {
		// After two stages without a reboot, or a second rollback in a row.
		// Retarget then keeps the target's existing token and seals nothing.
		log.Printf("image rollback: the running image is no longer on the ESP; keeping only the rollback target's existing token")
	}
	target, err := esp.ReadFile(imageupgrade.ActiveRelPath)
	if err != nil {
		log.Printf("image rollback: warn: state key prune skipped: read the rollback target: %v", err)
		return
	}
	if err := u.opts.Retarget(ctx, running, target); err != nil {
		log.Printf("image rollback: warn: state key prune failed, stale tokens stay until the next stage: %v", err)
		return
	}
	log.Printf("image rollback: state key now unseals only for image %s", shortDigest(imageDigest(target)))
}

// Activate reboots the node so a staged image starts running.
//
// The confirmation is checked with reset.CheckConfirm, as the resetter checks
// its own, against the CA CN looked up now: fail closed on an empty CA CN
// (reset.ErrNoCAIdentity) or an empty or different confirmation
// (reset.ErrConfirmMismatch), with a constant-time compare.
//
// It also refuses when nothing is staged. Rebooting an issuing CA takes every
// dependent system's certificate operations down with it, and doing that to
// boot the same image the node is already running is an outage with nothing to
// show for it -- far more likely a mistake than an intention.
func (u *nodeImageUpgrader) Activate(ctx context.Context, confirmCommonName string) error {
	if !u.mu.TryLock() {
		return cgrpc.ErrUpgradeInProgress
	}
	defer u.mu.Unlock()

	if err := reset.CheckConfirm(u.opts.CACN(), confirmCommonName); err != nil {
		return err
	}

	st, err := u.Status(ctx)
	if err != nil {
		return err
	}
	if !st.GetRebootPending() {
		return errors.New("init: activate image: no staged image; the node is already running what it would boot")
	}

	u.opts.Reboot()

	return nil
}

// Status reports the images on the ESP and the one running.
func (u *nodeImageUpgrader) Status(_ context.Context) (*nodev1.ImageStatus, error) {
	var st imageupgrade.Status
	err := u.opts.Mount(false, func(root string) error {
		stager, newErr := imageupgrade.New(dirFS{root: root}, u.opts.Release)
		if newErr != nil {
			return newErr
		}
		var statusErr error
		st, statusErr = stager.Status()

		return statusErr
	})
	if err != nil {
		return nil, fmt.Errorf("init: read image status: %w", err)
	}

	return u.imageStatus(st), nil
}

func (u *nodeImageUpgrader) imageStatus(st imageupgrade.Status) *nodev1.ImageStatus {
	return &nodev1.ImageStatus{
		ActiveSha256:   st.ActiveDigest,
		PreviousSha256: st.PreviousDigest,
		RebootPending:  st.ActiveDigest != u.opts.Running,
		RunningSha256:  u.opts.Running,
		RunningVersion: u.opts.Version,
	}
}

// dirFS is imageupgrade.FS over a mounted ESP.
//
// Durability comes from the unmount the mounter performs when the operation
// finishes, which is the real barrier on vfat; the per-file Sync here just
// narrows the window if the node loses power mid-upgrade.
type dirFS struct {
	root string
}

func (d dirFS) path(rel string) string { return filepath.Join(d.root, filepath.FromSlash(rel)) }

func (d dirFS) Exists(rel string) (bool, error) {
	_, err := os.Stat(d.path(rel))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return true, nil
}

func (d dirFS) ReadFile(rel string) ([]byte, error) { return os.ReadFile(d.path(rel)) }

func (d dirFS) Remove(rel string) error { return os.Remove(d.path(rel)) }

func (d dirFS) Rename(from, to string) error { return os.Rename(d.path(from), d.path(to)) }

func (d dirFS) WriteFile(rel string, data []byte) error {
	full := d.path(rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(full, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()

		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()

		return err
	}

	return f.Close()
}

// Sync fsyncs the ESP root directory, the barrier a vfat rename needs: the
// rename that swaps the active image updates a directory entry, which a
// file's own fsync (WriteFile, above) does not cover.
func (d dirFS) Sync() error {
	f, err := os.Open(d.root)
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()

		return err
	}

	return f.Close()
}

// digestFile returns the SHA-256 (hex) of rel under a mounted ESP, or an empty
// string when it is not there. It is how a booting node learns which image it
// is running: at startup the file on the boot path is, by definition, the one
// the firmware just booted.
func digestFile(mount espMounter, rel string) (string, error) {
	var out string
	err := mount(false, func(root string) error {
		data, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if errors.Is(readErr, fs.ErrNotExist) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
		sum := sha256.Sum256(data)
		out = hex.EncodeToString(sum[:])

		return nil
	})

	return out, err
}
