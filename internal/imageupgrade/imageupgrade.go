package imageupgrade

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

// Package imageupgrade replaces the node's UKI without touching its identity
// (#208).
//
// Until now the only way to put a new CryptOS build on a node was to
// re-provision it, which reformats the state partition and destroys the CA key
// with it. That made every OS change an irreversible ceremony, and it is what
// blocks putting RSA CA support onto an already-established node.
//
// The disk layout already separates the two concerns. internal/install lays out
// an EFI System Partition plus a cryptos-state partition, and the root
// filesystem is an immutable SquashFS carried inside the UKI on the ESP. So an
// upgrade is: write a new UKI to the ESP and reboot. The LUKS state partition --
// CA key, etcd, identity, issued history -- is never opened.
//
// # Two independent checks, neither pretending to be the other
//
// The firmware is the authority on whether an image may boot: it verifies the
// UKI's Authenticode signature against the Secure Boot db certificate enrolled
// on that machine. Nothing here can weaken or substitute for that.
//
// This package performs a second, earlier check: a detached release signature
// over the image bytes, verified against a release certificate the running
// image already carries. Its purpose is to refuse to *write* an image we cannot
// attribute, rather than to decide bootability. Without it, an admin-authorized
// call could park an unverifiable image on the ESP; the firmware would refuse to
// boot it and the node would need physical recovery, which is a denial of
// service dressed as an upgrade.
//
// A pure-Go Authenticode verifier is deliberately not attempted. sbverify is a
// build-host tool and is not in the rootfs, and a hand-rolled PE signature
// parser in the trusted path of a CA is a poor trade against a detached
// signature that is a dozen lines of standard library.
//
// # Slot layout
//
// The firmware boots the removable-media fallback path, with no NVRAM boot
// entry (see internal/install), so activation is a rename rather than an
// efibootmgr call:
//
//	EFI/BOOT/BOOTX64.EFI       the image the firmware boots
//	EFI/BOOT/BOOTX64.PREV.EFI  the previous image, kept bootable for recovery
//	EFI/BOOT/BOOTX64.NEW.EFI   the incoming image, mid-write
//
// The previous image is retained on purpose: the thing being upgraded is the
// node's only management surface, so an upgrade that boots to nothing must be
// recoverable without a site visit.

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
)

// Paths on the mounted ESP, relative to its root.
const (
	ActiveRelPath   = "EFI/BOOT/BOOTX64.EFI"
	PreviousRelPath = "EFI/BOOT/BOOTX64.PREV.EFI"
	incomingRelPath = "EFI/BOOT/BOOTX64.NEW.EFI"
)

// ErrNoPrevious is returned by Rollback when no previous image was retained,
// which is the case on a node that has never been upgraded.
var ErrNoPrevious = errors.New("imageupgrade: no previous image to roll back to")

// FS is the mounted ESP. It is an interface so the slot choreography is
// testable without a disk, the same reason internal/install injects its
// mount and exec dependencies.
//
// WriteFile must durably persist before returning: an upgrade interrupted by
// the reboot it triggers must not leave a half-written image in a slot the
// firmware will try.
type FS interface {
	Exists(rel string) (bool, error)
	ReadFile(rel string) ([]byte, error)
	Remove(rel string) error
	Rename(from, to string) error
	WriteFile(rel string, data []byte) error
	// Sync fsyncs the ESP's mounted directory. A vfat rename is only a
	// directory-entry update; WriteFile's own fsync covers a file's data, not
	// that entry. Without this, a power loss right after the rename that swaps
	// the active image can leave the directory entry unresolved -- neither
	// surely the old image nor surely the new one -- rather than one of the
	// two, which is what every caller of Stage and Rollback relies on.
	Sync() error
}

// Stager installs verified images into the ESP slots.
type Stager struct {
	fs FS
	// release is the certificate an incoming image must be signed by. It comes
	// from the running image rather than from configuration: configuration is
	// writable by the same caller who would be installing the image, so trusting
	// it would make the check circular.
	release *x509.Certificate
}

// New returns a Stager. A nil release certificate is refused rather than
// treated as "verification off" -- a build that forgot to embed one must fail
// loudly at the first upgrade attempt, not silently accept anything.
func New(fs FS, release *x509.Certificate) (*Stager, error) {
	if fs == nil {
		return nil, errors.New("imageupgrade: New: fs is required")
	}
	if release == nil {
		return nil, errors.New("imageupgrade: New: a release certificate is required")
	}

	return &Stager{fs: fs, release: release}, nil
}

// Verify checks a detached release signature over image: PKCS#1 v1.5 over a
// SHA-256 digest.
//
// PKCS#1 v1.5 rather than PSS because the release key lives on a hardware
// token, and v1.5 is the signing mode every token supports -- the same reason
// UEFI itself specifies it.
func Verify(image, signature []byte, release *x509.Certificate) error {
	if release == nil {
		return errors.New("imageupgrade: Verify: a release certificate is required")
	}
	if len(image) == 0 {
		return errors.New("imageupgrade: Verify: empty image")
	}
	if len(signature) == 0 {
		return errors.New("imageupgrade: Verify: empty signature")
	}

	pub, ok := release.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("imageupgrade: Verify: release key is %T, want RSA", release.PublicKey)
	}

	sum := sha256.Sum256(image)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], signature); err != nil {
		return fmt.Errorf("imageupgrade: Verify: the image is not signed by the release key: %w", err)
	}

	return nil
}

// Status describes what is on the ESP.
type Status struct {
	// ActiveDigest is the SHA-256 of the image the firmware will boot.
	ActiveDigest string
	// PreviousDigest is the retained image, empty when there is none.
	PreviousDigest string
}

// Stage verifies the image and makes it the one the firmware boots, retaining
// the current image for rollback. It does not reboot; activation takes effect
// on the next boot, which leaves the decision of when to that caller.
//
// The order is chosen so the live path is never absent: the incoming image is
// written and the current one copied aside first, and only then is the active
// path replaced by a single rename.
func (s *Stager) Stage(image, signature []byte) (Status, error) {
	if err := Verify(image, signature, s.release); err != nil {
		// Nothing has been written at this point, deliberately. An image that
		// cannot be attributed never reaches the disk.
		return Status{}, err
	}

	if err := s.fs.WriteFile(incomingRelPath, image); err != nil {
		return Status{}, fmt.Errorf("imageupgrade: write the incoming image: %w", err)
	}

	// Retain the current image by copy rather than rename, so the active path
	// stays populated until the final atomic replace.
	current, readErr := s.fs.ReadFile(ActiveRelPath)
	if readErr == nil {
		if err := s.fs.WriteFile(PreviousRelPath, current); err != nil {
			return Status{}, fmt.Errorf("imageupgrade: retain the current image: %w", err)
		}
	} else {
		// A node with no active image is being repaired rather than upgraded;
		// there is simply nothing to retain. Any other read failure is real.
		exists, existsErr := s.fs.Exists(ActiveRelPath)
		if existsErr != nil || exists {
			return Status{}, fmt.Errorf("imageupgrade: read the current image: %w", readErr)
		}
	}

	if err := s.fs.Rename(incomingRelPath, ActiveRelPath); err != nil {
		return Status{}, fmt.Errorf("imageupgrade: activate the incoming image: %w", err)
	}
	if err := s.fs.Sync(); err != nil {
		return Status{}, fmt.Errorf("imageupgrade: sync the ESP directory: %w", err)
	}

	return s.Status()
}

// Rollback puts the retained image back, for an upgrade that booted to
// nothing useful. The caller still has to reboot.
func (s *Stager) Rollback() error {
	exists, err := s.fs.Exists(PreviousRelPath)
	if err != nil {
		return fmt.Errorf("imageupgrade: look for a previous image: %w", err)
	}
	if !exists {
		return ErrNoPrevious
	}

	previous, err := s.fs.ReadFile(PreviousRelPath)
	if err != nil {
		return fmt.Errorf("imageupgrade: read the previous image: %w", err)
	}
	if err := s.fs.WriteFile(incomingRelPath, previous); err != nil {
		return fmt.Errorf("imageupgrade: stage the previous image: %w", err)
	}
	if err := s.fs.Rename(incomingRelPath, ActiveRelPath); err != nil {
		return fmt.Errorf("imageupgrade: restore the previous image: %w", err)
	}
	if err := s.fs.Sync(); err != nil {
		return fmt.Errorf("imageupgrade: sync the ESP directory: %w", err)
	}

	return nil
}

// Status reports the digests of what is installed, so an operator can tell
// whether an upgrade actually took.
func (s *Stager) Status() (Status, error) {
	active, err := s.digestOf(ActiveRelPath)
	if err != nil {
		return Status{}, err
	}
	previous, err := s.digestOf(PreviousRelPath)
	if err != nil {
		return Status{}, err
	}

	return Status{ActiveDigest: active, PreviousDigest: previous}, nil
}

func (s *Stager) digestOf(rel string) (string, error) {
	exists, err := s.fs.Exists(rel)
	if err != nil {
		return "", fmt.Errorf("imageupgrade: stat %s: %w", rel, err)
	}
	if !exists {
		return "", nil
	}

	data, err := s.fs.ReadFile(rel)
	if err != nil {
		return "", fmt.Errorf("imageupgrade: read %s: %w", rel, err)
	}
	sum := sha256.Sum256(data)

	return hex.EncodeToString(sum[:]), nil
}
