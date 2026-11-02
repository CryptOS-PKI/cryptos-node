//go:build linux

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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLocateBootUKI_ResolvesESPLabel verifies that locateBootUKIIn finds the
// partition with GPT label "EFI" via the sysfs scan. The mount syscall is
// integration-level and is not exercised here; the test confirms only that the
// device resolution seam (resolveStateDeviceIn) is wired correctly for the
// boot-ESP label.
func TestLocateBootUKI_ResolvesESPLabel(t *testing.T) {
	root := t.TempDir()
	// Lay down a fake sysfs tree: decoy partition + the boot ESP.
	writeUevent(t, root, "sda1", "MAJOR=8\nMINOR=1\nDEVNAME=sda1\nDEVTYPE=partition\nPARTNAME=cryptos-state\n")
	writeUevent(t, root, "sda2", "MAJOR=8\nMINOR=2\nDEVNAME=sda2\nDEVTYPE=partition\nPARTNAME=EFI\n")

	// locateBootUKIIn will resolve sda2, then attempt a real mount — which
	// will fail in the test environment. We confirm it got past the
	// resolution step (the error is about mount, not "no partition named").
	_, err := locateBootUKIIn(root, "")
	if err == nil {
		// Unexpectedly succeeded — only possible if /dev/sda2 exists and is
		// a mountable vfat device, which is not the case in CI.
		t.Fatal("expected an error from mount in test environment, got nil")
	}
	if strings.Contains(err.Error(), "no partition named") {
		t.Errorf("device resolution failed; expected mount-level error, got: %v", err)
	}
}

// TestLocateBootUKI_NotFound verifies that locateBootUKIIn returns an error
// when no partition with GPT label "EFI" is present and no CD-ROM device
// exists either.
func TestLocateBootUKI_NotFound(t *testing.T) {
	root := t.TempDir()
	writeUevent(t, root, "sda1", "DEVNAME=sda1\nPARTNAME=cryptos-state\n")

	_, err := locateBootUKIIn(root, "")
	if err == nil {
		t.Fatal("expected error when no EFI partition and no CD-ROM present, got nil")
	}
	// Should reach the CD-ROM fallback path and fail there.
	if strings.Contains(err.Error(), "no partition named") && !strings.Contains(err.Error(), "no sr*") {
		t.Errorf("unexpected error (expected CD-ROM fallback error): %v", err)
	}
}

// TestLocateBootUKI_CDROMFallback verifies that when no EFI GPT partition is
// present but an sr* CD-ROM block device exists in sysfs, locateBootUKIIn
// selects the CD-ROM device and attempts a mount (which will fail in the test
// environment, but with an iso9660 mount error rather than "no partition named"
// or "no sr*").
func TestLocateBootUKI_CDROMFallback(t *testing.T) {
	root := t.TempDir()
	// Only a data partition — no EFI label — and a CD-ROM device.
	writeUevent(t, root, "sda1", "MAJOR=8\nMINOR=1\nDEVNAME=sda1\nDEVTYPE=partition\nPARTNAME=cryptos-state\n")
	// sr0 is a directory entry in /sys/class/block; no uevent needed for the
	// device-name scan (CD-ROM discovery only uses ReadDir names).
	if err := writeSysfsDir(t, root, "sr0"); err != nil {
		t.Fatalf("setup: %v", err)
	}

	_, err := locateBootUKIIn(root, "")
	if err == nil {
		// Only possible if /dev/sr0 is a real mountable ISO — not expected in CI.
		t.Fatal("expected an error from iso9660 mount in test environment, got nil")
	}
	// Must NOT be "no partition named" (resolution succeeded) and must NOT be
	// "no sr*" (device discovery succeeded).
	if strings.Contains(err.Error(), "no partition named") {
		t.Errorf("EFI resolution error leaked; expected CD-ROM mount error: %v", err)
	}
	if strings.Contains(err.Error(), "no sr* CD-ROM block device") {
		t.Errorf("CD-ROM device not found; sr0 entry should have been discovered: %v", err)
	}
	// Expect the error to mention sr0.
	if !strings.Contains(err.Error(), "sr0") {
		t.Errorf("expected error to reference sr0 CD device, got: %v", err)
	}
}

// writeSysfsDir creates an empty directory at root/name to simulate a sysfs
// block device entry (CD-ROM discovery only needs the directory to exist).
func writeSysfsDir(t *testing.T, root, name string) error {
	t.Helper()
	return os.MkdirAll(filepath.Join(root, name), 0o755)
}
