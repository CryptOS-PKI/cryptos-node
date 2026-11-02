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
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// LocateBootUKI finds the booted UKI on the boot media, never on targetDisk
// (the disk the installer is about to repartition). It tries the devices
// planBootMedia lists, in order: a GPT partition named "EFI", an sr* CD-ROM,
// then a removable or USB-attached disk written from the ISO (the whole disk
// as ISO 9660, then its partitions as FAT). The first device that mounts and
// carries the UKI wins.
//
// The caller owns the returned path for the lifetime of the mount; the
// mount is left in place so the caller can copy or read the UKI. Cleanup
// (umount + rmdir) is the caller's responsibility.
func LocateBootUKI(targetDisk string) (string, error) {
	return locateBootUKIIn("/sys/class/block", targetDisk)
}

// locateBootUKIIn is LocateBootUKI with an explicit sysfs root so device
// discovery can be unit-tested without touching the real filesystem.
func locateBootUKIIn(sysfsRoot, targetDisk string) (string, error) {
	start := time.Now()
	target := targetDisk
	if targetDisk != "" {
		if real, err := filepath.EvalSymlinks(targetDisk); err == nil {
			target = real
		}
	}
	log.Printf("boot media: locating the boot UKI (install target %s)", target)

	plan, err := planBootMedia(sysfsRoot, target)
	if err != nil {
		return "", fmt.Errorf("init: locateBootUKI: %w", err)
	}
	if len(plan) == 0 {
		return "", fmt.Errorf("init: locateBootUKI: no EFI partition, no CD-ROM and no removable disk found apart from the install target %s", target)
	}

	var errs []error
	for _, c := range plan {
		var path string
		switch c.FSType {
		case fsVFAT:
			path, err = mountAndVerifyVFAT(c.Dev, c.File)
		default:
			path, err = mountAndVerifyISO(c.Dev, c.File)
		}
		if err == nil {
			log.Printf("boot media: found the boot UKI on %s (%s) at %s in %s", c.Dev, c.Source, path, time.Since(start).Round(time.Millisecond))
			return path, nil
		}
		log.Printf("boot media: %s (%s) has no boot UKI: %v", c.Dev, c.Source, err)
		errs = append(errs, err)
	}
	return "", fmt.Errorf("init: locateBootUKI: no boot UKI on any boot media: %w", errors.Join(errs...))
}

// mountAndVerifyVFAT mounts dev as vfat read-only at a temp dir, checks that
// relPath exists, and returns the absolute path.
func mountAndVerifyVFAT(dev, relPath string) (string, error) {
	tmp, err := os.MkdirTemp("", "cryptos-boot-esp-*")
	if err != nil {
		return "", fmt.Errorf("init: locateBootUKI: mktemp: %w", err)
	}

	// MS_RDONLY = 1
	if err := unix.Mount(dev, tmp, "vfat", 1, ""); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("init: locateBootUKI: mount %s: %w", dev, err)
	}

	ukiPath := filepath.Join(tmp, relPath)
	if _, err := os.Stat(ukiPath); err != nil {
		_ = unix.Unmount(tmp, 0)
		_ = os.Remove(tmp)
		return "", fmt.Errorf("init: locateBootUKI: UKI not found at %s: %w", ukiPath, err)
	}
	return ukiPath, nil
}

// mountAndVerifyISO mounts dev as iso9660 read-only at a temp dir, checks that
// fileName exists at the mount root, and returns the absolute path.
func mountAndVerifyISO(dev, fileName string) (string, error) {
	tmp, err := os.MkdirTemp("", "cryptos-boot-cdrom-*")
	if err != nil {
		return "", fmt.Errorf("init: locateBootUKI: mktemp: %w", err)
	}

	// MS_RDONLY = 1
	if err := unix.Mount(dev, tmp, "iso9660", 1, ""); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("init: locateBootUKI: mount iso9660 %s: %w", dev, err)
	}

	ukiPath := filepath.Join(tmp, fileName)
	if _, err := os.Stat(ukiPath); err != nil {
		_ = unix.Unmount(tmp, 0)
		_ = os.Remove(tmp)
		return "", fmt.Errorf("init: locateBootUKI: %s not found on %s: %w", fileName, dev, err)
	}
	return ukiPath, nil
}
