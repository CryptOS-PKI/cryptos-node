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
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// bootESPLabel is the GPT partition name of the ISO/boot-media ESP.
const bootESPLabel = "EFI"

// bootUKIRelPath is the UEFI removable-media fallback path under the ESP
// where the signed UKI lives on the boot media.
const bootUKIRelPath = "EFI/BOOT/BOOTX64.EFI"

// bootUKIISOName is the fixed filename placed at the root of the ISO9660
// volume when building the ISO. It is read when the ISO is booted as a CD or
// from a USB stick written from the ISO.
const bootUKIISOName = "cryptos.uki"

// Filesystem types a boot-media candidate is mounted as.
const (
	fsVFAT    = "vfat"
	fsISO9660 = "iso9660"
)

// Where a boot-media candidate came from, for logs and errors.
const (
	sourceESP                = "EFI partition"
	sourceCDROM              = "CD-ROM"
	sourceRemovableDisk      = "removable disk"
	sourceRemovablePartition = "removable disk partition"
)

// srDevPattern matches SCSI CD-ROM block device names (sr0, sr1, …).
var srDevPattern = regexp.MustCompile(`^sr[0-9]+$`)

// partSuffixPattern matches what the kernel appends to a disk name to name
// its partitions: sda1, or nvme0n1p1 and mmcblk0p1 when the disk name ends
// in a digit.
var partSuffixPattern = regexp.MustCompile(`^p?[0-9]+$`)

// notBootMediaPrefixes are block devices that are never boot media in the
// removable-disk pass: loopback, RAM/zram, device-mapper, md, network block
// devices, and the optical/floppy drives the CD-ROM pass handles.
var notBootMediaPrefixes = []string{"loop", "ram", "zram", "dm-", "md", "nbd", "sr", "fd"}

// bootMediaCandidate is one place the booted UKI may be: a block device,
// the filesystem to mount it as, and the file to read from its root.
type bootMediaCandidate struct {
	Dev    string
	FSType string
	File   string
	Source string
}

// blockDev is one /sys/class/block entry as the planner sees it.
type blockDev struct {
	name     string
	isPart   bool
	partName string
	// parent is the whole disk a partition belongs to ("" when unknown).
	parent    string
	removable bool
	usb       bool
}

// planBootMedia lists, in the order to try them, every block device that
// may hold the booted UKI, read from the sysfs block class at root:
//
//  1. Partitions with the GPT name "EFI", mounted vfat for
//     EFI/BOOT/BOOTX64.EFI (boot media carrying a CryptOS ESP).
//  2. sr* CD-ROM drives, mounted iso9660 for /cryptos.uki (the ISO booted as
//     a CD, physical or virtual).
//  3. Removable or USB-attached whole disks, mounted iso9660 for
//     /cryptos.uki (a USB stick written from the hybrid ISO: the whole
//     device is the ISO 9660 volume), then each of their partitions mounted
//     vfat for EFI/BOOT/BOOTX64.EFI (the El Torito EFI image, which xorriso
//     also exposes as a partition).
//
// targetDisk, the disk the installer is about to repartition, and every
// partition on it are left out of every pass, so the UKI is never read from
// the disk being overwritten. A device is listed at most once per
// filesystem type.
func planBootMedia(root, targetDisk string) ([]bootMediaCandidate, error) {
	devs, err := readBlockDevs(root)
	if err != nil {
		return nil, err
	}
	byName := make(map[string]blockDev, len(devs))
	for _, d := range devs {
		byName[d.name] = d
	}

	target := ""
	if targetDisk != "" {
		target = strings.TrimPrefix(filepath.Clean(targetDisk), "/dev/")
	}
	if t, ok := byName[target]; ok && t.isPart && t.parent != "" {
		target = t.parent
	}
	onTarget := func(d blockDev) bool {
		return target != "" && (d.name == target || d.parent == target)
	}

	var plan []bootMediaCandidate
	planned := map[string]bool{}
	add := func(d blockDev, fsType, file, source string) {
		key := d.name + "|" + fsType
		if planned[key] {
			return
		}
		planned[key] = true
		plan = append(plan, bootMediaCandidate{Dev: "/dev/" + d.name, FSType: fsType, File: file, Source: source})
	}

	for _, d := range devs {
		if !d.isPart || d.partName != bootESPLabel {
			continue
		}
		if onTarget(d) {
			log.Printf("boot media: skipping %s: an EFI partition on the install target %s", d.name, targetDisk)
			continue
		}
		add(d, fsVFAT, bootUKIRelPath, sourceESP)
	}

	for _, d := range devs {
		if !srDevPattern.MatchString(d.name) {
			continue
		}
		if onTarget(d) {
			log.Printf("boot media: skipping CD-ROM %s: it is the install target", d.name)
			continue
		}
		add(d, fsISO9660, bootUKIISOName, sourceCDROM)
	}

	for _, d := range devs {
		if d.isPart || hasAnyPrefix(d.name, notBootMediaPrefixes) || (!d.removable && !d.usb) {
			continue
		}
		if onTarget(d) {
			log.Printf("boot media: skipping removable disk %s: it is the install target", d.name)
			continue
		}
		add(d, fsISO9660, bootUKIISOName, sourceRemovableDisk)
		for _, p := range devs {
			if p.isPart && p.parent == d.name {
				add(p, fsVFAT, bootUKIRelPath, sourceRemovablePartition)
			}
		}
	}

	log.Printf("boot media: %d candidate(s) with install target %q excluded", len(plan), targetDisk)
	for i, c := range plan {
		log.Printf("boot media: candidate %d: %s (%s) as %s for %s", i+1, c.Dev, c.Source, c.FSType, c.File)
	}
	return plan, nil
}

// readBlockDevs reads every entry of the sysfs block class at root, in
// directory order. Partitions are matched to their whole disk through the
// kernel's layout (a partition's directory sits inside its disk's), falling
// back to the kernel's naming (sda1, nvme0n1p1) when the layout doesn't say.
func readBlockDevs(root string) ([]blockDev, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", root, err)
	}
	devs := make([]blockDev, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		dir := filepath.Join(root, name)
		d := blockDev{name: name}
		fields, err := parseUevent(filepath.Join(dir, "uevent"))
		if err == nil {
			d.isPart = fields["DEVTYPE"] == "partition"
			d.partName = fields["PARTNAME"]
		}
		if _, err := os.Stat(filepath.Join(dir, "partition")); err == nil {
			d.isPart = true
		}
		if !d.isPart {
			d.removable = readSysfsTrimmed(filepath.Join(dir, "removable")) == "1"
			if real, err := filepath.EvalSymlinks(dir); err == nil {
				d.usb = strings.Contains(real, "/usb")
			}
		}
		devs = append(devs, d)
	}
	for i := range devs {
		if !devs[i].isPart {
			continue
		}
		devs[i].parent = parentDisk(root, devs[i].name, devs)
	}
	return devs, nil
}

// parentDisk returns the whole disk that partition part belongs to, or ""
// when no listed disk owns it.
func parentDisk(root, part string, devs []blockDev) string {
	for _, d := range devs {
		if d.isPart {
			continue
		}
		if fi, err := os.Stat(filepath.Join(root, d.name, part)); err == nil && fi.IsDir() {
			return d.name
		}
	}
	for _, d := range devs {
		if d.isPart || !strings.HasPrefix(part, d.name) {
			continue
		}
		if partSuffixPattern.MatchString(strings.TrimPrefix(part, d.name)) {
			return d.name
		}
	}
	return ""
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// readSysfsTrimmed reads a sysfs attribute, trimmed; "" when it can't be read.
func readSysfsTrimmed(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
