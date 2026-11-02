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
	"reflect"
	"strings"
	"testing"
)

// fakeBlock is one entry of a fake /sys/class/block listing.
type fakeBlock struct {
	name      string
	parent    string // whole disk a partition belongs to; "" for a whole disk
	partName  string // GPT partition name (PARTNAME)
	removable bool   // the disk's removable attribute
	usb       bool   // the disk sits behind a USB host controller
	flat      bool   // a plain directory, with no device symlink (older fixtures)
}

// buildSysfs lays down a fake sysfs: real device directories under
// devices/, with /sys/class/block style symlinks to them in class/block,
// and each partition nested in its disk's directory as the kernel does.
// It returns the class/block root.
func buildSysfs(t *testing.T, blocks []fakeBlock) string {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "class", "block")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	usbOf := map[string]bool{}
	for _, b := range blocks {
		if b.parent == "" {
			usbOf[b.name] = b.usb
		}
	}
	for _, b := range blocks {
		disk := b.name
		if b.parent != "" {
			disk = b.parent
		}
		bus := filepath.Join("pci0000:00", "0000:00:17.0", "ata1", "host0")
		if usbOf[disk] {
			bus = filepath.Join("pci0000:00", "0000:00:14.0", "usb2", "2-1", "2-1:1.0", "host6")
		}
		devDir := filepath.Join(base, "devices", bus, "block", disk)
		if b.parent != "" {
			devDir = filepath.Join(devDir, b.name)
		}
		if b.flat {
			devDir = filepath.Join(root, b.name)
		}
		if err := os.MkdirAll(devDir, 0o755); err != nil {
			t.Fatal(err)
		}
		uevent := "DEVNAME=" + b.name + "\n"
		if b.parent != "" {
			uevent += "DEVTYPE=partition\n"
			if b.partName != "" {
				uevent += "PARTNAME=" + b.partName + "\n"
			}
			writeFile(t, filepath.Join(devDir, "partition"), "1\n")
		} else {
			uevent += "DEVTYPE=disk\n"
			removable := "0\n"
			if b.removable {
				removable = "1\n"
			}
			writeFile(t, filepath.Join(devDir, "removable"), removable)
		}
		writeFile(t, filepath.Join(devDir, "uevent"), uevent)
		if !b.flat {
			if err := os.Symlink(devDir, filepath.Join(root, b.name)); err != nil {
				t.Fatal(err)
			}
		}
	}
	return root
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func isoWhole(dev string) bootMediaCandidate {
	return bootMediaCandidate{Dev: "/dev/" + dev, FSType: fsISO9660, File: bootUKIISOName, Source: sourceRemovableDisk}
}

func espOf(dev, source string) bootMediaCandidate {
	return bootMediaCandidate{Dev: "/dev/" + dev, FSType: fsVFAT, File: bootUKIRelPath, Source: source}
}

func cdrom(dev string) bootMediaCandidate {
	return bootMediaCandidate{Dev: "/dev/" + dev, FSType: fsISO9660, File: bootUKIISOName, Source: sourceCDROM}
}

// usbStick is a stick written from the hybrid ISO with dd: a removable disk
// holding the ISO 9660 volume, with the two partitions xorriso writes for
// -isohybrid-gpt-basdat (neither named EFI).
func usbStick(name string, removable bool) []fakeBlock {
	return []fakeBlock{
		{name: name, removable: removable, usb: true},
		{name: name + "1", parent: name, partName: "ISOHybrid"},
		{name: name + "2", parent: name, partName: "ISOHybrid1"},
	}
}

func TestPlanBootMedia(t *testing.T) {
	internalDisk := []fakeBlock{{name: "sda"}}
	tests := []struct {
		name   string
		blocks []fakeBlock
		target string
		want   []bootMediaCandidate
	}{
		{
			name:   "USB stick written from the ISO",
			blocks: append(append([]fakeBlock{}, internalDisk...), usbStick("sdb", true)...),
			target: "/dev/sda",
			want: []bootMediaCandidate{
				isoWhole("sdb"),
				espOf("sdb1", sourceRemovablePartition),
				espOf("sdb2", sourceRemovablePartition),
			},
		},
		{
			name:   "USB stick that reports itself as fixed",
			blocks: append(append([]fakeBlock{}, internalDisk...), usbStick("sdb", false)...),
			target: "/dev/sda",
			want: []bootMediaCandidate{
				isoWhole("sdb"),
				espOf("sdb1", sourceRemovablePartition),
				espOf("sdb2", sourceRemovablePartition),
			},
		},
		{
			name:   "removable disk not on USB (BMC virtual media)",
			blocks: append(append([]fakeBlock{}, internalDisk...), fakeBlock{name: "sdc", removable: true}),
			target: "/dev/sda",
			want:   []bootMediaCandidate{isoWhole("sdc")},
		},
		{
			name:   "the USB stick is the install target",
			blocks: append(append([]fakeBlock{}, internalDisk...), usbStick("sdb", true)...),
			target: "/dev/sdb",
			want:   nil,
		},
		{
			name: "an old CryptOS ESP on the target is never used",
			blocks: append([]fakeBlock{
				{name: "sda"},
				{name: "sda1", parent: "sda", partName: "EFI"},
				{name: "sda2", parent: "sda", partName: "cryptos-state"},
			}, usbStick("sdb", true)...),
			target: "/dev/sda",
			want: []bootMediaCandidate{
				isoWhole("sdb"),
				espOf("sdb1", sourceRemovablePartition),
				espOf("sdb2", sourceRemovablePartition),
			},
		},
		{
			name: "an old ESP on an NVMe target is never used",
			blocks: []fakeBlock{
				{name: "nvme0n1"},
				{name: "nvme0n1p1", parent: "nvme0n1", partName: "EFI"},
			},
			target: "/dev/nvme0n1",
			want:   nil,
		},
		{
			name: "an EFI partition on another disk comes first, then CD-ROM, then removable media",
			blocks: append([]fakeBlock{
				{name: "sda"},
				{name: "sdc"},
				{name: "sdc1", parent: "sdc", partName: "EFI"},
				{name: "sr0"},
			}, usbStick("sdb", true)...),
			target: "/dev/sda",
			want: []bootMediaCandidate{
				espOf("sdc1", sourceESP),
				cdrom("sr0"),
				isoWhole("sdb"),
				espOf("sdb1", sourceRemovablePartition),
				espOf("sdb2", sourceRemovablePartition),
			},
		},
		{
			name: "every CD-ROM drive is tried",
			blocks: []fakeBlock{
				{name: "sda"},
				{name: "sr0"},
				{name: "sr1"},
			},
			target: "/dev/sda",
			want:   []bootMediaCandidate{cdrom("sr0"), cdrom("sr1")},
		},
		{
			name: "fixed internal disks and virtual devices are not boot media",
			blocks: []fakeBlock{
				{name: "sda"},
				{name: "sdb"},
				{name: "sdb1", parent: "sdb", partName: "data"},
				{name: "loop0", removable: true},
				{name: "zram0"},
				{name: "dm-0"},
			},
			target: "/dev/sda",
			want:   nil,
		},
		{
			name: "flat fixture partitions are matched to their disk by name",
			blocks: []fakeBlock{
				{name: "sda", flat: true},
				{name: "sda1", parent: "sda", partName: "EFI", flat: true},
				{name: "sdb", removable: true, flat: true},
				{name: "sdb1", parent: "sdb", partName: "EFI", flat: true},
			},
			target: "/dev/sda",
			// sdb1 is planned once, as an ESP; the removable-media pass
			// doesn't repeat it.
			want: []bootMediaCandidate{
				espOf("sdb1", sourceESP),
				isoWhole("sdb"),
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := buildSysfs(t, tc.blocks)
			got, err := planBootMedia(root, tc.target)
			if err != nil {
				t.Fatalf("planBootMedia: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("planBootMedia(%q) =\n  %+v\nwant\n  %+v", tc.target, got, tc.want)
			}
			for _, c := range got {
				if dev := strings.TrimPrefix(c.Dev, "/dev/"); dev == strings.TrimPrefix(tc.target, "/dev/") ||
					strings.HasPrefix(dev, strings.TrimPrefix(tc.target, "/dev/")) {
					t.Errorf("candidate %s is on the install target %s", c.Dev, tc.target)
				}
			}
		})
	}
}

func TestPlanBootMedia_UnreadableSysfs(t *testing.T) {
	if _, err := planBootMedia(filepath.Join(t.TempDir(), "missing"), "/dev/sda"); err == nil {
		t.Fatal("planBootMedia on a missing sysfs root: want an error, got nil")
	}
}
