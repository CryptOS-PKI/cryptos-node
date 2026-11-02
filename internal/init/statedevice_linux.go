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
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// resolveStateDevice returns the /dev path of the partition whose GPT name
// matches label, e.g. "cryptos-state" -> "/dev/vda1".
//
// The image has no udev, so /dev/disk/by-partlabel/* symlinks are never
// created. Instead we read what the in-kernel GPT parser (CONFIG_EFI_PARTITION)
// already published: each partition's sysfs uevent carries PARTNAME (the GPT
// partition name) and DEVNAME. devtmpfs has created the matching /dev node.
func resolveStateDevice(label string) (string, error) {
	return resolveStateDeviceIn("/sys/class/block", label)
}

// resolveStateDeviceIn is resolveStateDevice with an explicit sysfs root, so
// the scan can be unit-tested against a fixture tree.
func resolveStateDeviceIn(root, label string) (string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", fmt.Errorf("init: resolveStateDevice: read %s: %w", root, err)
	}
	var seen []string
	for _, e := range entries {
		uevent := filepath.Join(root, e.Name(), "uevent")
		fields, err := parseUevent(uevent)
		if err != nil {
			continue // a device without a readable uevent is simply skipped
		}
		if name := fields["PARTNAME"]; name != "" {
			seen = append(seen, name)
			if name == label {
				dev := fields["DEVNAME"]
				if dev == "" {
					return "", fmt.Errorf("init: resolveStateDevice: partition %q has no DEVNAME in %s", label, uevent)
				}
				return "/dev/" + dev, nil
			}
		}
	}
	return "", fmt.Errorf("init: resolveStateDevice: no partition named %q (saw partitions: %s)",
		label, strings.Join(seen, ", "))
}

// stateDeviceMissing reports whether no partition with the given GPT name is
// present — the maintenance-mode signal (booted from the ISO, nothing installed).
func stateDeviceMissing(label string) bool {
	_, err := resolveStateDevice(label)
	return err != nil
}
