//go:build e2ecover

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

// This file is compiled only into the coverage-instrumented test image that
// the full-image suite boots (cryptos-appliance's test/image/build.sh sets
// -tags=e2ecover together with -cover). No release or CI image build sets the
// tag.
//
// PID 1 never exits, so Go never writes its coverage counters on its own. The
// suite attaches a small FAT disk with the virtio serial coverSerial; this
// mounts it and rewrites the counters there every few seconds, so whatever
// the node ran up to its last flush survives a reboot, a power-off or the
// harness killing the VM. The harness reads the disk after QEMU exits.

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime/coverage"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	coverSerial   = "cryptos-cover"
	coverMount    = "/run/cryptos-cover"
	coverStaging  = "/run/cryptos-cover-staging"
	coverInterval = 2 * time.Second
)

func init() {
	go flushCoverage()
}

func flushCoverage() {
	var dir string
	for dir == "" {
		time.Sleep(time.Second)
		dir = mountCoverDisk()
	}
	log.Printf("coverage: writing counters to %s every %s", dir, coverInterval)
	if err := coverage.WriteMetaDir(dir); err != nil {
		log.Printf("coverage: write meta-data: %v (is this binary built with -cover?)", err)
		return
	}
	// Logged once: init logs to /dev/kmsg, which the kernel rate-limits, so a
	// repeating line would crowd out the node's own boot messages.
	var last string
	reported := false
	for {
		name, err := writeCounters(dir)
		if err != nil {
			if !reported {
				log.Printf("coverage: write counters: %v", err)
				reported = true
			}
		} else {
			if last != "" && last != name {
				_ = os.Remove(filepath.Join(dir, last))
			}
			last = name
		}
		time.Sleep(coverInterval)
	}
}

// mountCoverDisk finds the virtio disk carrying coverSerial and mounts it
// synchronously on coverMount. It returns "" until /sys, /dev and /run are up
// and the disk is there.
func mountCoverDisk() string {
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return ""
	}
	for _, e := range entries {
		serial, err := os.ReadFile(filepath.Join("/sys/block", e.Name(), "serial"))
		if err != nil || strings.TrimSpace(string(serial)) != coverSerial {
			continue
		}
		if err := os.MkdirAll(coverMount, 0o700); err != nil {
			return ""
		}
		dev := filepath.Join("/dev", e.Name())
		if err := unix.Mount(dev, coverMount, "vfat", unix.MS_SYNCHRONOUS|unix.MS_NOEXEC|unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
			log.Printf("coverage: mount %s on %s: %v", dev, coverMount, err)
			return ""
		}
		return coverMount
	}
	return ""
}

// writeCounters snapshots the counters into a staging directory on the /run
// tmpfs and copies the new file onto the disk under a temporary name before
// renaming it, so a VM killed mid-copy leaves the previous snapshot whole.
func writeCounters(dir string) (string, error) {
	if err := os.RemoveAll(coverStaging); err != nil {
		return "", err
	}
	if err := os.MkdirAll(coverStaging, 0o700); err != nil {
		return "", err
	}
	if err := coverage.WriteCountersDir(coverStaging); err != nil {
		return "", err
	}
	files, err := os.ReadDir(coverStaging)
	if err != nil {
		return "", err
	}
	var name string
	for _, f := range files {
		if strings.HasPrefix(f.Name(), "covcounters.") {
			name = f.Name()
		}
	}
	if name == "" {
		return "", os.ErrNotExist
	}
	src, err := os.Open(filepath.Join(coverStaging, name))
	if err != nil {
		return "", err
	}
	defer func() { _ = src.Close() }()
	tmp := filepath.Join(dir, "partial")
	dst, err := os.Create(tmp)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		return "", err
	}
	if err := dst.Sync(); err != nil {
		_ = dst.Close()
		return "", err
	}
	if err := dst.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return "", err
	}
	return name, nil
}
