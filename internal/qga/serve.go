package qga

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
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

const (
	// PortName is the virtio-serial port name QEMU hosts give the agent channel.
	PortName = "org.qemu.guest_agent.0"
	// DevLink is where udev links the port. CryptOS has no udev, so findPort
	// falls back to sysfs, but a system that has the link uses it.
	DevLink = "/dev/virtio-ports/" + PortName
	// sysPortsDir lists every virtio-serial port and its name.
	sysPortsDir = "/sys/class/virtio-ports"
	// idleWait is how long the read loop waits after an EOF. A virtio-serial
	// port reads EOF while no host client is connected, and Proxmox connects
	// only while it runs a command.
	idleWait = 200 * time.Millisecond
)

// ErrNoPort means this machine has no guest agent channel: bare metal, a
// hypervisor that is not QEMU/KVM, or a VM with the agent turned off.
var ErrNoPort = errors.New("qga: no " + PortName + " virtio-serial port")

// findPort returns the device for the agent channel: DevLink when it exists,
// else the /dev node of the sysfs port named PortName.
func findPort(exists func(string) bool, sysPorts fs.FS, devDir string) (string, error) {
	if exists(DevLink) {
		return DevLink, nil
	}
	entries, err := fs.ReadDir(sysPorts, ".")
	if err != nil {
		return "", ErrNoPort
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, n := range names {
		b, err := fs.ReadFile(sysPorts, path.Join(n, "name"))
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(b)) == PortName {
			return path.Join(devDir, n), nil
		}
	}

	return "", ErrNoPort
}

// Serve answers requests on port until ctx ends. EOF means no host is
// connected: any partial request is dropped and the loop waits idle before
// reading again. Nothing that arrives on the port stops it.
func Serve(ctx context.Context, port io.ReadWriter, h Host, logf func(format string, args ...any), idle time.Duration) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	s := newSession(h, port, logf)
	buf := make([]byte, 4096)
	connected := false
	for ctx.Err() == nil {
		n, err := port.Read(buf)
		if n > 0 {
			if !connected {
				logf("qga: host connected")
				connected = true
			}
			s.feed(buf[:n])
		}
		if err == nil {
			continue
		}
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, io.EOF) {
			if connected {
				logf("qga: host disconnected")
				connected = false
			}
		} else {
			logf("qga: read: %v", err)
			connected = false
		}
		s.reset()
		select {
		case <-ctx.Done():
			return
		case <-time.After(idle):
		}
	}
}

// Start looks for the agent channel and, when there is one, serves it in the
// background until ctx ends. It reports whether the agent started; both
// outcomes are logged.
func Start(ctx context.Context, h Host, logf func(format string, args ...any)) bool {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	exists := func(p string) bool {
		_, err := os.Stat(p)

		return err == nil
	}
	dev, err := findPort(exists, os.DirFS(sysPortsDir), "/dev")
	if err != nil {
		logf("qga: no %s virtio-serial port (checked %s and %s); guest agent not started", PortName, DevLink, sysPortsDir)

		return false
	}
	f, err := os.OpenFile(dev, os.O_RDWR, 0)
	if err != nil {
		logf("qga: open %s: %v; guest agent not started", dev, err)

		return false
	}
	logf("qga: port %s found at %s; guest agent starting (allow-list: %d commands)", PortName, dev, len(commands))
	go func() {
		<-ctx.Done()
		_ = f.Close()
	}()
	go func() {
		Serve(ctx, f, h, logf, idleWait)
		logf("qga: guest agent stopped")
	}()

	return true
}
