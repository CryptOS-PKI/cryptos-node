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
	"log"
	"time"

	"golang.org/x/sys/unix"
)

// disableCtrlAltDel stops the kernel restarting the node the instant
// Ctrl-Alt-Del arrives and has it send SIGINT to PID 1 instead, so the key
// combination (or a hypervisor console's "send Ctrl-Alt-Del") takes the
// orderly shutdown path. Call it only once SIGINT is being handled: with no
// handler the Go runtime exits on SIGINT, and PID 1 exiting panics the kernel.
func disableCtrlAltDel() error {
	return unix.Reboot(unix.LINUX_REBOOT_CMD_CAD_OFF)
}

// forceSyncTimeout bounds the sync forceHalt attempts before it gives up on
// flushing and asks the kernel to restart or power off anyway: a sync stuck
// on the same I/O that hung the teardown must not hang the watchdog too.
const forceSyncTimeout = 10 * time.Second

// forceHalt is the shutdown watchdog's last resort: it flushes what it can
// within forceSyncTimeout and then restarts or powers off the node directly
// with reboot(2), skipping whatever part of the orderly teardown has hung.
func forceHalt(action ShutdownAction) {
	// The orderly path already announced this when it was chosen, but the
	// console dashboard may have kept redrawing over it while the teardown
	// hung, so say it again right before the forced reboot.
	announceShutdown(action)

	synced := make(chan struct{})
	go func() {
		unix.Sync()
		close(synced)
	}()
	select {
	case <-synced:
	case <-time.After(forceSyncTimeout):
		log.Printf("shutdown: sync did not finish within %s; forcing %s without it", forceSyncTimeout, action)
	}
	cmd := unix.LINUX_REBOOT_CMD_RESTART
	if action == ShutdownPowerOff {
		cmd = unix.LINUX_REBOOT_CMD_POWER_OFF
	}
	if err := unix.Reboot(cmd); err != nil {
		log.Printf("shutdown: forced %s failed: %v", action, err)
	}
}
