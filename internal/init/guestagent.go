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

// The in-process QEMU guest agent (#395). It starts right after the kernel
// log is routed, before the maintenance / installed split, so a QEMU/KVM host
// (Proxmox with "QEMU Guest Agent" on) sees the agent from early boot through
// teardown. Its guest-shutdown lands in shutdownRequests, the same orderly
// path as the Reboot RPC, SIGTERM and the ACPI power button.

import (
	"context"
	"fmt"
	"log"

	"github.com/CryptOS-PKI/cryptos-node/internal/buildinfo"
	"github.com/CryptOS-PKI/cryptos-node/internal/qga"
)

// startGuestAgent starts the agent when the VM has the guest agent channel.
// Either way it only logs: the node runs the same without it.
func startGuestAgent(ctx context.Context, sd *shutdownRequests) {
	qga.Start(ctx, qga.SystemHost{
		BuildVersion: buildinfo.Get().Version,
		ShutdownFunc: guestShutdown(sd.Request),
	}, log.Printf)
}

// guestShutdown maps a guest-shutdown mode to a shutdown request. powerdown
// and halt both power off: a halted VM that never powers off would sit
// there holding its resources, and qemu-ga's halt does the same on most
// hosts.
func guestShutdown(request func(ShutdownAction)) func(mode string) error {
	return func(mode string) error {
		var a ShutdownAction
		switch mode {
		case "powerdown", "halt":
			a = ShutdownPowerOff
		case "reboot":
			a = ShutdownReboot
		default:
			return fmt.Errorf("init: guest-shutdown mode %q is not supported", mode)
		}
		log.Printf("shutdown: %s requested by the QEMU guest agent (mode %s)", a, mode)
		request(a)

		return nil
	}
}
