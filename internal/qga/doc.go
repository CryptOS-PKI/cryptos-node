// Package qga is CryptOS's in-process QEMU guest agent.
//
// A QEMU/KVM host (Proxmox VE with "QEMU Guest Agent" on, libvirt with a
// guest-agent channel) talks to the guest over the virtio-serial port
// org.qemu.guest_agent.0 using the QGA JSON protocol. The stock qemu-ga ships
// commands that run programs, read and write files and set passwords; a node
// with no shell must never answer those. This package speaks the same wire
// protocol but answers only a fixed allow-list of read-only and power
// commands, and refuses everything else with the error a locked-down qemu-ga
// sends.
//
// The agent runs inside PID 1. It starts only when the port exists, so bare
// metal and hypervisors without the channel never run it.
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
