//go:build !linux

package netlink

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
	"net/netip"
	"runtime"
)

// errUnsupported is returned by the netlink entry points on non-Linux
// hosts so the module builds and tests on a developer workstation.
// CryptOS only ever configures networking on Linux.
var errUnsupported = errors.New("netlink: rtnetlink is unsupported on " + runtime.GOOS)

// BringUpLoopback is unsupported off Linux.
func BringUpLoopback() error { return errUnsupported }

// ConfigureInterface is unsupported off Linux.
func ConfigureInterface(Config) error { return errUnsupported }

// SetLinkUp is unsupported off Linux.
func SetLinkUp(string) error { return errUnsupported }

// AddAddress is unsupported off Linux.
func AddAddress(string, netip.Prefix) error { return errUnsupported }
