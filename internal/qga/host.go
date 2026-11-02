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
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// Host is what the agent reads from, and asks of, the node it runs on.
type Host interface {
	// Version is the CryptOS release the node runs.
	Version() string
	// HostName is the node's host name.
	HostName() (string, error)
	// Uname is the running kernel.
	Uname() (Uname, error)
	// Now is the node's clock.
	Now() time.Time
	// Interfaces lists the network interfaces and their addresses.
	Interfaces() ([]Interface, error)
	// Shutdown asks for an orderly stop. mode is "powerdown", "halt" or
	// "reboot", already validated.
	Shutdown(mode string) error
}

// Uname is the part of uname(2) guest-get-osinfo reports.
type Uname struct {
	Release string
	Version string
	Machine string
}

// Interface is one entry of guest-network-get-interfaces.
type Interface struct {
	Name            string      `json:"name"`
	HardwareAddress string      `json:"hardware-address,omitempty"`
	IPAddresses     []IPAddress `json:"ip-addresses,omitempty"`
}

// IPAddress is one address of an Interface.
type IPAddress struct {
	// Type is "ipv4" or "ipv6".
	Type    string `json:"ip-address-type"`
	Address string `json:"ip-address"`
	Prefix  int    `json:"prefix"`
}

// SystemHost answers from the running system.
type SystemHost struct {
	// BuildVersion is the CryptOS version to report.
	BuildVersion string
	// ShutdownFunc carries out guest-shutdown.
	ShutdownFunc func(mode string) error
}

// Version implements Host.
func (h SystemHost) Version() string { return h.BuildVersion }

// HostName implements Host.
func (SystemHost) HostName() (string, error) { return os.Hostname() }

// Now implements Host.
func (SystemHost) Now() time.Time { return time.Now() }

// Uname implements Host.
func (SystemHost) Uname() (Uname, error) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return Uname{}, fmt.Errorf("qga: uname: %w", err)
	}

	return Uname{
		Release: unix.ByteSliceToString(u.Release[:]),
		Version: unix.ByteSliceToString(u.Version[:]),
		Machine: unix.ByteSliceToString(u.Machine[:]),
	}, nil
}

// Interfaces implements Host.
func (SystemHost) Interfaces() ([]Interface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("qga: list interfaces: %w", err)
	}
	out := make([]Interface, 0, len(ifs))
	for _, ifc := range ifs {
		e := Interface{Name: ifc.Name, HardwareAddress: ifc.HardwareAddr.String()}
		addrs, err := ifc.Addrs()
		if err != nil {
			return nil, fmt.Errorf("qga: addresses of %s: %w", ifc.Name, err)
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ones, _ := ipn.Mask.Size()
			typ := "ipv6"
			if ipn.IP.To4() != nil {
				typ = "ipv4"
			}
			e.IPAddresses = append(e.IPAddresses, IPAddress{Type: typ, Address: ipn.IP.String(), Prefix: ones})
		}
		out = append(out, e)
	}

	return out, nil
}

// Shutdown implements Host.
func (h SystemHost) Shutdown(mode string) error {
	if h.ShutdownFunc == nil {
		return fmt.Errorf("qga: shutdown is not wired on this node")
	}

	return h.ShutdownFunc(mode)
}
