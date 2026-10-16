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
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/CryptOS-PKI/cryptos-node/internal/console"
	"github.com/CryptOS-PKI/cryptos-node/internal/init/netlink"
)

// linkLocalInterval is how often a maintenance node checks whether it needs a
// self-assigned address. A laptop can be cabled in at any time after boot.
const linkLocalInterval = 2 * time.Second

// nicState is the part of an interface the link-local fallback reads.
type nicState struct {
	Name     string
	MAC      net.HardwareAddr
	Up       bool
	Carrier  bool
	Loopback bool
	Addrs    []net.Addr
}

// linkLocalDeps are the host operations the fallback needs, injectable so the
// selection logic is tested without touching the host's interfaces.
type linkLocalDeps struct {
	nics    func() ([]nicState, error)
	linkUp  func(name string) error
	addAddr func(name string, p netip.Prefix) error
}

// linkLocalAddr returns the IPv4 link-local address (RFC 3927) a node with
// this MAC assigns itself: drawn from 169.254.1.0 to 169.254.254.255 and seeded
// from the MAC, as RFC 3927 section 2.1 recommends, so a node comes back on the
// same address every boot and the operator can keep using it.
func linkLocalAddr(mac net.HardwareAddr) netip.Addr {
	sum := sha256.Sum256(mac)
	n := binary.BigEndian.Uint16(sum[:2]) % (254 * 256)
	return netip.AddrFrom4([4]byte{169, 254, byte(1 + n/256), byte(n % 256)})
}

// step makes one pass. When no interface has a reachable IPv4 address (the
// kernel's ip=dhcp got no answer, and nothing has been assigned yet), it brings
// down Ethernet links up so their carrier shows, and gives the first one with
// carrier its link-local address in 169.254.0.0/16. Only one interface gets one,
// so the node never holds two connected routes for the same prefix. It returns
// the prefix it assigned and the interface, or the zero prefix when it did
// nothing.
//
// No ARP probe is sent before claiming the address: the case this serves is a
// laptop cabled straight to the node, where the only other host on the link
// picks its own address the same way, and a clash is a 1 in 65024 chance that
// the operator sees at once and fixes by replugging.
func (d linkLocalDeps) step() (netip.Prefix, string, error) {
	nics, err := d.nics()
	if err != nil {
		return netip.Prefix{}, "", err
	}
	var all []net.Addr
	for _, n := range nics {
		all = append(all, n.Addrs...)
	}
	if len(console.ReachableAddrs(all)) > 0 {
		return netip.Prefix{}, "", nil
	}
	var errs []error
	for _, n := range nics {
		if n.Loopback || len(n.MAC) != 6 {
			continue
		}
		if !n.Up {
			if err := d.linkUp(n.Name); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		if !n.Carrier {
			continue
		}
		p := netip.PrefixFrom(linkLocalAddr(n.MAC), 16)
		if err := d.addAddr(n.Name, p); err != nil {
			return netip.Prefix{}, "", errors.Join(append(errs, err)...)
		}
		return p, n.Name, errors.Join(errs...)
	}
	return netip.Prefix{}, "", errors.Join(errs...)
}

// runLinkLocalFallback runs step every interval until ctx ends, so a maintenance
// node with no DHCP server stays reachable on a self-assigned address. The
// console picks the address up on its next refresh (console.ReachableAddrs).
func runLinkLocalFallback(ctx context.Context, d linkLocalDeps, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	var lastErr string
	for {
		p, nic, err := d.step()
		if p.IsValid() {
			log.Printf("maintenance: no DHCP address; assigned link-local %s to %s", p, nic)
		}
		msg := ""
		if err != nil {
			msg = err.Error()
		}
		if msg != "" && msg != lastErr {
			log.Printf("maintenance: link-local fallback: %v", err)
		}
		lastErr = msg
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// startLinkLocalFallback starts runLinkLocalFallback on this host's interfaces
// and returns the func that stops it.
func startLinkLocalFallback(ctx context.Context) func() {
	ctx, cancel := context.WithCancel(ctx)
	go runLinkLocalFallback(ctx, linkLocalDeps{
		nics:    localNICs,
		linkUp:  netlink.SetLinkUp,
		addAddr: netlink.AddAddress,
	}, linkLocalInterval)
	return cancel
}

func localNICs() ([]nicState, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]nicState, 0, len(ifs))
	for _, ifc := range ifs {
		addrs, err := ifc.Addrs()
		if err != nil {
			return nil, err
		}
		out = append(out, nicState{
			Name:     ifc.Name,
			MAC:      ifc.HardwareAddr,
			Up:       ifc.Flags&net.FlagUp != 0,
			Carrier:  ifc.Flags&net.FlagRunning != 0,
			Loopback: ifc.Flags&net.FlagLoopback != 0,
			Addrs:    addrs,
		})
	}
	return out, nil
}
