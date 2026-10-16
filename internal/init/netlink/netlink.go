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
	"fmt"
	"net/netip"
	"syscall"
)

// Config is the Phase 1 static network configuration for one interface.
type Config struct {
	// Name is the interface name (e.g. "eth0").
	Name string
	// Address is the static IPv4 address + prefix (e.g. 10.0.0.10/24).
	Address netip.Prefix
	// Gateway is the default-route next hop (e.g. 10.0.0.1). Zero value
	// means no default route is added.
	Gateway netip.Addr
}

// indexFunc resolves an interface name to its kernel index.
type indexFunc func(name string) (int, error)

// sendFunc sends a single rtnetlink request and waits for the kernel ACK.
type sendFunc func(msg []byte) error

// dumpFunc sends a dump request and returns every response message up to
// NLMSG_DONE.
type dumpFunc func(msg []byte) ([][]byte, error)

// bringUpLoopback sets IFF_UP on "lo".
func bringUpLoopback(ifIndex indexFunc, send sendFunc) error {
	idx, err := ifIndex("lo")
	if err != nil {
		return fmt.Errorf("netlink: loopback index: %w", err)
	}
	if err := send(buildLinkUpRequest(1, idx)); err != nil {
		return fmt.Errorf("netlink: bring up loopback: %w", err)
	}
	return nil
}

// setLinkUp sets IFF_UP on the named interface.
func setLinkUp(name string, ifIndex indexFunc, send sendFunc) error {
	idx, err := ifIndex(name)
	if err != nil {
		return fmt.Errorf("netlink: %s index: %w", name, err)
	}
	if err := send(buildLinkUpRequest(1, idx)); err != nil {
		return fmt.Errorf("netlink: set %s up: %w", name, err)
	}
	return nil
}

// addAddress brings the named interface up and adds the IPv4 prefix p to it.
// Unlike configure it flushes nothing and installs no route: the kernel adds
// the connected route for p itself.
func addAddress(name string, p netip.Prefix, ifIndex indexFunc, send sendFunc) error {
	if !p.IsValid() || !p.Addr().Is4() {
		return fmt.Errorf("netlink: add address: %q needs a valid IPv4 address/prefix", name)
	}
	idx, err := ifIndex(name)
	if err != nil {
		return fmt.Errorf("netlink: %s index: %w", name, err)
	}
	if err := send(buildLinkUpRequest(1, idx)); err != nil {
		return fmt.Errorf("netlink: set %s up: %w", name, err)
	}
	if err := send(buildAddrRequest(2, idx, p)); err != nil {
		return fmt.Errorf("netlink: add %s to %s: %w", p, name, err)
	}
	return nil
}

// configure brings the named interface up, flushes any existing IPv4
// addresses (e.g. a kernel ip=dhcp address on a different subnet),
// assigns the static address, and (if set) installs a default route via
// the gateway. Each step is a separate ACK'd request, applied in order;
// the first failure aborts.
func configure(cfg Config, ifIndex indexFunc, send sendFunc, dump dumpFunc) error {
	if cfg.Name == "" {
		return errors.New("netlink: configure: interface name is required")
	}
	if !cfg.Address.IsValid() || !cfg.Address.Addr().Is4() {
		return fmt.Errorf("netlink: configure: %q needs a valid IPv4 address/prefix", cfg.Name)
	}
	if cfg.Gateway.IsValid() && !cfg.Gateway.Is4() {
		return errors.New("netlink: configure: gateway must be IPv4")
	}

	idx, err := ifIndex(cfg.Name)
	if err != nil {
		return fmt.Errorf("netlink: %s index: %w", cfg.Name, err)
	}

	var seq uint32 = 1
	if err := send(buildLinkUpRequest(seq, idx)); err != nil {
		return fmt.Errorf("netlink: set %s up: %w", cfg.Name, err)
	}
	seq++

	// Flush any kernel ip=dhcp addresses so the static config is authoritative.
	msgs, err := dump(buildAddrDumpRequest(seq))
	if err != nil {
		return fmt.Errorf("netlink: dump %s addrs: %w", cfg.Name, err)
	}
	seq++
	existing, err := parseAddrMessages(msgs, idx)
	if err != nil {
		return fmt.Errorf("netlink: parse %s addrs: %w", cfg.Name, err)
	}
	for _, p := range existing {
		if derr := send(buildAddrDelRequest(seq, idx, p)); derr != nil {
			if isAddrNotFound(derr) { // EADDRNOTAVAIL / ENOENT — already gone
				seq++
				continue
			}
			return fmt.Errorf("netlink: del %s from %s: %w", p, cfg.Name, derr)
		}
		seq++
	}

	if err := send(buildAddrRequest(seq, idx, cfg.Address)); err != nil {
		return fmt.Errorf("netlink: add %s to %s: %w", cfg.Address, cfg.Name, err)
	}
	seq++
	if cfg.Gateway.IsValid() {
		if err := send(buildDefaultRouteRequest(seq, idx, cfg.Gateway)); err != nil {
			return fmt.Errorf("netlink: add default route via %s: %w", cfg.Gateway, err)
		}
	}
	return nil
}

// isAddrNotFound reports whether err is EADDRNOTAVAIL or ENOENT — meaning
// the address raced away before we could delete it, which is harmless.
func isAddrNotFound(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.EADDRNOTAVAIL || errno == syscall.ENOENT
	}
	return false
}
