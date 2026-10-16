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
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func mustMAC(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	mac, err := net.ParseMAC(s)
	if err != nil {
		t.Fatal(err)
	}
	return mac
}

func cidr(s string) net.Addr {
	ip, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return &net.IPNet{IP: ip, Mask: n.Mask}
}

// RFC 3927 2.1: the address is drawn from 169.254.1.0 to 169.254.254.255 and
// seeded from the MAC, so a node comes back on the same address every boot.
func TestLinkLocalAddrIsStableAndInRange(t *testing.T) {
	low := netip.MustParseAddr("169.254.1.0")
	high := netip.MustParseAddr("169.254.254.255")
	seen := map[netip.Addr]bool{}
	for i := 0; i < 512; i++ {
		mac := net.HardwareAddr{0x52, 0x54, 0x00, byte(i >> 8), byte(i), 0x01}
		a := linkLocalAddr(mac)
		if a != linkLocalAddr(mac) {
			t.Fatalf("%s: address not stable", mac)
		}
		if a.Less(low) || high.Less(a) {
			t.Fatalf("%s: %s outside 169.254.1.0-169.254.254.255", mac, a)
		}
		seen[a] = true
	}
	if len(seen) < 400 {
		t.Fatalf("512 MACs gave only %d distinct addresses", len(seen))
	}
}

type fakeNICs struct {
	nics   []nicState
	nicErr error
	up     []string
	added  map[string]netip.Prefix
	addErr error
}

func (f *fakeNICs) deps() linkLocalDeps {
	return linkLocalDeps{
		nics: func() ([]nicState, error) { return f.nics, f.nicErr },
		linkUp: func(name string) error {
			f.up = append(f.up, name)
			return nil
		},
		addAddr: func(name string, p netip.Prefix) error {
			if f.addErr != nil {
				return f.addErr
			}
			if f.added == nil {
				f.added = map[string]netip.Prefix{}
			}
			f.added[name] = p
			return nil
		},
	}
}

func lo() nicState {
	return nicState{Name: "lo", Up: true, Carrier: true, Loopback: true, Addrs: []net.Addr{cidr("127.0.0.1/8")}}
}

func TestLinkLocalStepLeavesARoutableAddressAlone(t *testing.T) {
	mac := mustMAC(t, "52:54:00:12:34:56")
	f := &fakeNICs{nics: []nicState{lo(), {Name: "eth0", MAC: mac, Up: true, Carrier: true, Addrs: []net.Addr{cidr("192.0.2.10/24")}}}}
	if _, _, err := f.deps().step(); err != nil {
		t.Fatal(err)
	}
	if len(f.up) != 0 || len(f.added) != 0 {
		t.Fatalf("touched a node with a DHCP address: up=%v added=%v", f.up, f.added)
	}
}

func TestLinkLocalStepAssignsOnceOnTheFirstLinkWithCarrier(t *testing.T) {
	mac0 := mustMAC(t, "52:54:00:00:00:01")
	mac1 := mustMAC(t, "52:54:00:00:00:02")
	mac2 := mustMAC(t, "52:54:00:00:00:03")
	f := &fakeNICs{nics: []nicState{
		lo(),
		{Name: "eth0", MAC: mac0, Up: true, Carrier: false},
		{Name: "eth1", MAC: mac1, Up: true, Carrier: true, Addrs: []net.Addr{cidr("fe80::5054:ff:fe00:2/64")}},
		{Name: "eth2", MAC: mac2, Up: true, Carrier: true},
	}}
	p, nic, err := f.deps().step()
	if err != nil {
		t.Fatal(err)
	}
	want := netip.PrefixFrom(linkLocalAddr(mac1), 16)
	if nic != "eth1" || p != want {
		t.Fatalf("step = %s on %q, want %s on eth1", p, nic, want)
	}
	if len(f.added) != 1 || f.added["eth1"] != want {
		t.Fatalf("added = %v, want only eth1 %s", f.added, want)
	}
}

func TestLinkLocalStepDoesNothingWhenOneIsAlreadyAssigned(t *testing.T) {
	mac := mustMAC(t, "52:54:00:00:00:01")
	f := &fakeNICs{nics: []nicState{
		lo(),
		{Name: "eth0", MAC: mac, Up: true, Carrier: true, Addrs: []net.Addr{cidr("169.254.7.7/16")}},
		{Name: "eth1", MAC: mustMAC(t, "52:54:00:00:00:02"), Up: true, Carrier: true},
	}}
	p, _, err := f.deps().step()
	if err != nil || p.IsValid() || len(f.added) != 0 {
		t.Fatalf("step = %s, %v, added %v; want nothing", p, err, f.added)
	}
}

// The kernel's failed ip=dhcp attempt leaves its interfaces down, so carrier
// can't be seen until something brings them up.
func TestLinkLocalStepBringsDownLinksUp(t *testing.T) {
	f := &fakeNICs{nics: []nicState{
		lo(),
		{Name: "eth0", MAC: mustMAC(t, "52:54:00:00:00:01")},
		{Name: "eth1", MAC: mustMAC(t, "52:54:00:00:00:02")},
		{Name: "sit0", MAC: net.HardwareAddr{0, 0, 0, 0}},
	}}
	if _, _, err := f.deps().step(); err != nil {
		t.Fatal(err)
	}
	if len(f.up) != 2 || f.up[0] != "eth0" || f.up[1] != "eth1" || len(f.added) != 0 {
		t.Fatalf("up = %v added = %v, want eth0 and eth1 up and nothing added", f.up, f.added)
	}
}

func TestLinkLocalStepOnlyLoopbackDoesNothing(t *testing.T) {
	f := &fakeNICs{nics: []nicState{lo()}}
	p, _, err := f.deps().step()
	if err != nil || p.IsValid() || len(f.up) != 0 {
		t.Fatalf("step = %s, %v, up %v; want nothing", p, err, f.up)
	}
}

func TestLinkLocalStepErrors(t *testing.T) {
	f := &fakeNICs{nicErr: errors.New("no netlink")}
	if _, _, err := f.deps().step(); err == nil {
		t.Error("interface read error should propagate")
	}
	g := &fakeNICs{addErr: errors.New("EPERM"), nics: []nicState{{Name: "eth0", MAC: mustMAC(t, "52:54:00:00:00:01"), Up: true, Carrier: true}}}
	if _, _, err := g.deps().step(); err == nil {
		t.Error("add address error should propagate")
	}
}

// The fallback keeps checking, so a cable plugged in after boot still gets an
// address, and it stops when maintenance ends.
func TestRunLinkLocalFallbackAssignsWhenCarrierArrivesAndStops(t *testing.T) {
	mac := mustMAC(t, "52:54:00:00:00:01")
	f := &fakeNICs{nics: []nicState{lo(), {Name: "eth0", MAC: mac, Up: true}}}
	d := f.deps()
	calls := 0
	nics := d.nics
	carrier := make(chan struct{})
	d.nics = func() ([]nicState, error) {
		calls++
		if calls == 2 {
			f.nics[1].Carrier = true
		}
		if calls == 3 {
			close(carrier)
		}
		return nics()
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runLinkLocalFallback(ctx, d, time.Millisecond)
		close(done)
	}()
	select {
	case <-carrier:
	case <-time.After(5 * time.Second):
		t.Fatal("fallback stopped checking")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("fallback did not stop on cancel")
	}
	if f.added["eth0"] != netip.PrefixFrom(linkLocalAddr(mac), 16) {
		t.Fatalf("added = %v, want eth0 link-local", f.added)
	}
}
